using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.Vcalm;
using Verifiable.Vcalm.Exchange;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.OAuth;
using Verifiable.Server;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// Multi-tenant flow tests for the W3C VCALM 1.0 issuer / verifier services
/// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
/// Management</see>): TWO tenants on ONE <see cref="Verifiable.Server.EndpointServer"/>, each securing
/// credentials under its OWN issuer identity and signing key, dispatched on its own tenant-scoped path
/// — the same multi-tenant shape the OAuth flow suite (<see cref="TenantIdThreadingTests"/>,
/// <see cref="RecursiveTenancyTests"/>) exercises on the shared host.
/// </summary>
/// <remarks>
/// <para>
/// Per-tenant issuance is wired through <see cref="VcalmIntegration.ResolveVcalmCredentialIssuanceAsync"/>:
/// the dispatcher stamps the resolved tenant on the request context, and the resolver returns that
/// tenant's <see cref="VcalmCredentialIssuance"/>. This is the productized counterpart of a single,
/// server-global issuer — the shape a deployment serving many issuers from one host requires, and the
/// model a self-contained showcase collapses to a single process-lifetime key.
/// </para>
/// <para>
/// The isolation boundary these tests pin: ISSUANCE is per-tenant (each tenant signs only as its own
/// configured issuer, with its own key, and its issued-credential store is tenant-scoped), while
/// VERIFICATION is identity-based (a credential resolves and verifies against its issuer's DID
/// regardless of which tenant's verifier endpoint handles it — verification is not tenant-partitioned).
/// </para>
/// </remarks>
[TestClass]
internal sealed class VcalmMultiTenantFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    //Both tenants allow the issuer and verifier roles so an issued credential can be driven straight
    //into a /credentials/verify endpoint — on its own tenant and on the other tenant.
    private static readonly ImmutableHashSet<CapabilityIdentifier> IssuerAndVerifier =
        ImmutableHashSet.Create(
            WellKnownVcalmCapabilities.VcalmIssuer, WellKnownVcalmCapabilities.VcalmVerifier);

    private static readonly ImmutableHashSet<CapabilityIdentifier> IssuerOnly =
        ImmutableHashSet.Create(WellKnownVcalmCapabilities.VcalmIssuer);

    //The full showcase host gives every tenant the issuer, verifier, status, and holder roles so one
    //tenant can be driven across all of its signing surfaces.
    private static readonly ImmutableHashSet<CapabilityIdentifier> ShowcaseCapabilities =
        ImmutableHashSet.Create(
            WellKnownVcalmCapabilities.VcalmIssuer,
            WellKnownVcalmCapabilities.VcalmVerifier,
            WellKnownVcalmCapabilities.VcalmStatus,
            WellKnownVcalmCapabilities.VcalmHolder);

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;
    private static KeyDidBuilder KeyDidBuilder { get; } = new();

    private static DidResolver KeyDidResolverSeam { get; } = new(
        DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, KeyDidResolver.Build(Pool))));

    private static CanonicalizationDelegate RdfcCanonicalizer { get; } =
        CanonicalizationTestUtilities.CreateRdfcCanonicalizer();

    private static ContextResolverDelegate ContextResolver { get; } =
        CanonicalizationTestUtilities.CreateTestContextResolver();

    private static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializerExtensions.Serialize(credential, JsonOptions);

    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(serialized, JsonOptions)!;

    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);

    //The §3.5.2 holder presentations sign with eddsa-jcs-2022; JCS is context-free.
    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, _, cancellationToken) =>
        ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = Jcs.Canonicalize(json) });

    private static PresentationSerializeDelegate SerializePresentation { get; } = presentation =>
        JsonSerializerExtensions.Serialize(presentation, JsonOptions);

    private static PresentationDeserializeDelegate DeserializePresentation { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiablePresentation>(serialized, JsonOptions)!;

    private List<IDisposable> OwnedKeys { get; } = [];

    //The issued-credential store, keyed by (tenant segment, credentialId), so the §3.2.2 retrieval is
    //tenant-scoped — a credential issued by one tenant is not reachable through another tenant's store.
    private ConcurrentDictionary<(string Tenant, string Id), VcalmStoredCredential> CredentialStore { get; } =
        new();


    [TestCleanup]
    public void DisposeOwnedKeys()
    {
        foreach(IDisposable key in OwnedKeys)
        {
            key.Dispose();
        }

        OwnedKeys.Clear();
        CredentialStore.Clear();
    }


    /// <summary>
    /// Each tenant secures credentials under ITS OWN issuer identity and signing key: tenant A's
    /// §3.2.1 issue signs with A's verification method, tenant B's with B's, the two verification
    /// methods differ, and each credential round-trips verify TRUE at its own tenant's verifier.
    /// </summary>
    [TestMethod]
    public async Task EachTenantIssuesUnderItsOwnIssuerAndKey()
    {
        await using TestHostShell app = new(TimeProvider);
        TwoTenants t = await StartTwoTenantHostAsync(app).ConfigureAwait(false);

        using JsonDocument issuedA = await PostIssueAsync(
            app, t.SegmentA, BuildIssueRequestBody(t.IssuerDidA, "urn:uuid:a-1"), expectedStatus: 201).ConfigureAwait(false);
        using JsonDocument issuedB = await PostIssueAsync(
            app, t.SegmentB, BuildIssueRequestBody(t.IssuerDidB, "urn:uuid:b-1"), expectedStatus: 201).ConfigureAwait(false);

        JsonElement vcA = issuedA.RootElement.GetProperty(VcalmParameterNames.VerifiableCredential);
        JsonElement vcB = issuedB.RootElement.GetProperty(VcalmParameterNames.VerifiableCredential);

        Assert.AreEqual(t.VmIdA, ProofVerificationMethod(vcA),
            "Tenant A's issue is signed by tenant A's verification method.");
        Assert.AreEqual(t.VmIdB, ProofVerificationMethod(vcB),
            "Tenant B's issue is signed by tenant B's verification method.");
        Assert.AreNotEqual(t.VmIdA, t.VmIdB,
            "The two tenants resolve to distinct per-tenant signing keys — not one shared server key.");

        //Each credential cryptographically verifies at its own tenant's verifier endpoint.
        await AssertVerifiedAsync(app, t.SegmentA, vcA.GetRawText(), expected: true).ConfigureAwait(false);
        await AssertVerifiedAsync(app, t.SegmentB, vcB.GetRawText(), expected: true).ConfigureAwait(false);
    }


    /// <summary>
    /// Issuance isolation: a request to tenant B's §3.2.1 endpoint that declares tenant A's issuer is
    /// rejected with HTTP 400 ("The provided value of 'issuer' does not match the expected
    /// configuration.") — tenant B never signs as tenant A.
    /// </summary>
    [TestMethod]
    public async Task TenantRejectsIssuanceUnderAnotherTenantsIssuer()
    {
        await using TestHostShell app = new(TimeProvider);
        TwoTenants t = await StartTwoTenantHostAsync(app).ConfigureAwait(false);

        //Tenant A's issuer DID, posted to tenant B's issue endpoint. Asserting the §3.2.1 issuer-mismatch
        //DETAIL (not merely the shared MalformedValueError type, which six 400 sites emit) proves the
        //rejection is FOR the cross-tenant reason — that tenant B refused to sign as tenant A.
        ServerHttpResponse forward = await DispatchIssueAsync(
            app, t.SegmentB, BuildIssueRequestBody(t.IssuerDidA, "urn:uuid:cross")).ConfigureAwait(false);
        Assert.AreEqual(400, forward.StatusCode, forward.Body);
        Assert.Contains("does not match the expected configuration", forward.Body,
            "Tenant B rejects tenant A's issuer as a §3.2.1 issuer mismatch — not merely 'some 400'.");

        //The reverse direction holds too: tenant A will not sign as tenant B.
        ServerHttpResponse reverse = await DispatchIssueAsync(
            app, t.SegmentA, BuildIssueRequestBody(t.IssuerDidB, "urn:uuid:cross-reverse")).ConfigureAwait(false);
        Assert.AreEqual(400, reverse.StatusCode, reverse.Body);
        Assert.Contains("does not match the expected configuration", reverse.Body,
            "The isolation is symmetric — tenant A rejects tenant B's issuer the same way.");
    }


    /// <summary>
    /// Verification is identity-based, not tenant-partitioned: a credential issued by tenant A verifies
    /// TRUE when driven into tenant B's §3.3.1 verifier endpoint (the verifier resolves the credential's
    /// issuer DID and checks the proof, regardless of which tenant fronts the verify call). This pins
    /// the boundary — issuance is per-tenant, verification is not.
    /// </summary>
    [TestMethod]
    public async Task CredentialFromOneTenantVerifiesAtAnotherTenantsVerifier()
    {
        await using TestHostShell app = new(TimeProvider);
        TwoTenants t = await StartTwoTenantHostAsync(app).ConfigureAwait(false);

        using JsonDocument issuedA = await PostIssueAsync(
            app, t.SegmentA, BuildIssueRequestBody(t.IssuerDidA, "urn:uuid:a-cross-verify"), expectedStatus: 201).ConfigureAwait(false);
        string securedA = issuedA.RootElement.GetProperty(VcalmParameterNames.VerifiableCredential).GetRawText();

        await AssertVerifiedAsync(app, t.SegmentB, securedA, expected: true).ConfigureAwait(false);
    }


    /// <summary>
    /// The §3.2.2 issued-credential store is tenant-scoped: a credential issued and stored by tenant A
    /// is retrievable (200) on tenant A's <c>GET /credentials/{id}</c> but is NOT found (404) on tenant
    /// B's — one tenant cannot read another tenant's issued credentials by id.
    /// </summary>
    [TestMethod]
    public async Task IssuedCredentialStoreIsTenantScoped()
    {
        await using TestHostShell app = new(TimeProvider);
        TwoTenants t = await StartTwoTenantHostAsync(app).ConfigureAwait(false);

        const string CredentialId = "urn:uuid:tenant-a-private";
        using JsonDocument _ = await PostIssueAsync(
            app, t.SegmentA, BuildIssueRequestBody(t.IssuerDidA, CredentialId), expectedStatus: 201).ConfigureAwait(false);

        //Tenant A retrieves its own credential.
        ServerHttpResponse onOwnTenant = await app.DispatchVcalmCredentialByIdAsync(
            t.SegmentA, "GET", CredentialId, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, onOwnTenant.StatusCode, onOwnTenant.Body);

        //Tenant B cannot reach tenant A's credential by the same id — 404, not a cross-tenant read.
        ServerHttpResponse onOtherTenant = await app.DispatchVcalmCredentialByIdAsync(
            t.SegmentB, "GET", CredentialId, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(404, onOtherTenant.StatusCode,
            "Tenant B cannot retrieve a credential issued and stored under tenant A.");
    }


    /// <summary>
    /// Fail-closed safety invariant of the per-tenant seam: when the §3.2.1 route materializes for a
    /// <see cref="WellKnownVcalmCapabilities.VcalmIssuer"/>-capable tenant (the resolver is wired) but the
    /// resolver yields NO issuance for that tenant, the endpoint returns a server error and secures
    /// NOTHING — it never falls back to a default or another tenant's identity. This pins the regression
    /// site a green suite would otherwise mask: a future change turning the null branch into a
    /// sign-with-default would be a real fail-open, and this test would catch it.
    /// </summary>
    [TestMethod]
    public async Task IssuerCapableTenantWithNoResolvedIssuanceFailsClosed()
    {
        await using TestHostShell app = new(TimeProvider);

        VerifierKeyMaterial hostMaterial = app.RegisterClient(
            "https://no-issuance.client.test", new Uri("https://no-issuance.client.test"), IssuerOnly);
        OwnedKeys.Add(hostMaterial);

        VcalmIntegration vcalm = app.Server.Vcalm();
        vcalm.UseDefaultVcalmJsonParsing(JsonOptions);

        //The resolver is wired — so the §3.2.1 route materializes — but resolves NO issuance for any
        //tenant: the capability-present-but-no-identity misconfiguration.
        vcalm.ResolveVcalmCredentialIssuanceAsync = (_, _) =>
            ValueTask.FromResult<VcalmCredentialIssuance?>(null);

        ServerHttpResponse response = await DispatchIssueAsync(
            app,
            hostMaterial.Registration.TenantId.Value,
            BuildIssueRequestBody("did:example:whoever", "urn:uuid:no-issuance")).ConfigureAwait(false);

        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.Contains("No VCALM issuance configuration resolved for this tenant.", response.Body,
            "A capability-bearing tenant with no resolved issuance fails closed — it secures nothing.");
    }


    /// <summary>
    /// Precedence: when BOTH a per-tenant resolver and a distinct flat
    /// <see cref="VcalmIntegration.VcalmCredentialIssuance"/> are wired, the resolver WINS — the §3.2.1
    /// endpoint signs under the per-tenant identity, never the flat one. Gates the documented precedence
    /// of <see cref="VcalmIntegration.ResolveEffectiveCredentialIssuanceAsync"/>.
    /// </summary>
    [TestMethod]
    public async Task PerTenantResolverSupersedesFlatIssuance()
    {
        await using TestHostShell app = new(TimeProvider);
        TwoTenants t = await StartTwoTenantHostAsync(app).ConfigureAwait(false);

        //A distinct flat issuer identity that MUST be ignored while the resolver is wired.
        FreshIssuance flat = await BuildFreshIssuanceAsync().ConfigureAwait(false);
        Assert.AreNotEqual(t.VmIdA, flat.VerificationMethodId,
            "The flat identity is genuinely distinct from tenant A's, so signing-as-A proves the resolver won.");
        app.Server.Vcalm().VcalmCredentialIssuance = flat.Issuance;

        using JsonDocument issuedA = await PostIssueAsync(
            app, t.SegmentA, BuildIssueRequestBody(t.IssuerDidA, "urn:uuid:precedence"), expectedStatus: 201).ConfigureAwait(false);

        Assert.AreEqual(t.VmIdA,
            ProofVerificationMethod(issuedA.RootElement.GetProperty(VcalmParameterNames.VerifiableCredential)),
            "With both wired, the per-tenant resolver supersedes the flat issuance — tenant A signs as A.");
    }


    /// <summary>
    /// §C.1 status-list isolation: each tenant secures its status lists under its OWN issuer identity
    /// and key (§C.1 reuses the issuer signing configuration). Tenant A's §C.1 create signs with A's
    /// verification method, tenant B's with B's, and the two differ.
    /// </summary>
    [TestMethod]
    public async Task EachTenantSecuresStatusListsUnderItsOwnKey()
    {
        await using TestHostShell app = new(TimeProvider);
        Showcase s = await StartShowcaseHostAsync(app).ConfigureAwait(false);

        using JsonDocument listA = await PostCreateStatusListAsync(app, s.SegmentA, "https://status.example/a/1", 201).ConfigureAwait(false);
        using JsonDocument listB = await PostCreateStatusListAsync(app, s.SegmentB, "https://status.example/b/1", 201).ConfigureAwait(false);

        Assert.AreEqual(s.IssuerVmIdA, ProofVerificationMethod(listA.RootElement.GetProperty(VcalmParameterNames.VerifiableCredential)),
            "Tenant A's status list is secured by tenant A's verification method.");
        Assert.AreEqual(s.IssuerVmIdB, ProofVerificationMethod(listB.RootElement.GetProperty(VcalmParameterNames.VerifiableCredential)),
            "Tenant B's status list is secured by tenant B's verification method.");
        Assert.AreNotEqual(s.IssuerVmIdA, s.IssuerVmIdB,
            "The two tenants secure their status lists under distinct per-tenant keys.");
    }


    /// <summary>
    /// §C.1 fail-closed: a VcalmStatus-capable tenant whose status-list resolver yields no issuance
    /// returns a server error and secures nothing — it never falls back to a default identity.
    /// </summary>
    [TestMethod]
    public async Task StatusCapableTenantWithNoResolvedIssuanceFailsClosed()
    {
        await using TestHostShell app = new(TimeProvider);

        VerifierKeyMaterial hostMaterial = app.RegisterClient(
            "https://no-status.client.test", new Uri("https://no-status.client.test"),
            ImmutableHashSet.Create(WellKnownVcalmCapabilities.VcalmStatus));
        OwnedKeys.Add(hostMaterial);

        VcalmIntegration vcalm = app.Server.Vcalm();
        vcalm.UseDefaultVcalmJsonParsing(JsonOptions);
        vcalm.ResolveVcalmStatusListIssuanceAsync = (_, _) =>
            ValueTask.FromResult<VcalmCredentialIssuance?>(null);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            hostMaterial.Registration.TenantId.Value, WellKnownVcalmEndpointNames.VcalmCreateStatusList, "POST",
            new RequestFields(), "{\"statusPurpose\":\"revocation\",\"id\":\"https://status.example/x\"}",
            new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.Contains("No VCALM status-list issuance configuration resolved for this tenant.", response.Body,
            "A status-capable tenant with no resolved issuance fails closed — it secures nothing.");
    }


    /// <summary>
    /// §3.5.2 presentation isolation: each holder tenant signs presentations under its OWN holder key.
    /// Tenant A's create-presentation signs with A's holder verification method, tenant B's with B's.
    /// </summary>
    [TestMethod]
    public async Task EachTenantSignsPresentationsUnderItsOwnHolderKey()
    {
        await using TestHostShell app = new(TimeProvider);
        Showcase s = await StartShowcaseHostAsync(app).ConfigureAwait(false);

        using JsonDocument presA = await PostCreatePresentationAsync(app, s.SegmentA, s.HolderDidA, "domain-a.example", 201).ConfigureAwait(false);
        using JsonDocument presB = await PostCreatePresentationAsync(app, s.SegmentB, s.HolderDidB, "domain-b.example", 201).ConfigureAwait(false);

        Assert.AreEqual(s.HolderVmIdA, ProofVerificationMethod(presA.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentation)),
            "Tenant A's presentation is signed by tenant A's holder verification method.");
        Assert.AreEqual(s.HolderVmIdB, ProofVerificationMethod(presB.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentation)),
            "Tenant B's presentation is signed by tenant B's holder verification method.");
        Assert.AreNotEqual(s.HolderVmIdA, s.HolderVmIdB,
            "The two holder tenants sign presentations under distinct per-tenant keys.");
    }


    /// <summary>
    /// §3.5.2 fail-closed: a VcalmHolder-capable tenant whose presentation-signing resolver yields no
    /// configuration returns a server error and signs nothing.
    /// </summary>
    [TestMethod]
    public async Task HolderCapableTenantWithNoResolvedSigningFailsClosed()
    {
        await using TestHostShell app = new(TimeProvider);

        VerifierKeyMaterial hostMaterial = app.RegisterClient(
            "https://no-holder.client.test", new Uri("https://no-holder.client.test"),
            ImmutableHashSet.Create(WellKnownVcalmCapabilities.VcalmHolder));
        OwnedKeys.Add(hostMaterial);

        VcalmIntegration vcalm = app.Server.Vcalm();
        vcalm.UseDefaultVcalmJsonParsing(JsonOptions);
        vcalm.ResolveVcalmPresentationSigningAsync = (_, _) =>
            ValueTask.FromResult<VcalmPresentationSigning?>(null);

        string body = "{\"presentation\":" + SerializeUnproofedPresentation("did:example:holder")
            + ",\"options\":{\"challenge\":\"c-1\",\"domain\":\"d.example\"}}";
        ExchangeContext context = new();
        context.SetCurrentChannelDomain("d.example");

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            hostMaterial.Registration.TenantId.Value, WellKnownVcalmEndpointNames.VcalmCreatePresentation, "POST",
            new RequestFields(), body, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.Contains("No VCALM presentation-signing configuration resolved for this tenant.", response.Body,
            "A holder-capable tenant with no resolved signing fails closed — it signs nothing.");
    }


    /// <summary>
    /// §3.5.1 fail-closed: a VcalmHolder-capable tenant whose derive resolver yields no configuration
    /// returns a server error and derives nothing — restoring the fail-closed-coverage symmetry across
    /// all four slice-2/3 signing surfaces (the derive null-guard is byte-identical to status/present).
    /// </summary>
    [TestMethod]
    public async Task DeriveCapableTenantWithNoResolvedDerivationFailsClosed()
    {
        await using TestHostShell app = new(TimeProvider);

        VerifierKeyMaterial hostMaterial = app.RegisterClient(
            "https://no-derive.client.test", new Uri("https://no-derive.client.test"),
            ImmutableHashSet.Create(WellKnownVcalmCapabilities.VcalmHolder));
        OwnedKeys.Add(hostMaterial);

        VcalmIntegration vcalm = app.Server.Vcalm();
        vcalm.UseDefaultVcalmJsonParsing(JsonOptions);
        vcalm.ResolveVcalmCredentialDerivationAsync = (_, _) =>
            ValueTask.FromResult<VcalmCredentialDerivation?>(null);

        //A parse-able derive request needs a SECURED (proofed) credential; the resolution null-guard
        //fires before the non-derivable check, so an ordinary eddsa-rdfc-2022 proof (not a real
        //ecdsa-sd-2023 base proof) is enough to reach the fail-closed branch.
        string body = "{\"verifiableCredential\":" + await SignedCredentialJsonAsync().ConfigureAwait(false)
            + ",\"options\":{\"selectivePointers\":[\"/credentialSubject/id\"]}}";

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            hostMaterial.Registration.TenantId.Value, WellKnownVcalmEndpointNames.VcalmCredentialsDerive, "POST",
            new RequestFields(), body, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.Contains("No VCALM credential-derivation configuration resolved for this tenant.", response.Body,
            "A derive-capable tenant with no resolved derivation fails closed — it derives nothing.");
    }


    /// <summary>
    /// §3.6 issuance-in-exchange resolution: the exchange engine's effective issuance resolves per
    /// tenant. With no exchange-specific wiring it FALLS BACK to the per-tenant issuer issuance; a
    /// dedicated per-tenant exchange resolver SUPERSEDES that fallback; and a tenant with no issuance
    /// anywhere resolves to null (the engine's fail-closed signal). This pins the one non-trivial
    /// effective-resolution method without reconstructing the whole §3.6 multi-step PDA flow.
    /// </summary>
    [TestMethod]
    public async Task ExchangeIssuanceResolvesPerTenantWithIssuerFallback()
    {
        await using TestHostShell app = new(TimeProvider);
        TenantIssuer a = await RegisterTenantAsync(app, "https://ex-a.client.test").ConfigureAwait(false);
        TenantIssuer b = await RegisterTenantAsync(app, "https://ex-b.client.test").ConfigureAwait(false);

        Dictionary<string, VcalmCredentialIssuance> issuerBySegment = new(StringComparer.Ordinal)
        {
            [a.Segment] = a.Issuance,
            [b.Segment] = b.Issuance
        };

        VcalmIntegration vcalm = app.Server.Vcalm();
        vcalm.ResolveVcalmCredentialIssuanceAsync = (context, _) =>
            ValueTask.FromResult(issuerBySegment.GetValueOrDefault(TenantSegment(context)));

        //No exchange-specific resolver/flat → exchange issuance falls back to the per-tenant ISSUER.
        Assert.AreSame(a.Issuance,
            await vcalm.ResolveEffectiveExchangeIssuanceAsync(ContextForTenant(a.Segment), TestContext.CancellationToken).ConfigureAwait(false),
            "With no exchange wiring, tenant A's exchange issuance falls back to tenant A's issuer issuance.");
        Assert.AreSame(b.Issuance,
            await vcalm.ResolveEffectiveExchangeIssuanceAsync(ContextForTenant(b.Segment), TestContext.CancellationToken).ConfigureAwait(false),
            "The fallback is per-tenant — tenant B falls back to tenant B's issuer issuance.");

        //A dedicated per-tenant EXCHANGE resolver supersedes the issuer fallback for the tenants it covers.
        FreshIssuance exchangeA = await BuildFreshIssuanceAsync().ConfigureAwait(false);
        vcalm.ResolveVcalmExchangeIssuanceAsync = (context, _) =>
            ValueTask.FromResult(string.Equals(TenantSegment(context), a.Segment, StringComparison.Ordinal) ? exchangeA.Issuance : null);

        Assert.AreSame(exchangeA.Issuance,
            await vcalm.ResolveEffectiveExchangeIssuanceAsync(ContextForTenant(a.Segment), TestContext.CancellationToken).ConfigureAwait(false),
            "Tenant A's dedicated exchange issuance supersedes the issuer fallback.");
        Assert.AreSame(b.Issuance,
            await vcalm.ResolveEffectiveExchangeIssuanceAsync(ContextForTenant(b.Segment), TestContext.CancellationToken).ConfigureAwait(false),
            "Tenant B has no exchange entry, so it still falls through to its issuer issuance.");

        //A tenant with no issuance anywhere resolves to null — the §3.6 engine's fail-closed signal.
        Assert.IsNull(
            await vcalm.ResolveEffectiveExchangeIssuanceAsync(ContextForTenant("unknown-tenant"), TestContext.CancellationToken).ConfigureAwait(false),
            "A tenant with no issuance anywhere resolves to null; the engine refuses the issuance step.");
    }


    /// <summary>
    /// The cross-cutting showcase: two tenants each driven across THREE signing surfaces — §3.2.1 issue,
    /// §C.1 status-list, §3.5.2 presentation — on one host, with every artifact secured under the right
    /// tenant's own key and no key ever crossing tenants. A tenant's issuer-role surfaces (credential +
    /// status list) share its issuer key; its presentation uses its distinct holder key.
    /// </summary>
    [TestMethod]
    public async Task CrossCuttingShowcaseKeepsEveryTenantSurfaceIsolated()
    {
        await using TestHostShell app = new(TimeProvider);
        Showcase s = await StartShowcaseHostAsync(app).ConfigureAwait(false);

        using JsonDocument issuedA = await PostIssueAsync(app, s.SegmentA, BuildIssueRequestBody(s.IssuerDidA, "urn:uuid:show-a"), 201).ConfigureAwait(false);
        using JsonDocument listA = await PostCreateStatusListAsync(app, s.SegmentA, "https://status.example/show-a", 201).ConfigureAwait(false);
        using JsonDocument presA = await PostCreatePresentationAsync(app, s.SegmentA, s.HolderDidA, "show-a.example", 201).ConfigureAwait(false);

        using JsonDocument issuedB = await PostIssueAsync(app, s.SegmentB, BuildIssueRequestBody(s.IssuerDidB, "urn:uuid:show-b"), 201).ConfigureAwait(false);
        using JsonDocument listB = await PostCreateStatusListAsync(app, s.SegmentB, "https://status.example/show-b", 201).ConfigureAwait(false);
        using JsonDocument presB = await PostCreatePresentationAsync(app, s.SegmentB, s.HolderDidB, "show-b.example", 201).ConfigureAwait(false);

        //Tenant A: credential + status list under A's ISSUER key; presentation under A's HOLDER key.
        Assert.AreEqual(s.IssuerVmIdA, ProofVerificationMethod(issuedA.RootElement.GetProperty(VcalmParameterNames.VerifiableCredential)));
        Assert.AreEqual(s.IssuerVmIdA, ProofVerificationMethod(listA.RootElement.GetProperty(VcalmParameterNames.VerifiableCredential)));
        Assert.AreEqual(s.HolderVmIdA, ProofVerificationMethod(presA.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentation)));

        //Tenant B: the same surfaces under B's keys.
        Assert.AreEqual(s.IssuerVmIdB, ProofVerificationMethod(issuedB.RootElement.GetProperty(VcalmParameterNames.VerifiableCredential)));
        Assert.AreEqual(s.IssuerVmIdB, ProofVerificationMethod(listB.RootElement.GetProperty(VcalmParameterNames.VerifiableCredential)));
        Assert.AreEqual(s.HolderVmIdB, ProofVerificationMethod(presB.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentation)));

        //No signing key crosses tenants on any surface.
        Assert.AreNotEqual(s.IssuerVmIdA, s.IssuerVmIdB, "Issuer keys never cross tenants.");
        Assert.AreNotEqual(s.HolderVmIdA, s.HolderVmIdB, "Holder keys never cross tenants.");
    }


    //Registers two tenants on one host, each with its own Ed25519 issuer identity, and wires the
    //per-tenant issuance resolver, the (shared, identity-based) verification seam, and the tenant-scoped
    //issued-credential store.
    private async Task<TwoTenants> StartTwoTenantHostAsync(TestHostShell app)
    {
        TenantIssuer a = await RegisterTenantAsync(app, "https://tenant-a.client.test").ConfigureAwait(false);
        TenantIssuer b = await RegisterTenantAsync(app, "https://tenant-b.client.test").ConfigureAwait(false);

        Dictionary<string, VcalmCredentialIssuance> issuanceBySegment = new(StringComparer.Ordinal)
        {
            [a.Segment] = a.Issuance,
            [b.Segment] = b.Issuance
        };

        VcalmIntegration vcalm = app.Server.Vcalm();
        vcalm.UseDefaultVcalmJsonParsing(JsonOptions);

        //The productized multi-tenant seam: resolve the §3.2.1 issuance configuration for the tenant the
        //dispatcher stamped on the request, instead of reading one server-global value.
        vcalm.ResolveVcalmCredentialIssuanceAsync = (context, _) =>
            ValueTask.FromResult(issuanceBySegment.GetValueOrDefault(TenantSegment(context)));

        //Verification is identity-based: one did:key resolver resolves either tenant's issuer DID.
        vcalm.VcalmCredentialVerification = new VcalmCredentialVerification
        {
            Resolver = KeyDidResolverSeam,
            Canonicalize = RdfcCanonicalizer,
            ContextResolver = ContextResolver,
            DecodeProofValue = ProofValueCodecs.DecodeBase58Btc,
            SerializeCredential = SerializeCredential,
            SerializePresentation = presentation => JsonSerializerExtensions.Serialize(presentation, JsonOptions),
            SerializeProofOptions = SerializeProofOptions,
            Decoder = TestSetup.Base58Decoder,
            ComputeDigest = MicrosoftEntropyFunctions.ComputeDigestAsync,
            MemoryPool = Pool
        };

        //Tenant-scoped issued-credential store: the key carries the request's tenant segment.
        vcalm.StoreVcalmIssuedCredentialAsync = (credentialId, json, context, _) =>
        {
            CredentialStore[(TenantSegment(context), credentialId)] =
                new VcalmStoredCredential { VerifiableCredentialJson = json };

            return ValueTask.CompletedTask;
        };
        vcalm.LoadVcalmIssuedCredentialAsync = (credentialId, context, _) =>
            ValueTask.FromResult(CredentialStore.GetValueOrDefault((TenantSegment(context), credentialId)));

        return new TwoTenants(a.Segment, a.IssuerDid, a.VerificationMethodId, b.Segment, b.IssuerDid, b.VerificationMethodId);
    }


    //Registers one tenant (the issuer + verifier roles) with a fresh Ed25519 issuer identity, and
    //builds that tenant's §3.2.1 issuance configuration. The host-client material and the issuer key
    //material are retained for disposal at cleanup.
    private async Task<TenantIssuer> RegisterTenantAsync(TestHostShell app, string clientId)
    {
        VerifierKeyMaterial hostMaterial = app.RegisterClient(clientId, new Uri(clientId), IssuerAndVerifier);
        OwnedKeys.Add(hostMaterial);

        FreshIssuance fresh = await BuildFreshIssuanceAsync().ConfigureAwait(false);

        return new TenantIssuer(
            hostMaterial.Registration.TenantId.Value, fresh.IssuerDid, fresh.VerificationMethodId, fresh.Issuance);
    }


    //Builds a §3.2.1 issuance configuration backed by a FRESH, distinct Ed25519 issuer identity (its
    //own key + did:key DID). Each call yields a different issuer — the precondition for proving
    //per-tenant isolation. The fixed-vector CreateEd25519KeyMaterial() would collapse callers onto one
    //identity; CreateFreshEd25519KeyMaterial() does not. Key material is retained for disposal at cleanup.
    private async Task<FreshIssuance> BuildFreshIssuanceAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeyPair =
            TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        OwnedKeys.Add(issuerKeyPair.PublicKey);
        OwnedKeys.Add(issuerKeyPair.PrivateKey);

        DidDocument issuerDidDocument = await KeyDidBuilder.BuildAsync(
            issuerKeyPair.PublicKey,
            MultikeyVerificationMethodTypeInfo.Instance,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string verificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;
        string issuerDid = issuerDidDocument.Id!.ToString();

        VcalmCredentialIssuance issuance = new()
        {
            ConfiguredIssuer = issuerDid,
            SigningDescriptors = [BuildDescriptor(issuerKeyPair.PrivateKey, verificationMethodId)],
            ExistingProofHandling = VcalmExistingProofHandling.Error,
            SupportsMandatoryPointers = false,
            MemoryPool = Pool
        };

        return new FreshIssuance(issuance, issuerDid, verificationMethodId);
    }


    private static VcalmProofDescriptor BuildDescriptor(PrivateKeyMemory privateKey, string verificationMethodId) =>
        new()
        {
            PrivateKey = privateKey,
            VerificationMethodId = verificationMethodId,
            Cryptosuite = EddsaRdfc2022CryptosuiteInfo.Instance,
            Canonicalize = RdfcCanonicalizer,
            ContextResolver = ContextResolver,
            EncodeProofValue = ProofValueCodecs.EncodeBase58Btc,
            SerializeCredential = SerializeCredential,
            DeserializeCredential = DeserializeCredential,
            SerializeProofOptions = SerializeProofOptions,
            Encoder = TestSetup.Base58Encoder,
            ComputeDigest = MicrosoftEntropyFunctions.ComputeDigestAsync
        };


    private async Task<ServerHttpResponse> DispatchIssueAsync(TestHostShell app, string segment, string body) =>
        await app.DispatchAtEndpointAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmCredentialsIssue,
            "POST",
            new RequestFields(),
            body,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);


    private async Task<JsonDocument> PostIssueAsync(TestHostShell app, string segment, string body, int expectedStatus)
    {
        ServerHttpResponse response = await DispatchIssueAsync(app, segment, body).ConfigureAwait(false);

        Assert.AreEqual(expectedStatus, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    private async Task AssertVerifiedAsync(TestHostShell app, string segment, string securedCredentialJson, bool expected)
    {
        string verifyBody = "{\"verifiableCredential\":" + securedCredentialJson
            + ",\"options\":{\"returnProblemDetails\":true}}";

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmCredentialsVerify,
            "POST",
            new RequestFields(),
            verifyBody,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.AreEqual(expected, doc.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(), response.Body);
    }


    //The verificationMethod id the issued credential's (first) proof was signed with — the cryptographic
    //witness of WHICH tenant's key secured it.
    private static string ProofVerificationMethod(JsonElement verifiableCredential)
    {
        JsonElement proof = verifiableCredential.GetProperty(VcalmParameterNames.Proof);
        JsonElement first = proof.ValueKind == JsonValueKind.Array ? proof[0] : proof;

        return first.GetProperty("verificationMethod").GetString()!;
    }


    //The tenant segment the dispatcher stamped on the request context — the key both the issuance
    //resolver and the issued-credential store scope themselves by. Absence is a fixture error: every
    //dispatched request is tenant-scoped.
    private static string TenantSegment(ExchangeContext context) =>
        context.TenantId is { } tenant
            ? tenant.Value
            : throw new InvalidOperationException("The dispatcher did not stamp a tenant on the request context.");


    private static VerifiableCredential BuildCredential(string issuerDid, string credentialId) =>
        new()
        {
            Context = new Context
            {
                Contexts =
                [
                    Context.Credentials20,
                    CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl
                ]
            },
            Id = credentialId,
            Type = ["VerifiableCredential", "ExampleAlumniCredential"],
            Issuer = new Issuer { Id = issuerDid },
            ValidFrom = "2023-01-01T00:00:00Z",
            ValidUntil = "2030-01-01T00:00:00Z",
            CredentialSubject =
            [
                new CredentialSubject
                {
                    Id = "did:example:alumni-subject",
                    AdditionalData = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["alumniOf"] = "The School of Examples"
                    }
                }
            ]
        };


    private static string BuildIssueRequestBody(string issuerDid, string credentialId) =>
        "{\"credential\":" + SerializeCredential(BuildCredential(issuerDid, credentialId)) + "}";


    //Signs the standard test credential with an ordinary eddsa-rdfc-2022 proof under a fresh did:key
    //issuer, returning the secured-credential JSON — a §3.5.1 derive request needs a SECURED credential
    //to parse (the non-derivable check happens after the resolution null-guard the fail-closed test hits).
    private async Task<string> SignedCredentialJsonAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        using PublicKeyMemory issuerPublic = keyPair.PublicKey;
        using PrivateKeyMemory issuerPrivate = keyPair.PrivateKey;

        DidDocument issuerDidDocument = await KeyDidBuilder.BuildAsync(
            issuerPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        VerifiableCredential credential = BuildCredential(issuerDidDocument.Id!.ToString(), "urn:uuid:no-derive");

        DataIntegritySecuredCredential secured = await credential.SignAsync(
            issuerPrivate,
            issuerDidDocument.VerificationMethod![0].Id!,
            EddsaRdfc2022CryptosuiteInfo.Instance,
            TimeProvider.GetUtcNow().UtcDateTime,
            RdfcCanonicalizer,
            ContextResolver,
            ProofValueCodecs.EncodeBase58Btc,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            Pool,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        return SerializeCredential(secured);
    }


    //The two tenants under test: each tenant's dispatch segment, configured issuer DID, and signing
    //verification method id.
    private sealed record TwoTenants(
        string SegmentA, string IssuerDidA, string VmIdA,
        string SegmentB, string IssuerDidB, string VmIdB);


    //A registered tenant's issuer: the dispatch segment, the configured issuer DID, the signing
    //verification method id, and the §3.2.1 issuance configuration the resolver hands back for it.
    private sealed record TenantIssuer(
        string Segment, string IssuerDid, string VerificationMethodId, VcalmCredentialIssuance Issuance);


    //A freshly-minted issuance configuration and the distinct issuer identity backing it.
    private sealed record FreshIssuance(
        VcalmCredentialIssuance Issuance, string IssuerDid, string VerificationMethodId);


    //Brings up the full showcase host: two tenants each with the issuer, verifier, status, and holder
    //roles, each securing its credentials and status lists under its own issuer key and signing its
    //presentations under its own distinct holder key. §C.1 status-list issuance reuses the per-tenant
    //issuer issuance (§C.1: "the status list credential typically uses the same securing mechanism");
    //§3.5.2 presentations resolve a separate per-tenant holder key. Verification is identity-based and
    //is not wired here — the showcase asserts which key SIGNED each artifact, not round-trip verify.
    private async Task<Showcase> StartShowcaseHostAsync(TestHostShell app)
    {
        VerifierKeyMaterial materialA = app.RegisterClient(
            "https://show-a.client.test", new Uri("https://show-a.client.test"), ShowcaseCapabilities);
        OwnedKeys.Add(materialA);
        FreshIssuance issuerA = await BuildFreshIssuanceAsync().ConfigureAwait(false);
        HolderSigning holderA = await BuildPresentationSigningAsync().ConfigureAwait(false);

        VerifierKeyMaterial materialB = app.RegisterClient(
            "https://show-b.client.test", new Uri("https://show-b.client.test"), ShowcaseCapabilities);
        OwnedKeys.Add(materialB);
        FreshIssuance issuerB = await BuildFreshIssuanceAsync().ConfigureAwait(false);
        HolderSigning holderB = await BuildPresentationSigningAsync().ConfigureAwait(false);

        string segmentA = materialA.Registration.TenantId.Value;
        string segmentB = materialB.Registration.TenantId.Value;

        Dictionary<string, VcalmCredentialIssuance> issuanceBySegment = new(StringComparer.Ordinal)
        {
            [segmentA] = issuerA.Issuance,
            [segmentB] = issuerB.Issuance
        };
        Dictionary<string, VcalmPresentationSigning> signingBySegment = new(StringComparer.Ordinal)
        {
            [segmentA] = holderA.Signing,
            [segmentB] = holderB.Signing
        };

        VcalmIntegration vcalm = app.Server.Vcalm();
        vcalm.UseDefaultVcalmJsonParsing(JsonOptions);

        vcalm.ResolveVcalmCredentialIssuanceAsync = (context, _) =>
            ValueTask.FromResult(issuanceBySegment.GetValueOrDefault(TenantSegment(context)));

        //§C.1 status-list issuance reuses the per-tenant issuer issuance.
        vcalm.ResolveVcalmStatusListIssuanceAsync = vcalm.ResolveVcalmCredentialIssuanceAsync;

        vcalm.ResolveVcalmPresentationSigningAsync = (context, _) =>
            ValueTask.FromResult(signingBySegment.GetValueOrDefault(TenantSegment(context)));

        return new Showcase(
            segmentA, issuerA.IssuerDid, issuerA.VerificationMethodId, holderA.HolderDid, holderA.VerificationMethodId,
            segmentB, issuerB.IssuerDid, issuerB.VerificationMethodId, holderB.HolderDid, holderB.VerificationMethodId);
    }


    //Builds a §3.5.2 presentation-signing configuration backed by a FRESH, distinct Ed25519 holder
    //identity (eddsa-jcs-2022 over a did:key the KeyDidResolver resolves locally). Key material is
    //retained for disposal at cleanup.
    private async Task<HolderSigning> BuildPresentationSigningAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeyPair =
            TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();

        DidDocument holderDidDocument = await KeyDidBuilder.BuildAsync(
            holderKeyPair.PublicKey,
            MultikeyVerificationMethodTypeInfo.Instance,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string verificationMethodId = holderDidDocument.VerificationMethod![0].Id!;
        string holderDid = holderDidDocument.Id!.ToString();

        //The public half is not retained on the signing config; only the private key lives on it.
        holderKeyPair.PublicKey.Dispose();
        OwnedKeys.Add(holderKeyPair.PrivateKey);

        VcalmPresentationSigning signing = new()
        {
            PrivateKey = holderKeyPair.PrivateKey,
            DefaultVerificationMethodId = verificationMethodId,
            Cryptosuite = EddsaJcs2022CryptosuiteInfo.Instance,
            Canonicalize = JcsCanonicalizer,
            ContextResolver = null,
            EncodeProofValue = ProofValueCodecs.EncodeBase58Btc,
            SerializePresentation = SerializePresentation,
            DeserializePresentation = DeserializePresentation,
            SerializeProofOptions = SerializeProofOptions,
            Encoder = TestSetup.Base58Encoder,
            ComputeDigest = MicrosoftEntropyFunctions.ComputeDigestAsync,
            MemoryPool = Pool
        };

        return new HolderSigning(signing, holderDid, verificationMethodId);
    }


    private async Task<JsonDocument> PostCreateStatusListAsync(TestHostShell app, string segment, string statusListId, int expectedStatus)
    {
        string body = "{\"statusPurpose\":\"revocation\",\"id\":\"" + statusListId + "\"}";

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateStatusList, "POST",
            new RequestFields(), body, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedStatus, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    private async Task<JsonDocument> PostCreatePresentationAsync(
        TestHostShell app, string segment, string holderDid, string domain, int expectedStatus)
    {
        string body = "{\"presentation\":" + SerializeUnproofedPresentation(holderDid)
            + ",\"options\":{\"challenge\":\"c-1\",\"domain\":\"" + domain + "\"}}";

        //§3.5.2 binds the proof's domain to the channel domain — the holder refuses a domain that does
        //not match the channel it is presenting over.
        ExchangeContext context = new();
        context.SetCurrentChannelDomain(domain);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreatePresentation, "POST",
            new RequestFields(), body, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedStatus, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    //A minimal unproofed VC-DM 2.0 presentation the §3.5.2 holder endpoint secures.
    private static string SerializeUnproofedPresentation(string holderDid) =>
        SerializePresentation(new VerifiablePresentation
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Type = ["VerifiablePresentation"],
            Holder = holderDid
        });


    //An ExchangeContext stamped with the given tenant segment, for resolution-method tests that do not
    //dispatch (the dispatcher stamps the tenant in the endpoint tests; here it is set directly).
    private static ExchangeContext ContextForTenant(string segment)
    {
        ExchangeContext context = new();
        context.SetTenantId(segment);

        return context;
    }


    //A registered showcase tenant's presentation-signing config plus its holder DID and verification
    //method id.
    private sealed record HolderSigning(
        VcalmPresentationSigning Signing, string HolderDid, string VerificationMethodId);


    //The two tenants of the full showcase: each tenant's dispatch segment, issuer DID + issuer signing
    //verification method, and holder DID + holder signing verification method.
    private sealed record Showcase(
        string SegmentA, string IssuerDidA, string IssuerVmIdA, string HolderDidA, string HolderVmIdA,
        string SegmentB, string IssuerDidB, string IssuerVmIdB, string HolderDidB, string HolderVmIdB);
}
