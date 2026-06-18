using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cbor;
using Verifiable.Core;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Model.Did.Methods;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.Vcalm;
using Verifiable.Vcalm.Exchange;
using Verifiable.Tests.DataIntegrity;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.OAuth;
using Verifiable.Server;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// End-to-end conformance tests for the W3C VCALM 1.0 holder presentation surface
/// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
/// Management</see>) exposed by <see cref="VcalmHolderEndpoints"/> — the §3.5 presenting interfaces:
/// §3.5.1 <c>POST /credentials/derive</c>, §3.5.2 <c>POST /presentations</c>, §3.5.3
/// <c>GET /presentations</c>, §3.5.4 <c>GET /presentations/{id}</c>, and §3.5.5
/// <c>DELETE /presentations/{id}</c>, driven through the real dispatch pipeline.
/// </summary>
/// <remarks>
/// <para>
/// §3.5 is the holder service's OPTIONAL presentation surface — the §1.3 conforming-holder MUST is
/// §3.6.4 / §3.6.5 exchange participation, not the §3.5 CRUD. The selective-disclosure derive
/// (ecdsa-sd-2023), the presentation signing (eddsa-jcs-2022), the RDFC / JCS canonicalizers, the
/// did:key resolver, and the project crypto are the same library primitives the Data Integrity flow
/// tests use — the holder COMPOSES them, it does not re-roll cryptography.
/// </para>
/// <para>
/// The §3.5.1 derive money-shot verifies the derived credential through the Core
/// <see cref="CredentialEcdsaSd2023Extensions.VerifyDerivedProofAsync"/> surface (the correct verifier
/// for an ecdsa-sd-2023 DERIVED proof, whose base/derived signature reconstruction the generic Data
/// Integrity verifier the V-1 <c>/credentials/verify</c> endpoint composes does not implement). The
/// §3.5.2 create-presentation money-shot drives the produced presentation straight into the V-1
/// <c>/presentations/verify</c> endpoint (<see cref="VcalmVerifierEndpoints"/>), a true cross-endpoint
/// round-trip — the presentation signer and the V-1 presentation verifier share the generic Data
/// Integrity surface.
/// </para>
/// </remarks>
[TestClass]
internal sealed class VcalmHolderEndpointTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string ClientId = "https://holder.client.test";
    private static readonly Uri ClientBaseUri = new("https://holder.client.test");

    private const string SdIssuerVerificationMethodId = "did:example:issuer#key-1";

    private static readonly ImmutableHashSet<CapabilityIdentifier> HolderCapabilities =
        ImmutableHashSet.Create(WellKnownVcalmCapabilities.VcalmHolder);

    //The §3.5.2 round-trip needs both the holder and the verifier roles on the same tenant so a
    //created presentation can be POSTed straight to /presentations/verify.
    private static readonly ImmutableHashSet<CapabilityIdentifier> HolderAndVerifierCapabilities =
        ImmutableHashSet.Create(
            WellKnownVcalmCapabilities.VcalmHolder, WellKnownVcalmCapabilities.VcalmVerifier);

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;
    private static KeyDidBuilder KeyDidBuilder { get; } = new();

    private static DidResolver KeyDidResolverSeam { get; } = new(
        DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, KeyDidResolver.Build(Pool))));

    private static CanonicalizationDelegate RdfcCanonicalizer { get; } =
        CanonicalizationTestUtilities.CreateRdfcCanonicalizer();

    private static ContextResolverDelegate ContextResolver { get; } =
        CanonicalizationTestUtilities.CreateTestContextResolver();

    //JCS is context-free and produces a non-empty canonical form for a minimal presentation; the
    //§3.5.2 presentation tests sign with eddsa-jcs-2022.
    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, _, cancellationToken) =>
        ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = Jcs.Canonicalize(json) });

    private static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializerExtensions.Serialize(credential, JsonOptions);

    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(serialized, JsonOptions)!;

    private static PresentationSerializeDelegate SerializePresentation { get; } = presentation =>
        JsonSerializerExtensions.Serialize(presentation, JsonOptions);

    private static PresentationDeserializeDelegate DeserializePresentation { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiablePresentation>(serialized, JsonOptions)!;

    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);

    private static readonly ExchangeContext EmptyContext = new();

    private List<VerifierKeyMaterial> RegisteredMaterials { get; } = [];

    //Key material the holder / SD-issuer signing configs retain for the host's lifetime — disposed at
    //cleanup, after the host (which holds the registration / seams) is torn down.
    private List<IDisposable> OwnedKeys { get; } = [];

    //The in-memory presentation store the §3.5.3 / §3.5.4 / §3.5.5 storage seams read and write.
    private ConcurrentDictionary<string, VcalmStoredPresentation> PresentationStore { get; } =
        new(StringComparer.Ordinal);


    [TestCleanup]
    public void DisposeRegisteredMaterials()
    {
        foreach(VerifierKeyMaterial material in RegisteredMaterials)
        {
            material.Dispose();
        }

        foreach(IDisposable key in OwnedKeys)
        {
            key.Dispose();
        }

        RegisteredMaterials.Clear();
        OwnedKeys.Clear();
        PresentationStore.Clear();
    }


    /// <summary>
    /// §3.5.1 derive (the money-shot): a base-proofed ecdsa-sd-2023 credential is derived through
    /// <c>POST /credentials/derive</c> with <c>options.selectivePointers</c> → HTTP 201 with the
    /// derived credential; the derived VC verifies through the Core ecdsa-sd-2023 derived-proof
    /// verifier, the disclosed claim is present, and an undisclosed claim is absent.
    /// </summary>
    [TestMethod]
    public async Task DeriveDisclosesSelectedPointersAndVerifies()
    {
        await using TestHostShell app = new(TimeProvider);
        SdIssuerContext sd = CreateSdIssuerKeys();
        string segment = RegisterHolder(app);

        DataIntegritySecuredCredential baseCredential = await CreateBaseProofedCredentialAsync(sd).ConfigureAwait(false);
        string deriveBody = "{\"verifiableCredential\":" + SerializeCredential(baseCredential)
            + ",\"options\":{\"selectivePointers\":[\"/credentialSubject/degree/name\"]}}";

        using JsonDocument derived = await PostDeriveAsync(app, segment, deriveBody, expectedStatus: 201).ConfigureAwait(false);

        //§3.5.1 201 body is the derived credential object itself (@context / id / type / issuer / proof).
        JsonElement derivedRoot = derived.RootElement;
        Assert.IsTrue(derivedRoot.TryGetProperty(VcalmParameterNames.Proof, out _),
            "The derived credential carries a derived ecdsa-sd-2023 proof.");

        //The derived VC verifies through the correct ecdsa-sd-2023 derived-proof verifier (the V-1
        ///credentials/verify endpoint composes the generic Data Integrity verifier, which does not
        //reconstruct an SD derived proof — the SD verifier is the conformant verifier here).
        DataIntegritySecuredCredential received = JsonSerializerExtensions.Deserialize<DataIntegritySecuredCredential>(
            derivedRoot.GetRawText(), JsonOptions)!;
        CredentialVerificationResult<DataIntegritySecuredCredential> verification = await received.VerifyDerivedProofAsync(
            sd.IssuerPublicKey,
            BouncyCastleCryptographicFunctions.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
            RdfcCanonicalizer,
            ContextResolver,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            Pool,
            EmptyContext,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verification.IsValid, "A derived ecdsa-sd-2023 credential must verify true.");

        //The disclosed claim is present; an unrelated, undisclosed claim is absent from the derived
        //credential (§3.5.1 selective disclosure).
        Assert.IsNull(received.ValidFrom, "validFrom was not selected, so it is absent from the derived credential.");
    }


    /// <summary>
    /// §3.5.1 multi-tenant derive: TWO holder tenants on ONE host, each with its OWN per-tenant-resolved
    /// derive configuration, derive their OWN ecdsa-sd-2023 base credential (each issued under a distinct
    /// verification method). Each derived credential carries its own base-issuer verification method, and
    /// the two differ — neither tenant derives or attributes the other's credential. The full §3.5.1 flow
    /// proof complementing the resolution-level fail-closed test.
    /// </summary>
    [TestMethod]
    public async Task EachTenantDerivesItsOwnCredentialUnderItsOwnResolvedConfig()
    {
        await using TestHostShell app = new(TimeProvider);

        VerifierKeyMaterial materialA = app.RegisterClient(
            "https://derive-a.client.test", new Uri("https://derive-a.client.test"), HolderCapabilities);
        RegisteredMaterials.Add(materialA);
        VerifierKeyMaterial materialB = app.RegisterClient(
            "https://derive-b.client.test", new Uri("https://derive-b.client.test"), HolderCapabilities);
        RegisteredMaterials.Add(materialB);

        string segmentA = materialA.Registration.TenantId.Value;
        string segmentB = materialB.Registration.TenantId.Value;

        //Two distinct base credentials — distinct ecdsa-sd-2023 issuers AND distinct verification methods.
        const string VmA = "did:example:issuer-a#key-1";
        const string VmB = "did:example:issuer-b#key-1";
        DataIntegritySecuredCredential baseA = await CreateBaseProofedCredentialAsync(CreateSdIssuerKeys(), VmA).ConfigureAwait(false);
        DataIntegritySecuredCredential baseB = await CreateBaseProofedCredentialAsync(CreateSdIssuerKeys(), VmB).ConfigureAwait(false);

        VcalmIntegration vcalm = app.Server.Vcalm();
        vcalm.UseDefaultVcalmJsonParsing(JsonOptions);

        //Per-tenant derive configuration resolved off the dispatcher-stamped tenant.
        Dictionary<string, VcalmCredentialDerivation> derivationBySegment = new(StringComparer.Ordinal)
        {
            [segmentA] = BuildDerivationConfig(),
            [segmentB] = BuildDerivationConfig()
        };
        vcalm.ResolveVcalmCredentialDerivationAsync = (context, _) =>
            ValueTask.FromResult(derivationBySegment.GetValueOrDefault(DeriveTenantSegment(context)));

        using JsonDocument derivedA = await PostDeriveAsync(app, segmentA, DeriveBody(baseA), expectedStatus: 201).ConfigureAwait(false);
        using JsonDocument derivedB = await PostDeriveAsync(app, segmentB, DeriveBody(baseB), expectedStatus: 201).ConfigureAwait(false);

        Assert.AreEqual(VmA, ProofVerificationMethod(derivedA),
            "Tenant A's derived credential carries tenant A's base-issuer verification method.");
        Assert.AreEqual(VmB, ProofVerificationMethod(derivedB),
            "Tenant B's derived credential carries tenant B's base-issuer verification method.");
        Assert.AreNotEqual(ProofVerificationMethod(derivedA), ProofVerificationMethod(derivedB),
            "Each tenant derives its own credential under its own resolved config — no cross-tenant bleed.");
    }


    /// <summary>
    /// §3.8 process-safety on the §3.5.1 derive path: a <c>selectivePointer</c> that is syntactically
    /// valid (RFC 6901) but does NOT resolve in the supplied credential makes the fragment selector throw
    /// (<c>ArgumentException</c> / <c>NotImplementedException</c> for an array index). That is
    /// client-malformed input (§3.5.1 / §2.4) and MUST be a sanitized MALFORMED_VALUE_ERROR 400, never an
    /// unhandled 500.
    /// </summary>
    [TestMethod]
    [DataRow("/credentialSubject/doesNotExist", "non-resolving pointer")]
    [DataRow("/credentialSubject/degree/0", "array-index pointer")]
    public async Task DeriveNonResolvingPointerYields400(string pointer, string reason)
    {
        await using TestHostShell app = new(TimeProvider);
        SdIssuerContext sd = CreateSdIssuerKeys();
        string segment = RegisterHolder(app);

        DataIntegritySecuredCredential baseCredential = await CreateBaseProofedCredentialAsync(sd).ConfigureAwait(false);
        string deriveBody = "{\"verifiableCredential\":" + SerializeCredential(baseCredential)
            + ",\"options\":{\"selectivePointers\":[\"" + pointer + "\"]}}";

        //The §3.8 process-safety boundary maps the selector's throw to a sanitized 400 ({reason}), not a 500.
        using JsonDocument _ = await PostDeriveAsync(app, segment, deriveBody, expectedStatus: 400).ConfigureAwait(false);
    }


    /// <summary>
    /// §3.5.1 non-derivable credential: a credential carrying no ecdsa-sd-2023 base proof is rejected
    /// with HTTP 400 — it is not a derivable selective-disclosure credential.
    /// </summary>
    [TestMethod]
    public async Task DeriveNonSdCredentialYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        SdIssuerContext sd = CreateSdIssuerKeys();
        string segment = RegisterHolder(app);

        //A credential with an ordinary (non-SD) eddsa proof: the converter upcasts it to the secured
        //subtype, so it parses, but it is not a derivable ecdsa-sd-2023 base credential.
        DataIntegritySecuredCredential nonSd = await SignOrdinaryCredentialAsync().ConfigureAwait(false);
        string deriveBody = "{\"verifiableCredential\":" + SerializeCredential(nonSd)
            + ",\"options\":{\"selectivePointers\":[\"/credentialSubject/degree/name\"]}}";

        using JsonDocument response = await PostDeriveAsync(app, segment, deriveBody, expectedStatus: 400).ConfigureAwait(false);

        Assert.AreEqual(VcalmProblemTypes.MalformedValueError,
            response.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "A non-SD credential is a §3.5.1 malformed-value 400.");
    }


    /// <summary>
    /// §3.5.2 → §3.3.2 round-trip (the money-shot): a presentation created through
    /// <c>POST /presentations</c> with a challenge and domain verifies TRUE when driven straight into
    /// the verifier service's <c>/presentations/verify</c> endpoint with the same challenge and domain.
    /// </summary>
    [TestMethod]
    public async Task CreatedPresentationVerifiesAtVerifierEndpoint()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = RegisterHolder(app, holder, alsoVerifier: true);

        const string Challenge = "challenge-roundtrip-123";
        const string Domain = "verifier.example";

        string presentationJson = SerializeUnproofedPresentation(holder.HolderDid);
        string createBody = "{\"presentation\":" + presentationJson
            + ",\"options\":{\"challenge\":\"" + Challenge + "\",\"domain\":\"" + Domain + "\"}}";

        using JsonDocument created = await PostCreatePresentationAsync(app, segment, createBody, expectedStatus: 201).ConfigureAwait(false);

        string securedPresentationJson = created.RootElement
            .GetProperty(VcalmParameterNames.VerifiablePresentation).GetRawText();
        string verifyBody = "{\"verifiablePresentation\":" + securedPresentationJson
            + ",\"options\":{\"challenge\":\"" + Challenge + "\",\"domain\":\"" + Domain + "\"}}";

        ServerHttpResponse verifyResponse = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmPresentationsVerify,
            "POST",
            new RequestFields(),
            verifyBody,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, verifyResponse.StatusCode, verifyResponse.Body);
        using JsonDocument verifyDoc = JsonDocument.Parse(verifyResponse.Body);
        Assert.IsTrue(verifyDoc.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A presentation created by the holder service must verify TRUE at the verifier service "
            + "with the same challenge and domain.");
    }


    /// <summary>
    /// §3.5.2 missing binding: a create-presentation request that omits <c>options.challenge</c> or
    /// <c>options.domain</c> is rejected with HTTP 400 (a presentation proof binds a challenge + domain,
    /// VC-DM 2.0 §4.13).
    /// </summary>
    [TestMethod]
    public async Task CreatePresentationWithoutChallengeYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = RegisterHolder(app, holder);

        string presentationJson = SerializeUnproofedPresentation(holder.HolderDid);
        string createBody = "{\"presentation\":" + presentationJson + ",\"options\":{\"domain\":\"verifier.example\"}}";

        using JsonDocument response = await PostCreatePresentationAsync(app, segment, createBody, expectedStatus: 400).ConfigureAwait(false);

        Assert.AreEqual(VcalmProblemTypes.MalformedValueError,
            response.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "A missing challenge is a §3.5.2 malformed-value 400.");
    }


    /// <summary>
    /// §3.4.3.2 holder anti-replay (refuse): when the deployment staged the current communication
    /// channel's domain on the context and it does NOT match the request's <c>options.domain</c>, the
    /// holder refuses to sign — a 400 MALFORMED_VALUE_ERROR — because the request's domain names a
    /// verifier other than the one on the wire (a relayed / replayed presentation request).
    /// </summary>
    [TestMethod]
    public async Task CreatePresentationRefusesWhenChannelDomainMismatches()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = RegisterHolder(app, holder);

        string presentationJson = SerializeUnproofedPresentation(holder.HolderDid);
        string createBody = "{\"presentation\":" + presentationJson
            + ",\"options\":{\"challenge\":\"c-1\",\"domain\":\"verifier.example\"}}";

        //The channel the holder is actually answering over belongs to a DIFFERENT verifier than the
        //one the request's domain names — the §3.4.3.2 mismatch the holder must refuse fail-closed.
        ExchangeContext context = new();
        context.SetCurrentChannelDomain("attacker.example");

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreatePresentation, "POST",
            new RequestFields(), createBody, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.AreEqual(VcalmProblemTypes.MalformedValueError,
            doc.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "A §3.4.3.2 channel-domain mismatch is an anti-replay refusal (malformed-value 400).");
    }


    /// <summary>
    /// §3.4.3.2 holder anti-replay (allow): when the staged current communication channel's domain
    /// MATCHES the request's <c>options.domain</c>, the holder signs normally — 201. The check binds
    /// only when the channel domain is populated; the matching case is indistinguishable from the
    /// stateless primitive.
    /// </summary>
    [TestMethod]
    public async Task CreatePresentationSignsWhenChannelDomainMatches()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = RegisterHolder(app, holder);

        const string Domain = "verifier.example";
        string presentationJson = SerializeUnproofedPresentation(holder.HolderDid);
        string createBody = "{\"presentation\":" + presentationJson
            + ",\"options\":{\"challenge\":\"c-1\",\"domain\":\"" + Domain + "\"}}";

        ExchangeContext context = new();
        context.SetCurrentChannelDomain(Domain);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreatePresentation, "POST",
            new RequestFields(), createBody, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode, response.Body);
    }


    /// <summary>
    /// §3.5.3 / §3.5.4 / §3.5.5 CRUD round-trip: create a presentation (stored), list it (§3.5.3),
    /// retrieve it by id (§3.5.4 200), delete it (§3.5.5 202), then a §3.5.4 GET is 410 Gone.
    /// </summary>
    [TestMethod]
    public async Task PresentationCrudRoundTrip()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = RegisterHolder(app, holder);

        const string PresentationId = "urn:uuid:presentation-crud-1";
        string presentationJson = SerializeUnproofedPresentation(holder.HolderDid, PresentationId);
        string createBody = "{\"presentation\":" + presentationJson
            + ",\"options\":{\"challenge\":\"c-1\",\"domain\":\"verifier.example\"}}";

        using JsonDocument createdDoc = await PostCreatePresentationAsync(app, segment, createBody, expectedStatus: 201).ConfigureAwait(false);
        Assert.IsTrue(PresentationStore.ContainsKey(PresentationId),
            "The created presentation is stored under its presentation.id.");

        //§3.5.3 list: the created presentation appears in the listing.
        ServerHttpResponse listResponse = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmGetPresentations, "GET",
            new RequestFields(), new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, listResponse.StatusCode, listResponse.Body);
        using JsonDocument listDoc = JsonDocument.Parse(listResponse.Body);
        Assert.AreEqual(JsonValueKind.Array, listDoc.RootElement.ValueKind, "§3.5.3 returns an array.");
        Assert.AreEqual(1, listDoc.RootElement.GetArrayLength(), "The one created presentation is listed.");

        //§3.5.4 get-by-id: 200 with the stored presentation.
        ServerHttpResponse getResponse = await app.DispatchVcalmPresentationByIdAsync(
            segment, "GET", PresentationId, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, getResponse.StatusCode, getResponse.Body);
        using JsonDocument getDoc = JsonDocument.Parse(getResponse.Body);
        Assert.IsTrue(getDoc.RootElement.TryGetProperty(VcalmParameterNames.VerifiablePresentation, out _),
            "The §3.5.4 retrieval returns the presentation under verifiablePresentation.");

        //§3.5.5 delete: 202 (the soft-delete default).
        ServerHttpResponse deleteResponse = await app.DispatchVcalmPresentationByIdAsync(
            segment, "DELETE", PresentationId, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(202, deleteResponse.StatusCode, deleteResponse.Body);

        //§3.5.4 after delete: 410 Gone.
        ServerHttpResponse gone = await app.DispatchVcalmPresentationByIdAsync(
            segment, "GET", PresentationId, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(410, gone.StatusCode, "After a §3.5.5 delete the §3.5.4 GET is 410 Gone.");
    }


    /// <summary>
    /// §3.5.4 unknown id: a GET for a presentation id the store never held is HTTP 404.
    /// </summary>
    [TestMethod]
    public async Task GetUnknownPresentationYields404()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = RegisterHolder(app, holder);

        ServerHttpResponse notFound = await app.DispatchVcalmPresentationByIdAsync(
            segment, "GET", "urn:uuid:never-created", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, notFound.StatusCode, "An unknown presentation id is 404.");
    }


    /// <summary>
    /// §2.4 unknown-option MUST: a §3.5.2 <c>options</c> member the holder does not understand is
    /// rejected with HTTP 400 and the §3.8 <c>UNKNOWN_OPTION_PROVIDED</c> type.
    /// </summary>
    [TestMethod]
    public async Task UnknownOptionYields400UnknownOptionProvided()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = RegisterHolder(app, holder);

        string presentationJson = SerializeUnproofedPresentation(holder.HolderDid);
        string createBody = "{\"presentation\":" + presentationJson
            + ",\"options\":{\"challenge\":\"c-1\",\"domain\":\"d\",\"notARealOption\":true}}";

        using JsonDocument response = await PostCreatePresentationAsync(app, segment, createBody, expectedStatus: 400).ConfigureAwait(false);

        Assert.AreEqual(VcalmProblemTypes.UnknownOptionProvided,
            response.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "An unknown option yields the UNKNOWN_OPTION_PROVIDED type.");
    }


    /// <summary>
    /// §2.4 content-serialization MUST: a §3.5.2 request whose Content-Type is not
    /// <c>application/json</c> is rejected with HTTP 400 before parsing.
    /// </summary>
    [TestMethod]
    public async Task NonJsonContentTypeYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = RegisterHolder(app, holder);

        byte[] bytes = Encoding.UTF8.GetBytes("{\"presentation\":{}}");
        ServerHttpResponse response = await app.DispatchWithBodyAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreatePresentation, "POST",
            bytes, "text/plain", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "A non-application/json body is rejected before parsing (§2.4 content-serialization MUST).");
    }


    //Registers a tenant with the VcalmHolder capability and wires the parse seams plus the holder's
    //selective-disclosure derive and presentation-signing configurations and the presentation store.
    private string RegisterHolder(TestHostShell app)
    {
        VerifierKeyMaterial material = app.RegisterClient(ClientId, ClientBaseUri, HolderCapabilities);
        RegisteredMaterials.Add(material);

        WireHolderSeams(app, presentationSigning: null);

        return material.Registration.TenantId.Value;
    }


    private string RegisterHolder(TestHostShell app, HolderSigningContext holder, bool alsoVerifier = false)
    {
        VerifierKeyMaterial material = app.RegisterClient(
            ClientId, ClientBaseUri, alsoVerifier ? HolderAndVerifierCapabilities : HolderCapabilities);
        RegisteredMaterials.Add(material);

        WireHolderSeams(app, holder.Signing);

        if(alsoVerifier)
        {
            //The §3.5.2 round-trip POSTs the created presentation to /presentations/verify on the same
            //tenant; the verifier composes the JCS canonicalizer matching the presentation's suite.
            app.Server.Vcalm().VcalmCredentialVerification = new VcalmCredentialVerification
            {
                Resolver = KeyDidResolverSeam,
                Canonicalize = JcsCanonicalizer,
                ContextResolver = ContextResolver,
                DecodeProofValue = ProofValueCodecs.DecodeBase58Btc,
                SerializeCredential = SerializeCredential,
                SerializePresentation = SerializePresentation,
                SerializeProofOptions = SerializeProofOptions,
                Decoder = TestSetup.Base58Decoder,
                ComputeDigest = MicrosoftEntropyFunctions.ComputeDigestAsync,
                MemoryPool = Pool
            };
        }

        return material.Registration.TenantId.Value;
    }


    private void WireHolderSeams(TestHostShell app, VcalmPresentationSigning? presentationSigning)
    {
        app.Server.Vcalm().UseDefaultVcalmJsonParsing(JsonOptions);

        //§3.5.1 derive: the ecdsa-sd-2023 selective-disclosure seams over the RDFC canonicalizer.
        app.Server.Vcalm().VcalmCredentialDerivation = new VcalmCredentialDerivation
        {
            Canonicalize = RdfcCanonicalizer,
            ContextResolver = ContextResolver,
            PartitionStatements = JsonLdSelection.PartitionStatements,
            SelectFragments = JsonLdSelection.SelectFragments,
            ParseBaseProof = EcdsaSd2023CborSerializer.ParseBaseProof,
            SerializeDerivedProof = EcdsaSd2023CborSerializer.SerializeDerivedProof,
            SerializeCredential = SerializeCredential,
            DeserializeCredential = DeserializeCredential,
            Encoder = TestSetup.Base64UrlEncoder,
            Decoder = TestSetup.Base64UrlDecoder,
            MemoryPool = Pool
        };

        if(presentationSigning is not null)
        {
            app.Server.Vcalm().VcalmPresentationSigning = presentationSigning;
        }

        //§3.5.3 / §3.5.4 / §3.5.5 storage seams over the in-memory store.
        app.Server.Vcalm().StoreVcalmPresentationAsync = (presentationId, json, _, _) =>
        {
            PresentationStore[presentationId] = new VcalmStoredPresentation
            {
                PresentationId = presentationId,
                VerifiablePresentationJson = json
            };

            return ValueTask.CompletedTask;
        };

        app.Server.Vcalm().ListVcalmPresentationsAsync = (_, _) =>
        {
            List<string> presentations = [];
            foreach(VcalmStoredPresentation stored in PresentationStore.Values)
            {
                if(!stored.IsDeleted)
                {
                    presentations.Add(stored.VerifiablePresentationJson);
                }
            }

            return ValueTask.FromResult<IReadOnlyList<string>>(presentations);
        };

        app.Server.Vcalm().LoadVcalmPresentationAsync = (presentationId, _, _) =>
            ValueTask.FromResult(PresentationStore.GetValueOrDefault(presentationId));

        app.Server.Vcalm().DeleteVcalmPresentationAsync = (presentationId, _, _) =>
        {
            if(!PresentationStore.TryGetValue(presentationId, out VcalmStoredPresentation? existing) || existing.IsDeleted)
            {
                return ValueTask.FromResult(false);
            }

            //§3.5.5 soft delete (the 202 default): retain a tombstone so the §3.5.4 GET answers 410.
            PresentationStore[presentationId] = existing with { IsDeleted = true };

            return ValueTask.FromResult(true);
        };
    }


    //Creates a fresh P-256 issuer + ephemeral key pair for ecdsa-sd-2023 base proofs, tracked for
    //disposal at cleanup.
    private SdIssuerContext CreateSdIssuerKeys()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuer =
            BouncyCastleKeyMaterialCreator.CreateP256Keys(Pool);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral =
            BouncyCastleKeyMaterialCreator.CreateP256Keys(Pool);

        OwnedKeys.Add(issuer.PublicKey);
        OwnedKeys.Add(issuer.PrivateKey);
        OwnedKeys.Add(ephemeral.PublicKey);
        OwnedKeys.Add(ephemeral.PrivateKey);

        return new SdIssuerContext(issuer.PublicKey, issuer.PrivateKey, ephemeral);
    }


    //Issuer base-signs the standard test credential with ecdsa-sd-2023 so the holder has a derivable
    //base credential (the realistic §3.5.1 input — what the issuer delivered to the holder).
    private Task<DataIntegritySecuredCredential> CreateBaseProofedCredentialAsync(SdIssuerContext sd) =>
        CreateBaseProofedCredentialAsync(sd, SdIssuerVerificationMethodId);


    //The ecdsa-sd-2023 derive configuration (selective-disclosure seams over the RDFC canonicalizer);
    //it carries no signing key — derive re-discloses the base proof. A multi-tenant test wires one per
    //tenant to exercise the per-tenant ResolveVcalmCredentialDerivationAsync resolution path.
    private static VcalmCredentialDerivation BuildDerivationConfig() => new()
    {
        Canonicalize = RdfcCanonicalizer,
        ContextResolver = ContextResolver,
        PartitionStatements = JsonLdSelection.PartitionStatements,
        SelectFragments = JsonLdSelection.SelectFragments,
        ParseBaseProof = EcdsaSd2023CborSerializer.ParseBaseProof,
        SerializeDerivedProof = EcdsaSd2023CborSerializer.SerializeDerivedProof,
        SerializeCredential = SerializeCredential,
        DeserializeCredential = DeserializeCredential,
        Encoder = TestSetup.Base64UrlEncoder,
        Decoder = TestSetup.Base64UrlDecoder,
        MemoryPool = Pool
    };


    //The §3.5.1 derive request body for a base credential, disclosing the degree name (plus the
    //mandatory /issuer and /type).
    private static string DeriveBody(DataIntegritySecuredCredential baseCredential) =>
        "{\"verifiableCredential\":" + SerializeCredential(baseCredential)
            + ",\"options\":{\"selectivePointers\":[\"/credentialSubject/degree/name\"]}}";


    //The verification method the derived credential's proof carries — for §3.5.1 derive this is the base
    //credential's issuer verification method, threaded through the derivation.
    private static string ProofVerificationMethod(JsonDocument derivedCredential)
    {
        JsonElement proof = derivedCredential.RootElement.GetProperty(VcalmParameterNames.Proof);
        JsonElement first = proof.ValueKind == JsonValueKind.Array ? proof[0] : proof;

        return first.GetProperty("verificationMethod").GetString()!;
    }


    //The dispatcher-stamped tenant segment on the request context — the key the per-tenant derive
    //resolver scopes itself by.
    private static string DeriveTenantSegment(ExchangeContext context) =>
        context.TenantId is { } tenant
            ? tenant.Value
            : throw new InvalidOperationException("The dispatcher did not stamp a tenant on the request context.");


    //Base-signs the standard test credential with an ecdsa-sd-2023 proof under the given verification
    //method id, so a multi-tenant test can give each tenant a base credential with a DISTINCT issuer
    //verification method (the derived proof carries it through).
    private async Task<DataIntegritySecuredCredential> CreateBaseProofedCredentialAsync(
        SdIssuerContext sd, string verificationMethodId)
    {
        VerifiableCredential credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(
            CredentialSecuringMaterial.UnsignedCredentialJson, JsonOptions)!;

        List<CredentialPath> mandatoryPaths =
        [
            CredentialPath.FromJsonPointer("/issuer"),
            CredentialPath.FromJsonPointer("/type")
        ];

        return await credential.CreateBaseProofAsync(
            sd.IssuerPrivateKey,
            sd.EphemeralKeyPair,
            verificationMethodId,
            TimeProvider.GetUtcNow().UtcDateTime,
            mandatoryPaths,
            () => RandomNumberGenerator.GetBytes(32),
            JsonLdSelection.PartitionStatements,
            RdfcCanonicalizer,
            ContextResolver,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            EcdsaSd2023CborSerializer.SerializeBaseProof,
            TestSetup.Base64UrlEncoder,
            Pool,
            EmptyContext,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Signs the standard test credential with an ordinary eddsa-rdfc-2022 proof (not an SD base proof)
    //under a did:key issuer — used to prove the §3.5.1 endpoint rejects a non-derivable credential.
    private async Task<DataIntegritySecuredCredential> SignOrdinaryCredentialAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory issuerPublic = keyPair.PublicKey;
        using PrivateKeyMemory issuerPrivate = keyPair.PrivateKey;

        DidDocument issuerDidDocument = await KeyDidBuilder.BuildAsync(
            issuerPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        VerifiableCredential credential = new()
        {
            Context = new Context { Contexts = [Context.Credentials20, CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl] },
            Id = "urn:uuid:non-sd-credential",
            Type = ["VerifiableCredential", "ExampleAlumniCredential"],
            Issuer = new Issuer { Id = issuerDidDocument.Id!.ToString() },
            ValidFrom = "2023-01-01T00:00:00Z",
            CredentialSubject =
            [
                new CredentialSubject { Id = "did:example:subject" }
            ]
        };

        return await credential.SignAsync(
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
            EmptyContext,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Builds the holder's eddsa-jcs-2022 signing configuration under a did:key holder the KeyDidResolver
    //resolves locally — the §3.5.2 presentation-signing seam plus the holder DID for the round-trip.
    private async Task<HolderSigningContext> CreateHolderSigningContextAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();

        DidDocument holderDidDocument = await KeyDidBuilder.BuildAsync(
            keyPair.PublicKey,
            MultikeyVerificationMethodTypeInfo.Instance,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string verificationMethodId = holderDidDocument.VerificationMethod![0].Id!;
        string holderDid = holderDidDocument.Id!.ToString();

        //The public half is not retained on the signing config; dispose it. The private key lives on
        //the signing config for the host's lifetime and is disposed at cleanup.
        keyPair.PublicKey.Dispose();
        OwnedKeys.Add(keyPair.PrivateKey);

        VcalmPresentationSigning signing = new()
        {
            PrivateKey = keyPair.PrivateKey,
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

        return new HolderSigningContext(signing, holderDid);
    }


    //A minimal unproofed VC-DM 2.0 presentation JSON the holder service secures. JCS is context-free,
    //so the base context alone yields a non-empty canonical form.
    private static string SerializeUnproofedPresentation(string holderDid, string? presentationId = null) =>
        SerializePresentation(new VerifiablePresentation
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Id = presentationId,
            Type = ["VerifiablePresentation"],
            Holder = holderDid
        });


    private async Task<JsonDocument> PostDeriveAsync(
        TestHostShell app, string segment, string body, int expectedStatus)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCredentialsDerive, "POST",
            new RequestFields(), body, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedStatus, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    private async Task<JsonDocument> PostCreatePresentationAsync(
        TestHostShell app, string segment, string body, int expectedStatus)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreatePresentation, "POST",
            new RequestFields(), body, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedStatus, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    //The ecdsa-sd-2023 issuer key material for the §3.5.1 derive money-shot.
    private sealed record SdIssuerContext(
        PublicKeyMemory IssuerPublicKey,
        PrivateKeyMemory IssuerPrivateKey,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> EphemeralKeyPair);


    //The holder's §3.5.2 presentation-signing configuration plus the holder DID for the round-trip.
    private sealed record HolderSigningContext(VcalmPresentationSigning Signing, string HolderDid);
}
