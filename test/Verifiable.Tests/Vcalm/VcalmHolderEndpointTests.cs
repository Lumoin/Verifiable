using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Cbor;
using Verifiable.Core;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.DataIntegrity;
using Verifiable.Tests.OAuth;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Vcalm;
using Verifiable.Vcalm.Exchange;

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
/// <see cref="CredentialEcdsaSd2023Extensions.VerifyDerivedProofAsync(DataIntegritySecuredCredential, PublicKeyMemory, VerificationDelegate, ParseDerivedProofDelegate, CanonicalizationDelegate, ContextResolverDelegate?, Context, CredentialSerializeDelegate, ProofOptionsSerializeDelegate, EncodeDelegate, DecodeDelegate, BaseMemoryPool, ExchangeContext, CancellationToken)"/> surface (the correct verifier
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
    /// <summary>The MSTest context of the running test; its cancellation token bounds every request in this class.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The fake clock the host and the signing helpers read, fixed at the canonical test epoch.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The memory pool the test-side signing and key material rent from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The client identifier registered with <see cref="TestHostShell"/> for holder requests.</summary>
    private const string ClientId = "https://holder.client.test";

    /// <summary>The base URI registered with <see cref="TestHostShell"/> alongside <see cref="ClientId"/>.</summary>
    private static Uri ClientBaseUri { get; } = new("https://holder.client.test");

    /// <summary>The verification method id the ecdsa-sd-2023 base proofs of this class are issued under.</summary>
    private const string SdIssuerVerificationMethodId = "did:example:issuer#key-1";

    /// <summary>The capabilities the holder tenant is registered with: the VCALM holder role only.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> HolderCapabilities { get; } =
        ImmutableHashSet.Create(WellKnownVcalmCapabilities.VcalmHolder);

    /// <summary>
    /// The holder and verifier roles on one tenant: the §3.5.2 round-trip POSTs a created presentation straight to
    /// <c>/presentations/verify</c>.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> HolderAndVerifierCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownVcalmCapabilities.VcalmHolder, WellKnownVcalmCapabilities.VcalmVerifier);

    /// <summary>The serializer options every credential and presentation in this class is written and read with.</summary>
    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    /// <summary>Builds the did:key documents of the test issuers and holders.</summary>
    private static KeyDidBuilder KeyDidBuilder { get; } = new();

    /// <summary>The did:key resolver seam — derives the controller DID document locally with no network.</summary>
    private static DidResolver KeyDidResolverSeam { get; } = new(
        DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, KeyDidResolver.Build(Pool))));

    /// <summary>The RDFC-1.0 canonicalizer the selective-disclosure proofs are signed and derived with.</summary>
    private static CanonicalizationDelegate RdfcCanonicalizer { get; } =
        CanonicalizationTestUtilities.CreateRdfcCanonicalizer();

    /// <summary>The closed, offline JSON-LD context resolver the RDFC canonicalizer loads contexts through.</summary>
    private static ContextResolverDelegate ContextResolver { get; } =
        CanonicalizationTestUtilities.CreateTestContextResolver();

    /// <summary>The known <c>@context</c> the derived credentials of this class are checked against.</summary>
    private static Context KnownContext { get; } = Context.FromIris(Context.Credentials20, Context.CredentialsExamples20);

    /// <summary>
    /// The JCS canonicalizer the §3.5.2 presentations are signed with (eddsa-jcs-2022): JCS is context-free and
    /// produces a non-empty canonical form for a minimal presentation.
    /// </summary>
    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, _, cancellationToken) =>
        ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = Jcs.Canonicalize(json) });

    /// <summary>Serializes a credential with <see cref="JsonOptions"/>.</summary>
    private static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializerExtensions.Serialize(credential, JsonOptions);

    /// <summary>Deserializes a credential with <see cref="JsonOptions"/>.</summary>
    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(serialized, JsonOptions)!;

    /// <summary>Serializes a presentation with <see cref="JsonOptions"/>.</summary>
    private static PresentationSerializeDelegate SerializePresentation { get; } = presentation =>
        JsonSerializerExtensions.Serialize(presentation, JsonOptions);

    /// <summary>Deserializes a presentation with <see cref="JsonOptions"/>.</summary>
    private static PresentationDeserializeDelegate DeserializePresentation { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiablePresentation>(serialized, JsonOptions)!;

    /// <summary>Serializes a proof options document with <see cref="JsonOptions"/>.</summary>
    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);

    /// <summary>The per-operation context the test-side signing takes; empty, so no network is reachable.</summary>
    private static ExchangeContext EmptyContext { get; } = [];

    /// <summary>The host registrations the test made, disposed at cleanup.</summary>
    private List<VerifierKeyMaterial> RegisteredMaterials { get; } = [];

    /// <summary>
    /// Key material the holder and SD-issuer signing configurations retain for the host's lifetime, disposed at
    /// cleanup after the host, which holds the registration and seams, is torn down.
    /// </summary>
    private List<IDisposable> OwnedKeys { get; } = [];

    /// <summary>The in-memory presentation store the §3.5.3 / §3.5.4 / §3.5.5 storage seams read and write.</summary>
    private ConcurrentDictionary<string, VcalmStoredPresentation> PresentationStore { get; } =
        new(StringComparer.Ordinal);


    /// <summary>Disposes the registrations and key material the test created, and empties the presentation store.</summary>
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
        string segment = await RegisterHolderAsync(app).ConfigureAwait(false);

        DataIntegritySecuredCredential baseCredential = await CreateBaseProofedCredentialAsync(sd).ConfigureAwait(false);
        string deriveBody = "{\"verifiableCredential\":" + SerializeCredential(baseCredential)
            + ",\"options\":{\"selectivePointers\":[\"/credentialSubject/degree/name\"]}}";

        using JsonDocument derived = await PostDeriveAsync(app, segment, deriveBody, expectedStatus: 201).ConfigureAwait(false);

        //§3.5.1 201 body is the derived credential object itself (@context / id / type / issuer / proof).
        JsonElement derivedRoot = derived.RootElement;
        Assert.IsTrue(derivedRoot.TryGetProperty(VcalmParameterNames.Proof, out _),
            "The derived credential carries a derived ecdsa-sd-2023 proof.");

        //The derived VC verifies through the correct ecdsa-sd-2023 derived-proof verifier (the V-1
        //credentials/verify endpoint composes the generic Data Integrity verifier, which does not
        //reconstruct an SD derived proof — the SD verifier is the conformant verifier here).
        DataIntegritySecuredCredential received = JsonSerializerExtensions.Deserialize<DataIntegritySecuredCredential>(
            derivedRoot.GetRawText(), JsonOptions)!;
        CredentialVerificationResult<DataIntegritySecuredCredential> verification = await received.VerifyDerivedProofAsync(
            sd.IssuerPublicKey,
            BouncyCastleCryptographicFunctionsAdapter.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
            RdfcCanonicalizer,
            ContextResolver,
            KnownContext,
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

        VerifierKeyMaterial materialA = await app.RegisterClientAsync(
            "https://derive-a.client.test", new Uri("https://derive-a.client.test"), HolderCapabilities).ConfigureAwait(false);
        RegisteredMaterials.Add(materialA);
        VerifierKeyMaterial materialB = await app.RegisterClientAsync(
            "https://derive-b.client.test", new Uri("https://derive-b.client.test"), HolderCapabilities).ConfigureAwait(false);
        RegisteredMaterials.Add(materialB);

        string segmentA = materialA.Registration.TenantId.Value;
        string segmentB = materialB.Registration.TenantId.Value;

        //Two distinct base credentials — distinct ecdsa-sd-2023 issuers AND distinct verification methods.
        const string VmA = "did:example:issuer-a#key-1";
        const string VmB = "did:example:issuer-b#key-1";
        DataIntegritySecuredCredential baseA = await CreateBaseProofedCredentialAsync(CreateSdIssuerKeys(), VmA).ConfigureAwait(false);
        DataIntegritySecuredCredential baseB = await CreateBaseProofedCredentialAsync(CreateSdIssuerKeys(), VmB).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultVcalmJsonParsing(JsonOptions);
        }).ConfigureAwait(false);

        //Per-tenant derive configuration resolved off the dispatcher-stamped tenant.
        Dictionary<string, VcalmCredentialDerivation> derivationBySegment = new(StringComparer.Ordinal)
        {
            [segmentA] = BuildDerivationConfig(),
            [segmentB] = BuildDerivationConfig()
        };
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmCredentialDerivationAsync = (context, _) =>
                ValueTask.FromResult(derivationBySegment.GetValueOrDefault(DeriveTenantSegment(context)));
        }).ConfigureAwait(false);

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
    [DataRow("/credentialSubject/doesNotExist")]
    [DataRow("/credentialSubject/degree/0")]
    public async Task DeriveNonResolvingPointerYields400(string pointer)
    {
        await using TestHostShell app = new(TimeProvider);
        SdIssuerContext sd = CreateSdIssuerKeys();
        string segment = await RegisterHolderAsync(app).ConfigureAwait(false);

        DataIntegritySecuredCredential baseCredential = await CreateBaseProofedCredentialAsync(sd).ConfigureAwait(false);
        string deriveBody = "{\"verifiableCredential\":" + SerializeCredential(baseCredential)
            + ",\"options\":{\"selectivePointers\":[\"" + pointer + "\"]}}";

        //A non-resolving pointer (missing property or an out-of-range array index) makes the §3.5.1
        //fragment selector throw; the §3.8 process-safety boundary maps that to a sanitized 400, never a 500.
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
        string segment = await RegisterHolderAsync(app).ConfigureAwait(false);

        //A credential with an ordinary (non-SD) eddsa proof: the converter upcasts it to the secured
        //subtype, so it parses, but it is not a derivable ecdsa-sd-2023 base credential.
        DataIntegritySecuredCredential nonSd = await SignOrdinaryCredentialAsync().ConfigureAwait(false);
        string deriveBody = "{\"verifiableCredential\":" + SerializeCredential(nonSd)
            + ",\"options\":{\"selectivePointers\":[\"/credentialSubject/degree/name\"]}}";

        using JsonDocument response = await PostDeriveAsync(app, segment, deriveBody, expectedStatus: 400).ConfigureAwait(false);

        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            response.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "A non-SD credential is a §3.5.1 malformed-value 400.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>: "Implementations MUST throw an error if
    /// an endpoint receives data, options, or option values that it does not understand or know how to process." The
    /// derived proof is built from the base proof's own members, so a base proof missing a
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>
    /// mandatory member is refused with MALFORMED_VALUE_ERROR before any signing, never carried into
    /// the derived credential.
    /// </summary>
    [TestMethod]
    [DataRow("type")]
    [DataRow("verificationMethod")]
    [DataRow("proofPurpose")]
    public async Task DeriveWithIncompleteBaseProofYields400(string member)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterHolderAsync(app).ConfigureAwait(false);

        SdIssuerContext sd = CreateSdIssuerKeys();
        DataIntegritySecuredCredential baseCredential = await CreateBaseProofedCredentialAsync(sd).ConfigureAwait(false);
        string mutatedCredentialJson = DataIntegrityContextTamperingFixture.MutateSecuredDocumentJson(
            SerializeCredential(baseCredential), "delete:proof." + member);
        string deriveBody = "{\"verifiableCredential\":" + mutatedCredentialJson
            + ",\"options\":{\"selectivePointers\":[\"/credentialSubject/degree/name\"]}}";

        using JsonDocument response = await VcalmWireFixtures.PostDeriveWireAsync(
            app, segment, deriveBody, 400, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            response.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            $"A base proof missing {member} is refused before any signing.");
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
        string segment = await RegisterHolderAsync(app, holder, alsoVerifier: true).ConfigureAwait(false);

        const string Challenge = "challenge-roundtrip-123";
        const string Domain = "verifier.example";

        string presentationJson = VcalmWireFixtures.SerializeUnproofedPresentation(holder.HolderDid, SerializePresentation);
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
            [],
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
        string segment = await RegisterHolderAsync(app, holder).ConfigureAwait(false);

        string presentationJson = VcalmWireFixtures.SerializeUnproofedPresentation(holder.HolderDid, SerializePresentation);
        string createBody = "{\"presentation\":" + presentationJson + ",\"options\":{\"domain\":\"verifier.example\"}}";

        using JsonDocument response = await PostCreatePresentationAsync(app, segment, createBody, expectedStatus: 400).ConfigureAwait(false);

        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
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
        string segment = await RegisterHolderAsync(app, holder).ConfigureAwait(false);

        string presentationJson = VcalmWireFixtures.SerializeUnproofedPresentation(holder.HolderDid, SerializePresentation);
        string createBody = "{\"presentation\":" + presentationJson
            + ",\"options\":{\"challenge\":\"c-1\",\"domain\":\"verifier.example\"}}";

        //The channel the holder is actually answering over belongs to a DIFFERENT verifier than the
        //one the request's domain names — the §3.4.3.2 mismatch the holder must refuse fail-closed.
        ExchangeContext context = [];
        context.SetCurrentChannelDomain("attacker.example");

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreatePresentation, "POST",
            new RequestFields(), createBody, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
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
        string segment = await RegisterHolderAsync(app, holder).ConfigureAwait(false);

        const string Domain = "verifier.example";
        string presentationJson = VcalmWireFixtures.SerializeUnproofedPresentation(holder.HolderDid, SerializePresentation);
        string createBody = "{\"presentation\":" + presentationJson
            + ",\"options\":{\"challenge\":\"c-1\",\"domain\":\"" + Domain + "\"}}";

        ExchangeContext context = [];
        context.SetCurrentChannelDomain(Domain);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreatePresentation, "POST",
            new RequestFields(), createBody, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode, response.Body);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>: "Implementations MUST throw an error if
    /// an endpoint receives data, options, or option values that it does not understand or know how to process." The
    /// presentation proof covers every contained credential's existing proof, so a contained credential whose proof is
    /// missing a <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>
    /// mandatory member is refused with MALFORMED_VALUE_ERROR before any signing, never signed over.
    /// </summary>
    [TestMethod]
    [DataRow("type")]
    [DataRow("verificationMethod")]
    [DataRow("proofPurpose")]
    public async Task CreatePresentationWithIncompleteContainedCredentialProofYields400(string member)
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = await RegisterHolderAsync(app, holder).ConfigureAwait(false);

        DataIntegritySecuredCredential contained = await SignOrdinaryCredentialAsync().ConfigureAwait(false);
        string mutatedCredentialJson = DataIntegrityContextTamperingFixture.MutateSecuredDocumentJson(
            SerializeCredential(contained), "delete:proof." + member);

        string presentationJson = "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],"
            + "\"type\":[\"VerifiablePresentation\"],\"holder\":\"" + holder.HolderDid + "\","
            + "\"verifiableCredential\":[" + mutatedCredentialJson + "]}";
        string createBody = "{\"presentation\":" + presentationJson
            + ",\"options\":{\"challenge\":\"c-1\",\"domain\":\"verifier.example\"}}";

        using JsonDocument response = await VcalmWireFixtures.PostCreatePresentationWireAsync(
            app, segment, createBody, 400, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            response.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            $"A contained credential's proof missing {member} is refused before any signing.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>: "Implementations MUST throw an error if
    /// an endpoint receives data, options, or option values that it does not understand or know how to process." The
    /// holder service builds a derived proof from the base proof's own members, so its derivation refuses a base proof
    /// missing its <c>proofPurpose</c>, a member <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data
    /// Integrity §4.4</see> requires of every proof, whoever calls it and before any derivation.
    /// </summary>
    [TestMethod]
    public async Task HolderServiceDerivationRefusesAnIncompleteBaseProof()
    {
        SdIssuerContext sd = CreateSdIssuerKeys();
        DataIntegritySecuredCredential baseCredential = await CreateBaseProofedCredentialAsync(sd).ConfigureAwait(false);
        baseCredential.Proof![0].ProofPurpose = null;

        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(async () => await VcalmHolderService.DeriveAsync(
            baseCredential,
            ["/credentialSubject/degree/name"],
            BuildDerivationConfig(),
            EmptyContext,
            TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>: "Implementations MUST throw an error if
    /// an endpoint receives data, options, or option values that it does not understand or know how to process." The
    /// presentation proof the holder service creates covers every contained credential's existing proof, so the service
    /// refuses a contained credential whose proof is missing its <c>proofPurpose</c>, a member
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see> requires of every
    /// proof, whoever calls it and before any signing.
    /// </summary>
    [TestMethod]
    public async Task HolderServicePresentationRefusesAnIncompleteContainedProof()
    {
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        DataIntegritySecuredCredential contained = await SignOrdinaryCredentialAsync().ConfigureAwait(false);
        contained.Proof![0].ProofPurpose = null;
        VerifiablePresentation presentation = new()
        {
            Context = Context.FromIris(Context.Credentials20),
            Type = ["VerifiablePresentation"],
            Holder = holder.HolderDid,
            VerifiableCredential = [contained]
        };

        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(async () => await VcalmHolderService.CreatePresentationAsync(
            presentation,
            "challenge-service-guard",
            "verifier.example",
            holder.Signing.DefaultVerificationMethodId,
            TimeProvider.GetUtcNow().UtcDateTime,
            holder.Signing,
            EmptyContext,
            TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
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
        string segment = await RegisterHolderAsync(app, holder).ConfigureAwait(false);

        const string PresentationId = "urn:uuid:presentation-crud-1";
        string presentationJson = VcalmWireFixtures.SerializeUnproofedPresentation(holder.HolderDid, SerializePresentation, PresentationId);
        string createBody = "{\"presentation\":" + presentationJson
            + ",\"options\":{\"challenge\":\"c-1\",\"domain\":\"verifier.example\"}}";

        using JsonDocument createdDoc = await PostCreatePresentationAsync(app, segment, createBody, expectedStatus: 201).ConfigureAwait(false);
        Assert.IsTrue(PresentationStore.ContainsKey(PresentationId),
            "The created presentation is stored under its presentation.id.");

        //§3.5.3 list: the created presentation appears in the listing.
        ServerHttpResponse listResponse = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmGetPresentations, "GET",
            new RequestFields(), [], TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, listResponse.StatusCode, listResponse.Body);
        using JsonDocument listDoc = JsonDocument.Parse(listResponse.Body);
        Assert.AreEqual(JsonValueKind.Array, listDoc.RootElement.ValueKind, "§3.5.3 returns an array.");
        Assert.AreEqual(1, listDoc.RootElement.GetArrayLength(), "The one created presentation is listed.");

        //§3.5.4 get-by-id: 200 with the stored presentation.
        ServerHttpResponse getResponse = await app.DispatchVcalmPresentationByIdAsync(
            segment, "GET", PresentationId, [], TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, getResponse.StatusCode, getResponse.Body);
        using JsonDocument getDoc = JsonDocument.Parse(getResponse.Body);
        Assert.IsTrue(getDoc.RootElement.TryGetProperty(VcalmParameterNames.VerifiablePresentation, out _),
            "The §3.5.4 retrieval returns the presentation under verifiablePresentation.");

        //§3.5.5 delete: 202 (the soft-delete default).
        ServerHttpResponse deleteResponse = await app.DispatchVcalmPresentationByIdAsync(
            segment, "DELETE", PresentationId, [], TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(202, deleteResponse.StatusCode, deleteResponse.Body);

        //§3.5.4 after delete: 410 Gone.
        ServerHttpResponse gone = await app.DispatchVcalmPresentationByIdAsync(
            segment, "GET", PresentationId, [], TestContext.CancellationToken).ConfigureAwait(false);
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
        string segment = await RegisterHolderAsync(app, holder).ConfigureAwait(false);

        ServerHttpResponse notFound = await app.DispatchVcalmPresentationByIdAsync(
            segment, "GET", "urn:uuid:never-created", [], TestContext.CancellationToken).ConfigureAwait(false);

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
        string segment = await RegisterHolderAsync(app, holder).ConfigureAwait(false);

        string presentationJson = VcalmWireFixtures.SerializeUnproofedPresentation(holder.HolderDid, SerializePresentation);
        string createBody = "{\"presentation\":" + presentationJson
            + ",\"options\":{\"challenge\":\"c-1\",\"domain\":\"d\",\"notARealOption\":true}}";

        using JsonDocument response = await PostCreatePresentationAsync(app, segment, createBody, expectedStatus: 400).ConfigureAwait(false);

        Assert.AreEqual("https://www.w3.org/TR/vcalm#UNKNOWN_OPTION_PROVIDED",
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
        string segment = await RegisterHolderAsync(app, holder).ConfigureAwait(false);

        byte[] bytes = Encoding.UTF8.GetBytes("{\"presentation\":{}}");
        ServerHttpResponse response = await app.DispatchWithBodyAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreatePresentation, "POST",
            bytes, "text/plain", [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "A non-application/json body is rejected before parsing (§2.4 content-serialization MUST).");
    }


    /// <summary>
    /// Registers a tenant with the VCALM holder capability and wires the parse seams, the holder's selective-disclosure
    /// derive configuration and the presentation store, with no presentation signing.
    /// </summary>
    /// <param name="app">The host shell the tenant is registered with.</param>
    /// <returns>The tenant segment.</returns>
    private async Task<string> RegisterHolderAsync(TestHostShell app)
    {
        VerifierKeyMaterial material = await app.RegisterClientAsync(ClientId, ClientBaseUri, HolderCapabilities).ConfigureAwait(false);
        RegisteredMaterials.Add(material);

        await WireHolderSeamsAsync(app, presentationSigning: null).ConfigureAwait(false);

        return material.Registration.TenantId.Value;
    }


    /// <summary>
    /// Registers a holder with the capabilities and delegates needed by the presentation cases.
    /// </summary>
    private async Task<string> RegisterHolderAsync(TestHostShell app, HolderSigningContext holder, bool alsoVerifier = false)
    {
        VerifierKeyMaterial material = await app.RegisterClientAsync(
            ClientId, ClientBaseUri, alsoVerifier ? HolderAndVerifierCapabilities : HolderCapabilities).ConfigureAwait(false);
        RegisteredMaterials.Add(material);

        await WireHolderSeamsAsync(app, holder.Signing).ConfigureAwait(false);

        if(alsoVerifier)
        {
            //The §3.5.2 round-trip POSTs the created presentation to /presentations/verify on the same
            //tenant; the verifier composes the JCS canonicalizer matching the presentation's suite.
            await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
            {
                candidateIntegration.VcalmCredentialVerification = new VcalmCredentialVerification
                {
                    Resolver = KeyDidResolverSeam,
                    Canonicalize = JcsCanonicalizer,
                    ContextResolver = ContextResolver,
                    KnownContext = VcalmWireFixtures.PresentationKnownContext,
                    DecodeProofValue = ProofValueCodecs.DecodeBase58Btc,
                    SerializeCredential = SerializeCredential,
                    SerializePresentation = SerializePresentation,
                    SerializeProofOptions = SerializeProofOptions,
                    Decoder = TestSetup.Base58Decoder,
                    ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
                    MemoryPool = Pool
                };
            }).ConfigureAwait(false);
        }

        return material.Registration.TenantId.Value;
    }


    /// <summary>
    /// Installs credential derivation and presentation storage delegates on the holder wiring.
    /// </summary>
    private async Task WireHolderSeamsAsync(TestHostShell app, VcalmPresentationSigning? presentationSigning)
    {
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultVcalmJsonParsing(JsonOptions);
        }).ConfigureAwait(false);

        //§3.5.1 derive: the ecdsa-sd-2023 selective-disclosure seams over the RDFC canonicalizer.
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.VcalmCredentialDerivation = new VcalmCredentialDerivation
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
        }).ConfigureAwait(false);

        if(presentationSigning is not null)
        {
            await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
            {
                candidateIntegration.VcalmPresentationSigning = presentationSigning;
            }).ConfigureAwait(false);
        }

        //§3.5.3 / §3.5.4 / §3.5.5 storage seams over the in-memory store.
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.StoreVcalmPresentationAsync = (presentationId, json, _, _) =>
            {
                PresentationStore[presentationId] = new VcalmStoredPresentation
                {
                    PresentationId = presentationId,
                    VerifiablePresentationJson = json
                };

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ListVcalmPresentationsAsync = (_, _) =>
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
        }).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.LoadVcalmPresentationAsync = (presentationId, _, _) =>
                ValueTask.FromResult(PresentationStore.GetValueOrDefault(presentationId));
        }).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.DeleteVcalmPresentationAsync = (presentationId, _, _) =>
            {
                if(!PresentationStore.TryGetValue(presentationId, out VcalmStoredPresentation? existing) || existing.IsDeleted)
                {

                    return ValueTask.FromResult(false);
                }

                //§3.5.5 soft delete (the 202 default): retain a tombstone so the §3.5.4 GET answers 410.
                PresentationStore[presentationId] = existing with { IsDeleted = true };

                return ValueTask.FromResult(true);
            };
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// Creates a fresh P-256 issuer and ephemeral key pair for ecdsa-sd-2023 base proofs, tracked for disposal at
    /// cleanup.
    /// </summary>
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


    /// <summary>
    /// Base-signs the standard test credential with ecdsa-sd-2023 under <see cref="SdIssuerVerificationMethodId"/>, so
    /// the holder has a derivable base credential: the realistic §3.5.1 input, what the issuer delivered to the holder.
    /// </summary>
    /// <param name="sd">The issuer and ephemeral key material.</param>
    private Task<DataIntegritySecuredCredential> CreateBaseProofedCredentialAsync(SdIssuerContext sd) =>
        CreateBaseProofedCredentialAsync(sd, SdIssuerVerificationMethodId);


    /// <summary>
    /// The ecdsa-sd-2023 derive configuration: the selective-disclosure seams over the RDFC canonicalizer. It carries no
    /// signing key, since derive re-discloses the base proof; a multi-tenant test wires one per tenant to exercise the
    /// per-tenant derivation resolution path.
    /// </summary>
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


    /// <summary>
    /// The §3.5.1 derive request body for a base credential, disclosing the degree name besides the mandatory
    /// <c>/issuer</c> and <c>/type</c>.
    /// </summary>
    /// <param name="baseCredential">The base-proofed credential to derive from.</param>
    private static string DeriveBody(DataIntegritySecuredCredential baseCredential) =>
        "{\"verifiableCredential\":" + SerializeCredential(baseCredential)
            + ",\"options\":{\"selectivePointers\":[\"/credentialSubject/degree/name\"]}}";


    /// <summary>
    /// The verification method the derived credential's proof carries: for §3.5.1 derive, the base credential's issuer
    /// verification method, threaded through the derivation.
    /// </summary>
    /// <param name="derivedCredential">The parsed derived credential.</param>
    private static string ProofVerificationMethod(JsonDocument derivedCredential)
    {
        JsonElement proof = derivedCredential.RootElement.GetProperty(VcalmParameterNames.Proof);
        JsonElement first = proof.ValueKind == JsonValueKind.Array ? proof[0] : proof;

        return first.GetProperty("verificationMethod").GetString()!;
    }


    /// <summary>
    /// The dispatcher-stamped tenant segment on the request context, the key the per-tenant derive resolver scopes
    /// itself by.
    /// </summary>
    /// <param name="context">The per-request context the dispatcher stamped.</param>
    private static string DeriveTenantSegment(ExchangeContext context) =>
        context.TenantId is { } tenant
            ? tenant.Value
            : throw new InvalidOperationException("The dispatcher did not stamp a tenant on the request context.");


    /// <summary>
    /// Base-signs the standard test credential with an ecdsa-sd-2023 proof under <paramref name="verificationMethodId"/>,
    /// so a multi-tenant test can give each tenant a base credential with a DISTINCT issuer verification method, which
    /// the derived proof carries through.
    /// </summary>
    /// <param name="sd">The issuer and ephemeral key material.</param>
    /// <param name="verificationMethodId">The verification method id the base proof names.</param>
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
            DataIntegrityContextTamperingFixture.GenerateSelectiveDisclosureHmacKey,
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


    /// <summary>
    /// Signs the standard test credential with an ordinary eddsa-rdfc-2022 proof, not a selective-disclosure base
    /// proof, under a did:key issuer: the §3.5.1 endpoint rejects such a credential as non-derivable.
    /// </summary>
    private async Task<DataIntegritySecuredCredential> SignOrdinaryCredentialAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory issuerPublic = keyPair.PublicKey;
        using PrivateKeyMemory issuerPrivate = keyPair.PrivateKey;

        DidDocument issuerDidDocument = await KeyDidBuilder.BuildAsync(
            issuerPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            BaseMemoryPool.Shared,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        VerifiableCredential credential = new()
        {
            Context = Context.FromIris(Context.Credentials20, CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl),
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
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            Pool,
            EmptyContext,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds the holder's eddsa-jcs-2022 signing configuration under a did:key holder the did:key resolver resolves
    /// locally: the §3.5.2 presentation-signing seam plus the holder DID for the round-trip.
    /// </summary>
    private async Task<HolderSigningContext> CreateHolderSigningContextAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();

        DidDocument holderDidDocument = await KeyDidBuilder.BuildAsync(
            keyPair.PublicKey,
            MultikeyVerificationMethodTypeInfo.Instance,
            BaseMemoryPool.Shared,
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
            ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            MemoryPool = Pool
        };

        return new HolderSigningContext(signing, holderDid);
    }


    /// <summary>
    /// Dispatches a §3.5.1 derive request in process through the host's dispatcher and returns the parsed body after
    /// checking its status.
    /// </summary>
    /// <param name="app">The host shell whose dispatcher serves the request.</param>
    /// <param name="segment">The holder tenant segment.</param>
    /// <param name="body">The derive request body JSON text.</param>
    /// <param name="expectedStatus">The HTTP status the response must carry.</param>
    private async Task<JsonDocument> PostDeriveAsync(
        TestHostShell app, string segment, string body, int expectedStatus)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCredentialsDerive, "POST",
            new RequestFields(), body, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedStatus, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    /// <summary>
    /// Dispatches a §3.5.2 create-presentation request in process through the host's dispatcher and returns the
    /// parsed body after checking its status.
    /// </summary>
    /// <param name="app">The host shell whose dispatcher serves the request.</param>
    /// <param name="segment">The holder tenant segment.</param>
    /// <param name="body">The create-presentation request body JSON text.</param>
    /// <param name="expectedStatus">The HTTP status the response must carry.</param>
    private async Task<JsonDocument> PostCreatePresentationAsync(
        TestHostShell app, string segment, string body, int expectedStatus)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreatePresentation, "POST",
            new RequestFields(), body, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedStatus, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    /// <summary>The ecdsa-sd-2023 issuer key material the §3.5.1 derive cases base-sign with.</summary>
    /// <param name="IssuerPublicKey">The issuer's public key.</param>
    /// <param name="IssuerPrivateKey">The issuer key that signs the base proof.</param>
    /// <param name="EphemeralKeyPair">The per-proof key pair that signs the disclosed statements.</param>
    private sealed record SdIssuerContext(
        PublicKeyMemory IssuerPublicKey,
        PrivateKeyMemory IssuerPrivateKey,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> EphemeralKeyPair);


    /// <summary>The holder's §3.5.2 presentation-signing configuration plus the holder DID for the round-trip.</summary>
    /// <param name="Signing">The presentation-signing configuration.</param>
    /// <param name="HolderDid">The holder DID the presentations claim.</param>
    private sealed record HolderSigningContext(VcalmPresentationSigning Signing, string HolderDid);
}
