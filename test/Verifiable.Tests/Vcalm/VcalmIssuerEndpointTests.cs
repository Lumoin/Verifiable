using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Resolvers;
using Verifiable.Core.Validation;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.OAuth;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Vcalm;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// End-to-end conformance tests for the W3C VCALM 1.0 issuer service
/// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
/// Management</see>) exposed by <see cref="VcalmIssuerEndpoints"/> — the §3.2.1
/// <c>POST /credentials/issue</c>, §3.2.2 <c>GET /credentials/{id}</c>, and §3.2.3
/// <c>DELETE /credentials/{id}</c> endpoints, driven through the real dispatch pipeline. The
/// issue→verify round-trip drives the issued credential straight back into the §3.3.1
/// <c>/credentials/verify</c> endpoint (<see cref="VcalmVerifierEndpoints"/>).
/// </summary>
/// <remarks>
/// The signing key, the cryptosuite (eddsa-rdfc-2022), the RDFC canonicalizer, the did:key resolver,
/// and the project crypto are the same library primitives the Data Integrity flow tests use — the
/// issuer COMPOSES them, it does not re-roll cryptography.
/// </remarks>
[TestClass]
internal sealed class VcalmIssuerEndpointTests
{
    /// <summary>The MSTest context of the running test; its cancellation token bounds every request in this class.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The fake clock the host and the signing helpers read, fixed at the canonical test epoch.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The memory pool the test-side signing and key material rent from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The client identifier registered with <see cref="TestHostShell"/> for issuer requests.</summary>
    private const string ClientId = "https://issuer.client.test";

    /// <summary>The base URI registered with <see cref="TestHostShell"/> alongside <see cref="ClientId"/>.</summary>
    private static Uri ClientBaseUri { get; } = new("https://issuer.client.test");

    /// <summary>The capabilities the issuer tenant is registered with: the VCALM issuer role only.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> IssuerCapabilities { get; } =
        ImmutableHashSet.Create(WellKnownVcalmCapabilities.VcalmIssuer);

    /// <summary>
    /// The issuer and verifier roles on one tenant: the round-trip tests POST an issued credential straight to
    /// <c>/credentials/verify</c>.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> IssuerAndVerifierCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownVcalmCapabilities.VcalmIssuer, WellKnownVcalmCapabilities.VcalmVerifier);

    /// <summary>The serializer options every credential in this class is written and read with.</summary>
    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    /// <summary>Builds the did:key documents of the test issuers.</summary>
    private static KeyDidBuilder KeyDidBuilder { get; } = new();

    /// <summary>The did:key resolver seam — derives the controller DID document locally with no network.</summary>
    private static DidResolver KeyDidResolverSeam { get; } = new(
        DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, KeyDidResolver.Build(Pool))));

    /// <summary>The RDFC-1.0 canonicalizer the eddsa-rdfc-2022 credentials are signed and verified with.</summary>
    private static CanonicalizationDelegate RdfcCanonicalizer { get; } =
        CanonicalizationTestUtilities.CreateRdfcCanonicalizer();

    /// <summary>The closed, offline JSON-LD context resolver the RDFC canonicalizer loads contexts through.</summary>
    private static ContextResolverDelegate ContextResolver { get; } =
        CanonicalizationTestUtilities.CreateTestContextResolver();

    /// <summary>Serializes a credential with <see cref="JsonOptions"/>.</summary>
    private static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializerExtensions.Serialize(credential, JsonOptions);

    /// <summary>Deserializes a credential with <see cref="JsonOptions"/>.</summary>
    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(serialized, JsonOptions)!;

    /// <summary>Serializes a proof options document with <see cref="JsonOptions"/>.</summary>
    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);

    /// <summary>The per-operation context the test-side signing takes; empty, so no network is reachable.</summary>
    private static ExchangeContext EmptyContext { get; } = [];

    /// <summary>
    /// The key material the test registered: the configured issuer identity's signing keys and the host
    /// registrations, disposed at cleanup. The verification method id and DID derive from the issuer key.
    /// </summary>
    private List<IssuerKeyMaterial> RegisteredMaterials { get; } = [];

    /// <summary>The in-memory issued-credential store the §3.2.2 / §3.2.3 storage seams read and write.</summary>
    private ConcurrentDictionary<string, VcalmStoredCredential> CredentialStore { get; } =
        new(StringComparer.Ordinal);


    /// <summary>Disposes the key material the test registered, and empties the issued-credential store.</summary>
    [TestCleanup]
    public void DisposeRegisteredMaterials()
    {
        foreach(IssuerKeyMaterial material in RegisteredMaterials)
        {
            material.Dispose();
        }

        RegisteredMaterials.Clear();
        CredentialStore.Clear();
    }


    /// <summary>
    /// §3.2.1 happy path: a valid issue request returns HTTP 201 with a Data-Integrity-secured
    /// credential under <c>verifiableCredential</c>, and that credential carries exactly one proof.
    /// </summary>
    [TestMethod]
    public async Task IssueReturns201SecuredCredential()
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(app).ConfigureAwait(false);

        string body = VcalmWireFixtures.BuildIssueRequestBody(ctx.IssuerDid, credentialId: "urn:uuid:issued-credential-1", SerializeCredential);

        using JsonDocument response = await PostIssueAsync(app, ctx.Segment, body, expectedStatus: 201).ConfigureAwait(false);

        JsonElement vc = response.RootElement.GetProperty(VcalmParameterNames.VerifiableCredential);
        JsonElement proof = vc.GetProperty(VcalmParameterNames.Proof);

        //The Data Integrity proof chain serializes as an array; a single-descriptor issuance yields a
        //one-element array carrying the DataIntegrityProof.
        JsonElement firstProof = proof.ValueKind == JsonValueKind.Array ? proof[0] : proof;
        Assert.AreEqual("DataIntegrityProof", firstProof.GetProperty("type").GetString(),
            "The issued credential carries a Data Integrity proof.");
        if(proof.ValueKind == JsonValueKind.Array)
        {
            Assert.AreEqual(1, proof.GetArrayLength(), "A single-descriptor issuance attaches one proof.");
        }
    }


    /// <summary>
    /// §3.2.1 → §3.3.1 round-trip (the money shot): a credential issued by the issuer service verifies
    /// TRUE when driven straight into the verifier service's <c>/credentials/verify</c> endpoint.
    /// </summary>
    [TestMethod]
    public async Task IssuedCredentialVerifiesAtVerifierEndpoint()
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(app, alsoVerifier: true).ConfigureAwait(false);

        //Wire the verification seams so the issued credential can be POSTed straight to
        //credentials/verify on the same tenant (the registration already allows both roles).
        await WireVerificationSeamAsync(app).ConfigureAwait(false);

        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(ctx.IssuerDid, credentialId: "urn:uuid:roundtrip-1", SerializeCredential);
        using JsonDocument issued = await PostIssueAsync(app, ctx.Segment, issueBody, expectedStatus: 201).ConfigureAwait(false);

        string securedCredentialJson = issued.RootElement.GetProperty(VcalmParameterNames.VerifiableCredential).GetRawText();
        string verifyBody = "{\"verifiableCredential\":" + securedCredentialJson + ",\"options\":{\"returnProblemDetails\":true}}";

        ServerHttpResponse verifyResponse = await app.DispatchAtEndpointAsync(
            ctx.Segment,
            WellKnownVcalmEndpointNames.VcalmCredentialsVerify,
            "POST",
            new RequestFields(),
            verifyBody,
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, verifyResponse.StatusCode, verifyResponse.Body);
        using JsonDocument verifyDoc = JsonDocument.Parse(verifyResponse.Body);
        Assert.IsTrue(verifyDoc.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A credential issued by the issuer service must verify TRUE at the verifier service.");
    }


    /// <summary>
    /// §3.2.1 issuer-mismatch 400: a credential whose <c>issuer</c> does not match the instance's
    /// configured identity is rejected ("The provided value of 'issuer' does not match the expected
    /// configuration.").
    /// </summary>
    [TestMethod]
    public async Task IssuerMismatchYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(app).ConfigureAwait(false);

        string body = VcalmWireFixtures.BuildIssueRequestBody(issuerDid: "did:example:not-this-instance", credentialId: "urn:uuid:mismatch", SerializeCredential);

        using JsonDocument response = await PostIssueAsync(app, ctx.Segment, body, expectedStatus: 400).ConfigureAwait(false);

        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            response.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "An issuer mismatch is a §3.2.1 malformed-value 400.");
    }


    /// <summary>
    /// §3.2.1 structural validation: the issuer MUST NOT secure a credential that is not a valid
    /// VC-DM credential. A credential missing a non-empty <c>@context</c>, a <c>type</c> containing
    /// <c>VerifiableCredential</c>, an <c>issuer</c>, or a <c>credentialSubject</c> is a 400, not a
    /// signed-but-invalid credential.
    /// </summary>
    [TestMethod]
    [DataRow("{\"type\":[\"VerifiableCredential\"],\"issuer\":\"ISSUER\",\"credentialSubject\":{\"id\":\"did:example:s\"}}", "missing @context")]
    [DataRow("{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"issuer\":\"ISSUER\",\"credentialSubject\":{\"id\":\"did:example:s\"}}", "missing type")]
    [DataRow("{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"Other\"],\"issuer\":\"ISSUER\",\"credentialSubject\":{\"id\":\"did:example:s\"}}", "type without VerifiableCredential")]
    [DataRow("{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiableCredential\"],\"issuer\":\"ISSUER\"}", "missing credentialSubject")]
    [DataRow("{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiableCredential\"],\"credentialSubject\":{\"id\":\"did:example:s\"}}", "missing issuer")]
    public async Task StructurallyInvalidCredentialYields400(string credentialTemplate, string reason)
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(app).ConfigureAwait(false);

        string credentialJson = credentialTemplate.Replace("ISSUER", ctx.IssuerDid, StringComparison.Ordinal);
        string body = "{\"credential\":" + credentialJson + "}";

        using JsonDocument response = await PostIssueAsync(app, ctx.Segment, body, expectedStatus: 400).ConfigureAwait(false);

        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            response.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            $"A structurally invalid credential ({reason}) is a §3.2.1 malformed-value 400.");
    }


    /// <summary>
    /// §3.2.1 wire-shape validation: the issuer MUST reject a credential whose core members carry the
    /// wrong JSON type, not silently coerce them. <c>@context</c> and <c>type</c> MUST be arrays,
    /// <c>issuer</c> MUST be a string or an object, and <c>credentialSubject</c> MUST be an object (or
    /// an array of objects). These are the exact type-coercion vectors the external W3C
    /// <c>vc-api-issuer-test-suite</c> drives ("credential '@context' MUST be an array", "'credential.type'
    /// MUST be an array", "'credential.issuer' MUST be a string or an object", "'credential.credentialSubject'
    /// MUST be an object"); each MUST be a §3.2.1 malformed-value 400, never a signed credential.
    /// </summary>
    [TestMethod]
    [DataRow("{\"@context\":4,\"type\":[\"VerifiableCredential\"],\"issuer\":\"ISSUER\",\"credentialSubject\":{\"id\":\"did:example:s\"}}", "@context is a number")]
    [DataRow("{\"@context\":{\"foo\":true},\"type\":[\"VerifiableCredential\"],\"issuer\":\"ISSUER\",\"credentialSubject\":{\"id\":\"did:example:s\"}}", "@context is an object")]
    [DataRow("{\"@context\":\"https://www.w3.org/ns/credentials/v2\",\"type\":[\"VerifiableCredential\"],\"issuer\":\"ISSUER\",\"credentialSubject\":{\"id\":\"did:example:s\"}}", "@context is a bare string")]
    [DataRow("{\"@context\":false,\"type\":[\"VerifiableCredential\"],\"issuer\":\"ISSUER\",\"credentialSubject\":{\"id\":\"did:example:s\"}}", "@context is a bool")]
    [DataRow("{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":4,\"issuer\":\"ISSUER\",\"credentialSubject\":{\"id\":\"did:example:s\"}}", "type is a number")]
    [DataRow("{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":\"VerifiableCredential\",\"issuer\":\"ISSUER\",\"credentialSubject\":{\"id\":\"did:example:s\"}}", "type is a bare string")]
    [DataRow("{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[4],\"issuer\":\"ISSUER\",\"credentialSubject\":{\"id\":\"did:example:s\"}}", "type item is a number")]
    [DataRow("{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiableCredential\"],\"issuer\":4,\"credentialSubject\":{\"id\":\"did:example:s\"}}", "issuer is a number")]
    [DataRow("{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiableCredential\"],\"issuer\":true,\"credentialSubject\":{\"id\":\"did:example:s\"}}", "issuer is a bool")]
    [DataRow("{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiableCredential\"],\"issuer\":[],\"credentialSubject\":{\"id\":\"did:example:s\"}}", "issuer is an array")]
    [DataRow("{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiableCredential\"],\"issuer\":\"ISSUER\",\"credentialSubject\":\"did:example:1234\"}", "credentialSubject is a string")]
    [DataRow("{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiableCredential\"],\"issuer\":\"ISSUER\",\"credentialSubject\":4}", "credentialSubject is a number")]
    [DataRow("{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiableCredential\"],\"issuer\":\"ISSUER\",\"credentialSubject\":true}", "credentialSubject is a bool")]
    [DataRow("{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiableCredential\"],\"issuer\":\"ISSUER\",\"credentialSubject\":[]}", "credentialSubject is an empty array")]
    public async Task TypeCoercedCredentialFieldYields400(string credentialTemplate, string reason)
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(app).ConfigureAwait(false);

        string credentialJson = credentialTemplate.Replace("ISSUER", ctx.IssuerDid, StringComparison.Ordinal);
        string body = "{\"credential\":" + credentialJson + "}";

        using JsonDocument response = await PostIssueAsync(app, ctx.Segment, body, expectedStatus: 400).ConfigureAwait(false);

        //A wrong-typed core member is a malformed credential, never a signed result; the response is the
        //§3.8 problem detail (the suite only requires a 4xx, but the type pins WHY it was rejected).
        Assert.IsTrue(response.RootElement.TryGetProperty(VcalmParameterNames.ProblemType, out _),
            $"A type-coerced credential ({reason}) is rejected with a §3.8 problem detail, not signed.");
    }


    /// <summary>
    /// §3.8 process-safety on the §3.2.1 issue path: a credential that is well-formed JSON and passes
    /// structural validation but that the Data Integrity signer cannot canonicalize — a non-string
    /// <c>@context</c> array item, or an unresolvable <c>@context</c> URL — MUST be a sanitized §3.8.1
    /// MALFORMED_VALUE_ERROR 400, never an unhandled 500 that leaks the canonicalizer exception. The
    /// soundness invariant (never sign an invalid credential) already held; this pins the error surface.
    /// </summary>
    [TestMethod]
    [DataRow("{\"@context\":[\"https://www.w3.org/ns/credentials/v2\",4],\"type\":[\"VerifiableCredential\"],\"issuer\":\"ISSUER\",\"credentialSubject\":{\"id\":\"did:example:s\"}}", "non-string @context item")]
    [DataRow("{\"@context\":[\"https://www.w3.org/ns/credentials/v2\",\"https://unresolvable.invalid/ctx\"],\"type\":[\"VerifiableCredential\"],\"issuer\":\"ISSUER\",\"credentialSubject\":{\"id\":\"did:example:s\"}}", "unresolvable @context URL")]
    public async Task UnsignableCredentialYields400(string credentialTemplate, string reason)
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(app).ConfigureAwait(false);

        string credentialJson = credentialTemplate.Replace("ISSUER", ctx.IssuerDid, StringComparison.Ordinal);
        string body = "{\"credential\":" + credentialJson + "}";

        using JsonDocument response = await PostIssueAsync(app, ctx.Segment, body, expectedStatus: 400).ConfigureAwait(false);

        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            response.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            $"A credential the signer cannot canonicalize ({reason}) is a §3.8.1 malformed-value 400, not a 500.");
    }


    /// <summary>
    /// The §3.2.1 structural gate runs only <see cref="ContextValidationRules.ValidateCredentialContextAsync"/>
    /// (the NORMATIVE pipeline), never <see cref="ContextValidationRules.ValidateCredentialContextStrictProfileAsync"/>'s
    /// allowlist. A well-formed, resolvable use-case context IRI outside this library's own
    /// <see cref="WellKnownContextAllowlists.Credentials20"/> — here the Citizenship vocabulary
    /// context — carries no <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data
    /// Model 2.0 §4.3 Contexts</see> "Subsequent items in the ordered set MUST be composed of any
    /// combination of URLs and objects" violation, so the credential still issues 201.
    /// </summary>
    [TestMethod]
    public async Task UnknownWellFormedContextIriIssuesSuccessfully()
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(app).ConfigureAwait(false);

        string credentialJson = "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\",\""
            + CanonicalizationTestUtilities.CitizenshipV4Rc1ContextUrl
            + "\"],\"type\":[\"VerifiableCredential\"],\"issuer\":\"ISSUER\",\"credentialSubject\":{\"id\":\"did:example:s\"}}";
        string body = "{\"credential\":" + credentialJson.Replace("ISSUER", ctx.IssuerDid, StringComparison.Ordinal) + "}";

        using JsonDocument response = await PostIssueAsync(app, ctx.Segment, body, expectedStatus: 201).ConfigureAwait(false);

        JsonElement vc = response.RootElement.GetProperty(VcalmParameterNames.VerifiableCredential);
        Assert.IsTrue(vc.TryGetProperty(VcalmParameterNames.Proof, out _),
            "A conformant credential carrying a use-case context outside this library's own allowlist still issues.");
    }


    /// <summary>
    /// §3.2.1 credentialId auto-populate: when only <c>credential.id</c> is given (no
    /// <c>options.credentialId</c>), the credential is stored under <c>credential.id</c> and is
    /// retrievable by it via §3.2.2 ("the issuer service will auto-populate its value from
    /// credential.id").
    /// </summary>
    [TestMethod]
    public async Task CredentialIdAutoPopulatesFromCredentialId()
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(app).ConfigureAwait(false);

        const string CredentialDotId = "urn:uuid:autopopulate-source";
        string body = VcalmWireFixtures.BuildIssueRequestBody(ctx.IssuerDid, credentialId: CredentialDotId, SerializeCredential);
        using JsonDocument _ = await PostIssueAsync(app, ctx.Segment, body, expectedStatus: 201).ConfigureAwait(false);

        //The §3.2.2 GET by the credential.id resolves the stored credential — auto-populated key.
        ServerHttpResponse getResponse = await app.DispatchVcalmCredentialByIdAsync(
            ctx.Segment, "GET", CredentialDotId, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, getResponse.StatusCode, getResponse.Body);
        Assert.IsTrue(CredentialStore.ContainsKey(CredentialDotId),
            "The credential was stored under its auto-populated credential.id.");
    }


    /// <summary>
    /// §3.2.1 both-set credentialId: when <c>options.credentialId</c> and <c>credential.id</c> are
    /// both set and DIFFER, the request is rejected with HTTP 400 (an ambiguous identity; §3.2.1:
    /// "credentialId SHOULD NOT be set by the issuer coordinator if the credential.id property is
    /// set").
    /// </summary>
    [TestMethod]
    public async Task ConflictingCredentialIdAndCredentialDotIdYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(app).ConfigureAwait(false);

        string credentialJson = BuildCredentialJson(ctx.IssuerDid, credentialId: "urn:uuid:credential-dot-id");
        string body = "{\"credential\":" + credentialJson
            + ",\"options\":{\"credentialId\":\"urn:uuid:different-option-id\"}}";

        using JsonDocument _ = await PostIssueAsync(app, ctx.Segment, body, expectedStatus: 400).ConfigureAwait(false);
    }


    /// <summary>
    /// §3.2.1 no-auto-generate: a credential with neither <c>credential.id</c> nor
    /// <c>options.credentialId</c> is still issued (201), but is NOT stored (the issuer SHOULD NOT
    /// auto-generate an id, so there is no key to refer to it by).
    /// </summary>
    [TestMethod]
    public async Task NoIdSuppliedIssuesButDoesNotStore()
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(app).ConfigureAwait(false);

        string credentialJson = BuildCredentialJson(ctx.IssuerDid, credentialId: null);
        string body = "{\"credential\":" + credentialJson + "}";

        using JsonDocument _ = await PostIssueAsync(app, ctx.Segment, body, expectedStatus: 201).ConfigureAwait(false);

        Assert.IsEmpty(CredentialStore,
            "A credential with no id is issued but not stored — the issuer does not auto-generate one.");
    }


    /// <summary>
    /// §3.2.1 multi-proof in one call: an instance configured with two signing descriptors attaches
    /// BOTH proofs in a single issue call ("the instance MUST attach all of these proofs in response
    /// to a single call"), and the resulting two-proof credential verifies as a §2.1.2 chain.
    /// </summary>
    [TestMethod]
    public async Task MultipleDescriptorsAttachAllProofsInOneCall()
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(app, secondDescriptor: true, alsoVerifier: true).ConfigureAwait(false);
        await WireVerificationSeamAsync(app).ConfigureAwait(false);

        string body = VcalmWireFixtures.BuildIssueRequestBody(ctx.IssuerDid, credentialId: "urn:uuid:multiproof-1", SerializeCredential);
        using JsonDocument issued = await PostIssueAsync(app, ctx.Segment, body, expectedStatus: 201).ConfigureAwait(false);

        JsonElement proof = issued.RootElement
            .GetProperty(VcalmParameterNames.VerifiableCredential)
            .GetProperty(VcalmParameterNames.Proof);
        Assert.AreEqual(JsonValueKind.Array, proof.ValueKind, "Two proofs are emitted as an array (a proof chain).");
        Assert.AreEqual(2, proof.GetArrayLength(), "Both descriptors' proofs are attached in one call.");

        //The two-proof chain verifies at the verifier endpoint.
        string securedCredentialJson = issued.RootElement.GetProperty(VcalmParameterNames.VerifiableCredential).GetRawText();
        string verifyBody = "{\"verifiableCredential\":" + securedCredentialJson + "}";
        ServerHttpResponse verifyResponse = await app.DispatchAtEndpointAsync(
            ctx.Segment, WellKnownVcalmEndpointNames.VcalmCredentialsVerify, "POST",
            new RequestFields(), verifyBody, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, verifyResponse.StatusCode, verifyResponse.Body);
        using JsonDocument verifyDoc = JsonDocument.Parse(verifyResponse.Body);
        Assert.IsTrue(verifyDoc.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "The two-proof chain issued in one call verifies true.");
    }


    /// <summary>
    /// §3.2.1 Error-Handling configuration: an instance configured to only accept credentials without
    /// existing proofs rejects a pre-proofed credential with HTTP 400 ("Return an error if credential
    /// values that contain existing proof values are provided").
    /// </summary>
    [TestMethod]
    public async Task ExistingProofWithErrorConfigYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(
            app, existingProofHandling: VcalmExistingProofHandling.Error).ConfigureAwait(false);

        //Sign the credential first so the issue request carries an existing proof.
        DataIntegritySecuredCredential preProofed = await SignCredentialAsync(
            ctx, "urn:uuid:pre-proofed").ConfigureAwait(false);
        string credentialJson = SerializeCredential(preProofed);
        string body = "{\"credential\":" + credentialJson + "}";

        using JsonDocument response = await PostIssueAsync(app, ctx.Segment, body, expectedStatus: 400).ConfigureAwait(false);

        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            response.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "The Error-Handling config rejects a pre-proofed credential.");
    }


    /// <summary>
    /// §3.2.1 Proof-Set configuration: an instance configured for Proof Sets appends its new proof in
    /// parallel to the caller's existing one (no <c>previousProof</c> binding), yielding a two-element
    /// proof array.
    /// </summary>
    [TestMethod]
    public async Task ExistingProofWithProofSetConfigAppendsParallelProof()
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(
            app, existingProofHandling: VcalmExistingProofHandling.ProofSet).ConfigureAwait(false);

        DataIntegritySecuredCredential preProofed = await SignCredentialAsync(
            ctx, "urn:uuid:set-base").ConfigureAwait(false);
        string credentialJson = SerializeCredential(preProofed);
        string body = "{\"credential\":" + credentialJson + "}";

        using JsonDocument issued = await PostIssueAsync(app, ctx.Segment, body, expectedStatus: 201).ConfigureAwait(false);

        JsonElement proof = issued.RootElement
            .GetProperty(VcalmParameterNames.VerifiableCredential)
            .GetProperty(VcalmParameterNames.Proof);
        Assert.AreEqual(JsonValueKind.Array, proof.ValueKind, "A proof set is a proof array.");
        Assert.AreEqual(2, proof.GetArrayLength(), "The caller's proof and the instance's proof sit in parallel.");

        foreach(JsonElement member in proof.EnumerateArray())
        {
            Assert.IsFalse(member.TryGetProperty("previousProof", out _),
                "A proof-set member carries no previousProof chain link (§2.1.1).");
        }
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>: "Implementations MUST throw an error if
    /// an endpoint receives data, options, or option values that it does not understand or know how to process." A
    /// Proof-Chain configuration binds the new proof to the caller's existing proof through <c>previousProof</c>, so an
    /// existing proof missing a <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity
    /// §4.4</see> mandatory member is refused with MALFORMED_VALUE_ERROR before any signing — never re-serialized
    /// and chained onto.
    /// </summary>
    [TestMethod]
    [DataRow("type")]
    [DataRow("verificationMethod")]
    [DataRow("proofPurpose")]
    public async Task ExistingProofWithProofChainConfigRejectsIncompleteInputProof(string member)
    {
        await AssertIncompleteExistingProofRefusedAsync(VcalmExistingProofHandling.ProofChain, member).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>: "Implementations MUST throw an error if
    /// an endpoint receives data, options, or option values that it does not understand or know how to process." A
    /// Proof-Set configuration places the new proof beside the caller's existing proof, so an existing proof missing a
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see> mandatory member is
    /// refused with MALFORMED_VALUE_ERROR before any signing, exactly as a Proof-Chain configuration refuses it, and
    /// never issued inside the proof set.
    /// </summary>
    [TestMethod]
    [DataRow("type")]
    [DataRow("verificationMethod")]
    [DataRow("proofPurpose")]
    public async Task ExistingProofWithProofSetConfigRejectsIncompleteInputProof(string member)
    {
        await AssertIncompleteExistingProofRefusedAsync(VcalmExistingProofHandling.ProofSet, member).ConfigureAwait(false);
    }


    /// <summary>
    /// Issues, over the real wire, a pre-proofed credential whose existing proof lacks <paramref name="member"/> to an
    /// instance configured with <paramref name="existingProofHandling"/>, and asserts the MALFORMED_VALUE_ERROR 400
    /// refusal and that nothing was stored under the credential's id.
    /// </summary>
    /// <param name="existingProofHandling">The instance's existing-proof configuration.</param>
    /// <param name="member">The mandatory proof member removed from the existing proof.</param>
    private async Task AssertIncompleteExistingProofRefusedAsync(VcalmExistingProofHandling existingProofHandling, string member)
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(app, existingProofHandling: existingProofHandling).ConfigureAwait(false);

        const string CredentialId = "urn:uuid:incomplete-existing-proof";
        DataIntegritySecuredCredential preProofed = await SignCredentialAsync(ctx, CredentialId).ConfigureAwait(false);
        string credentialJson = DataIntegrityContextTamperingFixture.MutateSecuredDocumentJson(
            SerializeCredential(preProofed), "delete:proof." + member);
        string body = "{\"credential\":" + credentialJson + "}";

        using JsonDocument response = await VcalmWireFixtures.PostIssueWireAsync(
            app, ctx.Segment, body, 400, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            response.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            $"An existing proof missing {member} is refused before any signing.");
        Assert.IsFalse(CredentialStore.ContainsKey(CredentialId), "A refused credential is never issued, so never stored.");
    }


    /// <summary>
    /// §2.4 unknown-option MUST: an <c>options</c> member the issuer does not understand is rejected
    /// with HTTP 400 and the §3.8 <c>UNKNOWN_OPTION_PROVIDED</c> type.
    /// </summary>
    [TestMethod]
    public async Task UnknownOptionYields400UnknownOptionProvided()
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(app).ConfigureAwait(false);

        string credentialJson = BuildCredentialJson(ctx.IssuerDid, credentialId: "urn:uuid:unknown-option");
        string body = "{\"credential\":" + credentialJson + ",\"options\":{\"notARealOption\":true}}";

        using JsonDocument response = await PostIssueAsync(app, ctx.Segment, body, expectedStatus: 400).ConfigureAwait(false);

        Assert.AreEqual("https://www.w3.org/TR/vcalm#UNKNOWN_OPTION_PROVIDED",
            response.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "An unknown option yields the UNKNOWN_OPTION_PROVIDED type.");
    }


    /// <summary>
    /// §3.2.1 / §2.4 mandatoryPointers prohibition: an instance that does not support selective
    /// disclosure rejects an issue request carrying <c>options.mandatoryPointers</c> as the §2.4
    /// inapplicable-option case (400 / UNKNOWN_OPTION_PROVIDED).
    /// </summary>
    [TestMethod]
    public async Task MandatoryPointersOnNonSdInstanceYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(app).ConfigureAwait(false);

        string credentialJson = BuildCredentialJson(ctx.IssuerDid, credentialId: "urn:uuid:mp");
        string body = "{\"credential\":" + credentialJson + ",\"options\":{\"mandatoryPointers\":[\"/credentialSubject/alumniOf\"]}}";

        using JsonDocument response = await PostIssueAsync(app, ctx.Segment, body, expectedStatus: 400).ConfigureAwait(false);

        Assert.AreEqual("https://www.w3.org/TR/vcalm#UNKNOWN_OPTION_PROVIDED",
            response.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "mandatoryPointers on a non-SD instance is the §2.4 inapplicable-option case.");
    }


    /// <summary>
    /// §3.2.2 retrieval: a stored credential is returned with HTTP 200, an unknown id is 404, and a
    /// soft-deleted id is 410 Gone. §3.2.2: 200 / 404 / 410 (and never 418).
    /// </summary>
    [TestMethod]
    public async Task GetStoredCredentialReturns200And404AndGone()
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(app).ConfigureAwait(false);

        const string CredentialId = "urn:uuid:get-target";
        string body = VcalmWireFixtures.BuildIssueRequestBody(ctx.IssuerDid, credentialId: CredentialId, SerializeCredential);
        using JsonDocument issued = await PostIssueAsync(app, ctx.Segment, body, expectedStatus: 201).ConfigureAwait(false);

        //200: the stored credential.
        ServerHttpResponse getResponse = await app.DispatchVcalmCredentialByIdAsync(
            ctx.Segment, "GET", CredentialId, [], TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, getResponse.StatusCode, getResponse.Body);
        using JsonDocument getDoc = JsonDocument.Parse(getResponse.Body);
        Assert.IsTrue(getDoc.RootElement.TryGetProperty(VcalmParameterNames.VerifiableCredential, out _),
            "The §3.2.2 retrieval returns the credential under verifiableCredential.");

        //404: an id the store never held.
        ServerHttpResponse notFound = await app.DispatchVcalmCredentialByIdAsync(
            ctx.Segment, "GET", "urn:uuid:never-issued", [], TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(404, notFound.StatusCode, "An unknown credential id is 404.");

        //410: soft-delete the credential, then GET → Gone.
        CredentialStore[CredentialId] = CredentialStore[CredentialId] with { IsDeleted = true };
        ServerHttpResponse gone = await app.DispatchVcalmCredentialByIdAsync(
            ctx.Segment, "GET", CredentialId, [], TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(410, gone.StatusCode, "A soft-deleted credential's tombstone is 410 Gone.");
    }


    /// <summary>
    /// §3.2.3 deletion: DELETE returns HTTP 202 (the soft-delete default), and a subsequent §3.2.2 GET
    /// returns 410 Gone. §3.2.3: "this is a 202 by default as soft deletes and processing time are
    /// assumed".
    /// </summary>
    [TestMethod]
    public async Task DeleteReturns202ThenGetReturnsGone()
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(app).ConfigureAwait(false);

        const string CredentialId = "urn:uuid:delete-target";
        string body = VcalmWireFixtures.BuildIssueRequestBody(ctx.IssuerDid, credentialId: CredentialId, SerializeCredential);
        using JsonDocument _ = await PostIssueAsync(app, ctx.Segment, body, expectedStatus: 201).ConfigureAwait(false);

        //202: the soft delete.
        ServerHttpResponse deleteResponse = await app.DispatchVcalmCredentialByIdAsync(
            ctx.Segment, "DELETE", CredentialId, [], TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(202, deleteResponse.StatusCode, deleteResponse.Body);

        //410: the §3.2.2 GET on the soft-deleted credential.
        ServerHttpResponse gone = await app.DispatchVcalmCredentialByIdAsync(
            ctx.Segment, "GET", CredentialId, [], TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(410, gone.StatusCode, "After a §3.2.3 delete the §3.2.2 GET is 410 Gone.");

        //404: deleting an id the store never held.
        ServerHttpResponse deleteUnknown = await app.DispatchVcalmCredentialByIdAsync(
            ctx.Segment, "DELETE", "urn:uuid:never-issued", [], TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(404, deleteUnknown.StatusCode, "Deleting an unknown credential id is 404.");
    }


    /// <summary>
    /// §2.4 content-serialization MUST: a §3.2.1 request whose Content-Type is not
    /// <c>application/json</c> is rejected with HTTP 400 before parsing.
    /// </summary>
    [TestMethod]
    public async Task NonJsonContentTypeYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(app).ConfigureAwait(false);

        byte[] bytes = Encoding.UTF8.GetBytes("{\"credential\":{}}");
        ServerHttpResponse response = await app.DispatchWithBodyAsync(
            ctx.Segment, WellKnownVcalmEndpointNames.VcalmCredentialsIssue, "POST",
            bytes, "text/plain", [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "A non-application/json body is rejected before parsing (§2.4 content-serialization MUST).");
    }


    /// <summary>
    /// §3.2.1 malformed input: a body that is not a JSON object yields HTTP 400.
    /// </summary>
    [TestMethod]
    public async Task MalformedIssueBodyYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        IssuerContext ctx = await RegisterIssuerAsync(app).ConfigureAwait(false);

        using JsonDocument _ = await PostIssueAsync(app, ctx.Segment, "{ not valid json", expectedStatus: 400).ConfigureAwait(false);
    }


    /// <summary>
    /// Registers and configures the issuer used by the credential-issuance endpoint cases.
    /// </summary>
    private async Task<IssuerContext> RegisterIssuerAsync(
        TestHostShell app,
        bool secondDescriptor = false,
        VcalmExistingProofHandling existingProofHandling = VcalmExistingProofHandling.Error,
        bool alsoVerifier = false)
    {
        IssuerKeyMaterial material = CreateIssuerKeyMaterial();
        RegisteredMaterials.Add(material);

        DidDocument issuerDidDocument = await KeyDidBuilder.BuildAsync(
            material.SigningPublicKey,
            MultikeyVerificationMethodTypeInfo.Instance,
            BaseMemoryPool.Shared,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string verificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;
        string issuerDid = issuerDidDocument.Id!.ToString();

        VerifierKeyMaterial hostMaterial = await app.RegisterClientAsync(
            ClientId, ClientBaseUri, alsoVerifier ? IssuerAndVerifierCapabilities : IssuerCapabilities).ConfigureAwait(false);
        RegisteredMaterials.Add(IssuerKeyMaterial.Wrapping(hostMaterial));

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultVcalmJsonParsing(JsonOptions);
        }).ConfigureAwait(false);

        ImmutableArray<VcalmProofDescriptor>.Builder descriptors = ImmutableArray.CreateBuilder<VcalmProofDescriptor>();
        descriptors.Add(BuildDescriptor(material.SigningPrivateKey, verificationMethodId));
        if(secondDescriptor)
        {
            //A second descriptor under the SAME issuer key — exercises the §3.2.1 "attach all proofs
            //in one call" MUST without needing a second resolvable controller.
            descriptors.Add(BuildDescriptor(material.SigningPrivateKey, verificationMethodId));
        }

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.VcalmCredentialIssuance = new VcalmCredentialIssuance
            {
                ConfiguredIssuer = issuerDid,
                SigningDescriptors = descriptors.ToImmutable(),
                ExistingProofHandling = existingProofHandling,
                SupportsMandatoryPointers = false,
                MemoryPool = Pool
            };
        }).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.StoreVcalmIssuedCredentialAsync = (credentialId, json, _, _) =>
            {
                CredentialStore[credentialId] = new VcalmStoredCredential { VerifiableCredentialJson = json };

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.LoadVcalmIssuedCredentialAsync = (credentialId, _, _) =>
                ValueTask.FromResult(CredentialStore.GetValueOrDefault(credentialId));
        }).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.DeleteVcalmIssuedCredentialAsync = (credentialId, _, _) =>
            {
                if(!CredentialStore.TryGetValue(credentialId, out VcalmStoredCredential? existing) || existing.IsDeleted)
                {

                    return ValueTask.FromResult(false);
                }

                //§3.2.3 soft delete (the 202 default): retain a tombstone so the §3.2.2 GET answers 410.
                CredentialStore[credentialId] = existing with { IsDeleted = true };

                return ValueTask.FromResult(true);
            };
        }).ConfigureAwait(false);

        return new IssuerContext(hostMaterial.Registration.TenantId.Value, issuerDid, verificationMethodId, material);
    }


    /// <summary>
    /// Wires the Data Integrity verification seams so an issued credential can be POSTed to
    /// <c>/credentials/verify</c> in the round-trip tests; the registration already allows both roles.
    /// </summary>
    /// <param name="app">The host shell whose VCALM integration is altered.</param>
    private static async Task WireVerificationSeamAsync(TestHostShell app)
    {
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.VcalmCredentialVerification = new VcalmCredentialVerification
            {
                Resolver = KeyDidResolverSeam,
                Canonicalize = RdfcCanonicalizer,
                ContextResolver = ContextResolver,
                KnownContext = VcalmWireFixtures.CredentialKnownContext,
                DecodeProofValue = ProofValueCodecs.DecodeBase58Btc,
                SerializeCredential = SerializeCredential,
                SerializePresentation = presentation => JsonSerializerExtensions.Serialize(presentation, JsonOptions),
                SerializeProofOptions = SerializeProofOptions,
                Decoder = TestSetup.Base58Decoder,
                ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
                MemoryPool = Pool
            };
        }).ConfigureAwait(false);
    }


    /// <summary>Builds an eddsa-rdfc-2022 proof descriptor signing with <paramref name="privateKey"/>.</summary>
    /// <param name="privateKey">The issuer's signing key.</param>
    /// <param name="verificationMethodId">The verification method id the produced proofs name.</param>
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
            ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync
        };


    /// <summary>Creates the issuer's Ed25519 signing key material from the cached test key pair.</summary>
    private static IssuerKeyMaterial CreateIssuerKeyMaterial()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();

        return new IssuerKeyMaterial(keyPair.PublicKey, keyPair.PrivateKey, hostMaterial: null);
    }


    /// <summary>
    /// Signs the standard test credential through the Core signing surface, so an issue request can carry a
    /// caller-supplied existing proof for the §3.2.1 existing-proof configuration cases.
    /// </summary>
    /// <param name="ctx">The issuer wiring whose key and verification method sign.</param>
    /// <param name="credentialId">The credential's <c>id</c>.</param>
    private async Task<DataIntegritySecuredCredential> SignCredentialAsync(IssuerContext ctx, string credentialId)
    {
        VerifiableCredential credential = VcalmWireFixtures.BuildCredential(ctx.IssuerDid, credentialId);
        DateTime proofCreated = TimeProvider.GetUtcNow().UtcDateTime;

        return await credential.SignAsync(
            ctx.Material.SigningPrivateKey,
            ctx.VerificationMethodId,
            EddsaRdfc2022CryptosuiteInfo.Instance,
            proofCreated,
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
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Serializes the shared test credential for <paramref name="issuerDid"/>.</summary>
    /// <param name="issuerDid">The credential's issuer.</param>
    /// <param name="credentialId">The credential's <c>id</c>, or <see langword="null"/> to omit it.</param>
    private static string BuildCredentialJson(string issuerDid, string? credentialId) =>
        SerializeCredential(VcalmWireFixtures.BuildCredential(issuerDid, credentialId));


    /// <summary>
    /// Dispatches a §3.2.1 issue request in process through the host's dispatcher and returns the parsed body after
    /// checking its status.
    /// </summary>
    /// <param name="app">The host shell whose dispatcher serves the request.</param>
    /// <param name="segment">The issuer tenant segment.</param>
    /// <param name="body">The issue request body JSON text.</param>
    /// <param name="expectedStatus">The HTTP status the response must carry.</param>
    private async Task<JsonDocument> PostIssueAsync(
        TestHostShell app, string segment, string body, int expectedStatus)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmCredentialsIssue,
            "POST",
            new RequestFields(),
            body,
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedStatus, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    /// <summary>
    /// The per-test issuer wiring: the tenant segment, the configured issuer DID, the verification method id the
    /// descriptors sign with, and the key material backing them.
    /// </summary>
    /// <param name="Segment">The issuer tenant segment.</param>
    /// <param name="IssuerDid">The configured issuer DID.</param>
    /// <param name="VerificationMethodId">The verification method id the descriptors sign with.</param>
    /// <param name="Material">The key material backing the descriptors.</param>
    private sealed record IssuerContext(string Segment, string IssuerDid, string VerificationMethodId, IssuerKeyMaterial Material);


    /// <summary>
    /// Owns the issuer's Ed25519 signing key for the test's lifetime, disposed at cleanup; the host-material wrapper
    /// lets the cleanup loop dispose the host registration's material uniformly.
    /// </summary>
    private sealed class IssuerKeyMaterial: IDisposable
    {
        /// <summary>The host registration this instance wraps, or <see langword="null"/> for the issuer's own keys.</summary>
        private VerifierKeyMaterial? HostMaterial { get; }

        /// <summary>Whether <see cref="Dispose"/> already ran.</summary>
        private bool isDisposed;

        /// <summary>Creates key material owning <paramref name="signingPublicKey"/> and <paramref name="signingPrivateKey"/>.</summary>
        /// <param name="signingPublicKey">The public half of the signing key.</param>
        /// <param name="signingPrivateKey">The private half of the signing key.</param>
        /// <param name="hostMaterial">The host registration this instance wraps, or <see langword="null"/>.</param>
        public IssuerKeyMaterial(PublicKeyMemory signingPublicKey, PrivateKeyMemory signingPrivateKey, VerifierKeyMaterial? hostMaterial)
        {
            SigningPublicKey = signingPublicKey;
            SigningPrivateKey = signingPrivateKey;
            this.HostMaterial = hostMaterial;
        }

        /// <summary>The public half of the signing key.</summary>
        public PublicKeyMemory SigningPublicKey { get; }

        /// <summary>The private half of the signing key.</summary>
        public PrivateKeyMemory SigningPrivateKey { get; }

        /// <summary>Wraps a host registration's key material so the cleanup loop disposes it with the others.</summary>
        /// <param name="hostMaterial">The host registration's key material.</param>
        public static IssuerKeyMaterial Wrapping(VerifierKeyMaterial hostMaterial) =>
            new(hostMaterial.SigningPublicKey, hostMaterial.SigningPrivateKey, hostMaterial);

        /// <summary>Disposes the wrapped host registration, or the owned key halves, once.</summary>
        public void Dispose()
        {
            if(isDisposed)
            {
                return;
            }

            isDisposed = true;
            if(HostMaterial is not null)
            {
                HostMaterial.Dispose();
            }
            else
            {
                SigningPublicKey.Dispose();
                SigningPrivateKey.Dispose();
            }
        }
    }
}
