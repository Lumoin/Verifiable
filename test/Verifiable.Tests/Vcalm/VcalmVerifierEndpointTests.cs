using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.BouncyCastle;
using Verifiable.Cbor;
using Verifiable.Core;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Did.Methods.Web;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.Resolvers;
using Verifiable.Core.Outbound;
using Verifiable.Core.StatusLists;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.DataIntegrity;
using Verifiable.Tests.OAuth;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Vcalm;
using CoreStatusList = Verifiable.Core.StatusLists.StatusList;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// End-to-end conformance tests for the W3C VCALM 1.0 verifier service
/// (<see href="https://www.w3.org/TR/vcalm-1.0/#verifier-service">A Verifiable Credential API for Lifecycle
/// Management</see>) exposed by <see cref="VcalmVerifierEndpoints"/> — the §3.3.1
/// <c>/credentials/verify</c>, §3.3.2 <c>/presentations/verify</c>, and §3.3.3 <c>/challenges</c>
/// endpoints, driven through the real dispatch pipeline.
/// </summary>
/// <remarks>
/// The credential / presentation signing, the cryptosuite (eddsa-rdfc-2022 for the credential,
/// eddsa-jcs-2022 for the presentation), the RDFC / JCS canonicalizers, the did:key resolver, and
/// the project crypto are sourced from the same library primitives the Data Integrity flow tests
/// use — the verifier COMPOSES them, it does not re-roll cryptography.
/// </remarks>
[TestClass]
internal sealed class VcalmVerifierEndpointTests
{
    /// <summary>The MSTest context of the running test; its cancellation token bounds every wait in this class.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The fake clock the host and the signing helpers read, fixed at the canonical test epoch.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The memory pool the test-side signing, decoding and key material rent from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The client identifier registered with <see cref="TestHostShell"/> for verifier requests.</summary>
    private const string ClientId = "https://verifier.client.test";

    /// <summary>The base URI registered with <see cref="TestHostShell"/> alongside <see cref="ClientId"/>.</summary>
    private static Uri ClientBaseUri { get; } = new("https://verifier.client.test");

    /// <summary>The capabilities the verifier tenant is registered with: the VCALM verifier role only.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> VerifierCapabilities { get; } =
        ImmutableHashSet.Create(WellKnownVcalmCapabilities.VcalmVerifier);

    /// <summary>The serializer options every credential and presentation in this class is written and read with.</summary>
    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    /// <summary>Builds the did:key documents of the test issuers and holders.</summary>
    private static KeyDidBuilder KeyDidBuilder { get; } = new();

    /// <summary>Builds the did:web document of a test issuer whose controller document a test serves itself.</summary>
    private static WebDidBuilder WebDidBuilder { get; } = new(BaseMemoryPool.Shared);

    /// <summary>The domain of the did:web test issuer, so its DID is <c>did:web:issuer.web.test</c>.</summary>
    private const string IssuerWebDomain = "issuer.web.test";

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

    /// <summary>
    /// The presentation tests sign with eddsa-jcs-2022 (JCS is context-free and produces a non-empty
    /// canonical form for a minimal presentation); the credential tests sign with eddsa-rdfc-2022. Each
    /// verifier instance is registered with the canonicalizer matching the suite it serves — the
    /// library does not hardcode the cryptosuite, and a multi-suite deployment wires a dispatching
    /// canonicalizer.
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

    /// <summary>Serializes a proof options document with <see cref="JsonOptions"/>.</summary>
    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);

    /// <summary>The per-operation context the test-side signing takes; empty, so no network is reachable.</summary>
    private static ExchangeContext EmptyContext { get; } = [];

    /// <summary>
    /// A P-256 public key in Multikey form, the issuer key the
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/">VC Data Integrity ECDSA Cryptosuites</see> test vectors publish,
    /// used where a verification method must carry a well-formed key of an algorithm other than the one it declares.
    /// </summary>
    private static string P256PublicKeyMultibase { get; } = "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP";

    /// <summary>
    /// Registered key material lives for the test's lifetime and is disposed at cleanup; the host
    /// keeps the registration, so the material cannot be disposed at the end of RegisterVerifier.
    /// </summary>
    private List<VerifierKeyMaterial> RegisteredMaterials { get; } = [];

    /// <summary>
    /// ecdsa-sd-2023 issuer / ephemeral key material the SD base-proof + derive helpers retain for the
    /// test's lifetime — disposed at cleanup.
    /// </summary>
    private List<IDisposable> OwnedKeys { get; } = [];


    /// <summary>Disposes the key material the test registered or created, after the test's host is torn down.</summary>
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
    }


    /// <summary>
    /// §3.3.1 happy path: a valid eddsa-rdfc-2022 credential verifies — HTTP 200 with
    /// <c>verified:true</c>. §3.3.1: "verified … is set to true if no errors were detected during the
    /// verification process."
    /// </summary>
    [TestMethod]
    public async Task ValidCredentialVerifiesTrue()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(validUntilPast: false).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A valid eddsa-rdfc-2022 credential must verify true.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#verification">VC Data Model 2.0 §7.1</see>: "If
    /// result.status is set to false, add a CRYPTOGRAPHIC_SECURITY_ERROR to result.errors." A tampered credential's
    /// proof fails to verify, so the response is still HTTP 200, the process having run, and
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verification-errors-vs-warnings">VCALM §3.8.1</see> sets
    /// <c>verified</c> false beside that error: "If an error is included, the verified property of the
    /// VerificationResponse object MUST be set to false".
    /// </summary>
    [TestMethod]
    public async Task TamperedCredentialVerifiesFalseWithError()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(validUntilPast: false).ConfigureAwait(false);
        //Tamper the subject claim after signing — the RDFC hash no longer matches the signature.
        credential.CredentialSubject![0].AdditionalData!["alumniOf"] = "Tampered University";

        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A tampered credential must verify false (the process still ran → 200).");

        JsonElement problems = response.RootElement.GetProperty(VcalmParameterNames.ProblemDetails);
        Assert.IsGreaterThan(0, problems.GetArrayLength(), "A crypto failure surfaces a ProblemDetail.");
        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#CRYPTOGRAPHIC_SECURITY_ERROR",
            problems[0].GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "The proof failure is a §3.8.1 cryptographic ERROR.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#verification">VCDM §7.1</see>:
    /// if result.status is false, add a CRYPTOGRAPHIC_SECURITY_ERROR to result.errors.
    /// Exercises the signature verdict through <see cref="VcalmVerifierEndpoints"/>.
    /// </summary>
    [TestMethod]
    public async Task FailedSignatureReportsCryptographicSecurityProblem()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);
        DataIntegritySecuredCredential credential = await SignCredentialAsync(false).ConfigureAwait(false);
        credential.CredentialSubject![0].AdditionalData!["alumniOf"] = "Forged University";
        using JsonDocument response = await PostCredentialWireAsync(app, segment,
            BuildCredentialRequestBody(credential, true), 200).ConfigureAwait(false);
        AssertVerificationProblem(response, "https://www.w3.org/TR/vc-data-model#CRYPTOGRAPHIC_SECURITY_ERROR");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see>:
    /// if controllerDocument is not a conforming controlled identifier document, an error MUST
    /// be raised and SHOULD convey INVALID_CONTROLLED_IDENTIFIER_DOCUMENT through
    /// <see cref="VcalmVerifierEndpoints"/>.
    /// </summary>
    [TestMethod]
    [DataRow("unreachable")]
    [DataRow("transport")]
    [DataRow("refused")]
    [DataRow("nonconforming")]
    public async Task ControllerFailureReportsControlledIdentifierProblem(string cause)
    {
        await AssertControllerProblemAsync(cause,
            "https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see>:
    /// if controllerDocument is not a conforming controlled identifier document, an error MUST
    /// be raised and SHOULD convey INVALID_CONTROLLED_IDENTIFIER_DOCUMENT.
    /// </summary>
    [TestMethod]
    [DataRow("{")]
    [DataRow("null")]
    [DataRow("[]")]
    [DataRow("{}")]
    [DataRow("42")]
    [DataRow("\"not a document\"")]
    public async Task MalformedRetrievedControllerReportsDocumentProblem(string documentJson)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);
        using System.Buffers.IMemoryOwner<byte> body = Pool.Rent(Encoding.UTF8.GetByteCount(documentJson));
        int written = Encoding.UTF8.GetBytes(documentJson, body.Memory.Span);
        bool hasParsedResponse = false;
        DidResolver resolver = new(DidMethodSelectors.FromResolvers((WellKnownDidMethodPrefixes.WebDidMethodPrefix,
            WebDidResolver.BuildResolving(
                (_, _, _) => ValueTask.FromResult(new OutboundResponse
                {
                    StatusCode = 200,
                    Body = new TaggedMemory<byte>(body.Memory[..written], BufferTags.Json)
                }),
                bytes =>
                {
                    hasParsedResponse = true;

                    return JsonSerializer.Deserialize<DidDocument>(bytes, JsonOptions);
                }))));
        await AlterVerificationAsync(app, verification => verification with { Resolver = resolver }).ConfigureAwait(false);
        DataIntegritySecuredCredential credential = await SignCredentialAsync(false).ConfigureAwait(false);
        credential.Proof![0].VerificationMethod = new AssertionMethod("did:web:controller.example#key");
        using JsonDocument response = await PostCredentialWireAsync(app, segment,
            BuildCredentialRequestBody(credential, true), 200).ConfigureAwait(false);
        Assert.IsTrue(hasParsedResponse, "The retrieved bytes must reach the document deserializer.");
        AssertVerificationProblem(response, "https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see>:
    /// if controllerDocument is not a conforming controlled identifier document, an error MUST
    /// be raised and SHOULD convey INVALID_CONTROLLED_IDENTIFIER_DOCUMENT.
    /// </summary>
    [TestMethod]
    [DataRow("documentController")]
    [DataRow("nullDocumentController")]
    public async Task InvalidDocumentControllerReportsDocumentProblem(string cause)
    {
        await AssertControllerProblemAsync(cause,
            "https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see>:
    /// let controllerDocument be the result of dereferencing controllerDocumentUrl; if it is not
    /// a conforming controlled identifier document, an error MUST be raised and SHOULD convey
    /// INVALID_CONTROLLED_IDENTIFIER_DOCUMENT.
    /// </summary>
    [TestMethod]
    public async Task UnretrievableNonDidUrlReportsDocumentProblem()
    {
        await AssertCredentialMutationProblemAsync("verificationMethod", JsonValue.Create("https://controller.example/keys#key"),
            "https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see>:
    /// "If vmIdentifier is not a valid URL, an error MUST be raised and SHOULD convey an error type of
    /// INVALID_VERIFICATION_METHOD_URL." The <c>/x#k</c> row pins a cross-platform pitfall:
    /// <see cref="Uri.TryCreate(string, UriKind, out Uri)"/> turns a rooted path such as <c>/x#k</c> into a
    /// <c>file:</c> URI on Unix-like platforms, as it turns a drive path into one on Windows, and a local file is never
    /// a verification method identifier, so the row reports the same type on every platform.
    /// </summary>
    [TestMethod]
    [DataRow("not a URL")]
    [DataRow("/x#k")]
    public async Task InvalidVerificationMethodUrlReportsUrlProblem(string malformedUrl)
    {
        await AssertCredentialMutationProblemAsync("verificationMethod", JsonValue.Create(malformedUrl),
            "https://w3id.org/security#INVALID_VERIFICATION_METHOD_URL").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see>:
    /// "If controllerDocument.id does not match the controllerDocumentUrl, an error MUST be raised and SHOULD
    /// convey an error type of INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID." The retrieved document names another
    /// DID, so the DID resolver refuses it before the verifier sees it; the step 6 type must survive that refusal.
    /// </summary>
    [TestMethod]
    public async Task ControllerIdMismatchReportsDocumentIdProblem()
    {
        DidResolver resolver = CreateControllerResolver("documentId");
        DataIntegritySecuredCredential credential = await SignCredentialAsync(false).ConfigureAwait(false);
        string verificationMethodId = credential.Proof![0].VerificationMethod!.Id!;
        DidResolutionResult resolution = await resolver.ResolveAsync(
            verificationMethodId[..verificationMethodId.IndexOf('#', StringComparison.Ordinal)], EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual<DidProblemDetails>(DidResolutionErrors.InvalidDidDocument, resolution.ResolutionMetadata.Error,
            "The resolver itself must refuse the retrieved document.");

        using JsonDocument response = await PostControllerCaseAsync(resolver, credential).ConfigureAwait(false);
        AssertVerificationProblem(response, "https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see>:
    /// a nonconforming method, a method id unequal to vmIdentifier, or a controller unequal
    /// to controllerDocumentUrl MUST raise an error and SHOULD convey INVALID_VERIFICATION_METHOD
    /// through <see cref="VcalmVerifierEndpoints"/>.
    /// </summary>
    [TestMethod]
    [DataRow("methodType")]
    [DataRow("invalidMethodController")]
    [DataRow("emptyMethodKey")]
    [DataRow("emptyJwk")]
    [DataRow("methodId")]
    [DataRow("methodKey")]
    public async Task InvalidMethodReportsVerificationMethodProblem(string cause)
    {
        await AssertControllerProblemAsync(cause,
            "https://w3id.org/security#INVALID_VERIFICATION_METHOD").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#verification-methods">CID §2.2</see>: "The value of the type
    /// property MUST be a string that references exactly one verification method type." A non-empty type the
    /// crypto registry does not know is a conforming shape, not a nonconforming method, so it reports the
    /// unsupported-mechanism problem rather than <see cref="InvalidMethodReportsVerificationMethodProblem"/>'s type.
    /// </summary>
    [TestMethod]
    public async Task UnknownVerificationMethodTypeReportsUnsupportedMechanism()
    {
        await AssertControllerProblemAsync("invalidMethodType",
            "https://verifiable.lumoin.com/problems#UNSUPPORTED_SECURING_MECHANISM").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see> step 8: "If
    /// verificationMethod is not a conforming verification method, an error MUST be raised and SHOULD convey an error
    /// type of INVALID_VERIFICATION_METHOD." A method filed under the <c>X25519KeyAgreementKey2020</c> key agreement type
    /// is not a signing method, so an assertion proof naming it is refused as nonconforming before any signature is
    /// checked, even though the Ed25519 key it carries would verify the signature.
    /// </summary>
    [TestMethod]
    public async Task KeyAgreementTypedMethodReportsVerificationMethodProblem()
    {
        await AssertControllerProblemAsync("keyAgreementType",
            "https://w3id.org/security#INVALID_VERIFICATION_METHOD").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see> step 8: "If
    /// verificationMethod is not a conforming verification method, an error MUST be raised and SHOULD convey an error
    /// type of INVALID_VERIFICATION_METHOD." A method declaring the <c>Ed25519VerificationKey2020</c> type while its
    /// Multikey value carries a P-256 key does not conform to its own type, so it is refused before its key is used for
    /// a signature check under an algorithm the type does not name.
    /// </summary>
    [TestMethod]
    public async Task MethodWhoseKeyIsNotOfItsDeclaredTypeReportsVerificationMethodProblem()
    {
        await AssertControllerProblemAsync("foreignCodec",
            "https://w3id.org/security#INVALID_VERIFICATION_METHOD").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see> raises at its first failing
    /// step, and step 8, "If verificationMethod is not a conforming verification method, an error MUST be raised and
    /// SHOULD convey an error type of INVALID_VERIFICATION_METHOD", precedes step 11, "If verificationMethod is not
    /// associated, either by reference (URL) or by value (object), with the verification relationship array in the
    /// controllerDocument identified by verificationRelationship, an error MUST be raised and SHOULD convey an error type
    /// of INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD." A method of a key agreement type, and a method whose key material
    /// is not a signing key of its declared type, fail step 8 even when the controller document also leaves them out of
    /// <c>assertionMethod</c>, so each reports INVALID_VERIFICATION_METHOD, never the relationship type.
    /// </summary>
    [TestMethod]
    [DataRow("keyAgreementTypeOutsideRelationship")]
    [DataRow("foreignCodecOutsideRelationship")]
    public async Task NonconformingMethodOutsideTheRelationshipReportsVerificationMethodProblem(string cause)
    {
        await AssertControllerProblemAsync(cause,
            "https://w3id.org/security#INVALID_VERIFICATION_METHOD").ConfigureAwait(false);
    }


    /// <summary>
    /// A presentation whose <c>holder</c> does not control the verification method its proof names is refused with
    /// this library's own <c>VERIFICATION_METHOD_CONTROLLER_MISMATCH</c>, never with CID's
    /// INVALID_VERIFICATION_METHOD: <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID
    /// §3.3</see> compares the method's controller only with the controller document URL ("If the absolute URL value of
    /// verificationMethod.controller does not equal controllerDocumentUrl"), which the signer's own document satisfies
    /// here, and no pulled specification text defines the binding of that controller to the presentation's holder.
    /// </summary>
    [TestMethod]
    public async Task PresentationHolderNotControllingItsMethodReportsControllerMismatch()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app, canonicalizer: JcsCanonicalizer).ConfigureAwait(false);

        const string Challenge = "challenge-holder-binding";
        const string Domain = "verifier.example";
        DataIntegritySecuredPresentation forged = await SignPresentationWithForgedHolderAsync(Challenge, Domain).ConfigureAwait(false);
        string body = BuildPresentationRequestBody(forged, Challenge, Domain, returnProblemDetails: true);

        using JsonDocument response = await PostPresentationWireAsync(app, segment, body, 200).ConfigureAwait(false);

        AssertVerificationProblem(response, "https://verifiable.lumoin.com/problems#VERIFICATION_METHOD_CONTROLLER_MISMATCH");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see> step 10:
    /// "If the absolute URL value of verificationMethod.controller does not equal controllerDocumentUrl, an error MUST
    /// be raised and SHOULD convey an error type of INVALID_VERIFICATION_METHOD." The retrieved document's
    /// verification method carries a controller that is not the controller document's own URL — this is
    /// tested on its own, split out from <see cref="InvalidMethodReportsVerificationMethodProblem"/>'s
    /// batch, because it is easily confused with the credential-issuer binding
    /// <see cref="IssuerControllerMismatchReportsLibraryProblem"/> exercises.
    /// </summary>
    [TestMethod]
    public async Task MethodControllerUnequalToDocumentUrlReportsVerificationMethodProblem()
    {
        await AssertControllerProblemAsync("methodController",
            "https://w3id.org/security#INVALID_VERIFICATION_METHOD").ConfigureAwait(false);
    }


    /// <summary>
    /// A verification method whose controller correctly names the controller document's own URL, but
    /// whose credential names a DIFFERENT issuer, is not a
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see> step 9 or
    /// 10 failure (step 9 compares the method's <c>id</c> with <c>vmIdentifier</c> and step 10 its controller with
    /// <c>controllerDocumentUrl</c>, both satisfied here) and no pulled specification text defines the issuer/holder
    /// binding: it is this library's own <c>VERIFICATION_METHOD_CONTROLLER_MISMATCH</c>.
    /// </summary>
    [TestMethod]
    public async Task IssuerControllerMismatchReportsLibraryProblem()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(false).ConfigureAwait(false);
        JsonObject document = JsonNode.Parse(SerializeCredential(credential))!.AsObject();

        //The verification method's own id and controller are untouched (they still name the real signer's DID,
        //satisfying CID §3.3 steps 9 and 10); only the credential's OWN issuer claim is changed to a
        //DIFFERENT DID, so the mismatch is between the credential and the (still-conforming) method.
        document["issuer"] = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

        string body = "{\"verifiableCredential\":" + document.ToJsonString() + ",\"options\":{\"returnProblemDetails\":true}}";
        using JsonDocument response = await PostCredentialWireAsync(app, segment, body, 200).ConfigureAwait(false);

        AssertVerificationProblem(response, "https://verifiable.lumoin.com/problems#VERIFICATION_METHOD_CONTROLLER_MISMATCH");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see>:
    /// a method not associated with the verification relationship array MUST raise an error
    /// and SHOULD convey INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD through <see cref="VcalmVerifierEndpoints"/>.
    /// </summary>
    [TestMethod]
    public async Task MissingRelationshipReportsRelationshipProblem()
    {
        await AssertControllerProblemAsync("relationship",
            "https://w3id.org/security#INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD").ConfigureAwait(false);
    }


    /// <summary>
    /// The §3.3.2 presentation analogue of <see cref="MissingRelationshipReportsRelationshipProblem"/>:
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see> step 11
    /// requires the verification method to be associated, by reference or by value, with the REQUESTED
    /// verification relationship array — <c>authentication</c> for a presentation proof, per
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>'s
    /// <c>expectedProofPurpose</c> of <c>authentication</c>. A holder document whose signing key is
    /// absent from <c>authentication</c> fails this step even though the same key is otherwise
    /// conforming.
    /// </summary>
    [TestMethod]
    public async Task PresentationMethodMissingAuthenticationRelationshipReportsRelationshipProblem()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app, canonicalizer: JcsCanonicalizer).ConfigureAwait(false);
        await AlterVerificationAsync(app, verification =>
            verification with { Resolver = CreateControllerResolver("authenticationRelationship") }).ConfigureAwait(false);

        DataIntegritySecuredPresentation presentation = await SignPresentationAsync(
            "challenge-xyz", "verifier.example").ConfigureAwait(false);
        string body = BuildPresentationRequestBody(presentation, "challenge-xyz", "verifier.example");
        JsonObject request = JsonNode.Parse(body)!.AsObject();
        request["options"]!["returnProblemDetails"] = true;

        using JsonDocument response = await PostPresentationWireAsync(app, segment, request.ToJsonString(), 200).ConfigureAwait(false);

        AssertVerificationProblem(response, "https://w3id.org/security#INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>: "If
    /// expectedProofPurpose was given, and it does not match proof.proofPurpose, an error MUST be raised and SHOULD
    /// convey an error type of PROOF_VERIFICATION_ERROR." A presentation proof MUST
    /// carry the <c>authentication</c> purpose; one signed with a different purpose is not the
    /// challenge/domain/relationship checks' concern but this earlier, purpose-level one.
    /// </summary>
    [TestMethod]
    public async Task PresentationProofPurposeMismatchReportsProofVerificationProblem()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app, canonicalizer: JcsCanonicalizer).ConfigureAwait(false);

        DataIntegritySecuredPresentation presentation = await SignPresentationAsync(
            "challenge-xyz", "verifier.example").ConfigureAwait(false);
        JsonObject document = JsonNode.Parse(SerializePresentation(presentation))!.AsObject();
        DataIntegrityContextTamperingFixture.FirstProof(document)["proofPurpose"] = "assertionMethod";

        string body = "{\"verifiablePresentation\":" + document.ToJsonString()
            + ",\"options\":{\"challenge\":\"challenge-xyz\",\"domain\":\"verifier.example\",\"returnProblemDetails\":true}}";

        using JsonDocument response = await PostPresentationWireAsync(app, segment, body, 200).ConfigureAwait(false);

        AssertVerificationProblem(response, "https://w3id.org/security#PROOF_VERIFICATION_ERROR");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>: "If
    /// expectedProofPurpose was given, and it does not match proof.proofPurpose, an error MUST be raised and SHOULD
    /// convey an error type of PROOF_VERIFICATION_ERROR." A credential proof declaring a purpose outside the modelled
    /// verification relationships, here an extension purpose URL, still carries its <c>verificationMethod</c>, so the
    /// verifier refuses it for that purpose mismatch and not as a proof whose mandatory members are missing.
    /// </summary>
    [TestMethod]
    public async Task ExtensionProofPurposeReportsPurposeMismatchProblem()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(false).ConfigureAwait(false);
        JsonObject document = JsonNode.Parse(SerializeCredential(credential))!.AsObject();
        DataIntegrityContextTamperingFixture.FirstProof(document)["proofPurpose"] = "https://purposes.example/vouch";
        string body = "{\"verifiableCredential\":" + document.ToJsonString() + ",\"options\":{\"returnProblemDetails\":true}}";

        using JsonDocument response = await PostCredentialWireAsync(app, segment, body, 200).ConfigureAwait(false);

        AssertVerificationProblem(response, "https://w3id.org/security#PROOF_VERIFICATION_ERROR");
        Assert.Contains("purpose does not match", response.RootElement.GetProperty("problemDetails")[0].GetProperty("detail").GetString()!,
            StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#processing-errors">Data Integrity §4.7</see>:
    /// PROOF_TRANSFORMATION_ERROR means an error was encountered during the transformation process;
    /// <see cref="VcalmVerifierEndpoints"/> must retain that cause when context loading fails.
    /// </summary>
    [TestMethod]
    [DataRow("refused")]
    [DataRow("unreachable")]
    [DataRow("httpRequest")]
    [DataRow("malformedJsonLd")]
    public async Task ContextFetchFailureReportsTransformationProblem(string cause)
    {
        await using TestHostShell app = new(TimeProvider);
        ContextResolverDelegate resolver = cause switch
        {
            "refused" => (_, _, _) => ValueTask.FromResult<string?>(null),
            "httpRequest" => (_, _, _) => ValueTask.FromException<string?>(new HttpRequestException("private-policy-host/path")),
            "malformedJsonLd" => (_, _, _) => ValueTask.FromResult<string?>("{\"@context\":"),
            _ => (_, _, _) => ValueTask.FromException<string?>(new IOException("private-policy-host/path"))
        };
        bool hasCompletedTransformation = false;
        async ValueTask<CanonicalizationResult> CanonicalizeAsync(
            string json, ContextResolverDelegate? contextResolver, ExchangeContext context, CancellationToken cancellationToken)
        {
            CanonicalizationResult result = await RdfcCanonicalizer(json, contextResolver, context, cancellationToken).ConfigureAwait(false);
            hasCompletedTransformation = true;

            return result;
        }

        string segment = await RegisterVerifierAsync(app, canonicalizer: CanonicalizeAsync, contextResolver: resolver).ConfigureAwait(false);
        DataIntegritySecuredCredential credential = await SignCredentialAsync(false).ConfigureAwait(false);
        using JsonDocument response = await PostCredentialWireAsync(app, segment,
            BuildCredentialRequestBody(credential, true), 200).ConfigureAwait(false);
        Assert.IsFalse(hasCompletedTransformation, "The failure must occur inside transformation.");
        AssertVerificationProblem(response, "https://w3id.org/security#PROOF_TRANSFORMATION_ERROR");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#processing-errors">Data Integrity §4.7</see>:
    /// PROOF_TRANSFORMATION_ERROR, "An error was encountered during the transformation process." A JSON-LD
    /// context fetch that ends on its own budget while the caller still waits is such an error, so the verifier
    /// reports it with that type in an HTTP 200 result instead of treating it as the caller's cancellation.
    /// </summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task ContextFetchBudgetCancellationReportsTransformationProblem(bool isPresentation)
    {
        await using TestHostShell app = new(TimeProvider);
        bool hasLiveCallerToken = false;
        ValueTask<string?> ResolveContextOnExpiredBudgetAsync(Uri contextUri, ExchangeContext context, CancellationToken cancellationToken)
        {
            hasLiveCallerToken = !cancellationToken.IsCancellationRequested;

            return ValueTask.FromException<string?>(new OperationCanceledException("private-policy-host/path"));
        }

        string segment = await RegisterVerifierAsync(app, contextResolver: ResolveContextOnExpiredBudgetAsync).ConfigureAwait(false);
        string body = isPresentation
            ? BuildPresentationRequestBody(await SignPresentationAsync("challenge", "domain").ConfigureAwait(false), "challenge", "domain")
            : BuildCredentialRequestBody(await SignCredentialAsync(false).ConfigureAwait(false), true);
        JsonObject request = JsonNode.Parse(body)!.AsObject();
        request["options"]!["returnProblemDetails"] = true;
        using JsonDocument response = isPresentation
            ? await PostPresentationWireAsync(app, segment, request.ToJsonString(), 200).ConfigureAwait(false)
            : await PostCredentialWireAsync(app, segment, request.ToJsonString(), 200).ConfigureAwait(false);

        Assert.IsTrue(hasLiveCallerToken, "The context fetch must end while the caller's token is still live.");
        AssertVerificationProblem(response, "https://w3id.org/security#PROOF_TRANSFORMATION_ERROR");
        string detail = response.RootElement.GetProperty("problemDetails")[0].GetProperty("detail").GetString()!;
        Assert.Contains("proof transformation", detail, StringComparison.Ordinal);
        Assert.Contains("cancelled by its own budget", detail, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#processing-errors">Data Integrity §4.7</see>:
    /// PROOF_VERIFICATION_ERROR, "An error was encountered during proof verification." A digest function whose own budget
    /// runs out while the caller still waits reports that cancellation inside an exception of its own, as the inner
    /// exception of its own fault or among the inner exceptions of an aggregate; the verifier recognises the carried
    /// cancellation as the dependency's own budget and reports the error of the phase it happened in, naming the stall,
    /// in an HTTP 200 result, whether the proof is a credential's or a presentation's.
    /// </summary>
    [TestMethod]
    [DataRow(false, "wrapped")]
    [DataRow(false, "aggregated")]
    [DataRow(true, "wrapped")]
    [DataRow(true, "aggregated")]
    public async Task WrappedDigestCancellationReportsVerificationProblem(bool isPresentation, string cancellationShape)
    {
        await using TestHostShell app = new(TimeProvider);
        bool hasLiveCallerToken = false;
        ValueTask<(DigestValue Result, CryptoEvent? Event)> ComputeDigestOnExpiredBudgetAsync(
            System.Buffers.ReadOnlySequence<byte> input,
            int outputByteLength,
            Tag tag,
            BaseMemoryPool pool,
            System.Collections.Frozen.FrozenDictionary<string, object>? context,
            CancellationToken cancellationToken)
        {
            hasLiveCallerToken = !cancellationToken.IsCancellationRequested;

            return ValueTask.FromException<(DigestValue Result, CryptoEvent? Event)>(CreateOwnBudgetCancellation(cancellationShape));
        }

        string segment = await RegisterVerifierAsync(app, canonicalizer: isPresentation ? JcsCanonicalizer : RdfcCanonicalizer).ConfigureAwait(false);
        await AlterVerificationAsync(app, verification => verification with { ComputeDigest = ComputeDigestOnExpiredBudgetAsync }).ConfigureAwait(false);
        string body = isPresentation
            ? BuildPresentationRequestBody(await SignPresentationAsync("challenge", "domain").ConfigureAwait(false), "challenge", "domain", returnProblemDetails: true)
            : BuildCredentialRequestBody(await SignCredentialAsync(false).ConfigureAwait(false), returnProblemDetails: true);
        using JsonDocument response = isPresentation
            ? await PostPresentationWireAsync(app, segment, body, 200).ConfigureAwait(false)
            : await PostCredentialWireAsync(app, segment, body, 200).ConfigureAwait(false);

        Assert.IsTrue(hasLiveCallerToken, "The digest must end while the caller's token is still live.");
        AssertVerificationProblem(response, "https://w3id.org/security#PROOF_VERIFICATION_ERROR");
        string detail = response.RootElement.GetProperty("problemDetails")[0].GetProperty("detail").GetString()!;
        Assert.Contains("proof verification", detail, StringComparison.Ordinal);
        Assert.Contains("cancelled by its own budget", detail, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verify-presentation">VCALM §3.3.2</see>: "A 200 status indicates
    /// the verification process itself succeeded, regardless of whether the presentation and/or credentials were
    /// determined to be valid or invalid." A caller that abandons its request while a JSON-LD context fetch runs
    /// ends that process, so the verifier produces no response for it at all: the cancellation is the caller's,
    /// not an error encountered during the transformation process
    /// (<see href="https://www.w3.org/TR/vc-data-integrity/#processing-errors">Data Integrity §4.7</see>).
    /// </summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task CallerCancellationDuringContextFetchProducesNoVerdict(bool isPresentation)
    {
        await using TestHostShell app = new(TimeProvider);
        TaskCompletionSource hasEnteredFetch = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource hasObservedCancellation = new(TaskCreationOptions.RunContinuationsAsynchronously);
        async ValueTask<string?> ResolveContextUntilCancelledAsync(Uri contextUri, ExchangeContext context, CancellationToken cancellationToken)
        {
            await VcalmWireFixtures.HangUntilCancelledAsync(hasEnteredFetch, hasObservedCancellation, cancellationToken).ConfigureAwait(false);

            return null;
        }

        string segment = await RegisterVerifierAsync(app, contextResolver: ResolveContextUntilCancelledAsync).ConfigureAwait(false);
        string body = isPresentation
            ? BuildPresentationRequestBody(await SignPresentationAsync("challenge", "domain").ConfigureAwait(false), "challenge", "domain")
            : BuildCredentialRequestBody(await SignCredentialAsync(false).ConfigureAwait(false), true);
        string endpoint = isPresentation
            ? WellKnownVcalmEndpointNames.VcalmPresentationsVerify
            : WellKnownVcalmEndpointNames.VcalmCredentialsVerify;

        await VcalmWireFixtures.AssertAbandonedRequestProducesNoResponseAsync(
            app, segment, endpoint, body, hasEnteredFetch.Task, hasObservedCancellation.Task, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verify-presentation">VCALM §3.3.2</see>: "A 200 status
    /// indicates the verification process itself succeeded, regardless of whether the presentation
    /// and/or credentials were determined to be valid or invalid." A caller that abandons its request
    /// while the controller-document fetch runs ends that process, so
    /// the verifier produces no response for it at all — the same no-verdict property
    /// <see cref="CallerCancellationDuringContextFetchProducesNoVerdict"/> pins for the context-fetch
    /// dependency, exercised here for the controller-document one.
    /// </summary>
    [TestMethod]
    public async Task CallerCancellationDuringControllerFetchProducesNoVerdict()
    {
        await using TestHostShell app = new(TimeProvider);
        TaskCompletionSource hasEnteredFetch = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource hasObservedCancellation = new(TaskCreationOptions.RunContinuationsAsynchronously);
        async ValueTask<DidResolutionResult> ResolveControllerUntilCancelledAsync(
            string did, DidResolutionOptions options, ExchangeContext context, CancellationToken cancellationToken)
        {
            await VcalmWireFixtures.HangUntilCancelledAsync(hasEnteredFetch, hasObservedCancellation, cancellationToken).ConfigureAwait(false);

            return DidResolutionResult.Failure(DidResolutionErrors.NotFound);
        }

        DidResolver resolver = new(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, ResolveControllerUntilCancelledAsync)));
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);
        await AlterVerificationAsync(app, verification => verification with { Resolver = resolver }).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(await SignCredentialAsync(false).ConfigureAwait(false), true);

        await VcalmWireFixtures.AssertAbandonedRequestProducesNoResponseAsync(
            app, segment, WellKnownVcalmEndpointNames.VcalmCredentialsVerify, body, hasEnteredFetch.Task,
            hasObservedCancellation.Task, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#error-handling">VCALM §3.8</see>: "It is recommended to
    /// avoid raising errors while performing verification, and instead gather ProblemDetails objects" —
    /// this bounds the COST of doing so. Within one request, once a dependency fetch (a JSON-LD
    /// context, a controller document, or a status list) has cancelled on its own budget, no further
    /// dependency fetch is attempted for the rest of that SAME request: the remaining contained
    /// credentials report the phase's own problem type without ever reaching the stalling dependency
    /// again, so a single slow host cannot multiply a request's cost by its number of contained
    /// credentials.
    /// </summary>
    [TestMethod]
    public async Task DependencyBudgetExhaustionBoundsRemainingContainedCredentialFetches()
    {
        await AssertContextFetchBudgetBoundsContainedCredentialsAsync(
            () => CreateOwnBudgetCancellation("bare")).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#error-handling">VCALM §3.8</see>: "avoid raising errors while
    /// performing verification, and instead gather ProblemDetails objects". A context loader, or the transport under it,
    /// commonly reports the cancellation of its fetch wrapped in an exception of its own; that wrapper still carries a
    /// fetch that ended on its own budget, so it bounds the rest of the request exactly as an unwrapped cancellation does:
    /// the first contained credential reports <see href="https://www.w3.org/TR/vc-data-integrity/#processing-errors">Data
    /// Integrity §4.7</see> PROOF_TRANSFORMATION_ERROR, "An error was encountered during the transformation process", and
    /// no later dependency fetch of the request is attempted.
    /// </summary>
    [TestMethod]
    public async Task WrappedContextFetchCancellationBoundsRemainingContainedCredentialFetches()
    {
        await AssertContextFetchBudgetBoundsContainedCredentialsAsync(
            () => CreateOwnBudgetCancellation("wrapped")).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#error-handling">VCALM §3.8</see>: "avoid raising errors while
    /// performing verification, and instead gather ProblemDetails objects". A context loader built over a task combinator
    /// reports the cancellation of its fetch as one of the inner exceptions of an <see cref="AggregateException"/>, not
    /// necessarily its first; that aggregate still carries a fetch that ended on its own budget, so it bounds the rest of
    /// the request exactly as an unwrapped cancellation does: the first contained credential reports
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#processing-errors">Data Integrity §4.7</see>
    /// PROOF_TRANSFORMATION_ERROR, "An error was encountered during the transformation process", and no later dependency
    /// fetch of the request is attempted.
    /// </summary>
    [TestMethod]
    public async Task AggregatedContextFetchCancellationBoundsRemainingContainedCredentialFetches()
    {
        await AssertContextFetchBudgetBoundsContainedCredentialsAsync(
            () => CreateOwnBudgetCancellation("aggregated")).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies, over the real wire, a presentation of three contained credentials of one issuer whose JSON-LD context
    /// fetch fails with <paramref name="ownBudgetFailure"/> while the caller's token is live, and asserts the request's
    /// cost is bounded: one context fetch in all, the first credential reporting PROOF_TRANSFORMATION_ERROR for the fetch
    /// that ended on its own budget, and the others, whose shared controller document the request already resolved, each
    /// reporting only PROOF_TRANSFORMATION_ERROR for a transformation never attempted.
    /// </summary>
    /// <param name="ownBudgetFailure">Creates the exception the context fetch ends with.</param>
    private async Task AssertContextFetchBudgetBoundsContainedCredentialsAsync(Func<Exception> ownBudgetFailure)
    {
        await using TestHostShell app = new(TimeProvider);
        int fetchAttempts = 0;
        ValueTask<string?> CountingStallingContextResolverAsync(Uri contextUri, ExchangeContext context, CancellationToken cancellationToken)
        {
            _ = Interlocked.Increment(ref fetchAttempts);

            return ValueTask.FromException<string?>(ownBudgetFailure());
        }

        string segment = await RegisterVerifierAsync(app, contextResolver: CountingStallingContextResolverAsync).ConfigureAwait(false);

        DataIntegritySecuredCredential credentialOne = await SignCredentialAsync(false).ConfigureAwait(false);
        DataIntegritySecuredCredential credentialTwo = await SignCredentialAsync(false).ConfigureAwait(false);
        DataIntegritySecuredCredential credentialThree = await SignCredentialAsync(false).ConfigureAwait(false);

        VerifiablePresentation presentation = new()
        {
            Context = Context.FromIris(Context.Credentials20),
            Type = ["VerifiablePresentation"],
            VerifiableCredential = [credentialOne, credentialTwo, credentialThree]
        };
        string body = "{\"presentation\":" + SerializePresentation(presentation)
            + ",\"options\":{\"returnProblemDetails\":true,\"returnResults\":true}}";

        using JsonDocument response = await PostPresentationWireAsync(app, segment, body, 200).ConfigureAwait(false);

        Assert.AreEqual(1, fetchAttempts,
            "Once the first contained credential's dependency fetch exhausts its own budget, no further "
            + "dependency fetch is attempted for the rest of this request.");
        Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean());

        JsonElement credentialResults = response.RootElement
            .GetProperty(VcalmParameterNames.Results).GetProperty(VcalmParameterNames.Credentials);
        Assert.AreEqual(3, credentialResults.GetArrayLength(), "All three contained credentials must be reported.");
        AssertSoleCredentialProblem(credentialResults[0],
            "https://w3id.org/security#PROOF_TRANSFORMATION_ERROR", "cancelled by its own budget.");
        AssertSoleCredentialProblem(credentialResults[1],
            "https://w3id.org/security#PROOF_TRANSFORMATION_ERROR", "not attempted: an earlier dependency of this request exhausted its budget.");
        AssertSoleCredentialProblem(credentialResults[2],
            "https://w3id.org/security#PROOF_TRANSFORMATION_ERROR", "not attempted: an earlier dependency of this request exhausted its budget.");
    }


    /// <summary>
    /// Checks that one contained credential's result is <c>verified:false</c> with exactly one ProblemDetail of
    /// <paramref name="expectedType"/> whose detail ends with <paramref name="expectedDetailEnding"/>.
    /// </summary>
    /// <param name="credentialResult">The credential's entry of the response's <c>results.credentials</c>.</param>
    /// <param name="expectedType">The literal problem type URL the entry must carry.</param>
    /// <param name="expectedDetailEnding">The ending the problem's detail must carry.</param>
    private static void AssertSoleCredentialProblem(JsonElement credentialResult, string expectedType, string expectedDetailEnding)
    {
        Assert.IsFalse(credentialResult.GetProperty(VcalmParameterNames.Verified).GetBoolean());
        JsonElement problems = credentialResult.GetProperty(VcalmParameterNames.ProblemDetails);
        Assert.AreEqual(1, problems.GetArrayLength(), "Each contained credential reports exactly one problem.");
        Assert.AreEqual(expectedType, problems[0].GetProperty(VcalmParameterNames.ProblemType).GetString());
        Assert.EndsWith(expectedDetailEnding, problems[0].GetProperty("detail").GetString(), StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see>: "If controllerDocument
    /// is not a conforming controlled identifier document, an error MUST be raised and SHOULD convey an error type of
    /// INVALID_CONTROLLED_IDENTIFIER_DOCUMENT." A controller document fetch that ends on its own budget while the
    /// caller still waits, the cancellation bare or carried inside the resolver's own exception, retrieves no document,
    /// so the verifier reports that type in an HTTP 200 result, naming the stall, instead of treating it as the caller's
    /// cancellation.
    /// </summary>
    [TestMethod]
    [DataRow("bare")]
    [DataRow("wrapped")]
    [DataRow("aggregated")]
    public async Task ControllerFetchBudgetCancellationReportsDocumentProblem(string cancellationShape)
    {
        bool hasLiveCallerToken = false;
        ValueTask<DidResolutionResult> ResolveControllerOnExpiredBudgetAsync(
            string did, DidResolutionOptions options, ExchangeContext context, CancellationToken cancellationToken)
        {
            hasLiveCallerToken = !cancellationToken.IsCancellationRequested;

            return ValueTask.FromException<DidResolutionResult>(CreateOwnBudgetCancellation(cancellationShape));
        }

        DidResolver resolver = new(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, ResolveControllerOnExpiredBudgetAsync)));
        DataIntegritySecuredCredential credential = await SignCredentialAsync(false).ConfigureAwait(false);
        using JsonDocument response = await PostControllerCaseAsync(resolver, credential).ConfigureAwait(false);

        Assert.IsTrue(hasLiveCallerToken, "The controller document fetch must end while the caller's token is still live.");
        AssertVerificationProblem(response, "https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT");
        string detail = response.RootElement.GetProperty("problemDetails")[0].GetProperty("detail").GetString()!;
        Assert.Contains("could not be retrieved", detail, StringComparison.Ordinal);
        Assert.Contains("cancelled by its own budget", detail, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see>: "If controllerDocument
    /// is not a conforming controlled identifier document, an error MUST be raised and SHOULD convey an error type of
    /// INVALID_CONTROLLED_IDENTIFIER_DOCUMENT." The controller-document resolution step classifies by phase, not
    /// by exception type: a resolver whose METHOD SELECTOR itself throws (rather than the method resolver it would
    /// select) never retrieves a controller document either, and must report the same type — never an unclassified
    /// PROOF_VERIFICATION_ERROR that names no phase.
    /// </summary>
    [TestMethod]
    public async Task ThrowingResolverSelectorReportsDocumentProblem()
    {
        DidResolver resolver = new(static _ => throw new InvalidOperationException("private-policy-host/path"));
        DataIntegritySecuredCredential credential = await SignCredentialAsync(false).ConfigureAwait(false);
        using JsonDocument response = await PostControllerCaseAsync(resolver, credential).ConfigureAwait(false);

        AssertVerificationProblem(response, "https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#problem-details">VC Data Model 2.0 §7.2</see>: RANGE_ERROR,
    /// "A provided value is outside of the expected range of an associated value, such as a given index value for an
    /// array being larger than the current size of the array." A credential carrying more proofs than the verifier
    /// accepts per document is refused with that type before any of its proofs costs a controller resolution or a
    /// canonicalization.
    /// </summary>
    [TestMethod]
    public async Task CredentialWithMoreProofsThanTheVerifierAcceptsReportsRangeError()
    {
        await using TestHostShell app = new(TimeProvider);
        int canonicalizations = 0;
        ValueTask<CanonicalizationResult> CountingCanonicalizeAsync(
            string json, ContextResolverDelegate? contextResolver, ExchangeContext context, CancellationToken cancellationToken)
        {
            _ = Interlocked.Increment(ref canonicalizations);

            return RdfcCanonicalizer(json, contextResolver, context, cancellationToken);
        }

        int resolutions = 0;
        ValueTask<DidResolutionResult> CountingResolveAsync(
            string did, DidResolutionOptions options, ExchangeContext context, CancellationToken cancellationToken)
        {
            _ = Interlocked.Increment(ref resolutions);

            return KeyDidResolverSeam.ResolveAsync(did, context, options, cancellationToken);
        }

        DidResolver resolver = new(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, CountingResolveAsync)));
        string segment = await RegisterVerifierAsync(app, canonicalizer: CountingCanonicalizeAsync).ConfigureAwait(false);
        await AlterVerificationAsync(app, verification => verification with { Resolver = resolver }).ConfigureAwait(false);

        //Nine proofs: one more than the eight a verifier accepts per document by default.
        DataIntegritySecuredCredential credential = await SignCredentialAsync(false).ConfigureAwait(false);
        List<DataIntegrityProof> proofs = credential.Proof!;
        proofs.AddRange(Enumerable.Repeat(proofs[0], 8));

        using JsonDocument response = await PostCredentialWireAsync(app, segment,
            BuildCredentialRequestBody(credential, returnProblemDetails: true), 200).ConfigureAwait(false);

        AssertVerificationProblem(response, "https://www.w3.org/TR/vc-data-model#RANGE_ERROR");
        Assert.AreEqual(0, resolutions, "No controller document is resolved for a document refused by its proof count.");
        Assert.AreEqual(0, canonicalizations, "No proof of a document refused by its proof count is transformed.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3 Retrieve Verification
    /// Method</see> dereferences the controller document once for a verification method identifier and checks that one
    /// method against it. Proofs of one document that all name the same verification method share that retrieval and
    /// that check: the controller document is resolved once and the method's key material decoded once, however many
    /// proofs name it. The context is refused here so the verification stops in the transformation, before any
    /// signature check decodes the key again.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public async Task ProofsNamingOneMethodShareOneResolutionAndOneKeyDecode()
    {
        await using TestHostShell app = new(TimeProvider);
        DataIntegritySecuredCredential credential = await SignCredentialAsync(false).ConfigureAwait(false);
        List<DataIntegrityProof> proofs = credential.Proof!;
        proofs.AddRange(Enumerable.Repeat(proofs[0], 2));

        string verificationMethodId = proofs[0].VerificationMethod!.Id!;
        DidResolutionResult issuerResolution = await KeyDidResolverSeam.ResolveAsync(
            verificationMethodId[..verificationMethodId.IndexOf('#', StringComparison.Ordinal)], EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string issuerKeyPayload = ((PublicKeyMultibase)issuerResolution.Document!.VerificationMethod![0].KeyFormat!).Key[1..];

        int resolutions = 0;
        ValueTask<DidResolutionResult> CountingResolveAsync(
            string did, DidResolutionOptions options, ExchangeContext context, CancellationToken cancellationToken)
        {
            _ = Interlocked.Increment(ref resolutions);

            return ValueTask.FromResult(issuerResolution);
        }

        DidResolver resolver = new(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, CountingResolveAsync)));
        string segment = await RegisterVerifierAsync(app, contextResolver: (_, _, _) => ValueTask.FromResult<string?>(null)).ConfigureAwait(false);
        await AlterVerificationAsync(app, verification => verification with { Resolver = resolver }).ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        int keyDecodes = 0;
        DecoderSelector previousSelector = DefaultCoderSelector.SelectDecoder;
        DefaultCoderSelector.SelectDecoder = keyFormatType =>
        {
            DecodeDelegate decode = previousSelector(keyFormatType);

            return (source, pool) =>
            {
                if(source.SequenceEqual(issuerKeyPayload))
                {
                    _ = Interlocked.Increment(ref keyDecodes);
                }

                return decode(source, pool);
            };
        };
        try
        {
            using JsonDocument response = await PostCredentialWireAsync(app, segment,
                BuildCredentialRequestBody(credential, returnProblemDetails: true), 200).ConfigureAwait(false);
            Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean());
        }
        finally
        {
            DefaultCoderSelector.SelectDecoder = previousSelector;
        }

        Assert.AreEqual(1, resolutions, "The controller document is resolved once for the three proofs naming it.");
        Assert.AreEqual(1, keyDecodes, "The verification method's key material is decoded once for the three proofs naming it.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3 Retrieve Verification
    /// Method</see>: "Let controllerDocument be the result of dereferencing controllerDocumentUrl, according to the rules
    /// of the URL scheme and using the supplied options." Within one verify request that dereference is made once per
    /// controller document URL: a presentation of several credentials whose proofs all name one did:web issuer resolves
    /// the issuer's controller document once, and every credential verifies against it.
    /// </summary>
    [TestMethod]
    public async Task ContainedCredentialsOfOneIssuerShareOneControllerResolution()
    {
        //Three contained credentials: more than one, so a resolution per credential would be counted twice over.
        const int ContainedCredentialCount = 3;

        await using TestHostShell app = new(TimeProvider);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;
        DidDocument issuerDocument = await WebDidBuilder.BuildAsync(
            issuerPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            IssuerWebDomain,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        DidResolutionResult issuerResolution = DidResolutionResult.Success(issuerDocument, DidDocumentMetadata.Empty, "application/did+json");

        int resolutions = 0;
        ValueTask<DidResolutionResult> CountingResolveAsync(
            string did, DidResolutionOptions options, ExchangeContext context, CancellationToken cancellationToken)
        {
            _ = Interlocked.Increment(ref resolutions);

            return ValueTask.FromResult(issuerResolution);
        }

        DidResolver resolver = new(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.WebDidMethodPrefix, CountingResolveAsync)));
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);
        await AlterVerificationAsync(app, verification => verification with { Resolver = resolver }).ConfigureAwait(false);

        List<VerifiableCredential> credentials = [];
        for(int i = 0; i < ContainedCredentialCount; i++)
        {
            credentials.Add(await SignCredentialAsIssuerAsync(
                issuerPrivate,
                issuerDocument.VerificationMethod![0].Id!,
                issuerDocument.Id!.ToString(),
                validUntilPast: false,
                credentialStatus: null,
                schemas: null).ConfigureAwait(false));
        }

        VerifiablePresentation presentation = new()
        {
            Context = Context.FromIris(Context.Credentials20),
            Type = ["VerifiablePresentation"],
            VerifiableCredential = credentials
        };
        string body = "{\"presentation\":" + SerializePresentation(presentation)
            + ",\"options\":{\"returnProblemDetails\":true,\"returnResults\":true}}";

        using JsonDocument response = await PostPresentationWireAsync(app, segment, body, 200).ConfigureAwait(false);

        Assert.AreEqual(1, resolutions, "The issuer's controller document is resolved once for every credential naming it.");
        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(), response.RootElement.GetRawText());
        JsonElement credentialResults = response.RootElement
            .GetProperty(VcalmParameterNames.Results).GetProperty(VcalmParameterNames.Credentials);
        Assert.AreEqual(ContainedCredentialCount, credentialResults.GetArrayLength(), "Every contained credential is reported.");
        foreach(JsonElement credentialResult in credentialResults.EnumerateArray())
        {
            Assert.IsTrue(credentialResult.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
                "Each credential verifies against the one resolved controller document.");
        }
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation">Data Integrity §4.6</see>
    /// requires an error when context validation fails but names no type; <see cref="VcalmVerifierEndpoints"/>
    /// identifies a failure after transformation with a library-defined RFC 9457 problem type.
    /// </summary>
    [TestMethod]
    public async Task ContextValidationReportsLibraryContextProblem()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);
        await AlterVerificationAsync(app, verification => verification with
        {
            KnownContext = Context.FromIris(Context.Credentials20)
        }).ConfigureAwait(false);
        DataIntegritySecuredCredential credential = await SignCredentialAsync(false).ConfigureAwait(false);
        using JsonDocument response = await PostCredentialWireAsync(app, segment,
            BuildCredentialRequestBody(credential, true), 200).ConfigureAwait(false);
        AssertVerificationProblem(response, "https://verifiable.lumoin.com/problems#CONTEXT_VALIDATION_ERROR");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>:
    /// if securedDocument.proof is not a map, an error MUST be raised and SHOULD convey PARSING_ERROR
    /// through <see cref="VcalmVerifierEndpoints"/>.
    /// </summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task MissingProofReportsParsingProblem(bool isPresentation)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);
        DataIntegritySecuredCredential credential = await SignCredentialAsync(false).ConfigureAwait(false);
        string body = isPresentation
            ? "{\"verifiablePresentation\":{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiablePresentation\"]},\"options\":{\"returnProblemDetails\":true}}"
            : "{\"verifiableCredential\":" + DataIntegrityContextTamperingFixture.MutateSecuredDocumentJson(SerializeCredential(credential), "delete:proof")
                + ",\"options\":{\"returnProblemDetails\":true}}";
        using JsonDocument response = isPresentation
            ? await PostPresentationWireAsync(app, segment, body, 200).ConfigureAwait(false)
            : await PostCredentialWireAsync(app, segment, body, 200).ConfigureAwait(false);
        AssertVerificationProblem(response, "https://www.w3.org/TR/vc-data-model#PARSING_ERROR");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>:
    /// missing type, verificationMethod or proofPurpose, or a purpose mismatch, MUST raise an error
    /// and SHOULD convey PROOF_VERIFICATION_ERROR through <see cref="VcalmVerifierEndpoints"/>.
    /// </summary>
    [TestMethod]
    [DataRow("type", null)]
    [DataRow("verificationMethod", null)]
    [DataRow("proofPurpose", null)]
    [DataRow("proofPurpose", "authentication")]
    public async Task InvalidProofOptionsReportProofVerificationProblem(string member, string? value)
    {
        await AssertCredentialMutationProblemAsync(member, JsonValue.Create(value),
            "https://w3id.org/security#PROOF_VERIFICATION_ERROR").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>:
    /// a domain or challenge unequal to the expected value MUST raise INVALID_DOMAIN_ERROR or
    /// INVALID_CHALLENGE_ERROR respectively through <see cref="VcalmVerifierEndpoints"/>.
    /// </summary>
    [TestMethod]
    [DataRow("domain", "https://w3id.org/security#INVALID_DOMAIN_ERROR")]
    [DataRow("challenge", "https://w3id.org/security#INVALID_CHALLENGE_ERROR")]
    public async Task PresentationBindingMismatchReportsBindingProblem(string member, string expectedType)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app, canonicalizer: JcsCanonicalizer).ConfigureAwait(false);
        DataIntegritySecuredPresentation presentation = await SignPresentationAsync("challenge", "domain").ConfigureAwait(false);
        JsonObject request = JsonNode.Parse(BuildPresentationRequestBody(presentation,
            member == "challenge" ? "other" : "challenge", member == "domain" ? "other" : "domain"))!.AsObject();
        request["options"]!["returnProblemDetails"] = true;
        using JsonDocument response = await PostPresentationWireAsync(app, segment, request.ToJsonString(), 200).ConfigureAwait(false);
        AssertVerificationProblem(response, expectedType);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see> runs each binding
    /// check only for a value the verifier gave: "If domain was given, and it does not contain the same strings as
    /// proof.domain (treating a single string as a set containing just that string), an error MUST be raised" and "If
    /// challenge was given, and it does not match proof.challenge, an error MUST be raised". A presentation proof
    /// carrying no domain, and no challenge when none was given either, is therefore not a binding failure: it verifies
    /// true with no ProblemDetail.
    /// </summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task PresentationWithoutBindingTheVerifierDidNotGiveVerifiesTrue(bool isChallengeGiven)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app, canonicalizer: JcsCanonicalizer).ConfigureAwait(false);

        Verifiable.Cryptography.PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keyPair.PublicKey;
        using PrivateKeyMemory holderPrivate = keyPair.PrivateKey;
        DidDocument holderDidDocument = await KeyDidBuilder.BuildAsync(
            holderPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            BaseMemoryPool.Shared,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        const string Challenge = "challenge-without-domain";
        string? givenChallenge = isChallengeGiven ? Challenge : null;
        DataIntegritySecuredPresentation presentation = await DataIntegrityContextTamperingFixture.SignJcsPresentationAsync(
            holderDidDocument, holderPrivate, givenChallenge, domain: null, TimeProvider.GetUtcNow().UtcDateTime).ConfigureAwait(false);
        string options = isChallengeGiven
            ? "{\"challenge\":\"" + Challenge + "\",\"returnProblemDetails\":true}"
            : "{\"returnProblemDetails\":true}";
        string body = "{\"verifiablePresentation\":" + SerializePresentation(presentation) + ",\"options\":" + options + "}";

        using JsonDocument response = await PostPresentationWireAsync(app, segment, body, 200).ConfigureAwait(false);

        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(), response.RootElement.GetRawText());
        Assert.AreEqual(0, response.RootElement.GetProperty(VcalmParameterNames.ProblemDetails).GetArrayLength(),
            "A binding the verifier never gave is not checked, so nothing is reported against it.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#error-handling">VCALM §3.8</see>:
    /// the type key MUST be present and its value MUST be a URL identifying the type of problem.
    /// An unavailable securing mechanism reports the library's unsupported-securing-mechanism type.
    /// </summary>
    [TestMethod]
    [DataRow("credentialEnvelope")]
    [DataRow("presentationEnvelope")]
    [DataRow("proofType")]
    [DataRow("cryptosuite")]
    [DataRow("unwired")]
    [DataRow("unwiredSd")]
    [DataRow("unwiredBbs")]
    public async Task UnsupportedMechanismReportsLibraryProblem(string cause)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);
        DataIntegritySecuredCredential credential = await SignCredentialAsync(false).ConfigureAwait(false);
        if(cause == "unwired")
        {
            await AlterVerificationAsync(app, _ => null).ConfigureAwait(false);
        }

        JsonObject document = JsonNode.Parse(SerializeCredential(credential))!.AsObject();
        JsonObject proof = DataIntegrityContextTamperingFixture.FirstProof(document);
        _ = cause switch
        {
            "proofType" => proof["type"] = "OtherProof",
            "cryptosuite" => proof["cryptosuite"] = "unregistered-suite",
            "unwiredSd" => proof["cryptosuite"] = "ecdsa-sd-2023",
            "unwiredBbs" => proof["cryptosuite"] = "bbs-2023",
            _ => null
        };

        string body = cause switch
        {
            "credentialEnvelope" => "{\"verifiableCredential\":{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"EnvelopedVerifiableCredential\"],\"id\":\"data:application/vc+jwt,eyJhbGciOiJFUzI1NiJ9.e30.c2ln\"},\"options\":{\"returnProblemDetails\":true}}",
            "presentationEnvelope" => "{\"verifiablePresentation\":{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"EnvelopedVerifiablePresentation\"],\"id\":\"data:application/vp+jwt,eyJhbGciOiJFUzI1NiJ9.e30.c2ln\"},\"options\":{\"returnProblemDetails\":true}}",
            _ => "{\"verifiableCredential\":" + document.ToJsonString() + ",\"options\":{\"returnProblemDetails\":true}}"
        };
        using JsonDocument response = cause == "presentationEnvelope"
            ? await PostPresentationWireAsync(app, segment, body, 200).ConfigureAwait(false)
            : await PostCredentialWireAsync(app, segment, body, 200).ConfigureAwait(false);
        AssertVerificationProblem(response, "https://verifiable.lumoin.com/problems#UNSUPPORTED_SECURING_MECHANISM");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#error-handling">VCALM §3.8</see> advises sanitizing all server errors;
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#processing-errors">Data Integrity §4.7</see>
    /// defines PROOF_VERIFICATION_ERROR for an error encountered during proof verification.
    /// <see cref="VcalmVerifierEndpoints"/> preserves the phase without exposing delegate exceptions.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    [DataRow("proofDecode")]
    [DataRow("registry")]
    public async Task UnexpectedVerificationExceptionReportsPhaseProblem(string cause)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);
        DataIntegritySecuredCredential credential = await SignCredentialAsync(false).ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            if(cause == "registry")
            {
                CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.Initialize(
                    (_, _, _) => MicrosoftCryptographicFunctionsAdapter.SignP256Async,
                    (_, _, _) => throw new ArgumentException("private-policy-host/path"));
            }
            else
            {
                await AlterVerificationAsync(app, verification => verification with
                {
                    DecodeProofValue = (_, _, _) => throw new InvalidOperationException("private-policy-host/path")
                }).ConfigureAwait(false);
            }

            using JsonDocument response = await PostCredentialWireAsync(app, segment,
                BuildCredentialRequestBody(credential, true), 200).ConfigureAwait(false);
            AssertVerificationProblem(response, "https://w3id.org/security#PROOF_VERIFICATION_ERROR");
            Assert.Contains("proof verification", response.RootElement.GetProperty("problemDetails")[0].GetProperty("detail").GetString()!, StringComparison.Ordinal);
        }
        finally
        {
            TestSetup.Setup();
        }
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/cid-1.0/#retrieve-verification-method">CID §3.3</see>:
    /// if controllerDocument is not a conforming controlled identifier document, an error MUST
    /// be raised and SHOULD convey INVALID_CONTROLLED_IDENTIFIER_DOCUMENT.
    /// </summary>
    [TestMethod]
    [DataRow("invalidDid")]
    [DataRow("invalidDidUrl")]
    public async Task ResolverRejectionOfValidUrlReportsDocumentProblem(string cause)
    {
        await AssertControllerProblemAsync(cause,
            "https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#processing-errors">Data Integrity §4.7</see>:
    /// PROOF_TRANSFORMATION_ERROR means an error was encountered during the transformation process.
    /// </summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task UnexpectedTransformationExceptionReportsPhaseProblem(bool isPresentation)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);
        await AlterVerificationAsync(app, verification => verification with
        {
            Canonicalize = (_, _, _, _) => throw new InvalidOperationException("private-policy-host/path")
        }).ConfigureAwait(false);
        string body = isPresentation
            ? BuildPresentationRequestBody(await SignPresentationAsync("challenge", "domain").ConfigureAwait(false), "challenge", "domain")
            : BuildCredentialRequestBody(await SignCredentialAsync(false).ConfigureAwait(false), true);
        JsonObject request = JsonNode.Parse(body)!.AsObject();
        request["options"]!["returnProblemDetails"] = true;
        using JsonDocument response = isPresentation
            ? await PostPresentationWireAsync(app, segment, request.ToJsonString(), 200).ConfigureAwait(false)
            : await PostCredentialWireAsync(app, segment, request.ToJsonString(), 200).ConfigureAwait(false);
        AssertVerificationProblem(response, "https://w3id.org/security#PROOF_TRANSFORMATION_ERROR");
        Assert.Contains("proof transformation", response.RootElement.GetProperty("problemDetails")[0].GetProperty("detail").GetString()!, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>:
    /// if one or more of proof.type, proof.verificationMethod, and proof.proofPurpose does not exist,
    /// an error MUST be raised and SHOULD convey PROOF_VERIFICATION_ERROR.
    /// </summary>
    [TestMethod]
    [DataRow("type")]
    [DataRow("verificationMethod")]
    [DataRow("proofPurpose")]
    public async Task PresentationMissingProofOptionReportsVerificationProblem(string member)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app, canonicalizer: JcsCanonicalizer).ConfigureAwait(false);
        DataIntegritySecuredPresentation presentation = await SignPresentationAsync("challenge", "domain").ConfigureAwait(false);
        JsonObject request = JsonNode.Parse(BuildPresentationRequestBody(presentation, "challenge", "domain"))!.AsObject();
        _ = DataIntegrityContextTamperingFixture.FirstProof(request["verifiablePresentation"]!.AsObject()).Remove(member);
        request["options"]!["returnProblemDetails"] = true;
        using JsonDocument response = await PostPresentationWireAsync(app, segment, request.ToJsonString(), 200).ConfigureAwait(false);
        AssertVerificationProblem(response, "https://w3id.org/security#PROOF_VERIFICATION_ERROR");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#error-handling">VCALM §3.8</see>:
    /// the type key MUST be present and its value MUST be a URL identifying the type of problem.
    /// An unavailable verifier reports the library's unsupported-securing-mechanism type.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    [DataRow(false)]
    [DataRow(true)]
    public async Task UnavailableCryptoRegistryReportsUnsupportedMechanism(bool isUninitialized)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);
        DataIntegritySecuredCredential credential = await SignCredentialAsync(false).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, true);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.Initialize(
                isUninitialized ? null! : (_, _, _) => MicrosoftCryptographicFunctionsAdapter.SignP256Async,
                isUninitialized ? null! : (algorithm, purpose, _) => (algorithm, purpose) switch
                {
                    _ when algorithm.Equals(CryptoAlgorithm.P256) && purpose.Equals(Purpose.Verification) => MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
                    _ => null!
                });
            Assert.AreEqual(!isUninitialized, CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.IsInitialized);
            using JsonDocument response = await PostCredentialWireAsync(app, segment, body, 200).ConfigureAwait(false);
            AssertVerificationProblem(response, "https://verifiable.lumoin.com/problems#UNSUPPORTED_SECURING_MECHANISM");
        }
        finally
        {
            TestSetup.Setup();
        }
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#processing-errors">Data Integrity §4.7</see>:
    /// PROOF_VERIFICATION_ERROR, "An error was encountered during proof verification." A reveal document that
    /// canonicalizes to no statements, a blank node the derived proof's label map does not cover, and a mandatory
    /// index outside the reveal document's statements each leave nothing the base signature is known to cover, so the
    /// selective-disclosure verifier refuses the proof during verification rather than reporting tampering.
    /// </summary>
    [TestMethod]
    [DataRow("emptyStatements")]
    [DataRow("unmappedBlankNode")]
    [DataRow("mandatoryIndex")]
    public async Task SelectiveDisclosureStructuralFailureReportsVerificationProblem(string cause)
    {
        await using TestHostShell app = new(TimeProvider);
        SdIssuerContext sd = await CreateSdIssuerContextAsync().ConfigureAwait(false);
        string segment = await RegisterVerifierAsync(app, sd: sd).ConfigureAwait(false);
        DataIntegritySecuredCredential credential = await CreateDerivedCredentialAsync(sd).ConfigureAwait(false);
        if(cause == "emptyStatements")
        {
            await AlterVerificationAsync(app, verification => verification with
            {
                Canonicalize = (_, _, _, _) => ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = string.Empty })
            }).ConfigureAwait(false);
        }
        else
        {
            credential.Proof![0].ProofValue = MutateDerivedProofStructure(credential.Proof[0].ProofValue!, cause);
        }

        using JsonDocument response = await PostCredentialWireAsync(app, segment, BuildCredentialRequestBody(credential, true), 200).ConfigureAwait(false);
        AssertVerificationProblem(response, "https://w3id.org/security#PROOF_VERIFICATION_ERROR");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#verify-derived-proof-ecdsa-sd-2023">VC-DI-ECDSA §3.6.7 Verify
    /// Derived Proof</see>: "If the length of signatures does not match the length of nonMandatory, an error MUST be
    /// raised and SHOULD convey an error type of PROOF_VERIFICATION_ERROR, indicating that the signature count does not
    /// match the non-mandatory message count." The derived proof here carries no signatures at all for its disclosed
    /// statements.
    /// </summary>
    [TestMethod]
    public async Task SelectiveDisclosureSignatureCountMismatchReportsVerificationProblem()
    {
        await using TestHostShell app = new(TimeProvider);
        SdIssuerContext sd = await CreateSdIssuerContextAsync().ConfigureAwait(false);
        string segment = await RegisterVerifierAsync(app, sd: sd).ConfigureAwait(false);
        DataIntegritySecuredCredential credential = await CreateDerivedCredentialAsync(sd).ConfigureAwait(false);
        credential.Proof![0].ProofValue = MutateDerivedProofStructure(credential.Proof[0].ProofValue!, "signatureCount");

        using JsonDocument response = await PostCredentialWireAsync(app, segment, BuildCredentialRequestBody(credential, true), 200).ConfigureAwait(false);

        AssertVerificationProblem(response, "https://w3id.org/security#PROOF_VERIFICATION_ERROR");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#parsederivedproofvalue">VC-DI-ECDSA §3.5.8
    /// parseDerivedProofValue</see>: "If the proofValue string does not start with u, indicating that it is a
    /// multibase-base64url-no-pad-encoded value, an error MUST be raised and SHOULD convey an error type of
    /// PROOF_VERIFICATION_ERROR."
    /// </summary>
    [TestMethod]
    public async Task DerivedProofValueWithoutBase64UrlPrefixReportsVerificationProblem()
    {
        await using TestHostShell app = new(TimeProvider);
        SdIssuerContext sd = await CreateSdIssuerContextAsync().ConfigureAwait(false);
        string segment = await RegisterVerifierAsync(app, sd: sd).ConfigureAwait(false);
        DataIntegritySecuredCredential credential = await CreateDerivedCredentialAsync(sd).ConfigureAwait(false);

        //The same base64url payload behind the base58btc prefix instead of the required u.
        credential.Proof![0].ProofValue = "z" + credential.Proof[0].ProofValue![1..];

        using JsonDocument response = await PostCredentialWireAsync(app, segment, BuildCredentialRequestBody(credential, true), 200).ConfigureAwait(false);

        AssertVerificationProblem(response, "https://w3id.org/security#PROOF_VERIFICATION_ERROR");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#parsederivedproofvalue">VC-DI-ECDSA §3.5.8
    /// parseDerivedProofValue</see>: "Initialize components to an array that is the result of CBOR-decoding the bytes
    /// that follow the three-byte ECDSA-SD disclosure proof header. If the result is not an array of the following five
    /// elements [...] an error MUST be raised and SHOULD convey an error type of PROOF_VERIFICATION_ERROR." The proof value
    /// here carries the header followed by an empty CBOR array.
    /// </summary>
    [TestMethod]
    public async Task DerivedProofValueWithMalformedComponentsReportsVerificationProblem()
    {
        await using TestHostShell app = new(TimeProvider);
        SdIssuerContext sd = await CreateSdIssuerContextAsync().ConfigureAwait(false);
        string segment = await RegisterVerifierAsync(app, sd: sd).ConfigureAwait(false);
        DataIntegritySecuredCredential credential = await CreateDerivedCredentialAsync(sd).ConfigureAwait(false);

        //The disclosure proof header 0xd9 0x5d 0x01 followed by an empty CBOR array (0x80) in place of the five components.
        ReadOnlySpan<byte> headerAndEmptyArray = [0xd9, 0x5d, 0x01, 0x80];
        credential.Proof![0].ProofValue = "u" + TestSetup.Base64UrlEncoder(headerAndEmptyArray);

        using JsonDocument response = await PostCredentialWireAsync(app, segment, BuildCredentialRequestBody(credential, true), 200).ConfigureAwait(false);

        AssertVerificationProblem(response, "https://w3id.org/security#PROOF_VERIFICATION_ERROR");
    }


    /// <summary>Replaces one structural CBOR component of a <see cref="DerivedProofValue"/> in pooled wire bytes, preserving the signatures verbatim.</summary>
    private static string MutateDerivedProofStructure(string proofValue, string cause)
    {
        using System.Buffers.IMemoryOwner<byte> decoded = TestSetup.Base64UrlDecoder(proofValue.AsSpan(1), Pool);
        Lumoin.Veritas.Cbor.CborReader reader = new(decoded.Memory[3..], CborOptions.Lax);
        Assert.AreEqual(5, reader.ReadStartArray());
        Assert.AreEqual(0x85, decoded.Memory.Span[3], "The fixture uses a definite five-element array.");
        int changedComponent = cause switch
        {
            "signatureCount" => 2,
            "unmappedBlankNode" => 3,
            "mandatoryIndex" => 4,
            _ => throw new AssertFailedException("Unknown structural mutation.")
        };
        using System.Buffers.IMemoryOwner<byte> mutated = Pool.Rent(decoded.Memory.Length + 6);
        decoded.Memory.Span[..4].CopyTo(mutated.Memory.Span);
        int written = 4;
        for(int index = 0; index < 5; ++index)
        {
            ReadOnlyMemory<byte> component = reader.ReadEncodedValue();
            ReadOnlySpan<byte> replacement = index != changedComponent ? component.Span : cause switch
            {
                "signatureCount" => [0x80],
                "unmappedBlankNode" => [0xa0],
                _ => [0x81, 0x1a, 0x7f, 0xff, 0xff, 0xff]
            };
            Assert.IsFalse(component.Span.SequenceEqual(replacement) && index == changedComponent,
                "The mutation must change the fixture's structural component.");
            replacement.CopyTo(mutated.Memory.Span[written..]);
            written += replacement.Length;
        }

        reader.ReadEndArray();

        return "u" + TestSetup.Base64UrlEncoder(mutated.Memory.Span[..written]);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>:
    /// if one or more of proof.type, proof.verificationMethod, and proof.proofPurpose does not exist,
    /// an error MUST be raised and SHOULD convey PROOF_VERIFICATION_ERROR.
    /// </summary>
    [TestMethod]
    [DataRow("type")]
    [DataRow("verificationMethod")]
    [DataRow("proofPurpose")]
    public async Task SelectiveDisclosureMissingProofOptionReportsVerificationProblem(string member)
    {
        await using TestHostShell app = new(TimeProvider);
        SdIssuerContext sd = await CreateSdIssuerContextAsync().ConfigureAwait(false);
        string segment = await RegisterVerifierAsync(app, sd: sd).ConfigureAwait(false);
        DataIntegritySecuredCredential credential = await CreateDerivedCredentialAsync(sd).ConfigureAwait(false);
        JsonObject request = JsonNode.Parse(BuildCredentialRequestBody(credential, true))!.AsObject();
        _ = DataIntegrityContextTamperingFixture.FirstProof(request["verifiableCredential"]!.AsObject()).Remove(member);
        using JsonDocument response = await PostCredentialWireAsync(app, segment, request.ToJsonString(), 200).ConfigureAwait(false);
        AssertVerificationProblem(response, "https://w3id.org/security#PROOF_VERIFICATION_ERROR");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#error-handling">VCALM §3.8</see>:
    /// implementers are strongly advised to sanitize all server errors in production environments.
    /// </summary>
    [TestMethod]
    public async Task SchemaFailureDetailOmitsValidatorInternals()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app,
            schemaValidators: SchemaValidationTestUtilities.CreateSchemaRegistry(),
            resolveSchemaDocument: SchemaValidationTestUtilities.CreateEmbeddedSchemaResolver(TestSchemas)).ConfigureAwait(false);
        DataIntegritySecuredCredential credential = await SignCredentialAsync(false,
            schemas: [new CredentialSchema { Id = EmailSchemaUrl, Type = "JsonSchema" }]).ConfigureAwait(false);
        using JsonDocument response = await PostCredentialWireAsync(app, segment, BuildCredentialRequestBody(credential, true), 200).ConfigureAwait(false);
        AssertVerificationProblem(response, "https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR");
        Assert.AreEqual($"The credential does not conform to its declared schema '{EmailSchemaUrl}'.",
            response.RootElement.GetProperty("problemDetails")[0].GetProperty("detail").GetString());
    }


    /// <summary>
    /// Posts credential JSON over the real wire to <see cref="VcalmVerifierEndpoints"/> through the shared
    /// <see cref="VcalmWireFixtures.PostCredentialWireAsync"/>, bounded by this test's cancellation token.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="segment">The verifier tenant segment.</param>
    /// <param name="body">The verify request body JSON text.</param>
    /// <param name="expectedStatus">The HTTP status the response must carry.</param>
    private Task<JsonDocument> PostCredentialWireAsync(TestHostShell app, string segment, string body, int expectedStatus) =>
        VcalmWireFixtures.PostCredentialWireAsync(app, segment, body, expectedStatus, TestContext.CancellationToken);


    /// <summary>
    /// Posts presentation JSON over the real wire to <see cref="VcalmVerifierEndpoints"/> through the shared
    /// <see cref="VcalmWireFixtures.PostPresentationWireAsync"/>, bounded by this test's cancellation token.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="segment">The verifier tenant segment.</param>
    /// <param name="body">The verify request body JSON text.</param>
    /// <param name="expectedStatus">The HTTP status the response must carry.</param>
    private Task<JsonDocument> PostPresentationWireAsync(TestHostShell app, string segment, string body, int expectedStatus) =>
        VcalmWireFixtures.PostPresentationWireAsync(app, segment, body, expectedStatus, TestContext.CancellationToken);


    /// <summary>Checks the error wire contract emitted by <see cref="VcalmVerifierEndpoints"/>.</summary>
    private static void AssertVerificationProblem(JsonDocument response, string expectedType)
    {
        Assert.IsFalse(response.RootElement.GetProperty("verified").GetBoolean());
        JsonElement problem = response.RootElement.GetProperty("problemDetails")[0];
        Assert.AreEqual(expectedType, problem.GetProperty("type").GetString());
        Assert.AreEqual(expectedType[(expectedType.IndexOf('#', StringComparison.Ordinal) + 1)..], problem.GetProperty("title").GetString());
        Assert.IsFalse(response.RootElement.GetRawText().Contains("private-policy-host/path", StringComparison.Ordinal));
    }


    /// <summary>Alters the host's ordinary <see cref="VcalmCredentialVerification"/> composition.</summary>
    private static async Task AlterVerificationAsync(TestHostShell app,
        Func<VcalmCredentialVerification, VcalmCredentialVerification?> alter)
    {
        await TestHostShell.AlterVcalmAsync(app.Server, integration =>
        {
            integration.VcalmCredentialVerification = alter(integration.VcalmCredentialVerification!);
        }).ConfigureAwait(false);
    }


    /// <summary>Submits a mutated proof through <see cref="VcalmVerifierEndpoints"/> and checks its exact type.</summary>
    private async Task AssertCredentialMutationProblemAsync(string member, JsonNode? value, string expectedType)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);
        DataIntegritySecuredCredential credential = await SignCredentialAsync(false).ConfigureAwait(false);
        JsonObject document = JsonNode.Parse(SerializeCredential(credential))!.AsObject();
        JsonObject proof = DataIntegrityContextTamperingFixture.FirstProof(document);
        if(value is null)
        {
            _ = proof.Remove(member);
        }
        else
        {
            proof[member] = value;
        }

        using JsonDocument response = await PostCredentialWireAsync(app, segment,
            "{\"verifiableCredential\":" + document.ToJsonString() + ",\"options\":{\"returnProblemDetails\":true}}", 200).ConfigureAwait(false);
        AssertVerificationProblem(response, expectedType);
    }


    /// <summary>Exercises CID retrieval failures through the host's <see cref="DidResolver"/>.</summary>
    private async Task AssertControllerProblemAsync(string cause, string expectedType)
    {
        DataIntegritySecuredCredential credential = await SignCredentialAsync(false).ConfigureAwait(false);
        using JsonDocument response = await PostControllerCaseAsync(CreateControllerResolver(cause), credential).ConfigureAwait(false);
        AssertVerificationProblem(response, expectedType);
    }


    /// <summary>
    /// Posts <paramref name="credential"/> over the existing HTTPS host to <see cref="VcalmVerifierEndpoints"/> with
    /// <paramref name="resolver"/> as the verifier's <see cref="VcalmCredentialVerification.Resolver"/>.
    /// </summary>
    private async Task<JsonDocument> PostControllerCaseAsync(DidResolver resolver, DataIntegritySecuredCredential credential)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);
        await AlterVerificationAsync(app, verification => verification with { Resolver = resolver }).ConfigureAwait(false);

        return await PostCredentialWireAsync(app, segment, BuildCredentialRequestBody(credential, true), 200).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds a <see cref="DidResolver"/> whose did:key method derives the controller document locally and then
    /// applies <paramref name="cause"/>: a resolution failure, a thrown fault, or one change to the retrieved document.
    /// </summary>
    private static DidResolver CreateControllerResolver(string cause)
    {
        return new(DidMethodSelectors.FromResolvers((WellKnownDidMethodPrefixes.KeyDidMethodPrefix,
            async (did, options, context, cancellationToken) =>
            {
                DidResolutionResult resolved = await KeyDidResolverSeam.ResolveAsync(did, context, options, cancellationToken).ConfigureAwait(false);
                DidDocument document = resolved.Document!;

                DidResolutionResult? failure = cause switch
                {
                    "unreachable" => DidResolutionResult.Failure(DidResolutionErrors.NotFound),
                    "refused" => DidResolutionResult.Failure(DidResolutionErrors.InternalError with { Detail = "private-policy-host/path" }),
                    "invalidDid" => DidResolutionResult.Failure(DidResolutionErrors.InvalidDid),
                    "invalidDidUrl" => DidResolutionResult.Failure(DidResolutionErrors.InvalidDidUrl),
                    "transport" => throw new IOException("private-policy-host/path"),
                    _ => null
                };
                if(failure is not null)
                {
                    return failure;
                }

                _ = cause switch
                {
                    "keyAgreementType" => (object?)(document.VerificationMethod![0].Type = "X25519KeyAgreementKey2020"),
                    //The type names Ed25519 while the Multikey value carries a P-256 key.
                    "foreignCodec" => (object?)(document.VerificationMethod![0].Type = "Ed25519VerificationKey2020",
                        document.VerificationMethod![0].KeyFormat = new PublicKeyMultibase(P256PublicKeyMultibase)),
                    //A key agreement type, and a method the document leaves out of assertionMethod.
                    "keyAgreementTypeOutsideRelationship" => (object?)(document.VerificationMethod![0].Type = "X25519KeyAgreementKey2020",
                        document.AssertionMethod = []),
                    //A P-256 Multikey value under the Ed25519 type, and a method the document leaves out of assertionMethod.
                    "foreignCodecOutsideRelationship" => (object?)(document.VerificationMethod![0].Type = "Ed25519VerificationKey2020",
                        document.VerificationMethod![0].KeyFormat = new PublicKeyMultibase(P256PublicKeyMultibase),
                        document.AssertionMethod = []),
                    "documentController" => (object?)(document.Controller = [new Controller("not a URL")]),
                    "nullDocumentController" => (object?)(document.Controller = [null!]),
                    "invalidMethodController" => (object?)(document.VerificationMethod![0].Controller = "not a URL"),
                    "invalidMethodType" => (object?)(document.VerificationMethod![0].Type = "not a verification method type"),
                    "emptyMethodKey" => (object?)(document.VerificationMethod![0].KeyFormat = new PublicKeyMultibase(string.Empty)),
                    "nonconforming" => document.Id = null,
                    "documentId" => (object?)(document.Id = new GenericDidMethod("did:key:other")),
                    "emptyJwk" => (object?)(document.VerificationMethod![0].KeyFormat = new PublicKeyJwk()),
                    "methodType" => document.VerificationMethod![0].Type = null,
                    "methodId" => (object?)(document.VerificationMethod![0].Id = did + "#other"),
                    "methodController" => (object?)(document.VerificationMethod![0].Controller = "did:key:other"),
                    "methodKey" => document.VerificationMethod![0].KeyFormat = null,
                    "relationship" => (object?)(document.AssertionMethod = []),
                    "authenticationRelationship" => (object?)(document.Authentication = []),
                    _ => null
                };

                return resolved;
            }
        )));
    }


    /// <summary>
    /// §3.8.1: a structurally
    /// malformed credential — a missing or wrong-typed core member, or a missing proof sub-member, the
    /// exact negatives the external W3C <c>vc-api-verifier-test-suite</c> drives — MUST NEVER verify
    /// TRUE, and MUST NEVER leak an uncaught exception (a 500). Either outcome is spec-conformant: a
    /// 400 (input so malformed the verification process could not run, §3.3.1) OR a 200 with
    /// <c>verified:false</c> and an ERROR ProblemDetail (the process ran and detected a data-model /
    /// malformed-context / cryptographic error, §3.8.1 — which §3.8 PREFERS: "avoid raising errors
    /// while performing verification, and instead gather ProblemDetails objects"). What is NOT
    /// acceptable is <c>verified:true</c> (a fail-open) or a 500 (an unsanitized server error, §3.8).
    /// The CCG suite expects 400 for every one of these; VCALM §3.8.1's 200+verified:false is the
    /// documented deviation — this test pins the property that actually matters either way.
    /// </summary>
    /// <remarks>
    /// The wrong-typed scalar member rows bind through the hand-written converters' <c>GetString()</c>
    /// calls: a non-string value there makes <c>GetString()</c> throw <see cref="InvalidOperationException"/>
    /// (not <see cref="System.Text.Json.JsonException"/>), a §3.8 unsanitized server error if it escaped.
    /// These rows run in the PARSE seam, before — and independent of — the verification guard.
    /// </remarks>
    [TestMethod]
    [DataRow("delete:@context", "missing @context")]
    [DataRow("delete:type", "missing type")]
    [DataRow("delete:issuer", "missing issuer")]
    [DataRow("delete:credentialSubject", "missing credentialSubject")]
    [DataRow("delete:proof", "missing proof")]
    [DataRow("delete:proof.type", "missing proof.type")]
    [DataRow("delete:proof.created", "missing proof.created")]
    [DataRow("delete:proof.verificationMethod", "missing proof.verificationMethod")]
    [DataRow("delete:proof.proofValue", "missing proof.proofValue")]
    [DataRow("delete:proof.proofPurpose", "missing proof.proofPurpose")]
    [DataRow("set:@context=4", "@context not an array")]
    [DataRow("setArray:@context=4", "@context item not a string/object")]
    [DataRow("set:type=\"VerifiableCredential\"", "type not an array")]
    [DataRow("setArray:type=4", "type item not a string")]
    [DataRow("set:issuer=[]", "issuer not a string/object")]
    [DataRow("set:credentialSubject=\"did:example:1234\"", "credentialSubject not an object")]
    [DataRow("set:proof=\"not-an-object\"", "proof not an object")]
    [DataRow("set:proof.created=4", "proof.created a number")]
    [DataRow("set:proof.cryptosuite=4", "proof.cryptosuite a number")]
    [DataRow("set:proof.proofValue=[]", "proof.proofValue an array")]
    [DataRow("set:proof.proofPurpose={}", "proof.proofPurpose an object")]
    [DataRow("set:issuer.id=4", "object issuer with a numeric id")]
    [DataRow("set:validFrom=4", "validFrom a number")]
    [DataRow("set:validUntil=true", "validUntil a bool")]
    [DataRow("set:id=4", "credential id a number")]
    public async Task MalformedCredentialNeverVerifiesTrue(string mutation, string reason)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(validUntilPast: false).ConfigureAwait(false);
        string mutatedCredentialJson = DataIntegrityContextTamperingFixture.MutateSecuredDocumentJson(SerializeCredential(credential), mutation);
        string body = "{\"verifiableCredential\":" + mutatedCredentialJson
            + ",\"options\":{\"returnProblemDetails\":true}}";

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmCredentialsVerify,
            "POST",
            new RequestFields(),
            body,
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        //An uncaught exception during verification would surface as a 500 — that is the §3.8
        //"unsanitized server error" failure mode. The only conformant statuses are 400 (verification
        //could not run) or 200 (verification ran; the result is in the body).
        Assert.IsTrue(response.StatusCode is 200 or 400,
            $"A malformed credential ({reason}) must be 200 or 400, never {response.StatusCode}: {response.Body}");

        if(response.StatusCode == 200)
        {
            using JsonDocument doc = JsonDocument.Parse(response.Body);
            Assert.IsFalse(doc.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
                $"A malformed credential ({reason}) MUST NEVER verify true (the §3.8.1 fail-open guard).");

            JsonElement problems = doc.RootElement.GetProperty(VcalmParameterNames.ProblemDetails);
            Assert.IsGreaterThan(0, problems.GetArrayLength(),
                $"A verified:false from a malformed credential ({reason}) carries a §3.8.1 ERROR ProblemDetail.");
        }
    }


    /// <summary>
    /// §3.8.1 SAFETY invariant for §3.3.2 (the presentation-side analogue): a structurally malformed
    /// presentation — a missing / wrong-typed core member, a missing proof sub-member, a non-object
    /// holder — MUST NEVER verify TRUE and MUST NEVER leak an uncaught exception (a 500). Either a 400
    /// or a 200 with <c>verified:false</c> is conformant; <c>verified:true</c> or a 500 is not. This
    /// pins the presentation proof-verification guard the same way <see cref="MalformedCredentialNeverVerifiesTrue"/>
    /// pins the credential one.
    /// </summary>
    /// <remarks>
    /// Each row either breaks the present proof or the signed content, is rejected by the parse seam,
    /// or (<c>delete:proof</c>) makes the <c>verifiablePresentation</c> unsecured — all MUST verify
    /// false, never true. A semantically-identical mutation (for example <c>type</c> as a bare string
    /// the model coerces back to a one-element array) is not a malformation and is excluded. The
    /// unsecured no-proof case is pinned in detail by
    /// <see cref="UnsecuredVerifiablePresentationVerifiesFalseWithError"/>; the legitimately-unproofed
    /// <c>presentation</c> member (which verifies true) is covered by
    /// <see cref="UnproofedPresentationVerifies"/>.
    /// </remarks>
    [TestMethod]
    [DataRow("delete:@context", "missing @context")]
    [DataRow("set:@context=4", "@context not an array")]
    [DataRow("setArray:@context=4", "@context item not a string/object")]
    [DataRow("delete:type", "missing type")]
    [DataRow("delete:proof", "no proof and no envelope (unsecured)")]
    [DataRow("delete:proof.proofValue", "missing proof.proofValue")]
    [DataRow("set:proof.created=4", "proof.created a number")]
    [DataRow("set:proof=\"not-an-object\"", "proof not an object")]
    [DataRow("set:holder=4", "holder a number")]
    public async Task MalformedPresentationNeverVerifiesTrue(string mutation, string reason)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app, canonicalizer: JcsCanonicalizer).ConfigureAwait(false);

        DataIntegritySecuredPresentation presentation = await SignPresentationAsync(
            "challenge-xyz", "verifier.example").ConfigureAwait(false);
        string mutated = DataIntegrityContextTamperingFixture.MutateSecuredDocumentJson(SerializePresentation(presentation), mutation);
        string body = "{\"verifiablePresentation\":" + mutated + ",\"options\":{\"returnProblemDetails\":true}}";

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmPresentationsVerify,
            "POST",
            new RequestFields(),
            body,
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(response.StatusCode is 200 or 400,
            $"A malformed presentation ({reason}) must be 200 or 400, never {response.StatusCode}: {response.Body}");

        if(response.StatusCode == 200)
        {
            using JsonDocument doc = JsonDocument.Parse(response.Body);
            Assert.IsFalse(doc.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
                $"A malformed presentation ({reason}) MUST NEVER verify true.");
        }
    }


    /// <summary>
    /// §3.3.2 / §3.8.1 secured-member contract: a presentation supplied under the
    /// <c>verifiablePresentation</c> member with NEITHER a Data Integrity proof NOR a <c>data:</c>-URL
    /// envelope is not a verifiable presentation — it verifies FALSE with a Data Integrity §4.4 PARSING_ERROR,
    /// mirroring how a proof-less <c>verifiableCredential</c> is treated. §3.3.2 reserves the
    /// <c>verifiablePresentation</c> member for the SECURED form (a proof or an
    /// <c>EnvelopedVerifiablePresentation</c>) and gives the unproofed form its own <c>presentation</c>
    /// member — see <see cref="UnproofedPresentationVerifies"/> for that legitimate (verifies-true) path.
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>:
    /// "If either securedDocument is not a map or securedDocument.proof is not a map, an error MUST be
    /// raised and SHOULD convey an error type of PARSING_ERROR."
    /// </summary>
    [TestMethod]
    public async Task UnsecuredVerifiablePresentationVerifiesFalseWithError()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app, canonicalizer: JcsCanonicalizer).ConfigureAwait(false);

        DataIntegritySecuredPresentation presentation = await SignPresentationAsync(
            "challenge-xyz", "verifier.example").ConfigureAwait(false);
        string mutated = DataIntegrityContextTamperingFixture.MutateSecuredDocumentJson(SerializePresentation(presentation), "delete:proof");
        string body = "{\"verifiablePresentation\":" + mutated + ",\"options\":{\"returnProblemDetails\":true}}";

        using JsonDocument response = await PostPresentationAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A verifiablePresentation with no proof and no envelope is not a secured presentation — it "
            + "verifies false (a Data Integrity §4.4 PARSING_ERROR), like a proof-less verifiableCredential.");

        Assert.IsTrue(VcalmWireFixtures.HasProblemOfType(response, "https://www.w3.org/TR/vc-data-model#PARSING_ERROR"),
            "The unsecured verifiablePresentation surfaces a Data Integrity §4.4 PARSING_ERROR ProblemDetail.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verification-errors-vs-warnings">VCALM §3.8.1</see>: "Warnings are
    /// ProblemDetails relating to status and validity periods", and "if no errors are included, it MUST be set to
    /// true". An expired credential (its <c>validUntil</c> in the past) therefore verifies TRUE with a validity-period
    /// warning beside it, the warning's type being the library's own since no specification names one.
    /// </summary>
    [TestMethod]
    public async Task ExpiredCredentialVerifiesTrueWithValidityWarning()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(validUntilPast: true).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true);

        using JsonDocument response = await PostCredentialWireAsync(app, segment, body, 200).ConfigureAwait(false);

        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "An expired but cryptographically valid credential verifies TRUE — a validity-period "
            + "ProblemDetail is a §3.8.1 WARNING that does not flip verified.");

        Assert.IsTrue(VcalmWireFixtures.HasProblemOfType(response, "https://verifiable.lumoin.com/problems#VALIDITY_PERIOD_WARNING"),
            "The expired validUntil must surface a validity-period WARNING.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-bitstring-status-list/#processing-errors">Bitstring Status List 1.0
    /// §3.5</see>: STATUS_RETRIEVAL_ERROR, "Retrieval of the status list failed." A <c>credentialStatus</c> whose
    /// status-list resolver throws must not become an unhandled 500:
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verification-errors-vs-warnings">VCALM §3.8.1</see> makes status a
    /// warning ("Warnings are ProblemDetails relating to status and validity periods"), so an undeterminable status
    /// yields no status result and never flips <c>verified</c>, and an exception that is not a
    /// <c>BitstringStatusListException</c> surfaces STATUS_RETRIEVAL_ERROR rather than the set-status
    /// <c>STATUS_WARNING</c> type.
    /// </summary>
    [TestMethod]
    public async Task StatusResolverThrowVerifiesTrueWithoutCrash()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);

        //A resolver that throws while dereferencing the status list — and records that it was reached, so
        //the test proves the credentialStatus entry mapped and the resolver was actually invoked (not a
        //false-positive where the entry never mapped and the throw path was never exercised).
        bool resolverInvoked = false;
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmStatusListAsync = (entry, ctx, ct) =>
            {
                resolverInvoked = true;

                throw new InvalidOperationException("The status list could not be dereferenced or decoded.");
            };
        }).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(
            validUntilPast: false, withStatus: true).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsTrue(resolverInvoked,
            "The credentialStatus entry must map so the status resolver is actually invoked (else the test proves nothing).");
        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A status-list resolver throw is swallowed (§3.8.1 status is a WARNING): the credential still verifies TRUE.");

        //A throw yields NO status result and never the set-status STATUS_WARNING type — it surfaces the
        //Bitstring Status List 1.0 §3.5 STATUS_RETRIEVAL_ERROR instead.
        Assert.IsFalse(VcalmWireFixtures.HasProblemOfType(response, "https://verifiable.lumoin.com/problems#STATUS_WARNING"),
            "A thrown (undeterminable) status must not surface a STATUS_WARNING.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verification-errors-vs-warnings">VCALM §3.8.1</see>: "Warnings are
    /// ProblemDetails relating to status and validity periods", and "if no errors are included, it MUST be set to true".
    /// A credential whose only status-list fetch ends on its own budget while the caller still waits, the cancellation
    /// bare or carried inside the resolver's own exception, has a status that could not be established: the status phase
    /// reports <see href="https://www.w3.org/TR/vc-bitstring-status-list/#processing-errors">Bitstring Status List 1.0
    /// §3.5</see> STATUS_RETRIEVAL_ERROR, "Retrieval of the status list failed.", naming the stall, as a warning, and the
    /// credential verifies true.
    /// </summary>
    [TestMethod]
    [DataRow("bare")]
    [DataRow("wrapped")]
    [DataRow("aggregated")]
    public async Task StatusFetchOwnBudgetCancellationReportsStatusRetrievalProblem(string cancellationShape)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);

        bool hasLiveCallerToken = false;
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmStatusListAsync = (entry, ctx, ct) =>
            {
                hasLiveCallerToken = !ct.IsCancellationRequested;

                return ValueTask.FromException<VcalmResolvedStatusList?>(CreateOwnBudgetCancellation(cancellationShape));
            };
        }).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(
            validUntilPast: false, withStatus: true).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true);

        using JsonDocument response = await PostCredentialWireAsync(app, segment, body, 200).ConfigureAwait(false);

        Assert.IsTrue(hasLiveCallerToken, "The status fetch must end while the caller's token is still live.");
        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "STATUS_RETRIEVAL_ERROR is a §3.8.1 WARNING: an own-budget status cancellation must not flip verified.");
        Assert.IsFalse(response.RootElement.GetRawText().Contains("private-policy-host/path", StringComparison.Ordinal),
            "The application's cancellation reason must never leak into the response.");
        Assert.IsTrue(VcalmWireFixtures.HasProblemOfType(response, "https://www.w3.org/ns/credentials/status-list#STATUS_RETRIEVAL_ERROR"),
            "An own-budget cancellation of the status fetch reports STATUS_RETRIEVAL_ERROR, never an escaping exception.");
        JsonElement problems = response.RootElement.GetProperty(VcalmParameterNames.ProblemDetails);
        Assert.AreEqual(1, problems.GetArrayLength(), "The stalled status fetch is the credential's only problem.");
        Assert.EndsWith("cancelled by its own budget.", problems[0].GetProperty("detail").GetString(), StringComparison.Ordinal,
            "The status problem names the fetch that ended on its own budget, whatever exception carried the cancellation.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verification-errors-vs-warnings">VCALM §3.8.1</see>: "Warnings are
    /// ProblemDetails relating to status and validity periods", and "if no errors are included, it MUST be set to true".
    /// When the first of a credential's two status entries has its fetch end on its own budget, the second entry is never
    /// fetched: its status could not be established either, so it reports
    /// <see href="https://www.w3.org/TR/vc-bitstring-status-list/#processing-errors">Bitstring Status List 1.0 §3.5</see>
    /// STATUS_RETRIEVAL_ERROR saying it was not attempted, a warning like the stalled first one, and the credential,
    /// whose proof verifies, verifies true.
    /// </summary>
    [TestMethod]
    public async Task StatusEntryLeftUnfetchedAfterAStallIsAWarning()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);
        int statusFetches = 0;
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmStatusListAsync = (entry, ctx, ct) =>
            {
                _ = Interlocked.Increment(ref statusFetches);

                return ValueTask.FromException<VcalmResolvedStatusList?>(CreateOwnBudgetCancellation("bare"));
            };
        }).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(
            validUntilPast: false,
            statuses:
            [
                new CredentialStatus
                {
                    Id = "https://status.example/list#94567",
                    Type = "BitstringStatusListEntry",
                    StatusPurpose = "revocation",
                    StatusListIndex = "94567",
                    StatusListCredential = "https://status.example/list"
                },
                new CredentialStatus
                {
                    Id = "https://status.example/suspension#23452",
                    Type = "BitstringStatusListEntry",
                    StatusPurpose = "suspension",
                    StatusListIndex = "23452",
                    StatusListCredential = "https://status.example/suspension"
                }
            ]).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true);

        using JsonDocument response = await PostCredentialWireAsync(app, segment, body, 200).ConfigureAwait(false);

        Assert.AreEqual(1, statusFetches, "Once the first status fetch exhausts its own budget, the second is never fetched.");
        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A status that could not be established is a §3.8.1 warning, fetched or not, and does not flip verified.");
        JsonElement problems = response.RootElement.GetProperty(VcalmParameterNames.ProblemDetails);
        Assert.AreEqual(2, problems.GetArrayLength(), "Both status entries are reported.");
        Assert.IsTrue(HasProblem(problems, "https://www.w3.org/ns/credentials/status-list#STATUS_RETRIEVAL_ERROR",
            "cancelled by its own budget."), "The stalled status fetch reports its retrieval problem.");
        Assert.IsTrue(HasProblem(problems, "https://www.w3.org/ns/credentials/status-list#STATUS_RETRIEVAL_ERROR",
            "not attempted: an earlier dependency of this request exhausted its budget."),
            "The unfetched status entry reports its retrieval problem, saying it was not attempted.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verification-errors-vs-warnings">VCALM §3.8.1</see>: "Errors are
    /// ProblemDetails relating to cryptography, data model, and malformed context and are unrecoverable", and "If an
    /// error is included, the verified property of the VerificationResponse object MUST be set to false". A status fetch
    /// that ends on its own budget, the cancellation bare or carried inside the resolver's own exception, leaves the rest
    /// of the request unfetched, so the credential's declared schema is never checked; an unchecked declared schema is an
    /// unrecoverable data-model condition, not a pass, so the schema entry reports
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#problem-details">VC Data Model 2.0 §7.2</see>
    /// MALFORMED_VALUE_ERROR and the credential, one that would in fact fail its schema, verifies false.
    /// </summary>
    [TestMethod]
    [DataRow("bare")]
    [DataRow("wrapped")]
    [DataRow("aggregated")]
    public async Task StatusStallLeavesSchemaUncheckedAndVerifiedFalse(string cancellationShape)
    {
        await using TestHostShell app = new(TimeProvider);
        int schemaFetches = 0;
        ResolveVcalmSchemaDocumentDelegate embeddedSchemas = SchemaValidationTestUtilities.CreateEmbeddedSchemaResolver(TestSchemas);
        ValueTask<string?> CountingResolveSchemaAsync(string schemaId, ExchangeContext context, CancellationToken cancellationToken)
        {
            _ = Interlocked.Increment(ref schemaFetches);

            return embeddedSchemas(schemaId, context, cancellationToken);
        }

        string segment = await RegisterVerifierAsync(
            app,
            schemaValidators: SchemaValidationTestUtilities.CreateSchemaRegistry(),
            resolveSchemaDocument: CountingResolveSchemaAsync).ConfigureAwait(false);
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmStatusListAsync = (entry, ctx, ct) =>
                ValueTask.FromException<VcalmResolvedStatusList?>(CreateOwnBudgetCancellation(cancellationShape));
        }).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(
            validUntilPast: false,
            withStatus: true,
            schemas: [new CredentialSchema { Id = EmailSchemaUrl, Type = "JsonSchema" }]).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true, returnResults: true);

        using JsonDocument response = await PostCredentialWireAsync(app, segment, body, 200).ConfigureAwait(false);

        Assert.AreEqual(0, schemaFetches, "Once the status fetch exhausts its own budget, the schema document is never fetched.");
        Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A declared schema left unchecked must not leave the credential verified.");
        JsonElement problems = response.RootElement.GetProperty(VcalmParameterNames.ProblemDetails);
        Assert.IsTrue(HasProblem(problems, "https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            "not attempted: an earlier dependency of this request exhausted its budget."),
            "The unchecked schema entry reports its data-model error, saying it was not attempted.");
        Assert.IsTrue(HasProblem(problems, "https://www.w3.org/ns/credentials/status-list#STATUS_RETRIEVAL_ERROR",
            "cancelled by its own budget."), "The stalled status fetch reports its retrieval problem.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verification-errors-vs-warnings">VCALM §3.8.1</see>: "Errors are
    /// ProblemDetails relating to cryptography, data model, and malformed context and are unrecoverable", and "If an
    /// error is included, the verified property of the VerificationResponse object MUST be set to false". A credential
    /// whose only declared schema cannot be fetched because the fetch ends on its own budget, the cancellation bare or
    /// carried inside the resolver's own exception, is never checked against that schema: an unrecoverable data-model
    /// condition, so the entry reports <see href="https://www.w3.org/TR/vc-data-model-2.0/#problem-details">VC Data Model
    /// 2.0 §7.2</see> MALFORMED_VALUE_ERROR naming the stall, and the credential, whose proof verifies, verifies false.
    /// </summary>
    [TestMethod]
    [DataRow("bare")]
    [DataRow("wrapped")]
    [DataRow("aggregated")]
    public async Task SchemaFetchOwnBudgetCancellationReportsMalformedValueError(string cancellationShape)
    {
        await using TestHostShell app = new(TimeProvider);
        bool hasLiveCallerToken = false;
        ValueTask<string?> ResolveSchemaOnExpiredBudgetAsync(string schemaId, ExchangeContext context, CancellationToken cancellationToken)
        {
            hasLiveCallerToken = !cancellationToken.IsCancellationRequested;

            return ValueTask.FromException<string?>(CreateOwnBudgetCancellation(cancellationShape));
        }

        string segment = await RegisterVerifierAsync(
            app,
            schemaValidators: SchemaValidationTestUtilities.CreateSchemaRegistry(),
            resolveSchemaDocument: ResolveSchemaOnExpiredBudgetAsync).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(
            validUntilPast: false,
            schemas: [new CredentialSchema { Id = AlumniSchemaUrl, Type = "JsonSchema" }]).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true, returnResults: true);

        using JsonDocument response = await PostCredentialWireAsync(app, segment, body, 200).ConfigureAwait(false);

        Assert.IsTrue(hasLiveCallerToken, "The schema fetch must end while the caller's token is still live.");
        Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A declared schema left unchecked must not leave the credential verified.");
        Assert.IsFalse(response.RootElement.GetRawText().Contains("private-policy-host/path", StringComparison.Ordinal),
            "The application's cancellation reason must never leak into the response.");
        JsonElement problems = response.RootElement.GetProperty(VcalmParameterNames.ProblemDetails);
        Assert.AreEqual(1, problems.GetArrayLength(), "The unchecked schema is the credential's only problem.");
        Assert.IsTrue(HasProblem(problems, "https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR", "cancelled by its own budget."),
            "The unchecked schema entry reports its data-model error, naming the fetch that ended on its own budget.");
        JsonElement schemaResults = response.RootElement
            .GetProperty(VcalmParameterNames.Results)
            .GetProperty(VcalmParameterNames.CredentialSchema);
        Assert.AreEqual(1, schemaResults.GetArrayLength(), "The declared schema is reported.");
        Assert.IsFalse(schemaResults[0].GetProperty(VcalmParameterNames.Verified).GetBoolean());
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verification-errors-vs-warnings">VCALM §3.8.1</see>: "If an error is
    /// included, the verified property of the VerificationResponse object MUST be set to false". When the first of two
    /// declared schemas cannot be fetched because its fetch ends on its own budget, that schema is never checked, and the
    /// second is never fetched at all; each unchecked declared schema is an unrecoverable data-model condition, so both
    /// report <see href="https://www.w3.org/TR/vc-data-model-2.0/#problem-details">VC Data Model 2.0 §7.2</see>
    /// MALFORMED_VALUE_ERROR, the first naming the stall and the second saying it was not attempted, and the credential
    /// verifies false.
    /// </summary>
    [TestMethod]
    public async Task SchemaStallLeavesLaterSchemaUncheckedAndVerifiedFalse()
    {
        await using TestHostShell app = new(TimeProvider);
        int schemaFetches = 0;
        ValueTask<string?> ResolveSchemaOnExpiredBudgetAsync(string schemaId, ExchangeContext context, CancellationToken cancellationToken)
        {
            _ = Interlocked.Increment(ref schemaFetches);

            return ValueTask.FromException<string?>(CreateOwnBudgetCancellation("bare"));
        }

        string segment = await RegisterVerifierAsync(
            app,
            schemaValidators: SchemaValidationTestUtilities.CreateSchemaRegistry(),
            resolveSchemaDocument: ResolveSchemaOnExpiredBudgetAsync).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(
            validUntilPast: false,
            schemas:
            [
                new CredentialSchema { Id = AlumniSchemaUrl, Type = "JsonSchema" },
                new CredentialSchema { Id = EmailSchemaUrl, Type = "JsonSchema" }
            ]).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true, returnResults: true);

        using JsonDocument response = await PostCredentialWireAsync(app, segment, body, 200).ConfigureAwait(false);

        Assert.AreEqual(1, schemaFetches, "Once the first schema fetch exhausts its own budget, the second is never fetched.");
        Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A declared schema left unchecked must not leave the credential verified.");
        JsonElement schemaResults = response.RootElement
            .GetProperty(VcalmParameterNames.Results)
            .GetProperty(VcalmParameterNames.CredentialSchema);
        Assert.AreEqual(2, schemaResults.GetArrayLength(), "Both declared schemas are reported.");
        Assert.IsFalse(schemaResults[0].GetProperty(VcalmParameterNames.Verified).GetBoolean());
        Assert.IsFalse(schemaResults[1].GetProperty(VcalmParameterNames.Verified).GetBoolean());
        JsonElement problems = response.RootElement.GetProperty(VcalmParameterNames.ProblemDetails);
        Assert.AreEqual(2, problems.GetArrayLength(), "Each unchecked schema asserts its own problem.");
        Assert.IsTrue(HasProblem(problems, "https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR", "cancelled by its own budget."),
            "The stalled schema entry reports its data-model error, naming the fetch that ended on its own budget.");
        Assert.IsTrue(HasProblem(problems, "https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            "not attempted: an earlier dependency of this request exhausted its budget."),
            "The unchecked second schema entry reports its data-model error, saying it was not attempted.");
    }


    /// <summary>
    /// Creates the exception a dependency whose own budget ran out raises, in one of the shapes a JSON-LD processor, a
    /// transport or a task combinator reports it: <c>bare</c>, the cancellation itself; <c>wrapped</c>, the cancellation
    /// as the inner exception of the dependency's own exception; <c>aggregated</c>, the cancellation as the second inner
    /// exception of an <see cref="AggregateException"/> whose first is an ordinary fault. Every message names a private
    /// host and path the response must never repeat.
    /// </summary>
    /// <param name="cancellationShape">The shape: <c>bare</c>, <c>wrapped</c> or <c>aggregated</c>.</param>
    /// <returns>The exception the dependency raises.</returns>
    private static Exception CreateOwnBudgetCancellation(string cancellationShape) => cancellationShape switch
    {
        "bare" => new OperationCanceledException("private-policy-host/path"),
        "wrapped" => new IOException("private-policy-host/path", new OperationCanceledException("private-policy-host/path")),
        "aggregated" => new AggregateException(
            new IOException("private-policy-host/path"), new OperationCanceledException("private-policy-host/path")),
        _ => throw new ArgumentOutOfRangeException(nameof(cancellationShape), cancellationShape, "Unknown cancellation shape.")
    };


    /// <summary>
    /// Whether <paramref name="problems"/> holds a ProblemDetail of <paramref name="type"/> whose detail ends with
    /// <paramref name="detailEnding"/>.
    /// </summary>
    /// <param name="problems">The response's or a result's <c>problemDetails</c> array.</param>
    /// <param name="type">The literal problem type URL looked for.</param>
    /// <param name="detailEnding">The ending the problem's detail must carry.</param>
    private static bool HasProblem(JsonElement problems, string type, string detailEnding)
    {
        foreach(JsonElement problem in problems.EnumerateArray())
        {
            if(string.Equals(problem.GetProperty(VcalmParameterNames.ProblemType).GetString(), type, StringComparison.Ordinal)
                && problem.GetProperty("detail").GetString()!.EndsWith(detailEnding, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// §C.3 / §3.8.1 status shape branches: a <c>credentialStatus</c> that does NOT map to a resolvable
    /// W3C status reference is turned away by <c>TryMapStatusEntry</c> BEFORE the resolver is ever
    /// reached, and never crashes (the unparseable index in particular must not throw a 500). A
    /// non-<c>BitstringStatusListEntry</c> type asserts nothing (this verifier implements no algorithm
    /// for it). A <c>BitstringStatusListEntry</c> with a missing <c>statusListCredential</c> or an
    /// unparseable <c>statusListIndex</c> IS the specification's shape, malformed: Bitstring Status
    /// List 1.0 §3.5 <c>STATUS_VERIFICATION_ERROR</c>. Neither shape surfaces the set-status
    /// <c>STATUS_WARNING</c> type, and the credential still verifies TRUE in every case. The
    /// complementary positive case — a well-formed entry DOES reach the resolver — is pinned by
    /// StatusResolverThrowVerifiesTrueWithoutCrash.
    /// </summary>
    [TestMethod]
    [DataRow("NotABitstringStatusEntry", "94567", "https://status.example/list", "non-BitstringStatusListEntry type")]
    [DataRow("BitstringStatusListEntry", "not-a-number", "https://status.example/list", "unparseable statusListIndex")]
    [DataRow("BitstringStatusListEntry", "94567", "", "missing statusListCredential")]
    public async Task NonMappingStatusEntryIsSkippedWithoutResolverOrCrash(
        string type, string statusListIndex, string statusListCredential, string reason)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);

        //A resolver that records being reached but resolves nothing. A MAPPING entry would reach it;
        //a NON-mapping entry must be turned away by TryMapStatusEntry first, so resolverInvoked stays false.
        bool resolverInvoked = false;
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmStatusListAsync = (entry, ctx, ct) =>
            {
                resolverInvoked = true;

                return ValueTask.FromResult<VcalmResolvedStatusList?>(null);
            };
        }).ConfigureAwait(false);

        CredentialStatus nonMapping = new()
        {
            Id = "https://status.example/list#x",
            Type = type,
            StatusPurpose = "revocation",
            StatusListIndex = statusListIndex,
            StatusListCredential = statusListCredential
        };
        DataIntegritySecuredCredential credential = await SignCredentialAsync(
            validUntilPast: false, customStatus: nonMapping).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsFalse(resolverInvoked,
            $"A non-mapping credentialStatus ({reason}) must be turned away by TryMapStatusEntry before the resolver.");
        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            $"A non-mapping credentialStatus ({reason}) establishes no status: verified stays TRUE, never a 500.");
        Assert.IsFalse(VcalmWireFixtures.HasProblemOfType(response, "https://verifiable.lumoin.com/problems#STATUS_WARNING"),
            $"A non-mapping credentialStatus ({reason}) must not surface a STATUS_WARNING.");
    }


    /// <summary>
    /// §3.3.1 <c>returnResults</c>: the verbose results object carries validFrom/validUntil/proof
    /// sub-results, each shaped <c>{ verified, input }</c>.
    /// </summary>
    [TestMethod]
    public async Task ReturnResultsEmitsPerStepResults()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(validUntilPast: false).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: false, returnResults: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        JsonElement results = response.RootElement.GetProperty(VcalmParameterNames.Results);
        JsonElement proofResults = results.GetProperty(VcalmParameterNames.Proof);
        Assert.AreEqual(1, proofResults.GetArrayLength(), "One proof → one proof result.");
        Assert.IsTrue(proofResults[0].GetProperty(VcalmParameterNames.Verified).GetBoolean());
        Assert.StartsWith("did:key:", proofResults[0].GetProperty(VcalmParameterNames.Input).GetString(),
            "The proof result input is the verificationMethod.");

        JsonElement validFrom = results.GetProperty(VcalmParameterNames.ValidFrom);
        Assert.IsTrue(validFrom.GetProperty(VcalmParameterNames.Verified).GetBoolean());
    }


    /// <summary>
    /// §3.3.1 <c>results.credentialSchema[]</c>: a credential conforming to its declared schema
    /// emits one <c>{verified:true, input:{id,type}}</c> item and stays verified. Each item MUST be
    /// an object of the form <c>verified</c> [boolean], <c>input</c> [object] (VCALM 1.0 §3.3.1);
    /// evaluation Success per
    /// <see href="https://www.w3.org/TR/vc-json-schema/#evaluation">VC JSON Schema §4.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ConformingCredentialSchemaEmitsVerifiedTrueResult()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(
            app,
            schemaValidators: SchemaValidationTestUtilities.CreateSchemaRegistry(),
            resolveSchemaDocument: SchemaValidationTestUtilities.CreateEmbeddedSchemaResolver(TestSchemas)).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(
            validUntilPast: false,
            schemas: [new CredentialSchema { Id = AlumniSchemaUrl, Type = "JsonSchema" }]).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: false, returnResults: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean());
        JsonElement schemaResults = response.RootElement
            .GetProperty(VcalmParameterNames.Results)
            .GetProperty(VcalmParameterNames.CredentialSchema);
        Assert.AreEqual(1, schemaResults.GetArrayLength(), "One credentialSchema entry produces one result item.");
        Assert.IsTrue(schemaResults[0].GetProperty(VcalmParameterNames.Verified).GetBoolean());
        JsonElement input = schemaResults[0].GetProperty(VcalmParameterNames.Input);
        Assert.AreEqual(AlumniSchemaUrl, input.GetProperty(VcalmParameterNames.Id).GetString());
        Assert.AreEqual("JsonSchema", input.GetProperty(VcalmParameterNames.Type).GetString());
    }


    /// <summary>
    /// A credential violating its declared schema verifies false with a
    /// <c>MALFORMED_VALUE_ERROR</c>: §3.8.1 classifies only status and validity ProblemDetails as
    /// warnings, so a schema Failure
    /// (<see href="https://www.w3.org/TR/vc-json-schema/#evaluation">VC JSON Schema §4.2</see>)
    /// is an error and flips <c>verified</c>.
    /// </summary>
    [TestMethod]
    public async Task SchemaViolatingCredentialVerifiesFalseWithError()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(
            app,
            schemaValidators: SchemaValidationTestUtilities.CreateSchemaRegistry(),
            resolveSchemaDocument: SchemaValidationTestUtilities.CreateEmbeddedSchemaResolver(TestSchemas)).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(
            validUntilPast: false,
            schemas: [new CredentialSchema { Id = EmailSchemaUrl, Type = "JsonSchema" }]).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true, returnResults: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A schema-violating credential must verify false.");
        JsonElement problems = response.RootElement.GetProperty(VcalmParameterNames.ProblemDetails);
        Assert.IsGreaterThan(0, problems.GetArrayLength());
        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            problems[0].GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "A schema Failure is a MALFORMED_VALUE_ERROR.");
        JsonElement schemaResults = response.RootElement
            .GetProperty(VcalmParameterNames.Results)
            .GetProperty(VcalmParameterNames.CredentialSchema);
        Assert.IsFalse(schemaResults[0].GetProperty(VcalmParameterNames.Verified).GetBoolean());
    }


    /// <summary>
    /// An unresolvable schema document and an unregistered mechanism both evaluate Indeterminate
    /// (<see href="https://www.w3.org/TR/vc-json-schema/#evaluation">VC JSON Schema §4.2</see>):
    /// the per-entry result is <c>verified:false</c> without asserting an error, so the overall
    /// <c>verified</c> does not flip — an undeterminable schema is not asserted as non-conformant,
    /// mirroring the undeterminable-status convention. With multiple schemas each entry contributes
    /// its own result (VC Data Model 2.0 §4.11: validity per each associated type's rules).
    /// </summary>
    [TestMethod]
    public async Task IndeterminateSchemaEntriesReportFalseWithoutFlippingVerified()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(
            app,
            schemaValidators: SchemaValidationTestUtilities.CreateSchemaRegistry(),
            resolveSchemaDocument: SchemaValidationTestUtilities.CreateEmbeddedSchemaResolver(TestSchemas)).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(
            validUntilPast: false,
            schemas:
            [
                new CredentialSchema { Id = AlumniSchemaUrl, Type = "JsonSchema" },
                new CredentialSchema { Id = "https://schemas.example/absent.json", Type = "JsonSchema" },
                new CredentialSchema { Id = AlumniSchemaUrl, Type = "VendorMechanism" }
            ]).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true, returnResults: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "Indeterminate schema entries must not flip the overall verified.");
        JsonElement schemaResults = response.RootElement
            .GetProperty(VcalmParameterNames.Results)
            .GetProperty(VcalmParameterNames.CredentialSchema);
        Assert.AreEqual(3, schemaResults.GetArrayLength(), "Three entries produce three result items (§4.11).");
        Assert.IsTrue(schemaResults[0].GetProperty(VcalmParameterNames.Verified).GetBoolean());
        Assert.IsFalse(schemaResults[1].GetProperty(VcalmParameterNames.Verified).GetBoolean());
        Assert.IsFalse(schemaResults[2].GetProperty(VcalmParameterNames.Verified).GetBoolean());
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#data-schemas">VC Data Model 2.0 §4.11 Data Schemas</see>:
    /// each <c>credentialSchema</c> "MUST specify its type (for example, JsonSchema) and an id property that MUST be a
    /// URL identifying the schema file". An entry missing its <c>type</c> is therefore a malformed value, reported as
    /// MALFORMED_VALUE_ERROR, and the credential verifies false.
    /// </summary>
    [TestMethod]
    public async Task SchemaEntryWithoutTypeVerifiesFalseWithMalformedValueError()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(
            app,
            schemaValidators: SchemaValidationTestUtilities.CreateSchemaRegistry(),
            resolveSchemaDocument: SchemaValidationTestUtilities.CreateEmbeddedSchemaResolver(TestSchemas)).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(
            validUntilPast: false,
            schemas: [new CredentialSchema { Id = AlumniSchemaUrl, Type = "" }]).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true, returnResults: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean());
        JsonElement problems = response.RootElement.GetProperty(VcalmParameterNames.ProblemDetails);
        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            problems[0].GetProperty(VcalmParameterNames.ProblemType).GetString());
    }


    /// <summary>The schema identifier used by <see cref="VcalmSchemaValidatorRegistry"/> conformance cases.</summary>
    private const string AlumniSchemaUrl = "https://schemas.example/alumni.json";
    /// <summary>The second schema identifier used to check independent <see cref="VcalmSchemaResult"/> values.</summary>
    private const string EmailSchemaUrl = "https://schemas.example/email.json";

    /// <summary>The embedded schema documents the schema tests resolve by id.</summary>
    private static Dictionary<string, string> TestSchemas { get; } = new(StringComparer.Ordinal)
    {
        [AlumniSchemaUrl] = /*lang=json,strict*/ """
            {
              "$schema": "https://json-schema.org/draft/2020-12/schema",
              "type": "object",
              "required": ["credentialSubject"]
            }
            """,
        [EmailSchemaUrl] = /*lang=json,strict*/ """
            {
              "$schema": "https://json-schema.org/draft/2020-12/schema",
              "type": "object",
              "properties": {
                "credentialSubject": {
                  "type": "object",
                  "required": ["emailAddress"]
                }
              },
              "required": ["credentialSubject"]
            }
            """
    };


    /// <summary>
    /// §2.4 unknown-option MUST: an <c>options</c> member the verifier does not understand is rejected
    /// with HTTP 400 and the §3.8 <c>UNKNOWN_OPTION_PROVIDED</c> problem type. §2.4: "Implementations
    /// MUST throw an error if an endpoint receives data, options, or option values that it does not
    /// understand or know how to process."
    /// </summary>
    [TestMethod]
    public async Task UnknownOptionYields400UnknownOptionProvided()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(validUntilPast: false).ConfigureAwait(false);
        string credentialJson = SerializeCredential(credential);
        string body = "{\"verifiableCredential\":" + credentialJson
            + ",\"options\":{\"notARealOption\":true}}";

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 400).ConfigureAwait(false);

        Assert.AreEqual("https://www.w3.org/TR/vcalm#UNKNOWN_OPTION_PROVIDED",
            response.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "An unknown option yields the UNKNOWN_OPTION_PROVIDED problem type.");
    }


    /// <summary>
    /// §2.4 strict top-level rejection: an unrecognized top-level member is malformed input → HTTP
    /// 400 (§3.3.1 "invalid input!").
    /// </summary>
    [TestMethod]
    public async Task UnknownTopLevelMemberYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(validUntilPast: false).ConfigureAwait(false);
        string credentialJson = SerializeCredential(credential);
        string body = "{\"verifiableCredential\":" + credentialJson + ",\"bogusTopLevel\":42}";

        using JsonDocument _ = await PostCredentialAsync(app, segment, body, expectedStatus: 400).ConfigureAwait(false);
    }


    /// <summary>
    /// §2.4 content-serialization MUST: a request whose Content-Type is not <c>application/json</c> is
    /// rejected with HTTP 400 before parsing.
    /// </summary>
    [TestMethod]
    public async Task NonJsonContentTypeYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);

        byte[] bytes = Encoding.UTF8.GetBytes("{\"verifiableCredential\":{}}");
        ServerHttpResponse response = await app.DispatchWithBodyAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmCredentialsVerify,
            "POST",
            bytes,
            "text/plain",
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "A non-application/json body is rejected before parsing (§2.4 content-serialization MUST).");
    }


    /// <summary>
    /// §2.4 / B.4 payload size: a request body over the configured cap is rejected with HTTP 413.
    /// </summary>
    [TestMethod]
    public async Task OversizeBodyYields413()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app, maxRequestBytes: 1024).ConfigureAwait(false);

        //A body comfortably over the 1 KiB cap configured for this verifier instance.
        byte[] bytes = Encoding.UTF8.GetBytes("{\"verifiableCredential\":{\"x\":\"" + new string('a', 4096) + "\"}}");
        ServerHttpResponse response = await app.DispatchWithBodyAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmCredentialsVerify,
            "POST",
            bytes,
            WellKnownMediaTypes.Application.Json,
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(413, response.StatusCode,
            "A body over the configured §2.4 payload-size cap is rejected with 413.");
    }


    /// <summary>
    /// §2.4 / B.4 payload size on §3.3.3: the /challenges endpoint accepts an empty body, but a PRESENT
    /// body over the configured cap is rejected with HTTP 413 — the same DoS gate every other
    /// body-bearing VCALM endpoint enforces.
    /// </summary>
    [TestMethod]
    public async Task ChallengeOversizeBodyYields413()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app, maxRequestBytes: 1024).ConfigureAwait(false);

        byte[] bytes = Encoding.UTF8.GetBytes("{\"x\":\"" + new string('a', 4096) + "\"}");
        ServerHttpResponse response = await app.DispatchWithBodyAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmCreateChallenge,
            "POST",
            bytes,
            WellKnownMediaTypes.Application.Json,
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(413, response.StatusCode,
            "A present /challenges body over the §2.4 payload cap is rejected with 413, like its siblings.");
    }


    /// <summary>
    /// §3.3.2 happy path: a holder-signed presentation whose proof's challenge and domain match the
    /// verify options verifies true.
    /// </summary>
    [TestMethod]
    public async Task ValidPresentationWithChallengeAndDomainVerifiesTrue()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app, canonicalizer: JcsCanonicalizer).ConfigureAwait(false);

        const string Challenge = "challenge-abc-123";
        const string Domain = "verifier.example";

        DataIntegritySecuredPresentation presentation = await SignPresentationAsync(Challenge, Domain).ConfigureAwait(false);
        string body = BuildPresentationRequestBody(presentation, Challenge, Domain);

        using JsonDocument response = await PostPresentationAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A presentation whose proof binds the expected challenge + domain verifies true.");
    }


    /// <summary>
    /// §3.3.2 challenge binding: a presentation whose proof carries a different challenge than the
    /// verify options is rejected (verified:false) with INVALID_CHALLENGE_ERROR under Data Integrity §4.4.
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>:
    /// "If challenge was given, and it does not match proof.challenge, an error MUST be raised and SHOULD
    /// convey an error type of INVALID_CHALLENGE_ERROR." This is a genuine mismatch — a
    /// challenge the proof actually carries a different value for — never
    /// <see cref="VcalmProblemTypes.ChallengeNotIssued"/>, which is reserved for a challenge this
    /// verifier never issued or already consumed.
    /// </summary>
    [TestMethod]
    public async Task PresentationWithWrongChallengeVerifiesFalse()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app, canonicalizer: JcsCanonicalizer).ConfigureAwait(false);

        DataIntegritySecuredPresentation presentation = await SignPresentationAsync(
            "challenge-the-holder-signed", "verifier.example").ConfigureAwait(false);
        //The verify call expects a DIFFERENT challenge than the one the proof carries.
        string body = BuildPresentationRequestBody(
            presentation, "challenge-the-verifier-expects", "verifier.example", returnProblemDetails: true);

        using JsonDocument response = await PostPresentationAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A challenge mismatch must verify false.");
        AssertVerificationProblem(response, "https://w3id.org/security#INVALID_CHALLENGE_ERROR");
    }


    /// <summary>
    /// §3.3.2 domain binding: a presentation whose proof carries a different domain than the verify
    /// options is rejected (verified:false).
    /// </summary>
    [TestMethod]
    public async Task PresentationWithWrongDomainVerifiesFalse()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app, canonicalizer: JcsCanonicalizer).ConfigureAwait(false);

        DataIntegritySecuredPresentation presentation = await SignPresentationAsync(
            "challenge-xyz", "holder-signed-domain.example").ConfigureAwait(false);
        string body = BuildPresentationRequestBody(presentation, "challenge-xyz", "verifier-expects-domain.example");

        using JsonDocument response = await PostPresentationAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A domain mismatch must verify false.");
    }


    /// <summary>
    /// §3.3.2 holder-to-key binding (soundness): a presentation whose <c>holder</c> claims one DID but
    /// whose proof is signed by a key controlled by a DIFFERENT DID is rejected (verified:false) — a
    /// valid signature alone does NOT authenticate a forged holder. The challenge and domain MATCH, so
    /// the only thing that can fail the proof is the holder-to-verificationMethod binding: the proof's
    /// verificationMethod is not found in the claimed holder's authentication relationship.
    /// </summary>
    [TestMethod]
    public async Task SwappedHolderDidVerifiesFalse()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app, canonicalizer: JcsCanonicalizer).ConfigureAwait(false);

        const string Challenge = "challenge-forged-holder";
        const string Domain = "verifier.example";

        //Signed by the attacker's key, but the holder member claims the victim's DID — both bindings
        //(challenge, domain) are correct, so a pass here could ONLY come from accepting the forged holder.
        DataIntegritySecuredPresentation forged = await SignPresentationWithForgedHolderAsync(Challenge, Domain).ConfigureAwait(false);
        string body = BuildPresentationRequestBody(forged, Challenge, Domain);

        using JsonDocument response = await PostPresentationAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A presentation whose holder DID does not control the signing key MUST verify false — the "
            + "holder-to-verificationMethod binding, not a valid signature alone, authenticates the holder.");
    }


    /// <summary>
    /// <see cref="VerifiablePresentation.Equals(VerifiablePresentation?)"/> and
    /// <see cref="DataIntegritySecuredPresentation"/>'s proof-folding equality compare the
    /// presentation's full structural content. An honest presentation
    /// (<see cref="SignPresentationAsync"/>) and one claiming the SAME holder but signed by a
    /// different key (<see cref="SignPresentationWithSameHolderDifferentSignerAsync"/>) agree on
    /// Context, Id (both null), Type, and Holder, and MUST still compare unequal because they
    /// differ in <see cref="DataIntegritySecuredPresentation.Proof"/>. Per
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#proofs">Data Integrity 1.0 §2.1 Proofs</see>
    /// the proof is part of what the presentation asserts, not incidental to its identity.
    /// </summary>
    [TestMethod]
    public async Task HonestAndSameHolderDifferentSignerPresentationsAreNotEqual()
    {
        const string Challenge = "challenge-equality-proof";
        const string Domain = "verifier.example";

        DataIntegritySecuredPresentation honest = await SignPresentationAsync(Challenge, Domain).ConfigureAwait(false);
        DataIntegritySecuredPresentation impersonated =
            await SignPresentationWithSameHolderDifferentSignerAsync(Challenge, Domain).ConfigureAwait(false);

        Assert.AreEqual(honest.Holder, impersonated.Holder,
            "The test's premise requires the SAME holder claim under two different signers.");
        Assert.AreNotEqual(honest, impersonated,
            "A presentation's identity includes its proof: two presentations claiming the same holder "
            + "but secured by different signers are different signed artifacts, not the same one twice.");
    }


    /// <summary>
    /// §3.3.2 unproofed alternative: a <c>presentation</c> (unproofed JSON-LD) request verifies its
    /// contained credentials only; with no contained credentials, it verifies true (nothing to
    /// contradict the verification process).
    /// </summary>
    [TestMethod]
    public async Task UnproofedPresentationVerifies()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);

        VerifiablePresentation presentation = new()
        {
            Context = Context.FromIris(Context.Credentials20),
            Type = ["VerifiablePresentation"],
            Holder = "did:example:holder-unproofed"
        };

        string presentationJson = SerializePresentation(presentation);
        string body = "{\"presentation\":" + presentationJson + "}";

        using JsonDocument response = await PostPresentationAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "An unproofed presentation with no contained credentials runs the process and verifies true.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>:
    /// "If either securedDocument is not a map or securedDocument.proof is not a map, an error MUST be
    /// raised and SHOULD convey an error type of PARSING_ERROR." A credential CONTAINED in a
    /// presentation carries the same requirement as the top-level <c>verifiableCredential</c>: one with
    /// no proof and no envelope cannot be cryptographically verified, so it is reported at the
    /// credential level rather than silently dropped or crashing the whole request.
    /// </summary>
    [TestMethod]
    public async Task ContainedCredentialWithoutProofReportsParsingProblem()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(false).ConfigureAwait(false);
        string unproofedCredentialJson = DataIntegrityContextTamperingFixture.MutateSecuredDocumentJson(SerializeCredential(credential), "delete:proof");

        JsonObject presentation = new()
        {
            ["@context"] = new JsonArray(CredentialConstants.CredentialsV2Context),
            ["type"] = new JsonArray("VerifiablePresentation"),
            ["verifiableCredential"] = new JsonArray(JsonNode.Parse(unproofedCredentialJson))
        };
        string body = "{\"presentation\":" + presentation.ToJsonString()
            + ",\"options\":{\"returnProblemDetails\":true,\"returnResults\":true}}";

        using JsonDocument response = await PostPresentationWireAsync(app, segment, body, 200).ConfigureAwait(false);

        Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A contained credential with no proof cannot be verified and must flip the overall result.");

        JsonElement credentialResults = response.RootElement
            .GetProperty(VcalmParameterNames.Results).GetProperty(VcalmParameterNames.Credentials);
        Assert.AreEqual(1, credentialResults.GetArrayLength());
        Assert.IsFalse(credentialResults[0].GetProperty(VcalmParameterNames.Verified).GetBoolean());
        JsonElement problem = credentialResults[0].GetProperty(VcalmParameterNames.ProblemDetails)[0];
        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#PARSING_ERROR", problem.GetProperty(VcalmParameterNames.ProblemType).GetString());
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#create-challenge">VCALM §3.3.3</see>: "The instance should create a
    /// challenge for use during verification". <c>POST /challenges</c> mints a challenge, and a later
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verify-presentation">§3.3.2</see> call whose presentation binds that
    /// challenge passes the issuance gate; a challenge the instance never issued is rejected with the library's own
    /// CHALLENGE_NOT_ISSUED, since no specification names a type for issuance tracking.
    /// </summary>
    [TestMethod]
    public async Task ChallengeMintedThenConsumedOnVerify()
    {
        await using TestHostShell app = new(TimeProvider);

        HashSet<string> issuedChallenges = [];
        string segment = await RegisterVerifierAsync(
            app,
            canonicalizer: JcsCanonicalizer,
            persistChallenge: (challenge, _, _) =>
            {
                _ = issuedChallenges.Add(challenge);

                return ValueTask.CompletedTask;
            },
            consumeChallenge: (challenge, _, _) =>
                ValueTask.FromResult(issuedChallenges.Contains(challenge))).ConfigureAwait(false);

        //§3.3.3: an empty body POST mints and returns a challenge string.
        ServerHttpResponse challengeResponse = await app.DispatchWithBodyAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmCreateChallenge,
            "POST",
            ReadOnlyMemory<byte>.Empty,
            contentType: string.Empty,
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, challengeResponse.StatusCode, challengeResponse.Body);
        using JsonDocument challengeDoc = JsonDocument.Parse(challengeResponse.Body);
        string mintedChallenge = challengeDoc.RootElement.GetProperty(VcalmParameterNames.Challenge).GetString()!;
        Assert.IsFalse(string.IsNullOrEmpty(mintedChallenge), "The challenge endpoint returns a challenge value.");
        Assert.Contains(mintedChallenge, issuedChallenges, "The minted challenge was persisted as issued.");

        //A verify call binding the minted challenge passes the issuance gate.
        const string Domain = "verifier.example";
        DataIntegritySecuredPresentation presentation = await SignPresentationAsync(mintedChallenge, Domain).ConfigureAwait(false);
        string body = BuildPresentationRequestBody(presentation, mintedChallenge, Domain);

        using JsonDocument issuedResponse = await PostPresentationAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);
        Assert.IsTrue(issuedResponse.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A presentation binding a minted, issued challenge passes the issuance gate and verifies.");

        //A verify call binding an unissued challenge fails the issuance gate. This is a library-defined
        //CHALLENGE_NOT_ISSUED, never Data Integrity's INVALID_CHALLENGE_ERROR: the proof's own challenge
        //matches what the caller bound, so DI §4.4's challenge-mismatch check never fires — this instance
        //simply never minted the value.
        DataIntegritySecuredPresentation unissued = await SignPresentationAsync("never-minted-challenge", Domain).ConfigureAwait(false);
        JsonObject unissuedRequest = JsonNode.Parse(BuildPresentationRequestBody(unissued, "never-minted-challenge", Domain))!.AsObject();
        unissuedRequest["options"]!["returnProblemDetails"] = true;

        using JsonDocument unissuedResponse = await PostPresentationAsync(
            app, segment, unissuedRequest.ToJsonString(), expectedStatus: 200).ConfigureAwait(false);
        AssertVerificationProblem(unissuedResponse, "https://verifiable.lumoin.com/problems#CHALLENGE_NOT_ISSUED");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verification-errors-vs-warnings">VCALM §3.8.1</see>: "If an
    /// error is included, the verified property of the VerificationResponse object MUST be set to false".
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verify-presentation">VCALM §3.3.2</see> gives the presentation
    /// its own per-check results: <c>challenge.verified</c> is the "Result of verifying the security challenge
    /// across all proofs provided" and <c>domain.verified</c> the "Result of verifying the security domain across
    /// all proofs provided". A presentation bound to a challenge the verifier never issued carries that check's
    /// error, so the response's <c>verified</c> and the challenge result's own <c>verified</c> are both false beside
    /// it, while the domain check, which found nothing wrong, reports true.
    /// </summary>
    [TestMethod]
    public async Task PresentationCheckWithAnErrorReportsItsOwnVerifiedFalse()
    {
        await using TestHostShell app = new(TimeProvider);

        //The verifier gates on issuance and has issued no challenge, so the presented one was never issued.
        string segment = await RegisterVerifierAsync(
            app,
            canonicalizer: JcsCanonicalizer,
            consumeChallenge: (_, _, _) => ValueTask.FromResult(false)).ConfigureAwait(false);

        const string Challenge = "challenge-never-issued";
        const string Domain = "verifier.example";
        DataIntegritySecuredPresentation presentation = await SignPresentationAsync(Challenge, Domain).ConfigureAwait(false);
        JsonObject request = JsonNode.Parse(
            BuildPresentationRequestBody(presentation, Challenge, Domain, returnProblemDetails: true))!.AsObject();
        request["options"]!["returnResults"] = true;

        using JsonDocument response = await PostPresentationWireAsync(app, segment, request.ToJsonString(), 200).ConfigureAwait(false);

        Assert.IsFalse(response.RootElement.GetProperty("verified").GetBoolean(),
            "An included error sets the response's verified to false.");
        AssertVerificationProblem(response, "https://verifiable.lumoin.com/problems#CHALLENGE_NOT_ISSUED");
        Assert.AreEqual(1, response.RootElement.GetProperty("problemDetails").GetArrayLength(),
            "The unissued challenge is the only error, so the domain check has none of its own.");

        JsonElement presentationResults = response.RootElement.GetProperty("results").GetProperty("presentation");
        JsonElement challengeResult = presentationResults.GetProperty("challenge");
        Assert.AreEqual(Challenge, challengeResult.GetProperty("input").GetString());
        Assert.IsFalse(challengeResult.GetProperty("verified").GetBoolean(),
            "The challenge check that produced the error reports verified false beside it.");

        JsonElement domainResult = presentationResults.GetProperty("domain");
        Assert.AreEqual(Domain, domainResult.GetProperty("input").GetString());
        Assert.IsTrue(domainResult.GetProperty("verified").GetBoolean(),
            "The domain check produced no error and reports verified true.");
    }


    /// <summary>
    /// §3.3.1 malformed input: a body that is not a JSON object yields HTTP 400.
    /// </summary>
    [TestMethod]
    public async Task MalformedCredentialBodyYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);

        using JsonDocument _ = await PostCredentialAsync(app, segment, "{ not valid json", expectedStatus: 400).ConfigureAwait(false);
    }


    /// <summary>
    /// §3.3.1 + §3.4 ecdsa-sd-2023 derived proof: an issuer base-proofs a credential
    /// (W3C VC-DI-ECDSA §3.4.1 createBaseProof), a holder derives a selectively-disclosed subset
    /// (§3.4.5 createDerivedProof), and the derived credential — the form a holder presents — is POSTed
    /// to the V-1 <c>/credentials/verify</c> endpoint. With the ecdsa-sd-2023 derived-proof seams
    /// wired, the verifier routes the CBOR <c>0xd9 5d 01</c>-tagged proof to the SD derived-proof
    /// verifier and returns HTTP 200 with <c>verified:true</c> and no error — the disclosed claims are
    /// authentic under the issuer's base signature.
    /// </summary>
    [TestMethod]
    public async Task DerivedEcdsaSd2023CredentialVerifiesTrue()
    {
        await using TestHostShell app = new(TimeProvider);
        SdIssuerContext sd = await CreateSdIssuerContextAsync().ConfigureAwait(false);
        string segment = await RegisterVerifierAsync(app, sd: sd).ConfigureAwait(false);

        DataIntegritySecuredCredential derived = await CreateDerivedCredentialAsync(sd).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(derived, returnProblemDetails: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A selectively-disclosed ecdsa-sd-2023 derived credential must verify TRUE at the V-1 "
            + "/credentials/verify endpoint.");

        JsonElement problems = response.RootElement.GetProperty(VcalmParameterNames.ProblemDetails);
        Assert.AreEqual(0, problems.GetArrayLength(),
            "A valid derived credential surfaces no §3.8.1 ProblemDetail.");
    }


    /// <summary>
    /// §3.3.1 / §3.8.1 ERROR + §3.4 no-false-positive: a TAMPERED ecdsa-sd-2023 derived credential
    /// (a disclosed claim altered after derivation, so its statement signature no longer matches) still
    /// returns HTTP 200 (the process ran) but <c>verified:false</c> with a cryptographic ERROR.
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#verification">VCDM §7.1</see>: "If
    /// result.status is set to false, add a CRYPTOGRAPHIC_SECURITY_ERROR to result.errors." A forged
    /// selective disclosure never wrongly returns true.
    /// </summary>
    [TestMethod]
    public async Task TamperedDerivedEcdsaSd2023CredentialVerifiesFalseWithError()
    {
        await using TestHostShell app = new(TimeProvider);
        SdIssuerContext sd = await CreateSdIssuerContextAsync().ConfigureAwait(false);
        string segment = await RegisterVerifierAsync(app, sd: sd).ConfigureAwait(false);

        DataIntegritySecuredCredential derived = await CreateDerivedCredentialAsync(sd).ConfigureAwait(false);

        JsonObject request = JsonNode.Parse(BuildCredentialRequestBody(derived, returnProblemDetails: true))!.AsObject();
        JsonObject subject = request["verifiableCredential"]!["credentialSubject"] switch
        {
            JsonArray subjects => subjects[0]!.AsObject(),
            _ => request["verifiableCredential"]!["credentialSubject"]!.AsObject()
        };
        Assert.IsNotNull(subject["degree"]?["name"], "The disclosed claim must already exist.");

        //Change only the signed literal, preserving blank-node identifiers and statement count.
        subject["degree"]!["name"] = "Tampered Master of Forgery";
        string body = request.ToJsonString();

        using JsonDocument response = await PostCredentialWireAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A tampered derived credential must verify FALSE (the no-false-positive property).");

        JsonElement problems = response.RootElement.GetProperty(VcalmParameterNames.ProblemDetails);
        Assert.IsGreaterThan(0, problems.GetArrayLength(), "A crypto failure surfaces a ProblemDetail.");
        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#CRYPTOGRAPHIC_SECURITY_ERROR",
            problems[0].GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "A false signature verdict is a §3.8.1 cryptographic ERROR.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#parsederivedproofvalue">VC-DI-ECDSA §3.5.8
    /// parseDerivedProofValue</see>: "If the decodedProofValue does not start with the ECDSA-SD disclosure proof header
    /// bytes 0xd9, 0x5d, and 0x01, an error MUST be raised and SHOULD convey an error type of PROOF_VERIFICATION_ERROR."
    /// A wrong header is a structural defect in the proof value, never UNSUPPORTED_SECURING_MECHANISM, which is
    /// reserved for a mechanism with no configured verifier at all.
    /// </summary>
    [TestMethod]
    public async Task WrongDisclosureHeaderReportsProofVerificationProblem()
    {
        await using TestHostShell app = new(TimeProvider);
        SdIssuerContext sd = await CreateSdIssuerContextAsync().ConfigureAwait(false);
        string segment = await RegisterVerifierAsync(app, sd: sd).ConfigureAwait(false);

        DataIntegritySecuredCredential derived = await CreateDerivedCredentialAsync(sd).ConfigureAwait(false);
        JsonObject request = JsonNode.Parse(BuildCredentialRequestBody(derived, returnProblemDetails: true))!.AsObject();
        JsonObject proof = DataIntegrityContextTamperingFixture.FirstProof(request["verifiableCredential"]!.AsObject());

        //"uAAAA" decodes (past the 'u' multibase prefix) to three zero bytes — a well-formed
        //base64url-multibase value that is NOT the required 0xd9 0x5d 0x01 disclosure-proof header.
        proof["proofValue"] = "uAAAA";
        string body = request.ToJsonString();

        using JsonDocument response = await PostCredentialWireAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        AssertVerificationProblem(response, "https://w3id.org/security#PROOF_VERIFICATION_ERROR");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#error-handling">VCALM §3.8</see>: "The type key MUST be present and
    /// its value MUST be a URL identifying the type of problem." Selective-disclosure verification is dispatched for
    /// exactly one derived proof, so a credential carrying an ecdsa-sd-2023 proof alongside another proof is a
    /// composition this verifier cannot dispatch, and no specification names a type for it: it reports the library's
    /// UNSUPPORTED_SECURING_MECHANISM, a problem type under the definer's control
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9457#section-4">RFC 9457 §4</see>), rather than attempting to
    /// verify the extra proof as part of the disclosure.
    /// </summary>
    [TestMethod]
    public async Task MultiProofSelectiveDisclosureChainReportsUnsupportedMechanism()
    {
        await using TestHostShell app = new(TimeProvider);
        SdIssuerContext sd = await CreateSdIssuerContextAsync().ConfigureAwait(false);
        string segment = await RegisterVerifierAsync(app, sd: sd).ConfigureAwait(false);

        DataIntegritySecuredCredential derived = await CreateDerivedCredentialAsync(sd).ConfigureAwait(false);
        List<DataIntegrityProof> derivedProofs = derived.Proof!;
        Assert.HasCount(1, derivedProofs, "The fixture must start from exactly one derived proof.");
        derivedProofs.Add(derivedProofs[0]);

        using JsonDocument response = await PostCredentialWireAsync(
            app, segment, BuildCredentialRequestBody(derived, returnProblemDetails: true), 200).ConfigureAwait(false);

        AssertVerificationProblem(response, "https://verifiable.lumoin.com/problems#UNSUPPORTED_SECURING_MECHANISM");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#error-handling">VCALM §3.8</see>: "The type key MUST be present and
    /// its value MUST be a URL identifying the type of problem." The composition that
    /// <see cref="MultiProofSelectiveDisclosureChainReportsUnsupportedMechanism"/> shows refused is refused wherever the
    /// ecdsa-sd-2023 proof stands in the proof list: here an eddsa-rdfc-2022 proof comes first and the
    /// selective-disclosure proof second, and the credential still reports UNSUPPORTED_SECURING_MECHANISM before any
    /// controller document is resolved for either proof.
    /// </summary>
    [TestMethod]
    public async Task SelectiveDisclosureProofAfterAnotherProofReportsUnsupportedMechanism()
    {
        await using TestHostShell app = new(TimeProvider);
        SdIssuerContext sd = await CreateSdIssuerContextAsync().ConfigureAwait(false);
        string segment = await RegisterVerifierAsync(app, sd: sd).ConfigureAwait(false);
        int resolutions = 0;
        ValueTask<DidResolutionResult> CountingResolveAsync(
            string did, DidResolutionOptions options, ExchangeContext context, CancellationToken cancellationToken)
        {
            _ = Interlocked.Increment(ref resolutions);

            return KeyDidResolverSeam.ResolveAsync(did, context, options, cancellationToken);
        }

        DidResolver resolver = new(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, CountingResolveAsync)));
        await AlterVerificationAsync(app, verification => verification with { Resolver = resolver }).ConfigureAwait(false);

        DataIntegritySecuredCredential derived = await CreateDerivedCredentialAsync(sd).ConfigureAwait(false);
        DataIntegritySecuredCredential eddsaSigned = await SignCredentialAsync(false).ConfigureAwait(false);
        derived.Proof!.Insert(0, eddsaSigned.Proof![0]);

        using JsonDocument response = await PostCredentialWireAsync(
            app, segment, BuildCredentialRequestBody(derived, returnProblemDetails: true), 200).ConfigureAwait(false);

        AssertVerificationProblem(response, "https://verifiable.lumoin.com/problems#UNSUPPORTED_SECURING_MECHANISM");
        Assert.AreEqual(0, resolutions, "No controller document is resolved for a composition refused before resolution.");
    }


    /// <summary>
    /// §3.3.1 regression: with the ecdsa-sd-2023 derived-proof seams wired, an ordinary non-SD
    /// eddsa-rdfc-2022 credential still verifies through the generic Data Integrity path exactly as
    /// before — HTTP 200, <c>verified:true</c>. The cryptosuite branch routes ONLY ecdsa-sd-2023
    /// derived proofs to the SD verifier; every other cryptosuite is unchanged.
    /// </summary>
    [TestMethod]
    public async Task NonSdCredentialUnaffectedBySdSeams()
    {
        await using TestHostShell app = new(TimeProvider);
        SdIssuerContext sd = await CreateSdIssuerContextAsync().ConfigureAwait(false);
        string segment = await RegisterVerifierAsync(app, sd: sd).ConfigureAwait(false);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(validUntilPast: false).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A non-SD eddsa-rdfc-2022 credential verifies TRUE through the generic path even when the "
            + "ecdsa-sd-2023 derived-proof seams are wired (regression guard).");
    }


    /// <summary>
    /// In-process (calls <see cref="VcalmVerificationService.VerifyCredentialAsync"/> directly, not
    /// over HTTP): the Bitstring Status List 1.0 §3.2 Validate Algorithm's result map carries the
    /// entry's <c>statusPurpose</c>, and carries no <c>message</c> for a non-<c>message</c>-purpose
    /// entry ("If the statusPurpose is message, set the message key in result…" — a <c>revocation</c>
    /// entry never is).
    /// </summary>
    [TestMethod]
    public async Task StatusResultCarriesPurposeAndNoMessageForNonMessagePurposeEntry()
    {
        DataIntegritySecuredCredential credential = await SignCredentialAsync(
            validUntilPast: false, withStatus: true).ConfigureAwait(false);

        VcalmCredentialVerification verification = new()
        {
            Resolver = KeyDidResolverSeam,
            Canonicalize = RdfcCanonicalizer,
            ContextResolver = ContextResolver,
            KnownContext = Context.FromIris(Context.Credentials20, CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl),
            DecodeProofValue = ProofValueCodecs.DecodeBase58Btc,
            SerializeCredential = SerializeCredential,
            SerializePresentation = SerializePresentation,
            SerializeProofOptions = SerializeProofOptions,
            Decoder = TestSetup.Base58Decoder,
            ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            MemoryPool = Pool
        };

        static ValueTask<VcalmResolvedStatusList?> ResolveStatusList(
            BitstringStatusListEntry entry, ExchangeContext exchangeContext, CancellationToken cancellationToken)
        {
            CoreStatusList list = CoreStatusList.Create(
                BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);

            return ValueTask.FromResult<VcalmResolvedStatusList?>(new VcalmResolvedStatusList
            {
                StatusList = list,
                Purposes = ["revocation"]
            });
        }

        VcalmVerificationOutcome outcome = await VcalmVerificationService.VerifyCredentialAsync(
            credential, verification, ResolveStatusList, TimeProvider.GetUtcNow(), EmptyContext,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, outcome.StatusResults, "One credentialStatus entry maps to one status result.");
        Assert.AreEqual("revocation", outcome.StatusResults[0].Purpose,
            "Bitstring Status List 1.0 §3.2 Validate Algorithm: 'set the purpose key in result to the "
            + "value of statusPurpose.'");
        Assert.IsNull(outcome.StatusResults[0].Message,
            "A non-message-purpose entry's result carries no message.");
    }


    /// <summary>
    /// In-process (calls <see cref="VcalmVerificationService.VerifyCredentialAsync"/> directly, not
    /// over HTTP), companion to <see cref="StatusResultCarriesPurposeAndNoMessageForNonMessagePurposeEntry"/>:
    /// a <c>message</c>-purpose <c>credentialStatus</c> entry carrying <c>statusSize</c> 2 and four
    /// <c>statusMessage</c> values must reach the mapped
    /// <see cref="BitstringStatusListEntry"/>, so the Bitstring Status List 1.0 §3.2 Validate
    /// Algorithm's result carries the message the status list's value maps to ("If the
    /// statusPurpose is message, set the message key in result to the corresponding message of
    /// the value as indicated in the statusMessages array").
    /// </summary>
    [TestMethod]
    public async Task StatusResultCarriesTheMappedMessageForAMessagePurposeEntry()
    {
        CredentialStatus messageStatus = new()
        {
            Id = "https://status.example/list#94567",
            Type = "BitstringStatusListEntry",
            StatusPurpose = "message",
            StatusListIndex = "94567",
            StatusListCredential = "https://status.example/list",
            StatusSize = 2,
            StatusMessage =
            [
                new BitstringStatusMessage("0x0", "pending_review"),
                new BitstringStatusMessage("0x1", "accepted"),
                new BitstringStatusMessage("0x2", "rejected"),
                new BitstringStatusMessage("0x3", "withdrawn")
            ]
        };

        DataIntegritySecuredCredential credential = await SignCredentialAsync(
            validUntilPast: false, customStatus: messageStatus).ConfigureAwait(false);

        VcalmCredentialVerification verification = new()
        {
            Resolver = KeyDidResolverSeam,
            Canonicalize = RdfcCanonicalizer,
            ContextResolver = ContextResolver,
            KnownContext = Context.FromIris(Context.Credentials20, CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl),
            DecodeProofValue = ProofValueCodecs.DecodeBase58Btc,
            SerializeCredential = SerializeCredential,
            SerializePresentation = SerializePresentation,
            SerializeProofOptions = SerializeProofOptions,
            Decoder = TestSetup.Base58Decoder,
            ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            MemoryPool = Pool
        };

        static ValueTask<VcalmResolvedStatusList?> ResolveStatusList(
            BitstringStatusListEntry entry, ExchangeContext exchangeContext, CancellationToken cancellationToken)
        {
            CoreStatusList list = CoreStatusList.Create(
                BitstringStatusListCodec.MinimumEntries, StatusListBitSize.TwoBits, Pool, BitOrder.MostSignificantFirst);
            list[94567] = 2;

            return ValueTask.FromResult<VcalmResolvedStatusList?>(new VcalmResolvedStatusList
            {
                StatusList = list,
                Purposes = ["message"]
            });
        }

        VcalmVerificationOutcome outcome = await VcalmVerificationService.VerifyCredentialAsync(
            credential, verification, ResolveStatusList, TimeProvider.GetUtcNow(), EmptyContext,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, outcome.StatusResults, "One credentialStatus entry maps to one status result.");
        Assert.AreEqual("rejected", outcome.StatusResults[0].Message,
            "The credentialStatus entry's statusSize and statusMessage must reach the mapped "
            + "BitstringStatusListEntry so the message resolves to the value the status list holds at the index.");
    }


    /// <summary>
    /// §C.3 / §3.8.1 malformed-entry shape: Bitstring Status List 1.0 §2.1 requires
    /// <c>statusMessage</c> whenever <c>statusSize</c> is greater than <c>1</c>. Its absence IS the
    /// specification's shape, malformed — the same §3.5 <c>STATUS_VERIFICATION_ERROR</c> the
    /// existing non-mapping shapes (<see cref="NonMappingStatusEntryIsSkippedWithoutResolverOrCrash"/>)
    /// already use, turned away by <c>TryMapStatusEntry</c> before the resolver.
    /// </summary>
    [TestMethod]
    public async Task StatusSizeGreaterThanOneWithoutStatusMessageIsMalformedStatusEntry()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);

        bool resolverInvoked = false;
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmStatusListAsync = (entry, ctx, ct) =>
            {
                resolverInvoked = true;

                return ValueTask.FromResult<VcalmResolvedStatusList?>(null);
            };
        }).ConfigureAwait(false);

        CredentialStatus status = new()
        {
            Id = "https://status.example/list#492847",
            Type = "BitstringStatusListEntry",
            StatusPurpose = "message",
            StatusListIndex = "492847",
            StatusListCredential = "https://status.example/list",
            StatusSize = 2
        };
        DataIntegritySecuredCredential credential = await SignCredentialAsync(
            validUntilPast: false, customStatus: status).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsFalse(resolverInvoked,
            "statusSize greater than 1 without statusMessage is malformed; TryMapStatusEntry must turn it away before the resolver.");
        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A malformed credentialStatus establishes no status: verified stays TRUE, never a 500.");
        Assert.IsTrue(VcalmWireFixtures.HasProblemOfType(response, "https://www.w3.org/ns/credentials/status-list#STATUS_VERIFICATION_ERROR"),
            "Bitstring Status List 1.0 §2.1: statusSize greater than 1 REQUIRES statusMessage; its "
            + "absence is the specification's shape, malformed.");
    }


    /// <summary>
    /// §C.3 / §3.8.1 malformed-entry shape: Bitstring Status List 1.0 §2.1 requires the
    /// <c>statusMessage</c> array's length to equal the number of possible status values
    /// <c>statusSize</c> indicates (4 for a 2-bit entry). A shorter array is the specification's
    /// shape, malformed, turned away by <c>TryMapStatusEntry</c> before the resolver.
    /// </summary>
    [TestMethod]
    public async Task StatusMessageArrayOfWrongLengthIsMalformedStatusEntry()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterVerifierAsync(app).ConfigureAwait(false);

        bool resolverInvoked = false;
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmStatusListAsync = (entry, ctx, ct) =>
            {
                resolverInvoked = true;

                return ValueTask.FromResult<VcalmResolvedStatusList?>(null);
            };
        }).ConfigureAwait(false);

        CredentialStatus status = new()
        {
            Id = "https://status.example/list#492847",
            Type = "BitstringStatusListEntry",
            StatusPurpose = "message",
            StatusListIndex = "492847",
            StatusListCredential = "https://status.example/list",
            StatusSize = 2,
            StatusMessage =
            [
                new BitstringStatusMessage("0x0", "pending_review"),
                new BitstringStatusMessage("0x1", "accepted")
            ]
        };
        DataIntegritySecuredCredential credential = await SignCredentialAsync(
            validUntilPast: false, customStatus: status).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsFalse(resolverInvoked,
            "A statusMessage array whose length does not match the number of values statusSize indicates is malformed.");
        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean());
        Assert.IsTrue(VcalmWireFixtures.HasProblemOfType(response, "https://www.w3.org/ns/credentials/status-list#STATUS_VERIFICATION_ERROR"),
            "Bitstring Status List 1.0 §2.1: the statusMessage array length MUST equal the number of "
            + "possible status messages indicated by statusSize (4 for a 2-bit entry); a 2-element array is malformed.");
    }


    /// <summary>
    /// Registers the verifier with the capabilities and delegates needed by the verification endpoint cases.
    /// </summary>
    private async Task<string> RegisterVerifierAsync(
        TestHostShell app,
        long maxRequestBytes = 10L * 1024 * 1024,
        CanonicalizationDelegate? canonicalizer = null,
        ContextResolverDelegate? contextResolver = null,
        PersistVcalmChallengeDelegate? persistChallenge = null,
        ConsumeVcalmChallengeDelegate? consumeChallenge = null,
        SdIssuerContext? sd = null,
        VcalmSchemaValidatorRegistry? schemaValidators = null,
        ResolveVcalmSchemaDocumentDelegate? resolveSchemaDocument = null)
    {
        VerifierKeyMaterial material = await app.RegisterClientAsync(ClientId, ClientBaseUri, VerifierCapabilities).ConfigureAwait(false);
        RegisteredMaterials.Add(material);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultVcalmJsonParsing(JsonOptions);
        }).ConfigureAwait(false);
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.VcalmCredentialVerification = new VcalmCredentialVerification
            {
                Resolver = KeyDidResolverSeam,
                //The canonicalizer matches the suite the verifier instance serves: RDFC-1.0 +
                //offline context resolver for eddsa-rdfc-2022 credentials, JCS for eddsa-jcs-2022
                //presentations. The library does not hardcode the choice; a multi-suite deployment
                //wires a canonicalizer that dispatches on the proof's cryptosuite.
                Canonicalize = canonicalizer ?? RdfcCanonicalizer,
                ContextResolver = contextResolver ?? ContextResolver,
                //JCS callers exercise the presentation path (SignPresentationAsync's bare, one-entry
                //context); every other caller exercises the credential path (VcalmWireFixtures'
                //base-plus-examples context).
                KnownContext = ReferenceEquals(canonicalizer, JcsCanonicalizer)
                    ? Context.FromIris(Context.Credentials20)
                    : Context.FromIris(Context.Credentials20, CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl),
                DecodeProofValue = ProofValueCodecs.DecodeBase58Btc,
                SerializeCredential = SerializeCredential,
                SerializePresentation = SerializePresentation,
                SerializeProofOptions = SerializeProofOptions,
                Decoder = TestSetup.Base58Decoder,
                ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
                MemoryPool = Pool,
                //§3.4 ecdsa-sd-2023 derived-proof seams: the CBOR derived-proof parser, the P-256
                //verification function, and the base64url codec the SD verifier composes. When wired, a
                //derived (0xd9 5d 01) proof routes to the derived-proof verifier; when null, an SD derived
                //credential reports an unsupported securing mechanism. RDFC is the SD canonicalizer.
                ParseDerivedProof = sd is null ? null : EcdsaSd2023CborSerializer.ParseDerivedProof,
                VerifyDerivedSignature = sd is null ? null : BouncyCastleCryptographicFunctionsAdapter.VerifyP256Async,
                SdProofEncoder = sd is null ? null : TestSetup.Base64UrlEncoder,
                SdProofDecoder = sd is null ? null : TestSetup.Base64UrlDecoder,
                //The §3.3.1 results.credentialSchema seams: wired only by the schema tests; unwired
                //deployments keep empty schema results.
                SchemaValidators = schemaValidators,
                ResolveSchemaDocument = resolveSchemaDocument
            };
        }).ConfigureAwait(false);

        if(persistChallenge is not null)
        {
            await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
            {
                candidateIntegration.PersistVcalmChallengeAsync = persistChallenge;
            }).ConfigureAwait(false);
        }

        if(consumeChallenge is not null)
        {
            await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
            {
                candidateIntegration.ConsumeVcalmChallengeAsync = consumeChallenge;
            }).ConfigureAwait(false);
        }

        //The §2.4 / B.4 payload-size cap is a server-level instance configuration.
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.VcalmMaxRequestBytes = maxRequestBytes;
        }).ConfigureAwait(false);

        return material.Registration.TenantId.Value;
    }


    /// <summary>
    /// Signs a VC-DM 2.0 credential with eddsa-rdfc-2022 under a did:key issuer the KeyDidResolver
    /// resolves locally. The issuer key is the cached Ed25519 identity
    /// (<see cref="TestKeyMaterialProvider.CreateEd25519KeyMaterial"/>), so every credential this helper signs names the
    /// same issuer. <paramref name="validUntilPast"/> sets <c>validUntil</c> before the
    /// verification instant to exercise the §3.8.1 validity-period WARNING; <paramref name="withStatus"/>
    /// adds a §C.3 BitstringStatusListEntry <c>credentialStatus</c> so the verifier's status-resolution
    /// path runs.
    /// </summary>
    /// <param name="validUntilPast">Whether the signed credential's <c>validUntil</c> lies before the verification instant.</param>
    /// <param name="withStatus">Whether to attach a default or <paramref name="customStatus"/> credentialStatus entry.</param>
    /// <param name="customStatus">A specific credentialStatus entry to attach instead of the default one.</param>
    /// <param name="schemas">The credentialSchema entries to attach, or <see langword="null"/> for none.</param>
    /// <param name="statuses">The credentialStatus entries to attach, taking precedence over the other status options.</param>
    private async Task<DataIntegritySecuredCredential> SignCredentialAsync(
        bool validUntilPast, bool withStatus = false, CredentialStatus? customStatus = null,
        List<CredentialSchema>? schemas = null, List<CredentialStatus>? statuses = null)
    {
        Verifiable.Cryptography.PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory issuerPublic = keyPair.PublicKey;
        using PrivateKeyMemory issuerPrivate = keyPair.PrivateKey;

        DidDocument issuerDidDocument = await KeyDidBuilder.BuildAsync(
            issuerPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            BaseMemoryPool.Shared,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //A caller-supplied list of entries, a single caller-supplied entry (the non-mapping shape branches: wrong type,
        //unparseable index, missing list reference), or the default §C.3 entry.
        List<CredentialStatus>? credentialStatus = (statuses, customStatus, withStatus) switch
        {
            ({ } given, _, _) => given,
            (_, { } custom, _) => [custom],
            (_, _, true) => [DefaultStatusEntry],
            _ => null
        };

        return await SignCredentialAsIssuerAsync(
            issuerPrivate,
            issuerDidDocument.VerificationMethod![0].Id!,
            issuerDidDocument.Id!.ToString(),
            validUntilPast,
            credentialStatus,
            schemas).ConfigureAwait(false);
    }


    /// <summary>
    /// A §C.3 BitstringStatusListEntry for the test credential's revocation status. Its <c>type</c> is the entry type the
    /// verifier maps on, so the entry resolves and the status-resolution path runs rather than being skipped.
    /// </summary>
    private static CredentialStatus DefaultStatusEntry => new()
    {
        Id = "https://status.example/list#94567",
        Type = "BitstringStatusListEntry",
        StatusPurpose = "revocation",
        StatusListIndex = "94567",
        StatusListCredential = "https://status.example/list"
    };


    /// <summary>
    /// Signs the class's VC-DM 2.0 test credential with eddsa-rdfc-2022 as the issuer <paramref name="issuerDid"/>, under
    /// its verification method <paramref name="verificationMethodId"/>, so a test can present credentials of an issuer
    /// whose controller document it serves itself.
    /// </summary>
    /// <param name="issuerPrivate">The issuer's Ed25519 private key.</param>
    /// <param name="verificationMethodId">The verification method the proof names.</param>
    /// <param name="issuerDid">The credential's <c>issuer</c>, the verification method's controller.</param>
    /// <param name="validUntilPast">Whether the signed credential's <c>validUntil</c> lies before the verification instant.</param>
    /// <param name="credentialStatus">The credentialStatus entries to attach, or <see langword="null"/> for none.</param>
    /// <param name="schemas">The credentialSchema entries to attach, or <see langword="null"/> for none.</param>
    private async Task<DataIntegritySecuredCredential> SignCredentialAsIssuerAsync(
        PrivateKeyMemory issuerPrivate,
        string verificationMethodId,
        string issuerDid,
        bool validUntilPast,
        List<CredentialStatus>? credentialStatus,
        List<CredentialSchema>? schemas)
    {
        VerifiableCredential credential = new()
        {
            Context = Context.FromIris(Context.Credentials20, CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl),
            Id = "urn:uuid:vcalm-test-credential",
            Type = ["VerifiableCredential", "ExampleAlumniCredential"],
            Issuer = new Issuer { Id = issuerDid },
            ValidFrom = "2023-01-01T00:00:00Z",
            ValidUntil = validUntilPast ? "2024-01-01T00:00:00Z" : "2030-01-01T00:00:00Z",
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
            ],
            CredentialSchema = schemas,
            CredentialStatus = credentialStatus
        };

        DateTime proofCreated = TimeProvider.GetUtcNow().UtcDateTime;

        return await credential.SignAsync(
            issuerPrivate,
            verificationMethodId,
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


    /// <summary>
    /// Builds and signs an eddsa-jcs-2022 embedded-proof presentation claiming
    /// <paramref name="holderDid"/> and signed by <paramref name="signerPrivate"/> /
    /// <paramref name="signerVerificationMethodId"/>, binding the given
    /// <paramref name="challenge"/> and <paramref name="domain"/>, at this class's clock instant. This is the common
    /// plumbing shared by every <c>SignPresentation*</c> fixture below; the signing itself is the one shared
    /// <see cref="DataIntegrityContextTamperingFixture.SignJcsPresentationAsync(string, string, PrivateKeyMemory, string?, string?, DateTime)"/>.
    /// </summary>
    /// <param name="challenge">The verifier's challenge to bind into the proof.</param>
    /// <param name="domain">The verifier's domain to bind into the proof.</param>
    /// <param name="holderDid">The DID the presentation's <c>holder</c> member claims.</param>
    /// <param name="signerPrivate">The private key that signs the proof.</param>
    /// <param name="signerVerificationMethodId">
    /// The verification method id the proof's <c>verificationMethod</c> references.
    /// </param>
    /// <returns>The signed <see cref="DataIntegritySecuredPresentation"/>.</returns>
    private Task<DataIntegritySecuredPresentation> SignPresentationCoreAsync(
        string challenge,
        string domain,
        string holderDid,
        PrivateKeyMemory signerPrivate,
        string signerVerificationMethodId) =>
        DataIntegrityContextTamperingFixture.SignJcsPresentationAsync(
            holderDid, signerVerificationMethodId, signerPrivate, challenge, domain, TimeProvider.GetUtcNow().UtcDateTime);


    /// <summary>
    /// Signs a holder presentation with eddsa-jcs-2022 binding the given <paramref name="challenge"/>
    /// and <paramref name="domain"/>, under a did:key holder the <see cref="KeyDidResolver"/>
    /// resolves locally. The holder key is the cached Ed25519 identity
    /// (<see cref="TestKeyMaterialProvider.CreateEd25519KeyMaterial"/>), so the resulting holder DID
    /// is the SAME did:key across every call in this class;
    /// <see cref="SignPresentationWithSameHolderDifferentSignerAsync"/> relies on that stability to
    /// claim the identical holder under a different signer.
    /// </summary>
    /// <param name="challenge">The verifier's challenge to bind into the proof.</param>
    /// <param name="domain">The verifier's domain to bind into the proof.</param>
    /// <returns>The signed, honestly-held <see cref="DataIntegritySecuredPresentation"/>.</returns>
    private async Task<DataIntegritySecuredPresentation> SignPresentationAsync(string challenge, string domain)
    {
        Verifiable.Cryptography.PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keyPair.PublicKey;
        using PrivateKeyMemory holderPrivate = keyPair.PrivateKey;

        DidDocument holderDidDocument = await KeyDidBuilder.BuildAsync(
            holderPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            BaseMemoryPool.Shared,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string verificationMethodId = holderDidDocument.VerificationMethod![0].Id!;
        string holderDid = holderDidDocument.Id!.ToString();

        return await SignPresentationCoreAsync(
            challenge, domain, holderDid, holderPrivate, verificationMethodId).ConfigureAwait(false);
    }


    /// <summary>
    /// Signs a holder presentation whose proof's <c>verificationMethod</c> belongs to a FRESH
    /// attacker did:key, but whose <c>holder</c> member claims the SAME cached did:key that
    /// <see cref="SignPresentationAsync"/> signs honestly for. The resulting presentation shares
    /// Context, Id, Type, and Holder with an honest <see cref="SignPresentationAsync"/> presentation
    /// and differs only in <see cref="DataIntegritySecuredPresentation.Proof"/>, so telling the two
    /// apart requires the folded-in proof to be part of equality.
    /// </summary>
    /// <param name="challenge">The verifier's challenge to bind into the proof.</param>
    /// <param name="domain">The verifier's domain to bind into the proof.</param>
    /// <returns>
    /// The signed <see cref="DataIntegritySecuredPresentation"/> claiming the honest holder under a
    /// different signer.
    /// </returns>
    private async Task<DataIntegritySecuredPresentation> SignPresentationWithSameHolderDifferentSignerAsync(
        string challenge, string domain)
    {
        Verifiable.Cryptography.PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DidDocument holderDidDocument = await KeyDidBuilder.BuildAsync(
            holderPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            BaseMemoryPool.Shared,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string holderDid = holderDidDocument.Id!.ToString();

        //A FRESH key is required here for the same reason SignPresentationWithForgedHolderAsync
        //requires one: the cached CreateEd25519KeyMaterial would hand this signer the holder's OWN
        //key, collapsing "different signer" into the honest case.
        Verifiable.Cryptography.PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> otherSignerKeys =
            TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        using PublicKeyMemory otherSignerPublic = otherSignerKeys.PublicKey;
        using PrivateKeyMemory otherSignerPrivate = otherSignerKeys.PrivateKey;
        DidDocument otherSignerDocument = await KeyDidBuilder.BuildAsync(
            otherSignerPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            BaseMemoryPool.Shared,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string otherSignerVerificationMethodId = otherSignerDocument.VerificationMethod![0].Id!;

        return await SignPresentationCoreAsync(
            challenge, domain, holderDid, otherSignerPrivate, otherSignerVerificationMethodId).ConfigureAwait(false);
    }


    /// <summary>
    /// Signs a holder presentation whose proof's <c>verificationMethod</c> belongs to one did:key
    /// (the attacker's signing key) but whose <c>holder</c> member claims a DIFFERENT did:key (the
    /// victim). The signature is cryptographically valid for the attacker key, but the claimed
    /// holder DID does NOT control that key: the verify-time holder-to-verificationMethod binding
    /// must reject it (<c>GetLocalAuthenticationMethodById</c> finds no such method in the victim's
    /// document).
    /// </summary>
    /// <param name="challenge">The verifier's challenge to bind into the proof.</param>
    /// <param name="domain">The verifier's domain to bind into the proof.</param>
    /// <returns>
    /// The signed <see cref="DataIntegritySecuredPresentation"/> whose holder does not control the
    /// signing key.
    /// </returns>
    private async Task<DataIntegritySecuredPresentation> SignPresentationWithForgedHolderAsync(
        string challenge, string domain)
    {
        //Victim A: only its DID is borrowed into the holder member; its key never signs. FRESH keys are
        //required here — the cached CreateEd25519KeyMaterial would hand the attacker the SAME key, making
        //the two DIDs identical and the "forgery" a legitimate holder==signer presentation.
        Verifiable.Cryptography.PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> victimKeys =
            TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        using PublicKeyMemory victimPublic = victimKeys.PublicKey;
        using PrivateKeyMemory victimPrivate = victimKeys.PrivateKey;
        DidDocument victimDocument = await KeyDidBuilder.BuildAsync(
            victimPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            BaseMemoryPool.Shared,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string victimDid = victimDocument.Id!.ToString();

        //Attacker B: its (distinct) key signs and its verificationMethod id rides the proof.
        Verifiable.Cryptography.PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> attackerKeys =
            TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        using PublicKeyMemory attackerPublic = attackerKeys.PublicKey;
        using PrivateKeyMemory attackerPrivate = attackerKeys.PrivateKey;
        DidDocument attackerDocument = await KeyDidBuilder.BuildAsync(
            attackerPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            BaseMemoryPool.Shared,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string attackerVerificationMethodId = attackerDocument.VerificationMethod![0].Id!;

        //Guard the test's premise: a vacuous "forgery" (identical DIDs) would verify true for the right
        //reason and silently pass nothing. The two identities MUST differ for the binding to be exercised.
        Assert.AreNotEqual(victimDid, attackerDocument.Id!.ToString(),
            "The forged-holder test requires two DISTINCT did:key identities.");

        return await SignPresentationCoreAsync(
            challenge, domain, victimDid, attackerPrivate, attackerVerificationMethodId).ConfigureAwait(false);
    }


    /// <summary>
    /// Creates a fresh P-256 issuer + ephemeral key pair for ecdsa-sd-2023 base proofs under a did:key
    /// issuer the KeyDidResolver resolves locally — the verifier resolves this DID document to extract
    /// the P-256 public key the derived-proof verifier reconstructs the base signature with. The key
    /// material is tracked for disposal at cleanup.
    /// </summary>
    private async Task<SdIssuerContext> CreateSdIssuerContextAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuer =
            BouncyCastleKeyMaterialCreator.CreateP256Keys(Pool);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral =
            BouncyCastleKeyMaterialCreator.CreateP256Keys(Pool);

        DidDocument issuerDidDocument = await KeyDidBuilder.BuildAsync(
            issuer.PublicKey,
            MultikeyVerificationMethodTypeInfo.Instance,
            BaseMemoryPool.Shared,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string verificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;
        string issuerDid = issuerDidDocument.Id!.ToString();

        //The issuer public key is retained on the context only to round-trip key material lifetime; the
        //verifier extracts its own copy from the resolved DID document, not from the context.
        OwnedKeys.Add(issuer.PublicKey);
        OwnedKeys.Add(issuer.PrivateKey);
        OwnedKeys.Add(ephemeral.PublicKey);
        OwnedKeys.Add(ephemeral.PrivateKey);

        return new SdIssuerContext(issuer.PrivateKey, ephemeral, verificationMethodId, issuerDid);
    }


    /// <summary>
    /// Creates the disclosed credential verified by the selective-disclosure cases using
    /// <see cref="SdIssuerContext"/> and the issuer's mandatory disclosure pointers.
    /// </summary>
    private async Task<DataIntegritySecuredCredential> CreateDerivedCredentialAsync(SdIssuerContext sd)
    {
        VerifiableCredential credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(
            CredentialSecuringMaterial.UnsignedCredentialJson, JsonOptions)!;

        //The credential's issuer is the resolvable did:key issuer so the verifier resolves it to the
        //P-256 verification method and extracts the issuer public key the SD verifier reconstructs the
        //base signature with.
        credential.Issuer = new Issuer { Id = sd.IssuerDid };

        List<CredentialPath> mandatoryPaths =
        [
            CredentialPath.FromJsonPointer("/issuer"),
            CredentialPath.FromJsonPointer("/type")
        ];

        DataIntegritySecuredCredential baseCredential = await credential.CreateBaseProofAsync(
            sd.IssuerPrivateKey,
            sd.EphemeralKeyPair,
            sd.VerificationMethodId,
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

        IReadOnlySet<CredentialPath> selectivePointers = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/credentialSubject/degree/name")
        };

        return await baseCredential.DeriveProofAsync(
            selectivePointers,
            userExclusions: null,
            JsonLdSelection.PartitionStatements,
            JsonLdSelection.SelectFragments,
            RdfcCanonicalizer,
            ContextResolver,
            SerializeCredential,
            DeserializeCredential,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            EcdsaSd2023CborSerializer.SerializeDerivedProof,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            Pool,
            EmptyContext,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds the §3.3.1 verify request body for <paramref name="credential"/>:
    /// <c>{"verifiableCredential": ..., "options": {...}}</c> with the requested response options.
    /// </summary>
    /// <param name="credential">The secured credential to verify.</param>
    /// <param name="returnProblemDetails">Whether the options ask for the <c>problemDetails</c> array.</param>
    /// <param name="returnResults">Whether the options ask for the per-step <c>results</c> object.</param>
    /// <returns>The request body JSON text.</returns>
    private static string BuildCredentialRequestBody(
        DataIntegritySecuredCredential credential, bool returnProblemDetails, bool returnResults = false)
    {
        string credentialJson = SerializeCredential(credential);
        StringBuilder options = new("{");
        bool first = true;
        if(returnProblemDetails)
        {
            _ = options.Append("\"returnProblemDetails\":true");
            first = false;
        }

        if(returnResults)
        {
            if(!first) { _ = options.Append(','); }

            _ = options.Append("\"returnResults\":true");
        }

        _ = options.Append('}');

        return "{\"verifiableCredential\":" + credentialJson + ",\"options\":" + options + "}";
    }


    /// <summary>
    /// Builds the §3.3.2 verify request body for <paramref name="presentation"/>:
    /// <c>{"verifiablePresentation": ..., "options": {"challenge": ..., "domain": ...}}</c>.
    /// </summary>
    /// <param name="presentation">The secured presentation to verify.</param>
    /// <param name="challenge">The challenge the verify options bind.</param>
    /// <param name="domain">The domain the verify options bind.</param>
    /// <param name="returnProblemDetails">Whether the options ask for the <c>problemDetails</c> array.</param>
    /// <returns>The request body JSON text.</returns>
    private static string BuildPresentationRequestBody(
        DataIntegritySecuredPresentation presentation, string challenge, string domain, bool returnProblemDetails = false)
    {
        string presentationJson = SerializePresentation(presentation);
        string problemDetailsOption = returnProblemDetails ? ",\"returnProblemDetails\":true" : string.Empty;

        return "{\"verifiablePresentation\":" + presentationJson
            + ",\"options\":{\"challenge\":\"" + challenge + "\",\"domain\":\"" + domain + "\"" + problemDetailsOption + "}}";
    }


    /// <summary>
    /// Dispatches a §3.3.1 verify request in process through the host's dispatcher, without the HTTP transport, and
    /// returns the parsed body after checking its status.
    /// </summary>
    /// <param name="app">The host shell whose dispatcher serves the request.</param>
    /// <param name="segment">The verifier tenant segment.</param>
    /// <param name="body">The verify request body JSON text.</param>
    /// <param name="expectedStatus">The HTTP status the response must carry.</param>
    private async Task<JsonDocument> PostCredentialAsync(
        TestHostShell app, string segment, string body, int expectedStatus)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmCredentialsVerify,
            "POST",
            new RequestFields(),
            body,
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedStatus, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    /// <summary>
    /// Dispatches a §3.3.2 verify request in process through the host's dispatcher, without the HTTP transport, and
    /// returns the parsed body after checking its status.
    /// </summary>
    /// <param name="app">The host shell whose dispatcher serves the request.</param>
    /// <param name="segment">The verifier tenant segment.</param>
    /// <param name="body">The verify request body JSON text.</param>
    /// <param name="expectedStatus">The HTTP status the response must carry.</param>
    private async Task<JsonDocument> PostPresentationAsync(
        TestHostShell app, string segment, string body, int expectedStatus)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmPresentationsVerify,
            "POST",
            new RequestFields(),
            body,
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedStatus, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    /// <summary>Retains signing keys for <see cref="CreateDerivedCredentialAsync"/>; verification resolves the issuer public key.</summary>
    /// <param name="IssuerPrivateKey">The issuer key that signs the base proof.</param>
    /// <param name="EphemeralKeyPair">The key pair that signs disclosed statements.</param>
    /// <param name="VerificationMethodId">The method resolved by <see cref="KeyDidResolver"/>.</param>
    /// <param name="IssuerDid">The issuer identifier bound by the derived proof.</param>
    private sealed record SdIssuerContext(
        PrivateKeyMemory IssuerPrivateKey,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> EphemeralKeyPair,
        string VerificationMethodId,
        string IssuerDid);
}
