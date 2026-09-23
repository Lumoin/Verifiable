using Microsoft.Extensions.Time.Testing;
using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.Core;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DataIntegrity;

/// <summary>
/// Unit tests for <see cref="PresentationDataIntegrityExtensions.VerifyLinkedPresentationAsync"/> — the
/// challenge/domain-free verify for a <strong>static linked</strong> presentation (a presentation published once
/// and resolved by anyone, such as a did:webvh <c>whois.vp</c>). The path performs the same cryptographic
/// verification as the interactive <c>VerifyAsync</c> but binds no verifier challenge/domain, and is fail-closed
/// against being handed a binding-bearing proof (Data Integrity 1.0 §4.2; VC-DM 2.0 §4.13).
/// </summary>
[TestClass]
internal sealed class PresentationLinkedVerifyTests
{
    /// <summary>The MSTest context, whose cancellation token bounds every signing and verification.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A challenge a binding-bearing proof carries, which the linked verification refuses.</summary>
    private const string VerifierChallenge = "verifier-challenge-abc123";

    /// <summary>A domain a binding-bearing proof carries, which the linked verification refuses.</summary>
    private const string VerifierDomain = "verifier.example";

    /// <summary>The serializer options every JSON delegate of these tests uses.</summary>
    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    /// <summary>Builds the holder's did:key document from its public key.</summary>
    private static KeyDidBuilder KeyDidBuilder { get; } = new KeyDidBuilder();

    /// <summary>The clock whose instant every signed proof records as its <c>created</c> time.</summary>
    private static FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero));

    /// <summary>The JCS canonicalizer the eddsa-jcs-2022 signing and verification share.</summary>
    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, _, cancellationToken) =>
        ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = Jcs.Canonicalize(json) });

    /// <summary>The context every signing and verification runs under, outside any request.</summary>
    private static ExchangeContext EmptyContext { get; } = [];

    /// <summary>Decodes the base58btc proof values the signing encodes.</summary>
    private static ProofValueDecoderDelegate ProofValueDecoder { get; } = ProofValueCodecs.DecodeBase58Btc;

    /// <summary>Serializes a presentation for signing and verification.</summary>
    private static PresentationSerializeDelegate SerializePresentation { get; } = presentation =>
        JsonSerializerExtensions.Serialize(presentation, JsonOptions);

    /// <summary>Reads a presentation back from its JSON.</summary>
    private static PresentationDeserializeDelegate DeserializePresentation { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiablePresentation>(serialized, JsonOptions)!;

    /// <summary>Serializes the proof options a Data Integrity proof hashes.</summary>
    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);


    /// <summary>
    /// An unbound static presentation (no challenge, no domain) signed under the holder's authentication
    /// relationship verifies through <c>VerifyLinkedPresentationAsync</c>.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task UnboundStaticPresentationVerifies(DidWebTestData testData)
    {
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            publicKey, testData.VerificationMethodTypeInfo, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        DataIntegritySecuredPresentation signed = await SignStaticPresentationAsync(
            holderDidDocument, privateKey, challenge: null, domain: null).ConfigureAwait(false);

        var result = await signed.VerifyLinkedPresentationAsync(
            holderDidDocument,
            JcsCanonicalizer,
            contextResolver: null,
            signed.Context!,
            ProofValueDecoder,
            SerializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, $"An unbound static presentation MUST verify; got {result.FailureReason}.");
    }


    /// <summary>
    /// A presentation carrying a <c>challenge</c> is rejected by the static verify with
    /// <see cref="VerificationFailureReason.UnexpectedPresentationBinding"/> — fail closed against a binding the
    /// static path cannot check.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task PresentationWithChallengeIsRejected(DidWebTestData testData)
    {
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            publicKey, testData.VerificationMethodTypeInfo, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //A challenge with no domain isolates the challenge half of the binding rejection.
        DataIntegritySecuredPresentation signed = await SignStaticPresentationAsync(
            holderDidDocument, privateKey, challenge: VerifierChallenge, domain: null).ConfigureAwait(false);

        var result = await signed.VerifyLinkedPresentationAsync(
            holderDidDocument,
            JcsCanonicalizer,
            contextResolver: null,
            signed.Context!,
            ProofValueDecoder,
            SerializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.UnexpectedPresentationBinding, result.FailureReason,
            "A challenge-bearing proof MUST be rejected by the static linked-presentation verify.");
    }


    /// <summary>
    /// A presentation carrying a <c>domain</c> is rejected by the static verify with
    /// <see cref="VerificationFailureReason.UnexpectedPresentationBinding"/>.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task PresentationWithDomainIsRejected(DidWebTestData testData)
    {
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            publicKey, testData.VerificationMethodTypeInfo, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //A domain with no challenge isolates the domain half of the binding rejection.
        DataIntegritySecuredPresentation signed = await SignStaticPresentationAsync(
            holderDidDocument, privateKey, challenge: null, domain: VerifierDomain).ConfigureAwait(false);

        var result = await signed.VerifyLinkedPresentationAsync(
            holderDidDocument,
            JcsCanonicalizer,
            contextResolver: null,
            signed.Context!,
            ProofValueDecoder,
            SerializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.UnexpectedPresentationBinding, result.FailureReason,
            "A domain-bearing proof MUST be rejected by the static linked-presentation verify.");
    }


    /// <summary>
    /// A tampered proof value yields <see cref="VerificationFailureReason.SignatureInvalid"/> — the static verify
    /// runs the full cryptographic check, not merely the binding and relationship gates.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task TamperedProofIsSignatureInvalid(DidWebTestData testData)
    {
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            publicKey, testData.VerificationMethodTypeInfo, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        DataIntegritySecuredPresentation signed = await SignStaticPresentationAsync(
            holderDidDocument, privateKey, challenge: null, domain: null).ConfigureAwait(false);

        //Flip the last proof-value character so the signature no longer matches the signed bytes.
        string proofValue = signed.Proof![0].ProofValue!;
        signed.Proof[0].ProofValue = proofValue[..^1] + (proofValue[^1] == 'A' ? 'B' : 'A');

        var result = await VerifyStaticAsync(signed, holderDidDocument).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.SignatureInvalid, result.FailureReason);
    }


    /// <summary>
    /// A proof whose verification method is not referenced from the holder's <c>authentication</c> relationship
    /// yields <see cref="VerificationFailureReason.VerificationMethodNotFound"/> — the key is resolved through
    /// authentication, not the raw verificationMethod array.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task MethodOutsideAuthenticationIsNotFound(DidWebTestData testData)
    {
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            publicKey, testData.VerificationMethodTypeInfo, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        DataIntegritySecuredPresentation signed = await SignStaticPresentationAsync(
            holderDidDocument, privateKey, challenge: null, domain: null).ConfigureAwait(false);

        //Point the proof at a method id absent from the document's authentication relationship; resolution fails
        //before the signature is ever checked.
        signed.Proof![0].VerificationMethod = new AuthenticationMethod($"{holderDidDocument.Id}#not-authorized");

        var result = await VerifyStaticAsync(signed, holderDidDocument).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.VerificationMethodNotFound, result.FailureReason);
    }


    /// <summary>
    /// A proof whose purpose is not <c>authentication</c> yields
    /// <see cref="VerificationFailureReason.ProofPurposeMismatch"/> even on the static path — a presentation must
    /// be authenticated, not asserted (Data Integrity 1.0 §4.2; VC-DM 2.0 §4.13).
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task NonAuthenticationPurposeIsRejected(DidWebTestData testData)
    {
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            publicKey, testData.VerificationMethodTypeInfo, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        DataIntegritySecuredPresentation signed = await SignStaticPresentationAsync(
            holderDidDocument, privateKey, challenge: null, domain: null).ConfigureAwait(false);

        signed.Proof![0].ProofPurpose = AssertionMethod.Purpose;

        var result = await VerifyStaticAsync(signed, holderDidDocument).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.ProofPurposeMismatch, result.FailureReason);
    }


    /// <summary>
    /// Stripping the <c>challenge</c> from a bound presentation's wire JSON to slip it past the binding check
    /// breaks the signature: the binding fields are signature-covered, so a field-stripped bound presentation
    /// fails with <see cref="VerificationFailureReason.SignatureInvalid"/> rather than verifying. This is the
    /// defense-in-depth backstop behind the <c>UnexpectedPresentationBinding</c> fail-closed check.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task StrippingBindingToEvadeRejectionBreaksSignature(DidWebTestData testData)
    {
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            publicKey, testData.VerificationMethodTypeInfo, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Bind the presentation with a challenge, take it to the wire, and DELETE the challenge member from the
        //proof — an attacker trying to route a replay-bound presentation through the static verify.
        DataIntegritySecuredPresentation bound = await SignStaticPresentationAsync(
            holderDidDocument, privateKey, challenge: VerifierChallenge, domain: null).ConfigureAwait(false);

        string wire = SerializePresentation(bound);
        JsonObject wireObject = JsonNode.Parse(wire)!.AsObject();
        _ = ((JsonObject)((JsonArray)wireObject["proof"]!)[0]!).Remove("challenge");
        var stripped = (DataIntegritySecuredPresentation)DeserializePresentation(wireObject.ToJsonString());

        var result = await VerifyStaticAsync(stripped, holderDidDocument).ConfigureAwait(false);

        //The stripped proof passes the binding check (no challenge present), but the signature was computed over
        //the challenge-bearing proof options, so the cryptographic check fails.
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.SignatureInvalid, result.FailureReason);
    }


    /// <summary>Verifies a static linked presentation with the standard eddsa-jcs-2022 delegate wiring.</summary>
    private ValueTask<CredentialVerificationResult<DataIntegritySecuredPresentation>> VerifyStaticAsync(
        DataIntegritySecuredPresentation presentation, DidDocument holderDidDocument)
    {
        return presentation.VerifyLinkedPresentationAsync(
            holderDidDocument,
            JcsCanonicalizer,
            contextResolver: null,
            presentation.Context!,
            ProofValueDecoder,
            SerializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken);
    }


    /// <summary>
    /// Signs a holder-only presentation, optionally with a challenge and/or domain, through the shared
    /// <see cref="DataIntegrityContextTamperingFixture.SignJcsPresentationAsync(DidDocument, PrivateKeyMemory, string?, string?, DateTime)"/>: the unbound form carries no binding
    /// fields and the bound forms the ones given, so the proof covers whatever binding is present, exactly as a wire
    /// whois.vp would.
    /// </summary>
    private static Task<DataIntegritySecuredPresentation> SignStaticPresentationAsync(
        DidDocument holderDidDocument, PrivateKeyMemory privateKey, string? challenge, string? domain) =>
        DataIntegrityContextTamperingFixture.SignJcsPresentationAsync(
            holderDidDocument, privateKey, challenge, domain, TimeProvider.GetUtcNow().UtcDateTime);


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>:
    /// "If one or more of proof.type, proof.verificationMethod, and proof.proofPurpose does not exist, an error MUST
    /// be raised and SHOULD convey an error type of PROOF_VERIFICATION_ERROR."
    /// </summary>
    /// <remarks>
    /// This drives the Core linked-presentation verification directly rather than an endpoint, so it proves Core's own
    /// refusal, which a caller that checks the mandatory members first would otherwise never reach.
    /// </remarks>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task LinkedPresentationProofWithoutTypeIsRejected(DidWebTestData testData)
    {
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            publicKey, testData.VerificationMethodTypeInfo, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        DataIntegritySecuredPresentation signed = await SignStaticPresentationAsync(
            holderDidDocument, privateKey, challenge: null, domain: null).ConfigureAwait(false);

        signed.Proof![0].Type = null!;

        var result = await signed.VerifyLinkedPresentationAsync(
            holderDidDocument,
            JcsCanonicalizer,
            contextResolver: null,
            signed.Context!,
            ProofValueDecoder,
            SerializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "Data Integrity §4.4: a proof without type MUST be refused.");
        Assert.AreEqual(VerificationFailureReason.MissingVerificationMethod, result.FailureReason,
            "Missing mandatory proof options share the existing verification failure result.");
    }

}
