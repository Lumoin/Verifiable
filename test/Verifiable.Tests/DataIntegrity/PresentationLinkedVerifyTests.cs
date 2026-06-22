using Microsoft.Extensions.Time.Testing;
using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.Core;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Cryptography;
using Verifiable.Foundation;
using Verifiable.Json;
using Verifiable.Microsoft;
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
    public TestContext TestContext { get; set; } = null!;

    private const string VerifierChallenge = "verifier-challenge-abc123";
    private const string VerifierDomain = "verifier.example";

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;
    private static KeyDidBuilder KeyDidBuilder { get; } = new KeyDidBuilder();

    private static FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero));

    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, _, cancellationToken) =>
        ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = Jcs.Canonicalize(json) });

    private static readonly ExchangeContext EmptyContext = new();

    private static ProofValueEncoderDelegate ProofValueEncoder { get; } = ProofValueCodecs.EncodeBase58Btc;
    private static ProofValueDecoderDelegate ProofValueDecoder { get; } = ProofValueCodecs.DecodeBase58Btc;

    private static PresentationSerializeDelegate SerializePresentation { get; } = presentation =>
        JsonSerializerExtensions.Serialize(presentation, JsonOptions);

    private static PresentationDeserializeDelegate DeserializePresentation { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiablePresentation>(serialized, JsonOptions)!;

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
            publicKey, testData.VerificationMethodTypeInfo, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        DataIntegritySecuredPresentation signed = await SignStaticPresentationAsync(
            holderDidDocument, privateKey, challenge: null, domain: null).ConfigureAwait(false);

        var result = await signed.VerifyLinkedPresentationAsync(
            holderDidDocument,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueDecoder,
            SerializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
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
            publicKey, testData.VerificationMethodTypeInfo, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //A challenge with no domain isolates the challenge half of the binding rejection.
        DataIntegritySecuredPresentation signed = await SignStaticPresentationAsync(
            holderDidDocument, privateKey, challenge: VerifierChallenge, domain: null).ConfigureAwait(false);

        var result = await signed.VerifyLinkedPresentationAsync(
            holderDidDocument,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueDecoder,
            SerializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
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
            publicKey, testData.VerificationMethodTypeInfo, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //A domain with no challenge isolates the domain half of the binding rejection.
        DataIntegritySecuredPresentation signed = await SignStaticPresentationAsync(
            holderDidDocument, privateKey, challenge: null, domain: VerifierDomain).ConfigureAwait(false);

        var result = await signed.VerifyLinkedPresentationAsync(
            holderDidDocument,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueDecoder,
            SerializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
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
            publicKey, testData.VerificationMethodTypeInfo, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
            publicKey, testData.VerificationMethodTypeInfo, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
            publicKey, testData.VerificationMethodTypeInfo, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
            publicKey, testData.VerificationMethodTypeInfo, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Bind the presentation with a challenge, take it to the wire, and DELETE the challenge member from the
        //proof — an attacker trying to route a replay-bound presentation through the static verify.
        DataIntegritySecuredPresentation bound = await SignStaticPresentationAsync(
            holderDidDocument, privateKey, challenge: VerifierChallenge, domain: null).ConfigureAwait(false);

        string wire = SerializePresentation(bound);
        JsonObject wireObject = JsonNode.Parse(wire)!.AsObject();
        ((JsonObject)((JsonArray)wireObject["proof"]!)[0]!).Remove("challenge");
        var stripped = (DataIntegritySecuredPresentation)DeserializePresentation(wireObject.ToJsonString());

        var result = await VerifyStaticAsync(stripped, holderDidDocument).ConfigureAwait(false);

        //The stripped proof passes the binding check (no challenge present), but the signature was computed over
        //the challenge-bearing proof options, so the cryptographic check fails.
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.SignatureInvalid, result.FailureReason);
    }


    //Verifies a static linked presentation with the standard eddsa-jcs-2022 delegate wiring.
    private ValueTask<CredentialVerificationResult<DataIntegritySecuredPresentation>> VerifyStaticAsync(
        DataIntegritySecuredPresentation presentation, DidDocument holderDidDocument)
    {
        return presentation.VerifyLinkedPresentationAsync(
            holderDidDocument,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueDecoder,
            SerializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken);
    }


    private static void HashCanonical(string json, Span<byte> destination)
    {
        var canonical = new TaggedMemory<byte>(Jcs.CanonicalizeToUtf8Bytes(json), BufferTags.Json);
        System.Security.Cryptography.SHA256.HashData(canonical.Span, destination);
    }


    //Signs a holder-only presentation, optionally with a challenge and/or domain. The unbound form mirrors the
    //production bound SignAsync minus the binding fields; the bound forms re-use the same hashing so the proof
    //covers whatever binding is present, exactly as a wire whois.vp would.
    private static async Task<DataIntegritySecuredPresentation> SignStaticPresentationAsync(
        DidDocument holderDidDocument, PrivateKeyMemory privateKey, string? challenge, string? domain)
    {
        var holderVerificationMethodId = holderDidDocument.VerificationMethod![0].Id!;
        var holderDid = holderDidDocument.Id!.ToString();
        var proofCreated = TimeProvider.GetUtcNow().UtcDateTime;

        VerifiablePresentation unsigned = new()
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Type = ["VerifiablePresentation"],
            Holder = holderDid
        };

        DataIntegrityProof newProof = new()
        {
            Type = DataIntegrityProof.DataIntegrityProofType,
            Cryptosuite = EddsaJcs2022CryptosuiteInfo.Instance,
            Created = DateTimeStampFormat.Format(proofCreated),
            VerificationMethod = new AuthenticationMethod(holderVerificationMethodId),
            ProofPurpose = AuthenticationMethod.Purpose
        };

        if(challenge is not null)
        {
            newProof.Challenge = challenge;
        }

        if(domain is not null)
        {
            newProof.Domain = [domain];
        }

        ProofOptionsDocument proofOptions = ProofOptionsDocument.FromProof(newProof, null);
        string proofOptionsSerialized = SerializeProofOptions(proofOptions);
        string presentationSerialized = SerializePresentation(unsigned);

        using System.Buffers.IMemoryOwner<byte> hashOwner = BaseMemoryPool.Shared.Rent(64);
        Memory<byte> hashData = hashOwner.Memory[..64];

        //eddsa-jcs-2022 signs SHA-256(JCS(proofOptions)) concatenated with SHA-256(JCS(presentation)); the JCS
        //canonicalization output is wrapped as JSON-tagged memory rather than materialized as a naked array.
        HashCanonical(proofOptionsSerialized, hashData.Span[..32]);
        HashCanonical(presentationSerialized, hashData.Span[32..]);

        using Signature signature = await privateKey.SignAsync(hashData, BaseMemoryPool.Shared).ConfigureAwait(false);
        newProof.ProofValue = ProofValueEncoder(signature.AsReadOnlySpan(), TestSetup.Base58Encoder, BaseMemoryPool.Shared);

        return new DataIntegritySecuredPresentation
        {
            Context = unsigned.Context,
            Type = unsigned.Type,
            Holder = unsigned.Holder,
            Proof = [newProof]
        };
    }
}
