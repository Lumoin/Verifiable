using Microsoft.Extensions.Time.Testing;
using System.Text.Json;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.FlowTests;

/// <summary>
/// End-to-end flow tests for Data Integrity-secured Verifiable Presentations.
/// </summary>
/// <remarks>
/// <para>
/// These tests exercise the three-party issuer → holder → verifier flow using
/// Data Integrity embedded proofs on both the credential and the presentation.
/// The credential is signed by the issuer using <c>eddsa-jcs-2022</c>, and the
/// presentation is signed by the holder using the <c>authentication</c> verification
/// relationship with a verifier-issued challenge and domain.
/// </para>
/// <para>
/// JCS canonicalization is used throughout because it requires no external context
/// resolution and signs all JSON properties, making the tests self-contained.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#presentations">VC Data Model 2.0 §3.3 Presentations</see>
/// and <see href="https://www.w3.org/TR/vc-data-integrity/">Data Integrity 1.0</see>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class DataIntegrityPresentationFlowTests
{
    /// <summary>
    /// Test context providing test run information and cancellation support.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    private const string IssuerDomain = "university.example";
    private const string IssuerDidWeb = "did:web:university.example";
    private const string AlumniCredentialType = "AlumniCredential";
    private const string ClaimAlumniOf = "alumniOf";
    private const string ClaimValueUniversityName = "Example University";
    private const string VerifierChallenge = "verifier-challenge-abc123";
    private const string VerifierDomain = "verifier.example";

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;
    private static CredentialBuilder CredentialBuilder { get; } = new CredentialBuilder();
    private static KeyDidBuilder KeyDidBuilder { get; } = new KeyDidBuilder();
    private static WebDidBuilder WebDidBuilder { get; } = new WebDidBuilder();

    private static FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero));

    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, cancellationToken) =>
    {
        var canonical = Jcs.Canonicalize(json);
        return ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = canonical });
    };

    private static ProofValueEncoderDelegate ProofValueEncoder { get; } = ProofValueCodecs.EncodeBase58Btc;
    private static ProofValueDecoderDelegate ProofValueDecoder { get; } = ProofValueCodecs.DecodeBase58Btc;

    private static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializer.Serialize(credential, JsonOptions);

    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializer.Deserialize<VerifiableCredential>(serialized, JsonOptions)!;

    private static PresentationSerializeDelegate SerializePresentation { get; } = presentation =>
        JsonSerializer.Serialize(presentation, JsonOptions);

    private static PresentationDeserializeDelegate DeserializePresentation { get; } = serialized =>
        JsonSerializer.Deserialize<VerifiablePresentation>(serialized, JsonOptions)!;

    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);


    /// <summary>
    /// Tests the complete three-party presentation flow using JCS canonicalization.
    /// Issuer signs a credential, holder wraps it in a VP and signs the VP with a
    /// verifier-issued challenge, and the verifier validates both signatures.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task IssueSignAndVerifyPresentationSucceeds(DidWebTestData testData)
    {
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        //Issuer builds a DID document; holder builds one using did:key.
        var issuerDidDocument = await WebDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var issuerVerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;
        var holderVerificationMethodId = holderDidDocument.VerificationMethod![0].Id!;
        var holderDid = holderDidDocument.Id!.ToString();

        //Issuer signs the credential.
        var issuer = new Issuer { Id = IssuerDidWeb, Name = ClaimValueUniversityName };
        var subject = new CredentialSubjectInput
        {
            Id = holderDid,
            Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
        };

        var validFrom = TimeProvider.GetUtcNow().UtcDateTime;
        var validUntil = validFrom.AddYears(10);
        var proofCreated = TimeProvider.GetUtcNow().UtcDateTime;

        var unsignedCredential = await CredentialBuilder.BuildAsync(
            issuer,
            subject,
            validFrom,
            additionalTypes: [AlumniCredentialType],
            validUntil: validUntil,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var signedCredential = await unsignedCredential.SignAsync(
            privateKey,
            issuerVerificationMethodId,
            EddsaJcs2022CryptosuiteInfo.Instance,
            proofCreated,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueEncoder,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Holder wraps the signed credential in a Verifiable Presentation.
        var unsignedPresentation = new VerifiablePresentation
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Type = ["VerifiablePresentation"],
            Holder = holderDid,
            VerifiableCredential = [signedCredential]
        };

        //Holder signs the presentation using the authentication relationship.
        var signedPresentation = await unsignedPresentation.SignAsync(
            privateKey,
            holderVerificationMethodId,
            EddsaJcs2022CryptosuiteInfo.Instance,
            proofCreated,
            VerifierChallenge,
            VerifierDomain,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueEncoder,
            SerializePresentation,
            DeserializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Verifier validates the credential issuer signature.
        var credentialVerificationResult = await signedCredential.VerifyAsync(
            issuerDidDocument,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueDecoder,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialVerificationResult.Success(), credentialVerificationResult);

        //Verifier validates the presentation holder signature, challenge, and domain.
        var presentationVerificationResult = await signedPresentation.VerifyAsync(
            holderDidDocument,
            VerifierChallenge,
            VerifierDomain,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueDecoder,
            SerializePresentation,
            DeserializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialVerificationResult.Success(), presentationVerificationResult);
        Assert.AreEqual(holderDid, signedPresentation.Holder);
        Assert.IsNotNull(signedPresentation.VerifiableCredential);
        Assert.HasCount(1, signedPresentation.VerifiableCredential);
    }


    /// <summary>
    /// Tests that a tampered presentation proof fails verification.
    /// Modifying the proof value after signing must invalidate the signature.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task TamperedPresentationProofFailsVerification(DidWebTestData testData)
    {
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var issuerDidDocument = await WebDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var issuerVerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;
        var holderVerificationMethodId = holderDidDocument.VerificationMethod![0].Id!;
        var holderDid = holderDidDocument.Id!.ToString();

        var proofCreated = TimeProvider.GetUtcNow().UtcDateTime;

        var unsignedCredential = await CredentialBuilder.BuildAsync(
            new Issuer { Id = IssuerDidWeb },
            new CredentialSubjectInput
            {
                Id = holderDid,
                Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
            },
            proofCreated,
            additionalTypes: [AlumniCredentialType],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var signedCredential = await unsignedCredential.SignAsync(
            privateKey,
            issuerVerificationMethodId,
            EddsaJcs2022CryptosuiteInfo.Instance,
            proofCreated,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueEncoder,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var signedPresentation = await new VerifiablePresentation
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Type = ["VerifiablePresentation"],
            Holder = holderDid,
            VerifiableCredential = [signedCredential]
        }.SignAsync(
            privateKey,
            holderVerificationMethodId,
            EddsaJcs2022CryptosuiteInfo.Instance,
            proofCreated,
            VerifierChallenge,
            VerifierDomain,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueEncoder,
            SerializePresentation,
            DeserializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Replace the proof value with an invalid one.
        signedPresentation.Proof![0].ProofValue = "zTAMPEREDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

        var result = await signedPresentation.VerifyAsync(
            holderDidDocument,
            VerifierChallenge,
            VerifierDomain,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueDecoder,
            SerializePresentation,
            DeserializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(CredentialVerificationResult.Success(), result);
        Assert.IsFalse(result.IsValid);
    }


    /// <summary>
    /// Tests that presenting a wrong challenge value fails verification.
    /// The verifier must reject a presentation whose proof challenge does not
    /// match the expected challenge.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task WrongChallengeFailsVerification(DidWebTestData testData)
    {
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var issuerDidDocument = await WebDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var issuerVerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;
        var holderVerificationMethodId = holderDidDocument.VerificationMethod![0].Id!;
        var holderDid = holderDidDocument.Id!.ToString();

        var proofCreated = TimeProvider.GetUtcNow().UtcDateTime;

        var unsignedCredential = await CredentialBuilder.BuildAsync(
            new Issuer { Id = IssuerDidWeb },
            new CredentialSubjectInput
            {
                Id = holderDid,
                Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
            },
            proofCreated,
            additionalTypes: [AlumniCredentialType],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var signedCredential = await unsignedCredential.SignAsync(
            privateKey,
            issuerVerificationMethodId,
            EddsaJcs2022CryptosuiteInfo.Instance,
            proofCreated,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueEncoder,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var signedPresentation = await new VerifiablePresentation
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Type = ["VerifiablePresentation"],
            Holder = holderDid,
            VerifiableCredential = [signedCredential]
        }.SignAsync(
            privateKey,
            holderVerificationMethodId,
            EddsaJcs2022CryptosuiteInfo.Instance,
            proofCreated,
            VerifierChallenge,
            VerifierDomain,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueEncoder,
            SerializePresentation,
            DeserializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Verify with a different challenge than was used when signing.
        var result = await signedPresentation.VerifyAsync(
            holderDidDocument,
            expectedChallenge: "wrong-challenge",
            VerifierDomain,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueDecoder,
            SerializePresentation,
            DeserializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.ChallengeMismatch, result.FailureReason);
    }


    /// <summary>
    /// Tests that presenting a wrong domain value fails verification.
    /// The verifier must reject a presentation whose proof domain does not
    /// match the expected domain.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task WrongDomainFailsVerification(DidWebTestData testData)
    {
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var issuerDidDocument = await WebDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var issuerVerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;
        var holderVerificationMethodId = holderDidDocument.VerificationMethod![0].Id!;
        var holderDid = holderDidDocument.Id!.ToString();

        var proofCreated = TimeProvider.GetUtcNow().UtcDateTime;

        var unsignedCredential = await CredentialBuilder.BuildAsync(
            new Issuer { Id = IssuerDidWeb },
            new CredentialSubjectInput
            {
                Id = holderDid,
                Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
            },
            proofCreated,
            additionalTypes: [AlumniCredentialType],
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var signedCredential = await unsignedCredential.SignAsync(
            privateKey,
            issuerVerificationMethodId,
            EddsaJcs2022CryptosuiteInfo.Instance,
            proofCreated,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueEncoder,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var signedPresentation = await new VerifiablePresentation
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Type = ["VerifiablePresentation"],
            Holder = holderDid,
            VerifiableCredential = [signedCredential]
        }.SignAsync(
            privateKey,
            holderVerificationMethodId,
            EddsaJcs2022CryptosuiteInfo.Instance,
            proofCreated,
            VerifierChallenge,
            VerifierDomain,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueEncoder,
            SerializePresentation,
            DeserializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Verify with a different domain than was used when signing.
        var result = await signedPresentation.VerifyAsync(
            holderDidDocument,
            VerifierChallenge,
            expectedDomain: "wrong.example",
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueDecoder,
            SerializePresentation,
            DeserializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.DomainMismatch, result.FailureReason);
    }
}