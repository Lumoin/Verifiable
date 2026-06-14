using Microsoft.Extensions.Time.Testing;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Microsoft;
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

    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, _, cancellationToken) =>
    {
        var canonical = Jcs.Canonicalize(json);
        return ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = canonical });
    };

    //Canonicalization/signing here is in-memory; a default context yields the
    //secure-default SSRF policy and satisfies the policy-carrying parameter.
    private static readonly ExchangeContext EmptyContext = new();

    private static ProofValueEncoderDelegate ProofValueEncoder { get; } = ProofValueCodecs.EncodeBase58Btc;
    private static ProofValueDecoderDelegate ProofValueDecoder { get; } = ProofValueCodecs.DecodeBase58Btc;

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
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
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
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Verifier validates the credential issuer signature.
        var credentialVerificationResult = await signedCredential.VerifyAsync(
            issuerDidDocument,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueDecoder,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(credentialVerificationResult.IsValid);

        //Verifier validates the presentation holder signature, challenge, and domain.
        var presentationVerificationResult = await signedPresentation.VerifyAsync(
            holderDidDocument,
            VerifierChallenge,
            VerifierDomain,
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

        Assert.IsTrue(presentationVerificationResult.IsValid);
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
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
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
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
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
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsFalse(result.IsValid);
    }


    /// <summary>
    /// A presentation that crossed the wire — serialized and re-parsed — verifies through
    /// the received-bytes path: the parser retained the proof's wire JSON, and the proof
    /// options canonicalize from the signer's own bytes (Data Integrity 1.0 §4.2).
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task WireRoundTrippedPresentationVerifies(DidWebTestData testData)
    {
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var signedPresentation = await SignMinimalPresentationAsync(
            holderDidDocument, privateKey).ConfigureAwait(false);

        //The verifier's view: wire bytes only.
        string wire = SerializePresentation(signedPresentation);
        var received = (DataIntegritySecuredPresentation)DeserializePresentation(wire);
        Assert.IsNotNull(received.Proof![0].ReceivedProofJson,
            "The parser must retain the proof's received wire JSON.");

        var result = await received.VerifyAsync(
            holderDidDocument,
            VerifierChallenge,
            VerifierDomain,
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

        Assert.IsTrue(result.IsValid,
            $"The wire-round-tripped presentation must verify; got {result.FailureReason}.");
    }


    /// <summary>
    /// Rewriting the challenge on the wire must fail the SIGNATURE — not merely the
    /// challenge comparison. The verifier here expects the TAMPERED value, so the
    /// equality gate passes; only cryptographic coverage of <c>challenge</c> in the
    /// proof options (Data Integrity 1.0 §2.1/§4.2) can reject the replay.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task WireTamperedChallengeFailsTheSignatureItself(DidWebTestData testData)
    {
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var signedPresentation = await SignMinimalPresentationAsync(
            holderDidDocument, privateKey).ConfigureAwait(false);

        //An attacker replaying the captured presentation to a different interaction
        //rewrites the challenge to the one that verifier issued.
        const string AttackerChallenge = "attacker-challenge-zzz999";
        string wire = SerializePresentation(signedPresentation)
            .Replace(VerifierChallenge, AttackerChallenge, StringComparison.Ordinal);
        var received = (DataIntegritySecuredPresentation)DeserializePresentation(wire);

        var result = await received.VerifyAsync(
            holderDidDocument,
            AttackerChallenge,
            VerifierDomain,
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
        Assert.AreEqual(VerificationFailureReason.SignatureInvalid, result.FailureReason,
            "A rewritten challenge must break the signature, not just the comparison.");
    }


    /// <summary>
    /// Rewriting the domain on the wire must fail the SIGNATURE — the cross-domain
    /// replay protection is cryptographic coverage, not the equality gate.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task WireTamperedDomainFailsTheSignatureItself(DidWebTestData testData)
    {
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var signedPresentation = await SignMinimalPresentationAsync(
            holderDidDocument, privateKey).ConfigureAwait(false);

        const string AttackerDomain = "attacker.example";
        string wire = SerializePresentation(signedPresentation)
            .Replace(VerifierDomain, AttackerDomain, StringComparison.Ordinal);
        var received = (DataIntegritySecuredPresentation)DeserializePresentation(wire);

        var result = await received.VerifyAsync(
            holderDidDocument,
            VerifierChallenge,
            AttackerDomain,
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
        Assert.AreEqual(VerificationFailureReason.SignatureInvalid, result.FailureReason,
            "A rewritten domain must break the signature, not just the comparison.");
    }


    /// <summary>
    /// Signs a minimal holder-only presentation with the standard challenge and domain.
    /// </summary>
    private async Task<DataIntegritySecuredPresentation> SignMinimalPresentationAsync(
        DidDocument holderDidDocument, PrivateKeyMemory privateKey)
    {
        var holderVerificationMethodId = holderDidDocument.VerificationMethod![0].Id!;
        var holderDid = holderDidDocument.Id!.ToString();
        var proofCreated = TimeProvider.GetUtcNow().UtcDateTime;

        return await new VerifiablePresentation
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Type = ["VerifiablePresentation"],
            Holder = holderDid
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
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// A presentation proof whose <c>proofPurpose</c> is not <c>authentication</c> must be
    /// rejected with <see cref="VerificationFailureReason.ProofPurposeMismatch"/> even when
    /// the signing key also appears in the holder's <c>authentication</c> relationship —
    /// Data Integrity 1.0 §4.2 mandates the expected-purpose comparison, and the check runs
    /// before any cryptographic work so the reason names the purpose, not the signature.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task WrongProofPurposeFailsVerification(DidWebTestData testData)
    {
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var holderVerificationMethodId = holderDidDocument.VerificationMethod![0].Id!;
        var holderDid = holderDidDocument.Id!.ToString();
        var proofCreated = TimeProvider.GetUtcNow().UtcDateTime;

        var signedPresentation = await new VerifiablePresentation
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Type = ["VerifiablePresentation"],
            Holder = holderDid
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
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Forge the purpose: the same key, the same signature, but a proof minted
        //for assertion rather than authentication.
        signedPresentation.Proof![0].ProofPurpose = AssertionMethod.Purpose;

        var result = await signedPresentation.VerifyAsync(
            holderDidDocument,
            VerifierChallenge,
            VerifierDomain,
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
        Assert.AreEqual(VerificationFailureReason.ProofPurposeMismatch, result.FailureReason,
            "The §4.2 purpose comparison must reject before signature work.");
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
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
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
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
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
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
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
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
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
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
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
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.DomainMismatch, result.FailureReason);
    }
}
