using System.Security.Cryptography;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Cbor;
using Verifiable.Core;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.Methods;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DataIntegrity;

/// <summary>
/// Tests for W3C VC Data Model 2.0 Data Integrity proof securing methods.
/// </summary>
/// <remarks>
/// <para>
/// Covers three cryptosuites:
/// </para>
/// <list type="bullet">
/// <item><description>eddsa-rdfc-2022: EdDSA with RDF Dataset Canonicalization.</description></item>
/// <item><description>eddsa-jcs-2022: EdDSA with JSON Canonicalization Scheme.</description></item>
/// <item><description>ecdsa-sd-2023: ECDSA with selective disclosure (Issuer → Holder → Verifier flow).</description></item>
/// </list>
/// </remarks>
[TestClass]
internal sealed class DataIntegrityProofTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly DateTime ProofCreated = new(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> P256IssuerKeys { get; } = BouncyCastleKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);

    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> P256EphemeralKeys { get; } = BouncyCastleKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);


    /// <summary>
    /// Tests eddsa-rdfc-2022 Data Integrity proof using SignAsync and VerifyAsync.
    /// </summary>
    [TestMethod]
    public async ValueTask EddsaRdfc2022DataIntegrityProofSucceeds()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        var didDocument = CreateDidDocument(CredentialSecuringMaterial.VerificationMethodId, CredentialSecuringMaterial.Ed25519PublicKeyMultibase);

        var signedCredential = await credential.SignAsync(
            privateKey,
            CredentialSecuringMaterial.VerificationMethodId,
            EddsaRdfc2022CryptosuiteInfo.Instance,
            ProofCreated,
            RdfcCanonicalizer,
            ContextResolver,
            ProofValueCodecs.EncodeBase58Btc,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            SensitiveMemoryPool<byte>.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(signedCredential.Proof);
        Assert.HasCount(1, signedCredential.Proof);

        var proof = signedCredential.Proof[0];
        Assert.AreEqual("DataIntegrityProof", proof.Type);
        Assert.AreEqual("eddsa-rdfc-2022", proof.Cryptosuite?.CryptosuiteName);
        Assert.StartsWith("z", proof.ProofValue, "Proof value must be base58btc encoded.");

        var verificationResult = await signedCredential.VerifyAsync(
            didDocument,
            RdfcCanonicalizer,
            ContextResolver,
            ProofValueCodecs.DecodeBase58Btc,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            SensitiveMemoryPool<byte>.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verificationResult.IsValid);
    }


    /// <summary>
    /// Tests eddsa-jcs-2022 Data Integrity proof using SignAsync and VerifyAsync.
    /// </summary>
    [TestMethod]
    public async ValueTask EddsaJcs2022DataIntegrityProofSucceeds()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        var didDocument = CreateDidDocument(CredentialSecuringMaterial.VerificationMethodId, CredentialSecuringMaterial.Ed25519PublicKeyMultibase);

        var signedCredential = await credential.SignAsync(
            privateKey,
            CredentialSecuringMaterial.VerificationMethodId,
            EddsaJcs2022CryptosuiteInfo.Instance,
            ProofCreated,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueCodecs.EncodeBase58Btc,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            SensitiveMemoryPool<byte>.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(signedCredential.Proof);
        Assert.HasCount(1, signedCredential.Proof);

        var proof = signedCredential.Proof[0];
        Assert.AreEqual("DataIntegrityProof", proof.Type);
        Assert.AreEqual("eddsa-jcs-2022", proof.Cryptosuite?.CryptosuiteName);
        Assert.StartsWith("z", proof.ProofValue, "Proof value must be base58btc encoded.");

        var verificationResult = await signedCredential.VerifyAsync(
            didDocument,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueCodecs.DecodeBase58Btc,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            SensitiveMemoryPool<byte>.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verificationResult.IsValid);
    }


    /// <summary>
    /// Tests ecdsa-sd-2023 Data Integrity proof with selective disclosure.
    /// Demonstrates the Issuer → Holder → Verifier flow using the library API.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This test demonstrates the realistic three-party flow where each party only has
    /// access to information they would receive in production:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Issuer: Has unsigned credential and keys, creates base proof.</description></item>
    /// <item><description>Holder: Receives signed credential, verifies, stores it, later creates derived proof.</description></item>
    /// <item><description>Verifier: Receives derived credential, verifies.</description></item>
    /// </list>
    /// </remarks>
    [TestMethod]
    public async ValueTask EcdsaSd2023BaseAndDerivedProofSucceeds()
    {
        var cancellationToken = TestContext.CancellationToken;
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        //Mandatory paths are always disclosed regardless of verifier request or user preference.
        var mandatoryPaths = new List<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/issuer"),
            CredentialPath.FromJsonPointer("/type")
        };

        //Issuer creates base proof containing all claims with selective disclosure capability.
        const string SelectedVerificationMethodId = "did:example:issuer#key-1";
        var signedCredential = await credential.CreateBaseProofAsync(
            P256IssuerKeys.PrivateKey,
            P256EphemeralKeys,
            SelectedVerificationMethodId,
            ProofCreated,
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
            SensitiveMemoryPool<byte>.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(signedCredential.Proof);
        Assert.StartsWith(
            MultibaseAlgorithms.Base64Url.ToString(),
            signedCredential.Proof[0].ProofValue,
            "Base proof must use base64url-no-pad multibase encoding.");

        //Holder receives credential and verifies issuer signature.
        var holderVerifyResult = await signedCredential.VerifyBaseProofAsync(
            P256IssuerKeys.PublicKey,
            BouncyCastleCryptographicFunctions.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            JsonLdSelection.PartitionStatements,
            RdfcCanonicalizer,
            ContextResolver,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            SensitiveMemoryPool<byte>.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(holderVerifyResult.IsValid);

        //Holder stores the credential (just the POCO, no internal state needed).
        //Later, when presenting to a verifier...

        //Verifier requests specific claims. Holder decides what to disclose.
        var verifierRequestedPaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/credentialSubject/degree/name")
        };

        //User could exclude certain paths, but in this test we don't exclude anything.
        IReadOnlySet<CredentialPath>? userExclusions = null;

        //Holder creates derived proof with selected claims.
        var derivedCredential = await signedCredential.DeriveProofAsync(
            verifierRequestedPaths,
            userExclusions,
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
            SensitiveMemoryPool<byte>.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(derivedCredential.Proof);
        Assert.StartsWith(
            MultibaseAlgorithms.Base64Url.ToString(),
            derivedCredential.Proof[0].ProofValue!,
            "Derived proof must use base64url-no-pad multibase encoding.");

        //Verifier receives derived credential and verifies the selective disclosure proof.
        var verificationResult = await derivedCredential.VerifyDerivedProofAsync(
            P256IssuerKeys.PublicKey,
            BouncyCastleCryptographicFunctions.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
            RdfcCanonicalizer,
            ContextResolver,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            SensitiveMemoryPool<byte>.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verificationResult.IsValid);
    }


    /// <summary>
    /// Tests that re-signing an already-secured credential appends a chained proof
    /// (<c>previousProof</c> referencing the prior proof's <c>id</c>) and that the
    /// verifier walks the two-link chain successfully.
    /// </summary>
    [TestMethod]
    public async ValueTask ProofChainTwoLinksVerifies()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        var didDocument = CreateDidDocument(CredentialSecuringMaterial.VerificationMethodId, CredentialSecuringMaterial.Ed25519PublicKeyMultibase);

        var firstSigned = await SignJcsAsync(credential, privateKey).ConfigureAwait(false);
        var secondSigned = await SignJcsAsync(firstSigned, privateKey).ConfigureAwait(false);

        Assert.IsNotNull(secondSigned.Proof);
        Assert.HasCount(2, secondSigned.Proof);
        Assert.IsNull(secondSigned.Proof[0].PreviousProof, "The first proof in a chain has no predecessor.");
        Assert.AreEqual(secondSigned.Proof[0].Id, secondSigned.Proof[1].PreviousProof, "The second proof must chain onto the first proof's id.");

        var result = await VerifyJcsAsync(secondSigned, didDocument).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid);
    }


    /// <summary>
    /// Relinking a proof chain CONSISTENTLY — a forged id on the first proof with the
    /// second proof's <c>previousProof</c> pointed at it — must fail the SIGNATURES:
    /// the chain walk still resolves, so only cryptographic coverage of <c>id</c> and
    /// <c>previousProof</c> in the signed proof options (Data Integrity 1.0 §2.1.2,
    /// §4.2 proof-minus-proofValue) can catch the rewrite. A chain whose links are not
    /// signed is not cryptographically chained.
    /// </summary>
    [TestMethod]
    public async ValueTask RelinkedProofChainFailsTheSignatures()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        var didDocument = CreateDidDocument(CredentialSecuringMaterial.VerificationMethodId, CredentialSecuringMaterial.Ed25519PublicKeyMultibase);

        var firstSigned = await SignJcsAsync(credential, privateKey).ConfigureAwait(false);
        var secondSigned = await SignJcsAsync(firstSigned, privateKey).ConfigureAwait(false);

        secondSigned.Proof![0].Id = "urn:uuid:ffffffff-0000-0000-0000-000000000000";
        secondSigned.Proof[1].PreviousProof = secondSigned.Proof[0].Id;

        var result = await VerifyJcsAsync(secondSigned, didDocument).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A consistently relinked chain must not verify.");
        Assert.AreEqual(VerificationFailureReason.SignatureInvalid, result.FailureReason,
            "The rewrite must break the signatures, not the chain walk.");
    }


    /// <summary>
    /// Tests that a proof whose <c>previousProof</c> references a non-existent proof id
    /// fails with <see cref="VerificationFailureReason.BrokenProofChain"/>.
    /// </summary>
    [TestMethod]
    public async ValueTask ProofChainBrokenLinkFails()
    {
        var didDocument = CreateDidDocument(CredentialSecuringMaterial.VerificationMethodId, CredentialSecuringMaterial.Ed25519PublicKeyMultibase);
        var secured = new DataIntegritySecuredCredential
        {
            Proof =
            [
                new DataIntegrityProof { Id = "urn:uuid:00000000-0000-0000-0000-000000000001" },
                new DataIntegrityProof { Id = "urn:uuid:00000000-0000-0000-0000-000000000002", PreviousProof = "urn:uuid:does-not-exist" }
            ]
        };

        var result = await VerifyJcsAsync(secured, didDocument).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.BrokenProofChain, result.FailureReason);
    }


    /// <summary>
    /// Tests that a proof chain whose <c>previousProof</c> references form a cycle (no root
    /// proof) fails with <see cref="VerificationFailureReason.ProofChainCycle"/>.
    /// </summary>
    [TestMethod]
    public async ValueTask ProofChainCycleFails()
    {
        var didDocument = CreateDidDocument(CredentialSecuringMaterial.VerificationMethodId, CredentialSecuringMaterial.Ed25519PublicKeyMultibase);
        var secured = new DataIntegritySecuredCredential
        {
            Proof =
            [
                new DataIntegrityProof { Id = "urn:uuid:00000000-0000-0000-0000-00000000000a", PreviousProof = "urn:uuid:00000000-0000-0000-0000-00000000000b" },
                new DataIntegrityProof { Id = "urn:uuid:00000000-0000-0000-0000-00000000000b", PreviousProof = "urn:uuid:00000000-0000-0000-0000-00000000000a" }
            ]
        };

        var result = await VerifyJcsAsync(secured, didDocument).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.ProofChainCycle, result.FailureReason);
    }


    /// <summary>
    /// Tests the proof-over-proof binding: a chained proof is computed over the credential
    /// carrying its predecessor, so presenting the later proof without the earlier one it
    /// builds upon fails the signature check.
    /// </summary>
    [TestMethod]
    public async ValueTask ProofChainRemovingEarlierLinkBreaksLaterProof()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        var didDocument = CreateDidDocument(CredentialSecuringMaterial.VerificationMethodId, CredentialSecuringMaterial.Ed25519PublicKeyMultibase);

        var firstSigned = await SignJcsAsync(credential, privateKey).ConfigureAwait(false);
        var secondSigned = await SignJcsAsync(firstSigned, privateKey).ConfigureAwait(false);

        //Drop the first proof but keep the second, which was signed over the credential+first proof.
        var withoutFirstLink = new DataIntegritySecuredCredential
        {
            Context = secondSigned.Context,
            Id = secondSigned.Id,
            Type = secondSigned.Type,
            Issuer = secondSigned.Issuer,
            CredentialSubject = secondSigned.CredentialSubject,
            ValidFrom = secondSigned.ValidFrom,
            ValidUntil = secondSigned.ValidUntil,
            Proof = [secondSigned.Proof![1]]
        };

        var result = await VerifyJcsAsync(withoutFirstLink, didDocument).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.SignatureInvalid, result.FailureReason);
    }


    /// <summary>
    /// Verification mints a <see cref="Verified{T}"/> carrying the credential and a verification
    /// context <see cref="Tag"/> (provenance: <see cref="Purpose.Verification"/> and the
    /// verification method). The minted value is what a trusted consumer requires — a bare
    /// deserialized credential cannot stand in for it, because only the verify path can mint it.
    /// </summary>
    [TestMethod]
    public async ValueTask VerifiedResultCarriesCredentialAndVerificationContext()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        var didDocument = CreateDidDocument(CredentialSecuringMaterial.VerificationMethodId, CredentialSecuringMaterial.Ed25519PublicKeyMultibase);

        var signedCredential = await SignJcsAsync(credential, privateKey).ConfigureAwait(false);
        var result = await VerifyJcsAsync(signedCredential, didDocument).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid);
        Assert.IsNotNull(result.Verified);

        var verified = result.Verified!.Value;
        Assert.AreEqual(signedCredential.Id, verified.Value.Id, "The verified value is the credential that was verified.");

        //Provenance: the verification context reuses the Tag mechanism.
        Assert.IsTrue(verified.Context.TryGet<Purpose>(out var purpose));
        Assert.AreEqual(Purpose.Verification, purpose);
        Assert.IsTrue(verified.Context.TryGet<KeyId>(out var keyId));
        Assert.AreEqual(CredentialSecuringMaterial.VerificationMethodId, keyId.Value);

        //Type discipline: a trusted consumer that requires Verified<...> accepts the minted value;
        //a bare VerifiableCredential would not satisfy this signature.
        Assert.AreEqual(signedCredential.Id, ReadTrustedCredentialId(verified));
    }


    //A stand-in for a trusted consumer: it can only be called with a minted Verified<...>.
    private static string? ReadTrustedCredentialId(Verified<DataIntegritySecuredCredential> verified) => verified.Value.Id;


    private static ValueTask<DataIntegritySecuredCredential> SignJcsAsync(VerifiableCredential credential, PrivateKeyMemory privateKey) =>
        credential.SignAsync(
            privateKey,
            CredentialSecuringMaterial.VerificationMethodId,
            EddsaJcs2022CryptosuiteInfo.Instance,
            ProofCreated,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueCodecs.EncodeBase58Btc,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            SensitiveMemoryPool<byte>.Shared,
            EmptyContext);


    private static ValueTask<CredentialVerificationResult<DataIntegritySecuredCredential>> VerifyJcsAsync(DataIntegritySecuredCredential credential, DidDocument didDocument) =>
        credential.VerifyAsync(
            didDocument,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueCodecs.DecodeBase58Btc,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            SensitiveMemoryPool<byte>.Shared,
            EmptyContext);


    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, _, cancellationToken) =>
        ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = Jcs.Canonicalize(json) });

    //Canonicalization/signing here is in-memory; a default context yields the
    //secure-default SSRF policy and satisfies the policy-carrying parameter.
    private static readonly ExchangeContext EmptyContext = new();

    private static CanonicalizationDelegate RdfcCanonicalizer { get; } = CanonicalizationTestUtilities.CreateRdfcCanonicalizer();

    private static ContextResolverDelegate ContextResolver { get; } = CanonicalizationTestUtilities.CreateTestContextResolver();

    private static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializerExtensions.Serialize(credential, CredentialSecuringMaterial.JsonOptions);

    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(serialized, CredentialSecuringMaterial.JsonOptions)!;

    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(CredentialSecuringMaterial.JsonOptions);

    private static DidDocument CreateDidDocument(string verificationMethodId, string publicKeyMultibase)
    {
        var did = verificationMethodId.Split('#')[0];
        return new DidDocument
        {
            Id = new GenericDidMethod(did),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = verificationMethodId,
                    Type = "Multikey",
                    Controller = did,
                    KeyFormat = new PublicKeyMultibase(publicKeyMultibase)
                }
            ],
            AssertionMethod = [new AssertionMethod(verificationMethodId)]
        };
    }
}
