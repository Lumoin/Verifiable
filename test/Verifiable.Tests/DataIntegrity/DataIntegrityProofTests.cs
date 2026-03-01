using System.Security.Cryptography;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Cbor;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.Methods;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Json;
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
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

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
            SensitiveMemoryPool<byte>.Shared,
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
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialVerificationResult.Success(), verificationResult);
    }


    /// <summary>
    /// Tests eddsa-jcs-2022 Data Integrity proof using SignAsync and VerifyAsync.
    /// </summary>
    [TestMethod]
    public async ValueTask EddsaJcs2022DataIntegrityProofSucceeds()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

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
            SensitiveMemoryPool<byte>.Shared,
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
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialVerificationResult.Success(), verificationResult);
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
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(CredentialSecuringMaterial.UnsignedCredentialJson, CredentialSecuringMaterial.JsonOptions)!;

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
            cancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialVerificationResult.Success(), holderVerifyResult);

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
            cancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialVerificationResult.Success(), verificationResult);
    }


    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, cancellationToken) =>
        ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = Jcs.Canonicalize(json) });

    private static CanonicalizationDelegate RdfcCanonicalizer { get; } = CanonicalizationTestUtilities.CreateRdfcCanonicalizer();

    private static ContextResolverDelegate ContextResolver { get; } = CanonicalizationTestUtilities.CreateTestContextResolver();

    private static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializer.Serialize(credential, CredentialSecuringMaterial.JsonOptions);

    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializer.Deserialize<VerifiableCredential>(serialized, CredentialSecuringMaterial.JsonOptions)!;

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