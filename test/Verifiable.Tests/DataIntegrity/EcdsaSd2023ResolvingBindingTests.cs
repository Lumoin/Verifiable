using System.Security.Cryptography;
using Verifiable.BouncyCastle;
using Verifiable.Cbor;
using Verifiable.Core;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DataIntegrity;

/// <summary>
/// Tests for the RESOLVING <c>VerifyBaseProofAsync(DidDocument, ...)</c>/<c>VerifyDerivedProofAsync(DidDocument, ...)</c>
/// overloads on ecdsa-sd-2023 (<see cref="CredentialEcdsaSd2023Extensions"/>). Each folds
/// into the SAME controller-resolution gate the embedded-proof Data Integrity credential path uses
/// (<c>SelectiveDisclosureIdentityBinding</c> -&gt; <see cref="BoundProvenance.TryBindByControllerArtifact"/>):
/// proof-purpose check, <c>assertionMethod</c>-relationship-scoped resolution, the cryptographic
/// check against the resolved key, and controller-RESOLUTION, ALL before minting
/// <see cref="Verified{T}.IsIdentityBound"/> <see langword="true"/>.
/// </summary>
[TestClass]
internal sealed class EcdsaSd2023ResolvingBindingTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string IssuerDid = "did:example:ecdsa-sd-issuer";
    private const string SignerKeyId = "did:example:ecdsa-sd-issuer#key-1";

    private static DateTime ProofCreated { get; } = new(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    //Canonicalization/signing here is in-memory; a default context yields the
    //secure-default SSRF policy and satisfies the policy-carrying parameter.
    private static ExchangeContext EmptyContext { get; } = new();

    private static CanonicalizationDelegate RdfcCanonicalizer { get; } = CanonicalizationTestUtilities.CreateRdfcCanonicalizer();

    private static ContextResolverDelegate ContextResolver { get; } = CanonicalizationTestUtilities.CreateTestContextResolver();

    private static IReadOnlyList<CredentialPath> MandatoryPaths { get; } =
    [
        CredentialPath.FromJsonPointer("/issuer"),
        CredentialPath.FromJsonPointer("/type")
    ];

    private const string CredentialJson = /*lang=json,strict*/ """
    {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "http://university.example/credentials/9821",
        "type": ["VerifiableCredential", "ExampleDegreeCredential"],
        "issuer": "did:example:ecdsa-sd-issuer",
        "validFrom": "2024-01-01T00:00:00Z",
        "credentialSubject": {
            "id": "did:example:subject",
            "degree": {
                "type": "ExampleBachelorDegree",
                "name": "Bachelor of Science and Arts"
            }
        }
    }
    """;


    /// <summary>
    /// Positive Bound mint (base proof) plus the witness-tie half: the resolving overload mints
    /// <see cref="BoundProvenance"/> (<see cref="ResolutionSource.CallerControllerArtifact"/>,
    /// <see cref="VerificationRelationship.AssertionMethod"/>) over a genuinely issuer-signed base
    /// proof, and the SAME <see cref="BoundProvenance"/> refuses to mint over a DIFFERENT credential
    /// instance via <see cref="Verified{T}.TryCreateBound"/>.
    /// </summary>
    [TestMethod]
    public async Task ResolvingBaseProofMintsBoundOnGenuineSignatureAndWitnessRefusesADifferentCredential()
    {
        var cancellationToken = TestContext.CancellationToken;
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var issuerPublicKey = issuerPair.PublicKey;
        using var issuerPrivateKey = issuerPair.PrivateKey;

        var signedCredential = await SignBaseAsync(issuerPrivateKey, cancellationToken).ConfigureAwait(false);
        var issuerDidDocument = CreateIssuerDidDocument(issuerPublicKey);

        var result = await VerifyBaseResolvingAsync(signedCredential, issuerDidDocument, cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "The resolving overload must verify a genuinely issuer-signed base proof.");
        Assert.IsNotNull(result.Verified);
        var verified = result.Verified!.Value;
        Assert.IsTrue(verified.IsIdentityBound, "The resolving overload must mint Bound, not Asserted.");
        Assert.IsTrue(verified.Provenance is BoundProvenance);
        var bound = (BoundProvenance)verified.Provenance!;
        Assert.AreEqual(ResolutionSource.CallerControllerArtifact, bound.Source);
        Assert.AreEqual(VerificationRelationship.AssertionMethod, bound.Relationship);
        Assert.AreEqual(SignerKeyId, bound.Identity?.Value);

        //Witness tie: the SAME BoundProvenance refuses to mint over a DIFFERENT credential instance.
        var otherSigned = await SignBaseAsync(issuerPrivateKey, cancellationToken).ConfigureAwait(false);
        Verified<DataIntegritySecuredCredential>? witnessMismatch = Verified<DataIntegritySecuredCredential>.TryCreateBound(otherSigned, bound);
        Assert.IsNull(witnessMismatch, "A BoundProvenance established for one credential instance must refuse to mint over a different instance.");
    }


    /// <summary>
    /// Controller-RESOLUTION semantics: a resolved method whose own <c>controller</c> does
    /// NOT equal the credential's <c>issuer</c> is refused, even though the signature, proof purpose,
    /// and <c>assertionMethod</c> scoping all otherwise hold.
    /// </summary>
    [TestMethod]
    public async Task BaseProofIssuerControllerMismatchIsRefused()
    {
        var cancellationToken = TestContext.CancellationToken;
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var issuerPublicKey = issuerPair.PublicKey;
        using var issuerPrivateKey = issuerPair.PrivateKey;

        var signedCredential = await SignBaseAsync(issuerPrivateKey, cancellationToken).ConfigureAwait(false);

        //The resolved method's own controller is deliberately NOT the credential's issuer.
        var mismatchedDidDocument = CreateIssuerDidDocument(issuerPublicKey, controller: "did:example:someone-else-entirely");

        var result = await VerifyBaseResolvingAsync(signedCredential, mismatchedDidDocument, cancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.ControllerMismatch, result.FailureReason);
        Assert.IsNull(result.Verified);
    }


    /// <summary>
    /// Data Integrity 1.0 §4.2: a proof whose declared <c>proofPurpose</c> is not <c>assertionMethod</c>
    /// is refused before any resolution or cryptographic work, even for an otherwise genuine signature.
    /// </summary>
    [TestMethod]
    public async Task BaseProofWrongProofPurposeIsRefused()
    {
        var cancellationToken = TestContext.CancellationToken;
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var issuerPublicKey = issuerPair.PublicKey;
        using var issuerPrivateKey = issuerPair.PrivateKey;

        var signedCredential = await SignBaseAsync(issuerPrivateKey, cancellationToken).ConfigureAwait(false);

        //Forge the purpose: the same key, the same signature, but a proof minted for authentication
        //rather than assertionMethod.
        signedCredential.Proof![0].ProofPurpose = AuthenticationMethod.Purpose;

        var issuerDidDocument = CreateIssuerDidDocument(issuerPublicKey);
        var result = await VerifyBaseResolvingAsync(signedCredential, issuerDidDocument, cancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.ProofPurposeMismatch, result.FailureReason);
    }


    /// <summary>The BYOK base-proof overload's behavior is unchanged: it mints Asserted, never Bound.</summary>
    [TestMethod]
    public async Task ByokBaseProofOverloadStillMintsAssertedNotBound()
    {
        var cancellationToken = TestContext.CancellationToken;
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var issuerPublicKey = issuerPair.PublicKey;
        using var issuerPrivateKey = issuerPair.PrivateKey;

        var signedCredential = await SignBaseAsync(issuerPrivateKey, cancellationToken).ConfigureAwait(false);

        var result = await signedCredential.VerifyBaseProofAsync(
            issuerPublicKey,
            BouncyCastleCryptographicFunctionsAdapter.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            JsonLdSelection.PartitionStatements,
            RdfcCanonicalizer,
            ContextResolver,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid);
        Assert.IsNotNull(result.Verified);
        Assert.IsFalse(result.Verified!.Value.IsIdentityBound, "The BYOK overload must mint Asserted, never Bound.");
        Assert.IsTrue(result.Verified.Value.Provenance is AssertedProvenance);
    }


    /// <summary>
    /// Positive Bound mint (derived proof): a derived proof's <c>verificationMethod</c> is the same
    /// issuer method the base proof carried, so the resolving derived overload runs the same
    /// resolve-and-bind recipe and mints Bound.
    /// </summary>
    [TestMethod]
    public async Task ResolvingDerivedProofMintsBoundOnGenuineSignature()
    {
        var cancellationToken = TestContext.CancellationToken;
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var issuerPublicKey = issuerPair.PublicKey;
        using var issuerPrivateKey = issuerPair.PrivateKey;

        var signedCredential = await SignBaseAsync(issuerPrivateKey, cancellationToken).ConfigureAwait(false);
        var derivedCredential = await DeriveAsync(signedCredential, cancellationToken).ConfigureAwait(false);
        var issuerDidDocument = CreateIssuerDidDocument(issuerPublicKey);

        var result = await derivedCredential.VerifyDerivedProofAsync(
            issuerDidDocument,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
            RdfcCanonicalizer,
            ContextResolver,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "The resolving overload must verify a genuinely issuer-signed derived proof.");
        Assert.IsNotNull(result.Verified);
        var verified = result.Verified!.Value;
        Assert.IsTrue(verified.IsIdentityBound, "The resolving overload must mint Bound, not Asserted.");
        Assert.IsTrue(verified.Provenance is BoundProvenance);
        var bound = (BoundProvenance)verified.Provenance!;
        Assert.AreEqual(ResolutionSource.CallerControllerArtifact, bound.Source);
        Assert.AreEqual(VerificationRelationship.AssertionMethod, bound.Relationship);
        Assert.AreEqual(SignerKeyId, bound.Identity?.Value);
    }


    /// <summary>On the derived-proof resolving overload: a resolved-method controller mismatch is refused.</summary>
    [TestMethod]
    public async Task DerivedProofIssuerControllerMismatchIsRefused()
    {
        var cancellationToken = TestContext.CancellationToken;
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var issuerPublicKey = issuerPair.PublicKey;
        using var issuerPrivateKey = issuerPair.PrivateKey;

        var signedCredential = await SignBaseAsync(issuerPrivateKey, cancellationToken).ConfigureAwait(false);
        var derivedCredential = await DeriveAsync(signedCredential, cancellationToken).ConfigureAwait(false);

        var mismatchedDidDocument = CreateIssuerDidDocument(issuerPublicKey, controller: "did:example:someone-else-entirely");

        var result = await derivedCredential.VerifyDerivedProofAsync(
            mismatchedDidDocument,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
            RdfcCanonicalizer,
            ContextResolver,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.ControllerMismatch, result.FailureReason);
        Assert.IsNull(result.Verified);
    }


    /// <summary>The BYOK derived-proof overload's behavior is unchanged: it mints Asserted, never Bound.</summary>
    [TestMethod]
    public async Task ByokDerivedProofOverloadStillMintsAssertedNotBound()
    {
        var cancellationToken = TestContext.CancellationToken;
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var issuerPublicKey = issuerPair.PublicKey;
        using var issuerPrivateKey = issuerPair.PrivateKey;

        var signedCredential = await SignBaseAsync(issuerPrivateKey, cancellationToken).ConfigureAwait(false);
        var derivedCredential = await DeriveAsync(signedCredential, cancellationToken).ConfigureAwait(false);

        var result = await derivedCredential.VerifyDerivedProofAsync(
            issuerPublicKey,
            BouncyCastleCryptographicFunctionsAdapter.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
            RdfcCanonicalizer,
            ContextResolver,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid);
        Assert.IsNotNull(result.Verified);
        Assert.IsFalse(result.Verified!.Value.IsIdentityBound, "The BYOK overload must mint Asserted, never Bound.");
        Assert.IsTrue(result.Verified.Value.Provenance is AssertedProvenance);
    }


    private static async Task<DataIntegritySecuredCredential> SignBaseAsync(PrivateKeyMemory issuerPrivateKey, CancellationToken cancellationToken)
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, TestSetup.DefaultSerializationOptions)!;
        var ephemeralPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var ephemeralPublicKey = ephemeralPair.PublicKey;
        using var ephemeralPrivateKey = ephemeralPair.PrivateKey;

        return await credential.CreateBaseProofAsync(
            issuerPrivateKey,
            ephemeralPair,
            SignerKeyId,
            ProofCreated,
            MandatoryPaths,
            () => RandomNumberGenerator.GetBytes(32),
            JsonLdSelection.PartitionStatements,
            RdfcCanonicalizer,
            ContextResolver,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.DeserializeCredential,
            CanonicalizationTestUtilities.SerializeProofOptions,
            EcdsaSd2023CborSerializer.SerializeBaseProof,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);
    }


    private static Task<DataIntegritySecuredCredential> DeriveAsync(DataIntegritySecuredCredential signedCredential, CancellationToken cancellationToken)
    {
        var verifierRequestedPaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/credentialSubject/degree/name")
        };

        return signedCredential.DeriveProofAsync(
            verifierRequestedPaths,
            userExclusions: null,
            JsonLdSelection.PartitionStatements,
            JsonLdSelection.SelectFragments,
            RdfcCanonicalizer,
            ContextResolver,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.DeserializeCredential,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            EcdsaSd2023CborSerializer.SerializeDerivedProof,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).AsTask();
    }


    private static ValueTask<CredentialVerificationResult<DataIntegritySecuredCredential>> VerifyBaseResolvingAsync(
        DataIntegritySecuredCredential credential,
        DidDocument issuerDidDocument,
        CancellationToken cancellationToken) =>
        credential.VerifyBaseProofAsync(
            issuerDidDocument,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            JsonLdSelection.PartitionStatements,
            RdfcCanonicalizer,
            ContextResolver,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken);


    //Controller-RESOLUTION semantics: the resolved method's own controller, which the caller
    //may point at any DID -- not necessarily documentDid -- so the mismatch tests can name a
    //controller distinct from both the credential's issuer and the resolved document's own id.
    private static DidDocument CreateIssuerDidDocument(
        PublicKeyMemory issuerPublicKey,
        string verificationMethodId = SignerKeyId,
        string documentDid = IssuerDid,
        string? controller = null)
    {
        string publicKeyMultibase = MultibaseSerializer.Encode(
            issuerPublicKey.AsReadOnlySpan(),
            MulticodecHeaders.P256PublicKey,
            MultibaseAlgorithms.Base58Btc,
            TestSetup.Base58Encoder,
            BaseMemoryPool.Shared);

        return new DidDocument
        {
            Id = new GenericDidMethod(documentDid),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = verificationMethodId,
                    Type = "Multikey",
                    Controller = controller ?? documentDid,
                    KeyFormat = new PublicKeyMultibase(publicKeyMultibase)
                }
            ],
            AssertionMethod = [new AssertionMethod(verificationMethodId)]
        };
    }
}
