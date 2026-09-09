using Verifiable.BouncyCastle;
using Verifiable.Cbor;
using Verifiable.Core;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.DataIntegrity;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cose;

/// <summary>
/// Tests for the RESOLVING <see cref="CredentialCoseExtensions.VerifyCoseAsync(CoseSign1Message, BuildSigStructureDelegate, DidResolver, ExchangeContext, CredentialFromJsonBytesDelegate, ParseProtectedHeaderDelegate, BaseMemoryPool, System.Threading.CancellationToken)"/>
/// overloads, the registry-flavored default and the "explicit-fn" variant that runs a
/// caller-supplied verification function against the RESOLVED key material. Both implement the
/// same DIDComm Tier-A recipe as the JWS resolving overloads, adapted to the COSE protected header.
/// </summary>
[TestClass]
internal sealed class CoseCredentialResolvingBindingTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string ExampleDidPrefix = "did:example";
    private const string IssuerDid = "did:example:issuer";
    private const string SignerKeyId = "did:example:issuer#key-1";

    private static ExchangeContext Context { get; } = new();

    private const string CredentialJson = /*lang=json,strict*/ """
    {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "http://university.example/credentials/9822",
        "type": ["VerifiableCredential", "ExampleDegreeCredential"],
        "issuer": "did:example:issuer",
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
    /// Positive Bound mint via the registry-flavored resolving overload, plus the witness-tie
    /// half: the same <see cref="BoundProvenance"/> refuses to mint over a different credential
    /// instance.
    /// </summary>
    [TestMethod]
    public async Task ResolvingDefaultOverloadMintsBoundOnGenuineSignature()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, CredentialSecuringMaterial.JsonOptions)!;
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        CoseSign1Message message = await SignAsync(credential, privateKey, SignerKeyId).ConfigureAwait(false);
        DidResolver resolver = CreateResolver(CreateIssuerDidDocument());

        CoseCredentialVerificationResult result = await CredentialCoseExtensions.VerifyCoseAsync(
            message,
            CoseSerialization.BuildSigStructure,
            resolver,
            Context,
            CredentialFromJsonBytes,
            CoseSerialization.ParseProtectedHeader,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "The resolving overload must verify a genuinely-signed credential.");
        Assert.IsNotNull(result.Credential);
        var verified = result.Credential!.Value;
        Assert.IsTrue(verified.IsIdentityBound, "The resolving overload must mint Bound, not Asserted.");
        var bound = (BoundProvenance)verified.Provenance!;
        Assert.AreEqual(ResolutionSource.MethodResolved, bound.Source);
        Assert.AreEqual(VerificationRelationship.AssertionMethod, bound.Relationship);
        Assert.AreEqual(SignerKeyId, bound.Identity?.Value);

        var otherCredential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, CredentialSecuringMaterial.JsonOptions)!;
        Verified<VerifiableCredential>? witnessMismatch = Verified<VerifiableCredential>.TryCreateBound(otherCredential, bound);
        Assert.IsNull(witnessMismatch, "A BoundProvenance established for one credential instance must refuse to mint over a different instance.");
    }


    /// <summary>Positive Bound mint via the "explicit-fn" resolving overload.</summary>
    [TestMethod]
    public async Task ResolvingExplicitFnOverloadMintsBoundOnGenuineSignature()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, CredentialSecuringMaterial.JsonOptions)!;
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        CoseSign1Message message = await SignAsync(credential, privateKey, SignerKeyId).ConfigureAwait(false);
        DidResolver resolver = CreateResolver(CreateIssuerDidDocument());

        VerificationFunction<byte, byte, Signature, ValueTask<bool>> verify = (keyBytes, data, signature) =>
        {
            CryptoAlgorithm algorithm = CryptoAlgorithm.Ed25519;
            Purpose purpose = Purpose.Verification;
            VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

            return VerifyAsync();

            async ValueTask<bool> VerifyAsync()
            {
                (bool isValid, CryptoEvent? evt) = await verificationDelegate(data, signature.AsReadOnlyMemory(), keyBytes, context: null, cancellationToken: default).ConfigureAwait(false);
                CryptographicKeyEvents.Emit(evt);

                return isValid;
            }
        };

        CoseCredentialVerificationResult result = await CredentialCoseExtensions.VerifyCoseAsync(
            message,
            CoseSerialization.BuildSigStructure,
            resolver,
            Context,
            verify,
            CredentialFromJsonBytes,
            CoseSerialization.ParseProtectedHeader,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "The explicit-fn resolving overload must verify a genuinely-signed credential.");
        Assert.IsNotNull(result.Credential);
        Assert.IsTrue(result.Credential!.Value.IsIdentityBound, "The explicit-fn resolving overload must mint Bound, not Asserted.");
    }


    /// <summary>A protected header carrying no <c>kid</c> is refused before any resolution is attempted.</summary>
    [TestMethod]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of protectedHeaderCarrier transfers into the returned CoseSign1Message, mirroring CredentialCoseExtensions.SignCoseAsync's own suppression.")]
    public async Task MissingKidIsRefused()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, CredentialSecuringMaterial.JsonOptions)!;
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        //A protected header with no kid at all -- signed genuinely under that (kid-less) header.
        var protectedHeader = new Dictionary<int, object>
        {
            [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.EdDsa,
            [CoseHeaderParameters.ContentType] = WellKnownMediaTypes.Application.ApplicationVc,
            [CoseHeaderParameters.Typ] = WellKnownMediaTypes.Application.VcCose
        };

        ReadOnlySpan<byte> protectedHeaderSerialized = CoseSerialization.SerializeProtectedHeader(protectedHeader);
        var protectedHeaderOwner = BaseMemoryPool.Shared.Rent(protectedHeaderSerialized.Length);
        protectedHeaderSerialized.CopyTo(protectedHeaderOwner.Memory.Span);
        var protectedHeaderCarrier = new EncodedCoseProtectedHeader(protectedHeaderOwner, CryptoTags.CoseEncodedProtectedHeader);

        byte[] payloadBytes = CredentialToCborBytes(credential).ToArray();

        CoseSign1Message message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeaderCarrier,
            unprotectedHeader: null,
            payloadBytes,
            CoseSerialization.BuildSigStructure,
            privateKey,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        DidResolver resolver = CreateResolver(CreateIssuerDidDocument());

        CoseCredentialVerificationResult result = await CredentialCoseExtensions.VerifyCoseAsync(
            message,
            CoseSerialization.BuildSigStructure,
            resolver,
            Context,
            CredentialFromJsonBytes,
            CoseSerialization.ParseProtectedHeader,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A COSE_Sign1 message with no kid must be refused.");
        Assert.IsNull(result.Credential);
    }


    /// <summary>
    /// The substitution the whole arc exists to refuse: a credential claims issuer A while the
    /// envelope is signed by a key whose kid names a DIFFERENT, genuinely-resolvable base DID (B).
    /// </summary>
    [TestMethod]
    public async Task IssuerKidBaseDidMismatchIsRefused()
    {
        const string otherSignerDid = "did:example:other-signer";
        const string otherSignerKeyId = "did:example:other-signer#key-1";

        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, CredentialSecuringMaterial.JsonOptions)!;
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        CoseSign1Message message = await SignAsync(credential, privateKey, otherSignerKeyId).ConfigureAwait(false);
        DidResolver resolver = CreateResolver(CreateIssuerDidDocument(otherSignerKeyId, did: otherSignerDid));

        CoseCredentialVerificationResult result = await CredentialCoseExtensions.VerifyCoseAsync(
            message,
            CoseSerialization.BuildSigStructure,
            resolver,
            Context,
            CredentialFromJsonBytes,
            CoseSerialization.ParseProtectedHeader,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A kid whose base DID disagrees with the signed issuer claim must be refused.");
        Assert.IsNull(result.Credential);
    }


    /// <summary>A kid whose base DID matches the issuer but whose DID resolution fails is refused.</summary>
    [TestMethod]
    public async Task UnresolvableDidIsRefused()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, CredentialSecuringMaterial.JsonOptions)!;
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        CoseSign1Message message = await SignAsync(credential, privateKey, SignerKeyId).ConfigureAwait(false);

        DidResolver resolver = new(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Failure(DidResolutionErrors.NotFound)))));

        CoseCredentialVerificationResult result = await CredentialCoseExtensions.VerifyCoseAsync(
            message,
            CoseSerialization.BuildSigStructure,
            resolver,
            Context,
            CredentialFromJsonBytes,
            CoseSerialization.ParseProtectedHeader,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "An unresolvable signer DID must be refused.");
        Assert.IsNull(result.Credential);
    }


    /// <summary>
    /// The signing key exists in the resolved document's flat verification-method array but was
    /// never granted the <c>assertionMethod</c> relationship.
    /// </summary>
    [TestMethod]
    public async Task MethodNotUnderAssertionMethodIsRefused()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, CredentialSecuringMaterial.JsonOptions)!;
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        CoseSign1Message message = await SignAsync(credential, privateKey, SignerKeyId).ConfigureAwait(false);

        var documentWithoutAssertionMethod = new DidDocument
        {
            Id = new GenericDidMethod(IssuerDid),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = SignerKeyId,
                    Type = "Multikey",
                    Controller = IssuerDid,
                    KeyFormat = new PublicKeyMultibase(CredentialSecuringMaterial.Ed25519PublicKeyMultibase)
                }
            ]
        };

        DidResolver resolver = CreateResolver(documentWithoutAssertionMethod);

        CoseCredentialVerificationResult result = await CredentialCoseExtensions.VerifyCoseAsync(
            message,
            CoseSerialization.BuildSigStructure,
            resolver,
            Context,
            CredentialFromJsonBytes,
            CoseSerialization.ParseProtectedHeader,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A method absent from assertionMethod must be refused even though the flat array carries it.");
        Assert.IsNull(result.Credential);
    }


    /// <summary>
    /// Every gate holds but the resolved document's key material is NOT the key that actually
    /// signed -- the cryptographic check itself must refuse.
    /// </summary>
    [TestMethod]
    public async Task ResolvedKeyMismatchIsRefused()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, CredentialSecuringMaterial.JsonOptions)!;
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        CoseSign1Message message = await SignAsync(credential, privateKey, SignerKeyId).ConfigureAwait(false);

        var wrongKeyPair = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
        using var wrongPublicKey = wrongKeyPair.PublicKey;
        using var wrongPrivateKey = wrongKeyPair.PrivateKey;
        string wrongPublicKeyMultibase = MultibaseSerializer.Encode(
            wrongPublicKey.AsReadOnlySpan(),
            MulticodecHeaders.Ed25519PublicKey,
            MultibaseAlgorithms.Base58Btc,
            TestSetup.Base58Encoder,
            BaseMemoryPool.Shared);

        DidResolver resolver = CreateResolver(CreateIssuerDidDocument(publicKeyMultibase: wrongPublicKeyMultibase));

        CoseCredentialVerificationResult result = await CredentialCoseExtensions.VerifyCoseAsync(
            message,
            CoseSerialization.BuildSigStructure,
            resolver,
            Context,
            CredentialFromJsonBytes,
            CoseSerialization.ParseProtectedHeader,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A resolved method whose key material disagrees with the actual signer must be refused.");
        Assert.IsNull(result.Credential);
    }


    /// <summary>The BYOK overload's behavior is unchanged: it mints Asserted, never Bound.</summary>
    [TestMethod]
    public async Task ByokOverloadStillMintsAssertedNotBound()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, CredentialSecuringMaterial.JsonOptions)!;
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        using var publicKey = CredentialSecuringMaterial.DecodeEd25519PublicKey();

        CoseSign1Message message = await SignAsync(credential, privateKey, SignerKeyId).ConfigureAwait(false);

        CoseCredentialVerificationResult result = await CredentialCoseExtensions.VerifyCoseAsync(
            message,
            CoseSerialization.BuildSigStructure,
            publicKey,
            CredentialFromJsonBytes,
            CoseSerialization.ParseProtectedHeader,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid);
        Assert.IsNotNull(result.Credential);
        Assert.IsFalse(result.Credential!.Value.IsIdentityBound, "The BYOK overload must mint Asserted, never Bound.");
        Assert.IsTrue(result.Credential.Value.Provenance is AssertedProvenance);
    }


    private async Task<CoseSign1Message> SignAsync(VerifiableCredential credential, PrivateKeyMemory privateKey, string verificationMethodId)
    {
        return await credential.SignCoseAsync(
            privateKey,
            verificationMethodId,
            CredentialToCborBytes,
            CoseProtectedHeaderToCborBytes,
            CoseSerialization.BuildSigStructure,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static DidDocument CreateIssuerDidDocument(string keyId = SignerKeyId, string? publicKeyMultibase = null, string did = IssuerDid)
    {
        return new DidDocument
        {
            Id = new GenericDidMethod(did),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = keyId,
                    Type = "Multikey",
                    Controller = did,
                    KeyFormat = new PublicKeyMultibase(publicKeyMultibase ?? CredentialSecuringMaterial.Ed25519PublicKeyMultibase)
                }
            ],
            AssertionMethod = [new AssertionMethod(keyId)]
        };
    }


    private static DidResolver CreateResolver(DidDocument document)
    {
        return new DidResolver(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Success(document, new DidDocumentMetadata())))));
    }


    private static ReadOnlySpan<byte> CredentialToCborBytes(VerifiableCredential credential) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes(credential, CredentialSecuringMaterial.JsonOptions);

    private static ReadOnlySpan<byte> CoseProtectedHeaderToCborBytes(IReadOnlyDictionary<int, object> header) =>
        CoseSerialization.SerializeProtectedHeader(header);

    private static VerifiableCredential CredentialFromJsonBytes(ReadOnlySpan<byte> bytes) =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(bytes, CredentialSecuringMaterial.JsonOptions)!;
}
