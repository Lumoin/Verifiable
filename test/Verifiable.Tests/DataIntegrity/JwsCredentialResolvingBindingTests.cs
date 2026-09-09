using System.Buffers;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DataIntegrity;

/// <summary>
/// Tests for the RESOLVING <see cref="CredentialJwsExtensions.VerifyJwsAsync(string, DidResolver, ExchangeContext, DecodeDelegate, JwtHeaderDeserializer, CredentialFromJsonBytesDelegate, BaseMemoryPool, System.Threading.CancellationToken)"/>
/// overloads. Each implements the DIDComm Tier-A recipe adapted to a credential's own
/// signed <c>issuer</c> claim: <c>kid</c> extraction, kid-base-DID-equals-issuer addressing
/// consistency, in-method resolution via the injected <see cref="DidResolver"/>, and
/// <c>assertionMethod</c>-relationship-scoped lookup, ALL before the cryptographic check —
/// minting <see cref="Verified{T}.IsIdentityBound"/> <see langword="true"/> only when every gate
/// holds.
/// </summary>
[TestClass]
internal sealed class JwsCredentialResolvingBindingTests
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
        "id": "http://university.example/credentials/9821",
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
    /// Positive Bound mint (compact form): the resolving overload verifies a genuinely-signed
    /// credential, mints <see cref="ResolutionSource.MethodResolved"/> scoped to
    /// <see cref="VerificationRelationship.AssertionMethod"/>, and the witness tie refuses to
    /// mint the same <see cref="BoundProvenance"/> over a different credential instance.
    /// </summary>
    [TestMethod]
    public async Task ResolvingCompactFormMintsBoundOnGenuineSignature()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, CredentialSecuringMaterial.JsonOptions)!;
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        string jws = await SignCompactAsync(credential, privateKey, SignerKeyId).ConfigureAwait(false);
        DidResolver resolver = CreateResolver(CreateIssuerDidDocument());

        JwsCredentialVerificationResult result = await CredentialJwsExtensions.VerifyJwsAsync(
            jws,
            resolver,
            Context,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            CredentialDeserializer,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "The resolving overload must verify a genuinely-signed credential.");
        Assert.IsNotNull(result.Credential);
        var verified = result.Credential!.Value;
        Assert.IsTrue(verified.IsIdentityBound, "The resolving overload must mint Bound, not Asserted.");
        Assert.IsTrue(verified.Provenance is BoundProvenance);
        var bound = (BoundProvenance)verified.Provenance!;
        Assert.AreEqual(ResolutionSource.MethodResolved, bound.Source);
        Assert.AreEqual(VerificationRelationship.AssertionMethod, bound.Relationship);
        Assert.AreEqual(SignerKeyId, bound.Identity?.Value);

        //Witness tie: the SAME BoundProvenance refuses to mint over a DIFFERENT credential instance.
        var otherCredential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, CredentialSecuringMaterial.JsonOptions)!;
        Verified<VerifiableCredential>? witnessMismatch = Verified<VerifiableCredential>.TryCreateBound(otherCredential, bound);
        Assert.IsNull(witnessMismatch, "A BoundProvenance established for one credential instance must refuse to mint over a different instance.");
    }


    /// <summary>Positive Bound mint (<see cref="JwsMessage"/> POCO form).</summary>
    [TestMethod]
    public async Task ResolvingPocoFormMintsBoundOnGenuineSignature()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, CredentialSecuringMaterial.JsonOptions)!;
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        JwsMessage jwsMessage = await credential.SignJwsAsync(
            privateKey,
            SignerKeyId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        DidResolver resolver = CreateResolver(CreateIssuerDidDocument());

        JwsCredentialVerificationResult result = await CredentialJwsExtensions.VerifyJwsAsync(
            jwsMessage,
            resolver,
            Context,
            TestSetup.Base64UrlEncoder,
            CredentialDeserializer,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "The resolving POCO overload must verify a genuinely-signed credential.");
        Assert.IsNotNull(result.Credential);
        Assert.IsTrue(result.Credential!.Value.IsIdentityBound, "The resolving POCO overload must mint Bound, not Asserted.");
    }


    /// <summary>A protected header carrying no <c>kid</c> is refused before any resolution is attempted.</summary>
    [TestMethod]
    public async Task MissingKidIsRefused()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, CredentialSecuringMaterial.JsonOptions)!;
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        JwsMessage jwsMessage = await credential.SignJwsAsync(
            privateKey,
            SignerKeyId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Rebuild the compact JWS with the kid stripped from the (now-mismatching) header segment --
        //gate 1 must refuse before any resolver call, so the resulting invalid signature is irrelevant.
        var headerWithoutKid = new Dictionary<string, object>(jwsMessage.Signatures[0].ProtectedHeader);
        headerWithoutKid.Remove(WellKnownJwkMemberNames.Kid);
        string headerSegment = TestSetup.Base64UrlEncoder(HeaderSerializer(headerWithoutKid));
        string payloadSegment = TestSetup.Base64UrlEncoder(jwsMessage.Payload.Span);
        string signatureSegment = TestSetup.Base64UrlEncoder(jwsMessage.Signatures[0].Signature.AsReadOnlySpan());
        string forgedJws = $"{headerSegment}.{payloadSegment}.{signatureSegment}";

        DidResolver resolver = CreateResolver(CreateIssuerDidDocument());

        JwsCredentialVerificationResult result = await CredentialJwsExtensions.VerifyJwsAsync(
            forgedJws,
            resolver,
            Context,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            CredentialDeserializer,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A JWS with no kid must be refused.");
        Assert.IsNull(result.Credential);
    }


    /// <summary>
    /// The substitution the whole arc exists to refuse: a credential claims issuer A while the
    /// envelope is signed by a key whose kid names a DIFFERENT base DID (B) — even though B
    /// genuinely resolves and its assertionMethod key genuinely produced the signature.
    /// </summary>
    [TestMethod]
    public async Task IssuerKidBaseDidMismatchIsRefused()
    {
        const string otherSignerDid = "did:example:other-signer";
        const string otherSignerKeyId = "did:example:other-signer#key-1";

        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, CredentialSecuringMaterial.JsonOptions)!;
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        //Genuinely signed by "other-signer", but the credential still claims issuer "did:example:issuer".
        string jws = await SignCompactAsync(credential, privateKey, otherSignerKeyId).ConfigureAwait(false);

        //The resolver can genuinely resolve the signer's own DID -- proving the refusal is the
        //addressing-consistency gate, not merely an unresolvable DID.
        DidResolver resolver = CreateResolver(CreateIssuerDidDocument(otherSignerKeyId, did: otherSignerDid));

        JwsCredentialVerificationResult result = await CredentialJwsExtensions.VerifyJwsAsync(
            jws,
            resolver,
            Context,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            CredentialDeserializer,
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

        string jws = await SignCompactAsync(credential, privateKey, SignerKeyId).ConfigureAwait(false);

        DidResolver resolver = new(DidMethodSelectors.FromResolvers(
            (ExampleDidPrefix, (_, _, _, _) => ValueTask.FromResult(DidResolutionResult.Failure(DidResolutionErrors.NotFound)))));

        JwsCredentialVerificationResult result = await CredentialJwsExtensions.VerifyJwsAsync(
            jws,
            resolver,
            Context,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            CredentialDeserializer,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "An unresolvable signer DID must be refused.");
        Assert.IsNull(result.Credential);
    }


    /// <summary>
    /// The signing key exists in the resolved document's flat verification-method array but was
    /// never granted the <c>assertionMethod</c> relationship -- must be refused regardless of a
    /// cryptographically valid signature.
    /// </summary>
    [TestMethod]
    public async Task MethodNotUnderAssertionMethodIsRefused()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, CredentialSecuringMaterial.JsonOptions)!;
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        string jws = await SignCompactAsync(credential, privateKey, SignerKeyId).ConfigureAwait(false);

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
            //Deliberately no AssertionMethod array: the key exists but was never granted the relationship.
        };

        DidResolver resolver = CreateResolver(documentWithoutAssertionMethod);

        JwsCredentialVerificationResult result = await CredentialJwsExtensions.VerifyJwsAsync(
            jws,
            resolver,
            Context,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            CredentialDeserializer,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A method absent from assertionMethod must be refused even though the flat array carries it.");
        Assert.IsNull(result.Credential);
    }


    /// <summary>
    /// Every gate holds (kid, addressing consistency, resolution, relationship scoping) but the
    /// resolved document's key material is NOT the key that actually signed -- the cryptographic
    /// check itself must refuse.
    /// </summary>
    [TestMethod]
    public async Task ResolvedKeyMismatchIsRefused()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, CredentialSecuringMaterial.JsonOptions)!;
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        string jws = await SignCompactAsync(credential, privateKey, SignerKeyId).ConfigureAwait(false);

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

        JwsCredentialVerificationResult result = await CredentialJwsExtensions.VerifyJwsAsync(
            jws,
            resolver,
            Context,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            CredentialDeserializer,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A resolved method whose key material disagrees with the actual signer must be refused.");
        Assert.IsNull(result.Credential);
    }


    /// <summary>
    /// Rewriting the protected header's <c>alg</c> claim post-signing invalidates the JWS's own
    /// signed binding of header+payload, so the resolved-key algorithm the verify actually exercises
    /// is never influenced by the wire claim -- the defeated algorithm-substitution shape.
    /// </summary>
    [TestMethod]
    public async Task ForgedProtectedHeaderAlgorithmIsRefused()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, CredentialSecuringMaterial.JsonOptions)!;
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();

        JwsMessage jwsMessage = await credential.SignJwsAsync(
            privateKey,
            SignerKeyId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var forgedHeader = new Dictionary<string, object>(jwsMessage.Signatures[0].ProtectedHeader)
        {
            [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256
        };
        string headerSegment = TestSetup.Base64UrlEncoder(HeaderSerializer(forgedHeader));
        string payloadSegment = TestSetup.Base64UrlEncoder(jwsMessage.Payload.Span);
        string signatureSegment = TestSetup.Base64UrlEncoder(jwsMessage.Signatures[0].Signature.AsReadOnlySpan());
        string forgedJws = $"{headerSegment}.{payloadSegment}.{signatureSegment}";

        DidResolver resolver = CreateResolver(CreateIssuerDidDocument());

        JwsCredentialVerificationResult result = await CredentialJwsExtensions.VerifyJwsAsync(
            forgedJws,
            resolver,
            Context,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            CredentialDeserializer,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A forged protected-header alg claim must be refused.");
    }


    /// <summary>The BYOK overload's behavior is unchanged: it mints Asserted, never Bound.</summary>
    [TestMethod]
    public async Task ByokOverloadStillMintsAssertedNotBound()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, CredentialSecuringMaterial.JsonOptions)!;
        using var privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        using var publicKey = CredentialSecuringMaterial.DecodeEd25519PublicKey();

        string jws = await SignCompactAsync(credential, privateKey, SignerKeyId).ConfigureAwait(false);

        JwsCredentialVerificationResult result = await CredentialJwsExtensions.VerifyJwsAsync(
            jws,
            publicKey,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            CredentialDeserializer,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid);
        Assert.IsNotNull(result.Credential);
        Assert.IsFalse(result.Credential!.Value.IsIdentityBound, "The BYOK overload must mint Asserted, never Bound.");
        Assert.IsTrue(result.Credential.Value.Provenance is AssertedProvenance);
    }


    private static async Task<string> SignCompactAsync(VerifiableCredential credential, PrivateKeyMemory privateKey, string verificationMethodId)
    {
        JwsMessage jwsMessage = await credential.SignJwsAsync(
            privateKey,
            verificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared,
            cancellationToken: default).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);
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


    private static ReadOnlySpan<byte> CredentialSerializer(VerifiableCredential credential) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes(credential, CredentialSecuringMaterial.JsonOptions);

    private static ReadOnlySpan<byte> HeaderSerializer(Dictionary<string, object> header) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes(header, CredentialSecuringMaterial.JsonOptions);

    private static Dictionary<string, object>? HeaderDeserializer(ReadOnlySpan<byte> headerBytes) =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(headerBytes, CredentialSecuringMaterial.JsonOptions);

    private static VerifiableCredential CredentialDeserializer(ReadOnlySpan<byte> credentialBytes) =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(credentialBytes, CredentialSecuringMaterial.JsonOptions)!;
}
