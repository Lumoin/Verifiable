using System;
using System.Buffers;
using System.Linq;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="KeyDidResolver"/> covering every supported key type, the verification
/// relationships each key kind earns, the resolved document's <c>@context</c>, the
/// <c>invalidPublicKeyLength</c> / malformed-input negatives, the base64url multibase form, the
/// explicit-version segment, and the optional Ed25519 → X25519 key-agreement derivation.
/// </summary>
[TestClass]
internal sealed class KeyDidResolverTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly ExchangeContext EmptyContext = new();

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    //Encodes a public key into its did:key string (the same multibase the builder mints), so the resolver can
    //be driven from a freshly generated key of each supported type.
    private static string ToDidKey(PublicKeyMemory publicKey)
    {
        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();

        string multibase = CryptoFormatConversions.DefaultAlgorithmToBase58Converter(
            algorithm,
            purpose,
            publicKey.AsReadOnlySpan(),
            DefaultCoderSelector.SelectEncoder(typeof(PublicKeyMultibase)));

        return $"{KeyDidMethod.Prefix}{multibase}";
    }


    private static async Task<DidResolutionResult> ResolveAsync(string did, DidResolutionOptions? options = null)
    {
        DidMethodResolverDelegate resolver = KeyDidResolver.Build(
            Pool, BouncyCastleKeyAgreementFunctions.DeriveX25519PublicKeyFromEd25519);

        return await resolver(did, options ?? DidResolutionOptions.Empty, EmptyContext, default).ConfigureAwait(false);
    }


    [TestMethod]
    [DynamicData(nameof(SigningKeyNames))]
    public async Task SigningKeyResolvesToMultikeyVerificationMethodWithSigningRelationships(string algorithmName)
    {
        var keyPair = CreateSigningKeyMaterial(algorithmName);
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        string did = ToDidKey(publicKey);
        DidResolutionResult result = await ResolveAsync(did).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"{algorithmName}: did:key MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
        DidDocument document = result.Document!;
        Assert.AreEqual(did, document.Id?.ToString());

        VerificationMethod method = document.VerificationMethod![0];
        string multibase = did[KeyDidMethod.Prefix.Length..];
        Assert.AreEqual($"{did}#{multibase}", method.Id, $"{algorithmName}: the verification method fragment MUST be the multibase value.");
        Assert.AreEqual("Multikey", method.Type);
        Assert.AreEqual(did, method.Controller);
        Assert.IsInstanceOfType<PublicKeyMultibase>(method.KeyFormat);
        Assert.AreEqual(multibase, ((PublicKeyMultibase)method.KeyFormat!).Key);

        //A signing key earns authentication, assertionMethod, capabilityInvocation, and capabilityDelegation.
        Assert.IsTrue(ReferencesMethod(document.Authentication, method.Id!), $"{algorithmName}: authentication MUST reference the key.");
        Assert.IsTrue(ReferencesMethod(document.AssertionMethod, method.Id!), $"{algorithmName}: assertionMethod MUST reference the key.");
        Assert.IsTrue(ReferencesMethod(document.CapabilityInvocation, method.Id!), $"{algorithmName}: capabilityInvocation MUST reference the key.");
        Assert.IsTrue(ReferencesMethod(document.CapabilityDelegation, method.Id!), $"{algorithmName}: capabilityDelegation MUST reference the key.");

        //A signing key MUST NOT be placed under keyAgreement.
        Assert.IsTrue(document.KeyAgreement is null || document.KeyAgreement.Length == 0, $"{algorithmName}: a signing key MUST NOT earn keyAgreement.");

        AssertHasDidContext(document);
    }


    [TestMethod]
    public async Task X25519KeyResolvesToKeyAgreementOnly()
    {
        var keyPair = TestKeyMaterialProvider.CreateX25519KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        string did = ToDidKey(publicKey);
        DidResolutionResult result = await ResolveAsync(did).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"did:key MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
        DidDocument document = result.Document!;

        VerificationMethod method = document.VerificationMethod![0];
        Assert.AreEqual("Multikey", method.Type);

        //An X25519 key earns keyAgreement and MUST NOT earn the signing relationships.
        Assert.IsTrue(ReferencesMethod(document.KeyAgreement, method.Id!), "X25519 MUST earn keyAgreement.");
        Assert.IsTrue(document.Authentication is null || document.Authentication.Length == 0, "X25519 MUST NOT earn authentication.");
        Assert.IsTrue(document.AssertionMethod is null || document.AssertionMethod.Length == 0, "X25519 MUST NOT earn assertionMethod.");

        AssertHasDidContext(document);
    }


    [TestMethod]
    public async Task ResolvedDocumentCarriesDidV1AndMultikeyContext()
    {
        var keyPair = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        DidResolutionResult result = await ResolveAsync(ToDidKey(publicKey)).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        var contexts = result.Document!.Context!.Contexts!;
        Assert.AreEqual("https://www.w3.org/ns/did/v1", contexts[0], "The first @context MUST be the DID v1 context.");
        Assert.Contains("https://w3id.org/security/multikey/v1", contexts, "A Multikey VM MUST carry the multikey suite context.");
    }


    [TestMethod]
    public async Task ResolvedDocumentCarriesJsonLdContentType()
    {
        var keyPair = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        DidResolutionResult result = await ResolveAsync(ToDidKey(publicKey)).ConfigureAwait(false);

        Assert.AreEqual("application/did+ld+json", result.ResolutionMetadata.ContentType);
    }


    [TestMethod]
    public async Task Bls12381G2VectorResolvesToMultikey()
    {
        //A known BLS12-381 G2 did:key vector (zUC7...) from the did:key BLS test vectors.
        const string Did = "did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY";

        DidResolutionResult result = await ResolveAsync(Did).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A BLS12-381 G2 did:key MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
        VerificationMethod method = result.Document!.VerificationMethod![0];
        Assert.AreEqual("Multikey", method.Type);
        Assert.IsInstanceOfType<PublicKeyMultibase>(method.KeyFormat);
    }


    [TestMethod]
    public async Task Base64UrlFormIsRejectedAsInvalidDid()
    {
        var keyPair = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        //The base58 ('z') form resolves; the base64url ('u') form of the SAME multicodec-prefixed bytes is a
        //well-formed multibase value, yet the did:key Document Creation Algorithm requires the multibaseValue to
        //begin with the letter `z` ("If any of these requirements fail, an invalidDid error MUST be raised").
        string base58Did = ToDidKey(publicKey);

        using IMemoryOwner<byte> prefixed = MultibaseSerializer.PrependHeader(
            publicKey.AsReadOnlySpan(), MulticodecHeaders.Ed25519PublicKey, Pool);
        string base64UrlPayload = TestSetup.Base64UrlEncoder(prefixed.Memory.Span[..(MulticodecHeaders.Ed25519PublicKey.Length + 32)]);
        string base64UrlDid = $"{KeyDidMethod.Prefix}u{base64UrlPayload}";

        DidResolutionResult z = await ResolveAsync(base58Did).ConfigureAwait(false);
        DidResolutionResult u = await ResolveAsync(base64UrlDid).ConfigureAwait(false);

        Assert.IsTrue(z.IsSuccessful, $"The base58 'z' form MUST resolve. Error: {z.ResolutionMetadata.Error?.Type}.");

        //The resolution algorithm rejects a non-`z` multibase even when the underlying base64url payload is a
        //byte-identical, decodable encoding of the same key.
        Assert.IsFalse(u.IsSuccessful, "A base64url 'u'-form did:key MUST be rejected by the resolver.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, u.ResolutionMetadata.Error,
            "A non-`z` multibaseValue MUST surface as invalidDid per the Document Creation Algorithm.");
    }


    [TestMethod]
    public async Task ExplicitVersionOneResolves()
    {
        var keyPair = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        string multibase = ToDidKey(publicKey)[KeyDidMethod.Prefix.Length..];
        string versionedDid = $"{KeyDidMethod.Prefix}1:{multibase}";

        DidResolutionResult result = await ResolveAsync(versionedDid).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"An explicit version-1 did:key MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
    }


    [TestMethod]
    public async Task UnknownVersionIsInvalidDid()
    {
        var keyPair = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        string multibase = ToDidKey(publicKey)[KeyDidMethod.Prefix.Length..];
        string versionedDid = $"{KeyDidMethod.Prefix}2:{multibase}";

        DidResolutionResult result = await ResolveAsync(versionedDid).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task MalformedBase58IsInvalidDid()
    {
        //A 'z'-prefixed payload carrying base58-invalid characters ('0', 'O', 'I', 'l' are not in the alphabet).
        DidResolutionResult result = await ResolveAsync("did:key:z0OIl0OIl0OIl").ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task TooShortMultibaseIsInvalidDid()
    {
        //A 'z'-prefixed payload that decodes to fewer bytes than a multicodec header.
        DidResolutionResult result = await ResolveAsync("did:key:z2").ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    [DynamicData(nameof(WrongLengthBodyCases))]
    public async Task WrongLengthBodyIsInvalidDid(string keyTypeName, byte[] multicodecHeader, int wrongBodyLength)
    {
        //A recognized multicodec header followed by a deliberately WRONG-length body: the
        //invalidPublicKeyLength check MUST reject it rather than mint a malformed verification method. Driving
        //this per key type makes a corrupted per-type ExpectedRawLength entry (or the RSA 270/526 discriminator)
        //independently falsifiable — a too-loose length check for any single type would let its row through.
        using IMemoryOwner<byte> wrong = Pool.Rent(multicodecHeader.Length + wrongBodyLength);
        multicodecHeader.CopyTo(wrong.Memory.Span);
        wrong.Memory.Span[multicodecHeader.Length..(multicodecHeader.Length + wrongBodyLength)].Clear();

        string multibase = TestSetup.Base58Encoder(wrong.Memory.Span[..(multicodecHeader.Length + wrongBodyLength)]);
        string did = $"{KeyDidMethod.Prefix}z{multibase}";

        DidResolutionResult result = await ResolveAsync(did).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, $"{keyTypeName}: a wrong-length body MUST NOT resolve.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error,
            $"{keyTypeName}: a wrong-length body MUST surface as invalidDid (invalidPublicKeyLength).");
    }


    //Each row is a recognized did:key multicodec header paired with a body length one off the spec's expected
    //length for that key type (32 Ed25519, 33 P-256/secp256k1, 49 P-384, 67 P-521, 270 RSA-2048), so the
    //invalidPublicKeyLength rejection is exercised for every supported family rather than Ed25519 alone.
    public static System.Collections.Generic.IEnumerable<object[]> WrongLengthBodyCases =>
    [
        ["Ed25519", MulticodecHeaders.Ed25519PublicKey.ToArray(), 31],
        ["P-256", MulticodecHeaders.P256PublicKey.ToArray(), 32],
        ["P-384", MulticodecHeaders.P384PublicKey.ToArray(), 48],
        ["P-521", MulticodecHeaders.P521PublicKey.ToArray(), 66],
        ["secp256k1", MulticodecHeaders.Secp256k1PublicKey.ToArray(), 32],
        ["RSA", MulticodecHeaders.RsaPublicKey.ToArray(), 269]
    ];


    [TestMethod]
    public async Task EncryptionKeyDerivationAddsX25519KeyAgreement()
    {
        var keyPair = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        string did = ToDidKey(publicKey);
        DidResolutionOptions options = new() { EnableEncryptionKeyDerivation = true };

        DidResolutionResult result = await ResolveAsync(did, options).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"did:key MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
        DidDocument document = result.Document!;

        //The signature verification method plus a derived X25519 key agreement verification method.
        Assert.HasCount(2, document.VerificationMethod!, "Encryption key derivation MUST add a second verification method.");
        VerificationMethod keyAgreement = document.VerificationMethod![1];
        Assert.AreEqual("Multikey", keyAgreement.Type);
        Assert.AreEqual(did, keyAgreement.Controller);

        //The derived key's fragment is the X25519 multibase (#z6LS...).
        string keyAgreementId = keyAgreement.Id!;
        string fragment = keyAgreementId[(keyAgreementId.IndexOf('#', StringComparison.Ordinal) + 1)..];
        Assert.StartsWith("z6LS", fragment, "The derived keyAgreement fragment MUST be the X25519 multibase (z6LS prefix).");
        Assert.IsTrue(ReferencesMethod(document.KeyAgreement, keyAgreement.Id!), "The derived key MUST be listed under keyAgreement.");
    }


    [TestMethod]
    public async Task EncryptionKeyDerivationMatchesSpecKnownAnswerVector()
    {
        //The did:key Ed25519-with-X25519 example: resolving this Ed25519 did:key with encryption key
        //derivation MUST produce exactly this X25519 keyAgreement multibase (a birational-map known answer).
        const string Did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        const string ExpectedKeyAgreementMultibase = "z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p";

        DidResolutionOptions options = new() { EnableEncryptionKeyDerivation = true };
        DidResolutionResult result = await ResolveAsync(Did, options).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"The spec Ed25519 did:key MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
        VerificationMethod keyAgreement = result.Document!.VerificationMethod![1];
        Assert.AreEqual($"{Did}#{ExpectedKeyAgreementMultibase}", keyAgreement.Id,
            "The derived X25519 keyAgreement id MUST match the did:key specification's known-answer vector.");
        Assert.AreEqual(ExpectedKeyAgreementMultibase, ((PublicKeyMultibase)keyAgreement.KeyFormat!).Key);
    }


    [TestMethod]
    public async Task IdentityPointEd25519KeyDerivationIsInvalidDid()
    {
        //An Ed25519 public key whose decoded Edwards y-coordinate is the identity point (y == 1): little-endian
        //0x01 followed by 31 zero bytes, with the x-sign bit (MSB of the last byte) clear. The birational map
        //u = (1 + y) / (1 - y) divides by (1 - y), which is zero here; the backend MUST reject this rather than
        //fault out of ModInverse, and the resolver MUST surface it as invalidDid (a returned failure, NOT a
        //thrown exception) when encryption key derivation is requested.
        const int Ed25519RawLength = 32;
        using IMemoryOwner<byte> identityKey = Pool.Rent(MulticodecHeaders.Ed25519PublicKey.Length + Ed25519RawLength);
        Span<byte> prefixed = identityKey.Memory.Span[..(MulticodecHeaders.Ed25519PublicKey.Length + Ed25519RawLength)];
        prefixed.Clear();
        MulticodecHeaders.Ed25519PublicKey.CopyTo(prefixed);
        prefixed[MulticodecHeaders.Ed25519PublicKey.Length] = 0x01;

        string multibase = TestSetup.Base58Encoder(prefixed);
        string did = $"{KeyDidMethod.Prefix}z{multibase}";

        DidResolutionOptions options = new() { EnableEncryptionKeyDerivation = true };
        DidResolutionResult result = await ResolveAsync(did, options).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "An identity-point Ed25519 did:key MUST NOT resolve under key derivation.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error,
            "A degenerate identity-point Ed25519 key MUST map to invalidDid, not fault.");
    }


    [TestMethod]
    public async Task EncryptionKeyDerivationWithoutBackendIsFeatureNotSupported()
    {
        var keyPair = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        //No derivation delegate wired: requesting derivation surfaces FeatureNotSupported rather than failing
        //open with a document missing the requested keyAgreement.
        DidMethodResolverDelegate resolver = KeyDidResolver.Build(Pool);
        DidResolutionOptions options = new() { EnableEncryptionKeyDerivation = true };

        DidResolutionResult result = await resolver(ToDidKey(publicKey), options, EmptyContext, default).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.FeatureNotSupported, result.ResolutionMetadata.Error);
    }


    public static System.Collections.Generic.IEnumerable<object[]> SigningKeyNames =>
    [
        ["Ed25519"],
        ["P-256"],
        ["P-384"],
        ["P-521"],
        ["secp256k1"],
        ["RSA-2048"],
        ["RSA-4096"]
    ];


    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateSigningKeyMaterial(string algorithmName) => algorithmName switch
    {
        "Ed25519" => TestKeyMaterialProvider.CreateEd25519KeyMaterial(),
        "P-256" => TestKeyMaterialProvider.CreateP256KeyMaterial(),
        "P-384" => TestKeyMaterialProvider.CreateP384KeyMaterial(),
        "P-521" => TestKeyMaterialProvider.CreateP521KeyMaterial(),
        "secp256k1" => TestKeyMaterialProvider.CreateSecp256k1KeyMaterial(),
        "RSA-2048" => TestKeyMaterialProvider.CreateRsa2048KeyMaterial(),
        "RSA-4096" => TestKeyMaterialProvider.CreateRsa4096KeyMaterial(),
        _ => throw new ArgumentException($"Unknown algorithm '{algorithmName}'.", nameof(algorithmName))
    };


    private static bool ReferencesMethod(VerificationMethodReference[]? relationships, string methodId)
    {
        return relationships is not null && relationships.Any(r => string.Equals(r.Id, methodId, StringComparison.Ordinal));
    }


    private static void AssertHasDidContext(DidDocument document)
    {
        Assert.IsNotNull(document.Context?.Contexts, "A resolved did:key document MUST carry @context.");
        Assert.AreEqual("https://www.w3.org/ns/did/v1", document.Context!.Contexts![0], "The first @context MUST be the DID v1 context.");
    }
}
