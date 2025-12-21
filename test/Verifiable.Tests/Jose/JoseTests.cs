using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Jose;
using Verifiable.Json.Converters;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests for JOSE operations using both registry-based and explicit function APIs.
/// </summary>
[TestClass]
public sealed class JoseTests
{
    /// <summary>
    /// Test context for accessing test information and cancellation token.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// JSON serializer options with dictionary converter.
    /// </summary>
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        Converters = { new DictionaryStringObjectJsonConverter() }
    };


    /// <summary>
    /// Encodes a JWT part (dictionary) to UTF-8 JSON bytes.
    /// </summary>
    private static ReadOnlySpan<byte> EncodeJwtPart(Dictionary<string, object> part)
    {
        return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(part));
    }


    /// <summary>
    /// Decodes UTF-8 JSON bytes to a dictionary.
    /// </summary>
    private static Dictionary<string, object> DecodeJwtPart(ReadOnlySpan<byte> bytes)
    {
        string json = Encoding.UTF8.GetString(bytes);
        return JsonSerializer.Deserialize<Dictionary<string, object>>(json, JsonOptions)!;
    }


    [TestMethod]
    public async Task SignAndVerifyWithExplicitFunctionSucceeds()
    {
        var header = new Dictionary<string, object> { [JwkProperties.Alg] = WellKnownJwaValues.Es256, [JwkProperties.Typ] = "JWT" };
        var payload = new Dictionary<string, object> { [JwkProperties.Sub] = "1234567890", ["name"] = "Test User" };

        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: true);

        using PrivateKeyMemory privateKey = CreatePrivateKeyMemory(parameters.D!, Tag.P256PrivateKey);
        using PublicKeyMemory publicKey = CreatePublicKeyMemory(ecdsa.ExportSubjectPublicKeyInfo(), Tag.P256PublicKey);

        string jws = await Jws.SignAsync(
            header,
            payload,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            P256SigningFunction,
            SensitiveMemoryPool<byte>.Shared);

        Assert.IsNotNull(jws);
        string[] parts = jws.Split('.');
        Assert.HasCount(3, parts);

        bool isValid = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            SensitiveMemoryPool<byte>.Shared,
            publicKey,
            P256VerificationFunction);

        Assert.IsTrue(isValid, "Signature verification should succeed.");
    }


    [TestMethod]
    public async Task SignAndVerifyWithResolverBinderSucceeds()
    {
        var header = new Dictionary<string, object> { [JwkProperties.Alg] = WellKnownJwaValues.Es256, [JwkProperties.Typ] = "JWT" };
        var payload = new Dictionary<string, object> { [JwkProperties.Sub] = "resolver-test", ["name"] = "Resolver Test" };

        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: true);

        var resolverState = new TestResolverState(parameters.D!, ecdsa.ExportSubjectPublicKeyInfo());

        string jws = await Jws.SignAsync<Dictionary<string, object>, TestResolverState, int>(
            header,
            payload,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            resolverState,
            ResolvePrivateKeyMaterial,
            0,
            BindPrivateKey,
            TestContext.CancellationToken);

        Assert.IsNotNull(jws);
        string[] parts = jws.Split('.');
        Assert.HasCount(3, parts);

        bool isValid = await Jws.VerifyAsync<Dictionary<string, object>, TestResolverState, int>(
            jws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            SensitiveMemoryPool<byte>.Shared,
            resolverState,
            ResolvePublicKeyMaterial,
            0,
            BindPublicKey,
            TestContext.CancellationToken);

        Assert.IsTrue(isValid, "Signature verification with resolver/binder should succeed.");
    }


    [TestMethod]
    public async Task SignAndVerifyWithP384ExplicitFunctionSucceeds()
    {
        var header = new Dictionary<string, object> { [JwkProperties.Alg] = WellKnownJwaValues.Es384, [JwkProperties.Typ] = "JWT" };
        var payload = new Dictionary<string, object> { [JwkProperties.Sub] = "user-384", [JwkProperties.Iat] = 1234567890 };

        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: true);

        using PrivateKeyMemory privateKey = CreatePrivateKeyMemory(parameters.D!, Tag.P384PrivateKey);
        using PublicKeyMemory publicKey = CreatePublicKeyMemory(ecdsa.ExportSubjectPublicKeyInfo(), Tag.P384PublicKey);

        string jws = await Jws.SignAsync(
            header,
            payload,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            P384SigningFunction,
            SensitiveMemoryPool<byte>.Shared);

        bool isValid = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            SensitiveMemoryPool<byte>.Shared,
            publicKey,
            P384VerificationFunction);

        Assert.IsTrue(isValid, "P-384 signature verification should succeed.");
    }


    [TestMethod]
    public async Task SignAndVerifyWithP521ExplicitFunctionSucceeds()
    {
        var header = new Dictionary<string, object> { [JwkProperties.Alg] = WellKnownJwaValues.Es512, [JwkProperties.Typ] = "JWT" };
        var payload = new Dictionary<string, object> { [JwkProperties.Sub] = "user-521", [JwkProperties.Exp] = 9999999999 };

        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: true);

        using PrivateKeyMemory privateKey = CreatePrivateKeyMemory(parameters.D!, Tag.P521PrivateKey);
        using PublicKeyMemory publicKey = CreatePublicKeyMemory(ecdsa.ExportSubjectPublicKeyInfo(), Tag.P521PublicKey);

        string jws = await Jws.SignAsync(
            header,
            payload,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            P521SigningFunction,
            SensitiveMemoryPool<byte>.Shared);

        bool isValid = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            SensitiveMemoryPool<byte>.Shared,
            publicKey,
            P521VerificationFunction);

        Assert.IsTrue(isValid, "P-521 signature verification should succeed.");
    }


    [TestMethod]
    public async Task VerifyWithWrongKeyFails()
    {
        var header = new Dictionary<string, object> { [JwkProperties.Alg] = WellKnownJwaValues.Es256, [JwkProperties.Typ] = "JWT" };
        var payload = new Dictionary<string, object> { [JwkProperties.Sub] = "test" };

        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        ECParameters signingParameters = signingKey.ExportParameters(includePrivateParameters: true);
        using PrivateKeyMemory privateKey = CreatePrivateKeyMemory(signingParameters.D!, Tag.P256PrivateKey);
        using PublicKeyMemory wrongPublicKey = CreatePublicKeyMemory(wrongKey.ExportSubjectPublicKeyInfo(), Tag.P256PublicKey);

        string jws = await Jws.SignAsync(
            header,
            payload,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            P256SigningFunction,
            SensitiveMemoryPool<byte>.Shared);

        bool isValid = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            SensitiveMemoryPool<byte>.Shared,
            wrongPublicKey,
            P256VerificationFunction);

        Assert.IsFalse(isValid, "Verification with wrong key should fail.");
    }


    [TestMethod]
    public async Task VerifyAndDecodeWithResolverBinderReturnsHeaderAndPayload()
    {
        var header = new Dictionary<string, object> { [JwkProperties.Alg] = WellKnownJwaValues.Es256, [JwkProperties.Typ] = "JWT" };
        var payload = new Dictionary<string, object> { [JwkProperties.Sub] = "decode-test", ["custom"] = "value" };

        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: true);

        using PrivateKeyMemory privateKey = CreatePrivateKeyMemory(parameters.D!, Tag.P256PrivateKey);
        var resolverState = new TestResolverState(parameters.D!, ecdsa.ExportSubjectPublicKeyInfo());

        string jws = await Jws.SignAsync(
            header,
            payload,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            P256SigningFunction,
            SensitiveMemoryPool<byte>.Shared);

        JwsVerificationResult<Dictionary<string, object>> result = await Jws.VerifyAndDecodeAsync<Dictionary<string, object>, TestResolverState, int>(
            jws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            SensitiveMemoryPool<byte>.Shared,
            resolverState,
            ResolvePublicKeyMaterial,
            0,
            BindPublicKey,
            TestContext.CancellationToken);

        Assert.IsTrue(result.IsValid, "Signature should be valid.");
        Assert.AreEqual(WellKnownJwaValues.Es256, result.Header[JwkProperties.Alg]?.ToString());
        Assert.AreEqual("decode-test", result.Payload[JwkProperties.Sub]?.ToString());
        Assert.AreEqual("value", result.Payload["custom"]?.ToString());
    }


    [TestMethod]
    public async Task ResolverReturningNullThrowsInvalidOperationException()
    {
        var header = new Dictionary<string, object> { [JwkProperties.Alg] = WellKnownJwaValues.Es256, [JwkProperties.Typ] = "JWT" };
        var payload = new Dictionary<string, object> { [JwkProperties.Sub] = "null-test" };
        CancellationToken cancellationToken = TestContext.CancellationToken;

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await Jws.SignAsync<Dictionary<string, object>, int, int>(
                header,
                payload,
                EncodeJwtPart,
                TestSetup.Base64UrlEncoder,
                SensitiveMemoryPool<byte>.Shared,
                0,
                (context, pool, state, ct) => ValueTask.FromResult<PrivateKeyMemory?>(null),
                0,
                (material, state, ct) => throw new InvalidOperationException("Binder should not be called."),
                cancellationToken);
        });
    }


    [TestMethod]
    public void CryptoFormatConversionsMapsEs256Correctly()
    {
        Tag signingTag = CryptoFormatConversions.GetSigningTag(WellKnownJwaValues.Es256);
        Tag verificationTag = CryptoFormatConversions.GetVerificationTag(WellKnownJwaValues.Es256);

        Assert.AreEqual(CryptoAlgorithm.P256, signingTag.Get<CryptoAlgorithm>());
        Assert.AreEqual(Purpose.Signing, signingTag.Get<Purpose>());

        Assert.AreEqual(CryptoAlgorithm.P256, verificationTag.Get<CryptoAlgorithm>());
        Assert.AreEqual(Purpose.Verification, verificationTag.Get<Purpose>());
    }


    [TestMethod]
    public void CryptoFormatConversionsThrowsForUnsupportedAlgorithm()
    {
        Assert.Throws<NotSupportedException>(() => CryptoFormatConversions.GetSigningTag("UNSUPPORTED"));
    }


    /// <summary>
    /// State for test resolvers containing key material.
    /// </summary>
    private sealed record TestResolverState(byte[] PrivateKeyBytes, byte[] PublicKeyBytes);


    /// <summary>
    /// Test resolver that returns private key material from state.
    /// </summary>
    private static ValueTask<PrivateKeyMemory?> ResolvePrivateKeyMaterial(
        JoseKeyContext<Dictionary<string, object>> context,
        MemoryPool<byte> pool,
        TestResolverState state,
        CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> memoryOwner = pool.Rent(state.PrivateKeyBytes.Length);
        state.PrivateKeyBytes.CopyTo(memoryOwner.Memory.Span);
        return ValueTask.FromResult<PrivateKeyMemory?>(new PrivateKeyMemory(memoryOwner, Tag.P256PrivateKey));
    }


    /// <summary>
    /// Test resolver that returns public key material from state.
    /// </summary>
    private static ValueTask<PublicKeyMemory?> ResolvePublicKeyMaterial(
        JoseKeyContext<Dictionary<string, object>> context,
        MemoryPool<byte> pool,
        TestResolverState state,
        CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> memoryOwner = pool.Rent(state.PublicKeyBytes.Length);
        state.PublicKeyBytes.CopyTo(memoryOwner.Memory.Span);
        return ValueTask.FromResult<PublicKeyMemory?>(new PublicKeyMemory(memoryOwner, Tag.P256PublicKey));
    }


    /// <summary>
    /// Test binder that binds signing function to private key material.
    /// </summary>
    private static ValueTask<PrivateKey> BindPrivateKey(
        PrivateKeyMemory material,
        int state,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(new PrivateKey(material, "test-key", P256SigningFunction));
    }


    /// <summary>
    /// Test binder that binds verification function to public key material.
    /// </summary>
    private static ValueTask<PublicKey> BindPublicKey(
        PublicKeyMemory material,
        int state,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(new PublicKey(material, "test-key", P256VerificationFunctionWithSignature));
    }


    /// <summary>
    /// Creates a <see cref="PrivateKeyMemory"/> from raw key bytes.
    /// </summary>
    private static PrivateKeyMemory CreatePrivateKeyMemory(byte[] keyBytes, Tag tag)
    {
        IMemoryOwner<byte> memoryOwner = SensitiveMemoryPool<byte>.Shared.Rent(keyBytes.Length);
        keyBytes.CopyTo(memoryOwner.Memory.Span);
        return new PrivateKeyMemory(memoryOwner, tag);
    }


    /// <summary>
    /// Creates a <see cref="PublicKeyMemory"/> from raw key bytes.
    /// </summary>
    private static PublicKeyMemory CreatePublicKeyMemory(byte[] keyBytes, Tag tag)
    {
        IMemoryOwner<byte> memoryOwner = SensitiveMemoryPool<byte>.Shared.Rent(keyBytes.Length);
        keyBytes.CopyTo(memoryOwner.Memory.Span);
        return new PublicKeyMemory(memoryOwner, tag);
    }


    /// <summary>
    /// P-256 signing function for explicit function pattern.
    /// </summary>
    private static ValueTask<Signature> P256SigningFunction(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool)
    {
        return EcdsaSigningFunction(privateKeyBytes, dataToSign, signaturePool, ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256, Tag.P256Signature);
    }


    /// <summary>
    /// P-384 signing function for explicit function pattern.
    /// </summary>
    private static ValueTask<Signature> P384SigningFunction(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool)
    {
        return EcdsaSigningFunction(privateKeyBytes, dataToSign, signaturePool, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384, Tag.P384Signature);
    }


    /// <summary>
    /// P-521 signing function for explicit function pattern.
    /// </summary>
    private static ValueTask<Signature> P521SigningFunction(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool)
    {
        return EcdsaSigningFunction(privateKeyBytes, dataToSign, signaturePool, ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512, Tag.P521Signature);
    }


    /// <summary>
    /// Generic ECDSA signing function.
    /// </summary>
    private static ValueTask<Signature> EcdsaSigningFunction(
        ReadOnlyMemory<byte> privateKeyBytes,
        ReadOnlyMemory<byte> dataToSign,
        MemoryPool<byte> signaturePool,
        ECCurve curve,
        HashAlgorithmName hashAlgorithm,
        Tag signatureTag)
    {
        using ECDsa ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = curve,
            D = privateKeyBytes.ToArray()
        });

        byte[] signatureBytes = ecdsa.SignData(dataToSign.Span, hashAlgorithm);

        IMemoryOwner<byte> memoryOwner = signaturePool.Rent(signatureBytes.Length);
        signatureBytes.CopyTo(memoryOwner.Memory.Span);

        return ValueTask.FromResult(new Signature(memoryOwner, signatureTag));
    }


    /// <summary>
    /// P-256 verification function for explicit function pattern.
    /// </summary>
    private static bool P256VerificationFunction(ReadOnlyMemory<byte> publicKeyBytes, ReadOnlySpan<byte> dataToVerify, ReadOnlyMemory<byte> signatureBytes)
    {
        return EcdsaVerificationFunction(publicKeyBytes, dataToVerify, signatureBytes, HashAlgorithmName.SHA256);
    }


    /// <summary>
    /// P-256 verification function for bound key pattern.
    /// </summary>
    private static ValueTask<bool> P256VerificationFunctionWithSignature(ReadOnlyMemory<byte> publicKeyBytes, ReadOnlyMemory<byte> dataToVerify, Signature signature)
    {
        bool result = EcdsaVerificationFunction(publicKeyBytes, dataToVerify.Span, signature.AsReadOnlyMemory(), HashAlgorithmName.SHA256);
        return ValueTask.FromResult(result);
    }


    /// <summary>
    /// P-384 verification function for explicit function pattern.
    /// </summary>
    private static bool P384VerificationFunction(ReadOnlyMemory<byte> publicKeyBytes, ReadOnlySpan<byte> dataToVerify, ReadOnlyMemory<byte> signatureBytes)
    {
        return EcdsaVerificationFunction(publicKeyBytes, dataToVerify, signatureBytes, HashAlgorithmName.SHA384);
    }


    /// <summary>
    /// P-521 verification function for explicit function pattern.
    /// </summary>
    private static bool P521VerificationFunction(ReadOnlyMemory<byte> publicKeyBytes, ReadOnlySpan<byte> dataToVerify, ReadOnlyMemory<byte> signatureBytes)
    {
        return EcdsaVerificationFunction(publicKeyBytes, dataToVerify, signatureBytes, HashAlgorithmName.SHA512);
    }


    /// <summary>
    /// Generic ECDSA verification function.
    /// </summary>
    private static bool EcdsaVerificationFunction(ReadOnlyMemory<byte> publicKeyBytes, ReadOnlySpan<byte> dataToVerify, ReadOnlyMemory<byte> signatureBytes, HashAlgorithmName hashAlgorithm)
    {
        using ECDsa ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(publicKeyBytes.Span, out _);
        return ecdsa.VerifyData(dataToVerify, signatureBytes.Span, hashAlgorithm);
    }
}