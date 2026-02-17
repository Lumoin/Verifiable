using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Jose;
using Verifiable.Json.Converters;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests for JOSE operations using both registry-based and explicit function APIs.
/// </summary>
[TestClass]
internal sealed class JoseTests
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


    [TestMethod]
    public async Task SignAndVerifyWithExplicitFunctionSucceeds()
    {
        var header = new Dictionary<string, object> { [JwkProperties.Alg] = WellKnownJwaValues.Es256, [JwkProperties.Typ] = "JWT" };
        var payload = new Dictionary<string, object> { [JwkProperties.Sub] = "1234567890", ["name"] = "Test User" };

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            SensitiveMemoryPool<byte>.Shared).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        Assert.IsNotNull(jws);
        string[] parts = jws.Split('.');
        Assert.HasCount(3, parts);

        bool isValid = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            SensitiveMemoryPool<byte>.Shared,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async).ConfigureAwait(false);

        Assert.IsTrue(isValid, "Signature verification should succeed.");
    }


    [TestMethod]
    public async Task SignAndVerifyWithResolverBinderSucceeds()
    {
        var header = new Dictionary<string, object> { [JwkProperties.Alg] = WellKnownJwaValues.Es256, [JwkProperties.Typ] = "JWT" };
        var payload = new Dictionary<string, object> { [JwkProperties.Sub] = "resolver-test", ["name"] = "Resolver Test" };

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var resolverState = new TestResolverState(
            privateKey.AsReadOnlySpan().ToArray(),
            publicKey.AsReadOnlySpan().ToArray());

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            resolverState,
            ResolvePrivateKeyMaterial,
            0,
            BindPrivateKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        Assert.IsNotNull(jws);
        string[] parts = jws.Split('.');
        Assert.HasCount(3, parts);

        bool isValid = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            SensitiveMemoryPool<byte>.Shared,
            resolverState,
            ResolvePublicKeyMaterial,
            0,
            BindPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "Signature verification with resolver/binder should succeed.");
    }


    [TestMethod]
    public async Task SignAndVerifyWithP384ExplicitFunctionSucceeds()
    {
        var header = new Dictionary<string, object> { [JwkProperties.Alg] = WellKnownJwaValues.Es384, [JwkProperties.Typ] = "JWT" };
        var payload = new Dictionary<string, object> { [JwkProperties.Sub] = "user-384", [JwkProperties.Iat] = 1234567890 };

        var keyPair = TestKeyMaterialProvider.CreateP384KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP384Async,
            SensitiveMemoryPool<byte>.Shared).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        bool isValid = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            SensitiveMemoryPool<byte>.Shared,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP384Async).ConfigureAwait(false);

        Assert.IsTrue(isValid, "P-384 signature verification should succeed.");
    }


    [TestMethod]
    public async Task SignAndVerifyWithP521ExplicitFunctionSucceeds()
    {
        var header = new Dictionary<string, object> { [JwkProperties.Alg] = WellKnownJwaValues.Es512, [JwkProperties.Typ] = "JWT" };
        var payload = new Dictionary<string, object> { [JwkProperties.Sub] = "user-521", [JwkProperties.Exp] = 9999999999 };

        var keyPair = TestKeyMaterialProvider.CreateP521KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP521Async,
            SensitiveMemoryPool<byte>.Shared).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        bool isValid = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            SensitiveMemoryPool<byte>.Shared,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP521Async).ConfigureAwait(false);

        Assert.IsTrue(isValid, "P-521 signature verification should succeed.");
    }


    [TestMethod]
    public async Task VerifyWithWrongKeyFails()
    {
        var header = new Dictionary<string, object> { [JwkProperties.Alg] = WellKnownJwaValues.Es256, [JwkProperties.Typ] = "JWT" };
        var payload = new Dictionary<string, object> { [JwkProperties.Sub] = "test" };

        //Use one key pair for signing.
        var signingKeyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var signingPublicKey = signingKeyPair.PublicKey;
        using var signingPrivateKey = signingKeyPair.PrivateKey;

        //Create a different key pair for verification (wrong key).
        var wrongKeyPair = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var wrongPublicKey = wrongKeyPair.PublicKey;
        using var wrongPrivateKey = wrongKeyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            signingPrivateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            SensitiveMemoryPool<byte>.Shared).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        bool isValid = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            SensitiveMemoryPool<byte>.Shared,
            wrongPublicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async).ConfigureAwait(false);

        Assert.IsFalse(isValid, "Verification with wrong key should fail.");
    }


    [TestMethod]
    public async Task VerifyAndDecodeWithResolverBinderReturnsHeaderAndPayload()
    {
        var header = new Dictionary<string, object> { [JwkProperties.Alg] = WellKnownJwaValues.Es256, [JwkProperties.Typ] = "JWT" };
        var payload = new Dictionary<string, object> { [JwkProperties.Sub] = "decode-test", ["custom"] = "value" };

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var resolverState = new TestResolverState(
            privateKey.AsReadOnlySpan().ToArray(),
            publicKey.AsReadOnlySpan().ToArray());

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            SensitiveMemoryPool<byte>.Shared).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        JwsVerificationResult<Dictionary<string, object>> result = await Jws.VerifyAndDecodeAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            SensitiveMemoryPool<byte>.Shared,
            resolverState,
            ResolvePublicKeyMaterial,
            0,
            BindPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

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
            await Jws.SignAsync(
                header,
                payload,
                EncodeJwtPart,
                TestSetup.Base64UrlEncoder,
                SensitiveMemoryPool<byte>.Shared,
                0,
                (context, pool, state, ct) => ValueTask.FromResult<PrivateKeyMemory?>(null),
                0,
                (material, state, ct) => throw new InvalidOperationException("Binder should not be called."),
                cancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
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
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller (Jws.SignAsync) which disposes via PrivateKey.")]
    private static ValueTask<PrivateKeyMemory?> ResolvePrivateKeyMaterial(
        JoseKeyContext<Dictionary<string, object>> context,
        MemoryPool<byte> pool,
        TestResolverState state,
        CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> memoryOwner = pool.Rent(state.PrivateKeyBytes.Length);
        state.PrivateKeyBytes.CopyTo(memoryOwner.Memory.Span);

        return ValueTask.FromResult<PrivateKeyMemory?>(new PrivateKeyMemory(memoryOwner, CryptoTags.P256PrivateKey));
    }


    /// <summary>
    /// Test resolver that returns public key material from state.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller (Jws.VerifyAsync) which disposes via PublicKey.")]
    private static ValueTask<PublicKeyMemory?> ResolvePublicKeyMaterial(
        JoseKeyContext<Dictionary<string, object>> context,
        MemoryPool<byte> pool,
        TestResolverState state,
        CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> memoryOwner = pool.Rent(state.PublicKeyBytes.Length);
        state.PublicKeyBytes.CopyTo(memoryOwner.Memory.Span);

        return ValueTask.FromResult<PublicKeyMemory?>(new PublicKeyMemory(memoryOwner, CryptoTags.P256PublicKey));
    }


    /// <summary>
    /// Test binder that binds signing function to private key material.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller (Jws.SignAsync) which disposes the returned PrivateKey.")]
    private static ValueTask<PrivateKey> BindPrivateKey(
        PrivateKeyMemory material,
        int state,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(new PrivateKey(material, "test-key", MicrosoftCryptographicFunctions.SignP256Async));
    }


    /// <summary>
    /// Test binder that binds verification function to public key material.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller (Jws.VerifyAsync) which disposes the returned PublicKey.")]
    private static ValueTask<PublicKey> BindPublicKey(
        PublicKeyMemory material,
        int state,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(new PublicKey(material, "test-key", MicrosoftCryptographicFunctions.VerifyP256Async));
    }


    /// <summary>
    /// Encodes a JWT part (dictionary) to tagged memory with UTF-8 JSON bytes.
    /// </summary>
    private static TaggedMemory<byte> EncodeJwtPart(Dictionary<string, object> part)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(part));
        return new TaggedMemory<byte>(bytes, BufferTags.Json);
    }


    /// <summary>
    /// Decodes UTF-8 JSON bytes to a dictionary.
    /// </summary>
    private static Dictionary<string, object> DecodeJwtPart(ReadOnlySpan<byte> bytes)
    {
        string json = Encoding.UTF8.GetString(bytes);
        return JsonSerializer.Deserialize<Dictionary<string, object>>(json, JsonOptions)!;
    }
}