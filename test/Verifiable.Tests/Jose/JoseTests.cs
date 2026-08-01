using System.Buffers;
using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using static Verifiable.JCose.CryptoFormatConversionsExtensions;

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


    [TestMethod]
    public async Task SignAndVerifyWithExplicitFunctionSucceeds()
    {
        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "1234567890", ["name"] = "Test User" };

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        Assert.IsNotNull(jws);
        string[] parts = jws.Split('.');
        Assert.HasCount(3, parts);

        bool isValid = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "Signature verification should succeed.");
    }


    [TestMethod]
    public async Task SignAndVerifyWithResolverBinderSucceeds()
    {
        JwtHeader header = new() { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        JwtPayload payload = new() { [WellKnownJwtClaimNames.Sub] = "resolver-test", ["name"] = "Resolver Test" };

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var resolverState = new TestResolverState(
            privateKey.AsReadOnlySpan().ToArray(),
            publicKey.AsReadOnlySpan().ToArray());

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared,
            resolverState,
            ResolvePrivateKeyMaterial,
            0,
            BindPrivateKey,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        Assert.IsNotNull(jws);
        string[] parts = jws.Split('.');
        Assert.HasCount(3, parts);

        bool isValid = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            BaseMemoryPool.Shared,
            resolverState,
            ResolvePublicKeyMaterial,
            0,
            BindPublicKey,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "Signature verification with resolver/binder should succeed.");
    }


    [TestMethod]
    public async Task SignAndVerifyWithP384ExplicitFunctionSucceeds()
    {
        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es384, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "user-384", [WellKnownJwtClaimNames.Iat] = 1234567890 };

        var keyPair = TestKeyMaterialProvider.CreateP384KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP384Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        bool isValid = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP384Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "P-384 signature verification should succeed.");
    }


    [TestMethod]
    public async Task SignAndVerifyWithP521ExplicitFunctionSucceeds()
    {
        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es512, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "user-521", [WellKnownJwtClaimNames.Exp] = 9999999999 };

        var keyPair = TestKeyMaterialProvider.CreateP521KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP521Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        bool isValid = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP521Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "P-521 signature verification should succeed.");
    }


    [TestMethod]
    public async Task VerifyWithWrongKeyFails()
    {
        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "test" };

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
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            signingPrivateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        bool isValid = await Jws.VerifyAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            wrongPublicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isValid, "Verification with wrong key should fail.");
    }


    /// <summary>
    /// The <see cref="JwsMessage"/>-based <c>VerifyAsync</c> overload shares the compact-string overload's
    /// documented contract that "callers depend on VerifyAsync returning false, never throwing, on untrusted
    /// input" (see the guard in <see cref="Jws.VerifyAsync(string, DecodeDelegate, BaseMemoryPool, PublicKeyMemory, VerificationDelegate, int, CryptoEventSink?, CancellationToken)"/>).
    /// A resolved <see cref="VerificationDelegate"/> can throw while parsing attacker-tampered key material —
    /// for example a tampered EC point surfacing as <see cref="PlatformNotSupportedException"/> on Windows CNG
    /// rather than a graceful rejection — and this overload must fail closed to <see langword="false"/> instead
    /// of letting that exception escape.
    /// </summary>
    [TestMethod]
    public async Task VerifyAsyncWithJwsMessageReturnsFalseWhenVerificationDelegateThrows()
    {
        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "throwing-delegate-test" };

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        bool isValid = await Jws.VerifyAsync(
            jwsMessage,
            TestSetup.Base64UrlEncoder,
            publicKey,
            ThrowingVerificationDelegate,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isValid, "A verification delegate that throws on tampered/untrusted key material must fail closed to false, never escape as an exception.");
    }


    /// <summary>
    /// <see cref="Jws.VerifySignatureAsync(string, ReadOnlyMemory{byte}, bool, ReadOnlyMemory{byte}, EncodeDelegate, VerificationDelegate, ReadOnlyMemory{byte}, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/>
    /// shares the same fail-closed contract as the other <c>Jws</c> verify overloads: a resolved
    /// <see cref="VerificationDelegate"/> that throws while parsing attacker-tampered key material must not let
    /// that exception escape past the guard — it must be treated as "signature does not verify".
    /// </summary>
    [TestMethod]
    public async Task VerifySignatureAsyncReturnsFalseWhenVerificationDelegateThrows()
    {
        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "verify-signature-throwing-delegate-test" };

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        JwsSignatureComponent signatureComponent = jwsMessage.Signatures[0];

        bool isValid = await Jws.VerifySignatureAsync(
            signatureComponent.Protected,
            jwsMessage.Payload,
            base64UrlPayload: true,
            signatureComponent.SignatureBytes,
            TestSetup.Base64UrlEncoder,
            ThrowingVerificationDelegate,
            publicKey.AsReadOnlyMemory(),
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isValid, "A verification delegate that throws on tampered/untrusted key material must fail closed to false, never escape as an exception.");
    }


    /// <summary>
    /// The explicit-<see cref="VerificationDelegate"/> compact-string
    /// <see cref="Jws.VerifyAndDecodeAsync(string, DecodeDelegate, JwtPartDecoder, BaseMemoryPool, PublicKeyMemory, VerificationDelegate, int, CryptoEventSink?, CancellationToken)"/>
    /// overload shares the same fail-closed contract as the other <c>Jws</c> verify overloads: a resolved
    /// <see cref="VerificationDelegate"/> that throws while parsing attacker-tampered key material must not let
    /// that exception escape past the guard — it must be treated as "signature does not verify", returning an
    /// invalid <see cref="JwsVerificationResult"/> rather than throwing.
    /// </summary>
    [TestMethod]
    public async Task VerifyAndDecodeAsyncWithCompactStringReturnsFalseWhenVerificationDelegateThrows()
    {
        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "verify-and-decode-throwing-delegate-test" };

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        JwsVerificationResult result = await Jws.VerifyAndDecodeAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            BaseMemoryPool.Shared,
            publicKey,
            ThrowingVerificationDelegate,
            Jws.DefaultMaxJwsLength,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A verification delegate that throws on tampered/untrusted key material must fail closed to an invalid result, never escape as an exception.");
    }


    /// <summary>
    /// Simulates a resolved verification backend rejecting attacker-tampered key material with an exception
    /// (for example a tampered EC point surfacing as <see cref="PlatformNotSupportedException"/> on Windows CNG)
    /// instead of a graceful "not verified" result — the shape every <c>Jws</c> verify overload's fail-closed
    /// guard exists to catch. Shared across the guard tests above.
    /// </summary>
    private static ValueTask<(bool IsVerified, CryptoEvent? Event)> ThrowingVerificationDelegate(
        ReadOnlyMemory<byte> dataToVerify,
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> publicKeyMaterial,
        FrozenDictionary<string, object>? context = null,
        CancellationToken cancellationToken = default)
        => throw new PlatformNotSupportedException("Simulated tampered EC point rejection.");


    [TestMethod]
    public async Task VerifyAndDecodeWithResolverBinderReturnsHeaderAndPayload()
    {
        var header = new Dictionary<string, object> { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        var payload = new Dictionary<string, object> { [WellKnownJwtClaimNames.Sub] = "decode-test", ["custom"] = "value" };

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var resolverState = new TestResolverState(
            privateKey.AsReadOnlySpan().ToArray(),
            publicKey.AsReadOnlySpan().ToArray());

        using JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        JwsVerificationResult result = await Jws.VerifyAndDecodeAsync(
            jws,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            BaseMemoryPool.Shared,
            resolverState,
            ResolvePublicKeyMaterial,
            0,
            BindPublicKey,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "Signature should be valid.");
        Assert.AreEqual(WellKnownJwaValues.Es256, result.Header[WellKnownJwkMemberNames.Alg]?.ToString());
        Assert.AreEqual("decode-test", result.Payload[WellKnownJwtClaimNames.Sub]?.ToString());
        Assert.AreEqual("value", result.Payload["custom"]?.ToString());
    }


    [TestMethod]
    public async Task ResolverReturningNullThrowsInvalidOperationException()
    {
        JwtHeader header = new() { [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256, [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt };
        JwtPayload payload = new() { [WellKnownJwtClaimNames.Sub] = "null-test" };
        CancellationToken cancellationToken = TestContext.CancellationToken;

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await Jws.SignAsync(
                header,
                payload,
                JwtWireFixtures.EncodeJwtPart,
                TestSetup.Base64UrlEncoder,
                BaseMemoryPool.Shared,
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
        Tag signingTag = GetSigningTag(WellKnownJwaValues.Es256);
        Tag verificationTag = GetVerificationTag(WellKnownJwaValues.Es256);

        Assert.AreEqual(CryptoAlgorithm.P256, signingTag.Get<CryptoAlgorithm>());
        Assert.AreEqual(Purpose.Signing, signingTag.Get<Purpose>());

        Assert.AreEqual(CryptoAlgorithm.P256, verificationTag.Get<CryptoAlgorithm>());
        Assert.AreEqual(Purpose.Verification, verificationTag.Get<Purpose>());
    }


    [TestMethod]
    public void CryptoFormatConversionsThrowsForUnsupportedAlgorithm()
    {
        Assert.Throws<NotSupportedException>(() => GetSigningTag("UNSUPPORTED"));
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
        JoseKeyContext context,
        BaseMemoryPool pool,
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
        JoseKeyContext context,
        BaseMemoryPool pool,
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
    /// Decodes UTF-8 JSON bytes to a dictionary.
    /// </summary>
    private static Dictionary<string, object> DecodeJwtPart(ReadOnlySpan<byte> bytes)
    {
        string json = Encoding.UTF8.GetString(bytes);
        return JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(json, TestSetup.DefaultSerializationOptions)!;
    }
}