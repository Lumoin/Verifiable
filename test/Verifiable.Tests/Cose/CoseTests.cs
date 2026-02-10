using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cose;

/// <summary>
/// Tests for COSE_Sign1 operations using explicit delegate, resolver/binder, and serialization round-trip APIs.
/// </summary>
[TestClass]
internal sealed class CoseTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task SignAndVerifyWithExplicitDelegateSucceeds()
    {
        var headerMap = new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256 };
        byte[] protectedHeader = CoseSerialization.SerializeProtectedHeader(headerMap);
        byte[] payload = BuildTestPayload();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            SensitiveMemoryPool<byte>.Shared).ConfigureAwait(false);

        Assert.IsNotNull(message);
        Assert.IsGreaterThan(0, message.Signature.Length);
        Assert.IsTrue(payload.AsSpan().SequenceEqual(message.Payload.Span));

        bool isValid = await Verifiable.JCose.Cose.VerifyAsync(
            message,
            CoseSerialization.BuildSigStructure,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async).ConfigureAwait(false);

        Assert.IsTrue(isValid, "COSE_Sign1 signature verification must succeed.");
    }


    [TestMethod]
    public async Task SignAndVerifyWithResolverBinderSucceeds()
    {
        var headerMap = new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256 };
        byte[] protectedHeader = CoseSerialization.SerializeProtectedHeader(headerMap);
        byte[] payload = BuildTestPayload();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var resolverState = new TestResolverState(
            privateKey.AsReadOnlySpan().ToArray(),
            publicKey.AsReadOnlySpan().ToArray());

        var message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            SensitiveMemoryPool<byte>.Shared,
            resolverState,
            ResolvePrivateKeyMaterial,
            0,
            BindPrivateKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(message);

        bool isValid = await Verifiable.JCose.Cose.VerifyAsync(
            message,
            CoseSerialization.BuildSigStructure,
            SensitiveMemoryPool<byte>.Shared,
            resolverState,
            ResolvePublicKeyMaterial,
            0,
            BindPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "COSE_Sign1 verification with resolver/binder must succeed.");
    }


    [TestMethod]
    public async Task SignAndVerifyWithP384ExplicitDelegateSucceeds()
    {
        var headerMap = new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es384 };
        byte[] protectedHeader = CoseSerialization.SerializeProtectedHeader(headerMap);
        byte[] payload = BuildTestPayload();

        var keyPair = TestKeyMaterialProvider.CreateP384KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            privateKey,
            MicrosoftCryptographicFunctions.SignP384Async,
            SensitiveMemoryPool<byte>.Shared).ConfigureAwait(false);

        bool isValid = await Verifiable.JCose.Cose.VerifyAsync(
            message,
            CoseSerialization.BuildSigStructure,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP384Async).ConfigureAwait(false);

        Assert.IsTrue(isValid, "P-384 COSE_Sign1 signature verification must succeed.");
    }


    [TestMethod]
    public async Task SignAndVerifyWithP521ExplicitDelegateSucceeds()
    {
        var headerMap = new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es512 };
        byte[] protectedHeader = CoseSerialization.SerializeProtectedHeader(headerMap);
        byte[] payload = BuildTestPayload();

        var keyPair = TestKeyMaterialProvider.CreateP521KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            privateKey,
            MicrosoftCryptographicFunctions.SignP521Async,
            SensitiveMemoryPool<byte>.Shared).ConfigureAwait(false);

        bool isValid = await Verifiable.JCose.Cose.VerifyAsync(
            message,
            CoseSerialization.BuildSigStructure,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP521Async).ConfigureAwait(false);

        Assert.IsTrue(isValid, "P-521 COSE_Sign1 signature verification must succeed.");
    }


    [TestMethod]
    public async Task VerifyWithWrongKeyFails()
    {
        var headerMap = new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256 };
        byte[] protectedHeader = CoseSerialization.SerializeProtectedHeader(headerMap);
        byte[] payload = BuildTestPayload();

        var signingKeyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var signingPublicKey = signingKeyPair.PublicKey;
        using var signingPrivateKey = signingKeyPair.PrivateKey;

        var wrongKeyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var wrongPublicKey = wrongKeyPair.PublicKey;
        using var wrongPrivateKey = wrongKeyPair.PrivateKey;

        var message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            signingPrivateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            SensitiveMemoryPool<byte>.Shared).ConfigureAwait(false);

        bool isValid = await Verifiable.JCose.Cose.VerifyAsync(
            message,
            CoseSerialization.BuildSigStructure,
            wrongPublicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async).ConfigureAwait(false);

        Assert.IsFalse(isValid, "Verification with wrong key must fail.");
    }


    [TestMethod]
    public async Task SerializeAndParseRoundTripSucceeds()
    {
        var headerMap = new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256 };
        byte[] protectedHeader = CoseSerialization.SerializeProtectedHeader(headerMap);
        byte[] payload = BuildTestPayload();

        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            privateKey,
            MicrosoftCryptographicFunctions.SignP256Async,
            SensitiveMemoryPool<byte>.Shared).ConfigureAwait(false);

        byte[] coseBytes = CoseSerialization.SerializeCoseSign1(message);
        CoseSign1Message parsed = CoseSerialization.ParseCoseSign1(coseBytes);

        Assert.IsTrue(message.ProtectedHeaderBytes.Span.SequenceEqual(parsed.ProtectedHeaderBytes.Span), "Protected header must round-trip.");
        Assert.IsTrue(message.Payload.Span.SequenceEqual(parsed.Payload.Span), "Payload must round-trip.");
        Assert.IsTrue(message.Signature.Span.SequenceEqual(parsed.Signature.Span), "Signature must round-trip.");

        bool isValid = await Verifiable.JCose.Cose.VerifyAsync(
            parsed,
            CoseSerialization.BuildSigStructure,
            publicKey,
            MicrosoftCryptographicFunctions.VerifyP256Async).ConfigureAwait(false);

        Assert.IsTrue(isValid, "Parsed COSE_Sign1 must verify successfully.");
    }


    [TestMethod]
    public void ProtectedHeaderSerializationRoundTripSucceeds()
    {
        var headerMap = new Dictionary<int, object>
        {
            [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256,
            [CoseHeaderParameters.Typ] = "application/vc+cose"
        };

        byte[] serialized = CoseSerialization.SerializeProtectedHeader(headerMap);
        IReadOnlyDictionary<int, object> parsed = CoseSerialization.ParseProtectedHeader(serialized);

        Assert.HasCount(2, parsed);
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, parsed[CoseHeaderParameters.Alg]);
        Assert.AreEqual("application/vc+cose", parsed[CoseHeaderParameters.Typ]?.ToString());
    }


    [TestMethod]
    public void DefaultTagToCoseConverterMapsP256Correctly()
    {
        int coseAlg = CryptoFormatConversions.DefaultTagToCoseConverter(CryptoTags.P256PrivateKey);
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, coseAlg);
    }


    [TestMethod]
    public void DefaultTagToCoseConverterMapsP384Correctly()
    {
        int coseAlg = CryptoFormatConversions.DefaultTagToCoseConverter(CryptoTags.P384PrivateKey);
        Assert.AreEqual(WellKnownCoseAlgorithms.Es384, coseAlg);
    }


    [TestMethod]
    public void DefaultTagToCoseConverterMapsP521Correctly()
    {
        int coseAlg = CryptoFormatConversions.DefaultTagToCoseConverter(CryptoTags.P521PrivateKey);
        Assert.AreEqual(WellKnownCoseAlgorithms.Es512, coseAlg);
    }


    [TestMethod]
    public void DefaultTagToCoseConverterMapsEd25519Correctly()
    {
        int coseAlg = CryptoFormatConversions.DefaultTagToCoseConverter(CryptoTags.Ed25519PrivateKey);
        Assert.AreEqual(WellKnownCoseAlgorithms.EdDsa, coseAlg);
    }


    [TestMethod]
    public void DefaultTagToCoseConverterThrowsForUnsupported()
    {
        Assert.Throws<NotSupportedException>(() =>
            CryptoFormatConversions.DefaultTagToCoseConverter(CryptoTags.X25519PublicKey));
    }


    [TestMethod]
    public void DefaultCoseToTagConverterRoundTripsWithTagToCose()
    {
        int coseAlg = CryptoFormatConversions.DefaultTagToCoseConverter(CryptoTags.P256PrivateKey);
        Tag roundTripped = CryptoFormatConversions.DefaultCoseToTagConverter(coseAlg, Purpose.Signing);
        Assert.AreEqual(CryptoTags.P256PrivateKey, roundTripped);
    }


    /// <summary>
    /// Builds a simple CWT-style test payload with issuer and issued-at claims.
    /// </summary>
    private static byte[] BuildTestPayload()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(WellKnownCwtClaims.Iss);
        writer.WriteTextString("did:example:issuer");
        writer.WriteInt32(WellKnownCwtClaims.Iat);
        writer.WriteInt64(1718452800);
        writer.WriteEndMap();
        return writer.Encode();
    }


    private sealed record TestResolverState(byte[] PrivateKeyBytes, byte[] PublicKeyBytes);


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller which disposes via PrivateKey.")]
    private static ValueTask<PrivateKeyMemory?> ResolvePrivateKeyMaterial(
        CoseKeyContext context,
        MemoryPool<byte> pool,
        TestResolverState state,
        CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> memoryOwner = pool.Rent(state.PrivateKeyBytes.Length);
        state.PrivateKeyBytes.CopyTo(memoryOwner.Memory.Span);
        return ValueTask.FromResult<PrivateKeyMemory?>(new PrivateKeyMemory(memoryOwner, CryptoTags.P256PrivateKey));
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller which disposes via PublicKey.")]
    private static ValueTask<PublicKeyMemory?> ResolvePublicKeyMaterial(
        CoseKeyContext context,
        MemoryPool<byte> pool,
        TestResolverState state,
        CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> memoryOwner = pool.Rent(state.PublicKeyBytes.Length);
        state.PublicKeyBytes.CopyTo(memoryOwner.Memory.Span);
        return ValueTask.FromResult<PublicKeyMemory?>(new PublicKeyMemory(memoryOwner, CryptoTags.P256PublicKey));
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller which disposes the returned PrivateKey.")]
    private static ValueTask<PrivateKey> BindPrivateKey(
        PrivateKeyMemory material,
        int state,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(new PrivateKey(material, "test-key", MicrosoftCryptographicFunctions.SignP256Async));
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller which disposes the returned PublicKey.")]
    private static ValueTask<PublicKey> BindPublicKey(
        PublicKeyMemory material,
        int state,
        CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(new PublicKey(material, "test-key", MicrosoftCryptographicFunctions.VerifyP256Async));
    }
}