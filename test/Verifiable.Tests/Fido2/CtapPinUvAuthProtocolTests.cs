using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Known-answer and round-trip tests for <see cref="CtapPinUvAuthProtocol"/> (CTAP 2.3 §6.5.6/§6.5.7).
/// </summary>
/// <remarks>
/// <para>
/// The ECDH key pairs, the resulting raw shared secret <c>Z</c>, both protocols' <c>kdf(Z)</c>
/// outputs, and the AES-256-CBC/HMAC-SHA-256 expected values below were computed once, offline, by
/// an independent implementation composed directly from <see cref="System.Security.Cryptography"/>
/// primitives (<c>ECDiffieHellman</c>, <c>HKDF</c>, <c>HMACSHA256</c>, <c>Aes</c>) - the same
/// offline-oracle convention <c>KdfaTests</c>/<c>KdfeTests</c>/<c>HkdfTests</c> use. This shipped test
/// file performs no cryptography of its own: <see cref="CtapPinUvAuthProtocol"/> is exercised through
/// the project's own registered production primitives (<see cref="MicrosoftKeyAgreementFunctions"/>,
/// <see cref="MicrosoftEntropyFunctions"/>, <see cref="MicrosoftHmacFunctions"/>,
/// <see cref="BouncyCastleSymmetricFunctions"/>), composed as the injected delegates
/// <see cref="CtapPinUvAuthProtocol"/> takes.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CtapPinUvAuthProtocolTests
{
    /// <summary>The MSTest-injected context; supplies <see cref="TestContext.CancellationToken"/> to every async call below.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed P-256 exchange private scalar for the "authenticator" side of the offline KAT.</summary>
    private const string AuthPrivateScalarHex = "3e37e78a7f1dde901aa8c525109cff78cb4a5d3d8889c76db6ef9ed8c227d1ac";

    /// <summary>The authenticator scalar's corresponding public x-coordinate.</summary>
    private const string AuthPublicXHex = "f65865007defe716c2c419c782ee717a06c484cc6b9f1f6e4b84dfe7ccc5a969";

    /// <summary>The authenticator scalar's corresponding public y-coordinate.</summary>
    private const string AuthPublicYHex = "2b5ac9ad3a1e221c2ca0315db09466ab3ae2db126ea6764c70003892f5a7f803";

    /// <summary>The "platform" side's fixed public x-coordinate (its private scalar is never published).</summary>
    private const string PeerPublicXHex = "dfd0a890aba2b61a44a8a9a3aa6b3b725301f74c4038db9629df4bbcfc907b66";

    /// <summary>The "platform" side's fixed public y-coordinate.</summary>
    private const string PeerPublicYHex = "4862028838cd3b0f82754cb91c42c7b623ccb941e48967d3b31b426b16a30c42";

    /// <summary>The expected protocol-one shared secret: <c>SHA-256(Z)</c> for the fixed key pair above.</summary>
    private const string ProtocolOneSharedSecretHex = "2155d74e63450e934c5cb96bfc024ad418d0c9d54e192aff4337ae62cd98e145";

    /// <summary>The expected protocol-two shared secret's HMAC-key half (bytes <c>[0,32)</c>).</summary>
    private const string ProtocolTwoHmacKeyHalfHex = "2cdf925f8ac821cda8bcb6b0b037aa3b4666a099934836781ddfd8b5311705ce";

    /// <summary>The expected protocol-two shared secret's AES-key half (bytes <c>[32,64)</c>).</summary>
    private const string ProtocolTwoAesKeyHalfHex = "03e4378d44f0ecd162b34a08a673b8d54b08a66b7baa61d31d481de18682304c";

    /// <summary>The fixed message the authenticate/verify tests sign and check.</summary>
    private const string MessageAscii = "ctap-pinuv-authenticate-message";

    /// <summary>The expected protocol-one <c>authenticate</c> output (first 16 bytes of HMAC-SHA-256).</summary>
    private const string ProtocolOneAuthenticateHex = "85dbd16c659a536096e38b28dc55f856";

    /// <summary>The expected protocol-two <c>authenticate</c> output (full, untruncated 32-byte HMAC-SHA-256).</summary>
    private const string ProtocolTwoAuthenticateHex = "b6d3851d407e9b8dd9c59d9290389e5f814b7e0e19c4dcbf224984f243c3337b";

    /// <summary>The fixed, block-aligned (32-byte) plaintext the encrypt/decrypt tests use.</summary>
    private const string PlaintextAscii = "0123456789abcdef0123456789ABCDEF";

    /// <summary>The expected protocol-one ciphertext: AES-256-CBC(plaintext, sharedSecret, zeroIv).</summary>
    private const string ProtocolOneCiphertextHex = "3dec6c6ef9bc202ac2e6425c5b6e0e96a9ef9adbe658da00c69d71bb18d74744";

    /// <summary>The fixed IV injected into protocol two's encrypt test via a deterministic <see cref="GenerateNonceDelegate"/> stub.</summary>
    private const string ProtocolTwoFixedIvHex = "000102030405060708090a0b0c0d0e0f";

    /// <summary>The expected protocol-two ciphertext (inner AES-256-CBC output only, without the prefixed IV).</summary>
    private const string ProtocolTwoInnerCiphertextHex = "1a77d97995758cf66205bfdfa638e94a1a5be6e56cde6a64fda5ff920a29f0f0";

    /// <summary>
    /// CTAP 2.3 §6.5.7 line 6229's explicitly WRONG construction: a single L=64 HKDF-Expand call under
    /// one info label, rather than two independent L=32 calls under two different labels.
    /// </summary>
    private const string WrongSingleCallSixtyFourHex =
        "2cdf925f8ac821cda8bcb6b0b037aa3b4666a099934836781ddfd8b5311705ce2a510a5f9b219397eb88d315735192dfcc51892f8cfd9dc4b5917ec520d93354";

    /// <summary>
    /// Protocol two's <c>kdf(Z)</c> HMAC-key and AES-key halves, and every raw HKDF/HMAC
    /// intermediate feeding them, are each exactly one SHA-256 digest wide (CTAP 2.3 §6.5.7).
    /// </summary>
    private const int KdfIntermediateHalfLength = 32;

    /// <summary>Builds a protocol instance composed from the project's own registered production primitives.</summary>
    private static CtapPinUvAuthProtocol CreateProtocol(CtapPinUvAuthProtocolId id, GenerateNonceDelegate? generateNonce = null) =>
        new(
            id,
            MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            MicrosoftHmacFunctions.ComputeHmacAsync,
            BouncyCastleSymmetricFunctions.SymmetricEncryptAsync,
            BouncyCastleSymmetricFunctions.SymmetricDecryptAsync,
            generateNonce ?? MicrosoftEntropyFunctions.GenerateNonce);

    /// <summary>Wraps a hex-encoded 32-byte P-256 exchange private scalar as a <see cref="PrivateKeyMemory"/>.</summary>
    private static PrivateKeyMemory PrivateKeyFromHex(string hex)
    {
        byte[] bytes = Convert.FromHexString(hex);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new PrivateKeyMemory(owner, CryptoTags.P256ExchangePrivateKey);
    }

    /// <summary>Wraps hex-encoded 32-byte X/Y coordinates as an uncompressed (<c>0x04 || X || Y</c>) <see cref="PublicKeyMemory"/>.</summary>
    private static PublicKeyMemory PublicKeyFromHex(string xHex, string yHex)
    {
        byte[] x = Convert.FromHexString(xHex);
        byte[] y = Convert.FromHexString(yHex);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(1 + x.Length + y.Length);
        owner.Memory.Span[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
        x.CopyTo(owner.Memory.Span[1..]);
        y.CopyTo(owner.Memory.Span[(1 + x.Length)..]);

        return new PublicKeyMemory(owner, CryptoTags.P256ExchangePublicKey);
    }

    /// <summary>Builds the peer's key-agreement COSE_Key (CTAP 2.3 §2.1's <c>keyAgreement</c> request parameter shape).</summary>
    private static CoseKey PeerCoseKey(string xHex, string yHex) => new(
        kty: CoseKeyTypes.Ec2,
        curve: CoseKeyCurves.P256,
        x: Convert.FromHexString(xHex),
        y: Convert.FromHexString(yHex));

    /// <summary>
    /// <see cref="CtapPinUvAuthProtocol.GetPublicKey"/> must return exactly the five COSE_Key members
    /// CTAP 2.3 §6.5.6 line 6175-6189 specifies, identically for both protocol ids.
    /// </summary>
    [TestMethod]
    [DataRow(CtapPinUvAuthProtocolId.One)]
    [DataRow(CtapPinUvAuthProtocolId.Two)]
    public void GetPublicKeyHasTheSpecMandatedShape(CtapPinUvAuthProtocolId id)
    {
        CtapPinUvAuthProtocol protocol = CreateProtocol(id);
        using PublicKeyMemory ownPublicKey = PublicKeyFromHex(AuthPublicXHex, AuthPublicYHex);

        CoseKey publicKey = protocol.GetPublicKey(ownPublicKey);

        Assert.AreEqual(CoseKeyTypes.Ec2, publicKey.Kty, "kty must be EC2 (2).");
        Assert.AreEqual(-25, publicKey.Alg, "alg must be the literal -25 (CTAP 2.3 §6.5.6 line 6182), never derived from a real algorithm.");
        Assert.AreEqual(CoseKeyCurves.P256, publicKey.Curve, "crv must be P-256 (1).");
        Assert.AreEqual(AuthPublicXHex, Convert.ToHexStringLower(publicKey.X!.Value.Span), "x must be the 32-byte big-endian x-coordinate.");
        Assert.AreEqual(AuthPublicYHex, Convert.ToHexStringLower(publicKey.Y!.Value.Span), "y must be the 32-byte big-endian y-coordinate.");
        Assert.IsNull(publicKey.EncodedYCompressionSign, "getPublicKey's COSE_Key carries no other optional member.");
        Assert.IsNull(publicKey.N, "getPublicKey's COSE_Key carries no RSA members.");
        Assert.IsNull(publicKey.E, "getPublicKey's COSE_Key carries no RSA members.");
    }

    /// <summary>Protocol one's <c>decapsulate</c> (ECDH + <c>kdf(Z) = SHA-256(Z)</c>) must match the offline known-answer shared secret.</summary>
    [TestMethod]
    public async Task ProtocolOneDecapsulateMatchesKnownSharedSecret()
    {
        CtapPinUvAuthProtocol protocol = CreateProtocol(CtapPinUvAuthProtocolId.One);
        using PrivateKeyMemory ownPrivateKey = PrivateKeyFromHex(AuthPrivateScalarHex);
        CoseKey peerKey = PeerCoseKey(PeerPublicXHex, PeerPublicYHex);

        IMemoryOwner<byte> sharedSecret = await protocol.DecapsulateAsync(
            ownPrivateKey, peerKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            Assert.AreEqual(ProtocolOneSharedSecretHex, Convert.ToHexStringLower(sharedSecret.Memory.Span[..32]),
                "Protocol one's kdf(Z) = SHA-256(Z) must match the offline known answer.");
        }
        finally
        {
            sharedSecret.Memory.Span.Clear();
            sharedSecret.Dispose();
        }
    }

    /// <summary>
    /// Protocol two's <c>decapsulate</c> must match the offline known-answer 64-byte shared secret and
    /// must diverge from the spec's explicitly WRONG single-L=64-call construction (CTAP 2.3 §6.5.7 line 6229).
    /// </summary>
    [TestMethod]
    public async Task ProtocolTwoDecapsulateMatchesKnownSharedSecretAndUsesTwoIndependentHkdfCalls()
    {
        CtapPinUvAuthProtocol protocol = CreateProtocol(CtapPinUvAuthProtocolId.Two);
        using PrivateKeyMemory ownPrivateKey = PrivateKeyFromHex(AuthPrivateScalarHex);
        CoseKey peerKey = PeerCoseKey(PeerPublicXHex, PeerPublicYHex);

        IMemoryOwner<byte> sharedSecret = await protocol.DecapsulateAsync(
            ownPrivateKey, peerKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            Assert.IsGreaterThanOrEqualTo(64, sharedSecret.Memory.Length, "Protocol two's kdf(Z) must produce at least 64 bytes.");
            Assert.AreEqual(ProtocolTwoHmacKeyHalfHex, Convert.ToHexStringLower(sharedSecret.Memory.Span[..32]),
                "bytes [0,32) must be the HKDF-SHA-256(salt=0^32, Z, info=\"CTAP2 HMAC key\", L=32) output.");
            Assert.AreEqual(ProtocolTwoAesKeyHalfHex, Convert.ToHexStringLower(sharedSecret.Memory.Span[32..64]),
                "bytes [32,64) must be the HKDF-SHA-256(salt=0^32, Z, info=\"CTAP2 AES key\", L=32) output.");

            string wrongSecondHalf = WrongSingleCallSixtyFourHex[64..];
            Assert.AreNotEqual(wrongSecondHalf, Convert.ToHexStringLower(sharedSecret.Memory.Span[32..64]),
                "The AES-key half must not equal what a single L=64 HKDF call under one info label would have produced as its second block.");
        }
        finally
        {
            sharedSecret.Memory.Span.Clear();
            sharedSecret.Dispose();
        }
    }

    /// <summary>
    /// Protocol two's <c>kdf(Z)</c> derives its HMAC-key and AES-key halves as intermediate,
    /// raw pooled buffers (each returned by a <see cref="Cryptography.Hkdf.DeriveAsync"/> call)
    /// before copying both into the final 64-byte shared secret. Those two intermediate buffers
    /// must be cleared before they return to the pool, exactly like every other raw intermediate
    /// this call graph rents (<c>Hkdf.ExtractAsync</c>'s PRK, <c>Hkdf.ExpandAsync</c>'s chain
    /// buffer) - the pool is an injected parameter, so this is observable through the public
    /// <see cref="CtapPinUvAuthProtocol.DecapsulateAsync"/> seam without any test-only hook in
    /// production code.
    /// </summary>
    [TestMethod]
    public async Task ProtocolTwoDecapsulateClearsKdfIntermediateHalfBuffersBeforeReturningThemToThePool()
    {
        CtapPinUvAuthProtocol protocol = CreateProtocol(CtapPinUvAuthProtocolId.Two);
        using PrivateKeyMemory ownPrivateKey = PrivateKeyFromHex(AuthPrivateScalarHex);
        CoseKey peerKey = PeerCoseKey(PeerPublicXHex, PeerPublicYHex);
        using var trackingPool = new ZeroOnDisposeTrackingMemoryPool(KdfIntermediateHalfLength);

        IMemoryOwner<byte> sharedSecret = await protocol.DecapsulateAsync(
            ownPrivateKey, peerKey, trackingPool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            Assert.IsGreaterThanOrEqualTo(2, trackingPool.TrackedDisposalCount,
                "At least the HMAC-key-half and AES-key-half intermediate buffers (one per Hkdf.DeriveAsync call) must be rented and disposed at this size.");
            Assert.IsTrue(trackingPool.AllTrackedDisposalsWereZero,
                "Every 32-byte intermediate buffer disposed along protocol two's kdf(Z) path - including the HMAC-key and AES-key halves - must be zeroed before it returns to the pool.");

            Assert.AreEqual(ProtocolTwoHmacKeyHalfHex, Convert.ToHexStringLower(sharedSecret.Memory.Span[..32]),
                "The final shared secret returned to the caller must still carry the correct (unaffected) HMAC-key half.");
            Assert.AreEqual(ProtocolTwoAesKeyHalfHex, Convert.ToHexStringLower(sharedSecret.Memory.Span[32..64]),
                "The final shared secret returned to the caller must still carry the correct (unaffected) AES-key half.");
        }
        finally
        {
            sharedSecret.Memory.Span.Clear();
            sharedSecret.Dispose();
        }
    }

    /// <summary>Protocol one's <c>encrypt</c> (AES-256-CBC, all-zero IV) must match the offline known-answer ciphertext.</summary>
    [TestMethod]
    public async Task ProtocolOneEncryptMatchesKnownAnswerWithZeroIv()
    {
        CtapPinUvAuthProtocol protocol = CreateProtocol(CtapPinUvAuthProtocolId.One);
        byte[] key = Convert.FromHexString(ProtocolOneSharedSecretHex);
        byte[] plaintext = System.Text.Encoding.ASCII.GetBytes(PlaintextAscii);

        using Ciphertext ciphertext = await protocol.EncryptAsync(
            key, plaintext, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ProtocolOneCiphertextHex, Convert.ToHexStringLower(ciphertext.AsReadOnlySpan()),
            "Protocol one's encrypt must be AES-256-CBC with an all-zero IV, matching the known answer.");
    }

    /// <summary>Protocol one's <c>decrypt</c> must invert <c>encrypt</c>'s output back to the original plaintext.</summary>
    [TestMethod]
    public async Task ProtocolOneDecryptRoundTripsThroughEncrypt()
    {
        CtapPinUvAuthProtocol protocol = CreateProtocol(CtapPinUvAuthProtocolId.One);
        byte[] key = Convert.FromHexString(ProtocolOneSharedSecretHex);
        byte[] plaintext = System.Text.Encoding.ASCII.GetBytes(PlaintextAscii);

        using Ciphertext ciphertext = await protocol.EncryptAsync(
            key, plaintext, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using DecryptedContent decrypted = await protocol.DecryptAsync(
            key, ciphertext.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreSequenceEqual(plaintext, decrypted.AsReadOnlySpan().ToArray());
    }

    /// <summary>
    /// Protocol two's <c>encrypt</c> must return <c>iv || AES-256-CBC(plaintext, aesKey, iv)</c>; a
    /// deterministic <see cref="GenerateNonceDelegate"/> stub fixes the IV so the whole output is
    /// byte-exact against the offline known answer.
    /// </summary>
    [TestMethod]
    public async Task ProtocolTwoEncryptMatchesKnownAnswerWithFixedRandomIv()
    {
        byte[] fixedIv = Convert.FromHexString(ProtocolTwoFixedIvHex);
        GenerateNonceDelegate deterministicNonce = (byteLength, tag, pool) =>
        {
            IMemoryOwner<byte> owner = pool.Rent(byteLength);
            fixedIv.AsSpan(0, byteLength).CopyTo(owner.Memory.Span);
            return (new Nonce(owner, tag), null);
        };

        CtapPinUvAuthProtocol protocol = CreateProtocol(CtapPinUvAuthProtocolId.Two, deterministicNonce);
        byte[] key = [.. Convert.FromHexString(ProtocolTwoHmacKeyHalfHex), .. Convert.FromHexString(ProtocolTwoAesKeyHalfHex)];
        byte[] plaintext = System.Text.Encoding.ASCII.GetBytes(PlaintextAscii);

        using Ciphertext ciphertext = await protocol.EncryptAsync(
            key, plaintext, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        string expected = ProtocolTwoFixedIvHex + ProtocolTwoInnerCiphertextHex;
        Assert.AreEqual(expected, Convert.ToHexStringLower(ciphertext.AsReadOnlySpan()),
            "Protocol two's encrypt must return iv (16 random bytes) || AES-256-CBC(plaintext, aesKey, iv).");
    }

    /// <summary>Protocol two's <c>decrypt</c> must invert <c>encrypt</c>'s output (with its own randomly-generated IV) back to the original plaintext.</summary>
    [TestMethod]
    public async Task ProtocolTwoDecryptRoundTripsThroughEncrypt()
    {
        CtapPinUvAuthProtocol protocol = CreateProtocol(CtapPinUvAuthProtocolId.Two);
        byte[] key = [.. Convert.FromHexString(ProtocolTwoHmacKeyHalfHex), .. Convert.FromHexString(ProtocolTwoAesKeyHalfHex)];
        byte[] plaintext = System.Text.Encoding.ASCII.GetBytes(PlaintextAscii);

        using Ciphertext ciphertext = await protocol.EncryptAsync(
            key, plaintext, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using DecryptedContent decrypted = await protocol.DecryptAsync(
            key, ciphertext.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreSequenceEqual(plaintext, decrypted.AsReadOnlySpan().ToArray());
    }

    /// <summary>CTAP 2.3 §6.5.7 line 6250-6261: protocol two's <c>decrypt</c> must reject ciphertext shorter than the 16-byte prefixed IV.</summary>
    [TestMethod]
    public async Task ProtocolTwoDecryptRejectsCiphertextShorterThanTheIv()
    {
        CtapPinUvAuthProtocol protocol = CreateProtocol(CtapPinUvAuthProtocolId.Two);
        byte[] key = [.. Convert.FromHexString(ProtocolTwoHmacKeyHalfHex), .. Convert.FromHexString(ProtocolTwoAesKeyHalfHex)];

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await protocol.DecryptAsync(key, new byte[8], BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    /// <summary>Protocol one's <c>authenticate</c> must truncate its HMAC-SHA-256 output to the first 16 bytes and match the known answer.</summary>
    [TestMethod]
    public async Task ProtocolOneAuthenticateTruncatesToSixteenBytes()
    {
        CtapPinUvAuthProtocol protocol = CreateProtocol(CtapPinUvAuthProtocolId.One);
        byte[] key = Convert.FromHexString(ProtocolOneSharedSecretHex);
        byte[] message = System.Text.Encoding.ASCII.GetBytes(MessageAscii);

        using IMemoryOwner<byte> signature = await protocol.AuthenticateAsync(
            key, message, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsGreaterThanOrEqualTo(16, signature.Memory.Length, "Protocol one's authenticate must produce at least 16 bytes.");
        Assert.AreEqual(ProtocolOneAuthenticateHex, Convert.ToHexStringLower(signature.Memory.Span[..16]),
            "Protocol one's authenticate must be the first 16 bytes of HMAC-SHA-256(sharedSecret, message).");
    }

    /// <summary>Protocol two's <c>authenticate</c> must return the full, untruncated 32-byte HMAC-SHA-256 output and match the known answer.</summary>
    [TestMethod]
    public async Task ProtocolTwoAuthenticateReturnsFullUntruncatedThirtyTwoBytes()
    {
        CtapPinUvAuthProtocol protocol = CreateProtocol(CtapPinUvAuthProtocolId.Two);
        byte[] sharedSecret = [.. Convert.FromHexString(ProtocolTwoHmacKeyHalfHex), .. Convert.FromHexString(ProtocolTwoAesKeyHalfHex)];
        byte[] message = System.Text.Encoding.ASCII.GetBytes(MessageAscii);

        using IMemoryOwner<byte> signature = await protocol.AuthenticateAsync(
            sharedSecret, message, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ProtocolTwoAuthenticateHex, Convert.ToHexStringLower(signature.Memory.Span[..32]),
            "Protocol two's authenticate must be the full, untruncated 32-byte HMAC-SHA-256 output.");
    }

    /// <summary>
    /// CTAP 2.3 §6.5.7 line 6262-6269: "a no-op when key already is the 32-byte pinUvAuthToken" - a
    /// caller that already holds only the HMAC-key half (as <c>pinUvAuthToken</c> always does) must get
    /// the identical signature as a caller passing the full 64-byte shared secret.
    /// </summary>
    [TestMethod]
    public async Task ProtocolTwoAuthenticateWithJustTheHmacKeyHalfIsANoOp()
    {
        CtapPinUvAuthProtocol protocol = CreateProtocol(CtapPinUvAuthProtocolId.Two);
        byte[] hmacKeyOnly = Convert.FromHexString(ProtocolTwoHmacKeyHalfHex);
        byte[] message = System.Text.Encoding.ASCII.GetBytes(MessageAscii);

        using IMemoryOwner<byte> signature = await protocol.AuthenticateAsync(
            hmacKeyOnly, message, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ProtocolTwoAuthenticateHex, Convert.ToHexStringLower(signature.Memory.Span[..32]));
    }

    /// <summary>Protocol one's <c>verify</c> must succeed for the correct 16-byte signature.</summary>
    [TestMethod]
    public async Task ProtocolOneVerifySucceedsForTheCorrectSixteenByteSignature()
    {
        CtapPinUvAuthProtocol protocol = CreateProtocol(CtapPinUvAuthProtocolId.One);
        byte[] key = Convert.FromHexString(ProtocolOneSharedSecretHex);
        byte[] message = System.Text.Encoding.ASCII.GetBytes(MessageAscii);
        byte[] signature = Convert.FromHexString(ProtocolOneAuthenticateHex);

        bool isValid = await protocol.VerifyAsync(
            key, message, signature, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid);
    }

    /// <summary>
    /// CTAP 2.3 §6.5.6 line 6210-6217: <c>verify</c> requires the signature to be exactly 16 bytes - a
    /// 32-byte value, even one whose first 16 bytes are correct, must fail.
    /// </summary>
    [TestMethod]
    public async Task ProtocolOneVerifyRejectsAThirtyTwoByteSignature()
    {
        CtapPinUvAuthProtocol protocol = CreateProtocol(CtapPinUvAuthProtocolId.One);
        byte[] key = Convert.FromHexString(ProtocolOneSharedSecretHex);
        byte[] message = System.Text.Encoding.ASCII.GetBytes(MessageAscii);
        byte[] oversizedSignature = [.. Convert.FromHexString(ProtocolOneAuthenticateHex), .. new byte[16]];

        bool isValid = await protocol.VerifyAsync(
            key, message, oversizedSignature, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isValid);
    }

    /// <summary>Protocol one's <c>verify</c> must fail for a correctly-sized but incorrect 16-byte signature.</summary>
    [TestMethod]
    public async Task ProtocolOneVerifyRejectsAWrongSixteenByteSignature()
    {
        CtapPinUvAuthProtocol protocol = CreateProtocol(CtapPinUvAuthProtocolId.One);
        byte[] key = Convert.FromHexString(ProtocolOneSharedSecretHex);
        byte[] message = System.Text.Encoding.ASCII.GetBytes(MessageAscii);

        bool isValid = await protocol.VerifyAsync(
            key, message, new byte[16], BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isValid);
    }

    /// <summary>Protocol two's <c>verify</c> must succeed for the correct, full 32-byte signature.</summary>
    [TestMethod]
    public async Task ProtocolTwoVerifySucceedsForTheCorrectThirtyTwoByteSignature()
    {
        CtapPinUvAuthProtocol protocol = CreateProtocol(CtapPinUvAuthProtocolId.Two);
        byte[] sharedSecret = [.. Convert.FromHexString(ProtocolTwoHmacKeyHalfHex), .. Convert.FromHexString(ProtocolTwoAesKeyHalfHex)];
        byte[] message = System.Text.Encoding.ASCII.GetBytes(MessageAscii);
        byte[] signature = Convert.FromHexString(ProtocolTwoAuthenticateHex);

        bool isValid = await protocol.VerifyAsync(
            sharedSecret, message, signature, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid);
    }

    /// <summary>
    /// CTAP 2.3 §6.5.7 line 6270-6279: unlike protocol one, protocol two's <c>verify</c> never truncates -
    /// a 16-byte value, even one whose bytes are the correct signature's prefix, must fail.
    /// </summary>
    [TestMethod]
    public async Task ProtocolTwoVerifyRejectsATruncatedSixteenByteSignature()
    {
        CtapPinUvAuthProtocol protocol = CreateProtocol(CtapPinUvAuthProtocolId.Two);
        byte[] sharedSecret = [.. Convert.FromHexString(ProtocolTwoHmacKeyHalfHex), .. Convert.FromHexString(ProtocolTwoAesKeyHalfHex)];
        byte[] message = System.Text.Encoding.ASCII.GetBytes(MessageAscii);
        byte[] truncatedSignature = Convert.FromHexString(ProtocolTwoAuthenticateHex)[..16];

        bool isValid = await protocol.VerifyAsync(
            sharedSecret, message, truncatedSignature, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isValid);
    }

    /// <summary>
    /// A firewalled round trip over a freshly minted key pair on each side: the "authenticator"
    /// decapsulates against the "platform's" public key, and the "platform" decapsulates (using the
    /// same authenticator-side operation, since ECDH is symmetric) against the authenticator's public
    /// key - both must derive the identical shared secret, proving <see cref="CtapPinUvAuthProtocol.DecapsulateAsync"/>'s
    /// ECDH + <c>kdf</c> composition works end to end, not merely against a hardcoded Z.
    /// </summary>
    [TestMethod]
    [DataRow(CtapPinUvAuthProtocolId.One)]
    [DataRow(CtapPinUvAuthProtocolId.Two)]
    public async Task BothPartiesDecapsulateAgreeOnTheSharedSecret(CtapPinUvAuthProtocolId id)
    {
        CtapPinUvAuthProtocol protocol = CreateProtocol(id);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> authenticatorKeys =
            CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm.P256, Purpose.Exchange, BaseMemoryPool.Shared);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> platformKeys =
            CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm.P256, Purpose.Exchange, BaseMemoryPool.Shared);

        using PrivateKeyMemory authenticatorPrivateKey = authenticatorKeys.PrivateKey;
        using PublicKeyMemory authenticatorPublicKeyMemory = authenticatorKeys.PublicKey;
        using PrivateKeyMemory platformPrivateKey = platformKeys.PrivateKey;
        using PublicKeyMemory platformPublicKeyMemory = platformKeys.PublicKey;

        CoseKey authenticatorPublicKey = protocol.GetPublicKey(authenticatorPublicKeyMemory);
        CoseKey platformPublicKey = protocol.GetPublicKey(platformPublicKeyMemory);

        IMemoryOwner<byte> fromAuthenticatorSide = await protocol.DecapsulateAsync(
            authenticatorPrivateKey, platformPublicKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            IMemoryOwner<byte> fromPlatformSide = await protocol.DecapsulateAsync(
                platformPrivateKey, authenticatorPublicKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            try
            {
                Assert.IsTrue(fromAuthenticatorSide.Memory.Span.SequenceEqual(fromPlatformSide.Memory.Span),
                    "Both sides of the same ECDH exchange must derive byte-identical shared secrets.");
            }
            finally
            {
                fromPlatformSide.Memory.Span.Clear();
                fromPlatformSide.Dispose();
            }
        }
        finally
        {
            fromAuthenticatorSide.Memory.Span.Clear();
            fromAuthenticatorSide.Dispose();
        }
    }
}
