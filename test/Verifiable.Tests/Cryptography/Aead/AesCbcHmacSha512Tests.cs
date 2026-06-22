using System.Buffers;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Microsoft;

namespace Verifiable.Tests.Cryptography.Aead;

/// <summary>
/// Tests for A256CBC-HS512 authenticated encryption per
/// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.2.5">RFC 7518 §5.2.5</see>,
/// pinned to the Appendix B.3 test vector. The decrypt path is vector-pinned directly;
/// the encrypt path generates a random IV and is pinned through the vector-validated
/// decrypt in the round-trip tests.
/// </summary>
[TestClass]
internal sealed class AesCbcHmacSha512Tests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    //RFC 7518 Appendix B.3 vector: composite key K (MAC half first), plaintext P,
    //fixed IV, AAD A, expected ciphertext E and truncated HMAC tag T.
    private const string VectorKey =
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
        "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F";

    private const string VectorPlaintext =
        "41206369706865722073797374656D206D757374206E6F742062652072657175" +
        "6972656420746F206265207365637265742C20616E64206974206D7573742062" +
        "652061626C6520746F2066616C6C20696E746F207468652068616E6473206F66" +
        "2074686520656E656D7920776974686F757420696E636F6E76656E69656E6365";

    private const string VectorIv = "1AF38C2DC2B96FFDD86694092341BC04";

    private const string VectorAad =
        "546865207365636F6E64207072696E6369706C65206F66204175677573746520" +
        "4B6572636B686F666673";

    private const string VectorCiphertext =
        "4AFFAAADB78C31C5DA4B1B590D10FFBD3DD8D5D302423526912DA037ECBCC7BD" +
        "822C301DD67C373BCCB584AD3E9279C2E6D12A1374B77F077553DF829410446B" +
        "36EBD97066296AE6427EA75C2E0846A11A09CCF5370DC80BFECBAD28C73F09B3" +
        "A3B75E662A2594410AE496B2E2E6609E31E6E02CC837F053D21F37FF4F51950B" +
        "BE2638D09DD7A4930930806D0703B1F6";

    private const string VectorTag =
        "4DD3B4C088A7F45C216839645B2012BF2E6269A8C56A816DBC1B267761955BC5";


    [TestMethod]
    public async Task DecryptMatchesRfc7518AppendixB3Vector()
    {
        using SymmetricKeyMemory key = KeyFromHex(VectorKey);
        using Ciphertext ciphertext = CiphertextFromHex(VectorCiphertext);
        using Nonce iv = IvFromHex(VectorIv);
        using AuthenticationTag tag = TagFromHex(VectorTag);
        using AdditionalData aad = AadFromHex(VectorAad);

        using DecryptedContent decrypted = await MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync(
            ciphertext, key, iv, tag, aad, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(VectorPlaintext, Convert.ToHexString(decrypted.AsReadOnlySpan()),
            "Decrypted plaintext must match the RFC 7518 Appendix B.3 vector.");
    }


    [TestMethod]
    public async Task TamperedTagFailsAuthentication()
    {
        using SymmetricKeyMemory key = KeyFromHex(VectorKey);
        using Ciphertext ciphertext = CiphertextFromHex(VectorCiphertext);
        using Nonce iv = IvFromHex(VectorIv);
        using AdditionalData aad = AadFromHex(VectorAad);

        byte[] tamperedTag = Convert.FromHexString(VectorTag);
        tamperedTag[0] ^= 0x01;
        using AuthenticationTag tag = TagFromBytes(tamperedTag);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
        {
            using DecryptedContent _ = await MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync(
                ciphertext, key, iv, tag, aad, Pool, TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task TamperedCiphertextFailsAuthentication()
    {
        using SymmetricKeyMemory key = KeyFromHex(VectorKey);
        using Nonce iv = IvFromHex(VectorIv);
        using AuthenticationTag tag = TagFromHex(VectorTag);
        using AdditionalData aad = AadFromHex(VectorAad);

        byte[] tamperedCiphertext = Convert.FromHexString(VectorCiphertext);
        tamperedCiphertext[^1] ^= 0x01;
        IMemoryOwner<byte> owner = Pool.Rent(tamperedCiphertext.Length);
        tamperedCiphertext.CopyTo(owner.Memory.Span);
        using Ciphertext ciphertext = new(owner, CryptoTags.AesCbcHmacCiphertext);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
        {
            using DecryptedContent _ = await MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync(
                ciphertext, key, iv, tag, aad, Pool, TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task TamperedAdditionalDataFailsAuthentication()
    {
        using SymmetricKeyMemory key = KeyFromHex(VectorKey);
        using Ciphertext ciphertext = CiphertextFromHex(VectorCiphertext);
        using Nonce iv = IvFromHex(VectorIv);
        using AuthenticationTag tag = TagFromHex(VectorTag);

        byte[] tamperedAad = Convert.FromHexString(VectorAad);
        tamperedAad[0] ^= 0x01;
        using AdditionalData aad = AadFromBytes(tamperedAad);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
        {
            using DecryptedContent _ = await MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync(
                ciphertext, key, iv, tag, aad, Pool, TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task EncryptDecryptRoundTripRecoversPlaintext()
    {
        //A plaintext that is not a multiple of the AES block size pins the PKCS#7
        //padding round trip and the exact-length trim on decrypt.
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("Three is a magic number.");

        byte[] keyBytes = new byte[64];
        RandomNumberGenerator.Fill(keyBytes);
        using SymmetricKeyMemory encryptKey = KeyFromBytes(keyBytes);
        using SymmetricKeyMemory decryptKey = KeyFromBytes(keyBytes);
        CryptographicOperations.ZeroMemory(keyBytes);

        using AdditionalData encryptAad = AadFromHex(VectorAad);
        using AeadEncryptResult encrypted = await MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync(
            plaintext, encryptKey, encryptAad, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(16, encrypted.Iv.AsReadOnlySpan().Length, "A256CBC-HS512 IV must be one AES block.");
        Assert.AreEqual(32, encrypted.Tag.AsReadOnlySpan().Length, "A256CBC-HS512 tag must be half the HMAC-SHA-512 output.");
        Assert.AreEqual(32, encrypted.Ciphertext.AsReadOnlySpan().Length,
            "PKCS#7 must pad the 24-byte plaintext to two full AES blocks.");

        using AdditionalData decryptAad = AadFromHex(VectorAad);
        using DecryptedContent decrypted = await MicrosoftKeyAgreementFunctions.AesCbcHmacSha512DecryptAsync(
            encrypted.Ciphertext, decryptKey, encrypted.Iv, encrypted.Tag, decryptAad, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(decrypted.AsReadOnlySpan().SequenceEqual(plaintext),
            "Round-tripped plaintext must be byte identical, with no padding residue.");
    }


    [TestMethod]
    public async Task WrongKeyLengthIsRejected()
    {
        using SymmetricKeyMemory tooShortKey = KeyFromHex(VectorKey[..64]);
        using AdditionalData aad = AadFromHex(VectorAad);

        await Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            using AeadEncryptResult _ = await MicrosoftKeyAgreementFunctions.AesCbcHmacSha512EncryptAsync(
                new byte[16], tooShortKey, aad, Pool, TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    private static SymmetricKeyMemory KeyFromHex(string hex) => KeyFromBytes(Convert.FromHexString(hex));

    private static SymmetricKeyMemory KeyFromBytes(ReadOnlySpan<byte> bytes)
    {
        IMemoryOwner<byte> owner = Pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new SymmetricKeyMemory(owner, CryptoTags.AesCbcHmacCek);
    }

    private static Ciphertext CiphertextFromHex(string hex)
    {
        byte[] bytes = Convert.FromHexString(hex);
        IMemoryOwner<byte> owner = Pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new Ciphertext(owner, CryptoTags.AesCbcHmacCiphertext);
    }

    private static Nonce IvFromHex(string hex)
    {
        byte[] bytes = Convert.FromHexString(hex);
        IMemoryOwner<byte> owner = Pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new Nonce(owner, CryptoTags.AesCbcHmacIv);
    }

    private static AuthenticationTag TagFromHex(string hex) => TagFromBytes(Convert.FromHexString(hex));

    private static AuthenticationTag TagFromBytes(ReadOnlySpan<byte> bytes)
    {
        IMemoryOwner<byte> owner = Pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new AuthenticationTag(owner, CryptoTags.AesCbcHmacAuthTag);
    }

    private static AdditionalData AadFromHex(string hex) => AadFromBytes(Convert.FromHexString(hex));

    private static AdditionalData AadFromBytes(ReadOnlySpan<byte> bytes)
    {
        IMemoryOwner<byte> owner = Pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new AdditionalData(owner, CryptoTags.AesCbcHmacAad);
    }
}
