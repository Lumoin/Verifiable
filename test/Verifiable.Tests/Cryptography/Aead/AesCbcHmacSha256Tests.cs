using System.Buffers;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Microsoft;

namespace Verifiable.Tests.Cryptography.Aead;

/// <summary>
/// Tests for A128CBC-HS256 authenticated encryption per
/// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.2.3">RFC 7518 §5.2.3</see>,
/// pinned to the Appendix B.1 test vector. The decrypt path is vector-pinned directly;
/// the encrypt path generates a random IV and is pinned through the vector-validated
/// decrypt in the round-trip test.
/// </summary>
[TestClass]
internal sealed class AesCbcHmacSha256Tests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    //RFC 7518 Appendix B.1 vector: composite key K (MAC half first), plaintext P,
    //fixed IV, AAD A, expected ciphertext E and truncated HMAC tag T.
    private const string VectorKey =
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";

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
        "C80EDFA32DDF39D5EF00C0B468834279A2E46A1B8049F792F76BFE54B903A9C9" +
        "A94AC9B47AD2655C5F10F9AEF71427E2FC6F9B3F399A221489F16362C7032336" +
        "09D45AC69864E3321CF82935AC4096C86E133314C54019E8CA7980DFA4B9CF1B" +
        "384C486F3A54C51078158EE5D79DE59FBD34D848B3D69550A67646344427ADE5" +
        "4B8851FFB598F7F80074B9473C82E2DB";

    private const string VectorTag =
        "652C3FA36B0A7C5B3219FAB3A30BC1C4";


    [TestMethod]
    public async Task DecryptMatchesRfc7518AppendixB1Vector()
    {
        using SymmetricKeyMemory key = KeyFromHex(VectorKey);
        using Ciphertext ciphertext = CiphertextFromHex(VectorCiphertext);
        using Nonce iv = IvFromHex(VectorIv);
        using AuthenticationTag tag = TagFromHex(VectorTag);
        using AdditionalData aad = AadFromHex(VectorAad);

        using DecryptedContent decrypted = await MicrosoftKeyAgreementFunctions.AesCbcHmacSha256DecryptAsync(
            ciphertext, key, iv, tag, aad, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(VectorPlaintext, Convert.ToHexString(decrypted.AsReadOnlySpan()),
            "Decrypted plaintext must match the RFC 7518 Appendix B.1 vector.");
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
            using DecryptedContent _ = await MicrosoftKeyAgreementFunctions.AesCbcHmacSha256DecryptAsync(
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
            using DecryptedContent _ = await MicrosoftKeyAgreementFunctions.AesCbcHmacSha256DecryptAsync(
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
            using DecryptedContent _ = await MicrosoftKeyAgreementFunctions.AesCbcHmacSha256DecryptAsync(
                ciphertext, key, iv, tag, aad, Pool, TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task EncryptDecryptRoundTripRecoversPlaintext()
    {
        //A plaintext that is not a multiple of the AES block size pins the PKCS#7
        //padding round trip and the exact-length trim on decrypt.
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("Three is a magic number.");

        byte[] keyBytes = new byte[32];
        RandomNumberGenerator.Fill(keyBytes);
        using SymmetricKeyMemory encryptKey = KeyFromBytes(keyBytes);
        using SymmetricKeyMemory decryptKey = KeyFromBytes(keyBytes);
        CryptographicOperations.ZeroMemory(keyBytes);

        using AdditionalData encryptAad = AadFromHex(VectorAad);
        using AeadEncryptResult encrypted = await MicrosoftKeyAgreementFunctions.AesCbcHmacSha256EncryptAsync(
            plaintext, encryptKey, encryptAad, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(16, encrypted.Iv.AsReadOnlySpan(), "A128CBC-HS256 IV must be one AES block.");
        Assert.HasCount(16, encrypted.Tag.AsReadOnlySpan(), "A128CBC-HS256 tag must be half the HMAC-SHA-256 output.");
        Assert.HasCount(32, encrypted.Ciphertext.AsReadOnlySpan(),
            "PKCS#7 must pad the 24-byte plaintext to two full AES blocks.");

        using AdditionalData decryptAad = AadFromHex(VectorAad);
        using DecryptedContent decrypted = await MicrosoftKeyAgreementFunctions.AesCbcHmacSha256DecryptAsync(
            encrypted.Ciphertext, decryptKey, encrypted.Iv, encrypted.Tag, decryptAad, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(decrypted.AsReadOnlySpan().SequenceEqual(plaintext),
            "Round-tripped plaintext must be byte identical, with no padding residue.");
    }


    [TestMethod]
    public async Task WrongKeyLengthIsRejected()
    {
        //A 64-byte composite key is the A256CBC-HS512 shape; the A128 method must reject it.
        byte[] keyBytes = new byte[64];
        RandomNumberGenerator.Fill(keyBytes);
        using SymmetricKeyMemory wrongLengthKey = KeyFromBytes(keyBytes);
        CryptographicOperations.ZeroMemory(keyBytes);
        using AdditionalData aad = AadFromHex(VectorAad);

        await Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            using AeadEncryptResult _ = await MicrosoftKeyAgreementFunctions.AesCbcHmacSha256EncryptAsync(
                new byte[16], wrongLengthKey, aad, Pool, TestContext.CancellationToken).ConfigureAwait(false);
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
