using System.Buffers;
using System.Security.Cryptography;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Microsoft;

namespace Verifiable.Tests.Cryptography.Aead;

/// <summary>
/// Tests for AES Key Wrap per <see href="https://www.rfc-editor.org/rfc/rfc3394">RFC 3394</see>
/// against the §4 test vectors, for both the Microsoft (manual RFC 3394 over AES-ECB)
/// and BouncyCastle (<c>AesWrapEngine</c>) implementations. The wrap operation is
/// deterministic, so vector equality pins both implementations byte for byte.
/// </summary>
[TestClass]
internal sealed class AesKeyWrapTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    //RFC 3394 §4.1: 128-bit key data wrapped with a 128-bit KEK.
    private const string Kek128 = "000102030405060708090A0B0C0D0E0F";
    private const string KeyData128 = "00112233445566778899AABBCCDDEEFF";
    private const string Wrapped128With128 = "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5";

    //RFC 3394 §4.3: 128-bit key data wrapped with a 256-bit KEK.
    private const string Kek256 = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    private const string Wrapped128With256 = "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7";

    //RFC 3394 §4.6: 256-bit key data wrapped with a 256-bit KEK — the A256KW shape
    //DIDComm v2 uses to wrap an A256GCM content encryption key.
    private const string KeyData256 = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F";
    private const string Wrapped256With256 = "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21";


    private static KeyWrapDelegate WrapFor(string driver) => driver switch
    {
        "Microsoft" => MicrosoftKeyAgreementFunctions.AesKeyWrapAsync,
        "BouncyCastle" => BouncyCastleKeyAgreementFunctions.AesKeyWrapAsync,
        _ => throw new ArgumentException($"Unknown driver '{driver}'.", nameof(driver))
    };


    private static KeyUnwrapDelegate UnwrapFor(string driver) => driver switch
    {
        "Microsoft" => MicrosoftKeyAgreementFunctions.AesKeyUnwrapAsync,
        "BouncyCastle" => BouncyCastleKeyAgreementFunctions.AesKeyUnwrapAsync,
        _ => throw new ArgumentException($"Unknown driver '{driver}'.", nameof(driver))
    };


    [TestMethod]
    [DataRow("Microsoft", Kek128, KeyData128, Wrapped128With128)]
    [DataRow("Microsoft", Kek256, KeyData128, Wrapped128With256)]
    [DataRow("Microsoft", Kek256, KeyData256, Wrapped256With256)]
    [DataRow("BouncyCastle", Kek128, KeyData128, Wrapped128With128)]
    [DataRow("BouncyCastle", Kek256, KeyData128, Wrapped128With256)]
    [DataRow("BouncyCastle", Kek256, KeyData256, Wrapped256With256)]
    public async Task WrapMatchesRfc3394Vector(string driver, string kekHex, string keyDataHex, string expectedHex)
    {
        using SymmetricKeyMemory kek = KeyFromHex(kekHex);
        using SymmetricKeyMemory keyData = KeyFromHex(keyDataHex);

        using Ciphertext wrapped = await WrapFor(driver)(
            kek, keyData, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedHex, Convert.ToHexString(wrapped.AsReadOnlySpan()),
            $"RFC 3394 wrapped output must match the specification vector for '{driver}'.");
    }


    [TestMethod]
    [DataRow("Microsoft", Kek128, Wrapped128With128, KeyData128)]
    [DataRow("Microsoft", Kek256, Wrapped128With256, KeyData128)]
    [DataRow("Microsoft", Kek256, Wrapped256With256, KeyData256)]
    [DataRow("BouncyCastle", Kek128, Wrapped128With128, KeyData128)]
    [DataRow("BouncyCastle", Kek256, Wrapped128With256, KeyData128)]
    [DataRow("BouncyCastle", Kek256, Wrapped256With256, KeyData256)]
    public async Task UnwrapMatchesRfc3394Vector(string driver, string kekHex, string wrappedHex, string expectedKeyDataHex)
    {
        using SymmetricKeyMemory kek = KeyFromHex(kekHex);

        using SymmetricKeyMemory unwrapped = await UnwrapFor(driver)(
            kek, Convert.FromHexString(wrappedHex), Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedKeyDataHex, Convert.ToHexString(unwrapped.AsReadOnlySpan()),
            $"RFC 3394 unwrapped key data must match the specification vector for '{driver}'.");
    }


    [TestMethod]
    [DataRow("Microsoft")]
    [DataRow("BouncyCastle")]
    public async Task TamperedWrappedKeyFailsIntegrityCheck(string driver)
    {
        using SymmetricKeyMemory kek = KeyFromHex(Kek256);

        byte[] tampered = Convert.FromHexString(Wrapped256With256);
        tampered[tampered.Length - 1] ^= 0x01;

        await Assert.ThrowsAsync<CryptographicException>(async () =>
        {
            using SymmetricKeyMemory _ = await UnwrapFor(driver)(
                kek, tampered, Pool, TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    [TestMethod]
    [DataRow("Microsoft")]
    [DataRow("BouncyCastle")]
    public async Task WrongKeyEncryptionKeyFailsIntegrityCheck(string driver)
    {
        //The §4.1 KEK cannot unwrap the §4.3 output: the recovered RFC 3394 §2.2.3
        //initial value will not match.
        using SymmetricKeyMemory wrongKek = KeyFromHex(Kek128);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
        {
            using SymmetricKeyMemory _ = await UnwrapFor(driver)(
                wrongKek, Convert.FromHexString(Wrapped128With256), Pool, TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    [TestMethod]
    [DataRow("Microsoft")]
    [DataRow("BouncyCastle")]
    public async Task TooShortKeyDataIsRejected(string driver)
    {
        using SymmetricKeyMemory kek = KeyFromHex(Kek256);
        using SymmetricKeyMemory tooShort = KeyFromHex("0011223344556677");

        await Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            using Ciphertext _ = await WrapFor(driver)(
                kek, tooShort, Pool, TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    [TestMethod]
    [DataRow("Microsoft")]
    [DataRow("BouncyCastle")]
    public async Task TooShortWrappedKeyIsRejected(string driver)
    {
        using SymmetricKeyMemory kek = KeyFromHex(Kek256);

        await Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            using SymmetricKeyMemory _ = await UnwrapFor(driver)(
                kek, Convert.FromHexString("00112233445566778899AABBCCDDEEFF"), Pool, TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    private static SymmetricKeyMemory KeyFromHex(string hex)
    {
        byte[] bytes = Convert.FromHexString(hex);
        IMemoryOwner<byte> owner = Pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);
        CryptographicOperations.ZeroMemory(bytes);

        return new SymmetricKeyMemory(owner, CryptoTags.AesKwKeyEncryptionKey);
    }
}
