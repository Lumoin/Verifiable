using System.Buffers;
using System.Security.Cryptography;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Microsoft;

namespace Verifiable.Tests.Cryptography.Aead;

/// <summary>
/// Tests for AES Key Wrap with a 192-bit key encryption key per
/// <see href="https://www.rfc-editor.org/rfc/rfc3394">RFC 3394</see> against the §4.2
/// (128-bit key data) and §4.4 (192-bit key data) test vectors, for both the Microsoft
/// (manual RFC 3394 over AES-ECB) and BouncyCastle (<c>AesWrapEngine</c>) implementations.
/// The wrap operation is deterministic, so vector equality pins both implementations byte
/// for byte.
/// </summary>
[TestClass]
internal sealed class AesKeyWrap192Tests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    //RFC 3394 §4.2: 128-bit key data wrapped with a 192-bit KEK.
    private const string Kek192 = "000102030405060708090A0B0C0D0E0F1011121314151617";
    private const string KeyData128 = "00112233445566778899AABBCCDDEEFF";
    private const string Wrapped128With192 = "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D";

    //RFC 3394 §4.4: 192-bit key data wrapped with a 192-bit KEK.
    private const string KeyData192 = "00112233445566778899AABBCCDDEEFF0001020304050607";
    private const string Wrapped192With192 = "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2";


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
    [DataRow("Microsoft")]
    [DataRow("BouncyCastle")]
    public async Task WrapMatchesRfc3394Section42Vector(string driver)
    {
        using SymmetricKeyMemory kek = KeyFromHex(Kek192);
        using SymmetricKeyMemory keyData = KeyFromHex(KeyData128);

        using Ciphertext wrapped = await WrapFor(driver)(
            kek, keyData, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(Wrapped128With192, Convert.ToHexString(wrapped.AsReadOnlySpan()),
            $"RFC 3394 §4.2 wrapped output must match the specification vector for '{driver}'.");
    }


    [TestMethod]
    [DataRow("Microsoft")]
    [DataRow("BouncyCastle")]
    public async Task UnwrapMatchesRfc3394Section42Vector(string driver)
    {
        using SymmetricKeyMemory kek = KeyFromHex(Kek192);

        using SymmetricKeyMemory unwrapped = await UnwrapFor(driver)(
            kek, Convert.FromHexString(Wrapped128With192), Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(KeyData128, Convert.ToHexString(unwrapped.AsReadOnlySpan()),
            $"RFC 3394 §4.2 unwrapped key data must match the specification vector for '{driver}'.");
    }


    [TestMethod]
    [DataRow("Microsoft")]
    [DataRow("BouncyCastle")]
    public async Task WrapUnwrapRoundTripSection44(string driver)
    {
        using SymmetricKeyMemory kek = KeyFromHex(Kek192);
        using SymmetricKeyMemory keyData = KeyFromHex(KeyData192);

        using Ciphertext wrapped = await WrapFor(driver)(
            kek, keyData, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(Wrapped192With192, Convert.ToHexString(wrapped.AsReadOnlySpan()),
            $"RFC 3394 §4.4 wrapped output must match the specification vector for '{driver}'.");

        byte[] wrappedBytes = Convert.FromHexString(Convert.ToHexString(wrapped.AsReadOnlySpan()));
        using SymmetricKeyMemory unwrapped = await UnwrapFor(driver)(
            kek, wrappedBytes, Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(KeyData192, Convert.ToHexString(unwrapped.AsReadOnlySpan()),
            $"RFC 3394 §4.4 unwrap must recover the original 192-bit key data for '{driver}'.");
    }


    [TestMethod]
    [DataRow("Microsoft")]
    [DataRow("BouncyCastle")]
    public async Task UnwrapWithWrongKekFailsIntegrityCheck(string driver)
    {
        //A single flipped KEK byte makes the recovered RFC 3394 §2.2.3 initial value mismatch.
        byte[] kekBytes = Convert.FromHexString(Kek192);
        kekBytes[0] ^= 0x01;
        using SymmetricKeyMemory wrongKek = KeyFromBytes(kekBytes);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
        {
            using SymmetricKeyMemory _ = await UnwrapFor(driver)(
                wrongKek, Convert.FromHexString(Wrapped192With192), Pool, TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    private static SymmetricKeyMemory KeyFromHex(string hex) => KeyFromBytes(Convert.FromHexString(hex));

    private static SymmetricKeyMemory KeyFromBytes(byte[] bytes)
    {
        IMemoryOwner<byte> owner = Pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);
        CryptographicOperations.ZeroMemory(bytes);

        return new SymmetricKeyMemory(owner, CryptoTags.AesKwKeyEncryptionKey);
    }
}
