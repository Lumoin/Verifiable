using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Known-answer tests for <see cref="Hkdf"/> against
/// <see href="https://www.rfc-editor.org/rfc/rfc5869">RFC 5869</see> Appendix A's SHA-256 test
/// vectors (test cases 1-3).
/// </summary>
/// <remarks>
/// The system under test routes through the project's registered HMAC primitive exactly as
/// <see cref="Kdfa"/>/<see cref="Kdfe"/> do (see <c>KdfaTests</c>/<c>KdfeTests</c> for the sibling
/// KDFs' own known-answer coverage); the test itself performs no cryptography.
/// </remarks>
[TestClass]
internal sealed class HkdfTests
{
    /// <summary>The MSTest-injected context; supplies <see cref="TestContext.CancellationToken"/> to every async call below.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>RFC 5869 §A.2 test case 2's 80-byte IKM, too long for inline DataRow readability alongside test cases 1/3.</summary>
    private const string TestCase2Ikm =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" +
        "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f";

    /// <summary>RFC 5869 §A.2 test case 2's 80-byte salt.</summary>
    private const string TestCase2Salt =
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f" +
        "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf";

    /// <summary>RFC 5869 §A.2 test case 2's 80-byte info.</summary>
    private const string TestCase2Info =
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    /// <summary>RFC 5869 §A.2 test case 2's expected 32-byte PRK (HKDF-Extract output).</summary>
    private const string TestCase2Prk =
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244";

    /// <summary>RFC 5869 §A.2 test case 2's expected 82-byte OKM (HKDF-Expand output).</summary>
    private const string TestCase2Okm =
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09" +
        "da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87";

    /// <summary>
    /// Verifies <see cref="Hkdf.ExtractAsync"/> alone against RFC 5869 §A.1/§A.2/§A.3's SHA-256 test cases 1-3.
    /// </summary>
    [TestMethod]
    //RFC 5869 §A.1 test case 1: basic test case with SHA-256.
    [DataRow("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c",
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")]
    //RFC 5869 §A.2 test case 2: SHA-256 with longer (80-byte) inputs.
    [DataRow(TestCase2Ikm, TestCase2Salt, TestCase2Prk)]
    //RFC 5869 §A.3 test case 3: SHA-256 with zero-length salt.
    [DataRow("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")]
    public async Task HkdfExtractMatchesKnownAnswer(string ikmHex, string saltHex, string expectedPrkHex)
    {
        using IMemoryOwner<byte> actual = await Hkdf.ExtractAsync(
            HashAlgorithmName.SHA256, Convert.FromHexString(saltHex), Convert.FromHexString(ikmHex),
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedPrkHex, Convert.ToHexStringLower(actual.Memory.Span[..(expectedPrkHex.Length / 2)]),
            "HKDF-Extract must match the RFC 5869 known-answer PRK.");
    }

    /// <summary>
    /// Verifies <see cref="Hkdf.ExpandAsync"/> alone (given the known PRK directly) against RFC 5869
    /// §A.1/§A.2/§A.3's SHA-256 test cases 1-3.
    /// </summary>
    [TestMethod]
    //RFC 5869 §A.1 test case 1.
    [DataRow("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "f0f1f2f3f4f5f6f7f8f9", 42,
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")]
    //RFC 5869 §A.2 test case 2.
    [DataRow(TestCase2Prk, TestCase2Info, 82, TestCase2Okm)]
    //RFC 5869 §A.3 test case 3: zero-length info.
    [DataRow("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", "", 42,
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")]
    public async Task HkdfExpandMatchesKnownAnswer(string prkHex, string infoHex, int outputLength, string expectedOkmHex)
    {
        using IMemoryOwner<byte> actual = await Hkdf.ExpandAsync(
            HashAlgorithmName.SHA256, Convert.FromHexString(prkHex), Convert.FromHexString(infoHex), outputLength,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedOkmHex, Convert.ToHexStringLower(actual.Memory.Span[..outputLength]),
            "HKDF-Expand must match the RFC 5869 known-answer OKM.");
    }

    /// <summary>
    /// Verifies the combined <see cref="Hkdf.DeriveAsync"/> (extract-then-expand in one call) against
    /// RFC 5869 §A.1/§A.2/§A.3's SHA-256 test cases 1-3.
    /// </summary>
    [TestMethod]
    //RFC 5869 §A.1 test case 1: the full extract-then-expand derivation in one call.
    [DataRow("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42,
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")]
    //RFC 5869 §A.2 test case 2.
    [DataRow(TestCase2Ikm, TestCase2Salt, TestCase2Info, 82, TestCase2Okm)]
    //RFC 5869 §A.3 test case 3: zero-length salt and info.
    [DataRow("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "", 42,
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")]
    public async Task HkdfDeriveMatchesKnownAnswer(string ikmHex, string saltHex, string infoHex, int outputLength, string expectedOkmHex)
    {
        using IMemoryOwner<byte> actual = await Hkdf.DeriveAsync(
            HashAlgorithmName.SHA256, Convert.FromHexString(saltHex), Convert.FromHexString(ikmHex),
            Convert.FromHexString(infoHex), outputLength, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedOkmHex, Convert.ToHexStringLower(actual.Memory.Span[..outputLength]),
            "The combined HKDF derivation must match the RFC 5869 known-answer OKM.");
    }

    /// <summary>A zero (or negative) requested output length must be rejected, never silently clamped.</summary>
    [TestMethod]
    public async Task NonPositiveOutputIsRejected()
    {
        await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(async () =>
            await Hkdf.ExpandAsync(HashAlgorithmName.SHA256, Convert.FromHexString(TestCase2Prk), ReadOnlyMemory<byte>.Empty, 0,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    /// <summary>
    /// RFC 5869 §2.3: L MUST NOT exceed 255 * HashLen (255 * 32 = 8160 for SHA-256) - the largest
    /// length HKDF-Expand's single-octet round counter can address.
    /// </summary>
    [TestMethod]
    public async Task OutputLongerThanTwoHundredFiftyFiveHashLensIsRejected()
    {
        await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(async () =>
            await Hkdf.ExpandAsync(HashAlgorithmName.SHA256, Convert.FromHexString(TestCase2Prk), ReadOnlyMemory<byte>.Empty, (255 * 32) + 1,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    /// <summary>
    /// CTAP 2.3 §6.5.7 (line 6229) warns that its <c>kdf(Z)</c> - two separate L=32 HKDF calls with
    /// different info labels, concatenated - "can NOT be equivalently performed using a single
    /// invocation with L=64". Proves the two constructions actually diverge: a single L=64 expansion's
    /// second 32-byte block is not the same computation as an independent L=32 expansion under a
    /// different info label, even though both expansions' first block coincides (both are
    /// <c>HMAC(PRK, info || 0x01)</c> under the L=32 call's own label).
    /// </summary>
    [TestMethod]
    public async Task ProtocolTwoTwoCallStructureDiffersFromSingleL64Call()
    {
        byte[] prk = Convert.FromHexString(TestCase2Prk);
        byte[] info = "CTAP2 HMAC key"u8.ToArray();

        using IMemoryOwner<byte> independentThirtyTwo = await Hkdf.ExpandAsync(
            HashAlgorithmName.SHA256, prk, info, 32, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using IMemoryOwner<byte> singleCallSixtyFour = await Hkdf.ExpandAsync(
            HashAlgorithmName.SHA256, prk, info, 64, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(independentThirtyTwo.Memory.Span[..32].SequenceEqual(singleCallSixtyFour.Memory.Span[..32]),
            "An independent L=32 expansion's T(1) must equal a single L=64 expansion's leading T(1) block - both are HMAC(PRK, info || 0x01).");

        using IMemoryOwner<byte> secondIndependentThirtyTwo = await Hkdf.ExpandAsync(
            HashAlgorithmName.SHA256, prk, "CTAP2 AES key"u8.ToArray(), 32, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(secondIndependentThirtyTwo.Memory.Span[..32].SequenceEqual(singleCallSixtyFour.Memory.Span[32..64]),
            "Protocol two's second HKDF call uses a distinct info label and is itself a fresh T(1) block, not the second T(2) block a single L=64 call under one info label would produce.");
    }
}
