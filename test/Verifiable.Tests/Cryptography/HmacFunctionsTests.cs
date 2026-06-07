using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Microsoft;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Tests for <see cref="MicrosoftHmacFunctions"/> using RFC 4231 test vectors.
/// </summary>
[TestClass]
internal sealed class HmacFunctionsTests
{
    public TestContext TestContext { get; set; } = null!;

    //RFC 4231 Test Case 1.
    private static readonly byte[] TestCase1Key = Enumerable.Repeat((byte)0x0b, 20).ToArray();
    private static readonly byte[] TestCase1Data = "Hi There"u8.ToArray();
    private const string TestCase1HmacSha256Hex =
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

    //RFC 4231 Test Case 2.
    private static readonly byte[] TestCase2Key = "Jefe"u8.ToArray();
    private static readonly byte[] TestCase2Data = "what do ya want for nothing?"u8.ToArray();
    private const string TestCase2HmacSha256Hex =
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    private const string TestCase2HmacSha384Hex =
        "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649";
    private const string TestCase2HmacSha512Hex =
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";


    [TestMethod]
    public async Task ComputeHmacRfc4231TestCase1Sha256()
    {
        (HmacValue Result, CryptoEvent? Event) outcome = await MicrosoftHmacFunctions.ComputeHmacAsync(
            TestCase1Data, TestCase1Key, 32, CryptoTags.HmacSha256Value,
            SensitiveMemoryPool<byte>.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);

        using HmacValue result = outcome.Result;
        string actualHex = Convert.ToHexStringLower(result.AsReadOnlySpan());
        Assert.AreEqual(TestCase1HmacSha256Hex, actualHex);
        Assert.IsNotNull(outcome.Event);
    }


    [TestMethod]
    public async Task ComputeHmacRfc4231TestCase2Sha256()
    {
        (HmacValue Result, CryptoEvent? Event) outcome = await MicrosoftHmacFunctions.ComputeHmacAsync(
            TestCase2Data, TestCase2Key, 32, CryptoTags.HmacSha256Value,
            SensitiveMemoryPool<byte>.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);

        using HmacValue result = outcome.Result;
        Assert.AreEqual(TestCase2HmacSha256Hex, Convert.ToHexStringLower(result.AsReadOnlySpan()));
    }


    [TestMethod]
    public async Task ComputeHmacRfc4231TestCase2Sha384()
    {
        (HmacValue Result, CryptoEvent? Event) outcome = await MicrosoftHmacFunctions.ComputeHmacAsync(
            TestCase2Data, TestCase2Key, 48, CryptoTags.HmacSha384Value,
            SensitiveMemoryPool<byte>.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);

        using HmacValue result = outcome.Result;
        Assert.AreEqual(TestCase2HmacSha384Hex, Convert.ToHexStringLower(result.AsReadOnlySpan()));
    }


    [TestMethod]
    public async Task ComputeHmacRfc4231TestCase2Sha512()
    {
        (HmacValue Result, CryptoEvent? Event) outcome = await MicrosoftHmacFunctions.ComputeHmacAsync(
            TestCase2Data, TestCase2Key, 64, CryptoTags.HmacSha512Value,
            SensitiveMemoryPool<byte>.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);

        using HmacValue result = outcome.Result;
        Assert.AreEqual(TestCase2HmacSha512Hex, Convert.ToHexStringLower(result.AsReadOnlySpan()));
    }


    [TestMethod]
    public async Task VerifyHmacAcceptsCorrectMac()
    {
        byte[] expectedMac = Convert.FromHexString(TestCase1HmacSha256Hex);

        (bool IsValid, CryptoEvent? Event) outcome = await MicrosoftHmacFunctions.VerifyHmacAsync(
            TestCase1Data, TestCase1Key, expectedMac, CryptoTags.HmacSha256Value,
            SensitiveMemoryPool<byte>.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsValid);
        Assert.IsInstanceOfType<HmacVerifiedEvent>(outcome.Event);
        Assert.AreEqual(VerificationOutcome.Valid, ((HmacVerifiedEvent)outcome.Event!).Outcome);
    }


    [TestMethod]
    public async Task VerifyHmacRejectsTamperedMac()
    {
        byte[] tampered = Convert.FromHexString(TestCase1HmacSha256Hex);
        tampered[0] ^= 0xff;

        (bool IsValid, CryptoEvent? Event) outcome = await MicrosoftHmacFunctions.VerifyHmacAsync(
            TestCase1Data, TestCase1Key, tampered, CryptoTags.HmacSha256Value,
            SensitiveMemoryPool<byte>.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsValid);
        Assert.AreEqual(VerificationOutcome.Invalid, ((HmacVerifiedEvent)outcome.Event!).Outcome);
    }


    [TestMethod]
    public async Task VerifyHmacRejectsWrongKey()
    {
        byte[] expectedMac = Convert.FromHexString(TestCase1HmacSha256Hex);
        byte[] wrongKey = new byte[20];
        RandomNumberGenerator.Fill(wrongKey);

        (bool IsValid, CryptoEvent? Event) outcome = await MicrosoftHmacFunctions.VerifyHmacAsync(
            TestCase1Data, wrongKey, expectedMac, CryptoTags.HmacSha256Value,
            SensitiveMemoryPool<byte>.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsValid);
    }


    [TestMethod]
    public async Task TagWithoutHashAlgorithmNameThrows()
    {
        Tag emptyTag = Tag.Empty;

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            _ = await MicrosoftHmacFunctions.ComputeHmacAsync(
                TestCase1Data, TestCase1Key, 32, emptyTag,
                SensitiveMemoryPool<byte>.Shared, null, TestContext.CancellationToken)
                .ConfigureAwait(false)).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task ComputeThenVerifyRoundTripsForAllSupportedSizes()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] message = Encoding.UTF8.GetBytes("round-trip message");

        foreach((Tag tag, int outputLength) in new[]
        {
            (CryptoTags.HmacSha256Value, 32),
            (CryptoTags.HmacSha384Value, 48),
            (CryptoTags.HmacSha512Value, 64),
        })
        {
            (HmacValue Result, CryptoEvent? _) computed = await MicrosoftHmacFunctions.ComputeHmacAsync(
                message, key, outputLength, tag, SensitiveMemoryPool<byte>.Shared, null,
                TestContext.CancellationToken).ConfigureAwait(false);
            using HmacValue mac = computed.Result;

            (bool IsValid, CryptoEvent? _) verified = await MicrosoftHmacFunctions.VerifyHmacAsync(
                message, key, mac.AsReadOnlyMemory(), tag, SensitiveMemoryPool<byte>.Shared,
                null, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(verified.IsValid, $"Round-trip must succeed for {tag}.");
        }
    }
}
