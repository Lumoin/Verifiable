using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Tests for <see cref="MicrosoftHmacFunctions"/> using RFC 4231 test vectors.
/// </summary>
[TestClass]
internal sealed class HmacFunctionsTests
{
    public TestContext TestContext { get; set; } = null!;

    //RFC 4231 Test Case 1.
    private static byte[] TestCase1Key { get; } = Enumerable.Repeat((byte)0x0b, 20).ToArray();
    private static byte[] TestCase1Data { get; } = "Hi There"u8.ToArray();
    private const string TestCase1HmacSha256Hex =
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

    //RFC 4231 Test Case 2.
    private static byte[] TestCase2Key { get; } = "Jefe"u8.ToArray();
    private static byte[] TestCase2Data { get; } = "what do ya want for nothing?"u8.ToArray();
    private const string TestCase2HmacSha256Hex =
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    private const string TestCase2HmacSha384Hex =
        "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649";
    private const string TestCase2HmacSha512Hex =
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";


    [TestMethod]
    public async Task ComputeHmacRfc4231TestCase1Sha256()
    {
        (HmacValue Result, CryptoEvent? Event) = await MicrosoftHmacFunctions.ComputeHmacAsync(TestCase1Data, TestCase1Key, 32, CryptoTags.HmacSha256Value, BaseMemoryPool.Shared, new FakeTimeProvider(TestClock.CanonicalEpoch), null, TestContext.CancellationToken).ConfigureAwait(false);

        using HmacValue result = Result;
        string actualHex = Convert.ToHexStringLower(result.AsReadOnlySpan());
        Assert.AreEqual(TestCase1HmacSha256Hex, actualHex);
        Assert.IsNotNull(Event);
    }


    [TestMethod]
    public async Task ComputeHmacRfc4231TestCase2Sha256()
    {
        (HmacValue Result, _) = await MicrosoftHmacFunctions.ComputeHmacAsync(TestCase2Data, TestCase2Key, 32, CryptoTags.HmacSha256Value, BaseMemoryPool.Shared, new FakeTimeProvider(TestClock.CanonicalEpoch), null, TestContext.CancellationToken).ConfigureAwait(false);

        using HmacValue result = Result;
        Assert.AreEqual(TestCase2HmacSha256Hex, Convert.ToHexStringLower(result.AsReadOnlySpan()));
    }


    [TestMethod]
    public async Task ComputeHmacRfc4231TestCase2Sha384()
    {
        (HmacValue Result, _) = await MicrosoftHmacFunctions.ComputeHmacAsync(TestCase2Data, TestCase2Key, 48, CryptoTags.HmacSha384Value, BaseMemoryPool.Shared, new FakeTimeProvider(TestClock.CanonicalEpoch), null, TestContext.CancellationToken).ConfigureAwait(false);

        using HmacValue result = Result;
        Assert.AreEqual(TestCase2HmacSha384Hex, Convert.ToHexStringLower(result.AsReadOnlySpan()));
    }


    [TestMethod]
    public async Task ComputeHmacRfc4231TestCase2Sha512()
    {
        (HmacValue Result, _) = await MicrosoftHmacFunctions.ComputeHmacAsync(TestCase2Data, TestCase2Key, 64, CryptoTags.HmacSha512Value, BaseMemoryPool.Shared, new FakeTimeProvider(TestClock.CanonicalEpoch), null, TestContext.CancellationToken).ConfigureAwait(false);

        using HmacValue result = Result;
        Assert.AreEqual(TestCase2HmacSha512Hex, Convert.ToHexStringLower(result.AsReadOnlySpan()));
    }


    [TestMethod]
    public async Task VerifyHmacAcceptsCorrectMac()
    {
        byte[] expectedMac = Convert.FromHexString(TestCase1HmacSha256Hex);

        (bool IsValid, CryptoEvent? Event) = await MicrosoftHmacFunctions.VerifyHmacAsync(TestCase1Data, TestCase1Key, expectedMac, CryptoTags.HmacSha256Value, BaseMemoryPool.Shared, new FakeTimeProvider(TestClock.CanonicalEpoch), null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(IsValid);
        _ = Assert.IsInstanceOfType<HmacVerifiedEvent>(Event);
        Assert.AreEqual(VerificationOutcome.Valid, ((HmacVerifiedEvent)Event).Outcome);
    }


    [TestMethod]
    public async Task VerifyHmacRejectsTamperedMac()
    {
        byte[] tampered = Convert.FromHexString(TestCase1HmacSha256Hex);
        tampered[0] ^= 0xff;

        (bool IsValid, CryptoEvent? Event) = await MicrosoftHmacFunctions.VerifyHmacAsync(TestCase1Data, TestCase1Key, tampered, CryptoTags.HmacSha256Value, BaseMemoryPool.Shared, new FakeTimeProvider(TestClock.CanonicalEpoch), null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(IsValid);
        Assert.AreEqual(VerificationOutcome.Invalid, ((HmacVerifiedEvent)Event!).Outcome);
    }


    [TestMethod]
    public async Task VerifyHmacRejectsWrongKey()
    {
        byte[] expectedMac = Convert.FromHexString(TestCase1HmacSha256Hex);
        byte[] wrongKey = new byte[20];
        RandomNumberGenerator.Fill(wrongKey);
        (bool IsValid, _) = await MicrosoftHmacFunctions.VerifyHmacAsync(TestCase1Data, wrongKey, expectedMac, CryptoTags.HmacSha256Value, BaseMemoryPool.Shared, new FakeTimeProvider(TestClock.CanonicalEpoch), null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(IsValid);
    }


    [TestMethod]
    public async Task TagWithoutHashAlgorithmNameThrows()
    {
        Tag emptyTag = Tag.Empty;

        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            _ = await MicrosoftHmacFunctions.ComputeHmacAsync(TestCase1Data, TestCase1Key, 32, emptyTag, BaseMemoryPool.Shared, new FakeTimeProvider(TestClock.CanonicalEpoch), null, TestContext.CancellationToken)
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
            (HmacValue Result, CryptoEvent? _) = await MicrosoftHmacFunctions.ComputeHmacAsync(message, key, outputLength, tag, BaseMemoryPool.Shared, new FakeTimeProvider(TestClock.CanonicalEpoch), null, TestContext.CancellationToken).ConfigureAwait(false);
            using HmacValue mac = Result;

            (bool isValid, CryptoEvent? _) = await MicrosoftHmacFunctions.VerifyHmacAsync(message, key, mac.AsReadOnlyMemory(), tag, BaseMemoryPool.Shared, new FakeTimeProvider(TestClock.CanonicalEpoch), null, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(isValid, $"Round-trip must succeed for {tag}.");
        }
    }
}
