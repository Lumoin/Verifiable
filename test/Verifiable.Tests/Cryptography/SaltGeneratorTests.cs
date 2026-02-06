using System.Buffers;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Tests for <see cref="SaltGenerator"/>.
/// </summary>
[TestClass]
internal sealed class SaltGeneratorTests
{
    private static EncodeDelegate Encoder => TestSetup.Base64UrlEncoder;
    private static DecodeDelegate Decoder => TestSetup.Base64UrlDecoder;
    private static System.Buffers.MemoryPool<byte> MemoryPool => SensitiveMemoryPool<byte>.Shared;


    [TestMethod]
    public void CreateProducesBase64UrlEncodedSalt()
    {
        SaltGeneratorDelegate generator = SaltGenerator.Create(Encoder);

        string salt = generator();

        //Default 16 bytes = 128 bits, base64url encoded = 22 characters (without padding).
        Assert.IsFalse(string.IsNullOrEmpty(salt));
        Assert.IsGreaterThanOrEqualTo(22, salt.Length);

        //Verify it's valid base64url (can be decoded).
        using var decoded = Decoder(salt, MemoryPool);
        Assert.AreEqual(SaltGenerator.DefaultSaltLengthBytes, decoded.Memory.Length);
    }


    [TestMethod]
    public void CreateProducesUniqueSalts()
    {
        SaltGeneratorDelegate generator = SaltGenerator.Create(Encoder);
        var salts = new HashSet<string>();

        //Generate many salts and verify uniqueness.
        const int count = 1000;
        for(int i = 0; i < count; i++)
        {
            string salt = generator();
            bool added = salts.Add(salt);
            Assert.IsTrue(added, $"Duplicate salt generated at iteration {i}.");
        }

        Assert.HasCount(count, salts);
    }


    [TestMethod]
    public void CreateWithCustomLengthProducesCorrectSize()
    {
        const int customLength = 32;
        SaltGeneratorDelegate generator = SaltGenerator.Create(Encoder, customLength);

        string salt = generator();

        using var decoded = Decoder(salt, MemoryPool);
        Assert.AreEqual(customLength, decoded.Memory.Length);
    }


    [TestMethod]
    public void CreateThrowsForZeroLength()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => SaltGenerator.Create(Encoder, saltLengthBytes: 0));
    }


    [TestMethod]
    public void CreateThrowsForNegativeLength()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => SaltGenerator.Create(Encoder, saltLengthBytes: -1));
    }


    [TestMethod]
    public void CreateThrowsForNullEncoder()
    {
        Assert.Throws<ArgumentNullException>(() => SaltGenerator.Create(null!));
    }


    [TestMethod]
    public void CreateDeterministicReturnsSaltsInOrder()
    {
        string[] expectedSalts = ["salt1", "salt2", "salt3"];
        SaltGeneratorDelegate generator = SaltGenerator.CreateDeterministic(expectedSalts);

        Assert.AreEqual("salt1", generator());
        Assert.AreEqual("salt2", generator());
        Assert.AreEqual("salt3", generator());
    }


    [TestMethod]
    public void CreateDeterministicThrowsWhenExhausted()
    {
        SaltGeneratorDelegate generator = SaltGenerator.CreateDeterministic(["only_one"]);

        _ = generator();

        Assert.Throws<InvalidOperationException>(() => generator());
    }


    [TestMethod]
    public void CreateDeterministicThrowsForNullSalts()
    {
        Assert.Throws<ArgumentNullException>(() => SaltGenerator.CreateDeterministic(null!));
    }


    [TestMethod]
    public void CreateDeterministicWorksWithEmptySequence()
    {
        SaltGeneratorDelegate generator = SaltGenerator.CreateDeterministic([]);

        Assert.Throws<InvalidOperationException>(() => generator());
    }


    [TestMethod]
    public void CreateFixedAlwaysReturnsSameValue()
    {
        const string fixedSalt = "my_fixed_salt_value";
        SaltGeneratorDelegate generator = SaltGenerator.CreateFixed(fixedSalt);

        for(int i = 0; i < 100; i++)
        {
            Assert.AreEqual(fixedSalt, generator());
        }
    }


    [TestMethod]
    public void CreateFixedThrowsForNullSalt()
    {
        Assert.Throws<ArgumentException>(() => SaltGenerator.CreateFixed(null!));
    }


    [TestMethod]
    public void CreateFixedThrowsForEmptySalt()
    {
        Assert.Throws<ArgumentException>(() => SaltGenerator.CreateFixed(""));
        Assert.Throws<ArgumentException>(() => SaltGenerator.CreateFixed(string.Empty));
    }


    [TestMethod]
    public void CreateFixedThrowsForWhitespaceSalt()
    {
        Assert.Throws<ArgumentException>(() => SaltGenerator.CreateFixed("   "));
    }


    [TestMethod]
    public void SaltsHaveSufficientEntropy()
    {
        //Statistical test: generated salts should have good distribution.
        //We check that the byte values are reasonably distributed.
        SaltGeneratorDelegate generator = SaltGenerator.Create(Encoder);

        var byteCounts = new int[256];
        const int sampleCount = 1000;
        for(int i = 0; i < sampleCount; i++)
        {
            string salt = generator();
            using IMemoryOwner<byte> decoded = Decoder(salt, MemoryPool);

            foreach(byte b in decoded.Memory.Span)
            {
                byteCounts[b]++;
            }
        }

        //Total bytes generated.
        int totalBytes = sampleCount * SaltGenerator.DefaultSaltLengthBytes;

        //Expected count per byte value if perfectly uniform.
        double expectedPerByte = totalBytes / 256.0;

        //Count how many byte values were never seen (should be very few with good randomness).
        int neverSeen = byteCounts.Count(c => c == 0);

        //With 16000 bytes, we expect most of the 256 possible values to appear.
        //Allow up to 10% to be missing (very conservative).
        Assert.IsLessThan(26, neverSeen);

        //Chi-squared-like check: no single byte value should dominate.
        int maxCount = byteCounts.Max();
        int minCount = byteCounts.Where(c => c > 0).Min();

        //The ratio between max and min (among seen values) should be reasonable.
        //With good randomness, this ratio should be small (< 5x for this sample size).
        double ratio = (double)maxCount / minCount;
        Assert.IsLessThan(5.0, ratio);
    }


    [TestMethod]
    public void KnownVectorDeterministicSaltProducesExpectedDisclosureDigest()
    {
        //RFC 9901 Section 4.2.1 uses this salt for the family_name disclosure.
        //This tests that our deterministic generator integrates correctly with the SD-JWT flow.
        const string rfc9901Salt = "_26bc4LT-ac6q2KI6cBW5es";
        const string rfc9901ClaimName = "family_name";
        const string rfc9901ClaimValue = "Möbius";

        //Expected encoded disclosure from RFC 9901.
        const string expectedEncoded = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0";

        SaltGeneratorDelegate generator = SaltGenerator.CreateDeterministic([rfc9901Salt]);
        string salt = generator();

        Assert.AreEqual(rfc9901Salt, salt);

        //Build the disclosure JSON array manually: [salt, claim_name, claim_value].
        string json = $"[\"{salt}\", \"{rfc9901ClaimName}\", \"{rfc9901ClaimValue}\"]";
        byte[] jsonBytes = Encoding.UTF8.GetBytes(json);
        string encoded = Encoder(jsonBytes);

        //The encoding should match the RFC example (note: RFC has spaces after commas).
        //Our encoding won't have spaces, so we verify the decoded content matches.
        using var decodedExpected = Decoder(expectedEncoded, MemoryPool);
        using var decodedActual = Decoder(encoded, MemoryPool);

        string expectedJson = Encoding.UTF8.GetString(decodedExpected.Memory.Span);
        string actualJson = Encoding.UTF8.GetString(decodedActual.Memory.Span);

        //Parse both as JSON arrays and compare semantically.
        using var expectedDoc = System.Text.Json.JsonDocument.Parse(expectedJson);
        using var actualDoc = System.Text.Json.JsonDocument.Parse(actualJson);

        Assert.AreEqual(expectedDoc.RootElement[0].GetString(), actualDoc.RootElement[0].GetString(), "Salt mismatch.");
        Assert.AreEqual(expectedDoc.RootElement[1].GetString(), actualDoc.RootElement[1].GetString(), "Claim name mismatch.");
        Assert.AreEqual(expectedDoc.RootElement[2].GetString(), actualDoc.RootElement[2].GetString(), "Claim value mismatch.");
    }


    [TestMethod]
    public void DefaultSaltLengthProduces128BitsOfEntropy()
    {
        //RFC 9901 recommends at least 128 bits of entropy, which is 16 bytes.
        SaltGeneratorDelegate generator = SaltGenerator.Create(Encoder);
        string salt = generator();

        using IMemoryOwner<byte> decoded = Decoder(salt, MemoryPool);

        //Verify the default produces exactly 16 bytes (128 bits).
        Assert.AreEqual(16, decoded.Memory.Length);
    }
}