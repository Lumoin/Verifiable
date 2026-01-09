using System.Formats.Cbor;
using System.Security.Cryptography;
using Verifiable.Cbor;
using Verifiable.JCose.Sd;

namespace Verifiable.Tests.DataIntegrity;

/// <summary>
/// End-to-end tests for SD-CWT (Selective Disclosure CBOR Web Tokens).
/// </summary>
/// <remarks>
/// <para>
/// Tests demonstrate the SD-CWT format as specified by IETF SPICE:
/// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html"/>.
/// </para>
/// <para>
/// Based on W3C VC Data Model 2.0 Example 8:
/// <see href="https://www.w3.org/TR/vc-data-model-2.0/#example-expanded-use-of-the-issuer-property"/>.
/// </para>
/// </remarks>
[TestClass]
public class SdCwtEndToEndTests
{
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Tests creating and parsing an SD-CWT disclosure for an object property.
    /// </summary>
    [TestMethod]
    public void ObjectPropertyDisclosureRoundTrips()
    {
        //Arrange - Create disclosure for issuer.name claim.
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        SdDisclosure disclosure = SdDisclosure.CreateProperty(salt, "name", "Example University");

        //Act - Serialize to CBOR and parse back.
        byte[] cborBytes = SdCwtSerializer.SerializeDisclosure(disclosure);
        SdDisclosure parsed = SdCwtSerializer.ParseDisclosure(cborBytes);

        //Assert - Round-trip preserves data.
        Assert.IsFalse(parsed.IsArrayElement);
        Assert.IsTrue(parsed.IsObjectProperty);
        Assert.AreEqual("name", parsed.ClaimName);
        Assert.AreEqual("Example University", parsed.ClaimValue);
        Assert.IsTrue(parsed.Salt.Span.SequenceEqual(salt));

        //Debug output.
        TestContext.WriteLine($"Salt: {Convert.ToHexString(salt)}");
        TestContext.WriteLine($"CBOR: {Convert.ToHexString(cborBytes)}");
    }


    /// <summary>
    /// Tests creating and parsing an SD-CWT disclosure for an array element.
    /// </summary>
    [TestMethod]
    public void ArrayElementDisclosureRoundTrips()
    {
        //Arrange - Create disclosure for a type array element.
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        SdDisclosure disclosure = SdDisclosure.CreateArrayElement(salt, "ExampleDegreeCredential");

        //Act - Serialize and parse.
        byte[] cborBytes = SdCwtSerializer.SerializeDisclosure(disclosure);
        SdDisclosure parsed = SdCwtSerializer.ParseDisclosure(cborBytes);

        //Assert.
        Assert.IsTrue(parsed.IsArrayElement);
        Assert.IsFalse(parsed.IsObjectProperty);
        Assert.IsNull(parsed.ClaimName);
        Assert.AreEqual("ExampleDegreeCredential", parsed.ClaimValue);

        TestContext.WriteLine($"CBOR: {Convert.ToHexString(cborBytes)}");
    }


    /// <summary>
    /// Tests disclosure with nested object value.
    /// </summary>
    [TestMethod]
    public void NestedObjectValueDisclosureRoundTrips()
    {
        //Arrange - Create disclosure for credentialSubject with nested degree.
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        var credentialSubject = new Dictionary<string, object?>
        {
            ["id"] = "did:example:ebfeb1f712ebc6f1c276e12ec21",
            ["degree"] = new Dictionary<string, object?>
            {
                ["type"] = "ExampleBachelorDegree",
                ["name"] = "Bachelor of Science and Arts"
            }
        };
        SdDisclosure disclosure = SdDisclosure.CreateProperty(salt, "credentialSubject", credentialSubject);

        //Act - Serialize and parse.
        byte[] cborBytes = SdCwtSerializer.SerializeDisclosure(disclosure);
        SdDisclosure parsed = SdCwtSerializer.ParseDisclosure(cborBytes);

        //Assert - Verify nested structure preserved.
        Assert.AreEqual("credentialSubject", parsed.ClaimName);
        Assert.IsInstanceOfType<Dictionary<object, object?>>(parsed.ClaimValue);

        TestContext.WriteLine($"CBOR: {Convert.ToHexString(cborBytes)}");
    }


    /// <summary>
    /// Tests hash computation produces expected lengths.
    /// </summary>
    [TestMethod]
    public void DisclosureDigestProducesCorrectLength()
    {
        //Arrange - Create disclosure with known salt.
        byte[] salt = new byte[16];
        Array.Fill(salt, (byte)0xAB);
        SdDisclosure disclosure = SdDisclosure.CreateProperty(salt, "name", "Test");
        byte[] cborBytes = SdCwtSerializer.SerializeDisclosure(disclosure);

        //Act - Compute digests with different algorithms.
        byte[] sha256Digest = SdCwtSerializer.ComputeDisclosureDigest(cborBytes, "sha-256");
        byte[] sha384Digest = SdCwtSerializer.ComputeDisclosureDigest(cborBytes, "sha-384");
        byte[] sha512Digest = SdCwtSerializer.ComputeDisclosureDigest(cborBytes, "sha-512");

        //Assert - Verify digest lengths.
        Assert.HasCount(32, sha256Digest);
        Assert.HasCount(48, sha384Digest);
        Assert.HasCount(64, sha512Digest);

        //Verify deterministic.
        byte[] sha256Digest2 = SdCwtSerializer.ComputeDisclosureDigest(cborBytes, "sha-256");
        Assert.IsTrue(sha256Digest.SequenceEqual(sha256Digest2), "Digest should be deterministic.");

        TestContext.WriteLine($"SHA-256: {Convert.ToHexString(sha256Digest)}");
        TestContext.WriteLine($"SHA-384: {Convert.ToHexString(sha384Digest)}");
        TestContext.WriteLine($"SHA-512: {Convert.ToHexString(sha512Digest)}");
    }


    /// <summary>
    /// Tests that CBOR encoding is deterministic (canonical).
    /// </summary>
    [TestMethod]
    public void CborEncodingIsDeterministic()
    {
        //Arrange - Create same disclosure twice.
        byte[] salt = new byte[16];
        Array.Fill(salt, (byte)0x42);

        SdDisclosure d1 = SdDisclosure.CreateProperty(salt, "test", "value");
        SdDisclosure d2 = SdDisclosure.CreateProperty(salt, "test", "value");

        //Act - Serialize both.
        byte[] cbor1 = SdCwtSerializer.SerializeDisclosure(d1);
        byte[] cbor2 = SdCwtSerializer.SerializeDisclosure(d2);

        //Assert - Should be identical.
        Assert.IsTrue(cbor1.SequenceEqual(cbor2), "Deterministic encoding should produce identical bytes.");

        TestContext.WriteLine($"CBOR: {Convert.ToHexString(cbor1)}");
    }


    /// <summary>
    /// Tests handling of various CBOR value types.
    /// </summary>
    [TestMethod]
    public void VariousValueTypesRoundTrip()
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);

        //Boolean.
        VerifyRoundTrip(salt, "bool_true", true);
        VerifyRoundTrip(salt, "bool_false", false);

        //Numbers.
        VerifyRoundTrip(salt, "int_positive", 42L);
        VerifyRoundTrip(salt, "int_negative", -123L);
        VerifyRoundTrip(salt, "double_value", 3.14159);

        //Strings.
        VerifyRoundTrip(salt, "string_value", "hello world");
        VerifyRoundTrip(salt, "empty_string", "");

        //Null.
        VerifyNullRoundTrip(salt, "null_value");

        TestContext.WriteLine("All value types round-tripped successfully.");
    }


    /// <summary>
    /// Tests writing and reading sd_claims header using WriteSdClaimsHeader.
    /// </summary>
    [TestMethod]
    public void SdClaimsHeaderRoundTrips()
    {
        //Arrange - Create multiple disclosures.
        var disclosures = new List<SdDisclosure>
        {
            SdDisclosure.CreateProperty(RandomNumberGenerator.GetBytes(16), "name", "Alice"),
            SdDisclosure.CreateProperty(RandomNumberGenerator.GetBytes(16), "age", 30L),
            SdDisclosure.CreateArrayElement(RandomNumberGenerator.GetBytes(16), "admin")
        };

        //Act - Write sd_claims header.
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        SdCwtSerializer.WriteSdClaimsHeader(writer, disclosures);
        writer.WriteEndMap();
        byte[] encoded = writer.Encode();

        //Parse back by reading the structure manually.
        var reader = new CborReader(encoded, CborConformanceMode.Lax);
        reader.ReadStartMap();
        int headerKey = reader.ReadInt32();

        //Read the array of disclosures.
        int? arrayLength = reader.ReadStartArray();
        var parsed = new List<SdDisclosure>();
        for(int i = 0; i < arrayLength; i++)
        {
            SdDisclosure disclosure = SdCwtSerializer.ReadDisclosure(ref reader);
            parsed.Add(disclosure);
        }
        reader.ReadEndArray();
        reader.ReadEndMap();

        //Assert.
        Assert.AreEqual(SdCwtSerializer.SdClaimsHeaderKey, headerKey);
        Assert.HasCount(3, parsed);
        Assert.AreEqual("name", parsed[0].ClaimName);
        Assert.AreEqual("age", parsed[1].ClaimName);
        Assert.IsNull(parsed[2].ClaimName);

        TestContext.WriteLine($"sd_claims header: {Convert.ToHexString(encoded)}");
    }


    /// <summary>
    /// Demonstrates full SD-CWT disclosure structure with Example 8 credential claims.
    /// </summary>
    [TestMethod]
    public void Example8CredentialDisclosuresSerializeCorrectly()
    {
        //Arrange - Create disclosures matching W3C Example 8 claims.
        var disclosures = new List<(string Description, SdDisclosure Disclosure)>
        {
            ("issuer.id", SdDisclosure.CreateProperty(
                RandomNumberGenerator.GetBytes(16),
                "id",
                "did:example:76e12ec712ebc6f1c221ebfeb1f")),

            ("issuer.name", SdDisclosure.CreateProperty(
                RandomNumberGenerator.GetBytes(16),
                "name",
                "Example University")),

            ("credentialSubject.id", SdDisclosure.CreateProperty(
                RandomNumberGenerator.GetBytes(16),
                "id",
                "did:example:ebfeb1f712ebc6f1c276e12ec21")),

            ("degree.type", SdDisclosure.CreateProperty(
                RandomNumberGenerator.GetBytes(16),
                "type",
                "ExampleBachelorDegree")),

            ("degree.name", SdDisclosure.CreateProperty(
                RandomNumberGenerator.GetBytes(16),
                "name",
                "Bachelor of Science and Arts")),

            ("type[1] (array element)", SdDisclosure.CreateArrayElement(
                RandomNumberGenerator.GetBytes(16),
                "ExampleDegreeCredential"))
        };

        //Act - Serialize all disclosures and compute digests.
        TestContext.WriteLine("SD-CWT Disclosures for W3C Example 8:");
        TestContext.WriteLine("======================================");

        foreach((string description, SdDisclosure disclosure) in disclosures)
        {
            byte[] cbor = SdCwtSerializer.SerializeDisclosure(disclosure);
            byte[] digest = SdCwtSerializer.ComputeDisclosureDigest(cbor, "sha-256");

            TestContext.WriteLine($"\n{description}:");
            TestContext.WriteLine($"  Salt: {Convert.ToHexString(disclosure.Salt.Span)}");
            if(disclosure.ClaimName is not null)
            {
                TestContext.WriteLine($"  Key: {disclosure.ClaimName}");
            }

            TestContext.WriteLine($"  Value: {disclosure.ClaimValue}");
            TestContext.WriteLine($"  CBOR: {Convert.ToHexString(cbor)}");
            TestContext.WriteLine($"  SHA-256 Digest: {Convert.ToHexString(digest)}");

            //Verify round-trip.
            SdDisclosure parsed = SdCwtSerializer.ParseDisclosure(cbor);
            Assert.AreEqual(disclosure.ClaimName, parsed.ClaimName);
        }

        //Assert - Verify count.
        Assert.HasCount(6, disclosures);
    }


    private void VerifyRoundTrip(byte[] salt, string claimName, object? value)
    {
        SdDisclosure original = SdDisclosure.CreateProperty(salt, claimName, value);
        byte[] cbor = SdCwtSerializer.SerializeDisclosure(original);
        SdDisclosure parsed = SdCwtSerializer.ParseDisclosure(cbor);

        Assert.AreEqual(claimName, parsed.ClaimName, $"Claim name mismatch for {claimName}.");
        Assert.AreEqual(value, parsed.ClaimValue, $"Value mismatch for {claimName}.");
    }


    private void VerifyNullRoundTrip(byte[] salt, string claimName)
    {
        SdDisclosure original = SdDisclosure.CreateProperty(salt, claimName, null);
        byte[] cbor = SdCwtSerializer.SerializeDisclosure(original);
        SdDisclosure parsed = SdCwtSerializer.ParseDisclosure(cbor);

        Assert.AreEqual(claimName, parsed.ClaimName, $"Claim name mismatch for {claimName}.");
        Assert.IsNull(parsed.ClaimValue, $"Value should be null for {claimName}.");
    }
}