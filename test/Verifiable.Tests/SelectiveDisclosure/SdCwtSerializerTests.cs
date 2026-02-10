using System.Formats.Cbor;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.JCose.Sd;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Tests for <see cref="SdCwtSerializer"/> based on SD-CWT specification.
/// See <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html"/>.
/// Test vectors to be added once available as byte arrays or manually converted from EDN.
/// </summary>
[TestClass]
internal sealed class SdCwtSerializerTests
{
    private static readonly byte[] TestSalt = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];


    [TestMethod]
    public void SerializeDisclosureForPropertyProducesThreeElementArray()
    {
        SdDisclosure disclosure = SdDisclosure.CreateProperty(
            TestSalt,
            "given_name",
            "John");

        byte[] cbor = SdCwtSerializer.SerializeDisclosure(disclosure);

        var reader = new CborReader(cbor, CborConformanceMode.Lax);
        int? length = reader.ReadStartArray();

        Assert.AreEqual(3, length, "Property disclosure must have 3 elements.");

        byte[] salt = reader.ReadByteString();
        string name = reader.ReadTextString();
        string value = reader.ReadTextString();
        reader.ReadEndArray();

        CollectionAssert.AreEqual(TestSalt, salt);
        Assert.AreEqual("given_name", name);
        Assert.AreEqual("John", value);
    }


    [TestMethod]
    public void SerializeDisclosureForArrayElementProducesTwoElementArray()
    {
        SdDisclosure disclosure = SdDisclosure.CreateArrayElement(TestSalt, "US");

        byte[] cbor = SdCwtSerializer.SerializeDisclosure(disclosure);

        var reader = new CborReader(cbor, CborConformanceMode.Lax);
        int? length = reader.ReadStartArray();

        Assert.AreEqual(2, length, "Array element disclosure must have 2 elements.");

        byte[] salt = reader.ReadByteString();
        string value = reader.ReadTextString();
        reader.ReadEndArray();

        CollectionAssert.AreEqual(TestSalt, salt);
        Assert.AreEqual("US", value);
    }


    [TestMethod]
    public void RoundTripDisclosurePreservesPropertyData()
    {
        SdDisclosure original = SdDisclosure.CreateProperty(
            TestSalt,
            "email",
            "john@example.com");

        byte[] cbor = SdCwtSerializer.SerializeDisclosure(original);
        SdDisclosure parsed = SdCwtSerializer.ParseDisclosure(cbor);

        Assert.AreEqual(original.ClaimName, parsed.ClaimName);
        Assert.AreEqual(original.ClaimValue, parsed.ClaimValue);
        Assert.IsTrue(original.Salt.Span.SequenceEqual(parsed.Salt.Span));
    }


    [TestMethod]
    public void RoundTripDisclosurePreservesArrayElementData()
    {
        SdDisclosure original = SdDisclosure.CreateArrayElement(TestSalt, "DE");

        byte[] cbor = SdCwtSerializer.SerializeDisclosure(original);
        SdDisclosure parsed = SdCwtSerializer.ParseDisclosure(cbor);

        Assert.IsNull(parsed.ClaimName, "Array element disclosure must have null claim name.");
        Assert.AreEqual(original.ClaimValue, parsed.ClaimValue);
        Assert.IsTrue(original.Salt.Span.SequenceEqual(parsed.Salt.Span));
    }


    [TestMethod]
    public void SerializeDisclosureHandlesIntegerValue()
    {
        SdDisclosure disclosure = SdDisclosure.CreateProperty(TestSalt, "age", 30);

        byte[] cbor = SdCwtSerializer.SerializeDisclosure(disclosure);
        SdDisclosure parsed = SdCwtSerializer.ParseDisclosure(cbor);

        Assert.AreEqual("age", parsed.ClaimName);
        Assert.AreEqual(30, parsed.ClaimValue);
    }


    [TestMethod]
    public void SerializeDisclosureHandlesBooleanValue()
    {
        SdDisclosure disclosure = SdDisclosure.CreateProperty(TestSalt, "verified", true);

        byte[] cbor = SdCwtSerializer.SerializeDisclosure(disclosure);
        SdDisclosure parsed = SdCwtSerializer.ParseDisclosure(cbor);

        Assert.AreEqual("verified", parsed.ClaimName);
        Assert.IsTrue((bool)parsed.ClaimValue!);
    }


    [TestMethod]
    public void SerializeDisclosureHandlesNullValue()
    {
        SdDisclosure disclosure = SdDisclosure.CreateProperty(TestSalt, "middle_name", null);

        byte[] cbor = SdCwtSerializer.SerializeDisclosure(disclosure);
        SdDisclosure parsed = SdCwtSerializer.ParseDisclosure(cbor);

        Assert.AreEqual("middle_name", parsed.ClaimName);
        Assert.IsNull(parsed.ClaimValue);
    }


    [TestMethod]
    public void SerializeDisclosureHandlesNestedMap()
    {
        var address = new Dictionary<string, object?>
        {
            ["street"] = "123 Main St",
            ["city"] = "Anytown",
            ["zip"] = 12345
        };

        SdDisclosure disclosure = SdDisclosure.CreateProperty(TestSalt, "address", address);

        byte[] cbor = SdCwtSerializer.SerializeDisclosure(disclosure);
        SdDisclosure parsed = SdCwtSerializer.ParseDisclosure(cbor);

        Assert.AreEqual("address", parsed.ClaimName);
        Assert.IsInstanceOfType<Dictionary<object, object?>>(parsed.ClaimValue);

        var parsedAddress = (Dictionary<object, object?>)parsed.ClaimValue!;
        Assert.AreEqual("123 Main St", parsedAddress["street"]);
        Assert.AreEqual("Anytown", parsedAddress["city"]);
        Assert.AreEqual(12345, parsedAddress["zip"]);
    }


    [TestMethod]
    public void SerializeDisclosureHandlesArrayValue()
    {
        var nationalities = new List<object?> { "US", "DE", "FR" };

        SdDisclosure disclosure = SdDisclosure.CreateProperty(TestSalt, "nationalities", nationalities);

        byte[] cbor = SdCwtSerializer.SerializeDisclosure(disclosure);
        SdDisclosure parsed = SdCwtSerializer.ParseDisclosure(cbor);

        Assert.AreEqual("nationalities", parsed.ClaimName);
        Assert.IsInstanceOfType<List<object?>>(parsed.ClaimValue);

        var parsedNationalities = (List<object?>)parsed.ClaimValue!;
        Assert.HasCount(3, parsedNationalities);
        Assert.AreEqual("US", parsedNationalities[0]);
        Assert.AreEqual("DE", parsedNationalities[1]);
        Assert.AreEqual("FR", parsedNationalities[2]);
    }


    [TestMethod]
    public void SerializeDisclosureHandlesByteStringValue()
    {
        byte[] binaryData = [0xDE, 0xAD, 0xBE, 0xEF];

        SdDisclosure disclosure = SdDisclosure.CreateProperty(TestSalt, "binary", binaryData);

        byte[] cbor = SdCwtSerializer.SerializeDisclosure(disclosure);
        SdDisclosure parsed = SdCwtSerializer.ParseDisclosure(cbor);

        Assert.AreEqual("binary", parsed.ClaimName);
        CollectionAssert.AreEqual(binaryData, (byte[])parsed.ClaimValue!);
    }


    [TestMethod]
    public void ComputeDisclosureDigestProducesConsistentOutput()
    {
        SdDisclosure disclosure = SdDisclosure.CreateProperty(TestSalt, "name", "John");

        byte[] cbor = SdCwtSerializer.SerializeDisclosure(disclosure);

        byte[] digest1 = SdCwtSerializer.ComputeDisclosureDigest(cbor, WellKnownHashAlgorithms.Sha256Iana);
        byte[] digest2 = SdCwtSerializer.ComputeDisclosureDigest(cbor, WellKnownHashAlgorithms.Sha256Iana);

        CollectionAssert.AreEqual(digest1, digest2, "Digest must be deterministic.");
    }


    [TestMethod]
    public void ComputeDisclosureDigestProduces32BytesForSha256()
    {
        SdDisclosure disclosure = SdDisclosure.CreateProperty(TestSalt, "name", "John");

        byte[] cbor = SdCwtSerializer.SerializeDisclosure(disclosure);
        byte[] digest = SdCwtSerializer.ComputeDisclosureDigest(cbor, "sha-256");

        Assert.HasCount(32, digest, "SHA-256 digest must be 32 bytes.");
    }


    [TestMethod]
    public void ComputeDisclosureDigestProduces48BytesForSha384()
    {
        SdDisclosure disclosure = SdDisclosure.CreateProperty(TestSalt, "name", "John");

        byte[] cbor = SdCwtSerializer.SerializeDisclosure(disclosure);
        byte[] digest = SdCwtSerializer.ComputeDisclosureDigest(cbor, "sha-384");

        Assert.HasCount(48, digest, "SHA-384 digest must be 48 bytes.");
    }


    [TestMethod]
    public void WriteSdClaimsHeaderProducesValidCbor()
    {
        var disclosures = new List<SdDisclosure>
        {
            SdDisclosure.CreateProperty(TestSalt, "name", "John"),
            SdDisclosure.CreateProperty(TestSalt, "email", "john@example.com")
        };

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        SdCwtSerializer.WriteSdClaimsHeader(writer, disclosures);
        writer.WriteEndMap();
        byte[] cbor = writer.Encode();

        //Verify structure.
        var reader = new CborReader(cbor, CborConformanceMode.Lax);
        reader.ReadStartMap();
        int key = reader.ReadInt32();
        Assert.AreEqual(SdCwtSerializer.SdClaimsHeaderKey, key);

        IReadOnlyList<SdDisclosure> parsed = SdCwtSerializer.ReadSdClaimsHeader(ref reader);
        reader.ReadEndMap();

        Assert.HasCount(2, parsed);
        Assert.AreEqual("name", parsed[0].ClaimName);
        Assert.AreEqual("email", parsed[1].ClaimName);
    }


    [TestMethod]
    public void ParseDisclosureThrowsForInvalidArrayLength()
    {
        //Create CBOR array with 4 elements (invalid).
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(4);
        writer.WriteByteString(TestSalt);
        writer.WriteTextString("name");
        writer.WriteTextString("value");
        writer.WriteTextString("extra");
        writer.WriteEndArray();
        byte[] cbor = writer.Encode();

        Assert.Throws<CborContentException>(() => SdCwtSerializer.ParseDisclosure(cbor));
    }


    [TestMethod]
    public void DeterministicEncodingProducesIdenticalOutput()
    {
        SdDisclosure disclosure = SdDisclosure.CreateProperty(
            TestSalt,
            "test_claim",
            "test_value");

        byte[] cbor1 = SdCwtSerializer.SerializeDisclosure(disclosure, CborConformanceMode.Canonical);
        byte[] cbor2 = SdCwtSerializer.SerializeDisclosure(disclosure, CborConformanceMode.Canonical);

        CollectionAssert.AreEqual(cbor1, cbor2, "Canonical encoding must be deterministic.");
    }


    [TestMethod]
    public void ComputeSdHashProducesConsistentOutput()
    {
        var disclosures = new List<SdDisclosure>
        {
            SdDisclosure.CreateProperty(TestSalt, "name", "John"),
            SdDisclosure.CreateProperty(TestSalt, "age", 30)
        };

        //Serialize sd_claims array.
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(disclosures.Count);
        foreach(var d in disclosures)
        {
            byte[] encoded = SdCwtSerializer.SerializeDisclosure(d);
            writer.WriteEncodedValue(encoded);
        }
        writer.WriteEndArray();
        byte[] sdClaimsCbor = writer.Encode();

        byte[] hash1 = SdCwtSerializer.ComputeSdHash(sdClaimsCbor, WellKnownHashAlgorithms.Sha256Iana);
        byte[] hash2 = SdCwtSerializer.ComputeSdHash(sdClaimsCbor, WellKnownHashAlgorithms.Sha256Iana);

        CollectionAssert.AreEqual(hash1, hash2, "SD hash must be deterministic.");
    }


    [TestMethod]
    public void SerializeDisclosureHandlesDateTimeOffset()
    {
        var issued = DateTimeOffset.FromUnixTimeSeconds(1683000000);

        SdDisclosure disclosure = SdDisclosure.CreateProperty(TestSalt, "iat", issued);

        byte[] cbor = SdCwtSerializer.SerializeDisclosure(disclosure);
        SdDisclosure parsed = SdCwtSerializer.ParseDisclosure(cbor);

        Assert.AreEqual("iat", parsed.ClaimName);
        Assert.AreEqual(1683000000, parsed.ClaimValue);
    }
}