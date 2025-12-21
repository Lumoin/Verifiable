using System.Buffers;
using System.Text;
using Verifiable.Core.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Jose.SdJwt;
using Verifiable.Json.Converters;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SdJwt;

/// <summary>
/// Tests for <see cref="Disclosure"/> based on RFC 9901 test vectors.
/// </summary>
/// <remarks>
/// Test vectors are from RFC 9901 Section 4.2 and Section 5.
/// See <see href="https://www.rfc-editor.org/rfc/rfc9901.html"/>.
/// </remarks>
[TestClass]
public sealed class DisclosureTests
{
    //RFC 9901 Section 4.2.1 example: family_name disclosure.
    private const string Rfc9901FamilyNameSalt = "_26bc4LT-ac6q2KI6cBW5es";
    private const string Rfc9901FamilyNameClaimName = "family_name";
    private const string Rfc9901FamilyNameValue = "Möbius";
    private const string Rfc9901FamilyNameEncoded = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0";
    private const string Rfc9901FamilyNameDigest = "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0";

    //RFC 9901 Section 4.2.2 example: array element disclosure.
    private const string Rfc9901ArrayElementSalt = "lklxF5jMYlGTPUovMNIvCA";
    private const string Rfc9901ArrayElementValue = "FR";
    private const string Rfc9901ArrayElementEncoded = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0";

    //RFC 9901 Section 5.1 examples.
    private const string Rfc9901GivenNameSalt = "2GLC42sKQveCfGfryNRN9w";
    private const string Rfc9901GivenNameEncoded = "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd";
    private const string Rfc9901GivenNameDigest = "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4";

    private const string Rfc9901EmailSalt = "6Ij7tM-a5iVPGboS5tmvVA";
    private const string Rfc9901EmailEncoded = "WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ";
    private const string Rfc9901EmailDigest = "JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE";

    private const string Rfc9901PhoneVerifiedSalt = "Qg_O64zqAxe412a108iroA";
    private const string Rfc9901PhoneVerifiedEncoded = "WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd";
    private const string Rfc9901PhoneVerifiedDigest = "XQ_3kPKt1XyX7KANkqVR6yZ2Va5NrPIvPYbyMvRKBMM";

    private const string Rfc9901UpdatedAtSalt = "G02NSrQfjFXQ7Io09syajA";
    private const string Rfc9901UpdatedAtEncoded = "WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ";
    private const string Rfc9901UpdatedAtDigest = "CrQe7S5kqBAHt-nMYXgc6bdt2SH5aTY1sU_M-PgkjPI";

    //Nationality array elements from RFC 9901 Section 5.1.
    private const string Rfc9901NationalityUsSalt = "lklxF5jMYlGTPUovMNIvCA";
    private const string Rfc9901NationalityUsEncoded = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0";
    private const string Rfc9901NationalityUsDigest = "pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo";

    private const string Rfc9901NationalityDeSalt = "nPuoQnkRFq3BIeAm7AnXFA";
    private const string Rfc9901NationalityDeEncoded = "WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0";
    private const string Rfc9901NationalityDeDigest = "7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0";

    private static MemoryPool<byte> MemoryPool => SensitiveMemoryPool<byte>.Shared;
    private static EncodeDelegate Encoder => TestSetup.Base64UrlEncoder;
    private static DecodeDelegate Decoder => TestSetup.Base64UrlDecoder;

    private static DisclosureJsonConverter Converter => new(Encoder, Decoder, MemoryPool);


    private Disclosure ParseDisclosure(string encoded)
    {
        var reader = new System.Text.Json.Utf8JsonReader(Encoding.UTF8.GetBytes($"\"{encoded}\""));
        reader.Read();
        return Converter.Read(ref reader, typeof(Disclosure), null!)!;
    }


    [TestMethod]
    public void ParseFamilyNameDisclosureFromRfc9901Succeeds()
    {
        Disclosure disclosure = ParseDisclosure(Rfc9901FamilyNameEncoded);

        Assert.AreEqual(Rfc9901FamilyNameSalt, disclosure.Salt);
        Assert.AreEqual(Rfc9901FamilyNameClaimName, disclosure.ClaimName);
        Assert.AreEqual(Rfc9901FamilyNameValue, disclosure.ClaimValue);
        Assert.IsFalse(disclosure.IsArrayElement);
    }


    [TestMethod]
    public void ComputeFamilyNameDigestMatchesRfc9901()
    {
        Disclosure disclosure = ParseDisclosure(Rfc9901FamilyNameEncoded);

        string digest = disclosure.ComputeDigest(SdJwtConstants.DefaultHashAlgorithm, Encoder);

        Assert.AreEqual(Rfc9901FamilyNameDigest, digest);
    }


    [TestMethod]
    public void ParseArrayElementDisclosureFromRfc9901Succeeds()
    {
        Disclosure disclosure = ParseDisclosure(Rfc9901ArrayElementEncoded);

        Assert.AreEqual(Rfc9901ArrayElementSalt, disclosure.Salt);
        Assert.IsNull(disclosure.ClaimName);
        Assert.AreEqual(Rfc9901ArrayElementValue, disclosure.ClaimValue);
        Assert.IsTrue(disclosure.IsArrayElement);
    }


    [TestMethod]
    public void ParseGivenNameDisclosureFromRfc9901Succeeds()
    {
        Disclosure disclosure = ParseDisclosure(Rfc9901GivenNameEncoded);

        Assert.AreEqual(Rfc9901GivenNameSalt, disclosure.Salt);
        Assert.AreEqual("given_name", disclosure.ClaimName);
        Assert.AreEqual("John", disclosure.ClaimValue);

        string digest = disclosure.ComputeDigest(SdJwtConstants.DefaultHashAlgorithm, Encoder);
        Assert.AreEqual(Rfc9901GivenNameDigest, digest);
    }


    [TestMethod]
    public void ParseEmailDisclosureFromRfc9901Succeeds()
    {
        Disclosure disclosure = ParseDisclosure(Rfc9901EmailEncoded);

        Assert.AreEqual(Rfc9901EmailSalt, disclosure.Salt);
        Assert.AreEqual("email", disclosure.ClaimName);
        Assert.AreEqual("johndoe@example.com", disclosure.ClaimValue);

        string digest = disclosure.ComputeDigest(SdJwtConstants.DefaultHashAlgorithm, Encoder);
        Assert.AreEqual(Rfc9901EmailDigest, digest);
    }


    [TestMethod]
    public void ParsePhoneVerifiedDisclosureWithBooleanValueSucceeds()
    {
        Disclosure disclosure = ParseDisclosure(Rfc9901PhoneVerifiedEncoded);

        Assert.AreEqual(Rfc9901PhoneVerifiedSalt, disclosure.Salt);
        Assert.AreEqual("phone_number_verified", disclosure.ClaimName);
        Assert.IsTrue((bool)disclosure.ClaimValue!);

        string digest = disclosure.ComputeDigest(SdJwtConstants.DefaultHashAlgorithm, Encoder);
        Assert.AreEqual(Rfc9901PhoneVerifiedDigest, digest);
    }


    [TestMethod]
    public void ParseUpdatedAtDisclosureWithNumericValueSucceeds()
    {
        Disclosure disclosure = ParseDisclosure(Rfc9901UpdatedAtEncoded);

        Assert.AreEqual(Rfc9901UpdatedAtSalt, disclosure.Salt);
        Assert.AreEqual("updated_at", disclosure.ClaimName);
        Assert.AreEqual(1570000000L, disclosure.ClaimValue);

        string digest = disclosure.ComputeDigest(SdJwtConstants.DefaultHashAlgorithm, Encoder);
        Assert.AreEqual(Rfc9901UpdatedAtDigest, digest);
    }


    [TestMethod]
    public void ParseNationalityUsArrayElementSucceeds()
    {
        Disclosure disclosure = ParseDisclosure(Rfc9901NationalityUsEncoded);

        Assert.AreEqual(Rfc9901NationalityUsSalt, disclosure.Salt);
        Assert.IsNull(disclosure.ClaimName);
        Assert.AreEqual("US", disclosure.ClaimValue);
        Assert.IsTrue(disclosure.IsArrayElement);

        string digest = disclosure.ComputeDigest(SdJwtConstants.DefaultHashAlgorithm, Encoder);
        Assert.AreEqual(Rfc9901NationalityUsDigest, digest);
    }


    [TestMethod]
    public void ParseNationalityDeArrayElementSucceeds()
    {
        Disclosure disclosure = ParseDisclosure(Rfc9901NationalityDeEncoded);

        Assert.AreEqual(Rfc9901NationalityDeSalt, disclosure.Salt);
        Assert.IsNull(disclosure.ClaimName);
        Assert.AreEqual("DE", disclosure.ClaimValue);
        Assert.IsTrue(disclosure.IsArrayElement);

        string digest = disclosure.ComputeDigest(SdJwtConstants.DefaultHashAlgorithm, Encoder);
        Assert.AreEqual(Rfc9901NationalityDeDigest, digest);
    }


    [TestMethod]
    public void CreateObjectPropertyDisclosureProducesValidEncoding()
    {
        Disclosure disclosure = DisclosureJsonConverter.Create("test_salt", "test_claim", "test_value", Encoder);

        Assert.AreEqual("test_salt", disclosure.Salt);
        Assert.AreEqual("test_claim", disclosure.ClaimName);
        Assert.IsFalse(disclosure.IsArrayElement);

        //Verify the encoding can be parsed back.
        Disclosure parsed = ParseDisclosure(disclosure.EncodedValue);
        Assert.AreEqual(disclosure.Salt, parsed.Salt);
        Assert.AreEqual(disclosure.ClaimName, parsed.ClaimName);
        Assert.AreEqual(disclosure.ClaimValue, parsed.ClaimValue);
    }


    [TestMethod]
    public void CreateArrayElementDisclosureProducesValidEncoding()
    {
        Disclosure disclosure = DisclosureJsonConverter.CreateArrayElement("array_salt", "element_value", Encoder);

        Assert.AreEqual("array_salt", disclosure.Salt);
        Assert.IsNull(disclosure.ClaimName);
        Assert.IsTrue(disclosure.IsArrayElement);

        Disclosure parsed = ParseDisclosure(disclosure.EncodedValue);
        Assert.AreEqual(disclosure.Salt, parsed.Salt);
        Assert.IsNull(parsed.ClaimName);
        Assert.AreEqual(disclosure.ClaimValue, parsed.ClaimValue);
    }


    [TestMethod]
    public void CreateDisclosureWithObjectValueSucceeds()
    {
        var addressValue = new Dictionary<string, object>
        {
            ["street_address"] = "123 Main St",
            ["locality"] = "Anytown",
            ["region"] = "Anystate",
            ["country"] = "US"
        };

        Disclosure disclosure = DisclosureJsonConverter.Create("address_salt", "address", addressValue, Encoder);

        Assert.AreEqual("address", disclosure.ClaimName);
        Assert.IsInstanceOfType<Dictionary<string, object>>(disclosure.ClaimValue);

        Disclosure parsed = ParseDisclosure(disclosure.EncodedValue);
        var parsedAddress = (Dictionary<string, object>)parsed.ClaimValue!;
        Assert.AreEqual("123 Main St", parsedAddress["street_address"]);
        Assert.AreEqual("US", parsedAddress["country"]);
    }


    [TestMethod]
    public void CreateDisclosureWithArrayValueSucceeds()
    {
        var arrayValue = new List<object> { "item1", "item2", "item3" };

        Disclosure disclosure = DisclosureJsonConverter.Create("array_salt", "items", arrayValue, Encoder);

        Assert.AreEqual("items", disclosure.ClaimName);
        Assert.IsInstanceOfType<List<object>>(disclosure.ClaimValue);

        var claimArray = (List<object>)disclosure.ClaimValue!;
        Assert.HasCount(3, claimArray);
    }


    [TestMethod]
    public void CreateDisclosureWithNullValueSucceeds()
    {
        Disclosure disclosure = DisclosureJsonConverter.Create("null_salt", "nullable_claim", null, Encoder);

        Assert.IsNull(disclosure.ClaimValue);

        Disclosure parsed = ParseDisclosure(disclosure.EncodedValue);
        Assert.IsNull(parsed.ClaimValue);
    }


    [TestMethod]
    public void CreateDisclosureRejectsSdClaimName()
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            DisclosureJsonConverter.Create("salt", "_sd", "value", Encoder));

        Assert.IsTrue(exception.Message.Contains("_sd", StringComparison.Ordinal));
    }


    [TestMethod]
    public void CreateDisclosureRejectsArrayDigestKeyClaimName()
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            DisclosureJsonConverter.Create("salt", "...", "value", Encoder));

        Assert.IsTrue(exception.Message.Contains("...", StringComparison.Ordinal));
    }


    [TestMethod]
    public void DisclosureEqualityWorksCorrectly()
    {
        Disclosure disclosure1 = ParseDisclosure(Rfc9901FamilyNameEncoded);
        Disclosure disclosure2 = ParseDisclosure(Rfc9901FamilyNameEncoded);
        Disclosure disclosure3 = ParseDisclosure(Rfc9901GivenNameEncoded);

        Assert.AreEqual(disclosure1, disclosure2);
        Assert.AreNotEqual(disclosure1, disclosure3);
        Assert.IsTrue(disclosure1 == disclosure2);
        Assert.IsTrue(disclosure1 != disclosure3);
        Assert.AreEqual(disclosure1.GetHashCode(), disclosure2.GetHashCode());
    }


    [TestMethod]
    public void ToStringReturnsEncodedValue()
    {
        Disclosure disclosure = ParseDisclosure(Rfc9901FamilyNameEncoded);

        Assert.AreEqual(Rfc9901FamilyNameEncoded, disclosure.ToString());
    }


    [TestMethod]
    public void CreateWithSaltGeneratorProducesValidDisclosure()
    {
        SaltGeneratorDelegate saltGenerator = SaltGenerator.CreateDeterministic(["fixed_salt"]);
        string salt = saltGenerator();

        Disclosure disclosure = DisclosureJsonConverter.Create(salt, "claim_name", "test", Encoder);

        Assert.AreEqual("fixed_salt", disclosure.Salt);
        Assert.AreEqual("claim_name", disclosure.ClaimName);
    }


    [TestMethod]
    public void CreateArrayElementWithSaltGeneratorProducesValidDisclosure()
    {
        SaltGeneratorDelegate saltGenerator = SaltGenerator.CreateDeterministic(["element_salt"]);
        string salt = saltGenerator();

        Disclosure disclosure = DisclosureJsonConverter.CreateArrayElement(salt, "element", Encoder);

        Assert.AreEqual("element_salt", disclosure.Salt);
        Assert.IsNull(disclosure.ClaimName);
        Assert.IsTrue(disclosure.IsArrayElement);
    }


    [TestMethod]
    public void ComputeDigestWithSha384Succeeds()
    {
        Disclosure disclosure = ParseDisclosure(Rfc9901FamilyNameEncoded);

        string digest = disclosure.ComputeDigest("sha-384", Encoder);

        Assert.IsFalse(string.IsNullOrEmpty(digest));
        Assert.AreNotEqual(Rfc9901FamilyNameDigest, digest);
    }


    [TestMethod]
    public void ComputeDigestWithSha512Succeeds()
    {
        Disclosure disclosure = ParseDisclosure(Rfc9901FamilyNameEncoded);

        string digest = disclosure.ComputeDigest("sha-512", Encoder);

        Assert.IsFalse(string.IsNullOrEmpty(digest));
        Assert.AreNotEqual(Rfc9901FamilyNameDigest, digest);
    }


    [TestMethod]
    public void ComputeDigestWithUnsupportedAlgorithmThrows()
    {
        Disclosure disclosure = ParseDisclosure(Rfc9901FamilyNameEncoded);

        Assert.Throws<ArgumentException>(() => disclosure.ComputeDigest("md5", Encoder));
    }


    [TestMethod]
    public void IsValidDisclosureClaimNameReturnsFalseForReservedNames()
    {
        Assert.IsFalse(SdJwtExtensions.IsValidDisclosureClaimName("_sd"));
        Assert.IsFalse(SdJwtExtensions.IsValidDisclosureClaimName("..."));
        Assert.IsFalse(SdJwtExtensions.IsValidDisclosureClaimName(""));
        Assert.IsFalse(SdJwtExtensions.IsValidDisclosureClaimName(null!));
    }


    [TestMethod]
    public void IsValidDisclosureClaimNameReturnsTrueForValidNames()
    {
        Assert.IsTrue(SdJwtExtensions.IsValidDisclosureClaimName("family_name"));
        Assert.IsTrue(SdJwtExtensions.IsValidDisclosureClaimName("given_name"));
        Assert.IsTrue(SdJwtExtensions.IsValidDisclosureClaimName("email"));
    }
}