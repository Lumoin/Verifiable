using System.Text;
using Verifiable.JCose;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests that every lookup of <see cref="JwkJsonReader"/> by member name reads a name as the text it spells,
/// its escapes decoded, never as its raw bytes.
/// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.3">RFC 8259 §8.3</see>: "implementations that
/// compare strings with escaped characters unconverted may incorrectly find that "a\\b" and "a\u005Cb"
/// are not equal."
/// </summary>
[TestClass]
internal sealed class JwkJsonReaderDecodedNameTests
{
    /// <summary>The value the documents below give their <c>jwks_uri</c> member.</summary>
    private const string JwksUri = "https://client.example/jwks";


    /// <summary>Encodes <paramref name="text"/> as UTF-8.</summary>
    /// <param name="text">The JSON text.</param>
    /// <returns>The UTF-8 bytes.</returns>
    private static byte[] Utf8(string text) =>
        Encoding.UTF8.GetBytes(text);


    /// <summary>
    /// A member name whose first character is written as an escape is found by its plain spelling: the
    /// string extraction, the name and value offsets, and the presence check all read
    /// <c>"\u006awks_uri"</c> as <c>jwks_uri</c>.
    /// </summary>
    [TestMethod]
    public void ANameWithALeadingEscapeIsFoundByItsPlainSpelling()
    {
        byte[] json = Utf8($$"""{"client_id":"a","\u006awks_uri":"{{JwksUri}}"}""");
        int nameOffset = Encoding.UTF8.GetString(json).IndexOf("\\u006awks_uri", StringComparison.Ordinal);
        Assert.AreNotEqual(-1, nameOffset, "The fixture spells the member name with an escape.");

        Assert.AreEqual(JwksUri, JwkJsonReader.ExtractStringValue(json, "jwks_uri"u8));
        Assert.IsTrue(JwkJsonReader.ContainsKey(json, "jwks_uri"u8));
        Assert.AreEqual(nameOffset, JwkJsonReader.IndexOfKey(json, "jwks_uri"u8));

        int valueOffset = JwkJsonReader.IndexOfValue(json, "jwks_uri"u8);
        Assert.AreEqual((byte)'"', json[valueOffset]);
        Assert.AreEqual(JwksUri, JwkJsonReader.ExtractStringAt(json, valueOffset + 1));
    }


    /// <summary>
    /// A name escaped in every character, in upper-case hex, is the name it spells, and the case of the
    /// characters it spells still tells two names apart.
    /// </summary>
    [TestMethod]
    public void ANameEscapedInEveryCharacterIsFound()
    {
        byte[] json = Utf8("""{"\u004B\u0049\u0044":"upper-case","\u006B\u0069\u0064":"k1"}""");

        Assert.AreEqual("k1", JwkJsonReader.ExtractStringValue(json, "kid"u8));
        Assert.AreEqual("upper-case", JwkJsonReader.ExtractStringValue(json, "KID"u8));
    }


    /// <summary>
    /// An escape that spells another character names another member: <c>"\u006bwks_uri"</c> is
    /// <c>kwks_uri</c>, so a lookup of <c>jwks_uri</c> finds nothing.
    /// </summary>
    [TestMethod]
    public void AnEscapeSpellingAnotherNameIsNotFound()
    {
        byte[] json = Utf8($$"""{"\u006bwks_uri":"{{JwksUri}}"}""");

        Assert.IsNull(JwkJsonReader.ExtractStringValue(json, "jwks_uri"u8));
        Assert.IsFalse(JwkJsonReader.ContainsKey(json, "jwks_uri"u8));
        Assert.AreEqual(-1, JwkJsonReader.IndexOfValue(json, "jwks_uri"u8));
    }


    /// <summary>
    /// A name holding a character above the Basic Multilingual Plane, written as an escaped surrogate pair,
    /// is found by the character's UTF-8 spelling.
    /// </summary>
    [TestMethod]
    public void ANameEscapedAsASurrogatePairIsFoundByTheCharacter()
    {
        byte[] json = Utf8("""{"\ud83d\ude00":"smile"}""");
        byte[] name = Utf8(char.ConvertFromUtf32(0x1F600));

        Assert.AreEqual("smile", JwkJsonReader.ExtractStringValue(json, name));
    }


    /// <summary>
    /// The numeric, Boolean, array, nested and object extractions read an escaped name the same way.
    /// </summary>
    [TestMethod]
    public void EveryExtractionReadsAnEscapedName()
    {
        byte[] json = Utf8("""
            {"\u0065xp":1700000000,"\u0062\u0036\u0034":false,"\u0061ud":["a","b"],
             "\u0065pk":{"\u0078":"coordinate"},"\u006beys":[{"\u006bid":"k1"}],"\u0063nf":{"jkt":"t"}}
            """);
        string[] expectedAudiences = ["a", "b"];
        string[] expectedKeyIds = ["k1"];

        Assert.IsTrue(JwkJsonReader.TryExtractLongValue(json, "exp"u8, out long expiration));
        Assert.AreEqual(1_700_000_000L, expiration);
        Assert.IsTrue(JwkJsonReader.TryExtractBooleanValue(json, "b64"u8, out bool isBase64Encoded));
        Assert.IsFalse(isBase64Encoded);
        Assert.AreSequenceEqual(expectedAudiences, JwkJsonReader.ExtractStringArrayProperty(json, "aud"u8));
        Assert.AreEqual("a", JwkJsonReader.ExtractFirstStringFromArrayProperty(json, "aud"u8));
        Assert.AreEqual("coordinate", JwkJsonReader.ExtractNestedStringValue(json, "epk"u8, "x"u8));
        Assert.AreEqual("k1", JwkJsonReader.ExtractNestedStringValueFromArray(json, "keys"u8, "kid"u8));
        Assert.AreSequenceEqual(expectedKeyIds, JwkJsonReader.ExtractNestedStringValuesFromArray(json, "keys"u8, "kid"u8));
        Assert.AreEqual("""{"jkt":"t"}""", JwkJsonReader.ExtractObjectAsString(json, "cnf"u8));
        Assert.AreEqual("""[{"\u006bid":"k1"}]""", JwkJsonReader.ExtractArrayAsString(json, "keys"u8));
        Assert.AreEqual("t", JwkJsonReader.ExtractStringValue(JwkJsonReader.ExtractObjectContent(json, "cnf"u8), "jkt"u8));
    }


    /// <summary>
    /// The top-level names are answered decoded, so a caller holding them against a set of names reads
    /// <c>"\u0064"</c> as <c>d</c> and <c>"a\u005Cb"</c> as <c>a\b</c>.
    /// </summary>
    [TestMethod]
    public void TopLevelNamesAreAnsweredDecoded()
    {
        byte[] json = Utf8("""{"kty":"EC","\u0064":"private","a\u005Cb":1,"nested":{"\u006bid":"x"}}""");
        string[] expectedTopLevelNames = ["kty", "d", "a\\b", "nested"];
        string[] expectedNestedNames = ["kid"];

        Assert.AreSequenceEqual(expectedTopLevelNames, JwkJsonReader.GetTopLevelKeyNames(json));
        Assert.AreSequenceEqual(expectedNestedNames, JwkJsonReader.GetObjectMemberNames(json, "nested"u8));
    }


    /// <summary>
    /// The object-property extractions key each string member by its decoded name, so a key whose
    /// <c>x</c> is named <c>"\u0078"</c> hands its consumer the plain <c>x</c>.
    /// </summary>
    [TestMethod]
    public void ObjectPropertiesAreKeyedByTheirDecodedNames()
    {
        byte[] json = Utf8("""{"\u0063nf":{"\u006awk":{"kty":"OKP","\u0078":"coordinate"}},"sub_jwk":{"\u006bty":"EC"}}""");
        Assert.DoesNotContain("\"x\"", Encoding.UTF8.GetString(json), StringComparison.Ordinal, "The fixture names the members with escapes.");

        Dictionary<string, object>? confirmationKey = JwkJsonReader.ExtractNestedObjectProperties(json, "cnf"u8, "jwk"u8);
        Dictionary<string, object>? subjectKey = JwkJsonReader.ExtractObjectProperties(json, "sub_jwk"u8);

        Assert.IsNotNull(confirmationKey);
        Assert.AreEqual("coordinate", confirmationKey["x"]);
        Assert.AreEqual("OKP", confirmationKey["kty"]);
        Assert.IsNotNull(subjectKey);
        Assert.AreEqual("EC", subjectKey["kty"]);
    }


    /// <summary>
    /// An escaped namesake nested in a deeper object, and a string value that spells the name, never stand
    /// in for the top-level member.
    /// </summary>
    [TestMethod]
    public void NeitherANestedNamesakeNorAValueSpellingTheNameShadowsTheMember()
    {
        byte[] json = Utf8("""{"inner":{"\u006bid":"nested"},"label":"\u006bid","\u006bid":"top"}""");

        Assert.AreEqual("top", JwkJsonReader.ExtractStringValue(json, "kid"u8));
    }
}
