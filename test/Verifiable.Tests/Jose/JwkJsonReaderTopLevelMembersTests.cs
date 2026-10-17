using System.Text;
using System.Text.Json;
using Verifiable.JCose;

namespace Verifiable.Tests.Jose;

/// <summary>
/// <see cref="JwkJsonReader.ReadTopLevelMembers"/> reads the members of a JSON object's own level as the JSON it is (RFC 8259
/// section 4), each name and string value decoded once (RFC 8259 section 7), never a member an object or array nested beneath
/// it carries. <see cref="JsonDocument"/> is the oracle: for every document both read, the names, the kinds and the decoded
/// strings agree member for member.
/// </summary>
[TestClass]
internal sealed class JwkJsonReaderTopLevelMembersTests
{
    /// <summary>
    /// The top-level members of a document agree with the oracle's reading of its root object: an extension object carrying
    /// members of the same names as the top level's, before or after them, escaped names, escaped values, an escaped
    /// backslash, raw multi-byte text, numbers, literals and an array.
    /// </summary>
    /// <param name="document">The document.</param>
    [TestMethod]
    [DataRow(
        /*lang=json,strict*/ """{"ext":{"access_token":"nested","token_type":"DPoP"},"access_token":"top","token_type":"Bearer"}""",
        DisplayName = "An extension object before the top-level members it competes with")]
    [DataRow(
        /*lang=json,strict*/ """{"access_token":"top","ext":{"access_token":"nested"},"list":[{"access_token":"in-array"}]}""",
        DisplayName = "Nested members after the top-level ones")]
    [DataRow(
        /*lang=json,strict*/ """{"acc\u0065ss_token":"a\/b\u002ec","token_\u0074ype":"Bearer"}""",
        DisplayName = "Escaped names and values")]
    [DataRow(
        /*lang=json,strict*/ """{"v":"back\\u002eslash","w":"caf\u00e9 \ud83d\ude00","x":"café"}""",
        DisplayName = "An escaped backslash, an escaped surrogate pair and raw UTF-8")]
    [DataRow(
        /*lang=json,strict*/ """ { "n" : -12 , "f" : 1.5e3 , "t" : true , "u" : false , "z" : null , "a" : [ 1 , "two" ] } """,
        DisplayName = "Numbers, literals, an array and insignificant whitespace")]
    [DataRow(/*lang=json,strict*/ """{}""", DisplayName = "The empty object")]
    public void TheTopLevelMembersAgreeWithTheOracle(string document)
    {
        var members = JwkJsonReader.ReadTopLevelMembers(Encoding.UTF8.GetBytes(document));

        Assert.IsNotNull(members, "A well-formed object is read.");

        using var oracle = JsonDocument.Parse(document);
        var expected = oracle.RootElement.EnumerateObject().ToList();

        Assert.HasCount(expected.Count, members, "The reader reads the root object's own members and no nested one.");

        for(var index = 0; index < expected.Count; index++)
        {
            var read = members[index];
            var property = expected[index];

            Assert.AreEqual(property.Name, read.Name, "The name is the decoded name.");
            Assert.AreEqual(KindOf(property.Value.ValueKind), read.Kind, $"The kind of {property.Name}.");
            Assert.AreEqual(
                property.Value.ValueKind == JsonValueKind.String ? property.Value.GetString() : property.Value.GetRawText(),
                read.Text,
                $"The text of {property.Name}: a string decoded once, any other value as written.");
        }
    }


    /// <summary>
    /// A document that is not exactly one well-formed JSON object is no object: an array, a string, a document repeating a name
    /// at the top level or in a nested object (RFC 8259 section 4), one never closed and one followed by more text.
    /// </summary>
    /// <param name="document">The document.</param>
    [TestMethod]
    [DataRow(/*lang=json,strict*/ """["access_token","top"]""", DisplayName = "An array")]
    [DataRow(/*lang=json,strict*/ "\"access_token\"", DisplayName = "A string")]
    [DataRow(
        /*lang=json*/ """{"access_token":"first","access_token":"second"}""",
        DisplayName = "A name repeated at the top level")]
    [DataRow(/*lang=json*/ """{"ext":{"note":"one","note":"two"}}""", DisplayName = "A name repeated in a nested object")]
    [DataRow("{\"access_token\":\"top\"", DisplayName = "An object never closed")]
    [DataRow("""{"access_token":"top"}{"access_token":"second"}""", DisplayName = "An object followed by another")]
    public void ADocumentThatIsNotOneWellFormedObjectIsNone(string document)
    {
        Assert.IsNull(JwkJsonReader.ReadTopLevelMembers(Encoding.UTF8.GetBytes(document)), "No members are read from it.");
    }


    /// <summary>
    /// RFC 8259 section 8.2: an escape naming an unpaired surrogate is grammatical but names no Unicode text. A string value so
    /// spelled is read as undecodable, carrying no text, and a member whose name is so spelled is left out, every other member
    /// still read.
    /// </summary>
    [TestMethod]
    public void TextNamingAnUnpairedSurrogateIsReadAsUndecodable()
    {
        var members = JwkJsonReader.ReadTopLevelMembers(
            Encoding.UTF8.GetBytes(/*lang=json*/ """{"access_token":"\uD800","\uDC00":"left-out","token_type":"Bearer"}"""));

        Assert.IsNotNull(members, "The document is well formed.");
        Assert.HasCount(2, members, "The member whose name names no Unicode text is left out.");
        Assert.AreEqual(new JsonTopLevelMember("access_token", JsonTopLevelValueKind.UndecodableString, string.Empty), members[0]);
        Assert.AreEqual(new JsonTopLevelMember("token_type", JsonTopLevelValueKind.String, "Bearer"), members[1]);
    }


    /// <summary>
    /// RFC 8259 section 8.1: JSON text exchanged between systems "MUST be encoded using UTF-8". A document holding bytes that are
    /// no well-formed UTF-8 - in a member name, in a string value, in a name or a string nested beneath the top level - is no
    /// well-formed document, so it is no object, never one whose text holds a character its bytes do not encode. The rows are
    /// bytes, as no managed string carries such a sequence.
    /// </summary>
    /// <param name="document">The document's bytes.</param>
    [TestMethod]
    [DataRow(new byte[] { 0x7B, 0x22, 0x76, 0x22, 0x3A, 0x22, 0xFF, 0x22, 0x7D }, DisplayName = "A string value holding FF")]
    [DataRow(new byte[] { 0x7B, 0x22, 0xFF, 0x22, 0x3A, 0x22, 0x76, 0x22, 0x7D }, DisplayName = "A member name holding FF")]
    [DataRow(
        new byte[] { 0x7B, 0x22, 0x65, 0x22, 0x3A, 0x7B, 0x22, 0x76, 0x22, 0x3A, 0x22, 0xFF, 0x22, 0x7D, 0x7D },
        DisplayName = "A nested string value holding FF")]
    [DataRow(
        new byte[] { 0x7B, 0x22, 0x65, 0x22, 0x3A, 0x7B, 0x22, 0xFF, 0x22, 0x3A, 0x22, 0x76, 0x22, 0x7D, 0x7D },
        DisplayName = "A nested member name holding FF")]
    [DataRow(
        new byte[] { 0x7B, 0x22, 0x61, 0x22, 0x3A, 0x5B, 0x22, 0xFF, 0x22, 0x5D, 0x7D },
        DisplayName = "A string in a nested array holding FF")]
    [DataRow(new byte[] { 0x7B, 0x22, 0x76, 0x22, 0x3A, 0x22, 0x80, 0x22, 0x7D }, DisplayName = "A continuation byte with no lead")]
    [DataRow(new byte[] { 0x7B, 0x22, 0x76, 0x22, 0x3A, 0x22, 0xC3, 0x22, 0x7D }, DisplayName = "A two-byte sequence cut short")]
    [DataRow(
        new byte[] { 0x7B, 0x22, 0x76, 0x22, 0x3A, 0x22, 0xC0, 0xAF, 0x22, 0x7D },
        DisplayName = "An overlong form of the solidus")]
    [DataRow(
        new byte[] { 0x7B, 0x22, 0x76, 0x22, 0x3A, 0x22, 0xED, 0xA0, 0x80, 0x22, 0x7D },
        DisplayName = "An encoded surrogate")]
    [DataRow(
        new byte[] { 0x7B, 0x22, 0x76, 0x22, 0x3A, 0x22, 0xF4, 0x90, 0x80, 0x80, 0x22, 0x7D },
        DisplayName = "A code point past U+10FFFF")]
    public void ADocumentHoldingBytesThatAreNoUtf8IsNone(byte[] document)
    {
        var members = JwkJsonReader.ReadTopLevelMembers(document);

        Assert.IsNull(members, $"No members are read from it; read {(members is null ? "none" : string.Join(", ", members))}.");
        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(document), "The document is no well-formed JSON text.");
    }


    /// <summary>
    /// The bounds of well-formed UTF-8 are text: the greatest scalar value each sequence length encodes, and the scalar values
    /// either side of the surrogate range, are read as the characters they encode, so the refusal of malformed bytes refuses
    /// none of them.
    /// </summary>
    [TestMethod]
    public void TheBoundsOfWellFormedUtf8AreReadAsText()
    {
        byte[] document =
        [
            0x7B, 0x22, 0x76, 0x22, 0x3A, 0x22,
            0x7F, 0xDF, 0xBF, 0xED, 0x9F, 0xBF, 0xEE, 0x80, 0x80, 0xEF, 0xBF, 0xBF, 0xF4, 0x8F, 0xBF, 0xBF,
            0x22, 0x7D
        ];

        var members = JwkJsonReader.ReadTopLevelMembers(document);

        Assert.IsNotNull(members, "The document is well formed.");
        Assert.HasCount(1, members);
        Assert.AreEqual(new JsonTopLevelMember("v", JsonTopLevelValueKind.String, "\u007F\u07FF\uD7FF\uE000\uFFFF\U0010FFFF"), members[0]);
    }


    /// <summary>The reader's kind of a value of the oracle's kind.</summary>
    /// <param name="kind">The oracle's kind.</param>
    /// <returns>The reader's kind.</returns>
    private static JsonTopLevelValueKind KindOf(JsonValueKind kind) => kind switch
    {
        JsonValueKind.String => JsonTopLevelValueKind.String,
        JsonValueKind.Number => JsonTopLevelValueKind.Number,
        JsonValueKind.True => JsonTopLevelValueKind.True,
        JsonValueKind.False => JsonTopLevelValueKind.False,
        JsonValueKind.Null => JsonTopLevelValueKind.Null,
        JsonValueKind.Object => JsonTopLevelValueKind.Object,
        JsonValueKind.Array => JsonTopLevelValueKind.Array,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "No member value is of this kind.")
    };
}
