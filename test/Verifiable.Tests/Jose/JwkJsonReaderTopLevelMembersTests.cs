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
        var reading = JwkJsonReader.ReadTopLevelMembers(Encoding.UTF8.GetBytes(document));
        var members = Assert.IsInstanceOfType<JsonTopLevelMembers>(reading, "A well-formed object is read.").Members;

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
    /// A document that is not exactly one well-formed JSON object is no object: an array, a string, one never closed and one
    /// followed by more text, each also when it repeats a name or holds a string naming no Unicode text, as a document that is
    /// no well-formed object names no member at all, once, more than once or in no text.
    /// </summary>
    /// <param name="document">The document.</param>
    [TestMethod]
    [DataRow(/*lang=json,strict*/ """["access_token","top"]""", DisplayName = "An array")]
    [DataRow(/*lang=json,strict*/ "\"access_token\"", DisplayName = "A string")]
    [DataRow("{\"access_token\":\"top\"", DisplayName = "An object never closed")]
    [DataRow("""{"access_token":"top"}{"access_token":"second"}""", DisplayName = "An object followed by another")]
    [DataRow(
        /*lang=json*/ """[{"access_token":"first","access_token":"second"}]""",
        DisplayName = "An array holding an object that repeats a name")]
    [DataRow(
        "{\"access_token\":\"first\",\"access_token\":\"second\"",
        DisplayName = "An object never closed that repeats a name")]
    [DataRow(
        """{"access_token":"first","access_token":"second"}{"access_token":"third"}""",
        DisplayName = "An object repeating a name followed by another")]
    [DataRow("{\"access_token\":\"\\uD800\"", DisplayName = "An object never closed whose member names no Unicode text")]
    [DataRow(/*lang=json*/ """["\uD800"]""", DisplayName = "An array holding a string that names no Unicode text")]
    [DataRow(
        """{"access_token":"\uD800"}{"token_type":"Bearer"}""",
        DisplayName = "An object whose member names no Unicode text followed by another")]
    public void ADocumentThatIsNotOneWellFormedObjectIsNone(string document)
    {
        var reading = JwkJsonReader.ReadTopLevelMembers(Encoding.UTF8.GetBytes(document));

        _ = Assert.IsInstanceOfType<JsonNotOneObject>(reading, "No members are read from it, and no name is said to repeat.");
    }


    /// <summary>
    /// RFC 8259 section 4: the names within an object SHOULD be unique, and "the behavior of software that receives such an
    /// object is unpredictable". A well-formed object one of whose objects repeats a name breaks no rule of the grammar, so it
    /// is refused for the repetition itself, never as a document that is not well formed: the reading names the repeated name,
    /// decoded once (RFC 8259 section 7), and the depth of the object repeating it.
    /// </summary>
    /// <param name="document">The document.</param>
    /// <param name="expectedName">The repeated name.</param>
    /// <param name="expectedDepth">The depth of the object repeating it.</param>
    [TestMethod]
    [DataRow(
        /*lang=json*/ """{"access_token":"first","access_token":"second","token_type":"Bearer"}""",
        "access_token",
        1,
        DisplayName = "A name repeated at the top level")]
    [DataRow(
        /*lang=json*/ """{"access_token":"first","access\u005ftoken":"second"}""",
        "access_token",
        1,
        DisplayName = "A name repeated through an escape")]
    [DataRow(
        /*lang=json*/ """{"access_token":"at","ext":{"note":"one","note":"two"}}""",
        "note",
        2,
        DisplayName = "A name repeated in a nested object")]
    [DataRow(
        /*lang=json*/ """{"list":[{"b":1,"b":2}],"access_token":"at","access_token":"again"}""",
        "b",
        3,
        DisplayName = "The first repetition, in an object within an array, before a later one")]
    public void ARepeatedNameIsRefusedByTheNameAndTheDepthOfItsObject(string document, string expectedName, int expectedDepth)
    {
        var reading = JwkJsonReader.ReadTopLevelMembers(Encoding.UTF8.GetBytes(document));

        var repeated = Assert.IsInstanceOfType<JsonRepeatedMemberName>(reading, "The repetition is refused as itself.");
        Assert.AreEqual(expectedName, repeated.Name, "The repeated name, decoded.");
        Assert.AreEqual(expectedDepth, repeated.ObjectDepth, "The depth of the object repeating it.");
        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Encoding.UTF8.GetBytes(document)), "The whole-document judgement still refuses it.");
    }


    /// <summary>
    /// RFC 8259 section 8.2: an escape naming an unpaired surrogate is grammatical but names no Unicode text, and the behavior
    /// of software receiving it is unpredictable. A well-formed object one of whose members has a name or a string value so
    /// spelled - at the top level or nested, in a member any reader reads or in one none reads, the value itself or a string an
    /// array value holds - is refused by that member: its name as it can be written, the depth of the object carrying it and
    /// which part names no text. A name that is the defect is answered as the document spells it, escapes as written, so the
    /// refusal holds text a strict encoder writes.
    /// </summary>
    /// <param name="document">The document.</param>
    /// <param name="expectedName">The member's name as the refusal carries it.</param>
    /// <param name="expectedDepth">The depth of the object carrying the member.</param>
    /// <param name="expectedPart">Which part of the member names no Unicode text.</param>
    [TestMethod]
    [DataRow(
        /*lang=json*/ """{"access_token":"at","token_type":"Bearer","ext":"\uD800"}""",
        "ext",
        1,
        JsonUndecodableMemberPart.Value,
        DisplayName = "A value in a top-level member no reader reads")]
    [DataRow(
        /*lang=json*/ """{"access_token":"at","ext":{"note":"x\uDC00"}}""",
        "note",
        2,
        JsonUndecodableMemberPart.Value,
        DisplayName = "A value in a nested object")]
    [DataRow(
        /*lang=json*/ """{"access_token":"at","aud":["one","\uD800"]}""",
        "aud",
        1,
        JsonUndecodableMemberPart.Value,
        DisplayName = "A string an array value holds")]
    [DataRow(
        /*lang=json*/ """{"ext":{"list":[["\uDBFF"]]}}""",
        "list",
        2,
        JsonUndecodableMemberPart.Value,
        DisplayName = "A string an array within an array holds, in a nested object")]
    [DataRow(
        /*lang=json*/ """{"v":"\uD800\uD800\uDC00"}""",
        "v",
        1,
        JsonUndecodableMemberPart.Value,
        DisplayName = "A high surrogate followed by a pair")]
    [DataRow(
        /*lang=json*/ """{"acc\u0065ss_token":"\uDFFF"}""",
        "access_token",
        1,
        JsonUndecodableMemberPart.Value,
        DisplayName = "A value whose member is named through an escape, the name decoded")]
    [DataRow(
        /*lang=json*/ """{"access_token":"at","\uDC00":"v"}""",
        "\\uDC00",
        1,
        JsonUndecodableMemberPart.Name,
        DisplayName = "A top-level name, spelled as the document escapes it")]
    [DataRow(
        /*lang=json*/ """{"ext":{"a\uD800b":1}}""",
        "a\\uD800b",
        2,
        JsonUndecodableMemberPart.Name,
        DisplayName = "A nested name, spelled as the document escapes it")]
    public void AMemberNamingNoUnicodeTextRefusesTheDocument(
        string document,
        string expectedName,
        int expectedDepth,
        JsonUndecodableMemberPart expectedPart)
    {
        var reading = JwkJsonReader.ReadTopLevelMembers(Encoding.UTF8.GetBytes(document));

        var undecodable = Assert.IsInstanceOfType<JsonUndecodableMember>(reading, $"The member is the reason; read {reading}.");
        Assert.AreEqual(expectedName, undecodable.Name, "The member's name as it can be written.");
        Assert.AreEqual(expectedDepth, undecodable.ObjectDepth, "The depth of the object carrying it.");
        Assert.AreEqual(expectedPart, undecodable.Part, "Which part names no Unicode text.");

        var strict = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
        Assert.AreEqual(undecodable.Name, strict.GetString(strict.GetBytes(undecodable.Name)), "The name is text a strict encoder writes.");
    }


    /// <summary>
    /// When a well-formed object both repeats a name and holds a member naming no Unicode text, the defect the document reaches
    /// first is answered, the order a reader meets them in: a value naming no text written before the repeating occurrence of
    /// its member's name, or a string an array holds before a later repetition, is answered as undecodable, and a name naming
    /// no text as undecodable at its first occurrence, before its repetition.
    /// </summary>
    /// <param name="document">The document.</param>
    /// <param name="expectedName">The member's name as the refusal carries it.</param>
    /// <param name="expectedDepth">The depth of the object carrying the member.</param>
    /// <param name="expectedPart">Which part of the member names no Unicode text.</param>
    [TestMethod]
    [DataRow(
        /*lang=json*/ """{"a":"\uD800","a":"x"}""",
        "a",
        1,
        JsonUndecodableMemberPart.Value,
        DisplayName = "A value naming no text before its name is repeated")]
    [DataRow(
        /*lang=json*/ """{"v":["\uDC00"],"list":[{"b":1,"b":2}]}""",
        "v",
        1,
        JsonUndecodableMemberPart.Value,
        DisplayName = "A string an array holds before a later repetition")]
    [DataRow(
        /*lang=json*/ """{"\uD800":1,"\uD800":2}""",
        "\\uD800",
        1,
        JsonUndecodableMemberPart.Name,
        DisplayName = "A name naming no text, repeated")]
    public void AnUndecodableMemberTheDocumentReachesFirstIsAnsweredBeforeARepetition(
        string document,
        string expectedName,
        int expectedDepth,
        JsonUndecodableMemberPart expectedPart)
    {
        var reading = JwkJsonReader.ReadTopLevelMembers(Encoding.UTF8.GetBytes(document));

        var undecodable = Assert.IsInstanceOfType<JsonUndecodableMember>(reading, "The first defect in document order.");
        Assert.AreEqual(expectedName, undecodable.Name, "The member's name as it can be written.");
        Assert.AreEqual(expectedDepth, undecodable.ObjectDepth, "The depth of the object carrying it.");
        Assert.AreEqual(expectedPart, undecodable.Part, "Which part names no Unicode text.");
    }


    /// <summary>
    /// A repetition the document reaches before any member naming no Unicode text is answered as the repetition: a value naming
    /// no text written after the repeating occurrence of its member's name, and one in a member after a repetition in an object
    /// within an array.
    /// </summary>
    /// <param name="document">The document.</param>
    /// <param name="expectedName">The repeated name.</param>
    /// <param name="expectedDepth">The depth of the object repeating it.</param>
    [TestMethod]
    [DataRow(
        /*lang=json*/ """{"a":"x","a":"\uD800"}""",
        "a",
        1,
        DisplayName = "A value naming no text after its name is repeated")]
    [DataRow(
        /*lang=json*/ """{"list":[{"b":1,"b":2}],"v":"\uDC00"}""",
        "b",
        3,
        DisplayName = "A repetition in an object within an array before a value naming no text")]
    public void ARepetitionTheDocumentReachesFirstIsAnsweredBeforeAnUndecodableMember(string document, string expectedName, int expectedDepth)
    {
        var reading = JwkJsonReader.ReadTopLevelMembers(Encoding.UTF8.GetBytes(document));

        var repeated = Assert.IsInstanceOfType<JsonRepeatedMemberName>(reading, "The first defect in document order.");
        Assert.AreEqual(expectedName, repeated.Name, "The repeated name, decoded.");
        Assert.AreEqual(expectedDepth, repeated.ObjectDepth, "The depth of the object repeating it.");
    }


    /// <summary>
    /// RFC 8259 section 8.1: JSON text exchanged between systems "MUST be encoded using UTF-8". A document holding bytes that are
    /// no well-formed UTF-8 - in a member name, in a string value, in a name or a string nested beneath the top level - is no
    /// well-formed document, so it is no object, never one whose text holds a character its bytes do not encode, also when a
    /// string before them names no Unicode text. The rows are bytes, as no managed string carries such a sequence.
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
    [DataRow(
        new byte[]
        {
            0x7B, 0x22, 0x76, 0x22, 0x3A, 0x22, 0x5C, 0x75, 0x44, 0x38, 0x30, 0x30, 0x22,
            0x2C, 0x22, 0x77, 0x22, 0x3A, 0x22, 0xFF, 0x22, 0x7D
        },
        DisplayName = "FF after a value naming no Unicode text")]
    public void ADocumentHoldingBytesThatAreNoUtf8IsNone(byte[] document)
    {
        var reading = JwkJsonReader.ReadTopLevelMembers(document);

        _ = Assert.IsInstanceOfType<JsonNotOneObject>(reading, $"No members are read from it; read {reading}.");
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
        var document = new byte[]
        {
            0x7B, 0x22, 0x76, 0x22, 0x3A, 0x22,
            0x7F, 0xDF, 0xBF, 0xED, 0x9F, 0xBF, 0xEE, 0x80, 0x80, 0xEF, 0xBF, 0xBF, 0xF4, 0x8F, 0xBF, 0xBF,
            0x22, 0x7D
        };

        var reading = JwkJsonReader.ReadTopLevelMembers(document);

        var members = Assert.IsInstanceOfType<JsonTopLevelMembers>(reading, "The document is well formed.").Members;
        Assert.HasCount(1, members);
        Assert.AreEqual(new JsonTopLevelMember("v", JsonTopLevelValueKind.String, "\u007F\u07FF\uD7FF\uE000\uFFFF\U0010FFFF"), members[0]);
    }


    /// <summary>
    /// A member asked for by name is answered as one typed case: a string with its decoded text, a number with its spelling as
    /// written, a literal, an object or an array naming its kind, and a name the object does not carry at its top level - one only
    /// a nested object carries among them - as absent. The name asked for is the decoded name, so an escaped spelling is found.
    /// </summary>
    [TestMethod]
    public void AMemberAskedForByNameIsAnsweredAsOneTypedCase()
    {
        var document = /*lang=json,strict*/ """{"s":"café","n":-1.5e3,"t":true,"z":null,"o":{"nested":"x"},"a":[1],"esc\u0061ped":"v"}""";
        var reading = JwkJsonReader.ReadTopLevelMembers(Encoding.UTF8.GetBytes(document));
        var members = Assert.IsInstanceOfType<JsonTopLevelMembers>(reading, "A well-formed object is read.");

        Assert.Contains("esc\\u0061ped", document, "The name is spelled through an escape of its letter a.");
        Assert.AreEqual(new JsonMemberString("café"), members.Find("s"), "A string, decoded.");
        Assert.AreEqual(new JsonMemberNumber("-1.5e3"), members.Find("n"), "A number, its spelling as written.");
        Assert.AreEqual(new JsonMemberOfOtherKind(JsonTopLevelValueKind.True), members.Find("t"), "A literal names its kind.");
        Assert.AreEqual(new JsonMemberOfOtherKind(JsonTopLevelValueKind.Null), members.Find("z"), "The null literal names its kind.");
        Assert.AreEqual(new JsonMemberOfOtherKind(JsonTopLevelValueKind.Object), members.Find("o"), "An object names its kind.");
        Assert.AreEqual(new JsonMemberOfOtherKind(JsonTopLevelValueKind.Array), members.Find("a"), "An array names its kind.");
        Assert.AreEqual(new JsonMemberString("v"), members.Find("escaped"), "A name spelled through an escape is found by its decoded name.");
        Assert.AreEqual(new JsonMemberAbsent(), members.Find("nested"), "A member only a nested object carries is absent from the top level.");
        Assert.AreEqual(new JsonMemberAbsent(), members.Find("missing"), "A name the object does not carry is absent.");
    }


    /// <summary>
    /// The members answered carry the account of the top-level members observed without their values: each string as the length
    /// of its decoded text in UTF-16 code units - an escape decoded first, a surrogate pair two units - and each other value by
    /// its kind.
    /// </summary>
    [TestMethod]
    public void TheMembersAnsweredCarryTheirAccountWithoutTheirValues()
    {
        var document = /*lang=json,strict*/ """{"access_token":"a\/b","pair":"😀","n":7}""";
        var reading = JwkJsonReader.ReadTopLevelMembers(Encoding.UTF8.GetBytes(document));
        var account = Assert.IsInstanceOfType<JsonTopLevelMembers>(reading, "A well-formed object is read.").TopLevel;

        var expected = new JsonTopLevelAccount(
        [
            new JsonTopLevelObservation("access_token", new JsonReadableString(3)),
            new JsonTopLevelObservation("pair", new JsonReadableString(2)),
            new JsonTopLevelObservation("n", new JsonNonStringValue(JsonTopLevelValueKind.Number))
        ]);

        Assert.AreEqual(expected, account, "Each member observed in document order, no value carried.");
    }


    /// <summary>
    /// A refusal of a well-formed object carries the account of its top-level members from the same reading: beside an extension
    /// member naming no Unicode text, a readable <c>access_token</c> is observed with the length of its text and the extension
    /// member as naming none; a repeated <c>access_token</c> is observed at both occurrences; and a member whose own name names no
    /// Unicode text is left out, as no reader can ask for it by name. No observation carries a value.
    /// </summary>
    [TestMethod]
    public void TheRefusalsOfAWellFormedObjectCarryTheTopLevelMembersObserved()
    {
        var undecodable = JwkJsonReader.ReadTopLevelMembers(Encoding.UTF8.GetBytes(
            /*lang=json*/ """{"access_token":"kx7Qz","token_type":"Bearer","ext":"\uD800","\uDC00":"v"}"""));

        var repeated = JwkJsonReader.ReadTopLevelMembers(Encoding.UTF8.GetBytes(
            /*lang=json*/ """{"access_token":"first-credential-text","access_token":"second","token_type":"Bearer"}"""));

        var undecodableAccount = Assert.IsInstanceOfType<JsonUndecodableMember>(undecodable, "The extension member is the reason.").TopLevel;
        var repeatedAccount = Assert.IsInstanceOfType<JsonRepeatedMemberName>(repeated, "The repetition is the reason.").TopLevel;

        var expectedUndecodable = new JsonTopLevelAccount(
        [
            new JsonTopLevelObservation("access_token", new JsonReadableString(5)),
            new JsonTopLevelObservation("token_type", new JsonReadableString(6)),
            new JsonTopLevelObservation("ext", new JsonUndecodableString())
        ]);

        Assert.AreEqual(expectedUndecodable, undecodableAccount, "The readable credential, its length and no value; the member naming no text left out.");
        Assert.AreSequenceEqual(
            new JsonValueObservation[] { new JsonReadableString(21), new JsonReadableString(6) },
            repeatedAccount.OccurrencesOf("access_token").ToArray(),
            "Both occurrences of the repeated name, in document order.");
        Assert.DoesNotContain("kx7Qz", undecodable.ToString(), "The refusal's text carries no value.");
        Assert.DoesNotContain("credential-text", repeated.ToString(), "The refusal's text carries no value.");
    }


    /// <summary>
    /// A member's array elements (<see cref="JsonTopLevelMember.ArrayElements"/>) are answered only for text the strict judgement
    /// admits as one well-formed array of Unicode text, judged whole, at every depth: an object or an array nested in it holding a
    /// string whose escape names an unpaired surrogate (RFC 8259 section 8.2), and a text a caller composed holding an unpaired
    /// surrogate itself, directly or nested, are refused, never answered with an element encoded over the defect; the controls,
    /// the same shapes naming Unicode text, are answered element for element.
    /// </summary>
    /// <param name="textCase">The name of the array's text.</param>
    /// <param name="admitted">Whether the elements are answered.</param>
    [TestMethod]
    [DataRow("escaped-surrogate-in-a-nested-object", false)]
    [DataRow("escaped-surrogate-in-a-nested-array", false)]
    [DataRow("literal-surrogate-in-an-element", false)]
    [DataRow("literal-surrogate-in-a-nested-array", false)]
    [DataRow("escaped-pair-in-a-nested-object", true)]
    [DataRow("text-in-a-nested-array", true)]
    public void ArrayElementsJudgeTheWholeArrayAsUnicodeText(string textCase, bool admitted)
    {
        var text = textCase switch
        {
            "escaped-surrogate-in-a-nested-object" => /*lang=json*/ """[{"v":"\uD800"}]""",
            "escaped-surrogate-in-a-nested-array" => /*lang=json*/ """[["\uD800"]]""",
            "literal-surrogate-in-an-element" => "[\"\uD800\"]",
            "literal-surrogate-in-a-nested-array" => "[[\"a\uDC00\"]]",
            "escaped-pair-in-a-nested-object" => /*lang=json,strict*/ """[{"v":"\uD83D\uDE00"}]""",
            "text-in-a-nested-array" => /*lang=json,strict*/ """[["ok"],"x"]""",
            _ => throw new ArgumentOutOfRangeException(nameof(textCase), textCase, "No array text is named so.")
        };

        var elements = new JsonTopLevelMember("m", JsonTopLevelValueKind.Array, text).ArrayElements();

        Assert.AreEqual(admitted, elements is not null, textCase);

        if(admitted)
        {
            Assert.AreEqual(new JsonMemberOfOtherKind(textCase is "text-in-a-nested-array" ? JsonTopLevelValueKind.Array : JsonTopLevelValueKind.Object), elements?[0]);
        }
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
