using System.Globalization;
using System.Text;
using CsCheck;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests for <see cref="JwkJsonReader.IsWellFormedJsonDocument"/>: the strict pass a caller runs, once,
/// over a document that arrived from outside the process before extracting anything from it, per
/// <see href="https://www.rfc-editor.org/rfc/rfc8259">RFC 8259</see>.
/// </summary>
[TestClass]
internal sealed class JwkJsonReaderWellFormedDocumentTests
{
    private static byte[] Utf8(string text) =>
        Encoding.UTF8.GetBytes(text);


    [TestMethod]
    public void AcceptsAMinimalKeySet()
    {
        //RFC 8259 §2: an object whose one member's value is an empty array is one well-formed JSON value.
        Assert.IsTrue(JwkJsonReader.IsWellFormedJsonDocument(Utf8("""{"keys":[]}""")));
    }


    [TestMethod]
    public void AcceptsNestedObjectsAndArrays()
    {
        string json = """{"keys":[{"kty":"EC","crv":"P-256","x5c":["a","b"],"epk":{"kty":"EC","crv":"P-256"}}]}""";

        Assert.IsTrue(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void AcceptsEveryStringEscapeForm()
    {
        //RFC 8259 §7: the two-character escapes, and \u followed by exactly four hex digits.
        string json = """{"a":"\"\\\/\b\f\n\r\tA"}""";

        Assert.IsTrue(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void AcceptsNumbersInEveryGrammarForm()
    {
        //RFC 8259 §6: an optional leading minus, an integer part, an optional fraction, and an
        //optional exponent in either letter case with an optional sign.
        string json = """{"a":0,"b":-0,"c":123,"d":-45,"e":1.5,"f":1.5e10,"g":1.5E+10,"h":1.5e-10,"i":2E3}""";

        Assert.IsTrue(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void AcceptsLeadingAndTrailingWhitespace()
    {
        //RFC 8259 §2: insignificant whitespace is permitted before and after the value.
        string json = "  \t\r\n{\"a\":1}\n\t  ";

        Assert.IsTrue(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void AcceptsDepthAtTheBound()
    {
        string json = string.Concat(Enumerable.Repeat("{\"a\":", JwkJsonReader.MaximumNestingDepth))
            + "1"
            + string.Concat(Enumerable.Repeat("}", JwkJsonReader.MaximumNestingDepth));

        Assert.IsTrue(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void RejectsDuplicateTopLevelKeysArrayCleanThenDirty()
    {
        //RFC 8259 §4: "the behavior of software that receives such an object is unpredictable."
        string json = """{"keys":[],"keys":[{"kid":"a"}]}""";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void RejectsDuplicateTopLevelKeysArrayDirtyThenClean()
    {
        string json = """{"keys":[{"kid":"a"}],"keys":[]}""";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void RejectsDuplicateKidInsideAKey()
    {
        string json = """{"keys":[{"kty":"EC","kid":"a","kid":"b"}]}""";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void RejectsDuplicateNameThatDiffersOnlyByEscape()
    {
        //RFC 8259 §4 names compare by decoded value; \u006b decodes to 'k' (RFC 8259 §7).
        string json = """{"\u006bid":"a","kid":"b"}""";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void RejectsDuplicateInANestedObject()
    {
        string json = """{"cnf":{"jwk":{"kty":"EC","kty":"RSA"}}}""";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void RejectsADocumentMissingItsFinalBrace()
    {
        string json = """{"keys":[{"kid":"a"}]""";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void RejectsADocumentEndingInsideAString()
    {
        string json = """{"kid":"abc""";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void RejectsADocumentEndingInsideANumber()
    {
        string json = """{"exp":1.5e""";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void RejectsADocumentEndingInsideALiteral()
    {
        string json = """{"ok":tru""";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void RejectsTrailingGarbageAfterTheValue()
    {
        //RFC 8259 §2: only insignificant whitespace may follow the value.
        string json = """{"keys":[]}garbage""";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void RejectsATrailingComma()
    {
        string json = """{"a":1,}""";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void RejectsAnUnescapedControlCharacter()
    {
        //RFC 8259 §7: a character below U+0020 must be escaped.
        string json = "{\"a\":\"xy\"}";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void RejectsABadEscape()
    {
        string json = """{"a":"\q"}""";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void RejectsAShortUnicodeEscape()
    {
        string json = """{"a":"\u12"}""";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void RejectsDepthOverTheBound()
    {
        string json = string.Concat(Enumerable.Repeat("{\"a\":", JwkJsonReader.MaximumNestingDepth + 1))
            + "1"
            + string.Concat(Enumerable.Repeat("}", JwkJsonReader.MaximumNestingDepth + 1));

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void RejectsEmptyInput()
    {
        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8("")));
    }


    [TestMethod]
    public void RejectsWhitespaceOnlyInput()
    {
        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8("   \t\r\n  ")));
    }


    /// <summary>
    /// A surrogate escape that is not one half of an escaped high-then-low pair is refused, in a value and
    /// in a member name, without throwing: RFC 7493 §2.1 (I-JSON) forbids a string that holds an unpaired
    /// surrogate, escaped or not, though RFC 8259 §7's grammar admits the escape.
    /// </summary>
    /// <param name="json">The document holding the unpaired surrogate escape.</param>
    [TestMethod]
    [DataRow("""{"a":"\ud800"}""", DisplayName = "a lone high surrogate in a value")]
    [DataRow("""{"a":"\udc00"}""", DisplayName = "a lone low surrogate in a value")]
    [DataRow("""{"a":"x\ud800"}""", DisplayName = "a high surrogate ending a value")]
    [DataRow("""{"a":"\ud800\u0041"}""", DisplayName = "a high surrogate followed by another escape")]
    [DataRow("""{"a":"\ud800x"}""", DisplayName = "a high surrogate followed by a character")]
    [DataRow("""{"a":"\ud800\n"}""", DisplayName = "a high surrogate followed by a two-character escape")]
    [DataRow("""{"a":"\udc00\ud800"}""", DisplayName = "a pair written low first")]
    [DataRow("""{"a":"\ud800\ud800"}""", DisplayName = "two high surrogates")]
    [DataRow("""{"\ud800":1}""", DisplayName = "a lone high surrogate in a member name")]
    [DataRow("""{"a":{"b":["\udfff"]}}""", DisplayName = "a lone low surrogate in an array at depth")]
    public void RefusesAnUnpairedSurrogateEscape(string json)
    {
        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    /// <summary>
    /// A high surrogate escape followed at once by a low surrogate escape spells one character above the
    /// Basic Multilingual Plane and is admitted, in either hex letter case (RFC 8259 §7: "To escape an
    /// extended character that is not in the Basic Multilingual Plane, the character is represented as a
    /// 12-character sequence, encoding the UTF-16 surrogate pair.").
    /// </summary>
    /// <param name="json">The document holding the escaped pair.</param>
    [TestMethod]
    [DataRow("""{"a":"\ud83d\ude00"}""", DisplayName = "U+1F600 in a value")]
    [DataRow("""{"a":"\uD834\uDD1E"}""", DisplayName = "U+1D11E in upper-case hex")]
    [DataRow("""{"\ud83d\ude00":1}""", DisplayName = "U+1F600 as a member name")]
    public void AcceptsAnEscapedSurrogatePair(string json)
    {
        Assert.IsTrue(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    /// <summary>
    /// U+0000 written as an escape is refused, in a value and in a member name, a rule of this library: the
    /// text the reader extracts becomes a member name, a key identifier, a replay identifier or an issuer a
    /// durable store holds, and a store of text cannot hold U+0000. RFC 8259 §7 and RFC 7493 §2.1 both admit
    /// it. Written directly, it is a control character RFC 8259 §7 already requires to be escaped.
    /// </summary>
    /// <param name="json">The document holding the escaped U+0000.</param>
    [TestMethod]
    [DataRow("""{"a":"\u0000"}""", DisplayName = "U+0000 as a whole value")]
    [DataRow("""{"a":"x\u0000y"}""", DisplayName = "U+0000 inside a value")]
    [DataRow("""{"jti\u0000":"a"}""", DisplayName = "U+0000 in a member name")]
    [DataRow("""{"a":["b",{"c":"\u0000"}]}""", DisplayName = "U+0000 at depth")]
    public void RefusesAnEscapedNullCharacter(string json)
    {
        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    /// <summary>
    /// A Unicode noncharacter is refused whether it is escaped, escaped as a surrogate pair, or written
    /// directly as UTF-8 (RFC 7493 §2.1, I-JSON), while the code points beside each noncharacter range are
    /// admitted.
    /// </summary>
    /// <param name="escapedText">The string content, in JSON escape form.</param>
    /// <param name="isAdmitted">Whether the content is admitted.</param>
    [TestMethod]
    [DataRow("\\ufdd0", false, DisplayName = "U+FDD0, the first contiguous noncharacter")]
    [DataRow("\\ufdef", false, DisplayName = "U+FDEF, the last contiguous noncharacter")]
    [DataRow("\\ufffe", false, DisplayName = "U+FFFE")]
    [DataRow("\\uFFFF", false, DisplayName = "U+FFFF")]
    [DataRow("\\ud83f\\udffe", false, DisplayName = "U+1FFFE as a pair")]
    [DataRow("\\udbff\\udfff", false, DisplayName = "U+10FFFF as a pair")]
    [DataRow("\\ufdcf", true, DisplayName = "U+FDCF before the range")]
    [DataRow("\\ufdf0", true, DisplayName = "U+FDF0 after the range")]
    [DataRow("\\ufffd", true, DisplayName = "U+FFFD, the replacement character")]
    [DataRow("\\ud83f\\udffd", true, DisplayName = "U+1FFFD as a pair")]
    public void RefusesAnEscapedNoncharacterAndAdmitsItsNeighbours(string escapedText, bool isAdmitted)
    {
        string json = "{\"a\":\"" + escapedText + "\"}";

        Assert.AreEqual(isAdmitted, JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    /// <summary>
    /// String content that is not well-formed UTF-8 is refused (RFC 7493 §2.1: I-JSON text is UTF-8;
    /// RFC 3629 §3 makes an overlong form, an encoded surrogate, a code point past U+10FFFF and a truncated
    /// sequence ill-formed), as is a noncharacter written directly; well-formed text of two, three and four
    /// bytes is admitted.
    /// </summary>
    /// <param name="hexContent">The raw string content bytes, as hexadecimal.</param>
    /// <param name="isAdmitted">Whether the content is admitted.</param>
    [TestMethod]
    [DataRow("FF", false, DisplayName = "a byte that begins no sequence")]
    [DataRow("80", false, DisplayName = "a continuation byte alone")]
    [DataRow("C080", false, DisplayName = "an overlong U+0000")]
    [DataRow("C1BF", false, DisplayName = "an overlong U+007F")]
    [DataRow("EDA080", false, DisplayName = "an encoded high surrogate")]
    [DataRow("EDBFBF", false, DisplayName = "an encoded low surrogate")]
    [DataRow("F4908080", false, DisplayName = "a code point past U+10FFFF")]
    [DataRow("E282", false, DisplayName = "a truncated sequence")]
    [DataRow("EFBFBF", false, DisplayName = "U+FFFF written directly")]
    [DataRow("EFB790", false, DisplayName = "U+FDD0 written directly")]
    [DataRow("C3A9", true, DisplayName = "U+00E9")]
    [DataRow("E282AC", true, DisplayName = "U+20AC")]
    [DataRow("F09F9880", true, DisplayName = "U+1F600")]
    public void RefusesRawContentThatIsNotAUtf8CharacterAndAdmitsWellFormedText(string hexContent, bool isAdmitted)
    {
        byte[] json = [.. "{\"a\":\"x"u8, .. Convert.FromHexString(hexContent), .. "y\"}"u8];

        Assert.AreEqual(isAdmitted, JwkJsonReader.IsWellFormedJsonDocument(json));
    }


    /// <summary>
    /// A name repeated in an object at depth, once plain and once with a leading escape, is a repeated
    /// name: names compare as the text they spell (RFC 8259 §8.3), and RFC 8259 §4 leaves the behavior of
    /// software receiving such an object unpredictable.
    /// </summary>
    [TestMethod]
    public void RefusesANameRepeatedAtDepthBehindALeadingEscape()
    {
        string json = """{"a":{"b":[{"kid":"one","\u006bid":"two"}]}}""";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    private static Gen<string> GenFieldName { get; } =
        Gen.String[Gen.Char.AlphaNumeric, 1, 6];

    private static Gen<string> GenStringValue { get; } =
        Gen.Char.AlphaNumeric.Array[0, 6].Select(chars => "\"" + new string(chars) + "\"");

    private static Gen<string> GenNumberValue { get; } =
        Gen.Int.Select(i => i.ToString(CultureInfo.InvariantCulture));

    private static Gen<string> GenScalarValue { get; } =
        Gen.OneOf(GenStringValue, GenNumberValue, Gen.Const("true"), Gen.Const("false"), Gen.Const("null"));


    //A JSON value down to the given nesting depth: a scalar at depth 0, otherwise also possibly a
    //nested array or object whose own member names are independently unique.
    private static Gen<string> GenValue(int depth) =>
        depth <= 0
            ? GenScalarValue
            : Gen.OneOf(GenScalarValue, GenArrayText(depth - 1), GenObjectText(depth - 1));


    private static Gen<string> GenArrayText(int depth) =>
        GenValue(depth).Array[0, 3].Select(items => "[" + string.Join(",", items) + "]");


    //An object text with 1-4 DISTINCT member names — the property this validator is exercised
    //against — each bound to an independently generated value.
    private static Gen<string> GenObjectText(int depth) =>
        Gen.Int[1, 4].SelectMany(count =>
            GenFieldName.Array[count, count]
                .Where(names => names.Distinct(StringComparer.Ordinal).Count() == names.Length)
                .SelectMany(names => GenValue(depth).Array[count, count]
                    .Select(values => BuildObjectText(names, values))));


    //Like GenObjectText, but also reports the first member's name and value so a test can splice a
    //duplicate of it back in.
    private static Gen<(string Json, string Name, string Value)> GenObjectTextWithFirstMember(int depth) =>
        Gen.Int[1, 4].SelectMany(count =>
            GenFieldName.Array[count, count]
                .Where(names => names.Distinct(StringComparer.Ordinal).Count() == names.Length)
                .SelectMany(names => GenValue(depth).Array[count, count]
                    .Select(values => (BuildObjectText(names, values), names[0], values[0]))));


    private static string BuildObjectText(string[] names, string[] values)
    {
        string[] members = new string[names.Length];
        for(int index = 0; index < names.Length; index++)
        {
            members[index] = $"\"{names[index]}\":{values[index]}";
        }

        return "{" + string.Join(",", members) + "}";
    }


    [TestMethod]
    public void GeneratedWellFormedDocumentsWithUniqueNamesAreAccepted()
    {
        GenObjectText(2).Sample(json =>
        {
            Assert.IsTrue(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)),
                $"A generated document with unique names at every depth must be accepted. Input: {json}");
        }, threads: CsCheckSampling.Threads);
    }


    [TestMethod]
    public void InjectingADuplicateOfAnExistingMemberIsRejected()
    {
        GenObjectTextWithFirstMember(2).Sample(sample =>
        {
            (string json, string name, string value) = sample;
            string withDuplicate = json[..^1] + $",\"{name}\":{value}}}";

            Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(withDuplicate)),
                $"Injecting a duplicate of an existing top-level member must be refused. Input: {withDuplicate}");
        }, threads: CsCheckSampling.Threads);
    }


    [TestMethod]
    public void TruncatingAGeneratedDocumentAtARandomOffsetIsRejected()
    {
        GenObjectText(2).SelectMany(json => Gen.Int[0, json.Length - 1].Select(cut => (json, cut)))
            .Sample(sample =>
            {
                (string json, int cut) = sample;
                string truncated = json[..cut];

                Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(truncated)),
                    $"A document truncated before its final byte must be refused. Full: {json}, truncated: {truncated}");
            }, threads: CsCheckSampling.Threads);
    }


    /// <summary>Builds a single flat object with <paramref name="memberCount"/> distinct member names, each an int value.</summary>
    private static string BuildFlatObjectWithUniqueNames(int memberCount, string prefix = "f")
    {
        string[] members = new string[memberCount];
        for(int index = 0; index < memberCount; index++)
        {
            members[index] = $"\"{prefix}{index.ToString(CultureInfo.InvariantCulture)}\":0";
        }

        return "{" + string.Join(",", members) + "}";
    }


    /// <summary>Builds a top-level array holding <paramref name="objectCount"/> copies of the same small object, one after another.</summary>
    private static string BuildArrayOfSmallObjects(int objectCount, int membersPerObject)
    {
        string singleObject = BuildFlatObjectWithUniqueNames(membersPerObject);

        return "[" + string.Join(",", Enumerable.Repeat(singleObject, objectCount)) + "]";
    }


    /// <summary>
    /// Builds an object with <paramref name="parentMemberCount"/> scalar members followed by one more
    /// member whose value is a nested object of <paramref name="nestedMemberCount"/> distinct members, so
    /// while the nested object is open, the live name count is the sum of both.
    /// </summary>
    private static string BuildParentWithNestedObject(int parentMemberCount, int nestedMemberCount)
    {
        string[] parentMembers = new string[parentMemberCount];
        for(int index = 0; index < parentMemberCount; index++)
        {
            parentMembers[index] = $"\"p{index.ToString(CultureInfo.InvariantCulture)}\":0";
        }

        string nested = BuildFlatObjectWithUniqueNames(nestedMemberCount, "n");

        return "{" + string.Join(",", parentMembers) + ",\"nested\":" + nested + "}";
    }


    /// <summary>Builds a well-formed minimal document padded with trailing spaces out to exactly <paramref name="totalLength"/> bytes.</summary>
    private static byte[] BuildPaddedDocument(int totalLength)
    {
        byte[] prefix = Utf8("""{"a":1}""");
        byte[] document = new byte[totalLength];
        prefix.CopyTo(document, 0);
        for(int index = prefix.Length; index < totalLength; index++)
        {
            document[index] = (byte)' ';
        }

        return document;
    }


    [TestMethod]
    public void AcceptsExactlyTheMaximumLiveMemberNames()
    {
        string json = BuildFlatObjectWithUniqueNames(JwkJsonReader.MaximumLiveMemberNames);

        Assert.IsTrue(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void RejectsOneMoreThanTheMaximumLiveMemberNames()
    {
        string json = BuildFlatObjectWithUniqueNames(JwkJsonReader.MaximumLiveMemberNames + 1);

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void AcceptsManySequentialObjectsWhoseTotalNameCountFarExceedsTheBound()
    {
        //Each object closes before the next opens, so its names are discarded (RemoveNamesAtDepth)
        //and never accumulate; only the live count within one open object is bounded.
        string json = BuildArrayOfSmallObjects(objectCount: JwkJsonReader.MaximumLiveMemberNames * 2, membersPerObject: 4);

        Assert.IsTrue(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void RejectsNestedObjectsWhoseCombinedLiveNamesExceedTheBound()
    {
        int parentMemberCount = (JwkJsonReader.MaximumLiveMemberNames / 2) + 10;
        int nestedMemberCount = (JwkJsonReader.MaximumLiveMemberNames / 2) + 10;
        string json = BuildParentWithNestedObject(parentMemberCount, nestedMemberCount);

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
    }


    [TestMethod]
    public void AcceptsADocumentExactlyAtTheMaximumLength()
    {
        byte[] json = BuildPaddedDocument(JwkJsonReader.MaximumDocumentLength);

        Assert.IsTrue(JwkJsonReader.IsWellFormedJsonDocument(json));
    }


    [TestMethod]
    public void RejectsADocumentOneByteOverTheMaximumLength()
    {
        byte[] json = BuildPaddedDocument(JwkJsonReader.MaximumDocumentLength + 1);

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonDocument(json));
    }
}
