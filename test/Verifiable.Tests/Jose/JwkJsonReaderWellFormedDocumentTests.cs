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
        //RFC 8259 §4 names compare by decoded value; k decodes to 'k' (RFC 8259 §7).
        string json = """{"kid":"a","kid":"b"}""";

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


    [TestMethod]
    public void NeverThrowsOnALoneSurrogateEscape()
    {
        //RFC 8259 §7 requires \u followed by four hex digits; it says nothing about the resulting
        //code unit being paired, so a lone surrogate escape is syntactically valid and not a reason
        //to refuse — this is a Unicode string well-formedness question, not a JSON grammar one.
        string json = """{"a":"\ud800"}""";

        Assert.IsTrue(JwkJsonReader.IsWellFormedJsonDocument(Utf8(json)));
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
