using System.Text;
using Verifiable.JCose;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests for <see cref="JwkJsonReader.IsWellFormedJsonObjectContent"/>: the strict pass a caller runs
/// over the brace-less inner content of one JSON object — as <see cref="JwkJsonReader.ExtractObjectContent"/>
/// returns it — under the same grammar, depth, live-name and length rules as
/// <see cref="JwkJsonReader.IsWellFormedJsonDocument"/>, per <see href="https://www.rfc-editor.org/rfc/rfc8259">RFC 8259</see>.
/// </summary>
[TestClass]
internal sealed class JwkJsonReaderWellFormedObjectContentTests
{
    private static byte[] Utf8(string text) =>
        Encoding.UTF8.GetBytes(text);


    [TestMethod]
    public void AcceptsMembersWithoutEnclosingBraces()
    {
        //RFC 8259 §2: an object's members remain one well-formed value when the caller has already
        //sliced away the object's own braces, as JwkJsonReader.ExtractObjectContent returns them.
        string content = "\"kty\":\"EC\",\"crv\":\"P-256\"";

        Assert.IsTrue(JwkJsonReader.IsWellFormedJsonObjectContent(Utf8(content)));
    }


    [TestMethod]
    public void AcceptsEmptyContentAsAnEmptyObject()
    {
        Assert.IsTrue(JwkJsonReader.IsWellFormedJsonObjectContent(Utf8("")));
    }


    [TestMethod]
    public void AcceptsWhitespaceOnlyContentAsAnEmptyObject()
    {
        Assert.IsTrue(JwkJsonReader.IsWellFormedJsonObjectContent(Utf8("   \t\r\n  ")));
    }


    [TestMethod]
    public void AcceptsANestedObjectWithItsOwnBraces()
    {
        string content = "\"epk\":{\"kty\":\"EC\",\"crv\":\"P-256\"}";

        Assert.IsTrue(JwkJsonReader.IsWellFormedJsonObjectContent(Utf8(content)));
    }


    [TestMethod]
    public void RejectsADuplicateTopLevelName()
    {
        //RFC 8259 §4: "the behavior of software that receives such an object is unpredictable."
        string content = "\"kid\":\"a\",\"kid\":\"b\"";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonObjectContent(Utf8(content)));
    }


    [TestMethod]
    public void RejectsADuplicateNameThatDiffersOnlyByEscape()
    {
        //RFC 8259 §4 names compare by decoded value (RFC 8259 §7); \u006bid decodes to "kid".
        string content = "\"\\u006bid\":\"a\",\"kid\":\"b\"";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonObjectContent(Utf8(content)));
    }


    [TestMethod]
    public void RejectsATrailingComma()
    {
        string content = "\"a\":1,";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonObjectContent(Utf8(content)));
    }


    [TestMethod]
    public void RejectsALeadingComma()
    {
        string content = ""","a":1""";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonObjectContent(Utf8(content)));
    }


    [TestMethod]
    public void RejectsAStrayClosingBraceAtTheEnd()
    {
        //The content is documented to carry no enclosing braces of its own, so a trailing '}' is a
        //structural violation rather than a close.
        string content = "\"a\":1}";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonObjectContent(Utf8(content)));
    }


    [TestMethod]
    public void RejectsTruncationInsideAMember()
    {
        string content = "\"a\":\"b\",\"kid\":\"ab";

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonObjectContent(Utf8(content)));
    }


    [TestMethod]
    public void RejectsContentOverTheMaximumDocumentLength()
    {
        byte[] content = new byte[JwkJsonReader.MaximumDocumentLength + 1];
        Array.Fill(content, (byte)' ');

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonObjectContent(content));
    }


    [TestMethod]
    public void RejectsContentOverTheMaximumNestingDepth()
    {
        //The content itself is already at depth 1 (the object it is the members of), so nesting
        //MaximumNestingDepth further objects inside it reaches depth 1 + MaximumNestingDepth, one past
        //the bound IsWellFormedJsonDocument enforces for a full document nested to the same depth.
        string content = string.Concat(Enumerable.Repeat("\"a\":{", JwkJsonReader.MaximumNestingDepth))
            + "1"
            + string.Concat(Enumerable.Repeat("}", JwkJsonReader.MaximumNestingDepth));

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonObjectContent(Utf8(content)));
    }


    [TestMethod]
    public void RejectsContentOverTheMaximumLiveMemberNames()
    {
        string[] members = new string[JwkJsonReader.MaximumLiveMemberNames + 1];
        for(int index = 0; index < members.Length; index++)
        {
            members[index] = $"\"f{index}\":0";
        }

        string content = string.Join(",", members);

        Assert.IsFalse(JwkJsonReader.IsWellFormedJsonObjectContent(Utf8(content)));
    }


    [TestMethod]
    public void AcceptsExactlyTheMaximumLiveMemberNames()
    {
        string[] members = new string[JwkJsonReader.MaximumLiveMemberNames];
        for(int index = 0; index < members.Length; index++)
        {
            members[index] = $"\"f{index}\":0";
        }

        string content = string.Join(",", members);

        Assert.IsTrue(JwkJsonReader.IsWellFormedJsonObjectContent(Utf8(content)));
    }
}
