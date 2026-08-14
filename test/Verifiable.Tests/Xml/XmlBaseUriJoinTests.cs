using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Unit fixtures for <see cref="XmlBaseUriJoin"/>, the join-URI-References function of
/// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see> section 2.4:
/// the modified remove-dot-segments algorithm proven against every row of the specification's Appendix A
/// table and the join proven against the section 2.4 worked examples.
/// </summary>
[TestClass]
internal sealed class XmlBaseUriJoinTests
{
    private static string RemoveDotSegments(string path)
    {
        using var destination = new PooledStructList<byte>(BaseMemoryPool.Shared, Math.Max(1, path.Length + 4));
        XmlBaseUriJoin.RemoveDotSegments(Encoding.UTF8.GetBytes(path), BaseMemoryPool.Shared, destination);

        return Encoding.UTF8.GetString(destination.AsSpan());
    }


    private static string Join(string baseValue, string referenceValue)
    {
        using var destination = new PooledStructList<byte>(BaseMemoryPool.Shared, Math.Max(1, baseValue.Length + referenceValue.Length + 4));
        XmlBaseUriJoin.Join(Encoding.UTF8.GetBytes(baseValue), Encoding.UTF8.GetBytes(referenceValue), BaseMemoryPool.Shared, destination);

        return Encoding.UTF8.GetString(destination.AsSpan());
    }


    /// <summary>
    /// Proves every row of <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML
    /// 1.1</see> Appendix A, the table of "example results of the modified Remove Dot Segments algorithm
    /// described in Section 2.4", in the table's own order and including its repeated rows. The
    /// modifications over RFC 3986 section 5.2.4 are: "Keep leading '../' segments", "Replace multiple
    /// consecutive '/' characters with a single '/' character" and "Append a '/' character to a trailing
    /// '..' segment".
    /// </summary>
    [TestMethod]
    public void RemoveDotSegmentsReproducesEveryAppendixARow()
    {
        (string Input, string Output)[] rows =
        [
            ("no/.././/pseudo-netpath/seg/file.ext", "pseudo-netpath/seg/file.ext"),
            ("no/..//.///pseudo-netpath/seg/file.ext", "pseudo-netpath/seg/file.ext"),
            ("yes/no//..//.///pseudo-netpath/seg/file.ext", "yes/pseudo-netpath/seg/file.ext"),
            ("no/../yes", "yes"),
            ("no/../yes/", "yes/"),
            ("no/../yes/no/..", "yes/"),
            ("../../no/../..", "../../../"),
            ("no/../..", "../"),
            ("no/..", ""),
            ("no/../", ""),
            ("/a/b/c/./../../g", "/a/g"),
            ("mid/content=5/../6", "mid/6"),
            ("../../..", "../../../"),
            ("no/../../", "../"),
            ("..yes/..no/..no/..no/../../../..yes", "..yes/..yes"),
            ("..yes/..no/..no/..no/../../../..yes/", "..yes/..yes/"),
            ("../..", "../../"),
            ("../../../", "../../../"),
            (".", ""),
            ("./", ""),
            ("./.", ""),
            ("//no/..", "/"),
            ("../../no/..", "../../"),
            ("../../no/../", "../../"),
            ("yes/no/../", "yes/"),
            ("yes/no/no/../..", "yes/"),
            ("yes/no/no/no/../../..", "yes/"),
            ("yes/no/../yes/no/no/../..", "yes/yes/"),
            ("yes/no/no/no/../../../yes", "yes/yes"),
            ("yes/no/no/no/../../../yes/", "yes/yes/"),
            ("/no/../", "/"),
            ("/yes/no/../", "/yes/"),
            ("/yes/no/no/../..", "/yes/"),
            ("/yes/no/no/no/../../..", "/yes/"),
            ("../../..no/..", "../../"),
            ("../../..no/../", "../../"),
            ("..yes/..no/../", "..yes/"),
            ("..yes/..no/..no/../..", "..yes/"),
            ("..yes/...no/..no/..no/../../..", "..yes/"),
            ("..yes/..no/../..yes/..no/..no/../..", "..yes/..yes/"),
            ("/..no/../", "/"),
            ("/..yes/..no/../", "/..yes/"),
            ("/..yes/..no/..no/../..", "/..yes/"),
            ("/..yes/..no/..no/..no/../../..", "/..yes/"),
            ("/", "/"),
            ("/.", "/"),
            ("/./", "/"),
            ("/./.", "/"),
            ("/././", "/"),
            ("/..", "/"),
            ("/../..", "/"),
            ("/../../..", "/"),
            ("/../../..", "/"),
            ("//..", "/"),
            ("//..//..", "/"),
            ("//..//..//..", "/"),
            ("/./..", "/"),
            ("/./.././..", "/"),
            ("/./.././.././..", "/"),
            (".", ""),
            ("./", ""),
            ("./.", ""),
            ("..", "../"),
            ("../", "../")
        ];
        for(int i = 0; i < rows.Length; ++i)
        {
            Assert.AreEqual(rows[i].Output, RemoveDotSegments(rows[i].Input), $"Appendix A row {i + 1} with input \"{rows[i].Input}\" must match.");
        }
    }


    /// <summary>
    /// Proves the <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>
    /// section 2.4 examples illustrating the modification of the Remove Dot Segments algorithm:
    /// "'abc/' and '../' should result in ''", "'../' and '../' are combined as '../../' and the result is
    /// '../../'", and "'..' and '..' are combined as '../../' and the result is '../../'".
    /// </summary>
    [TestMethod]
    public void JoinReproducesTheSection24ModificationExamples()
    {
        Assert.AreEqual("", Join("abc/", "../"));
        Assert.AreEqual("../../", Join("../", "../"));
        Assert.AreEqual("../../", Join("..", ".."));
    }


    /// <summary>
    /// Proves the <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>
    /// section 2.4 worked case: "when the elements b and c are removed from the following sample XML
    /// document, the correct result for the xml:base attribute on element d would be '../../x'" — the
    /// section 2.4 reduction combines the innermost value with the next outer one, then the result with
    /// the one beyond, over the omitted values '..', '..' and the element's own 'x'.
    /// </summary>
    [TestMethod]
    public void JoinReductionReproducesTheSection24WorkedCase()
    {
        string reduced = Join("..", "x");
        Assert.AreEqual("../x", reduced);

        Assert.AreEqual("../../x", Join("..", reduced));
    }


    /// <summary>
    /// Proves the merge step of <see href="https://www.rfc-editor.org/rfc/rfc3986">IETF RFC 3986</see>
    /// section 5.2.3 the join builds on — "a string consisting of the reference's path component appended
    /// to all but the last segment of the base URI's path" — with the value pair of the
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>
    /// section 3.8 example as corrected by erratum E11-01 of the
    /// <see href="https://www.w3.org/2008/05/xml-c14n11-errata">Canonical XML 1.1 errata</see>: the
    /// omitted <c>e2</c>'s <c>bar/</c> joined with <c>e3</c>'s own <c>foo</c> gives <c>bar/foo</c>.
    /// </summary>
    [TestMethod]
    public void JoinMergesRelativeReferenceAgainstBasePath()
    {
        Assert.AreEqual("bar/foo", Join("bar/", "foo"));
        Assert.AreEqual("something/bar/", Join("something/else", "bar/"));
    }


    /// <summary>
    /// Proves the <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>
    /// section 2.4 modification of RFC 3986 section 5.2.2, "modified as follows to ignore the fragment
    /// part of R: After parsing R set R.fragment = null" — a fragment on the reference never reaches the
    /// joined value.
    /// </summary>
    [TestMethod]
    public void JoinDropsTheReferenceFragment()
    {
        Assert.AreEqual("a/b", Join("a/", "b#fragment"));
        Assert.AreEqual("a/", Join("a/", "#fragment"));
    }


    /// <summary>
    /// Proves the untouched first branch of <see href="https://www.rfc-editor.org/rfc/rfc3986">IETF RFC
    /// 3986</see> section 5.2.2 within the join: a reference with a scheme replaces the base entirely, so
    /// an absolute <c>xml:base</c> value on an inner element wins over any outer value.
    /// </summary>
    [TestMethod]
    public void JoinWithAbsoluteReferenceTakesTheReference()
    {
        Assert.AreEqual("urn:x", Join("something/else", "urn:x"));
        Assert.AreEqual("http://example.org/a/b", Join("ignored/base", "http://example.org/a/b"));
    }
}
