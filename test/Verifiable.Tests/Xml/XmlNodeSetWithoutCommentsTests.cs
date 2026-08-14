using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XmlNodeSet.WithoutComments"/>: the set-level comment-exclusion mark adds. A
/// comment renders exactly when the <see cref="XmlCanonicalizationAlgorithm"/> variant is with-comments
/// AND the set does not carry the mark, so the mark reproduces the effect <see
/// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see> section 4.3.3.3 step 4 requires of a same-document dereference whose fragment is
/// absent or a bare-name (shortname) XPointer — "then delete all comment nodes" — independently of, and
/// prior to, whichever canonicalization algorithm renders the dereferenced set afterwards.
/// </summary>
[TestClass]
internal sealed class XmlNodeSetWithoutCommentsTests
{
    /// <summary>
    /// The fixture document: one root-level comment before the document element, one comment inside the
    /// identified subtree, and one root-level comment after the document element — exercising the mark
    /// both over whole-document and element-subtree shapes and over comments both inside and outside the
    /// document element.
    /// </summary>
    private const string Document = "<!--outer-before--><doc><a Id=\"x\"><!--inner-->text<b/></a></doc><!--outer-after-->";


    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static string Canonicalize(XmlNodeTable table, XmlNodeSet nodeSet, XmlCanonicalizationAlgorithm algorithm)
    {
        bool isCanonicalized = XmlCanonicalization.TryCanonicalize(table, nodeSet, algorithm, BaseMemoryPool.Shared, out PooledMemory? canonicalOctets, out XmlCanonicalizationError error);
        Assert.IsTrue(isCanonicalized, $"Canonicalization must succeed but was refused with {error.Failure}.");
        using(canonicalOctets)
        {
            return Encoding.UTF8.GetString(canonicalOctets!.AsReadOnlySpan());
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.3 step 4, "delete all comment nodes", over the
    /// whole-document shape: a <see cref="XmlNodeSet.WholeDocument"/> set marked
    /// <see cref="XmlNodeSet.WithoutComments"/> and rendered under
    /// <see cref="XmlCanonicalizationAlgorithm.CanonicalXml10WithComments"/> carries no comment octets at
    /// all, byte-identical to the same set rendered under the comment-omitting
    /// <see cref="XmlCanonicalizationAlgorithm.CanonicalXml10"/> — the algorithm asked for with comments
    /// still yields none, because the set itself excludes them before rendering ever inspects the variant.
    /// </summary>
    [TestMethod]
    public void MarkedWholeDocumentSetUnderWithCommentsAlgorithmRendersNoComments()
    {
        using XmlNodeTable table = Parse(Document);
        XmlNodeSet marked = XmlNodeSet.WholeDocument(table).WithoutComments();

        string withCommentsAlgorithm = Canonicalize(table, marked, XmlCanonicalizationAlgorithm.CanonicalXml10WithComments);
        string noCommentsAlgorithm = Canonicalize(table, XmlNodeSet.WholeDocument(table), XmlCanonicalizationAlgorithm.CanonicalXml10);

        Assert.DoesNotContain("<!--", withCommentsAlgorithm, "A marked set must carry no comment nodes even under a with-comments algorithm.");
        Assert.AreEqual(noCommentsAlgorithm, withCommentsAlgorithm, "A marked set under the with-comments algorithm must render byte-identically to the unmarked set under the comment-omitting algorithm.");
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.3 step 4's exemption for the rendering semantics of a
    /// set built without the mark: a plain <see cref="XmlNodeSet.WholeDocument"/> set (the
    /// <c>#xpointer(/)</c> dereference shape, which step 4 exempts from comment deletion) rendered under <see
    /// cref="XmlCanonicalizationAlgorithm.CanonicalXml10WithComments"/> carries every comment node, both
    /// inside the document element and outside it.
    /// </summary>
    [TestMethod]
    public void UnmarkedWholeDocumentSetUnderWithCommentsAlgorithmRendersEveryComment()
    {
        using XmlNodeTable table = Parse(Document);

        string rendered = Canonicalize(table, XmlNodeSet.WholeDocument(table), XmlCanonicalizationAlgorithm.CanonicalXml10WithComments);

        Assert.Contains("<!--outer-before-->", rendered, "An unmarked set must still render a root-level comment preceding the document element.");
        Assert.Contains("<!--inner-->", rendered, "An unmarked set must still render a comment inside the document element.");
        Assert.Contains("<!--outer-after-->", rendered, "An unmarked set must still render a root-level comment following the document element.");
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.2's plain statement — "<c>URI="#foo"</c> will
    /// automatically remove comments before the canonicalization can even be invoked" — over the
    /// element-subtree shape a bare-name (shortname) same-document XPointer dereferences to: a subtree set
    /// marked <see cref="XmlNodeSet.WithoutComments"/> renders no comment even though its own descendant
    /// carries one and the algorithm is with-comments; the same subtree set without the mark renders it.
    /// </summary>
    [TestMethod]
    public void MarkedElementSubtreeSetRendersNoCommentUnmarkedRendersIt()
    {
        using XmlNodeTable table = Parse(Document);
        int apex = XmlCanonicalizationC14N10FixtureTests.FindElement(table, "a");

        string marked = Canonicalize(table, XmlNodeSet.ElementSubtree(table, apex).WithoutComments(), XmlCanonicalizationAlgorithm.CanonicalXml10WithComments);
        string unmarked = Canonicalize(table, XmlNodeSet.ElementSubtree(table, apex), XmlCanonicalizationAlgorithm.CanonicalXml10WithComments);

        Assert.DoesNotContain("<!--", marked, "A marked element-subtree set must carry no comment nodes.");
        Assert.Contains("<!--inner-->", unmarked, "An unmarked element-subtree set must still render its descendant comment.");
    }


    /// <summary>
    /// Proves the "<c>WithoutComments</c> ... one composition" holds the same algebraic discipline as the
    /// rest of <see cref="XmlNodeSet"/>, over the mark that reproduces <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 4.3.3.3 step 4's "delete all comment nodes": it composes idempotently
    /// and commutes with <see cref="XmlNodeSet.Excluding"/>: marking before or after excluding a subtree
    /// yields equal sets with equal hash codes, and marking twice is equal to marking once — the same
    /// normalized-composition discipline the other <see cref="XmlNodeSet"/> composers already prove.
    /// </summary>
    [TestMethod]
    public void WithoutCommentsComposesIdempotentlyAndCommutesWithExcluding()
    {
        using XmlNodeTable table = Parse(Document);
        int excluded = XmlCanonicalizationC14N10FixtureTests.FindElement(table, "b");

        XmlNodeSet markedOnce = XmlNodeSet.WholeDocument(table).WithoutComments();
        XmlNodeSet markedTwice = XmlNodeSet.WholeDocument(table).WithoutComments().WithoutComments();
        XmlNodeSet markThenExclude = XmlNodeSet.WholeDocument(table).WithoutComments().Excluding(excluded);
        XmlNodeSet excludeThenMark = XmlNodeSet.WholeDocument(table).Excluding(excluded).WithoutComments();

        Assert.AreEqual(markedOnce, markedTwice);
        Assert.AreEqual(markedOnce.GetHashCode(), markedTwice.GetHashCode());
        Assert.AreEqual(markThenExclude, excludeThenMark);
        Assert.AreEqual(markThenExclude.GetHashCode(), excludeThenMark.GetHashCode());
    }


    /// <summary>
    /// Proves, against the comment-exclusion mark <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">
    /// XML Signature Syntax and Processing (Second Edition)</see> section 4.3.3.3 step 4 grounds, the mark is
    /// load-bearing for <see cref="XmlNodeSet.Equals(XmlNodeSet)"/>: two sets that are otherwise structurally
    /// identical but differ only by the mark are unequal, so the equality surface this library established grows to
    /// cover the new composition.
    /// </summary>
    [TestMethod]
    public void MarkedAndUnmarkedOtherwiseIdenticalSetsAreUnequal()
    {
        using XmlNodeTable table = Parse(Document);

        XmlNodeSet unmarked = XmlNodeSet.WholeDocument(table);
        XmlNodeSet marked = XmlNodeSet.WholeDocument(table).WithoutComments();

        Assert.AreNotEqual(unmarked, marked);
        Assert.IsFalse(unmarked == marked);
        Assert.IsTrue(unmarked != marked);
    }
}
