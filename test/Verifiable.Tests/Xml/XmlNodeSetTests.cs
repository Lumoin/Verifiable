using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of the set semantics of <see cref="XmlNodeSet"/>. A node-set is "an unordered collection of
/// nodes without duplicates" per <see href="https://www.w3.org/TR/1999/REC-xpath-19991116">XML Path
/// Language 1.0</see> section 1, so the composition surface normalizes its index arrays — sorted
/// ascending, duplicate-free — and two compositions denoting the same node-set are equal regardless of
/// composition order or repetition. Canonicalization refuses a composition index that names no element of
/// the table under every set shape, per this library's own result-shaped refusal surface.
/// </summary>
[TestClass]
internal sealed class XmlNodeSetTests
{
    /// <summary>The document the composition proofs mark nodes of.</summary>
    private const string CompositionDocument = "<doc><a><b><c/></b></a><d/><e/></doc>";


    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static int FindElement(XmlNodeTable table, string localName)
    {
        return XmlCanonicalizationC14N10FixtureTests.FindElement(table, localName);
    }


    /// <summary>
    /// Proves that <see cref="XmlNodeSet.Excluding"/> compositions denote the node-set — "an unordered
    /// collection of nodes without duplicates" per
    /// <see href="https://www.w3.org/TR/1999/REC-xpath-19991116">XML Path Language 1.0</see>
    /// section 1 — insensitively to composition order: excluding two subtrees in either order yields
    /// equal sets with equal hash codes.
    /// </summary>
    [TestMethod]
    public void ExclusionCompositionOrderDoesNotAffectEquality()
    {
        using XmlNodeTable table = Parse(CompositionDocument);
        int first = FindElement(table, "d");
        int second = FindElement(table, "e");

        XmlNodeSet inDocumentOrder = XmlNodeSet.WholeDocument(table).Excluding(first).Excluding(second);
        XmlNodeSet inReverseOrder = XmlNodeSet.WholeDocument(table).Excluding(second).Excluding(first);

        Assert.AreEqual(inDocumentOrder, inReverseOrder);
        Assert.IsTrue(inDocumentOrder == inReverseOrder);
        Assert.AreEqual(inDocumentOrder.GetHashCode(), inReverseOrder.GetHashCode());
    }


    /// <summary>
    /// Proves that repeating an <see cref="XmlNodeSet.Excluding"/> composition is idempotent: a node-set
    /// holds no duplicates per <see href="https://www.w3.org/TR/1999/REC-xpath-19991116">XML Path
    /// Language 1.0</see> section 1, so excluding the same subtree twice yields a set equal to
    /// excluding it once, with an equal hash code.
    /// </summary>
    [TestMethod]
    public void RepeatedExclusionComposesIdempotently()
    {
        using XmlNodeTable table = Parse(CompositionDocument);
        int excluded = FindElement(table, "d");

        XmlNodeSet once = XmlNodeSet.WholeDocument(table).Excluding(excluded);
        XmlNodeSet twice = XmlNodeSet.WholeDocument(table).Excluding(excluded).Excluding(excluded);

        Assert.AreEqual(once, twice);
        Assert.IsTrue(once == twice);
        Assert.AreEqual(once.GetHashCode(), twice.GetHashCode());
    }


    /// <summary>
    /// Proves that <see cref="XmlNodeSet.IncludingAncestor"/> compositions denote the node-set — "an
    /// unordered collection of nodes without duplicates" per
    /// <see href="https://www.w3.org/TR/1999/REC-xpath-19991116">XML Path Language 1.0</see>
    /// section 1 — insensitively to composition order: including two ancestors in either order yields
    /// equal sets with equal hash codes.
    /// </summary>
    [TestMethod]
    public void AncestorContextCompositionOrderDoesNotAffectEquality()
    {
        using XmlNodeTable table = Parse(CompositionDocument);
        int apex = FindElement(table, "c");
        int outerAncestor = FindElement(table, "a");
        int innerAncestor = FindElement(table, "b");

        XmlNodeSet outerFirst = XmlNodeSet.ElementSubtree(table, apex).IncludingAncestor(outerAncestor).IncludingAncestor(innerAncestor);
        XmlNodeSet innerFirst = XmlNodeSet.ElementSubtree(table, apex).IncludingAncestor(innerAncestor).IncludingAncestor(outerAncestor);

        Assert.AreEqual(outerFirst, innerFirst);
        Assert.IsTrue(outerFirst == innerFirst);
        Assert.AreEqual(outerFirst.GetHashCode(), innerFirst.GetHashCode());
    }


    /// <summary>
    /// Proves that repeating an <see cref="XmlNodeSet.IncludingAncestor"/> composition is idempotent: a
    /// node-set holds no duplicates per <see href="https://www.w3.org/TR/1999/REC-xpath-19991116">XML
    /// Path Language 1.0</see> section 1, so including the same ancestor twice yields a set equal to
    /// including it once, with an equal hash code.
    /// </summary>
    [TestMethod]
    public void RepeatedAncestorContextComposesIdempotently()
    {
        using XmlNodeTable table = Parse(CompositionDocument);
        int apex = FindElement(table, "c");
        int ancestor = FindElement(table, "a");

        XmlNodeSet once = XmlNodeSet.ElementSubtree(table, apex).IncludingAncestor(ancestor);
        XmlNodeSet twice = XmlNodeSet.ElementSubtree(table, apex).IncludingAncestor(ancestor).IncludingAncestor(ancestor);

        Assert.AreEqual(once, twice);
        Assert.IsTrue(once == twice);
        Assert.AreEqual(once.GetHashCode(), twice.GetHashCode());
    }


    /// <summary>
    /// Proves the result-shaped refusal surface holds uniformly across set shapes: an ancestor-context
    /// index that names no element of the table refuses as <see
    /// cref="XmlCanonicalizationFailure.InvalidNodeIndex"/> under the whole-document shape exactly as
    /// under the element-subtree shape.
    /// </summary>
    [TestMethod]
    public void AncestorContextIndexOutsideTheTableRefusesUnderEverySetShape()
    {
        using XmlNodeTable table = Parse(CompositionDocument);
        const int OutsideTheTable = 999_999;
        XmlNodeSet wholeDocument = XmlNodeSet.WholeDocument(table).IncludingAncestor(OutsideTheTable);
        XmlNodeSet elementSubtree = XmlNodeSet.ElementSubtree(table, FindElement(table, "c")).IncludingAncestor(OutsideTheTable);

        bool isWholeDocumentCanonicalized = XmlCanonicalization.TryCanonicalize(table, wholeDocument, XmlCanonicalizationAlgorithm.CanonicalXml10, BaseMemoryPool.Shared, out PooledMemory? _, out XmlCanonicalizationError wholeDocumentError);
        bool isElementSubtreeCanonicalized = XmlCanonicalization.TryCanonicalize(table, elementSubtree, XmlCanonicalizationAlgorithm.CanonicalXml10, BaseMemoryPool.Shared, out PooledMemory? _, out XmlCanonicalizationError elementSubtreeError);

        Assert.IsFalse(isWholeDocumentCanonicalized, "An ancestor-context index outside the table must refuse under the whole-document shape.");
        Assert.AreEqual(XmlCanonicalizationFailure.InvalidNodeIndex, wholeDocumentError.Failure);
        Assert.IsFalse(isElementSubtreeCanonicalized, "An ancestor-context index outside the table must refuse under the element-subtree shape.");
        Assert.AreEqual(XmlCanonicalizationFailure.InvalidNodeIndex, elementSubtreeError.Failure);
    }
}
