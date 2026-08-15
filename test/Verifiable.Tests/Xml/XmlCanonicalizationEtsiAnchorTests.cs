using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// End-to-end proofs, one per bullet, that the six canonicalization algorithms
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI
/// EN 319 132-1 V1.3.1</see> clause 6.3(d) requires of the <c>Algorithm</c> attribute of
/// <c>ds:SignedInfo</c>'s <c>ds:CanonicalizationMethod</c> child element are supported by this substrate:
/// each parses a document, canonicalizes the <c>e3</c> subtree under the bullet's algorithm through
/// <see cref="XmlCanonicalization.TryCanonicalize"/>, obtains non-empty octets, and proves the
/// distinction the bullet encodes — the comment stance its parenthesis names and, over the crafted
/// subtree, the divergence of its family from the other two, whose <c>xml</c>-namespace attribute
/// treatments Canonical XML 1.0 section 2.4, Canonical XML 1.1 section 2.4 and Exclusive XML
/// Canonicalization 1.0 section 3 specify differently.
/// </summary>
[TestClass]
internal sealed class XmlCanonicalizationEtsiAnchorTests
{
    /// <summary>
    /// A document on whose <c>e3</c> subtree the three canonicalization families must diverge: the
    /// omitted <c>e2</c> carries <c>xml:id</c>, which Canonical XML 1.0 section 2.4 imports and Canonical
    /// XML 1.1 section 2.4 does not; the omitted ancestors carry <c>xml:base</c> values, which Canonical
    /// XML 1.1 joins into <c>e3</c>'s own and Canonical XML 1.0 leaves untouched; and the in-scope
    /// <c>w3c</c> binding is not visibly utilized, so Exclusive XML Canonicalization 1.0 section 3 renders
    /// no namespace declaration at all. The comment inside <c>e3</c> separates the comment-omitting from
    /// the comment-preserving forms.
    /// </summary>
    private const string CraftedDocument =
        "<doc xmlns=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\" xml:base=\"something/else\">"
        + "<e1><e2 xmlns=\"\" xml:id=\"abc\" xml:base=\"bar/\"><e3 id=\"E3\" xml:base=\"foo\"><!--inside e3-->t</e3></e2></e1></doc>";

    private const string CraftedComment = "<!--inside e3-->";


    private static string CanonicalizeCraftedSubtree(XmlCanonicalizationAlgorithm algorithm)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(CraftedDocument), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The crafted document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");
        using(table)
        {
            XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table!, XmlCanonicalizationC14N10FixtureTests.FindElement(table!, "e3"));
            bool isCanonicalized = XmlCanonicalization.TryCanonicalize(table!, nodeSet, algorithm, BaseMemoryPool.Shared, out PooledMemory? canonicalOctets, out XmlCanonicalizationError error);
            Assert.IsTrue(isCanonicalized, $"Canonicalization under {algorithm} must succeed but was refused with {error.Failure}.");
            using(canonicalOctets)
            {
                Assert.IsGreaterThan(0, canonicalOctets!.Length, $"Canonicalization under {algorithm} must produce non-empty octets.");

                return Encoding.UTF8.GetString(canonicalOctets.AsReadOnlySpan());
            }
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI
    /// EN 319 132-1 V1.3.1</see> clause 6.3(d) first bullet — "'http://www.w3.org/2006/12/xml-c14n11'.
    /// The corresponding canonicalization algorithm Canonical XML v1.1 (omits comments) [11] shall be
    /// supported." — end to end: the canonical octets omit the comment and differ from both the Canonical
    /// XML v1.0 and the Exclusive Canonicalization renderings of the same subtree.
    /// </summary>
    [TestMethod]
    public void CanonicalXml11OmittingCommentsIsSupportedEndToEnd()
    {
        string canonical = CanonicalizeCraftedSubtree(XmlCanonicalizationAlgorithm.CanonicalXml11);

        Assert.IsFalse(canonical.Contains(CraftedComment, StringComparison.Ordinal), "Canonical XML v1.1 omits comments.");
        Assert.AreNotEqual(CanonicalizeCraftedSubtree(XmlCanonicalizationAlgorithm.CanonicalXml10), canonical, "Canonical XML v1.1 must diverge from v1.0 over the crafted subtree.");
        Assert.AreNotEqual(CanonicalizeCraftedSubtree(XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10), canonical, "Canonical XML v1.1 must diverge from Exclusive Canonicalization over the crafted subtree.");
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI
    /// EN 319 132-1 V1.3.1</see> clause 6.3(d) second bullet — "'http://www.w3.org/2001/10/xml-exc-c14n#'.
    /// The corresponding canonicalization algorithm Exclusive Canonicalization (omits comments) [10] shall
    /// be supported." — end to end: the canonical octets omit the comment and differ from both the
    /// Canonical XML v1.0 and the Canonical XML v1.1 renderings of the same subtree.
    /// </summary>
    [TestMethod]
    public void ExclusiveCanonicalizationOmittingCommentsIsSupportedEndToEnd()
    {
        string canonical = CanonicalizeCraftedSubtree(XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10);

        Assert.IsFalse(canonical.Contains(CraftedComment, StringComparison.Ordinal), "Exclusive Canonicalization omits comments.");
        Assert.AreNotEqual(CanonicalizeCraftedSubtree(XmlCanonicalizationAlgorithm.CanonicalXml10), canonical, "Exclusive Canonicalization must diverge from Canonical XML v1.0 over the crafted subtree.");
        Assert.AreNotEqual(CanonicalizeCraftedSubtree(XmlCanonicalizationAlgorithm.CanonicalXml11), canonical, "Exclusive Canonicalization must diverge from Canonical XML v1.1 over the crafted subtree.");
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI
    /// EN 319 132-1 V1.3.1</see> clause 6.3(d) third bullet —
    /// "'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'. The corresponding canonicalization algorithm
    /// Canonical XML v1.0 (omits comments) [9] shall be supported." — end to end: the canonical octets
    /// omit the comment and differ from both the Canonical XML v1.1 and the Exclusive Canonicalization
    /// renderings of the same subtree.
    /// </summary>
    [TestMethod]
    public void CanonicalXml10OmittingCommentsIsSupportedEndToEnd()
    {
        string canonical = CanonicalizeCraftedSubtree(XmlCanonicalizationAlgorithm.CanonicalXml10);

        Assert.IsFalse(canonical.Contains(CraftedComment, StringComparison.Ordinal), "Canonical XML v1.0 omits comments.");
        Assert.AreNotEqual(CanonicalizeCraftedSubtree(XmlCanonicalizationAlgorithm.CanonicalXml11), canonical, "Canonical XML v1.0 must diverge from v1.1 over the crafted subtree.");
        Assert.AreNotEqual(CanonicalizeCraftedSubtree(XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10), canonical, "Canonical XML v1.0 must diverge from Exclusive Canonicalization over the crafted subtree.");
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI
    /// EN 319 132-1 V1.3.1</see> clause 6.3(d) fourth bullet —
    /// "'http://www.w3.org/2006/12/xml-c14n11#WithComments'. The corresponding canonicalization algorithm
    /// Canonical XML v1.1 (with comments) [11] shall be supported." — end to end: the canonical octets
    /// preserve the comment and differ from both the Canonical XML v1.0 and the Exclusive Canonicalization
    /// comment-preserving renderings of the same subtree.
    /// </summary>
    [TestMethod]
    public void CanonicalXml11WithCommentsIsSupportedEndToEnd()
    {
        string canonical = CanonicalizeCraftedSubtree(XmlCanonicalizationAlgorithm.CanonicalXml11WithComments);

        Assert.IsTrue(canonical.Contains(CraftedComment, StringComparison.Ordinal), "Canonical XML v1.1 with comments preserves comments.");
        Assert.AreNotEqual(CanonicalizeCraftedSubtree(XmlCanonicalizationAlgorithm.CanonicalXml10WithComments), canonical, "Canonical XML v1.1 must diverge from v1.0 over the crafted subtree.");
        Assert.AreNotEqual(CanonicalizeCraftedSubtree(XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments), canonical, "Canonical XML v1.1 must diverge from Exclusive Canonicalization over the crafted subtree.");
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI
    /// EN 319 132-1 V1.3.1</see> clause 6.3(d) fifth bullet —
    /// "'http://www.w3.org/2001/10/xml-exc-c14n#WithComments'. The corresponding canonicalization
    /// algorithm Exclusive Canonicalization (with comments) [10] shall be supported." — end to end: the
    /// canonical octets preserve the comment and differ from both the Canonical XML v1.0 and the Canonical
    /// XML v1.1 comment-preserving renderings of the same subtree.
    /// </summary>
    [TestMethod]
    public void ExclusiveCanonicalizationWithCommentsIsSupportedEndToEnd()
    {
        string canonical = CanonicalizeCraftedSubtree(XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments);

        Assert.IsTrue(canonical.Contains(CraftedComment, StringComparison.Ordinal), "Exclusive Canonicalization with comments preserves comments.");
        Assert.AreNotEqual(CanonicalizeCraftedSubtree(XmlCanonicalizationAlgorithm.CanonicalXml10WithComments), canonical, "Exclusive Canonicalization must diverge from Canonical XML v1.0 over the crafted subtree.");
        Assert.AreNotEqual(CanonicalizeCraftedSubtree(XmlCanonicalizationAlgorithm.CanonicalXml11WithComments), canonical, "Exclusive Canonicalization must diverge from Canonical XML v1.1 over the crafted subtree.");
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI
    /// EN 319 132-1 V1.3.1</see> clause 6.3(d) sixth bullet —
    /// "'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments'. The corresponding canonicalization
    /// algorithm Canonical XML v1.0 (with comments) [9] shall be supported." — end to end: the canonical
    /// octets preserve the comment and differ from both the Canonical XML v1.1 and the Exclusive
    /// Canonicalization comment-preserving renderings of the same subtree.
    /// </summary>
    [TestMethod]
    public void CanonicalXml10WithCommentsIsSupportedEndToEnd()
    {
        string canonical = CanonicalizeCraftedSubtree(XmlCanonicalizationAlgorithm.CanonicalXml10WithComments);

        Assert.IsTrue(canonical.Contains(CraftedComment, StringComparison.Ordinal), "Canonical XML v1.0 with comments preserves comments.");
        Assert.AreNotEqual(CanonicalizeCraftedSubtree(XmlCanonicalizationAlgorithm.CanonicalXml11WithComments), canonical, "Canonical XML v1.0 must diverge from v1.1 over the crafted subtree.");
        Assert.AreNotEqual(CanonicalizeCraftedSubtree(XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments), canonical, "Canonical XML v1.0 must diverge from Exclusive Canonicalization over the crafted subtree.");
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI
    /// EN 319 132-1 V1.3.1</see> clause 6.3(e) — "The generator should not use canonicalization
    /// algorithms 'with comments'. See note 6." — together with its NOTE 6: "Support of canonicalization
    /// algorithms 'with comments' is for residual interoperability in the signature validation process."
    /// The SHOULD NOT binds signature generation, which this substrate does not perform; what a validator
    /// owes is the residual support, proven here by every comment-preserving member of
    /// <see cref="XmlCanonicalizationAlgorithm"/> producing octets that retain the comment.
    /// </summary>
    [TestMethod]
    public void WithCommentsAlgorithmsRemainSupportedForValidation()
    {
        XmlCanonicalizationAlgorithm[] commentPreservingAlgorithms =
        [
            XmlCanonicalizationAlgorithm.CanonicalXml10WithComments,
            XmlCanonicalizationAlgorithm.CanonicalXml11WithComments,
            XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments
        ];
        foreach(XmlCanonicalizationAlgorithm algorithm in commentPreservingAlgorithms)
        {
            string canonical = CanonicalizeCraftedSubtree(algorithm);

            Assert.IsTrue(canonical.Contains(CraftedComment, StringComparison.Ordinal), $"The comment must survive {algorithm} for residual interoperability in the signature validation process.");
        }
    }
}
