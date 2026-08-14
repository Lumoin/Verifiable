using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs that the document-subsets processing of
/// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.4 and
/// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see> section 2.4
/// diverge exactly as specified when the same subtree is canonicalized under each: which
/// <c>xml</c>-namespace attributes an element with an omitted parent inherits, and how <c>xml:base</c>
/// values of omitted ancestors are treated.
/// </summary>
[TestClass]
internal sealed class XmlCanonicalizationSubsetDivergenceTests
{
    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static string Canonicalize(XmlNodeTable table, XmlNodeSet nodeSet, XmlCanonicalizationAlgorithm algorithm, BaseMemoryPool? pool = null)
    {
        bool isCanonicalized = XmlCanonicalization.TryCanonicalize(table, nodeSet, algorithm, pool ?? BaseMemoryPool.Shared, out PooledMemory? canonicalOctets, out XmlCanonicalizationError error);
        Assert.IsTrue(isCanonicalized, $"Canonicalization must succeed but was refused with {error.Failure}.");
        using(canonicalOctets)
        {
            return Encoding.UTF8.GetString(canonicalOctets!.AsReadOnlySpan());
        }
    }


    private static int FindElement(XmlNodeTable table, string localName)
    {
        return XmlCanonicalizationC14N10FixtureTests.FindElement(table, localName);
    }


    /// <summary>
    /// Proves the <c>xml:id</c> and <c>xml:base</c> divergence over the section 3.8 input of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>.
    /// Under <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>
    /// section 2.4, "All element nodes along E's ancestor axis are examined for nearest occurrences of
    /// attributes in the xml namespace ... From this list of attributes, remove any that are in E's
    /// attribute axis": <c>e3</c> imports <c>xml:id="abc"</c> from the omitted <c>e2</c> verbatim and
    /// keeps its own <c>xml:base="foo"</c> untouched. Under Canonical XML 1.1 section 2.4, "The xml:id
    /// attribute is not a simple inheritable attribute and no processing of these attributes is
    /// performed", and the <c>xml:base</c> fixup joins the contiguously omitted <c>e2</c>'s <c>bar/</c>
    /// with <c>e3</c>'s own <c>foo</c> into <c>bar/foo</c>.
    /// </summary>
    [TestMethod]
    public void XmlIdImportAndXmlBaseHandlingDivergeBetweenC14N10AndC14N11()
    {
        string document = XmlCanonicalizationFixtureInputs.Section38Document;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table, FindElement(table, "e3")).IncludingAncestor(FindElement(table, "e1"));

        string under10 = Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10);
        string under11 = Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml11);

        Assert.AreEqual(
            "<e1 xmlns=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\" xml:base=\"something/else\">"
            + "<e3 xmlns=\"\" id=\"E3\" xml:base=\"foo\" xml:id=\"abc\"></e3></e1>",
            under10);
        Assert.AreEqual(
            "<e1 xmlns=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\" xml:base=\"something/else\">"
            + "<e3 xmlns=\"\" id=\"E3\" xml:base=\"bar/foo\"></e3></e1>",
            under11);
    }


    /// <summary>
    /// Proves the treatment of <c>xml</c>-namespace attributes beyond the four named ones.
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.4
    /// imports the nearest occurrence of every attribute "in the xml namespace, such as xml:lang and
    /// xml:space", so both <c>xml:lang</c> and the unnamed <c>xml:other</c> import onto the apex.
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>
    /// section 2.4 defines "Simple inheritable attributes are xml:lang and xml:space" and requires that
    /// "Attributes in the XML namespace other than xml:base, xml:id, xml:lang, and xml:space MUST be
    /// processed as ordinary attributes", so only <c>xml:lang</c> imports.
    /// </summary>
    [TestMethod]
    public void GeneralXmlNamespaceAttributeImportDivergesWhileSimpleInheritablesImportUnderBoth()
    {
        string document = XmlCanonicalizationFixtureInputs.GeneralXmlAttributeDocument;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table, FindElement(table, "e"));

        string under10 = Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10);
        string under11 = Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml11);

        Assert.AreEqual("<e xml:lang=\"en\" xml:other=\"o\"></e>", under10);
        Assert.AreEqual("<e xml:lang=\"en\"></e>", under11);
    }


    /// <summary>
    /// Proves the <c>xml:base</c> chain divergence over the sample document of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>
    /// section 2.4, whitespace compacted: "when the elements b and c are removed from the following sample
    /// XML document, the correct result for the xml:base attribute on element d would be '../../x'".
    /// Under <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>
    /// section 2.4 no join exists: <c>d</c> carries its own <c>xml:base</c>, the nearest ancestor
    /// occurrence is therefore removed from the import list, and <c>x</c> renders verbatim.
    /// </summary>
    [TestMethod]
    public void XmlBaseChainJoinsUnderC14N11AndStaysVerbatimUnderC14N10()
    {
        string document = XmlCanonicalizationFixtureInputs.XmlBaseChainDocument;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table, FindElement(table, "d")).IncludingAncestor(FindElement(table, "a"));

        string under11 = Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml11);
        string under10 = Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10);

        Assert.AreEqual("<a xml:base=\"foo/bar\"><d xml:base=\"../../x\"></d></a>", under11);
        Assert.AreEqual("<a xml:base=\"foo/bar\"><d xml:base=\"x\"></d></a>", under10);
    }


    /// <summary>
    /// Proves the empty-join rule of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>
    /// section 2.4: "The result may also be null or empty (xml:base=\"\") in which case xml:base MUST NOT
    /// be rendered", with the section's own value pair "'abc/' and '../' should result in ''". Under
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.4
    /// the element's own <c>xml:base="../"</c> renders verbatim because the ancestor occurrence is
    /// removed from the import list.
    /// </summary>
    [TestMethod]
    public void EmptyJoinResultSuppressesXmlBaseUnderC14N11()
    {
        string document = XmlCanonicalizationFixtureInputs.XmlBaseEmptyJoinDocument;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table, FindElement(table, "b"));

        string under11 = Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml11);
        string under10 = Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10);

        Assert.AreEqual("<b>t</b>", under11);
        Assert.AreEqual("<b xml:base=\"../\">t</b>", under10);
    }


    /// <summary>
    /// Proves the trigger condition of the
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>
    /// section 2.4 fixup: "Note that this xml:base fixup is only performed if an element with an xml:base
    /// attribute is removed." Over the whole document no element is omitted, so Canonical XML 1.0 and 1.1
    /// produce identical octets with every <c>xml:base</c> and <c>xml:id</c> rendered verbatim in sorted
    /// position.
    /// </summary>
    [TestMethod]
    public void WholeDocumentRendersIdenticallyUnderC14N10AndC14N11()
    {
        string document = XmlCanonicalizationFixtureInputs.Section38Document;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        XmlNodeSet nodeSet = XmlNodeSet.WholeDocument(table);

        string under10 = Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10);
        string under11 = Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml11);

        string expected =
            "<doc xmlns=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\" xml:base=\"something/else\">\n"
            + "   <e1>\n"
            + "      <e2 xmlns=\"\" xml:base=\"bar/\" xml:id=\"abc\">\n"
            + "         <e3 id=\"E3\" xml:base=\"foo\"></e3>\n"
            + "      </e2>\n"
            + "   </e1>\n"
            + "</doc>";
        Assert.AreEqual(expected, under10);
        Assert.AreEqual(expected, under11);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>
    /// section 2.3 over the excluded-subtree composition: "If a node is not in the node-set, then no text
    /// is generated for the node" — excluding an element removes its tags, axes and entire content from
    /// the canonical form while its siblings and their namespace context render unchanged. This is the
    /// node-set shape the enveloped-signature transform of XML Signature produces.
    /// </summary>
    [TestMethod]
    public void ExcludedSubtreeGeneratesNoText()
    {
        string document = XmlCanonicalizationFixtureInputs.ExcludedSubtreeDocument;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        XmlNodeSet nodeSet = XmlNodeSet.WholeDocument(table).Excluding(FindElement(table, "sig"));

        string canonical = Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10);

        Assert.AreEqual("<doc xmlns:p=\"urn:x\"><a>t</a><b p:q=\"v\"></b></doc>", canonical);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>
    /// section 2.3 — "If a node is not in the node-set, then no text is generated for the node" — over a
    /// composition of five excluded subtrees, the node-set shape a document carrying five enveloped
    /// signatures produces: every excluded subtree vanishes from the canonical form while the remaining
    /// content renders unchanged.
    /// </summary>
    [TestMethod]
    public void FiveExclusionsComposeAndGenerateNoText()
    {
        string document = "<doc><s1>x</s1><a>t</a><s2>x</s2><s3>x</s3><b>u</b><s4>x</s4><s5>x</s5></doc>";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        XmlNodeSet nodeSet = XmlNodeSet.WholeDocument(table)
            .Excluding(FindElement(table, "s1"))
            .Excluding(FindElement(table, "s2"))
            .Excluding(FindElement(table, "s3"))
            .Excluding(FindElement(table, "s4"))
            .Excluding(FindElement(table, "s5"));

        string canonical = Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10);

        Assert.AreEqual("<doc><a>t</a><b>u</b></doc>", canonical);
    }


    /// <summary>
    /// Proves the pooled-buffer custody of the canonicalization surface: every buffer rented for a subset
    /// canonicalization that exercises the ancestor-import and <c>xml:base</c> fixup paths is returned
    /// once the returned canonical octets and the table are disposed, observed through the house pool's
    /// own rent and return counters. The returned <see cref="PooledMemory"/> holds a live lease from the
    /// supplied pool, so the outstanding count stays above zero until it is disposed — the distinction
    /// between a pooled result and an unpooled copy.
    /// </summary>
    [TestMethod]
    public void CanonicalizationReturnsEveryRentedBuffer()
    {
        using var metered = new MeteredHousePool();
        string document = XmlCanonicalizationFixtureInputs.CompactSubsetDocument;
        XmlNodeTable table = Parse(document, metered.Pool);
        XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table, FindElement(table, "e3")).IncludingAncestor(FindElement(table, "e1"));

        bool isCanonicalized10 = XmlCanonicalization.TryCanonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10, metered.Pool, out PooledMemory? under10, out XmlCanonicalizationError error10);
        Assert.IsTrue(isCanonicalized10, $"Canonicalization under Canonical XML 1.0 must succeed but was refused with {error10.Failure}.");
        bool isCanonicalized11 = XmlCanonicalization.TryCanonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml11, metered.Pool, out PooledMemory? under11, out XmlCanonicalizationError error11);
        Assert.IsTrue(isCanonicalized11, $"Canonicalization under Canonical XML 1.1 must succeed but was refused with {error11.Failure}.");
        Assert.IsFalse(under10!.AsReadOnlySpan().SequenceEqual(under11!.AsReadOnlySpan()), "The subset paths under test must both have run.");
        Assert.IsGreaterThan(0L, metered.RentedCount, "The canonicalization must rent from the supplied pool.");

        table.Dispose();
        Assert.AreNotEqual(0L, metered.OutstandingCount, "The returned canonical octets must hold their pooled leases until disposed.");

        under10.Dispose();
        under11.Dispose();
        Assert.AreEqual(0L, metered.OutstandingCount, "Every rented buffer must be returned once the results and the table are disposed.");
    }
}
