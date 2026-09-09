using System.Globalization;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Verifiable.Foundation;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// The differential oracle of this library's <see
/// href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> and <see
/// href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization 1.0</see>
/// outputs, both comment variants, byte-compared against the platform transforms <see
/// cref="XmlDsigC14NTransform"/>, <see cref="XmlDsigC14NWithCommentsTransform"/>, <see
/// cref="XmlDsigExcC14NTransform"/> and <see cref="XmlDsigExcC14NWithCommentsTransform"/> over the
/// deterministic corpus of <see cref="XmlDifferentialCorpusGenerator"/>. Whole documents load into an
/// <see cref="XmlDocument"/> with preserved whitespace and prohibited DTD processing; element subtrees
/// load as an <see cref="XmlNodeList"/> holding the apex element, its attributes and every descendant
/// node, the node-list form of the transforms' subset input. Canonical XML 1.1 is deliberately absent:
/// the platform ships no transform for it, so it is proven from specification text alone by the fixture
/// suites. A mismatch fails with the first divergent byte offset and a hex context window of both forms.
/// </summary>
[TestClass]
internal sealed class XmlCanonicalizationDifferentialTests
{
    private const string CanonicalXml10Identifier = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    private const string CanonicalXml10WithCommentsIdentifier = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
    private const string ExclusiveCanonicalXml10Identifier = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private const string ExclusiveCanonicalXml10WithCommentsIdentifier = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

    private static IReadOnlyList<XmlDifferentialCase> Corpus { get; } = XmlDifferentialCorpusGenerator.Generate();


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>
    /// without comments over whole documents: for every corpus document the canonical form under the
    /// identifier <c>http://www.w3.org/TR/2001/REC-xml-c14n-20010315</c> is byte-identical to the
    /// platform <see cref="XmlDsigC14NTransform"/>, the differential oracle requires.
    /// </summary>
    [TestMethod]
    public void WholeDocumentCanonicalXml10MatchesPlatformTransform()
    {
        foreach(XmlDifferentialCase corpusCase in Corpus)
        {
            byte[] libraryOctets = CanonicalizeWithLibrary(corpusCase, XmlCanonicalizationAlgorithm.CanonicalXml10, isElementSubtree: false);
            byte[] platformOctets = CanonicalizeWithPlatform(corpusCase, new XmlDsigC14NTransform(), isElementSubtree: false);
            AssertCanonicalOctetsMatch(platformOctets, libraryOctets, corpusCase, CanonicalXml10Identifier);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> with
    /// comments over whole documents: for every corpus document the canonical form under the identifier
    /// <c>http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments</c> is byte-identical to the
    /// platform <see cref="XmlDsigC14NWithCommentsTransform"/>, the differential oracle requires.
    /// </summary>
    [TestMethod]
    public void WholeDocumentCanonicalXml10WithCommentsMatchesPlatformTransform()
    {
        foreach(XmlDifferentialCase corpusCase in Corpus)
        {
            byte[] libraryOctets = CanonicalizeWithLibrary(corpusCase, XmlCanonicalizationAlgorithm.CanonicalXml10WithComments, isElementSubtree: false);
            byte[] platformOctets = CanonicalizeWithPlatform(corpusCase, new XmlDsigC14NWithCommentsTransform(), isElementSubtree: false);
            AssertCanonicalOctetsMatch(platformOctets, libraryOctets, corpusCase, CanonicalXml10WithCommentsIdentifier);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML
    /// Canonicalization 1.0</see> without comments over whole documents: for every corpus document the
    /// canonical form under the identifier <c>http://www.w3.org/2001/10/xml-exc-c14n#</c> with an empty
    /// <c>InclusiveNamespaces PrefixList</c> is byte-identical to the platform <see
    /// cref="XmlDsigExcC14NTransform"/>, the differential oracle requires.
    /// </summary>
    [TestMethod]
    public void WholeDocumentExclusiveCanonicalXml10MatchesPlatformTransform()
    {
        foreach(XmlDifferentialCase corpusCase in Corpus)
        {
            byte[] libraryOctets = CanonicalizeWithLibrary(corpusCase, XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10, isElementSubtree: false);
            byte[] platformOctets = CanonicalizeWithPlatform(corpusCase, new XmlDsigExcC14NTransform(), isElementSubtree: false);
            AssertCanonicalOctetsMatch(platformOctets, libraryOctets, corpusCase, ExclusiveCanonicalXml10Identifier);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML
    /// Canonicalization 1.0</see> with comments over whole documents: for every corpus document the
    /// canonical form under the identifier <c>http://www.w3.org/2001/10/xml-exc-c14n#WithComments</c>
    /// with an empty <c>InclusiveNamespaces PrefixList</c> is byte-identical to the platform <see
    /// cref="XmlDsigExcC14NWithCommentsTransform"/>, the differential oracle requires.
    /// </summary>
    [TestMethod]
    public void WholeDocumentExclusiveCanonicalXml10WithCommentsMatchesPlatformTransform()
    {
        foreach(XmlDifferentialCase corpusCase in Corpus)
        {
            byte[] libraryOctets = CanonicalizeWithLibrary(corpusCase, XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments, isElementSubtree: false);
            byte[] platformOctets = CanonicalizeWithPlatform(corpusCase, new XmlDsigExcC14NWithCommentsTransform(), isElementSubtree: false);
            AssertCanonicalOctetsMatch(platformOctets, libraryOctets, corpusCase, ExclusiveCanonicalXml10WithCommentsIdentifier);
        }
    }


    /// <summary>
    /// Proves the <c>InclusiveNamespaces PrefixList</c> parameter of <see
    /// href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> section 4 without comments over whole documents: for every corpus document the form
    /// produced with the corpus case's deterministic prefix list — pool prefixes, the never-declared
    /// <c>zz</c>, and the <c>#default</c> token — is byte-identical to the platform <see
    /// cref="XmlDsigExcC14NTransform"/> constructed with the same list, the differential oracle
    /// requires.
    /// </summary>
    [TestMethod]
    public void WholeDocumentExclusiveWithPrefixListMatchesPlatformTransform()
    {
        foreach(XmlDifferentialCase corpusCase in Corpus)
        {
            byte[] libraryOctets = CanonicalizeExclusiveWithLibrary(corpusCase, isWithComments: false, corpusCase.InclusivePrefixList, isElementSubtree: false);
            XmlDsigExcC14NTransform transform = corpusCase.InclusivePrefixList.Length == 0 ? new XmlDsigExcC14NTransform() : new XmlDsigExcC14NTransform(corpusCase.InclusivePrefixList);
            byte[] platformOctets = CanonicalizeWithPlatform(corpusCase, transform, isElementSubtree: false);
            AssertCanonicalOctetsMatch(platformOctets, libraryOctets, corpusCase, ExclusiveCanonicalXml10Identifier);
        }
    }


    /// <summary>
    /// Proves the <c>InclusiveNamespaces PrefixList</c> parameter of <see
    /// href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> section 4 with comments over whole documents: for every corpus document the form
    /// produced with the corpus case's deterministic prefix list is byte-identical to the platform <see
    /// cref="XmlDsigExcC14NWithCommentsTransform"/> constructed with the same list, the differential
    /// oracle requires.
    /// </summary>
    [TestMethod]
    public void WholeDocumentExclusiveWithPrefixListWithCommentsMatchesPlatformTransform()
    {
        foreach(XmlDifferentialCase corpusCase in Corpus)
        {
            byte[] libraryOctets = CanonicalizeExclusiveWithLibrary(corpusCase, isWithComments: true, corpusCase.InclusivePrefixList, isElementSubtree: false);
            XmlDsigExcC14NWithCommentsTransform transform = corpusCase.InclusivePrefixList.Length == 0 ? new XmlDsigExcC14NWithCommentsTransform() : new XmlDsigExcC14NWithCommentsTransform(corpusCase.InclusivePrefixList);
            byte[] platformOctets = CanonicalizeWithPlatform(corpusCase, transform, isElementSubtree: false);
            AssertCanonicalOctetsMatch(platformOctets, libraryOctets, corpusCase, ExclusiveCanonicalXml10WithCommentsIdentifier);
        }
    }


    /// <summary>
    /// Proves the document-subsets processing of <see
    /// href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.4
    /// without comments over element subtrees: for every apex-planting corpus document the canonical form
    /// of the apex subtree is byte-identical to the platform <see cref="XmlDsigC14NTransform"/> given the
    /// subtree as an <see cref="XmlNodeList"/>, the differential oracle requires. The corpus keeps
    /// <c>xml:*</c> attributes off the apex ancestors because the platform transform propagates them onto
    /// every element of a node-list input, while section 2.4 augments only an element whose parent is
    /// omitted from the node-set; the ancestor-import rule itself is proven from specification text by
    /// the subset-divergence fixtures.
    /// </summary>
    [TestMethod]
    public void ElementSubtreeCanonicalXml10MatchesPlatformTransform()
    {
        foreach(XmlDifferentialCase corpusCase in Corpus)
        {
            if(!corpusCase.HasApexElement)
            {
                continue;
            }

            byte[] libraryOctets = CanonicalizeWithLibrary(corpusCase, XmlCanonicalizationAlgorithm.CanonicalXml10, isElementSubtree: true);
            byte[] platformOctets = CanonicalizeWithPlatform(corpusCase, new XmlDsigC14NTransform(), isElementSubtree: true);
            AssertCanonicalOctetsMatch(platformOctets, libraryOctets, corpusCase, CanonicalXml10Identifier);
        }
    }


    /// <summary>
    /// Proves the document-subsets processing of <see
    /// href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.4 with
    /// comments over element subtrees: for every apex-planting corpus document the canonical form of the
    /// apex subtree is byte-identical to the platform <see cref="XmlDsigC14NWithCommentsTransform"/>
    /// given the subtree as an <see cref="XmlNodeList"/>, the differential oracle requires. The corpus
    /// keeps <c>xml:*</c> attributes off the apex ancestors for the reason stated on <see
    /// cref="ElementSubtreeCanonicalXml10MatchesPlatformTransform"/>.
    /// </summary>
    [TestMethod]
    public void ElementSubtreeCanonicalXml10WithCommentsMatchesPlatformTransform()
    {
        foreach(XmlDifferentialCase corpusCase in Corpus)
        {
            if(!corpusCase.HasApexElement)
            {
                continue;
            }

            byte[] libraryOctets = CanonicalizeWithLibrary(corpusCase, XmlCanonicalizationAlgorithm.CanonicalXml10WithComments, isElementSubtree: true);
            byte[] platformOctets = CanonicalizeWithPlatform(corpusCase, new XmlDsigC14NWithCommentsTransform(), isElementSubtree: true);
            AssertCanonicalOctetsMatch(platformOctets, libraryOctets, corpusCase, CanonicalXml10WithCommentsIdentifier);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML
    /// Canonicalization 1.0</see> section 3 without comments over element subtrees: for every
    /// apex-planting corpus document the exclusive canonical form of the apex subtree — namespace nodes
    /// rendered by the visibly-utilizes rule against the ancestor context — is byte-identical to the
    /// platform <see cref="XmlDsigExcC14NTransform"/> given the subtree as an <see cref="XmlNodeList"/>,
    /// the differential oracle requires.
    /// </summary>
    [TestMethod]
    public void ElementSubtreeExclusiveCanonicalXml10MatchesPlatformTransform()
    {
        foreach(XmlDifferentialCase corpusCase in Corpus)
        {
            if(!corpusCase.HasApexElement)
            {
                continue;
            }

            byte[] libraryOctets = CanonicalizeWithLibrary(corpusCase, XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10, isElementSubtree: true);
            byte[] platformOctets = CanonicalizeWithPlatform(corpusCase, new XmlDsigExcC14NTransform(), isElementSubtree: true);
            AssertCanonicalOctetsMatch(platformOctets, libraryOctets, corpusCase, ExclusiveCanonicalXml10Identifier);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML
    /// Canonicalization 1.0</see> section 3 with comments over element subtrees: for every apex-planting
    /// corpus document the exclusive canonical form of the apex subtree is byte-identical to the platform
    /// <see cref="XmlDsigExcC14NWithCommentsTransform"/> given the subtree as an <see
    /// cref="XmlNodeList"/>, the differential oracle requires.
    /// </summary>
    [TestMethod]
    public void ElementSubtreeExclusiveCanonicalXml10WithCommentsMatchesPlatformTransform()
    {
        foreach(XmlDifferentialCase corpusCase in Corpus)
        {
            if(!corpusCase.HasApexElement)
            {
                continue;
            }

            byte[] libraryOctets = CanonicalizeWithLibrary(corpusCase, XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments, isElementSubtree: true);
            byte[] platformOctets = CanonicalizeWithPlatform(corpusCase, new XmlDsigExcC14NWithCommentsTransform(), isElementSubtree: true);
            AssertCanonicalOctetsMatch(platformOctets, libraryOctets, corpusCase, ExclusiveCanonicalXml10WithCommentsIdentifier);
        }
    }


    /// <summary>
    /// Proves the <c>InclusiveNamespaces PrefixList</c> parameter of <see
    /// href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> section 4 without comments over element subtrees: for every apex-planting corpus
    /// document the exclusive canonical form of the apex subtree under the corpus case's subtree-safe
    /// prefix list is byte-identical to the platform <see cref="XmlDsigExcC14NTransform"/> constructed
    /// with the same list, the differential oracle requires. The subtree list omits the <c>#default</c>
    /// token and every prefix the document element declares: a listed token is handled inclusively over
    /// the element's in-scope namespace axis, which the node-set of <see
    /// cref="XmlNodeSet.ElementSubtree"/> includes for bindings inherited from omitted ancestors, while
    /// the platform's node-list input carries no namespace nodes for declarations outside the list and
    /// so cannot be driven to that shape; those semantics are proven from specification text by the
    /// prefix-list fixtures instead, and the whole-document prefix-list differentials cover the full
    /// token set.
    /// </summary>
    [TestMethod]
    public void ElementSubtreeExclusiveWithPrefixListMatchesPlatformTransform()
    {
        foreach(XmlDifferentialCase corpusCase in Corpus)
        {
            if(!corpusCase.HasApexElement)
            {
                continue;
            }

            string prefixList = corpusCase.SubtreeInclusivePrefixList;
            byte[] libraryOctets = CanonicalizeExclusiveWithLibrary(corpusCase, isWithComments: false, prefixList, isElementSubtree: true);
            XmlDsigExcC14NTransform transform = prefixList.Length == 0 ? new XmlDsigExcC14NTransform() : new XmlDsigExcC14NTransform(prefixList);
            byte[] platformOctets = CanonicalizeWithPlatform(corpusCase, transform, isElementSubtree: true);
            AssertCanonicalOctetsMatch(platformOctets, libraryOctets, corpusCase, ExclusiveCanonicalXml10Identifier);
        }
    }


    /// <summary>
    /// Proves the <c>InclusiveNamespaces PrefixList</c> parameter of <see
    /// href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> section 4 with comments over element subtrees: for every apex-planting corpus document
    /// the exclusive canonical form of the apex subtree under the corpus case's subtree-safe prefix list
    /// is byte-identical to the platform <see cref="XmlDsigExcC14NWithCommentsTransform"/> constructed
    /// with the same list, the differential oracle requires. The subtree list is narrowed for the reason
    /// stated on <see cref="ElementSubtreeExclusiveWithPrefixListMatchesPlatformTransform"/>.
    /// </summary>
    [TestMethod]
    public void ElementSubtreeExclusiveWithPrefixListWithCommentsMatchesPlatformTransform()
    {
        foreach(XmlDifferentialCase corpusCase in Corpus)
        {
            if(!corpusCase.HasApexElement)
            {
                continue;
            }

            string prefixList = corpusCase.SubtreeInclusivePrefixList;
            byte[] libraryOctets = CanonicalizeExclusiveWithLibrary(corpusCase, isWithComments: true, prefixList, isElementSubtree: true);
            XmlDsigExcC14NWithCommentsTransform transform = prefixList.Length == 0 ? new XmlDsigExcC14NWithCommentsTransform() : new XmlDsigExcC14NWithCommentsTransform(prefixList);
            byte[] platformOctets = CanonicalizeWithPlatform(corpusCase, transform, isElementSubtree: true);
            AssertCanonicalOctetsMatch(platformOctets, libraryOctets, corpusCase, ExclusiveCanonicalXml10WithCommentsIdentifier);
        }
    }


    /// <summary>
    /// Pins the platform divergence that motivates the differential corpus of
    /// <see cref="XmlDifferentialCorpusGenerator"/> keeping <c>xml:*</c> attributes off the apex
    /// ancestors: over a node-list input holding an element subtree whose omitted ancestor carries
    /// <c>xml:lang</c> or <c>xml:base</c>, <see cref="XmlDsigC14NTransform"/> propagates the ancestral
    /// attribute verbatim onto every element of the node-list, while
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.4
    /// enhances attribute-axis processing only "when an XPath node-set is given as input and the
    /// element's parent is omitted from the node-set" — the apex alone here, because <c>leaf</c>'s parent
    /// is in the node-set and so renders bare. This library follows the specification rule over the same
    /// input, the treatment the subset-divergence fixtures of
    /// <see cref="XmlCanonicalizationSubsetDivergenceTests"/> prove over the specification's own
    /// examples, so the two implementations legitimately diverge over such inputs and the ancestor-import
    /// rule is proven from specification text rather than differentially.
    /// </summary>
    [TestMethod]
    public void ElementSubtreeAncestralXmlAttributePropagationDivergesBetweenPlatformAndSpecification()
    {
        var langCase = new XmlDifferentialCase(index: -1, "<doc xml:lang=\"en\"><apex><leaf>t</leaf></apex></doc>", hasApexElement: true, string.Empty, string.Empty);
        var baseCase = new XmlDifferentialCase(index: -2, "<doc xml:base=\"base/\"><apex><leaf>t</leaf></apex></doc>", hasApexElement: true, string.Empty, string.Empty);

        string platformLangForm = Encoding.UTF8.GetString(CanonicalizeWithPlatform(langCase, new XmlDsigC14NTransform(), isElementSubtree: true));
        string platformBaseForm = Encoding.UTF8.GetString(CanonicalizeWithPlatform(baseCase, new XmlDsigC14NTransform(), isElementSubtree: true));
        string libraryLangForm = Encoding.UTF8.GetString(CanonicalizeWithLibrary(langCase, XmlCanonicalizationAlgorithm.CanonicalXml10, isElementSubtree: true));
        string libraryBaseForm = Encoding.UTF8.GetString(CanonicalizeWithLibrary(baseCase, XmlCanonicalizationAlgorithm.CanonicalXml10, isElementSubtree: true));

        Assert.AreEqual("<apex xml:lang=\"en\"><leaf xml:lang=\"en\">t</leaf></apex>", platformLangForm);
        Assert.AreEqual("<apex xml:base=\"base/\"><leaf xml:base=\"base/\">t</leaf></apex>", platformBaseForm);
        Assert.AreEqual("<apex xml:lang=\"en\"><leaf>t</leaf></apex>", libraryLangForm);
        Assert.AreEqual("<apex xml:base=\"base/\"><leaf>t</leaf></apex>", libraryBaseForm);
    }


    /// <summary>
    /// Canonicalizes a corpus document with this library under the given algorithm, over the whole
    /// document or the apex element subtree.
    /// </summary>
    /// <param name="corpusCase">The corpus case.</param>
    /// <param name="algorithm">The canonicalization algorithm.</param>
    /// <param name="isElementSubtree">Whether to canonicalize the apex subtree instead of the whole
    /// document.</param>
    /// <returns>The canonical octets.</returns>
    private static byte[] CanonicalizeWithLibrary(XmlDifferentialCase corpusCase, XmlCanonicalizationAlgorithm algorithm, bool isElementSubtree)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(corpusCase.Xml), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"Corpus document {corpusCase.Index} must parse but was refused with {readError.Failure} at byte offset {readError.ByteOffset}.");
        using(table)
        {
            XmlNodeSet nodeSet = isElementSubtree
                ? XmlNodeSet.ElementSubtree(table!, FindLibraryApexElement(table!, corpusCase))
                : XmlNodeSet.WholeDocument(table!);
            bool isCanonicalized = XmlCanonicalization.TryCanonicalize(table!, nodeSet, algorithm, BaseMemoryPool.Shared, out PooledMemory? canonicalOctets, out XmlCanonicalizationError error);
            Assert.IsTrue(isCanonicalized, $"Corpus document {corpusCase.Index} must canonicalize but was refused with {error.Failure}.");
            using(canonicalOctets)
            {
                return canonicalOctets!.AsReadOnlySpan().ToArray();
            }
        }
    }


    /// <summary>
    /// Canonicalizes a corpus document with this library's exclusive surface and the given
    /// <c>InclusiveNamespaces PrefixList</c>, over the whole document or the apex element subtree.
    /// </summary>
    /// <param name="corpusCase">The corpus case.</param>
    /// <param name="isWithComments">Whether comment nodes render.</param>
    /// <param name="prefixList">The white-space separated prefix list, possibly empty.</param>
    /// <param name="isElementSubtree">Whether to canonicalize the apex subtree instead of the whole
    /// document.</param>
    /// <returns>The canonical octets.</returns>
    private static byte[] CanonicalizeExclusiveWithLibrary(XmlDifferentialCase corpusCase, bool isWithComments, string prefixList, bool isElementSubtree)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(corpusCase.Xml), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"Corpus document {corpusCase.Index} must parse but was refused with {readError.Failure} at byte offset {readError.ByteOffset}.");
        using(table)
        {
            XmlNodeSet nodeSet = isElementSubtree
                ? XmlNodeSet.ElementSubtree(table!, FindLibraryApexElement(table!, corpusCase))
                : XmlNodeSet.WholeDocument(table!);
            bool isCanonicalized = XmlCanonicalization.TryCanonicalizeExclusive(table!, nodeSet, isWithComments, [prefixList], BaseMemoryPool.Shared, out PooledMemory? canonicalOctets, out XmlCanonicalizationError error);
            Assert.IsTrue(isCanonicalized, $"Corpus document {corpusCase.Index} must canonicalize but was refused with {error.Failure}.");
            using(canonicalOctets)
            {
                return canonicalOctets!.AsReadOnlySpan().ToArray();
            }
        }
    }


    /// <summary>
    /// Canonicalizes a corpus document with a platform transform, loading the whole document or the apex
    /// subtree node-list as the transform input.
    /// </summary>
    /// <param name="corpusCase">The corpus case.</param>
    /// <param name="transform">The single-use platform transform.</param>
    /// <param name="isElementSubtree">Whether to load the apex subtree node-list instead of the whole
    /// document.</param>
    /// <returns>The canonical octets.</returns>
    private static byte[] CanonicalizeWithPlatform(XmlDifferentialCase corpusCase, Transform transform, bool isElementSubtree)
    {
        XmlDocument document = LoadPlatformDocument(corpusCase.Xml);
        if(isElementSubtree)
        {
            XmlElement apex = FindPlatformApexElement(document, corpusCase);
            var subtreeNodes = new List<XmlNode>();
            CollectSubtreeNodes(apex, subtreeNodes);
            using var subtreeNodeList = new MaterializedNodeList(subtreeNodes);
            transform.LoadInput(subtreeNodeList);
        }
        else
        {
            transform.LoadInput(document);
        }

        using var outputStream = (Stream)transform.GetOutput(typeof(Stream));
        using var buffer = new MemoryStream();
        outputStream.CopyTo(buffer);

        return buffer.ToArray();
    }


    /// <summary>
    /// Loads a corpus document into an <see cref="XmlDocument"/> with preserved whitespace, prohibited
    /// DTD processing and no resolver, the load shape the differential oracle prescribes.
    /// </summary>
    /// <param name="xml">The document text.</param>
    /// <returns>The loaded document.</returns>
    private static XmlDocument LoadPlatformDocument(string xml)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null
        };
        var document = new XmlDocument
        {
            PreserveWhitespace = true,
            XmlResolver = null!
        };
        using(var stringReader = new StringReader(xml))
        {
            using var reader = XmlReader.Create(stringReader, settings);
            document.Load(reader);
        }

        return document;
    }


    /// <summary>
    /// Collects the node-list shape of an element subtree: the element, its attributes including
    /// namespace declarations, and every descendant with its attributes, in document order.
    /// </summary>
    /// <param name="node">The subtree apex.</param>
    /// <param name="subtreeNodes">The list the nodes are appended to.</param>
    private static void CollectSubtreeNodes(XmlNode node, List<XmlNode> subtreeNodes)
    {
        subtreeNodes.Add(node);
        if(node.Attributes != null)
        {
            foreach(XmlAttribute attribute in node.Attributes)
            {
                subtreeNodes.Add(attribute);
            }
        }

        foreach(XmlNode child in node.ChildNodes)
        {
            CollectSubtreeNodes(child, subtreeNodes);
        }
    }


    /// <summary>
    /// Finds the apex element in the library node table by its local name.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="corpusCase">The corpus case, named on failure.</param>
    /// <returns>The apex element index.</returns>
    private static int FindLibraryApexElement(XmlNodeTable table, XmlDifferentialCase corpusCase)
    {
        ReadOnlySpan<byte> apexLocalName = "apex"u8;
        for(int i = 0; i < table.Count; ++i)
        {
            if(table.KindOf(i) == XmlNodeKind.Element && table.LocalNameOf(i).SequenceEqual(apexLocalName))
            {
                return i;
            }
        }

        Assert.Fail($"Corpus document {corpusCase.Index} must contain the apex element.");

        return -1;
    }


    /// <summary>
    /// Finds the apex element in the platform document by its local name.
    /// </summary>
    /// <param name="document">The platform document.</param>
    /// <param name="corpusCase">The corpus case, named on failure.</param>
    /// <returns>The apex element.</returns>
    private static XmlElement FindPlatformApexElement(XmlDocument document, XmlDifferentialCase corpusCase)
    {
        XmlElement? apex = FindElementByLocalName(document.DocumentElement!, XmlDifferentialCorpusGenerator.ApexLocalName);
        Assert.IsNotNull(apex, $"Corpus document {corpusCase.Index} must contain the apex element.");

        return apex;
    }


    /// <summary>
    /// Searches an element and its descendants for the first element with the given local name.
    /// </summary>
    /// <param name="element">The element the search starts from.</param>
    /// <param name="localName">The local name to find.</param>
    /// <returns>The found element, or <see langword="null"/>.</returns>
    private static XmlElement? FindElementByLocalName(XmlElement element, string localName)
    {
        if(string.Equals(element.LocalName, localName, StringComparison.Ordinal))
        {
            return element;
        }

        foreach(XmlNode child in element.ChildNodes)
        {
            if(child is XmlElement childElement && FindElementByLocalName(childElement, localName) is XmlElement found)
            {
                return found;
            }
        }

        return null;
    }


    /// <summary>
    /// Asserts two canonical forms are byte-identical; a mismatch fails with the first divergent byte
    /// offset, both lengths, a hex and printable-character context window of each form around the
    /// divergence, and the source document.
    /// </summary>
    /// <param name="platformOctets">The platform transform's canonical octets.</param>
    /// <param name="libraryOctets">This library's canonical octets.</param>
    /// <param name="corpusCase">The corpus case, named in the report.</param>
    /// <param name="algorithmIdentifier">The algorithm identifier, named in the report.</param>
    private static void AssertCanonicalOctetsMatch(byte[] platformOctets, byte[] libraryOctets, XmlDifferentialCase corpusCase, string algorithmIdentifier)
    {
        int sharedLength = Math.Min(platformOctets.Length, libraryOctets.Length);
        int firstDivergentOffset = -1;
        for(int i = 0; i < sharedLength; ++i)
        {
            if(platformOctets[i] != libraryOctets[i])
            {
                firstDivergentOffset = i;
                break;
            }
        }

        if(firstDivergentOffset < 0)
        {
            if(platformOctets.Length == libraryOctets.Length)
            {
                return;
            }

            firstDivergentOffset = sharedLength;
        }

        string message =
            $"Canonical forms diverge for corpus document {corpusCase.Index} under {algorithmIdentifier} at byte offset {firstDivergentOffset}."
            + $"\nPlatform length {platformOctets.Length}, library length {libraryOctets.Length}."
            + $"\nPlatform context: {DescribeContext(platformOctets, firstDivergentOffset)}"
            + $"\nLibrary context:  {DescribeContext(libraryOctets, firstDivergentOffset)}"
            + $"\nDocument: {Truncate(corpusCase.Xml, 2000)}";
        Assert.Fail(message);
    }


    /// <summary>
    /// Renders a hex and printable-character window of up to 48 octets around an offset.
    /// </summary>
    /// <param name="octets">The octets.</param>
    /// <param name="offset">The offset the window centers on.</param>
    /// <returns>The rendered window.</returns>
    private static string DescribeContext(byte[] octets, int offset)
    {
        int start = Math.Max(0, offset - 24);
        int length = Math.Min(48, octets.Length - start);
        if(length <= 0)
        {
            return "(no octets at offset)";
        }

        var hex = new StringBuilder();
        var printable = new StringBuilder();
        for(int i = start; i < start + length; ++i)
        {
            hex.Append(octets[i].ToString("X2", CultureInfo.InvariantCulture)).Append(' ');
            printable.Append(octets[i] is >= 0x20 and < 0x7F ? (char)octets[i] : '.');
        }

        return $"bytes [{start}..{start + length}) {hex.ToString().TrimEnd()} |{printable}|";
    }


    /// <summary>
    /// Truncates a report string to a maximum length.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <param name="maximumLength">The maximum length.</param>
    /// <returns>The possibly truncated text.</returns>
    private static string Truncate(string text, int maximumLength)
    {
        return text.Length <= maximumLength ? text : text[..maximumLength] + " …(truncated)";
    }


    /// <summary>
    /// An <see cref="XmlNodeList"/> over a materialized node list, the input shape the platform
    /// transforms take for document subsets.
    /// </summary>
    private sealed class MaterializedNodeList: XmlNodeList
    {
        private List<XmlNode> Nodes { get; }


        /// <summary>
        /// Creates the list over its nodes.
        /// </summary>
        /// <param name="nodes">The nodes in document order.</param>
        public MaterializedNodeList(List<XmlNode> nodes)
        {
            this.Nodes = nodes;
        }


        /// <inheritdoc/>
        public override int Count => Nodes.Count;


        /// <inheritdoc/>
        public override XmlNode? Item(int index)
        {
            return index >= 0 && index < Nodes.Count ? Nodes[index] : null;
        }


        /// <inheritdoc/>
        public override System.Collections.IEnumerator GetEnumerator()
        {
            return Nodes.GetEnumerator();
        }
    }
}
