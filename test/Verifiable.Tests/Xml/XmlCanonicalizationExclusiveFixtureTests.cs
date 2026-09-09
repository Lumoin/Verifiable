using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// The worked examples of
/// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
/// 1.0</see> sections 2.1 and 2.2, transcribed from the raw specification HTML and asserted byte-exact
/// under both the inclusive and the exclusive algorithm, together with the divergence of the exclusive
/// namespace and attribute policies from Canonical XML 1.0 and 1.1 over one subtree. The specification
/// displays every serialization "except for line wrapping to fit this document": each expectation here
/// joins the displayed start-tag continuation lines with the single space the wrap replaced, and carries
/// the character content verbatim from the input octets, which
/// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 1.1
/// requires ("All whitespace in character content is retained").
/// </summary>
[TestClass]
internal sealed class XmlCanonicalizationExclusiveFixtureTests
{
    private static XmlNodeTable Parse(string document, BaseMemoryPool? pool = null)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool ?? BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
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


    internal static string CanonicalizeExclusive(XmlNodeTable table, XmlNodeSet nodeSet, bool isWithComments = false, string[]? inclusivePrefixes = null, BaseMemoryPool? pool = null)
    {
        bool isCanonicalized = XmlCanonicalization.TryCanonicalizeExclusive(table, nodeSet, isWithComments, inclusivePrefixes ?? [], pool ?? BaseMemoryPool.Shared, out PooledMemory? canonicalOctets, out XmlCanonicalizationError error);
        Assert.IsTrue(isCanonicalized, $"Exclusive canonicalization must succeed but was refused with {error.Failure}.");
        using(canonicalOctets)
        {
            return Encoding.UTF8.GetString(canonicalOctets!.AsReadOnlySpan());
        }
    }


    private static int FindElement(XmlNodeTable table, string localName)
    {
        return XmlCanonicalizationC14N10FixtureTests.FindElement(table, localName);
    }


    private const string Section21FirstDocument = XmlCanonicalizationFixtureInputs.Section21FirstDocument;


    private const string Section21EnvelopedDocument = XmlCanonicalizationFixtureInputs.Section21EnvelopedDocument;


    private const string Section22FirstDocument = XmlCanonicalizationFixtureInputs.Section22FirstDocument;


    private const string Section22ReEnvelopedDocument = XmlCanonicalizationFixtureInputs.Section22ReEnvelopedDocument;


    /// <summary>
    /// The exclusive rendering of <c>elem2</c> section 2.2 displays with the caveat "except for line
    /// wrapping so it will fit into this document", stating it is the physical form extracted from either
    /// enveloping "in both cases".
    /// </summary>
    private const string Section22ExpectedExclusiveForm =
        "<n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\">\n"
        + "          <n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>\n"
        + "      </n1:elem2>";


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML
    /// Canonicalization 1.0</see> section 2.1's statement "The first document above is in canonical form"
    /// by canonicalizing the first document with Canonical XML 1.0: the canonical octets reproduce the
    /// document except for the white space outside the document element, which the XPath data model does
    /// not represent and which the specification's three-space display margin adds.
    /// </summary>
    [TestMethod]
    public void Section21FirstDocumentIsInCanonicalForm()
    {
        using XmlNodeTable table = Parse(Section21FirstDocument);
        string expected =
            "<n1:elem1 xmlns:n1=\"http://b.example\">\n"
            + "       content\n"
            + "   </n1:elem1>";

        Assert.AreEqual(expected, Canonicalize(table, XmlNodeSet.WholeDocument(table), XmlCanonicalizationAlgorithm.CanonicalXml10));
    }


    /// <summary>
    /// Proves the inclusive rendering of the
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> section 2.1 worked example: "The result of applying Canonical XML to the resulting XPath
    /// node-set" over the subdocument "with elem1 as its apex node" carries the enveloping context —
    /// "Note that the n0 namespace has been included by Canonical XML because it includes namespace
    /// context. This change which would break a signature over elem1 based on the first version." The
    /// expectation joins the wrapped start tag; its character content is the enveloped input's, which the
    /// display reuses from the first document's layout.
    /// </summary>
    [TestMethod]
    public void Section21InclusiveRenderingImportsAncestorNamespaceContext()
    {
        using XmlNodeTable table = Parse(Section21EnvelopedDocument);
        XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table, FindElement(table, "elem1"));
        string expected =
            "<n1:elem1 xmlns:n0=\"http://a.example\" xmlns:n1=\"http://b.example\">\n"
            + "          content\n"
            + "      </n1:elem1>";

        Assert.AreEqual(expected, Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10));
    }


    /// <summary>
    /// Proves the exclusive counterpart of the
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> section 2.1 worked example, per the section 1.1 summary of the method: "namespace nodes
    /// that are not on the InclusiveNamespaces PrefixList are expressed only in start tags where they are
    /// visible and if they are not in effect from an output ancestor of that tag" — the <c>n0</c> binding
    /// the enveloping declared is not visibly utilized by <c>elem1</c> and does not render, so the start
    /// tag matches the first document's.
    /// </summary>
    [TestMethod]
    public void Section21ExclusiveRenderingOmitsUnutilizedAncestorNamespace()
    {
        using XmlNodeTable table = Parse(Section21EnvelopedDocument);
        XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table, FindElement(table, "elem1"));
        string expected =
            "<n1:elem1 xmlns:n1=\"http://b.example\">\n"
            + "          content\n"
            + "      </n1:elem1>";

        Assert.AreEqual(expected, CanonicalizeExclusive(table, nodeSet));
    }


    /// <summary>
    /// Proves the first inclusive rendering of the
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> section 2.2 worked example: "Applying Canonical XML to the node-set produced from the
    /// first document yields the following serialization" — per the section's own reading, "n0 had been
    /// included from the context and the presence of an identical n3 namespace declaration in the context
    /// had elevated that declaration to the apex of the canonicalized form", leaving <c>n3:stuff</c>
    /// without its own declaration. The expectation joins the wrapped start tags; its character content is
    /// the input's.
    /// </summary>
    [TestMethod]
    public void Section22InclusiveRenderingOfFirstEnvelopeElevatesContextDeclarations()
    {
        using XmlNodeTable table = Parse(Section22FirstDocument);
        XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table, FindElement(table, "elem2"));
        string expected =
            "<n1:elem2 xmlns:n0=\"foo:bar\" xmlns:n1=\"http://example.net\" xmlns:n3=\"ftp://example.org\" xml:lang=\"en\">\n"
            + "          <n3:stuff></n3:stuff>\n"
            + "      </n1:elem2>";

        Assert.AreEqual(expected, Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10));
    }


    /// <summary>
    /// Proves the second inclusive rendering of the
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> section 2.2 worked example: after re-enveloping, "n0 has gone away but n2 has appeared,
    /// n3 is no longer elevated, and an xml:space declaration has appeared, due to changes in context. But
    /// not all context changes have effect ... the presence at ancestor nodes of an xml:lang and n1 prefix
    /// namespace declaration have no effect because of existing declarations at the elem2 node." The
    /// expectation joins the wrapped start tags; its character content is the input's.
    /// </summary>
    [TestMethod]
    public void Section22InclusiveRenderingOfReEnvelopeImportsChangedContext()
    {
        using XmlNodeTable table = Parse(Section22ReEnvelopedDocument);
        XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table, FindElement(table, "elem2"));
        string expected =
            "<n1:elem2 xmlns:n1=\"http://example.net\" xmlns:n2=\"http://foo.example\" xml:lang=\"en\" xml:space=\"retain\">\n"
            + "          <n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>\n"
            + "      </n1:elem2>";

        Assert.AreEqual(expected, Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10));
    }


    /// <summary>
    /// Proves the exclusive rendering of the
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> section 2.2 worked example: "using Exclusive XML Canonicalization as specified herein,
    /// the physical form of elem2 as extracted by the XPath expression above is ... in both cases" — the
    /// same octets from the first envelope and from the re-envelope, with only the visibly utilized
    /// <c>n1</c> and <c>n3</c> declarations rendered where they are visible and the ancestor
    /// <c>xml:space</c> not imported.
    /// </summary>
    [TestMethod]
    public void Section22ExclusiveRenderingIsInvariantAcrossReEnveloping()
    {
        using XmlNodeTable firstTable = Parse(Section22FirstDocument);
        using XmlNodeTable reEnvelopedTable = Parse(Section22ReEnvelopedDocument);
        XmlNodeSet firstNodeSet = XmlNodeSet.ElementSubtree(firstTable, FindElement(firstTable, "elem2"));
        XmlNodeSet reEnvelopedNodeSet = XmlNodeSet.ElementSubtree(reEnvelopedTable, FindElement(reEnvelopedTable, "elem2"));

        string fromFirst = CanonicalizeExclusive(firstTable, firstNodeSet);
        string fromReEnveloped = CanonicalizeExclusive(reEnvelopedTable, reEnvelopedNodeSet);

        Assert.AreEqual(Section22ExpectedExclusiveForm, fromFirst);
        Assert.AreEqual(Section22ExpectedExclusiveForm, fromReEnveloped);
    }


    /// <summary>
    /// Proves the three-way divergence of <c>xml</c>-namespace attribute inheritance over one subtree.
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.4
    /// examines "nearest occurrences of attributes in the xml namespace" and imports both, the element's
    /// own <c>xml:base</c> excluding the ancestor occurrence.
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see> section 2.4
    /// imports the simple inheritable <c>xml:lang</c> and joins the omitted ancestor's <c>xml:base</c>
    /// with the element's own.
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> section 3 item 1 imports neither: "This search and copying are omitted from the Exclusive
    /// XML Canonicalization method", so only the element's own <c>xml:base</c> renders, per section 5
    /// item 2 ("implementations of this specification only render attributes from the 'XML' namespace ...
    /// when they are in the subset being serialized").
    /// </summary>
    [TestMethod]
    public void XmlNamespaceAttributeInheritanceDivergesAcrossTheThreeAlgorithms()
    {
        string document = "<doc xml:lang=\"en\" xml:base=\"base/\"><e xml:base=\"file\">t</e></doc>";
        using XmlNodeTable table = Parse(document);
        XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table, FindElement(table, "e"));

        string under10 = Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10);
        string under11 = Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml11);
        string underExclusive = CanonicalizeExclusive(table, nodeSet);

        Assert.AreEqual("<e xml:base=\"file\" xml:lang=\"en\">t</e>", under10);
        Assert.AreEqual("<e xml:base=\"base/file\" xml:lang=\"en\">t</e>", under11);
        Assert.AreEqual("<e xml:base=\"file\">t</e>", underExclusive);
    }


    /// <summary>
    /// Proves the divergence of the namespace axis over one subtree.
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> and
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see> render the
    /// in-scope namespace axis of an apex element per their section 2.3, so the ancestor-declared
    /// <c>b</c> binding renders although nothing utilizes it, while under
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> section 3 item 3 a namespace node renders only when "it is visibly utilized by its parent
    /// element", so only the element's own <c>a</c> prefix survives.
    /// </summary>
    [TestMethod]
    public void AncestorNamespaceContextDivergesAcrossTheThreeAlgorithms()
    {
        string document = "<doc xmlns:a=\"urn:a\" xmlns:b=\"urn:b\"><a:e>t</a:e></doc>";
        using XmlNodeTable table = Parse(document);
        XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table, FindElement(table, "e"));

        string under10 = Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10);
        string under11 = Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml11);
        string underExclusive = CanonicalizeExclusive(table, nodeSet);

        Assert.AreEqual("<a:e xmlns:a=\"urn:a\" xmlns:b=\"urn:b\">t</a:e>", under10);
        Assert.AreEqual("<a:e xmlns:a=\"urn:a\" xmlns:b=\"urn:b\">t</a:e>", under11);
        Assert.AreEqual("<a:e xmlns:a=\"urn:a\">t</a:e>", underExclusive);
    }


    /// <summary>
    /// Proves condition 3 of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> section 3 item 3: a namespace node renders if "the prefix has not yet been rendered by
    /// any output ancestor, or the nearest output ancestor of its parent element that visibly utilizes the
    /// namespace prefix does not have a namespace node in the node-set with the same namespace prefix and
    /// value" — the binding renders at the nearest utilizing element, is suppressed at a descendant that
    /// utilizes the same value, and renders again where a redeclaration changes the value.
    /// </summary>
    [TestMethod]
    public void NamespaceRendersAtNearestUtilizingElementAndRerendersOnValueChange()
    {
        string document = "<doc xmlns:a=\"urn:1\"><a:e><a:f xmlns:a=\"urn:2\"><a:g>t</a:g></a:f></a:e></doc>";
        using XmlNodeTable table = Parse(document);

        string canonical = CanonicalizeExclusive(table, XmlNodeSet.WholeDocument(table));

        Assert.AreEqual("<doc><a:e xmlns:a=\"urn:1\"><a:f xmlns:a=\"urn:2\"><a:g>t</a:g></a:f></a:e></doc>", canonical);
    }


    /// <summary>
    /// Proves the <c>#WithComments</c> parameter of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> section 4: "Just as with [XML-C14N] one may use the '#WithComments' parameter to include
    /// the serialization of XML comments", with the section 2.3 <c>#xA</c> separators of Canonical XML
    /// around comments outside the document element. Both exclusive members of
    /// <see cref="XmlCanonicalizationAlgorithm"/> through
    /// <see cref="XmlCanonicalization.TryCanonicalize"/> produce the same octets as
    /// <see cref="XmlCanonicalization.TryCanonicalizeExclusive"/> with an empty prefix list.
    /// </summary>
    [TestMethod]
    public void ExclusiveWithCommentsRendersCommentsAndAlgorithmMembersDelegate()
    {
        string document = "<!--before-->\n<doc><!--inside--><a>t</a></doc>\n<!--after-->";
        using XmlNodeTable table = Parse(document);
        XmlNodeSet nodeSet = XmlNodeSet.WholeDocument(table);

        string withComments = Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10WithComments);
        string withoutComments = Canonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.ExclusiveCanonicalXml10);

        Assert.AreEqual("<!--before-->\n<doc><!--inside--><a>t</a></doc>\n<!--after-->", withComments);
        Assert.AreEqual("<doc><a>t</a></doc>", withoutComments);
        Assert.AreEqual(withComments, CanonicalizeExclusive(table, nodeSet, isWithComments: true));
        Assert.AreEqual(withoutComments, CanonicalizeExclusive(table, nodeSet, isWithComments: false));
    }


    /// <summary>
    /// Proves the pooled-buffer custody of the exclusive canonicalization surface: every buffer rented for
    /// a subtree canonicalization that exercises the visibly-utilizes walk and the prefix-list transcoding
    /// is returned once the returned canonical octets and the table are disposed, observed through the
    /// house pool's own rent and return counters. The returned <see cref="PooledMemory"/> holds a live
    /// lease from the supplied pool, so the outstanding count stays above zero until it is disposed — the
    /// distinction between a pooled result and an unpooled copy. <c>table</c> and the two results are
    /// disposed explicitly, in two stages, rather than via <see langword="using"/> declarations, because
    /// the outstanding-count assertion between the stages must observe the state at each specific point.
    /// </summary>
    [TestMethod]
    public void ExclusiveCanonicalizationReturnsEveryRentedBuffer()
    {
        using var metered = new MeteredHousePool();
        XmlNodeTable table = Parse(Section22FirstDocument, metered.Pool);
        XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table, FindElement(table, "elem2"));

        bool isCanonicalized = XmlCanonicalization.TryCanonicalizeExclusive(table, nodeSet, isWithComments: false, [], metered.Pool, out PooledMemory? withoutPrefixes, out XmlCanonicalizationError error);
        Assert.IsTrue(isCanonicalized, $"Exclusive canonicalization must succeed but was refused with {error.Failure}.");
        bool isListedCanonicalized = XmlCanonicalization.TryCanonicalizeExclusive(table, nodeSet, isWithComments: false, ["n0 n3 #default"], metered.Pool, out PooledMemory? withPrefixes, out XmlCanonicalizationError listedError);
        Assert.IsTrue(isListedCanonicalized, $"Exclusive canonicalization with the prefix list must succeed but was refused with {listedError.Failure}.");
        Assert.IsFalse(withoutPrefixes!.AsReadOnlySpan().SequenceEqual(withPrefixes!.AsReadOnlySpan()), "The prefix-list path under test must have run.");
        Assert.IsGreaterThan(0L, metered.RentedCount, "The canonicalization must rent from the supplied pool.");

        table.Dispose();
        Assert.AreNotEqual(0L, metered.OutstandingCount, "The returned canonical octets must hold their pooled leases until disposed.");

        withoutPrefixes.Dispose();
        withPrefixes.Dispose();
        Assert.AreEqual(0L, metered.OutstandingCount, "Every rented buffer must be returned once the results and the table are disposed.");
    }
}
