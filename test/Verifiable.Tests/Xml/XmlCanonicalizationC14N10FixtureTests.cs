using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// The worked examples of <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML
/// 1.0</see> section 3, transcribed from the raw specification HTML and asserted byte-exact against
/// <see cref="XmlCanonicalization.TryCanonicalize"/>. Examples whose inputs carry a document type
/// declaration are adapted: the DOCTYPE line or lines and every DTD-derived expectation are dropped and
/// the rest kept verbatim, with the delta stated in each test's own documentation. Section 3.5 exists to
/// demonstrate DTD entity replacement and has no DOCTYPE-free remainder, so it has no fixture here.
/// </summary>
[TestClass]
internal sealed class XmlCanonicalizationC14N10FixtureTests
{
    private static byte[] Canonicalize(string document, XmlCanonicalizationAlgorithm algorithm)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");
        using(table)
        {
            return Canonicalize(table!, XmlNodeSet.WholeDocument(table!), algorithm);
        }
    }


    private static byte[] Canonicalize(XmlNodeTable table, XmlNodeSet nodeSet, XmlCanonicalizationAlgorithm algorithm)
    {
        bool isCanonicalized = XmlCanonicalization.TryCanonicalize(table, nodeSet, algorithm, BaseMemoryPool.Shared, out PooledMemory? canonicalOctets, out XmlCanonicalizationError error);
        Assert.IsTrue(isCanonicalized, $"Canonicalization must succeed but was refused with {error.Failure}.");
        using(canonicalOctets)
        {
            return canonicalOctets!.AsReadOnlySpan().ToArray();
        }
    }


    private static void AssertCanonicalFormEquals(string expected, byte[] actual)
    {
        Assert.AreEqual(expected, Encoding.UTF8.GetString(actual));
        Assert.AreSequenceEqual(Encoding.UTF8.GetBytes(expected), actual, "The canonical form must match the expectation byte for byte.");
    }


    internal static int FindElement(XmlNodeTable table, string localName)
    {
        byte[] name = Encoding.UTF8.GetBytes(localName);
        for(int i = 0; i < table.Count; ++i)
        {
            if(table.KindOf(i) == XmlNodeKind.Element && table.LocalNameOf(i).SequenceEqual(name))
            {
                return i;
            }
        }

        Assert.Fail($"The fixture document must contain element '{localName}'.");

        return -1;
    }


    private const string Section31Input = XmlCanonicalizationFixtureInputs.Section31Document;


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>
    /// section 3.1 without comments: loss of the XML declaration, loss of whitespace between the PITarget
    /// and its data with retention of whitespace inside the data, comment removal, and the section 2.3
    /// separator rule under which "a trailing #xA is rendered after the closing PI symbol for PI children
    /// of the root node with a lesser document order than the document element, and a leading #xA is
    /// rendered before the opening PI symbol of PI children of the root node with a greater document
    /// order". Adapted per the DOCTYPE prohibition of this surface: the input line
    /// <c>&lt;!DOCTYPE doc SYSTEM "doc.dtd"&gt;</c> and its adjacent blank line are dropped; the example
    /// draws nothing else from the DTD, so the expectation is otherwise verbatim.
    /// </summary>
    [TestMethod]
    public void PisCommentsAndOutsideOfDocumentElementCanonicalizeUncommented()
    {
        string expected =
            "<?xml-stylesheet href=\"doc.xsl\"\n"
            + "   type=\"text/xsl\"   ?>\n"
            + "<doc>Hello, world!</doc>\n"
            + "<?pi-without-data?>";

        AssertCanonicalFormEquals(expected, Canonicalize(Section31Input, XmlCanonicalizationAlgorithm.CanonicalXml10));
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>
    /// section 3.1 with comments: comment children of the root node render with the section 2.3 separator
    /// rule, under which each comment after the document element carries a leading #xA and the last
    /// character of the canonical form is '&gt;'. Adapted per the DOCTYPE prohibition of this surface: the
    /// input line <c>&lt;!DOCTYPE doc SYSTEM "doc.dtd"&gt;</c> and its adjacent blank line are dropped.
    /// </summary>
    [TestMethod]
    public void PisCommentsAndOutsideOfDocumentElementCanonicalizeCommented()
    {
        string expected =
            "<?xml-stylesheet href=\"doc.xsl\"\n"
            + "   type=\"text/xsl\"   ?>\n"
            + "<doc>Hello, world!<!-- Comment 1 --></doc>\n"
            + "<?pi-without-data?>\n"
            + "<!-- Comment 2 -->\n"
            + "<!-- Comment 3 -->";

        AssertCanonicalFormEquals(expected, Canonicalize(Section31Input, XmlCanonicalizationAlgorithm.CanonicalXml10WithComments));
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>
    /// section 3.2: all whitespace in character content is retained between consecutive start tags,
    /// consecutive end tags and end-tag/start-tag pairs, clean or dirty — the input document and the
    /// canonical form are identical and both end with the '&gt;' character.
    /// </summary>
    [TestMethod]
    public void WhitespaceInDocumentContentIsRetained()
    {
        string document = XmlCanonicalizationFixtureInputs.Section32Document;

        AssertCanonicalFormEquals(document, Canonicalize(document, XmlCanonicalizationAlgorithm.CanonicalXml10));
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>
    /// section 3.3: empty-element conversion to start-end tag pairs, normalization of whitespace in start
    /// and end tags, the relative order and lexicographic ordering of the namespace and attribute axes —
    /// in <c>e5</c> "b:attr precedes a:attr because the primary key is namespace URI not namespace prefix,
    /// and attr2 precedes b:attr because the default namespace is not applied to unqualified attributes" —
    /// retention of namespace prefixes, and elimination of superfluous namespace declarations. Adapted per
    /// the DOCTYPE prohibition of this surface: the input line
    /// <c>&lt;!DOCTYPE doc [&lt;!ATTLIST e9 attr CDATA "default"&gt;]&gt;</c> is dropped and with it the
    /// DTD-defaulted <c>attr="default"</c> on <c>e9</c> in the expectation; the rest is verbatim.
    /// </summary>
    [TestMethod]
    public void StartAndEndTagsNormalizeSortAndSuppressSuperfluousDeclarations()
    {
        string document = XmlCanonicalizationFixtureInputs.Section33Document;
        string expected =
            "<doc>\n"
            + "   <e1></e1>\n"
            + "   <e2></e2>\n"
            + "   <e3 id=\"elem3\" name=\"elem3\"></e3>\n"
            + "   <e4 id=\"elem4\" name=\"elem4\"></e4>\n"
            + "   <e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" xmlns:b=\"http://www.ietf.org\" attr=\"I'm\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>\n"
            + "   <e6 xmlns:a=\"http://www.w3.org\">\n"
            + "      <e7 xmlns=\"http://www.ietf.org\">\n"
            + "         <e8 xmlns=\"\">\n"
            + "            <e9 xmlns:a=\"http://www.ietf.org\"></e9>\n"
            + "         </e8>\n"
            + "      </e7>\n"
            + "   </e6>\n"
            + "</doc>";

        AssertCanonicalFormEquals(expected, Canonicalize(document, XmlCanonicalizationAlgorithm.CanonicalXml10));
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>
    /// section 3.4: character reference replacement, attribute value delimiters set to double quotes,
    /// attribute value normalization, CDATA section replacement, and the encoding of special characters as
    /// character references — <c>&amp;amp;</c>, <c>&amp;lt;</c>, <c>&amp;quot;</c>, <c>&amp;#xD;</c>,
    /// <c>&amp;#xA;</c>, <c>&amp;#x9;</c> in attribute values and <c>&amp;amp;</c>, <c>&amp;lt;</c>,
    /// <c>&amp;gt;</c>, <c>&amp;#xD;</c> in text — such that "the value of the attribute named attr in the
    /// element norm begins with a space, an apostrophe (single quote), then four spaces before the first
    /// character reference". Adapted per the DOCTYPE prohibition of this surface: the four DOCTYPE lines
    /// are dropped and with them the <c>normNames</c> and <c>normId</c> rows, whose expectations exist
    /// only through their ATTLIST-declared NMTOKENS and ID attribute types; the rest is verbatim.
    /// </summary>
    [TestMethod]
    public void CharacterModificationsAndCharacterReferencesRender()
    {
        string document = XmlCanonicalizationFixtureInputs.Section34Document;
        string expected =
            "<doc>\n"
            + "   <text>First line&#xD;\n"
            + "Second line</text>\n"
            + "   <value>2</value>\n"
            + "   <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n"
            + "   <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n"
            + "   <norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n"
            + "</doc>";

        AssertCanonicalFormEquals(expected, Canonicalize(document, XmlCanonicalizationAlgorithm.CanonicalXml10));
    }


    /// <summary>
    /// Proves the refusal this surface substitutes for
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 3.6,
    /// whose example transcodes an ISO-8859-1 document to UTF-8. Delta: this surface accepts only UTF-8
    /// and UTF-16 and refuses every other declared encoding — conformant, since section 2.1 makes UTF-8
    /// and UTF-16 required and ISO-8859-1 merely RECOMMENDED — so the example's canonical form, the two
    /// octets C2 A9, is unreachable and the input is refused as
    /// <see cref="XmlReadFailure.InvalidEncoding"/> instead.
    /// </summary>
    [TestMethod]
    public void Utf8EncodingExampleInputIsRefusedAsIso88591()
    {
        string document = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<doc>&#169;</doc>";
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError error);
        table?.Dispose();

        Assert.IsFalse(isParsed, "A document declaring ISO-8859-1 must be refused.");
        Assert.AreEqual(XmlReadFailure.InvalidEncoding, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>
    /// section 3.7: empty default namespace propagation from an omitted parent element — <c>e3</c> renders
    /// <c>xmlns=""</c> because its nearest in-set ancestor <c>e1</c> has a default namespace node while
    /// <c>e3</c> has none — and persistence of omitted namespace declarations in descendants, with the
    /// <c>w3c</c> declaration suppressed on <c>e3</c> as superfluous against <c>e1</c>. The node-set is
    /// the one the example's subset expression selects: <c>e1</c> with its namespace and attribute axes
    /// and the <c>e3</c> subtree, with <c>e2</c> and the text nodes omitted, so "the canonical form
    /// contains no line delimiters". Adapted per the DOCTYPE prohibition of this surface: the three
    /// DOCTYPE lines are dropped and with them the DTD-defaulted <c>xml:space="preserve"</c> on <c>e3</c>
    /// in the expectation; the rest is verbatim.
    /// </summary>
    [TestMethod]
    public void DocumentSubsetRendersAncestorContextAndPropagatedDeclarations()
    {
        string document = XmlCanonicalizationFixtureInputs.Section37Document;
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");
        using(table)
        {
            XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table!, FindElement(table!, "e3")).IncludingAncestor(FindElement(table!, "e1"));
            string expected = "<e1 xmlns=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\"><e3 xmlns=\"\" id=\"E3\"></e3></e1>";

            AssertCanonicalFormEquals(expected, Canonicalize(table!, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10));
        }
    }
}
