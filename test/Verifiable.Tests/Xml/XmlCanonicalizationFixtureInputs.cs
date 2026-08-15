namespace Verifiable.Tests.Xml;

/// <summary>
/// The parseable fixture input documents of the Canonical XML fixture and divergence test classes, held
/// once so the specification-example proofs of <see cref="XmlCanonicalizationC14N10FixtureTests"/>,
/// <see cref="XmlCanonicalizationC14N11FixtureTests"/>,
/// <see cref="XmlCanonicalizationExclusiveFixtureTests"/> and
/// <see cref="XmlCanonicalizationSubsetDivergenceTests"/> and the idempotence proofs of
/// <see cref="XmlCanonicalizationIdempotenceTests"/> run over the same octets. Inputs transcribed from a
/// specification example carry the DOCTYPE adaptation of this surface: the DOCTYPE line or lines are
/// dropped and the rest kept verbatim, with the delta stated in the doc comment of each asserting test.
/// </summary>
internal static class XmlCanonicalizationFixtureInputs
{
    /// <summary>
    /// The section 3.1 example input of
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> and
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>: an XML
    /// declaration, processing instructions and comments outside the document element.
    /// </summary>
    internal const string Section31Document =
        "<?xml version=\"1.0\"?>\n"
        + "\n"
        + "<?xml-stylesheet   href=\"doc.xsl\"\n"
        + "   type=\"text/xsl\"   ?>\n"
        + "\n"
        + "<doc>Hello, world!<!-- Comment 1 --></doc>\n"
        + "\n"
        + "<?pi-without-data     ?>\n"
        + "\n"
        + "<!-- Comment 2 -->\n"
        + "\n"
        + "<!-- Comment 3 -->\n";

    /// <summary>
    /// The section 3.2 example input of
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> and
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>: whitespace
    /// in document content, clean and dirty.
    /// </summary>
    internal const string Section32Document =
        "<doc>\n"
        + "   <clean>   </clean>\n"
        + "   <dirty>   A   B   </dirty>\n"
        + "   <mixed>\n"
        + "      A\n"
        + "      <clean>   </clean>\n"
        + "      B\n"
        + "      <dirty>   A   B   </dirty>\n"
        + "      C\n"
        + "   </mixed>\n"
        + "</doc>";

    /// <summary>
    /// The section 3.3 example input of
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> and
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>: start and
    /// end tags, the namespace and attribute axes, and superfluous namespace declarations.
    /// </summary>
    internal const string Section33Document =
        "<doc>\n"
        + "   <e1   />\n"
        + "   <e2   ></e2>\n"
        + "   <e3   name = \"elem3\"   id=\"elem3\"   />\n"
        + "   <e4   name=\"elem4\"   id=\"elem4\"   ></e4>\n"
        + "   <e5 a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" attr=\"I'm\"\n"
        + "      xmlns:b=\"http://www.ietf.org\"\n"
        + "      xmlns:a=\"http://www.w3.org\"\n"
        + "      xmlns=\"http://example.org\"/>\n"
        + "   <e6 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n"
        + "      <e7 xmlns=\"http://www.ietf.org\">\n"
        + "         <e8 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n"
        + "            <e9 xmlns=\"\" xmlns:a=\"http://www.ietf.org\"/>\n"
        + "         </e8>\n"
        + "      </e7>\n"
        + "   </e6>\n"
        + "</doc>";

    /// <summary>
    /// The section 3.4 example input of
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> and
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>: character
    /// modifications, character references and CDATA sections.
    /// </summary>
    internal const string Section34Document =
        "<doc>\n"
        + "   <text>First line&#x0d;&#10;Second line</text>\n"
        + "   <value>&#x32;</value>\n"
        + "   <compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\n"
        + "   <compute expr='value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"'>valid</compute>\n"
        + "   <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n"
        + "</doc>\n";

    /// <summary>
    /// The section 3.7 example input of
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> and
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>: the
    /// document whose subset canonicalization proves ancestor-context and propagated declarations.
    /// </summary>
    internal const string Section37Document =
        "<doc xmlns=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\">\n"
        + "   <e1>\n"
        + "      <e2 xmlns=\"\">\n"
        + "         <e3 id=\"E3\"/>\n"
        + "      </e2>\n"
        + "   </e1>\n"
        + "</doc>";

    /// <summary>
    /// The section 3.8 example input of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see>: the
    /// document whose subset canonicalization proves the <c>xml:id</c> and <c>xml:base</c> treatment.
    /// </summary>
    internal const string Section38Document =
        "<doc xmlns=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\" xml:base=\"something/else\">\n"
        + "   <e1>\n"
        + "      <e2 xmlns=\"\" xml:id=\"abc\" xml:base=\"bar/\">\n"
        + "         <e3 id=\"E3\" xml:base=\"foo\"/>\n"
        + "      </e2>\n"
        + "   </e1>\n"
        + "</doc>";

    /// <summary>
    /// The first document of the section 2.1 worked example of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see>: the element <c>elem1</c> standing alone with its own namespace declaration, which the
    /// section states "is in canonical form".
    /// </summary>
    internal const string Section21FirstDocument =
        "   <n1:elem1 xmlns:n1=\"http://b.example\">\n"
        + "       content\n"
        + "   </n1:elem1>";

    /// <summary>
    /// The enveloped document of the section 2.1 worked example of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see>: <c>elem1</c> "then enveloped in another document", whose <c>n0</c> declaration the
    /// inclusive and exclusive subtree renderings treat differently.
    /// </summary>
    internal const string Section21EnvelopedDocument =
        "   <n0:pdu xmlns:n0=\"http://a.example\">\n"
        + "      <n1:elem1 xmlns:n1=\"http://b.example\">\n"
        + "          content\n"
        + "      </n1:elem1>\n"
        + "   </n0:pdu>";

    /// <summary>
    /// The first document of the section 2.2 worked example of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see>: <c>elem2</c> enveloped with a context that declares <c>n0</c> and an <c>n3</c> binding
    /// identical to the one <c>n3:stuff</c> declares.
    /// </summary>
    internal const string Section22FirstDocument =
        "   <n0:local xmlns:n0=\"foo:bar\"\n"
        + "             xmlns:n3=\"ftp://example.org\">\n"
        + "      <n1:elem2 xmlns:n1=\"http://example.net\"\n"
        + "                xml:lang=\"en\">\n"
        + "          <n3:stuff xmlns:n3=\"ftp://example.org\"/>\n"
        + "      </n1:elem2>\n"
        + "   </n0:local>";

    /// <summary>
    /// The re-enveloped document of the section 2.2 worked example of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see>: <c>elem2</c> "extracted and enveloped in a new document" whose changed context carries
    /// <c>n2</c>, a shadowed <c>n1</c>, <c>xml:lang</c> and <c>xml:space</c> declarations.
    /// </summary>
    internal const string Section22ReEnvelopedDocument =
        "   <n2:pdu xmlns:n1=\"http://example.com\"\n"
        + "           xmlns:n2=\"http://foo.example\"\n"
        + "           xml:lang=\"fr\"\n"
        + "           xml:space=\"retain\">\n"
        + "      <n1:elem2 xmlns:n1=\"http://example.net\"\n"
        + "                xml:lang=\"en\">\n"
        + "          <n3:stuff xmlns:n3=\"ftp://example.org\"/>\n"
        + "      </n1:elem2>\n"
        + "   </n2:pdu>";

    /// <summary>
    /// The divergence document carrying an <c>xml</c>-namespace attribute beyond the ones
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see> section 2.4
    /// names, over which Canonical XML 1.0 and 1.1 import differently.
    /// </summary>
    internal const string GeneralXmlAttributeDocument = "<doc xml:lang=\"en\" xml:other=\"o\"><e/></doc>";

    /// <summary>
    /// The sample document of <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical
    /// XML 1.1</see> section 2.4, whitespace compacted, whose <c>xml:base</c> chain joins to
    /// <c>../../x</c> when the elements <c>b</c> and <c>c</c> are removed.
    /// </summary>
    internal const string XmlBaseChainDocument = "<a xml:base=\"foo/bar\"><b xml:base=\"..\"><c xml:base=\"..\"><d xml:base=\"x\"></d></c></b></a>";

    /// <summary>
    /// The divergence document carrying the
    /// <see href="https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/">Canonical XML 1.1</see> section 2.4
    /// value pair "'abc/' and '../' should result in ''", whose subset canonicalization suppresses
    /// <c>xml:base</c> under Canonical XML 1.1.
    /// </summary>
    internal const string XmlBaseEmptyJoinDocument = "<a xml:base=\"abc/\"><b xml:base=\"../\">t</b></a>";

    /// <summary>
    /// The divergence document whose <c>sig</c> subtree is excluded to prove the
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.3
    /// rule that no text is generated for a node outside the node-set.
    /// </summary>
    internal const string ExcludedSubtreeDocument = "<doc xmlns:p=\"urn:x\"><a>t</a><sig><inner/>s</sig><b p:q=\"v\"/></doc>";

    /// <summary>
    /// The compact <c>xml:base</c> and <c>xml:id</c> subset document of the pooled-buffer custody proof of
    /// <see cref="XmlCanonicalizationSubsetDivergenceTests"/>, exercising the ancestor-import and
    /// <c>xml:base</c> fixup paths of both Canonical XML 1.0 and 1.1 section 2.4.
    /// </summary>
    internal const string CompactSubsetDocument =
        "<doc xmlns=\"http://www.ietf.org\" xml:base=\"something/else\">"
        + "<e1><e2 xml:id=\"abc\" xml:base=\"bar/\"><e3 id=\"E3\" xml:base=\"foo\"/></e2></e1></doc>";


    /// <summary>
    /// Every document above by name: the domain over which the idempotence proofs of
    /// <see cref="XmlCanonicalizationIdempotenceTests"/> run.
    /// </summary>
    internal static (string Name, string Document)[] AllDocuments =>
    [
        (nameof(Section31Document), Section31Document),
        (nameof(Section32Document), Section32Document),
        (nameof(Section33Document), Section33Document),
        (nameof(Section34Document), Section34Document),
        (nameof(Section37Document), Section37Document),
        (nameof(Section38Document), Section38Document),
        (nameof(Section21FirstDocument), Section21FirstDocument),
        (nameof(Section21EnvelopedDocument), Section21EnvelopedDocument),
        (nameof(Section22FirstDocument), Section22FirstDocument),
        (nameof(Section22ReEnvelopedDocument), Section22ReEnvelopedDocument),
        (nameof(GeneralXmlAttributeDocument), GeneralXmlAttributeDocument),
        (nameof(XmlBaseChainDocument), XmlBaseChainDocument),
        (nameof(XmlBaseEmptyJoinDocument), XmlBaseEmptyJoinDocument),
        (nameof(ExcludedSubtreeDocument), ExcludedSubtreeDocument),
        (nameof(CompactSubsetDocument), CompactSubsetDocument)
    ];
}
