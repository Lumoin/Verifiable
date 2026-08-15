using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of the <c>InclusiveNamespaces PrefixList</c> parameter of
/// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
/// 1.0</see> section 4 as <see cref="XmlCanonicalization.TryCanonicalizeExclusive"/> takes it: the
/// NMTOKENS white-space split, the Canonical XML handling of listed prefixes, the <c>#default</c> token,
/// the visibly-utilizes boundary the list relaxes, and the refusal of tokens that are neither a namespace
/// prefix nor <c>#default</c>.
/// </summary>
[TestClass]
internal sealed class XmlCanonicalizationExclusivePrefixListTests
{
    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static string CanonicalizeExclusive(XmlNodeTable table, XmlNodeSet nodeSet, string[]? inclusivePrefixes = null)
    {
        return XmlCanonicalizationExclusiveFixtureTests.CanonicalizeExclusive(table, nodeSet, isWithComments: false, inclusivePrefixes);
    }


    private static int FindElement(XmlNodeTable table, string localName)
    {
        return XmlCanonicalizationC14N10FixtureTests.FindElement(table, localName);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML
    /// Canonicalization 1.0</see> section 3 item 2: "All namespace nodes appearing on this list are
    /// handled as provided in Canonical XML [XML-C14N]" — a listed prefix renders on the subtree apex from
    /// the ancestor context although nothing visibly utilizes it, exactly as Canonical XML renders the
    /// in-scope axis, while unlisted it is dropped. This is the section 1.3 remedy for namespace prefixes
    /// that are not visibly utilized: "the prefixes for such namespaces must appear in the
    /// InclusiveNamespaces PrefixList."
    /// </summary>
    [TestMethod]
    public void ListedPrefixIsHandledPerCanonicalXmlEvenWhenNotVisiblyUtilized()
    {
        string document = "<root xmlns:a=\"urn:a\"><child>t</child></root>";
        using XmlNodeTable table = Parse(document);
        XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table, FindElement(table, "child"));

        string withoutList = CanonicalizeExclusive(table, nodeSet);
        string withList = CanonicalizeExclusive(table, nodeSet, ["a"]);

        Assert.AreEqual("<child>t</child>", withoutList);
        Assert.AreEqual("<child xmlns:a=\"urn:a\">t</child>", withList);
    }


    /// <summary>
    /// Proves the <c>PrefixList</c> value format of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> section 4 with the section's own example value <c>PrefixList="dsig soap #default"</c>:
    /// "The value of this attribute, which may be null, is a white space delimited list of namespace
    /// prefixes, and where #default indicates the default namespace ... The list is in NMTOKENS format (a
    /// white space separated list)", indicating "that namespaces with prefix 'dsig' or 'soap' and default
    /// namespaces should be processed according to [XML-C14N]" — one white-space-delimited entry behaves
    /// exactly as the same tokens passed separately, and the unlisted <c>other</c> prefix stays excluded.
    /// </summary>
    [TestMethod]
    public void PrefixListValueSplitsAsNmtokensOnXmlWhiteSpace()
    {
        string document = "<env xmlns=\"urn:env\" xmlns:dsig=\"urn:dsig\" xmlns:soap=\"urn:soap\" xmlns:other=\"urn:other\"><x:body xmlns:x=\"urn:x\">t</x:body></env>";
        using XmlNodeTable table = Parse(document);
        XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table, FindElement(table, "body"));

        string withSingleEntry = CanonicalizeExclusive(table, nodeSet, ["dsig soap #default"]);
        string withSeparateTokens = CanonicalizeExclusive(table, nodeSet, ["dsig", "soap", "#default"]);
        string withoutList = CanonicalizeExclusive(table, nodeSet);

        Assert.AreEqual("<x:body xmlns=\"urn:env\" xmlns:dsig=\"urn:dsig\" xmlns:soap=\"urn:soap\" xmlns:x=\"urn:x\">t</x:body>", withSingleEntry);
        Assert.AreEqual(withSingleEntry, withSeparateTokens);
        Assert.AreEqual("<x:body xmlns:x=\"urn:x\">t</x:body>", withoutList);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML
    /// Canonicalization 1.0</see> section 3 items 3 and 4 for the default namespace against the
    /// <c>#default</c> token. Without the token, a prefixed apex does not visibly utilize the default
    /// namespace, so the ancestor-declared default renders only on the unprefixed descendant that does;
    /// with the token the default namespace is "handled as provided in Canonical XML", rendering on the
    /// apex from the ancestor context and suppressed on the descendant as superfluous.
    /// </summary>
    [TestMethod]
    public void DefaultTokenSelectsCanonicalXmlHandlingOfTheDefaultNamespace()
    {
        string document = "<a xmlns=\"urn:d\" xmlns:p=\"urn:p\"><p:b><c>t</c></p:b></a>";
        using XmlNodeTable table = Parse(document);
        XmlNodeSet nodeSet = XmlNodeSet.ElementSubtree(table, FindElement(table, "b"));

        string withoutToken = CanonicalizeExclusive(table, nodeSet);
        string withToken = CanonicalizeExclusive(table, nodeSet, ["#default"]);

        Assert.AreEqual("<p:b xmlns:p=\"urn:p\"><c xmlns=\"urn:d\">t</c></p:b>", withoutToken);
        Assert.AreEqual("<p:b xmlns=\"urn:d\" xmlns:p=\"urn:p\"><c>t</c></p:b>", withToken);
    }


    /// <summary>
    /// Proves the <c>xmlns=""</c> rule of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> section 3 item 4: without the <c>#default</c> token, <c>xmlns=""</c> is output "if and
    /// only if" the element "visibly utilizes the default namespace (i.e., it has no namespace prefix)",
    /// "has no default namespace node in the node-set", and "the nearest output ancestor of E that visibly
    /// utilizes the default namespace has a default namespace node in the node-set" — so it lands on the
    /// unprefixed <c>f</c>, not on the prefixed <c>p:e</c> that carries the un-declaration. With the token
    /// the changed rules do not apply and <c>xmlns=""</c> lands on <c>p:e</c> per Canonical XML, whose
    /// section 2.3 keys on the nearest in-set ancestor's default namespace node alone.
    /// </summary>
    [TestMethod]
    public void EmptyDefaultNamespaceRenderingFollowsVisibleUtilizationWithoutDefaultToken()
    {
        string document = "<root xmlns=\"urn:d\" xmlns:p=\"urn:p\"><p:e xmlns=\"\"><f>t</f></p:e></root>";
        using XmlNodeTable table = Parse(document);
        XmlNodeSet nodeSet = XmlNodeSet.WholeDocument(table);

        string withoutToken = CanonicalizeExclusive(table, nodeSet);
        string withToken = CanonicalizeExclusive(table, nodeSet, ["#default"]);

        Assert.AreEqual("<root xmlns=\"urn:d\"><p:e xmlns:p=\"urn:p\"><f xmlns=\"\">t</f></p:e></root>", withoutToken);
        Assert.AreEqual("<root xmlns=\"urn:d\"><p:e xmlns=\"\" xmlns:p=\"urn:p\"><f>t</f></p:e></root>", withToken);
    }


    /// <summary>
    /// Proves over a whole document — no subsetting at all — that
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> differs from Canonical XML 1.0: per the section 1.1 summary, "namespace nodes that are
    /// not on the InclusiveNamespaces PrefixList are expressed only in start tags where they are visible",
    /// so the never-utilized declaration is dropped by the exclusive form, retained by
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.3,
    /// which renders the namespace axis without a visibility condition, and restored by listing its
    /// prefix.
    /// </summary>
    [TestMethod]
    public void UnusedNamespaceDeclarationDropsUnderExclusiveButNotInclusiveOverWholeDocument()
    {
        string document = "<doc xmlns:unused=\"urn:unused\"><a>t</a></doc>";
        using XmlNodeTable table = Parse(document);
        XmlNodeSet nodeSet = XmlNodeSet.WholeDocument(table);

        bool isCanonicalized = XmlCanonicalization.TryCanonicalize(table, nodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10, BaseMemoryPool.Shared, out PooledMemory? inclusiveOctets, out XmlCanonicalizationError error);
        Assert.IsTrue(isCanonicalized, $"Inclusive canonicalization must succeed but was refused with {error.Failure}.");
        string underInclusive;
        using(inclusiveOctets)
        {
            underInclusive = Encoding.UTF8.GetString(inclusiveOctets!.AsReadOnlySpan());
        }

        string underExclusive = CanonicalizeExclusive(table, nodeSet);
        string underExclusiveListed = CanonicalizeExclusive(table, nodeSet, ["unused"]);

        Assert.AreEqual("<doc xmlns:unused=\"urn:unused\"><a>t</a></doc>", underInclusive);
        Assert.AreEqual("<doc><a>t</a></doc>", underExclusive);
        Assert.AreEqual(underInclusive, underExclusiveListed);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML
    /// Canonicalization 1.0</see> section 5 item 3: "implementations of this specification do not consider
    /// the appearance of a namespace prefix within an attribute value to be visibly utilized" — over the
    /// section 1.3 example attribute <c>xsi:type="xsd:decimal"</c>, the <c>xsi</c> prefix of the qualified
    /// attribute name renders while the <c>xsd</c> prefix appearing only inside the value does not, until
    /// its prefix appears on the list per the section 1.3 remedy.
    /// </summary>
    [TestMethod]
    public void PrefixInAttributeValueIsNotVisiblyUtilized()
    {
        string document = "<doc xmlns:xsi=\"urn:xsi\" xmlns:xsd=\"urn:xsd\"><number xsi:type=\"xsd:decimal\">10.09</number></doc>";
        using XmlNodeTable table = Parse(document);
        XmlNodeSet nodeSet = XmlNodeSet.WholeDocument(table);

        string withoutList = CanonicalizeExclusive(table, nodeSet);
        string withList = CanonicalizeExclusive(table, nodeSet, ["xsd"]);

        Assert.AreEqual("<doc><number xmlns:xsi=\"urn:xsi\" xsi:type=\"xsd:decimal\">10.09</number></doc>", withoutList);
        Assert.AreEqual("<doc xmlns:xsd=\"urn:xsd\"><number xmlns:xsi=\"urn:xsi\" xsi:type=\"xsd:decimal\">10.09</number></doc>", withList);
    }


    /// <summary>
    /// Proves the refusal contract of <see cref="XmlCanonicalizationFailure.InvalidPrefixList"/> against
    /// the <c>PrefixList</c> format of
    /// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
    /// 1.0</see> section 4: a namespace prefix is an <c>NCName</c> of
    /// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 3, so a token carrying a colon, a leading digit, or an unknown <c>#</c>
    /// token is refused, while entries that split into no tokens at all contribute nothing.
    /// </summary>
    [TestMethod]
    public void InvalidPrefixListTokenIsRefused()
    {
        string document = "<doc xmlns:a=\"urn:a\"><a:e>t</a:e></doc>";
        using XmlNodeTable table = Parse(document);
        XmlNodeSet nodeSet = XmlNodeSet.WholeDocument(table);

        foreach(string invalidToken in (string[])["p:q", "1abc", "#other"])
        {
            bool isCanonicalized = XmlCanonicalization.TryCanonicalizeExclusive(table, nodeSet, isWithComments: false, [invalidToken], BaseMemoryPool.Shared, out PooledMemory? _, out XmlCanonicalizationError error);

            Assert.IsFalse(isCanonicalized, $"The token '{invalidToken}' must be refused.");
            Assert.AreEqual(XmlCanonicalizationFailure.InvalidPrefixList, error.Failure);
        }

        string withEmptyEntries = XmlCanonicalizationExclusiveFixtureTests.CanonicalizeExclusive(table, nodeSet, isWithComments: false, ["", "   \t\r\n"]);
        Assert.AreEqual("<doc><a:e xmlns:a=\"urn:a\">t</a:e></doc>", withEmptyEntries);
    }
}
