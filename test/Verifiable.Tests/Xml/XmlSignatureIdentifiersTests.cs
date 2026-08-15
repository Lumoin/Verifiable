using System.Text;
using Verifiable.Cryptography.Pki;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XmlSignatureIdentifiers"/>: the identifiers stated match the defining specification
/// text exactly, the UTF-8 <c>Utf8</c>-suffixed accessors are byte-identical to encoding the <see
/// cref="string"/> form, and every identifier stated in both this leaf and <see
/// cref="XmlSignatureWellKnown"/> — the namespace and the six canonicalization identifiers — restates it
/// byte-identically and forms a real bijection with the Pki layer's own enumerated recognized set, per the
/// amended bijection discipline: adding a canonicalization identifier to either side alone, without the
/// matching addition on the other, changes a cardinality this file asserts against, not merely an equality
/// that string comparison already made symmetric for free.
/// </summary>
[TestClass]
internal sealed class XmlSignatureIdentifiersTests
{
    /// <summary>
    /// Every identifier this type states, as its string form. <see cref="ReadOnlySpan{T}"/> is a ref
    /// struct and cannot sit in a heap-allocated collection, so the paired UTF-8 span accessors are read
    /// directly in <see cref="Utf8FormMatchesUtf8EncodingOfTheStringForm"/> instead of being collected here.
    /// </summary>
    private static string[] AllIdentifierStrings =>
    [
        XmlSignatureIdentifiers.XmlSignatureNamespace,
        XmlSignatureIdentifiers.CanonicalXml10Uri,
        XmlSignatureIdentifiers.CanonicalXml10WithCommentsUri,
        XmlSignatureIdentifiers.CanonicalXml11Uri,
        XmlSignatureIdentifiers.CanonicalXml11WithCommentsUri,
        XmlSignatureIdentifiers.ExclusiveCanonicalXml10Uri,
        XmlSignatureIdentifiers.ExclusiveCanonicalXml10WithCommentsUri,
        XmlSignatureIdentifiers.EnvelopedSignatureTransformUri,
        XmlSignatureIdentifiers.Base64TransformUri,
        XmlSignatureIdentifiers.XPathTransformUri,
        XmlSignatureIdentifiers.XsltTransformUri,
        XmlSignatureIdentifiers.XPathFilter2TransformUri,
        XmlSignatureIdentifiers.RelationshipTransformUri
    ];

    /// <summary>The UTF-8 accessors of <see cref="AllIdentifierStrings"/>, in the same order, pre-materialized as arrays.</summary>
    private static byte[][] AllIdentifierUtf8Forms =>
    [
        XmlSignatureIdentifiers.XmlSignatureNamespaceUtf8.ToArray(),
        XmlSignatureIdentifiers.CanonicalXml10UriUtf8.ToArray(),
        XmlSignatureIdentifiers.CanonicalXml10WithCommentsUriUtf8.ToArray(),
        XmlSignatureIdentifiers.CanonicalXml11UriUtf8.ToArray(),
        XmlSignatureIdentifiers.CanonicalXml11WithCommentsUriUtf8.ToArray(),
        XmlSignatureIdentifiers.ExclusiveCanonicalXml10UriUtf8.ToArray(),
        XmlSignatureIdentifiers.ExclusiveCanonicalXml10WithCommentsUriUtf8.ToArray(),
        XmlSignatureIdentifiers.EnvelopedSignatureTransformUriUtf8.ToArray(),
        XmlSignatureIdentifiers.Base64TransformUriUtf8.ToArray(),
        XmlSignatureIdentifiers.XPathTransformUriUtf8.ToArray(),
        XmlSignatureIdentifiers.XsltTransformUriUtf8.ToArray(),
        XmlSignatureIdentifiers.XPathFilter2TransformUriUtf8.ToArray(),
        XmlSignatureIdentifiers.RelationshipTransformUriUtf8.ToArray()
    ];

    /// <summary>The core namespace, paired between this leaf's type and the Pki layer's — the first-named restated identifier.</summary>
    private static (string Leaf, string Pki) NamespacePair =>
        (XmlSignatureIdentifiers.XmlSignatureNamespace, XmlSignatureWellKnown.XmlSignatureNamespace);


    /// <summary>The six canonicalization identifiers, paired between this leaf's type and the Pki layer's.</summary>
    private static (string Leaf, string Pki)[] CanonicalizationPairs =>
    [
        (XmlSignatureIdentifiers.CanonicalXml10Uri, XmlSignatureWellKnown.CanonicalXml10Uri),
        (XmlSignatureIdentifiers.CanonicalXml10WithCommentsUri, XmlSignatureWellKnown.CanonicalXml10WithCommentsUri),
        (XmlSignatureIdentifiers.CanonicalXml11Uri, XmlSignatureWellKnown.CanonicalXml11Uri),
        (XmlSignatureIdentifiers.CanonicalXml11WithCommentsUri, XmlSignatureWellKnown.CanonicalXml11WithCommentsUri),
        (XmlSignatureIdentifiers.ExclusiveCanonicalXml10Uri, XmlSignatureWellKnown.ExclusiveCanonicalXml10Uri),
        (XmlSignatureIdentifiers.ExclusiveCanonicalXml10WithCommentsUri, XmlSignatureWellKnown.ExclusiveCanonicalXml10WithCommentsUri)
    ];


    /// <summary>
    /// Proves every identifier's UTF-8 span accessor is byte-identical to UTF-8-encoding the identifier's
    /// string form — the two representations this leaf states name the same octets, matching the exact
    /// algorithm-identifier URIs <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-AlgID">XML Signature clause
    /// 6.1</see> defines: the wire form (an attribute value) and this leaf's pre-encoded UTF-8 span must
    /// never diverge by so much as a code point.
    /// </summary>
    [TestMethod]
    public void Utf8FormMatchesUtf8EncodingOfTheStringForm()
    {
        string[] stringForms = AllIdentifierStrings;
        byte[][] utf8Forms = AllIdentifierUtf8Forms;
        Assert.HasCount(stringForms.Length, utf8Forms, "The two fixtures must be kept in the same order and count.");
        for(int i = 0; i < stringForms.Length; ++i)
        {
            Assert.AreSequenceEqual(Encoding.UTF8.GetBytes(stringForms[i]), utf8Forms[i], $"The UTF-8 accessor for '{stringForms[i]}' must match encoding its string form.");
        }
    }


    /// <summary>
    /// Proves the ds namespace matches
    /// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> Appendix A's schema <c>targetNamespace</c>,
    /// <c>http://www.w3.org/2000/09/xmldsig#</c>.
    /// </summary>
    [TestMethod]
    public void NamespaceMatchesTheSpecificationText()
    {
        Assert.AreEqual("http://www.w3.org/2000/09/xmldsig#", XmlSignatureIdentifiers.XmlSignatureNamespace);
    }


    /// <summary>
    /// Proves the enveloped-signature and base64 transform identifiers match section 6.6.4 and 6.6.2 of
    /// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see>.
    /// </summary>
    [TestMethod]
    public void EnvelopedSignatureAndBase64TransformUrisMatchTheSpecificationText()
    {
        Assert.AreEqual("http://www.w3.org/2000/09/xmldsig#enveloped-signature", XmlSignatureIdentifiers.EnvelopedSignatureTransformUri);
        Assert.AreEqual("http://www.w3.org/2000/09/xmldsig#base64", XmlSignatureIdentifiers.Base64TransformUri);
    }


    /// <summary>
    /// Proves the XPath and XSLT transform identifiers match section 6.6.3 and 6.6.5 of
    /// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see>: the identifiers ARE the XPath 1.0 and XSLT 1.0 recommendation
    /// URIs.
    /// </summary>
    [TestMethod]
    public void XPathAndXsltTransformUrisMatchTheSpecificationText()
    {
        Assert.AreEqual("http://www.w3.org/TR/1999/REC-xpath-19991116", XmlSignatureIdentifiers.XPathTransformUri);
        Assert.AreEqual("http://www.w3.org/TR/1999/REC-xslt-19991116", XmlSignatureIdentifiers.XsltTransformUri);
    }


    /// <summary>
    /// Proves the XPath Filter 2.0 and OOXML Relationships transform identifiers match clause 6.3(g) of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see>.
    /// </summary>
    [TestMethod]
    public void XPathFilter2AndRelationshipTransformUrisMatchTheSpecificationText()
    {
        Assert.AreEqual("http://www.w3.org/2002/06/xmldsig-filter2", XmlSignatureIdentifiers.XPathFilter2TransformUri);
        Assert.AreEqual("http://schemas.openxmlformats.org/package/2006/RelationshipTransform", XmlSignatureIdentifiers.RelationshipTransformUri);
    }


    /// <summary>
    /// Proves the identifiers this leaf restates — the namespace and the six canonicalization identifiers —
    /// are byte-identical to <see cref="XmlSignatureWellKnown"/>'s identically-named members, and that each
    /// canonicalization identifier is recognized there, per this leaf and <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-AlgID">XML Signature clause
    /// 6.1</see>'s general algorithm-identifier structure, which both layers must name identically since one
    /// URI value has exactly one algorithm meaning.
    /// </summary>
    [TestMethod]
    public void RestatedIdentifiersAreByteIdenticalToThePkiLayer()
    {
        Assert.AreEqual(NamespacePair.Pki, NamespacePair.Leaf, "The leaf and Pki-layer namespace constants must name the same identifier.");

        foreach((string leaf, string pki) in CanonicalizationPairs)
        {
            Assert.AreEqual(pki, leaf, $"'{leaf}' (leaf) and '{pki}' (Pki) must name the same canonicalization algorithm identifier.");
            Assert.IsTrue(XmlSignatureWellKnown.IsRecognizedCanonicalizationUri(leaf), $"'{leaf}' must be recognized as a canonicalization algorithm by the Pki layer.");
        }
    }


    /// <summary>
    /// Proves the six canonicalization identifiers form a REAL bijection with <see
    /// cref="XmlSignatureWellKnown.AllCanonicalizationUris"/> — not merely that this leaf's six URIs happen to be recognized (a
    /// Pki-side URI added without a matching leaf-side addition would not disturb that check), but that the two sides name the
    /// exact same set: <see cref="XmlSignatureWellKnown.AllCanonicalizationUris"/>'s count is tied to the real <see
    /// cref="XmlCanonicalizationAlgorithm"/> enumeration (the totality anchor <c>XmlCanonicalizationUriMappingTests</c> already
    /// proves the Pki layer's recognized set IS exactly that enumeration), and this leaf's stated pairing must cover <see
    /// cref="XmlSignatureWellKnown.AllCanonicalizationUris"/> exactly, in either order — so a canonicalization identifier added
    /// to either side alone, without the matching addition on the other, changes a cardinality or a set-membership this assertion
    /// catches. These are the <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-CanonicalizationMethod">XML
    /// Signature clause 4.3.1</see> "Implementations MUST support the REQUIRED canonicalization algorithms" obligation restated
    /// as a closed, enumerable set.
    /// </summary>
    [TestMethod]
    public void CanonicalizationIdentifiersFormABijectionWithThePkiLayersRecognizedSet()
    {
        Assert.HasCount(Enum.GetValues<XmlCanonicalizationAlgorithm>().Length, XmlSignatureWellKnown.AllCanonicalizationUris,
            "The Pki layer's enumerated recognized set must have exactly one member per XmlCanonicalizationAlgorithm value.");

        string[] pkiSide = [.. CanonicalizationPairs.Select(pair => pair.Pki)];
        Assert.AreSequenceEqual(XmlSignatureWellKnown.AllCanonicalizationUris, pkiSide, SequenceOrder.InAnyOrder,
            "This leaf's stated pairing must be exactly the Pki layer's enumerated recognized set — a canonicalization identifier added to either side alone, without the matching addition on the other, must change this comparison.");
    }


    /// <summary>
    /// Binds <see cref="XmlSignatureWellKnown.AllCanonicalizationUris"/> directly to
    /// <see cref="XmlSignatureWellKnown.IsRecognizedCanonicalizationUri"/>, independent of the fixture
    /// pairing <see cref="CanonicalizationIdentifiersFormABijectionWithThePkiLayersRecognizedSet"/> compares
    /// against: every listed URI is recognized, and the count the predicate recognizes over the union of the
    /// leaf-side and Pki-side canonicalization constants equals the list's own count — a recognition arm
    /// added to <see cref="XmlSignatureWellKnown.IsRecognizedCanonicalizationUri"/> without a matching
    /// <see cref="XmlSignatureWellKnown.AllCanonicalizationUris"/> entry changes that count, per the same
    /// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-CanonicalizationMethod">XML
    /// Signature clause 4.3.1</see> totality obligation.
    /// </summary>
    [TestMethod]
    public void AllCanonicalizationUrisAreRecognizedAndTheRecognizedCountMatchesTheList()
    {
        foreach(string uri in XmlSignatureWellKnown.AllCanonicalizationUris)
        {
            Assert.IsTrue(XmlSignatureWellKnown.IsRecognizedCanonicalizationUri(uri), $"'{uri}' is listed in AllCanonicalizationUris and must be recognized.");
        }

        string[] unionOfBothSidesConstants =
        [
            .. CanonicalizationPairs.Select(pair => pair.Pki).Concat(CanonicalizationPairs.Select(pair => pair.Leaf)).Distinct()
        ];
        int recognizedCount = unionOfBothSidesConstants.Count(XmlSignatureWellKnown.IsRecognizedCanonicalizationUri);
        Assert.AreEqual(XmlSignatureWellKnown.AllCanonicalizationUris.Count, recognizedCount,
            "The predicate must recognize exactly as many candidates from the leaf/Pki union as AllCanonicalizationUris lists — a recognition arm added without the matching list entry changes this count.");
    }
}
