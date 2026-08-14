using Verifiable.Cryptography.Pki;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESIdentifiers"/>: every stated identifier matches the exact character sequence
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see> names it with, and the UTF-8 <c>Utf8</c>-suffixed accessors are
/// byte-identical to encoding the string form — the same discipline <see cref="XmlSignatureIdentifiersTests"/>
/// proves for the XMLDSIG core. Also proves the clause 5.1.3 <c>Encoding</c> URIs form a REAL bijection with
/// the Pki layer's own <see cref="AdESPkiObjectEncoding"/> enumeration (the same bijection discipline applied
/// to this member set) — this project references both <c>Verifiable.Xml</c> and <c>Verifiable.Cryptography</c>, so it is the one
/// place that pairing can be proved.
/// </summary>
[TestClass]
internal sealed class XAdESIdentifiersTests
{
    /// <summary>The five clause 5.1.3 Encoding URIs, paired between this leaf's type and the Pki layer's.</summary>
    private static (string Leaf, string Pki)[] EncodingPairs =>
    [
        (XAdESIdentifiers.DerEncodingUri, AdESPkiObjectEncodingUris.DerUri),
        (XAdESIdentifiers.BerEncodingUri, AdESPkiObjectEncodingUris.BerUri),
        (XAdESIdentifiers.CerEncodingUri, AdESPkiObjectEncodingUris.CerUri),
        (XAdESIdentifiers.PerEncodingUri, AdESPkiObjectEncodingUris.PerUri),
        (XAdESIdentifiers.XerEncodingUri, AdESPkiObjectEncodingUris.XerUri)
    ];


    private static (string StringForm, byte[] Utf8Form)[] AllIdentifiers =>
    [
        (XAdESIdentifiers.XAdESNamespaceV132, [.. XAdESIdentifiers.XAdESNamespaceV132Utf8]),
        (XAdESIdentifiers.XAdESNamespaceV141, [.. XAdESIdentifiers.XAdESNamespaceV141Utf8]),
        (XAdESIdentifiers.SignedPropertiesTypeUri, [.. XAdESIdentifiers.SignedPropertiesTypeUriUtf8]),
        (XAdESIdentifiers.CountersignedSignatureTypeUri, [.. XAdESIdentifiers.CountersignedSignatureTypeUriUtf8]),
        (XAdESIdentifiers.SPDocDigestAsInSpecificationTransformUri, [.. XAdESIdentifiers.SPDocDigestAsInSpecificationTransformUriUtf8]),
        (XAdESIdentifiers.DerEncodingUri, [.. XAdESIdentifiers.DerEncodingUriUtf8]),
        (XAdESIdentifiers.BerEncodingUri, [.. XAdESIdentifiers.BerEncodingUriUtf8]),
        (XAdESIdentifiers.CerEncodingUri, [.. XAdESIdentifiers.CerEncodingUriUtf8]),
        (XAdESIdentifiers.PerEncodingUri, [.. XAdESIdentifiers.PerEncodingUriUtf8]),
        (XAdESIdentifiers.XerEncodingUri, [.. XAdESIdentifiers.XerEncodingUriUtf8])
    ];


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.2, every identifier's UTF-8 span accessor is byte-identical to UTF-8-encoding the identifier's
    /// string form.
    /// </summary>
    [TestMethod]
    public void Utf8FormMatchesUtf8EncodingOfTheStringForm()
    {
        foreach((string stringForm, byte[] utf8Form) in AllIdentifiers)
        {
            Assert.AreSequenceEqual(System.Text.Encoding.UTF8.GetBytes(stringForm), utf8Form, $"The UTF-8 accessor for '{stringForm}' must match encoding its string form.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.2's two XAdES namespace URIs: <c>http://uri.etsi.org/01903/v1.3.2#</c> (most
    /// qualifying properties) and <c>http://uri.etsi.org/01903/v1.4.1#</c> — verified against the acquired
    /// <c>1913201-XAdES01903v132.xsd</c>/<c>1913201-XAdES01903v141.xsd</c> <c>targetNamespace</c> attributes,
    /// which clause 4.2's own precedence rule (XA-4.2-4) makes authoritative over the in-document excerpts.
    /// </summary>
    [TestMethod]
    public void NamespacesMatchTheAcquiredSchemaFiles()
    {
        Assert.AreEqual("http://uri.etsi.org/01903/v1.3.2#", XAdESIdentifiers.XAdESNamespaceV132);
        Assert.AreEqual("http://uri.etsi.org/01903/v1.4.1#", XAdESIdentifiers.XAdESNamespaceV141);
        Assert.AreNotEqual(XAdESIdentifiers.XAdESNamespaceV132, XAdESIdentifiers.XAdESNamespaceV141, "The two namespaces are separate, first-class identities per clause 4.2's NOTE 3 — never conflated.");
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.2's <c>ds:Reference</c> <c>Type</c> discovery URI for a XAdES signature's
    /// <c>SignedProperties</c> element, <c>http://uri.etsi.org/01903#SignedProperties</c> — the version-less
    /// <c>01903#</c> URI space, distinct from the versioned <c>01903/v1.3.2#</c> namespace.
    /// </summary>
    [TestMethod]
    public void SignedPropertiesTypeUriMatchesTheSpecificationText()
    {
        Assert.AreEqual("http://uri.etsi.org/01903#SignedProperties", XAdESIdentifiers.SignedPropertiesTypeUri);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.1's countersignature <c>ds:Reference</c> <c>Type</c> URI,
    /// <c>http://uri.etsi.org/01903#CountersignedSignature</c>.
    /// </summary>
    [TestMethod]
    public void CountersignedSignatureTypeUriMatchesTheSpecificationText()
    {
        Assert.AreEqual("http://uri.etsi.org/01903#CountersignedSignature", XAdESIdentifiers.CountersignedSignatureTypeUri);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.1's <c>SPDocDigestAsInSpecification</c> transform algorithm identifier,
    /// <c>http://uri.etsi.org/01903/v1.3.2/SignaturePolicy/SPDocDigestAsInSpecification</c>.
    /// </summary>
    [TestMethod]
    public void SPDocDigestAsInSpecificationTransformUriMatchesTheSpecificationText()
    {
        Assert.AreEqual("http://uri.etsi.org/01903/v1.3.2/SignaturePolicy/SPDocDigestAsInSpecification", XAdESIdentifiers.SPDocDigestAsInSpecificationTransformUri);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.3's closed five-value <c>Encoding</c> enumeration verbatim, each of the form
    /// <c>http://uri.etsi.org/01903/v1.2.2#{DER,BER,CER,PER,XER}</c> — verified directly against clause 5.1.3's own PDF text layer.
    /// </summary>
    [TestMethod]
    public void EncodingUrisMatchTheSpecificationText()
    {
        Assert.AreEqual("http://uri.etsi.org/01903/v1.2.2#DER", XAdESIdentifiers.DerEncodingUri);
        Assert.AreEqual("http://uri.etsi.org/01903/v1.2.2#BER", XAdESIdentifiers.BerEncodingUri);
        Assert.AreEqual("http://uri.etsi.org/01903/v1.2.2#CER", XAdESIdentifiers.CerEncodingUri);
        Assert.AreEqual("http://uri.etsi.org/01903/v1.2.2#PER", XAdESIdentifiers.PerEncodingUri);
        Assert.AreEqual("http://uri.etsi.org/01903/v1.2.2#XER", XAdESIdentifiers.XerEncodingUri);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.2, the five encoding URIs are pairwise distinct — a closed enumeration whose five members must
    /// remain five, not collapse under a copy-paste slip.
    /// </summary>
    [TestMethod]
    public void EncodingUrisArePairwiseDistinct()
    {
        string[] encodings =
        [
            XAdESIdentifiers.DerEncodingUri,
            XAdESIdentifiers.BerEncodingUri,
            XAdESIdentifiers.CerEncodingUri,
            XAdESIdentifiers.PerEncodingUri,
            XAdESIdentifiers.XerEncodingUri
        ];

        Assert.HasCount(5, encodings.Distinct().ToArray(), "The five Encoding URIs of clause 5.1.3 must be pairwise distinct.");
    }


    /// <summary>
    /// Proves each leaf-side encoding URI restates its Pki-side counterpart byte-identically — the first half
    /// of the bijection: a leaf/Pki literal drifting apart (a copy-paste slip on either side) fails this
    /// pairwise comparison directly, independent of the cardinality check <see
    /// cref="EncodingUrisFormABijectionWithThePkiLayersEnumeration"/> performs.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.3, restated in <see
    /// cref="AdESPkiObjectEncodingUris"/>.
    /// </remarks>
    [TestMethod]
    public void EncodingUriPairsAreByteIdenticalBetweenLeafAndPki()
    {
        foreach((string leaf, string pki) in EncodingPairs)
        {
            Assert.AreEqual(leaf, pki, $"Leaf identifier '{leaf}' must restate its Pki-layer counterpart byte-identically.");
        }
    }


    /// <summary>
    /// Proves the five clause 5.1.3 <c>Encoding</c> URIs form a REAL bijection with <see
    /// cref="AdESPkiObjectEncoding"/> — not merely that this leaf's five URIs happen to be recognized (a
    /// Pki-side member added without a matching leaf-side URI would not disturb that check alone), but that the
    /// two sides name the exact same five-member set: <see cref="AdESPkiObjectEncodingUris.All"/>'s count is
    /// tied to the real <see cref="AdESPkiObjectEncoding"/> enumeration, and this leaf's stated pairing must
    /// cover it exactly, in either order — the bijection discipline applied to this member set.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.3.
    /// </remarks>
    [TestMethod]
    public void EncodingUrisFormABijectionWithThePkiLayersEnumeration()
    {
        Assert.HasCount(Enum.GetValues<AdESPkiObjectEncoding>().Length, AdESPkiObjectEncodingUris.All,
            "The Pki layer's enumerated URI set must have exactly one member per AdESPkiObjectEncoding value.");

        string[] pkiSide = [.. EncodingPairs.Select(pair => pair.Pki)];
        Assert.AreSequenceEqual(AdESPkiObjectEncodingUris.All, pkiSide, SequenceOrder.InAnyOrder,
            "This leaf's stated pairing must be exactly the Pki layer's enumerated URI set — an encoding identifier added to either side alone, without the matching addition on the other, must change this comparison.");
    }


    /// <summary>
    /// Proves <see cref="AdESPkiObjectEncodingUris.FromUri"/> resolves each leaf-stated URI to the matching
    /// <see cref="AdESPkiObjectEncoding"/> value, and <see cref="AdESPkiObjectEncodingUris.ToUri"/> round-trips
    /// each value back to the SAME leaf-stated URI byte-for-byte — the mapping functions stay consistent with
    /// the leaf's own literal, not just the bare URI text.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.3.
    /// </remarks>
    [TestMethod]
    [DataRow("DER", AdESPkiObjectEncoding.Der)]
    [DataRow("BER", AdESPkiObjectEncoding.Ber)]
    [DataRow("CER", AdESPkiObjectEncoding.Cer)]
    [DataRow("PER", AdESPkiObjectEncoding.Per)]
    [DataRow("XER", AdESPkiObjectEncoding.Xer)]
    public void FromUriAndToUriRoundTripEveryLeafEncodingUri(string label, AdESPkiObjectEncoding expected)
    {
        string leafUri = label switch
        {
            "DER" => XAdESIdentifiers.DerEncodingUri,
            "BER" => XAdESIdentifiers.BerEncodingUri,
            "CER" => XAdESIdentifiers.CerEncodingUri,
            "PER" => XAdESIdentifiers.PerEncodingUri,
            "XER" => XAdESIdentifiers.XerEncodingUri,
            _ => throw new ArgumentOutOfRangeException(nameof(label), label, "Unknown test label.")
        };

        Assert.AreEqual(expected, AdESPkiObjectEncodingUris.FromUri(leafUri));
        Assert.AreEqual(leafUri, AdESPkiObjectEncodingUris.ToUri(expected));
    }


    /// <summary>
    /// Proves clause 5.1.3's absent-<c>Encoding</c>-means-DER default: <see cref="AdESPkiObjectEncodingUris.FromUri"/>
    /// resolves a <see langword="null"/> input to <see cref="AdESPkiObjectEncoding.Der"/>, the same value the
    /// explicit DER URI resolves to.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.3.
    /// </remarks>
    [TestMethod]
    public void FromUriResolvesAbsentEncodingToDer()
    {
        Assert.AreEqual(AdESPkiObjectEncoding.Der, AdESPkiObjectEncodingUris.FromUri(null));
    }


    /// <summary>
    /// An unrecognized, non-null <c>Encoding</c> value resolves to <see langword="null"/> — clause 5.1.3's five
    /// members are closed for CLASSIFICATION purposes even though the wire type itself (<c>tstr</c>/JSON
    /// string) is open, per <see cref="AdESPkiObjectEncodingUris"/>'s own remarks.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.3.
    /// </remarks>
    [TestMethod]
    public void FromUriReturnsNullForAnUnrecognizedEncoding()
    {
        Assert.IsNull(AdESPkiObjectEncodingUris.FromUri("urn:example:not-a-recognized-encoding"));
    }
}
