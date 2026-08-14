using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs anchoring clause 6.3 letters f) and g) of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see> to the shipped <c>ds:Reference/ds:Transforms</c> transform-chain dispatch
/// (<see cref="XmlReferenceProcessing"/>), driven here through the XAdES-level <see
/// cref="XAdESAllDataObjectsTimeStampImprint"/> entry point: no new production code, since every disposition
/// below is already the shipped surface's own recorded posture, including the XPath-family deferral.
/// </summary>
[TestClass]
internal sealed class XAdESReferenceTransformDispositionTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string ExclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

    private const string SignedPropertiesType = "http://uri.etsi.org/01903#SignedProperties";

    private const string XsltTransformUri = "http://www.w3.org/TR/1999/REC-xslt-19991116";

    private const string RelationshipTransformUri = "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";

    private const string XPathTransformUri = "http://www.w3.org/TR/1999/REC-xpath-19991116";

    private const string XPathFilter2TransformUri = "http://www.w3.org/2002/06/xmldsig-filter2";

    private static string Base64TransformUri => XmlSignatureIdentifiers.Base64TransformUri;

    private static string EnvelopedSignatureTransformUri => XmlSignatureIdentifiers.EnvelopedSignatureTransformUri;


    private static string Document(string transformAlgorithmUri) => $$"""
        <root xmlns:ds="{{DsNamespace}}">
          <ds:Signature Id="sig1">
            <ds:SignedInfo>
              <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
              <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
              <ds:Reference Id="ref1" URI="#data1">
                <ds:Transforms><ds:Transform Algorithm="{{transformAlgorithmUri}}"/></ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>QQ==</ds:DigestValue>
              </ds:Reference>
              <ds:Reference Id="ref-sp" URI="#sp1" Type="{{SignedPropertiesType}}">
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>QQ==</ds:DigestValue>
              </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>QQ==</ds:SignatureValue>
            <ds:Object>
              <Data Id="data1">payload</Data>
              <SignedProperties Id="sp1">ignored</SignedProperties>
            </ds:Object>
          </ds:Signature>
          <AllDataObjectsTimeStamp xmlns="{{XAdESIdentifiers.XAdESNamespaceV132}}" xmlns:ds="{{DsNamespace}}" Id="adots1">
            <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
            <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
          </AllDataObjectsTimeStamp>
        </root>
        """;


    private static (XmlNodeTable Table, XmlSignature Signature, XAdESAllDataObjectsTimeStamp Stamp) ReadFixture(string transformAlgorithmUri, BaseMemoryPool pool)
    {
        string document = Document(transformAlgorithmUri);
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
        Assert.HasCount(1, signatureIndices);
        bool isSignatureRead = XmlSignature.TryRead(table!, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError signatureError);
        Assert.IsTrue(isSignatureRead, $"The fixture Signature must read but was refused with {signatureError.Failure}.");

        bool isFound = table!.TryFindElementById("adots1"u8, out int stampIndex, out _);
        Assert.IsTrue(isFound, "The fixture AllDataObjectsTimeStamp must resolve by Id.");
        bool isStampRead = XAdESAllDataObjectsTimeStamp.TryRead(table, stampIndex, pool, out XAdESAllDataObjectsTimeStamp? stamp, out XAdESReadError stampError);
        Assert.IsTrue(isStampRead, $"The fixture AllDataObjectsTimeStamp must read but was refused with {stampError.Failure}.");

        return (table, signature!, stamp!);
    }


    private static void AssertReferenceProcessingRefusal(string transformAlgorithmUri, XmlSignatureProcessingFailure expectedInnerFailure)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESAllDataObjectsTimeStamp stamp) = ReadFixture(transformAlgorithmUri, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            bool isComputed = XAdESAllDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature, stamp, resolver: null, pool, out _, out XAdESProcessingError error);
            Assert.IsFalse(isComputed, $"A '{transformAlgorithmUri}' transform must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.MessageImprintReferenceProcessingFailed, error.Failure);
            Assert.IsNotNull(error.InnerProcessingError);
            Assert.AreEqual(expectedInnerFailure, error.InnerProcessingError!.Value.Failure);
        }
    }


    // --- Letter g): the six transform-URI dispositions ---

    /// <summary>
    /// Proves letter g)'s XSLT disposition: "the corresponding XSLT transform ... shall be
    /// supported" is recognized-but-refused, not silently accepted, per this library's own grounds
    /// (untrusted stylesheet execution).
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter g).
    /// </summary>
    [TestMethod]
    public void LetterGsXsltTransformIsRefusedPerDV21()
    {
        AssertReferenceProcessingRefusal(XsltTransformUri, XmlSignatureProcessingFailure.TransformRefused);
    }


    /// <summary>
    /// Proves letter g)'s OOXML Relationships-transform disposition: recognized but
    /// refused, the same posture as the XSLT transform.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter g).
    /// </summary>
    [TestMethod]
    public void LetterGsRelationshipTransformIsRefusedPerDV22()
    {
        AssertReferenceProcessingRefusal(RelationshipTransformUri, XmlSignatureProcessingFailure.TransformRefused);
    }


    /// <summary>
    /// Proves letter g)'s XPath transform disposition: recognized but STAGED — the XPath 1.0 evaluator deferral this leg's own contract leaves untouched, distinct from
    /// the XSLT/OOXML-transform outright refusal. Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1
    /// V1.3.1</see> clause 6.3 letter g).
    /// </summary>
    [TestMethod]
    public void LetterGsXPathTransformIsStagedNotRefused()
    {
        AssertReferenceProcessingRefusal(XPathTransformUri, XmlSignatureProcessingFailure.TransformNotYetSupported);
    }


    /// <summary>
    /// Proves letter g)'s XML-Signature XPath Filter 2.0 disposition — the SAME staged deferral as the plain
    /// XPath transform, both named by letter g) itself.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter g).
    /// </summary>
    [TestMethod]
    public void LetterGsXPathFilter2TransformIsStagedNotRefused()
    {
        AssertReferenceProcessingRefusal(XPathFilter2TransformUri, XmlSignatureProcessingFailure.TransformNotYetSupported);
    }


    /// <summary>
    /// Proves letter g)'s base64 (g1) disposition: the shipped base64-decoding transform is applied, not refused as unsupported or merely staged — the referenced content
    /// (<c>QQ==</c>, valid base64) decodes and the imprint computation succeeds. No new production code: this exercises the SAME <see cref="XmlReferenceProcessing"/> dispatch <see
    /// cref="XmlReferenceProcessingTests"/> already proves generically, anchored here at the XAdES layer for the clause 6.3 letter-g) requirement. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter g).
    /// </summary>
    [TestMethod]
    public void LetterGsBase64TransformIsAppliedNotRefused()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        string document = Document(Base64TransformUri).Replace(">payload<", ">QQ==<", StringComparison.Ordinal);
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");
        using(table)
        {
            int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
            Assert.HasCount(1, signatureIndices);
            bool isSignatureRead = XmlSignature.TryRead(table!, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError signatureError);
            Assert.IsTrue(isSignatureRead, $"The fixture Signature must read but was refused with {signatureError.Failure}.");
            using(signature)
            {
                bool isFound = table!.TryFindElementById("adots1"u8, out int stampIndex, out _);
                Assert.IsTrue(isFound, "The fixture AllDataObjectsTimeStamp must resolve by Id.");
                bool isStampRead = XAdESAllDataObjectsTimeStamp.TryRead(table, stampIndex, pool, out XAdESAllDataObjectsTimeStamp? stamp, out XAdESReadError stampError);
                Assert.IsTrue(isStampRead, $"The fixture AllDataObjectsTimeStamp must read but was refused with {stampError.Failure}.");
                using(stamp)
                {
                    bool isComputed = XAdESAllDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature!, stamp!, resolver: null, pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
                    Assert.IsTrue(isComputed, $"The base64 transform must be applied, but was refused with {error.Failure}.");
                    imprintInput!.Dispose();
                }
            }
        }
    }


    /// <summary>
    /// Proves letter g)'s enveloped-signature (g3) disposition: the shipped enveloped-signature transform (section 6.6.4 of XMLDSIG) is applied over a same-document,
    /// whole-document reference (<c>URI=""</c>) — not refused as unsupported or merely staged. No new production code: this exercises the SAME <see cref="XmlReferenceProcessing"/>
    /// dispatch <see cref="XmlReferenceProcessingTests"/> already proves generically, anchored here at the XAdES layer for the clause 6.3 letter-g) requirement. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter g).
    /// </summary>
    [TestMethod]
    public void LetterGsEnvelopedSignatureTransformIsAppliedNotRefused()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        string document = $$"""
            <root xmlns:ds="{{DsNamespace}}">
              <ds:Signature Id="sig1">
                <ds:SignedInfo>
                  <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
                  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                  <ds:Reference Id="ref1" URI="">
                    <ds:Transforms><ds:Transform Algorithm="{{EnvelopedSignatureTransformUri}}"/></ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>QQ==</ds:DigestValue>
                  </ds:Reference>
                  <ds:Reference Id="ref-sp" URI="#sp1" Type="{{SignedPropertiesType}}">
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>QQ==</ds:DigestValue>
                  </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>QQ==</ds:SignatureValue>
                <ds:Object>
                  <SignedProperties Id="sp1">ignored</SignedProperties>
                </ds:Object>
              </ds:Signature>
              <AllDataObjectsTimeStamp xmlns="{{XAdESIdentifiers.XAdESNamespaceV132}}" xmlns:ds="{{DsNamespace}}" Id="adots1">
                <ds:CanonicalizationMethod Algorithm="{{ExclusiveC14N}}"/>
                <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
              </AllDataObjectsTimeStamp>
            </root>
            """;
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");
        using(table)
        {
            int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
            Assert.HasCount(1, signatureIndices);
            bool isSignatureRead = XmlSignature.TryRead(table!, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError signatureError);
            Assert.IsTrue(isSignatureRead, $"The fixture Signature must read but was refused with {signatureError.Failure}.");
            using(signature)
            {
                bool isFound = table!.TryFindElementById("adots1"u8, out int stampIndex, out _);
                Assert.IsTrue(isFound, "The fixture AllDataObjectsTimeStamp must resolve by Id.");
                bool isStampRead = XAdESAllDataObjectsTimeStamp.TryRead(table, stampIndex, pool, out XAdESAllDataObjectsTimeStamp? stamp, out XAdESReadError stampError);
                Assert.IsTrue(isStampRead, $"The fixture AllDataObjectsTimeStamp must read but was refused with {stampError.Failure}.");
                using(stamp)
                {
                    bool isComputed = XAdESAllDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature!, stamp!, resolver: null, pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
                    Assert.IsTrue(isComputed, $"The enveloped-signature transform must be applied, but was refused with {error.Failure}.");
                    imprintInput!.Dispose();
                }
            }
        }
    }


    // --- Letter f): a canonicalizing transform inside ds:Reference/ds:Transforms uses letter d)'s own list ---

    /// <summary>
    /// Proves letter f): "If the transform indicated by a <c>ds:Reference</c>/<c>ds:Transforms</c>'s
    /// <c>ds:Transform</c> child element is a canonicalization, its <c>Algorithm</c> attribute shall have one
    /// of the values listed in ... additional requirement d)" — a <c>ds:Transform</c> naming one of letter d)'s
    /// six URIs is recognized and applied as a canonicalizing transform (never <c>UnsupportedTransform</c>),
    /// the SAME dispatch <see cref="XmlReferenceProcessing.TryComputeSignedInfoOctets"/> and
    /// <see cref="XAdESCanonicalizationManagementTests.LetterDsSixUriEnumerationResolves"/> both exercise for
    /// <c>ds:CanonicalizationMethod</c> — letter f) reuses letter d)'s list by construction, not by a second,
    /// independently-maintained enumeration.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter f).
    /// </summary>
    [TestMethod]
    public void LetterFsCanonicalizingTransformUsesLetterDsUriSet()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (XmlNodeTable table, XmlSignature signature, XAdESAllDataObjectsTimeStamp stamp) = ReadFixture(ExclusiveC14N, pool);
        using(table)
        using(signature)
        using(stamp)
        {
            bool isComputed = XAdESAllDataObjectsTimeStampImprint.TryComputeImprintInput(table, signature, stamp, resolver: null, pool, out PooledMemory? imprintInput, out XAdESProcessingError error);
            Assert.IsTrue(isComputed, $"A ds:Transform naming letter d)'s own Exclusive-c14n URI must be applied, but was refused with {error.Failure}.");
            imprintInput!.Dispose();
        }
    }


    /// <summary>
    /// Proves the negative half of letter f): a <c>ds:Transform</c> algorithm outside BOTH letter d)'s
    /// canonicalization list and letter g)'s non-canonicalization list is genuinely unrecognized, not silently
    /// treated as a canonicalization.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter f).
    /// </summary>
    [TestMethod]
    public void AnUnlistedTransformAlgorithmIsUnrecognized()
    {
        AssertReferenceProcessingRefusal("http://example.test/not-a-real-transform", XmlSignatureProcessingFailure.UnsupportedTransform);
    }
}
