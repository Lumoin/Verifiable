using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESDataObjectFormat.TryRead"/> and <see cref="XAdESDataObjectFormat.TryVerifyConsistency"/>
/// against clause 5.2.4's <c>DataObjectFormat</c> qualifying property of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>.
/// </summary>
[TestClass]
internal sealed class XAdESDataObjectFormatTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string SignatureMethodAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private const string DigestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";


    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static (XmlNodeTable Table, XmlSignature Signature) ReadSoleSignature(string document)
    {
        XmlNodeTable table = Parse(document);
        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table);
        Assert.HasCount(1, signatureIndices, "The fixture must carry exactly one ds:Signature.");
        bool isRead = XmlSignature.TryRead(table, signatureIndices[0], BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError signatureError);
        Assert.IsTrue(isRead, $"The signature must read but was refused with {signatureError.Failure}.");

        return (table, signature!);
    }


    // --- TryRead: clause 5.2.4's own shape ---

    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.4, the minimal shape: the
    /// mandatory <c>ObjectReference</c> attribute plus a single <c>Description</c> child (one of the three
    /// descriptive children the cross-child floor requires) reads.
    /// </summary>
    [TestMethod]
    public void MinimalShapeWithDescriptionReads()
    {
        using XmlNodeTable table = Parse($"""<DataObjectFormat xmlns="{V132}" ObjectReference="#ref1"><Description>A plain text document</Description></DataObjectFormat>""");
        bool isRead = XAdESDataObjectFormat.TryRead(table, table.DocumentElementIndex, out XAdESDataObjectFormat value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.AreEqual("#ref1", Encoding.UTF8.GetString(value.ObjectReference));
        Assert.IsTrue(value.HasDescription);
        Assert.AreEqual("A plain text document", Encoding.UTF8.GetString(value.Description));
        Assert.IsFalse(value.HasObjectIdentifier);
        Assert.IsFalse(value.HasMimeType);
        Assert.IsFalse(value.HasEncoding);
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.4's acquired v132
    /// <c>DataObjectFormatType</c> schema, all four optional children, in their fixed schema order, read
    /// together.
    /// </summary>
    [TestMethod]
    public void AllFourChildrenInFixedOrderRead()
    {
        using XmlNodeTable table = Parse($"""
            <DataObjectFormat xmlns="{V132}" ObjectReference="#ref1">
              <Description>A plain text document</Description>
              <ObjectIdentifier><Identifier>http://example.com/format/1</Identifier></ObjectIdentifier>
              <MimeType>text/plain</MimeType>
              <Encoding>http://uri.etsi.org/01903/v1.2.2#DER</Encoding>
            </DataObjectFormat>
            """);
        bool isRead = XAdESDataObjectFormat.TryRead(table, table.DocumentElementIndex, out XAdESDataObjectFormat value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasDescription);
        Assert.IsTrue(value.HasObjectIdentifier);
        Assert.AreEqual("http://example.com/format/1", Encoding.UTF8.GetString(value.ObjectIdentifier.Identifier));
        Assert.IsTrue(value.HasMimeType);
        Assert.AreEqual("text/plain", Encoding.UTF8.GetString(value.MimeType));
        Assert.IsTrue(value.HasEncoding);
        Assert.AreEqual("http://uri.etsi.org/01903/v1.2.2#DER", Encoding.UTF8.GetString(value.Encoding));
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.4's cross-child floor: "this
    /// qualifying property shall contain at least one of the following elements: Description, ObjectIdentifier
    /// and MimeType" — an instance carrying only <c>Encoding</c> (which the floor explicitly excludes) is
    /// refused, even though the schema's own individually-optional <c>minOccurs="0"</c> children would
    /// otherwise permit it.
    /// </summary>
    [TestMethod]
    public void EncodingAloneWithNoDescriptiveChildIsRefused()
    {
        using XmlNodeTable table = Parse($"""<DataObjectFormat xmlns="{V132}" ObjectReference="#ref1"><Encoding>http://uri.etsi.org/01903/v1.2.2#DER</Encoding></DataObjectFormat>""");
        bool isRead = XAdESDataObjectFormat.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "Encoding alone, with none of Description/ObjectIdentifier/MimeType, must be refused.");
        Assert.AreEqual(XAdESReadFailure.DataObjectFormatMissingDescriptiveChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.4's cross-child floor, an
    /// entirely empty <c>DataObjectFormat</c> (no children at all) is refused.
    /// </summary>
    [TestMethod]
    public void NoChildrenAtAllIsRefused()
    {
        using XmlNodeTable table = Parse($"""<DataObjectFormat xmlns="{V132}" ObjectReference="#ref1"/>""");
        bool isRead = XAdESDataObjectFormat.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An entirely empty DataObjectFormat must be refused.");
        Assert.AreEqual(XAdESReadFailure.DataObjectFormatMissingDescriptiveChild, error.Failure);
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.4's acquired v132 XSD,
    /// the mandatory <c>ObjectReference</c> attribute's absence is refused — the schema declares it
    /// <c>use="required"</c>.
    /// </summary>
    [TestMethod]
    public void MissingObjectReferenceAttributeIsRefused()
    {
        using XmlNodeTable table = Parse($"""<DataObjectFormat xmlns="{V132}"><Description>text</Description></DataObjectFormat>""");
        bool isRead = XAdESDataObjectFormat.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A missing ObjectReference attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredAttribute, error.Failure);
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.4's fixed
    /// <c>Description, ObjectIdentifier, MimeType, Encoding</c> sequence, a child out of order — here,
    /// <c>MimeType</c> before <c>Description</c> — is refused.
    /// </summary>
    [TestMethod]
    public void OutOfOrderChildIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <DataObjectFormat xmlns="{V132}" ObjectReference="#ref1">
              <MimeType>text/plain</MimeType>
              <Description>A plain text document</Description>
            </DataObjectFormat>
            """);
        bool isRead = XAdESDataObjectFormat.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An out-of-order child must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.4's fixed at-most-once
    /// sequence, a repeated child — two <c>Description</c> elements — is refused as a duplicate, distinct from
    /// a generic unknown-element refusal.
    /// </summary>
    [TestMethod]
    public void DuplicateChildIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <DataObjectFormat xmlns="{V132}" ObjectReference="#ref1">
              <Description>first</Description>
              <Description>second</Description>
            </DataObjectFormat>
            """);
        bool isRead = XAdESDataObjectFormat.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A duplicate child must be refused.");
        Assert.AreEqual(XAdESReadFailure.DuplicateCoreChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.4, an unrecognized attribute
    /// beyond <c>ObjectReference</c> is refused fail-closed.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeIsRefused()
    {
        using XmlNodeTable table = Parse($"""<DataObjectFormat xmlns="{V132}" ObjectReference="#ref1" unexpected="value"><Description>text</Description></DataObjectFormat>""");
        bool isRead = XAdESDataObjectFormat.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }


    // --- TryVerifyConsistency: clause 5.2.4's cross-artifact rule ---

    private static string SignatureWithDataObjectFormat(string objectAttributes, string dataObjectFormatBody) => $"""
        <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
          <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
            <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
            <ds:Reference Id="ref1" URI="#data1">
              <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
              <ds:DigestValue>AQ==</ds:DigestValue>
            </ds:Reference>
            <ds:Reference Id="ref2" URI="http://example.com/external.bin">
              <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
              <ds:DigestValue>AQ==</ds:DigestValue>
            </ds:Reference>
          </ds:SignedInfo>
          <ds:SignatureValue>AQ==</ds:SignatureValue>
          <ds:Object Id="data1"{objectAttributes}>payload</ds:Object>
          <ds:Object>
            <DataObjectFormat xmlns="{V132}" ObjectReference="#ref1">
              {dataObjectFormatBody}
            </DataObjectFormat>
          </ds:Object>
        </ds:Signature>
        """;


    private static XAdESDataObjectFormat ReadDataObjectFormat(XmlNodeTable table)
    {
        int documentElement = table.DocumentElementIndex;
        int lastObject = -1;
        for(int child = table.FirstChildOf(documentElement); child >= 0; child = table.NextSiblingOf(child))
        {
            if(table.KindOf(child) == XmlNodeKind.Element && XmlSignatureModelGrammar.IsDsElement(table, child, "Object"u8))
            {
                lastObject = child;
            }
        }

        Assert.IsGreaterThanOrEqualTo(0, lastObject, "The fixture must carry at least one ds:Object.");
        int formatElement = -1;
        for(int child = table.FirstChildOf(lastObject); child >= 0; child = table.NextSiblingOf(child))
        {
            if(table.KindOf(child) == XmlNodeKind.Element)
            {
                formatElement = child;
            }
        }

        Assert.IsGreaterThanOrEqualTo(0, formatElement, "The fixture's last ds:Object must carry a DataObjectFormat child.");
        bool isRead = XAdESDataObjectFormat.TryRead(table, formatElement, out XAdESDataObjectFormat value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"The fixture's DataObjectFormat must read but was refused with {error.Failure}.");

        return value;
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.4, the consistency rule
    /// succeeds when the referenced <c>ds:Object</c>'s <c>MimeType</c> and <c>Encoding</c> attributes exactly
    /// match <c>DataObjectFormat</c>'s own children.
    /// </summary>
    [TestMethod]
    public void MatchingMimeTypeAndEncodingVerifies()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(
            SignatureWithDataObjectFormat(
                """ MimeType="text/plain" Encoding="http://uri.etsi.org/01903/v1.2.2#DER" """,
                """<MimeType>text/plain</MimeType><Encoding>http://uri.etsi.org/01903/v1.2.2#DER</Encoding>"""));
        using(table)
        using(signature)
        {
            XAdESDataObjectFormat dataObjectFormat = ReadDataObjectFormat(table);
            bool isVerified = XAdESDataObjectFormat.TryVerifyConsistency(table, signature, dataObjectFormat, out XAdESProcessingError error);
            Assert.IsTrue(isVerified, $"Matching MimeType/Encoding must verify but was refused with {error.Failure}.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.4, the consistency rule
    /// refuses when <c>DataObjectFormat</c>'s <c>MimeType</c> differs from the referenced <c>ds:Object</c>'s
    /// own <c>MimeType</c> attribute.
    /// </summary>
    [TestMethod]
    public void MismatchedMimeTypeIsRefused()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(
            SignatureWithDataObjectFormat(""" MimeType="application/pdf" """, """<MimeType>text/plain</MimeType>"""));
        using(table)
        using(signature)
        {
            XAdESDataObjectFormat dataObjectFormat = ReadDataObjectFormat(table);
            bool isVerified = XAdESDataObjectFormat.TryVerifyConsistency(table, signature, dataObjectFormat, out XAdESProcessingError error);
            Assert.IsFalse(isVerified, "A mismatched MimeType must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.DataObjectFormatMimeTypeMismatch, error.Failure);
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.4, the consistency rule
    /// refuses when <c>DataObjectFormat</c>'s <c>Encoding</c> differs from the referenced <c>ds:Object</c>'s
    /// own <c>Encoding</c> attribute.
    /// </summary>
    [TestMethod]
    public void MismatchedEncodingIsRefused()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(
            SignatureWithDataObjectFormat(
                """ Encoding="http://uri.etsi.org/01903/v1.2.2#BER" """,
                """<Description>text</Description><Encoding>http://uri.etsi.org/01903/v1.2.2#DER</Encoding>"""));
        using(table)
        using(signature)
        {
            XAdESDataObjectFormat dataObjectFormat = ReadDataObjectFormat(table);
            bool isVerified = XAdESDataObjectFormat.TryVerifyConsistency(table, signature, dataObjectFormat, out XAdESProcessingError error);
            Assert.IsFalse(isVerified, "A mismatched Encoding must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.DataObjectFormatEncodingMismatch, error.Failure);
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.4, the consistency rule does
    /// not apply — and so trivially succeeds — when the referenced <c>ds:Object</c> carries neither
    /// <c>MimeType</c> nor <c>Encoding</c> attributes: "if this <c>ds:Object</c> element has the
    /// <c>MimeType</c> or (and) the <c>Encoding</c> attribute(s)" is a conditional the rule's obligation
    /// depends on.
    /// </summary>
    [TestMethod]
    public void ReferencedObjectWithNeitherAttributeHasNothingToVerify()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(
            SignatureWithDataObjectFormat(string.Empty, """<MimeType>text/plain</MimeType>"""));
        using(table)
        using(signature)
        {
            XAdESDataObjectFormat dataObjectFormat = ReadDataObjectFormat(table);
            bool isVerified = XAdESDataObjectFormat.TryVerifyConsistency(table, signature, dataObjectFormat, out XAdESProcessingError error);
            Assert.IsTrue(isVerified, $"No applicable attributes must trivially verify but was refused with {error.Failure}.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.4, the consistency rule does
    /// not apply when the resolved <c>ds:Reference</c>'s own <c>URI</c> targets an external, non-same-document
    /// location rather than a <c>ds:Object</c> — NOTE 8's scope is a <c>ds:Object</c> "within the XAdES
    /// signature."
    /// </summary>
    [TestMethod]
    public void ObjectReferenceToExternalDataHasNothingToVerify()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature($"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                <ds:Reference Id="ref1" URI="http://example.com/external.bin">
                  <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue>AQ==</ds:SignatureValue>
              <ds:Object>
                <DataObjectFormat xmlns="{V132}" ObjectReference="#ref1"><MimeType>application/octet-stream</MimeType></DataObjectFormat>
              </ds:Object>
            </ds:Signature>
            """);
        using(table)
        using(signature)
        {
            XAdESDataObjectFormat dataObjectFormat = ReadDataObjectFormat(table);
            bool isVerified = XAdESDataObjectFormat.TryVerifyConsistency(table, signature, dataObjectFormat, out XAdESProcessingError error);
            Assert.IsTrue(isVerified, $"An externally-targeted reference must trivially verify but was refused with {error.Failure}.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.4, the <c>ObjectReference</c>
    /// resolution failures — see <see cref="XAdESObjectReferenceResolution.TryResolve"/> — surface unchanged
    /// through <see cref="XAdESDataObjectFormat.TryVerifyConsistency"/>: an <c>ObjectReference</c> naming no
    /// <c>Id</c> in the document is refused.
    /// </summary>
    [TestMethod]
    public void UnresolvableObjectReferenceIsRefused()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(
            SignatureWithDataObjectFormat(string.Empty, """<MimeType>text/plain</MimeType>"""));
        using(table)
        using(signature)
        {
            XAdESDataObjectFormat dataObjectFormat = ReadDataObjectFormat(table);

            // Re-read with a deliberately dangling ObjectReference by constructing a second fixture.
            (XmlNodeTable danglingTable, XmlSignature danglingSignature) = ReadSoleSignature(
                SignatureWithDataObjectFormat(string.Empty, """<MimeType>text/plain</MimeType>""").Replace("#ref1", "#doesNotExist", StringComparison.Ordinal));
            using(danglingTable)
            using(danglingSignature)
            {
                XAdESDataObjectFormat danglingFormat = ReadDataObjectFormat(danglingTable);
                bool isVerified = XAdESDataObjectFormat.TryVerifyConsistency(danglingTable, danglingSignature, danglingFormat, out XAdESProcessingError error);
                Assert.IsFalse(isVerified, "A dangling ObjectReference must be refused.");
                Assert.AreEqual(XAdESProcessingFailure.ObjectReferenceTargetIdNotFound, error.Failure);
            }

            // The first fixture (a valid ObjectReference) is unaffected and still verifies, proving the two
            // documents/tables were not accidentally cross-wired above.
            bool isFirstVerified = XAdESDataObjectFormat.TryVerifyConsistency(table, signature, dataObjectFormat, out XAdESProcessingError firstError);
            Assert.IsTrue(isFirstVerified, $"Must verify but was refused with {firstError.Failure}.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.4, the
    /// <see cref="XAdESProcessingFailure.TableMismatch"/> guard on <see cref="XAdESDataObjectFormat.TryVerifyConsistency"/> — the anti-wrapping discipline: a table
    /// argument that is not the identical instance both the signature and the property were read from refuses rather than being processed.
    /// </summary>
    [TestMethod]
    public void TryVerifyConsistencyRefusesWhenTableIsMismatched()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(
            SignatureWithDataObjectFormat(string.Empty, """<MimeType>text/plain</MimeType>"""));
        using(table)
        using(signature)
        using(XmlNodeTable otherTable = Parse("""<root/>"""))
        {
            XAdESDataObjectFormat dataObjectFormat = ReadDataObjectFormat(table);
            bool isVerified = XAdESDataObjectFormat.TryVerifyConsistency(otherTable, signature, dataObjectFormat, out XAdESProcessingError error);
            Assert.IsFalse(isVerified, "A mismatched table must be refused.");
            Assert.AreEqual(XAdESProcessingFailure.TableMismatch, error.Failure);
        }
    }
}
