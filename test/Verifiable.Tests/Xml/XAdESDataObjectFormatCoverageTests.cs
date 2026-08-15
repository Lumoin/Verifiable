using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESDataObjectFormatCoverage"/> against clause 6.3 letter k) of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>.
/// </summary>
[TestClass]
internal sealed class XAdESDataObjectFormatCoverageTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string SignatureMethodAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private const string DigestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

    private const string SignedPropertiesTypeUri = "http://uri.etsi.org/01903#SignedProperties";

    private const string CountersignedSignatureTypeUri = "http://uri.etsi.org/01903#CountersignedSignature";


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


    private static string Reference(string id, string uri, string? type = null) =>
        $"""<ds:Reference Id="{id}" URI="{uri}"{(type is null ? "" : $""" Type="{type}" """)}><ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/><ds:DigestValue>AQ==</ds:DigestValue></ds:Reference>""";


    private static string DataObjectFormat(string objectReference) =>
        $"""<DataObjectFormat xmlns="{V132}" ObjectReference="{objectReference}"><MimeType>text/plain</MimeType></DataObjectFormat>""";


    /// <summary>
    /// A bare <c>ds:Signature</c> carrying only <c>ds:SignedInfo</c>/<c>ds:SignatureValue</c> — the
    /// <c>ds:Reference URI</c> values named in <paramref name="referencesXml"/> (<c>#spid</c>/<c>#data1</c>/
    /// <c>#data2</c>/<c>#sigvalue</c>) never need to dereference to anything real for this test's own checks,
    /// which never dereference a <c>ds:Reference</c>'s own <c>URI</c> — only its <c>Type</c> attribute and
    /// element identity matter here.
    /// </summary>
    private static string Document(string referencesXml) => $"""
        <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
          <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
            <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
            {referencesXml}
          </ds:SignedInfo>
          <ds:SignatureValue Id="sigvalue">AQ==</ds:SignatureValue>
        </ds:Signature>
        """;


    /// <summary>
    /// Reads each fragment into its OWN <see cref="XmlNodeTable"/> — valid because
    /// <see cref="XAdESDataObjectFormatCoverage.TryVerify"/> only ever consumes
    /// <see cref="XAdESDataObjectFormat.ObjectReference"/>'s plain octets against the CALLER-supplied signature
    /// table, never <see cref="XAdESDataObjectFormat"/>'s own originating table — mirroring how a real caller
    /// would read <c>DataObjectFormat</c> instances individually via <see cref="XAdESSignedDataObjectProperties"/>
    /// entries before verifying coverage. <see cref="XAdESDataObjectFormat.ObjectReference"/> reads its span
    /// straight from <paramref name="tables"/> on every access, so every fragment table the caller receives
    /// through <paramref name="tables"/> must outlive every use of the returned values, including the
    /// <see cref="XAdESDataObjectFormatCoverage.TryVerify"/> call itself — the caller disposes them afterward.
    /// </summary>
    private static List<XAdESDataObjectFormat> ReadDataObjectFormats(List<XmlNodeTable> tables, params string[] fragments)
    {
        var values = new List<XAdESDataObjectFormat>();
        foreach(string fragment in fragments)
        {
            bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(fragment), BaseMemoryPool.Shared, out XmlNodeTable? fragmentTable, out XmlReadError readError);
            Assert.IsTrue(isParsed, $"The DataObjectFormat fragment must parse but was refused with {readError.Failure}.");
            tables.Add(fragmentTable!);
            bool isRead = XAdESDataObjectFormat.TryRead(fragmentTable!, fragmentTable!.DocumentElementIndex, out XAdESDataObjectFormat value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"The DataObjectFormat fragment must read but was refused with {error.Failure}.");
            values.Add(value);
        }

        return values;
    }


    private static void DisposeAll(List<XmlNodeTable> tables)
    {
        foreach(XmlNodeTable table in tables)
        {
            table.Dispose();
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter k)'s XA-6.3-k1: one
    /// <c>DataObjectFormat</c> per non-<c>SignedProperties</c> reference is a complete, matching bijection.
    /// </summary>
    [TestMethod]
    public void OneDataObjectFormatPerSignedDataObjectSatisfiesTheBijection()
    {
        string references = Reference("ref-sp", "#spid", SignedPropertiesTypeUri) + Reference("ref1", "#data1") + Reference("ref2", "#data2");
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(Document(references));
        using(table)
        using(signature)
        {
            var fragmentTables = new List<XmlNodeTable>();
            try
            {
                List<XAdESDataObjectFormat> dataObjectFormats = ReadDataObjectFormats(fragmentTables, DataObjectFormat("#ref1"), DataObjectFormat("#ref2"));

                bool isVerified = XAdESDataObjectFormatCoverage.TryVerify(table, signature, dataObjectFormats, out XAdESProcessingError error);
                Assert.IsTrue(isVerified, $"Must verify but was refused with {error.Failure}.");
            }
            finally
            {
                DisposeAll(fragmentTables);
            }
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter k)'s XA-6.3-k1 "except the
    /// <c>SignedProperties</c> element": a <c>DataObjectFormat</c> whose <c>ObjectReference</c> targets the
    /// <c>SignedProperties</c> reference is refused rather than silently accepted.
    /// </summary>
    [TestMethod]
    public void DataObjectFormatTargetingSignedPropertiesIsRefused()
    {
        string references = Reference("ref-sp", "#spid", SignedPropertiesTypeUri) + Reference("ref1", "#data1");
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(Document(references));
        using(table)
        using(signature)
        {
            var fragmentTables = new List<XmlNodeTable>();
            try
            {
                List<XAdESDataObjectFormat> dataObjectFormats = ReadDataObjectFormats(fragmentTables, DataObjectFormat("#ref1"), DataObjectFormat("#ref-sp"));

                bool isVerified = XAdESDataObjectFormatCoverage.TryVerify(table, signature, dataObjectFormats, out XAdESProcessingError error);
                Assert.IsFalse(isVerified, "A DataObjectFormat targeting the SignedProperties reference must be refused.");
                Assert.AreEqual(XAdESProcessingFailure.DataObjectFormatCoverageExcludedTarget, error.Failure);
            }
            finally
            {
                DisposeAll(fragmentTables);
            }
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter k)'s XA-6.3-k1: a signed data
    /// object with no matching <c>DataObjectFormat</c> is refused.
    /// </summary>
    [TestMethod]
    public void MissingDataObjectFormatIsRefused()
    {
        string references = Reference("ref-sp", "#spid", SignedPropertiesTypeUri) + Reference("ref1", "#data1") + Reference("ref2", "#data2");
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(Document(references));
        using(table)
        using(signature)
        {
            var fragmentTables = new List<XmlNodeTable>();
            try
            {
                List<XAdESDataObjectFormat> dataObjectFormats = ReadDataObjectFormats(fragmentTables, DataObjectFormat("#ref1"));

                bool isVerified = XAdESDataObjectFormatCoverage.TryVerify(table, signature, dataObjectFormats, out XAdESProcessingError error);
                Assert.IsFalse(isVerified, "A signed data object with no DataObjectFormat must be refused.");
                Assert.AreEqual(XAdESProcessingFailure.DataObjectFormatCoverageMissing, error.Failure);
            }
            finally
            {
                DisposeAll(fragmentTables);
            }
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter k)'s XA-6.3-k1's one-to-one
    /// binding: two <c>DataObjectFormat</c> entries targeting the SAME reference are refused.
    /// </summary>
    [TestMethod]
    public void DuplicateDataObjectFormatForOneReferenceIsRefused()
    {
        string references = Reference("ref-sp", "#spid", SignedPropertiesTypeUri) + Reference("ref1", "#data1");
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(Document(references));
        using(table)
        using(signature)
        {
            var fragmentTables = new List<XmlNodeTable>();
            try
            {
                List<XAdESDataObjectFormat> dataObjectFormats = ReadDataObjectFormats(fragmentTables, DataObjectFormat("#ref1"), DataObjectFormat("#ref1"));

                bool isVerified = XAdESDataObjectFormatCoverage.TryVerify(table, signature, dataObjectFormats, out XAdESProcessingError error);
                Assert.IsFalse(isVerified, "Two DataObjectFormat entries targeting the same reference must be refused.");
                Assert.AreEqual(XAdESProcessingFailure.DataObjectFormatCoverageDuplicate, error.Failure);
            }
            finally
            {
                DisposeAll(fragmentTables);
            }
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter k)'s XA-6.3-k2: a baseline
    /// signature countersigning another signature (per clause 5.2.7.1's <c>CountersignedSignature</c> marker,
    /// <see cref="XAdESCountersignatureIdentification"/>) that signs only its own signed properties and the
    /// countersigned signature needs NO <c>DataObjectFormat</c> at all.
    /// </summary>
    [TestMethod]
    public void CountersigningOnlyItsOwnSignedPropertiesAndTheCountersignedSignatureNeedsNoDataObjectFormat()
    {
        string references = Reference("ref-sp", "#spid", SignedPropertiesTypeUri) + Reference("ref-cs", "#sigvalue", CountersignedSignatureTypeUri);
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(Document(references));
        using(table)
        using(signature)
        {
            Assert.IsTrue(XAdESCountersignatureIdentification.IsCountersignature(signature));

            bool isVerified = XAdESDataObjectFormatCoverage.TryVerify(table, signature, [], out XAdESProcessingError error);
            Assert.IsTrue(isVerified, $"Must verify but was refused with {error.Failure}.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter k)'s XA-6.3-k2: even while
    /// countersigning, a <c>DataObjectFormat</c> targeting the <c>CountersignedSignature</c>-marked reference
    /// itself is refused ("it shall not include any <c>DataObjectFormat</c> signed property").
    /// </summary>
    [TestMethod]
    public void DataObjectFormatTargetingTheCountersignedSignatureReferenceIsRefused()
    {
        string references = Reference("ref-sp", "#spid", SignedPropertiesTypeUri) + Reference("ref-cs", "#sigvalue", CountersignedSignatureTypeUri);
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(Document(references));
        using(table)
        using(signature)
        {
            var fragmentTables = new List<XmlNodeTable>();
            try
            {
                List<XAdESDataObjectFormat> dataObjectFormats = ReadDataObjectFormats(fragmentTables, DataObjectFormat("#ref-cs"));

                bool isVerified = XAdESDataObjectFormatCoverage.TryVerify(table, signature, dataObjectFormats, out XAdESProcessingError error);
                Assert.IsFalse(isVerified, "A DataObjectFormat targeting the CountersignedSignature reference must be refused.");
                Assert.AreEqual(XAdESProcessingFailure.DataObjectFormatCoverageExcludedTarget, error.Failure);
            }
            finally
            {
                DisposeAll(fragmentTables);
            }
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter k)'s XA-6.3-k3: a
    /// countersigning baseline signature that ALSO signs another data object shall include one
    /// <c>DataObjectFormat</c> for that OTHER object — the countersigned-signature reference itself still needs
    /// none.
    /// </summary>
    [TestMethod]
    public void CountersigningWithAnOtherDataObjectRequiresOneDataObjectFormatForIt()
    {
        string references = Reference("ref-sp", "#spid", SignedPropertiesTypeUri) + Reference("ref-cs", "#sigvalue", CountersignedSignatureTypeUri) + Reference("ref1", "#data1");
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(Document(references));
        using(table)
        using(signature)
        {
            var fragmentTables = new List<XmlNodeTable>();
            try
            {
                List<XAdESDataObjectFormat> dataObjectFormats = ReadDataObjectFormats(fragmentTables, DataObjectFormat("#ref1"));

                bool isVerified = XAdESDataObjectFormatCoverage.TryVerify(table, signature, dataObjectFormats, out XAdESProcessingError error);
                Assert.IsTrue(isVerified, $"Must verify but was refused with {error.Failure}.");
            }
            finally
            {
                DisposeAll(fragmentTables);
            }
        }
    }


    /// <summary>
    /// Proves the table-identity guard: a foreign table refuses rather than computing against the wrong document. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter k).
    /// </summary>
    [TestMethod]
    public void TableMismatchIsRefused()
    {
        string references = Reference("ref-sp", "#spid", SignedPropertiesTypeUri) + Reference("ref1", "#data1");
        string document = Document(references);
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document);
        (XmlNodeTable foreignTable, XmlSignature foreignSignature) = ReadSoleSignature(document);
        using(table)
        using(signature)
        using(foreignTable)
        using(foreignSignature)
        {
            bool isVerified = XAdESDataObjectFormatCoverage.TryVerify(foreignTable, signature, [], out XAdESProcessingError error);
            Assert.IsFalse(isVerified, "A foreign table must refuse rather than verifying against the wrong document.");
            Assert.AreEqual(XAdESProcessingFailure.TableMismatch, error.Failure);
        }
    }
}
