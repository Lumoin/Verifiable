using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESBaselineIncorporationRequirements"/> against clause 6.3's opening structural
/// requirements of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>.
/// </summary>
[TestClass]
internal sealed class XAdESBaselineIncorporationRequirementsTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string SignatureMethodAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private const string DigestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

    private const string SignedPropertiesTypeUri = "http://uri.etsi.org/01903#SignedProperties";


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


    private static string DocumentWithReferences(string qualifyingContent) => $"""
        <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
          <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
            <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
            <ds:Reference URI="#spid" Type="{SignedPropertiesTypeUri}">
              <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
              <ds:DigestValue>AQ==</ds:DigestValue>
            </ds:Reference>
          </ds:SignedInfo>
          <ds:SignatureValue>AQ==</ds:SignatureValue>
          <ds:Object>
            {qualifyingContent}
          </ds:Object>
        </ds:Signature>
        """;


    // --- XA-6.3-02: direct incorporation only ---

    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3's XA-6.3-02: a signature carrying only a
    /// direct-incorporation <c>QualifyingProperties</c>, per NOTE 1's own restatement ("no
    /// <c>QualifyingPropertiesReference</c> element is present"), satisfies the baseline direct-incorporation
    /// requirement.
    /// </summary>
    [TestMethod]
    public void DirectIncorporationAloneSatisfiesTheRequirement()
    {
        string document = DocumentWithReferences($"""
            <QualifyingProperties xmlns="{V132}" Target="#sig1">
              <SignedProperties Id="spid">
                <SignedSignatureProperties><SigningTime/></SignedSignatureProperties>
              </SignedProperties>
            </QualifyingProperties>
            """);
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document);
        using(table)
        using(signature)
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out XAdESQualifyingPropertiesDiscoveryResult result, out XAdESProcessingError error);
            Assert.IsTrue(isDiscovered, $"Discovery must complete but was refused with {error.Failure}.");

            Assert.IsTrue(XAdESBaselineIncorporationRequirements.IsDirectIncorporationOnly(result));
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3's XA-6.3-02: a signature carrying even one
    /// indirectly-incorporated <c>QualifyingPropertiesReference</c> — modeled at read, never itself a read refusal — fails the baseline direct-incorporation-only requirement.
    /// </summary>
    [TestMethod]
    public void IndirectIncorporationFailsTheRequirement()
    {
        string document = DocumentWithReferences($"""<QualifyingPropertiesReference xmlns="{V132}" URI="external.xml#qp"/>""");
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document);
        using(table)
        using(signature)
        {
            bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out XAdESQualifyingPropertiesDiscoveryResult result, out XAdESProcessingError error);
            Assert.IsTrue(isDiscovered, $"Discovery must complete but was refused with {error.Failure}.");
            Assert.HasCount(1, result.QualifyingPropertiesReferences);

            Assert.IsFalse(XAdESBaselineIncorporationRequirements.IsDirectIncorporationOnly(result));
        }
    }


    // --- XA-6.3-04: RFC 3161-only time-stamp containers ---

    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3's XA-6.3-04: a time-stamp container whose
    /// every entry is an <c>EncapsulatedTimeStamp</c> (RFC 3161 token) satisfies the requirement.
    /// </summary>
    [TestMethod]
    public void AllEncapsulatedTimeStampEntriesSatisfyTheRequirement()
    {
        string document = $"""
            <SignatureTimeStamp xmlns="{V132}">
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </SignatureTimeStamp>
            """;
        using XmlNodeTable table = Parse(document);
        bool isRead = XAdESSignatureTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSignatureTimeStamp? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(XAdESBaselineIncorporationRequirements.ContainsOnlyRfc3161TimeStamps(value!.TimeStamp.TimeStamps));
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3's XA-6.3-04: a time-stamp container
    /// carrying an <c>XMLTimeStamp</c> entry — carried unmodeled at read, never itself a read refusal — fails the RFC-3161-only requirement.
    /// </summary>
    [TestMethod]
    public void AnXmlTimeStampEntryFailsTheRequirement()
    {
        string document = $"""
            <SignatureTimeStamp xmlns="{V132}">
              <XMLTimeStamp><Foreign/></XMLTimeStamp>
            </SignatureTimeStamp>
            """;
        using XmlNodeTable table = Parse(document);
        bool isRead = XAdESSignatureTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSignatureTimeStamp? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.AreEqual(XAdESTimeStampEntryKind.XmlTimeStamp, value!.TimeStamp.TimeStamps[0].Kind);
            Assert.IsFalse(XAdESBaselineIncorporationRequirements.ContainsOnlyRfc3161TimeStamps(value.TimeStamp.TimeStamps));
        }
    }
}
