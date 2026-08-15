using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESCountersignatureIdentification"/> against clause 5.2.7.1's detached-
/// countersignature identification convention of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>.
/// </summary>
[TestClass]
internal sealed class XAdESCountersignatureIdentificationTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string SignatureMethodAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private const string DigestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

    private const string CountersignedSignatureType = "http://uri.etsi.org/01903#CountersignedSignature";


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


    private static string SignatureWithReferenceType(string? referenceType) => $"""
        <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
          <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
            <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
            <ds:Reference URI="#countersignedValue"{(referenceType is null ? string.Empty : $""" Type="{referenceType}" """)}>
              <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
              <ds:DigestValue>AQ==</ds:DigestValue>
            </ds:Reference>
          </ds:SignedInfo>
          <ds:SignatureValue Id="countersignedValue">AQ==</ds:SignatureValue>
        </ds:Signature>
        """;


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.1, a <c>ds:Reference</c> whose
    /// <c>Type</c> attribute equals <c>http://uri.etsi.org/01903#CountersignedSignature</c> is recognized as
    /// the countersignature marker, exact-character.
    /// </summary>
    [TestMethod]
    public void ReferenceWithMatchingTypeIsRecognized()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(SignatureWithReferenceType(CountersignedSignatureType));
        using(table)
        using(signature)
        {
            Assert.IsTrue(XAdESCountersignatureIdentification.IsCountersignatureReference(signature.SignedInfo.References[0]));
            Assert.IsTrue(XAdESCountersignatureIdentification.IsCountersignature(signature));
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.1, a <c>ds:Reference</c> with no
    /// <c>Type</c> attribute at all is not recognized — 5.2.7.1's marker is optional-to-use, not a generation
    /// obligation every countersignature must carry.
    /// </summary>
    [TestMethod]
    public void ReferenceWithNoTypeAttributeIsNotRecognized()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(SignatureWithReferenceType(referenceType: null));
        using(table)
        using(signature)
        {
            Assert.IsFalse(XAdESCountersignatureIdentification.IsCountersignatureReference(signature.SignedInfo.References[0]));
            Assert.IsFalse(XAdESCountersignatureIdentification.IsCountersignature(signature));
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.1, a <c>ds:Reference</c> carrying
    /// a DIFFERENT <c>Type</c> value — here, the unrelated <c>SignedProperties</c> type URI — is not recognized;
    /// comparison is exact-character, not merely "some Type is present."
    /// </summary>
    [TestMethod]
    public void ReferenceWithDifferentTypeIsNotRecognized()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(SignatureWithReferenceType(XAdESIdentifiers.SignedPropertiesTypeUri));
        using(table)
        using(signature)
        {
            Assert.IsFalse(XAdESCountersignatureIdentification.IsCountersignatureReference(signature.SignedInfo.References[0]));
            Assert.IsFalse(XAdESCountersignatureIdentification.IsCountersignature(signature));
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.1, when a signature carries
    /// several <c>ds:Reference</c> elements, <see cref="XAdESCountersignatureIdentification.IsCountersignature"/>
    /// finds the marker among them regardless of position.
    /// </summary>
    [TestMethod]
    public void IsCountersignatureFindsTheMarkerAmongMultipleReferences()
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                <ds:Reference URI="#data1">
                  <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </ds:Reference>
                <ds:Reference URI="#countersignedValue" Type="{CountersignedSignatureType}">
                  <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue Id="countersignedValue">AQ==</ds:SignatureValue>
              <ds:Object Id="data1">payload</ds:Object>
            </ds:Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadSoleSignature(document);
        using(table)
        using(signature)
        {
            Assert.IsFalse(XAdESCountersignatureIdentification.IsCountersignatureReference(signature.SignedInfo.References[0]));
            Assert.IsTrue(XAdESCountersignatureIdentification.IsCountersignatureReference(signature.SignedInfo.References[1]));
            Assert.IsTrue(XAdESCountersignatureIdentification.IsCountersignature(signature));
        }
    }
}
