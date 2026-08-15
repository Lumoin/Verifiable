using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESKeyInfoValidationDataPlacement.HasCertificateRevocationListMember"/> against clause
/// 6.3 letter u) of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>, Table 2 row XA-6.3-t32.
/// </summary>
[TestClass]
internal sealed class XAdESKeyInfoValidationDataPlacementTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static string Document(string keyInfoContent) => $"""
        <Signature xmlns="{DsNamespace}">
          <SignedInfo>
            <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
            <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
            <Reference><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>AQ==</DigestValue></Reference>
          </SignedInfo>
          <SignatureValue>AQ==</SignatureValue>
          <KeyInfo>{keyInfoContent}</KeyInfo>
        </Signature>
        """;


    /// <summary>
    /// Proves letter u)'s SHOULD-NOT-observable half: a <c>ds:KeyInfo/X509Data/X509CRL</c> member is detected —
    /// "Certificate status values SHOULD NOT be included in <c>ds:KeyInfo</c> element."
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, row XA-6.3-t32, letter u.
    /// </summary>
    [TestMethod]
    public void CertificateRevocationListInKeyInfoIsDetected()
    {
        using XmlNodeTable table = Parse(Document("""<X509Data><X509CRL>AQ==</X509CRL></X509Data>"""));
        bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(signature)
        {
            Assert.IsTrue(XAdESKeyInfoValidationDataPlacement.HasCertificateRevocationListMember(signature!.KeyInfo));
        }
    }


    /// <summary>
    /// Proves the negative half: a <c>ds:KeyInfo/X509Data</c> carrying only an <c>X509Certificate</c> member (no
    /// <c>X509CRL</c>) is not flagged, and an absent <c>KeyInfo</c> is not flagged either.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, row XA-6.3-t32, letter u.
    /// </summary>
    [TestMethod]
    public void NoCertificateRevocationListMemberIsNotFlagged()
    {
        using XmlNodeTable table = Parse(Document("""<X509Data><X509Certificate>AQ==</X509Certificate></X509Data>"""));
        bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(signature)
        {
            Assert.IsFalse(XAdESKeyInfoValidationDataPlacement.HasCertificateRevocationListMember(signature!.KeyInfo));
        }

        Assert.IsFalse(XAdESKeyInfoValidationDataPlacement.HasCertificateRevocationListMember(null));
    }
}
