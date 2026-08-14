using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESSignaturePolicyStoreLegality"/> against clause 6.3 letter m) of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>.
/// </summary>
[TestClass]
internal sealed class XAdESSignaturePolicyStoreLegalityTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";


    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter m)'s XA-6.3-m1: a
    /// <c>SignaturePolicyIdentifier</c> carrying the explicit <c>SignaturePolicyId</c> arm — which
    /// <see cref="XAdESSignaturePolicyId.TryRead"/> only ever reads with its mandatory <c>SigPolicyHash</c>
    /// present — makes <c>SignaturePolicyStore</c> legal.
    /// </summary>
    [TestMethod]
    public void SignaturePolicyIdArmMakesTheStoreLegal()
    {
        string document = $"""
            <SignaturePolicyIdentifier xmlns="{V132}" xmlns:ds="{DsNamespace}">
              <SignaturePolicyId>
                <SigPolicyId><Identifier>urn:oid:1.2.3.4</Identifier></SigPolicyId>
                <SigPolicyHash>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </SigPolicyHash>
              </SignaturePolicyId>
            </SignaturePolicyIdentifier>
            """;
        using XmlNodeTable table = Parse(document);
        bool isRead = XAdESSignaturePolicyIdentifier.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSignaturePolicyIdentifier? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(XAdESSignaturePolicyStoreLegality.IsSignaturePolicyStoreLegal(value));
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter m)'s XA-6.3-m2 (the
    /// "[o]therwise... shall not be incorporated" converse): a <c>SignaturePolicyIdentifier</c> carrying the
    /// empty <c>SignaturePolicyImplied</c> arm — which structurally never carries a <c>SigPolicyHash</c> —
    /// makes <c>SignaturePolicyStore</c> illegal.
    /// </summary>
    [TestMethod]
    public void SignaturePolicyImpliedArmMakesTheStoreIllegal()
    {
        string document = $"""<SignaturePolicyIdentifier xmlns="{V132}"><SignaturePolicyImplied/></SignaturePolicyIdentifier>""";
        using XmlNodeTable table = Parse(document);
        bool isRead = XAdESSignaturePolicyIdentifier.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSignaturePolicyIdentifier? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsFalse(XAdESSignaturePolicyStoreLegality.IsSignaturePolicyStoreLegal(value));
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter m)'s XA-6.3-m2: a
    /// signature carrying no <c>SignaturePolicyIdentifier</c> at all makes <c>SignaturePolicyStore</c> illegal.
    /// </summary>
    [TestMethod]
    public void AbsentSignaturePolicyIdentifierMakesTheStoreIllegal()
    {
        Assert.IsFalse(XAdESSignaturePolicyStoreLegality.IsSignaturePolicyStoreLegal(null));
    }
}
