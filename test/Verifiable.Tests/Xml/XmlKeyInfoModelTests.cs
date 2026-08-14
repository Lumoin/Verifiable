using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs that every <c>KeyInfo</c> child type of section 4.4 of <see
/// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see> reads, with a <c>KeyInfo</c> carrying EVERY child modelled.
/// </summary>
[TestClass]
internal sealed class XmlKeyInfoModelTests
{
    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.4: every recognized <c>KeyInfo</c> child kind —
    /// <c>KeyName</c>, <c>KeyValue</c>/<c>RSAKeyValue</c>, <c>RetrievalMethod</c>, <c>X509Data</c> (all five
    /// members), <c>PGPData</c>, <c>SPKIData</c>, <c>MgmtData</c> — and a foreign-namespace child carried as
    /// an opaque node index per the section 4.4 extension rule ("<c>MUST</c> be a child of <c>KeyInfo</c>",
    /// "safe to ignore ... while claiming support for the types defined in this specification").
    /// </summary>
    [TestMethod]
    public void EveryKeyInfoChildKindReads()
    {
        using XmlNodeTable table = Parse("""
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                <Reference>
                  <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
              <KeyInfo Id="ki1">
                <KeyName>Example Key</KeyName>
                <KeyValue><RSAKeyValue><Modulus>AQ==</Modulus><Exponent>AQE=</Exponent></RSAKeyValue></KeyValue>
                <RetrievalMethod URI="#cert1" Type="http://www.w3.org/2000/09/xmldsig#X509Data"/>
                <X509Data>
                  <X509IssuerSerial><X509IssuerName>CN=Test CA</X509IssuerName><X509SerialNumber>12345</X509SerialNumber></X509IssuerSerial>
                  <X509SKI>Ag==</X509SKI>
                  <X509SubjectName>CN=Subject</X509SubjectName>
                  <X509Certificate>Aw==</X509Certificate>
                  <X509CRL>BA==</X509CRL>
                </X509Data>
                <PGPData><PGPKeyID>BQ==</PGPKeyID><PGPKeyPacket>Bg==</PGPKeyPacket></PGPData>
                <SPKIData><SPKISexp>Bw==</SPKISexp></SPKIData>
                <MgmtData>opaque management data</MgmtData>
                <foreign:Other xmlns:foreign="urn:example:foreign"/>
              </KeyInfo>
            </Signature>
            """);

        bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(signature)
        {
            XmlKeyInfo keyInfo = signature!.KeyInfo!.Value;
            Assert.AreSequenceEqual("ki1"u8.ToArray(), keyInfo.Id.ToArray());
            Assert.HasCount(8, keyInfo.Children);

            Assert.AreEqual(XmlKeyInfoChildKind.KeyName, keyInfo.Children[0].Kind);
            Assert.AreEqual("Example Key", Encoding.UTF8.GetString(keyInfo.Children[0].KeyNameValue));

            XmlKeyValue keyValue = keyInfo.Children[1].KeyValue!.Value;
            Assert.AreEqual(XmlKeyValueKind.Rsa, keyValue.Kind);
            Assert.AreEqual((byte)0x01, keyValue.Rsa!.Value.Modulus.AsReadOnlySpan()[0]);
            Assert.AreEqual((byte)0x01, keyValue.Rsa.Value.Exponent.AsReadOnlySpan()[0]);

            XmlRetrievalMethod retrievalMethod = keyInfo.Children[2].RetrievalMethod!.Value;
            Assert.IsTrue(retrievalMethod.HasUri);
            Assert.AreSequenceEqual("#cert1"u8.ToArray(), retrievalMethod.Uri.ToArray());
            Assert.IsTrue(retrievalMethod.HasType);
            Assert.IsEmpty(retrievalMethod.Transforms);

            var x509 = keyInfo.Children[3].X509DataMembers!;
            Assert.HasCount(5, x509);
            Assert.AreEqual(XmlX509DataMemberKind.IssuerSerial, x509[0].Kind);
            Assert.AreEqual("CN=Test CA", Encoding.UTF8.GetString(x509[0].IssuerName));
            Assert.AreEqual("12345", Encoding.UTF8.GetString(x509[0].SerialNumber));
            Assert.AreEqual(XmlX509DataMemberKind.SubjectKeyIdentifier, x509[1].Kind);
            Assert.AreEqual((byte)0x02, x509[1].DecodedOctets!.AsReadOnlySpan()[0]);
            Assert.AreEqual(XmlX509DataMemberKind.SubjectName, x509[2].Kind);
            Assert.AreEqual("CN=Subject", Encoding.UTF8.GetString(x509[2].SubjectName));
            Assert.AreEqual(XmlX509DataMemberKind.Certificate, x509[3].Kind);
            Assert.AreEqual((byte)0x03, x509[3].DecodedOctets!.AsReadOnlySpan()[0]);
            Assert.AreEqual(XmlX509DataMemberKind.CertificateRevocationList, x509[4].Kind);
            Assert.AreEqual((byte)0x04, x509[4].DecodedOctets!.AsReadOnlySpan()[0]);

            XmlPgpData pgp = keyInfo.Children[4].PgpData!.Value;
            Assert.AreEqual((byte)0x05, pgp.KeyId!.AsReadOnlySpan()[0]);
            Assert.AreEqual((byte)0x06, pgp.KeyPacket!.AsReadOnlySpan()[0]);

            XmlSpkiData spki = keyInfo.Children[5].SpkiData!.Value;
            Assert.HasCount(1, spki.Sexps);
            Assert.AreEqual((byte)0x07, spki.Sexps[0].AsReadOnlySpan()[0]);

            Assert.AreEqual(XmlKeyInfoChildKind.MgmtData, keyInfo.Children[6].Kind);
            Assert.AreEqual("opaque management data", Encoding.UTF8.GetString(keyInfo.Children[6].MgmtDataValue));

            Assert.AreEqual(XmlKeyInfoChildKind.Foreign, keyInfo.Children[7].Kind);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.4.2.1: <c>DSAKeyValue</c>'s full optional field set —
    /// <c>P</c>, <c>Q</c>, <c>G</c>, <c>Y</c>, <c>J</c>, <c>Seed</c>, <c>PgenCounter</c> — decodes when every
    /// field is present.
    /// </summary>
    [TestMethod]
    public void DsaKeyValueWithEveryOptionalFieldDecodes()
    {
        using XmlNodeTable table = Parse("""
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
                <Reference><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>AQ==</DigestValue></Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
              <KeyInfo>
                <KeyValue>
                  <DSAKeyValue>
                    <P>AQ==</P><Q>Ag==</Q><G>Aw==</G><Y>BA==</Y><J>BQ==</J><Seed>Bg==</Seed><PgenCounter>Bw==</PgenCounter>
                  </DSAKeyValue>
                </KeyValue>
              </KeyInfo>
            </Signature>
            """);

        bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(signature)
        {
            XmlDsaKeyValue dsa = signature!.KeyInfo!.Value.Children[0].KeyValue!.Value.Dsa!.Value;
            Assert.AreEqual((byte)1, dsa.P!.AsReadOnlySpan()[0]);
            Assert.AreEqual((byte)2, dsa.Q!.AsReadOnlySpan()[0]);
            Assert.AreEqual((byte)3, dsa.G!.AsReadOnlySpan()[0]);
            Assert.AreEqual((byte)4, dsa.Y.AsReadOnlySpan()[0]);
            Assert.AreEqual((byte)5, dsa.J!.AsReadOnlySpan()[0]);
            Assert.AreEqual((byte)6, dsa.Seed!.AsReadOnlySpan()[0]);
            Assert.AreEqual((byte)7, dsa.PgenCounter!.AsReadOnlySpan()[0]);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.4.2.1: <c>DSAKeyValue</c>'s minimal shape — only the
    /// mandatory <c>Y</c> — reads too, since <c>P</c>/<c>Q</c>/<c>G</c>/<c>J</c>/<c>Seed</c>/<c>PgenCounter</c>
    /// are all optional.
    /// </summary>
    [TestMethod]
    public void DsaKeyValueWithOnlyYReads()
    {
        using XmlNodeTable table = Parse("""
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
                <Reference><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>AQ==</DigestValue></Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
              <KeyInfo><KeyValue><DSAKeyValue><Y>BA==</Y></DSAKeyValue></KeyValue></KeyInfo>
            </Signature>
            """);

        bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(signature)
        {
            XmlDsaKeyValue dsa = signature!.KeyInfo!.Value.Children[0].KeyValue!.Value.Dsa!.Value;
            Assert.IsNull(dsa.P);
            Assert.IsNull(dsa.Q);
            Assert.IsNull(dsa.G);
            Assert.IsNull(dsa.J);
            Assert.IsNull(dsa.Seed);
            Assert.IsNull(dsa.PgenCounter);
            Assert.AreEqual((byte)4, dsa.Y.AsReadOnlySpan()[0]);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.4.2.1's paired-optional constraint on <c>P</c>/<c>Q</c> —
    /// "they are optional but P and Q must either both appear or both be absent" — refuses when <c>P</c> is
    /// present without <c>Q</c>.
    /// </summary>
    [TestMethod]
    public void DsaKeyValueWithPButNoQRefuses()
    {
        using XmlNodeTable table = Parse("""
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
                <Reference><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>AQ==</DigestValue></Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
              <KeyInfo><KeyValue><DSAKeyValue><P>AQ==</P><Y>BA==</Y></DSAKeyValue></KeyValue></KeyInfo>
            </Signature>
            """);

        bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError error);
        using(signature)
        {
            Assert.IsFalse(isRead, "P without Q must refuse.");
            Assert.IsNull(signature);
            Assert.AreEqual(XmlSignatureReadFailure.MissingRequiredChild, error.Failure);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.4.2.1's paired-optional constraint on
    /// <c>Seed</c>/<c>PgenCounter</c> refuses when <c>Seed</c> is present without <c>PgenCounter</c>.
    /// </summary>
    [TestMethod]
    public void DsaKeyValueWithSeedButNoPgenCounterRefuses()
    {
        using XmlNodeTable table = Parse("""
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
                <Reference><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>AQ==</DigestValue></Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
              <KeyInfo><KeyValue><DSAKeyValue><Y>BA==</Y><Seed>Bg==</Seed></DSAKeyValue></KeyValue></KeyInfo>
            </Signature>
            """);

        bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError error);
        using(signature)
        {
            Assert.IsFalse(isRead, "Seed without PgenCounter must refuse.");
            Assert.IsNull(signature);
            Assert.AreEqual(XmlSignatureReadFailure.MissingRequiredChild, error.Failure);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.4.3's errata is honored: <c>RetrievalMethod</c> without a
    /// <c>URI</c> attribute is accepted, not refused, because "the schema for the URI attribute of
    /// RetrievalMethod erroneously omitted the attribute: use="required"" and "this error only results in a
    /// more lax schema which permits all valid RetrievalMethod elements" — a stricter reader would break
    /// documents the errata itself says must stay valid.
    /// </summary>
    [TestMethod]
    public void RetrievalMethodWithoutUriIsAcceptedPerTheErrata()
    {
        using XmlNodeTable table = Parse("""
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
                <Reference><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>AQ==</DigestValue></Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
              <KeyInfo><RetrievalMethod/></KeyInfo>
            </Signature>
            """);

        bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError error);
        Assert.IsTrue(isRead, $"A RetrievalMethod without URI must be accepted per the section 4.4.3 errata, but was refused with {error.Failure}.");
        using(signature)
        {
            Assert.IsFalse(signature!.KeyInfo!.Value.Children[0].RetrievalMethod!.Value.HasUri);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.4.5's "<c>PGPData</c> must contain one <c>PGPKeyID</c>
    /// and/or one <c>PGPKeyPacket</c>" content rule: an empty <c>PGPData</c> refuses.
    /// </summary>
    [TestMethod]
    public void EmptyPgpDataRefusesAsMissingRequiredChild()
    {
        using XmlNodeTable table = Parse("""
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
                <Reference><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>AQ==</DigestValue></Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
              <KeyInfo><PGPData/></KeyInfo>
            </Signature>
            """);

        bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError error);
        using(signature)
        {
            Assert.IsFalse(isRead);
            Assert.IsNull(signature);
            Assert.AreEqual(XmlSignatureReadFailure.MissingRequiredChild, error.Failure);
        }
    }
}
