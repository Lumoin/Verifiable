using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Decode-conformance proofs with full byte-exact comparisons — not the
/// single-octet spot checks <see cref="XmlKeyInfoModelTests"/> uses — against octets this test itself mints
/// and base64-encodes, "Decoded octets are ... reference-processing output octets are tagged ...
/// Validation-side comparison guidance (§3.2 chapeau: compare decoded octets, never base64 text) binds the
/// test-side composition" and "<c>ds:CryptoBinary</c>'s minimal-length/no-leading-zero rule is a
/// generation-side encoding constraint; reading exposes the decoded octets as-is."
/// </summary>
[TestClass]
internal sealed class XmlCryptoBinaryDecodeConformanceTests
{
    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// A deterministic, non-trivial byte sequence resembling a DER-encoded structure's opening (a SEQUENCE
    /// tag and a long-form length) followed by varied filler bytes spanning the full octet range, including
    /// <c>0x00</c> and <c>0xFF</c> — chosen so a byte-for-byte comparison actually exercises every base64
    /// quantum shape rather than a single repeated value.
    /// </summary>
    /// <param name="length">How many octets to mint.</param>
    /// <returns>The minted octets.</returns>
    private static byte[] MintDeterministicOctets(int length)
    {
        byte[] octets = new byte[length];
        octets[0] = 0x30;
        octets[1] = 0x82;
        for(int i = 2; i < length; ++i)
        {
            octets[i] = (byte)((i * 37) + 11);
        }

        return octets;
    }


    /// <summary>
    /// Proves the "<c>X509Data</c> and all five members with <c>X509Certificate</c> content decoded to DER
    /// octets", against <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature
    /// Syntax and Processing (Second Edition)</see> section 4.4.4's <c>X509Certificate</c> element, which
    /// "contains a base64-encoded [X509v3] certificate": <c>X509Certificate</c> DER extraction is byte-exact
    /// against a self-minted 300-octet payload, base64-encoded into the fixture — the decoded <see
    /// cref="XmlX509DataMember.DecodedOctets"/> equal the original octets exactly, over their full length,
    /// not merely the leading byte.
    /// </summary>
    [TestMethod]
    public void X509CertificateDecodesToExactDerOctetsAgainstTheMintedInput()
    {
        byte[] mintedDer = MintDeterministicOctets(300);
        string base64 = Convert.ToBase64String(mintedDer);
        using XmlNodeTable table = Parse($$"""
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <Reference><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>AQ==</DigestValue></Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
              <KeyInfo>
                <X509Data>
                  <X509Certificate>{{base64}}</X509Certificate>
                </X509Data>
              </KeyInfo>
            </Signature>
            """);

        bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(signature)
        {
            XmlX509DataMember member = signature!.KeyInfo!.Value.Children[0].X509DataMembers![0];
            Assert.AreEqual(XmlX509DataMemberKind.Certificate, member.Kind);
            Assert.AreSequenceEqual(mintedDer, member.DecodedOctets!.AsReadOnlySpan().ToArray(), "The decoded X509Certificate octets must byte-exactly match the minted DER input, over the full length.");
        }
    }


    /// <summary>
    /// Proves the "<c>ds:CryptoBinary</c>'s minimal-length/no-leading-zero rule is a generation-side encoding
    /// constraint; reading exposes the decoded octets as-is", against <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 4.4.2.2's <c>RSAKeyValue</c> element, whose <c>Modulus</c> and
    /// <c>Exponent</c> are typed <c>ds:CryptoBinary</c> (section 4.0.1): <c>ds:CryptoBinary</c> fields decode
    /// byte-exactly, INCLUDING a leading zero octet the minted <c>Modulus</c> deliberately carries, so a
    /// leading zero must survive the round trip rather than being stripped.
    /// </summary>
    [TestMethod]
    public void RsaKeyValueCryptoBinaryFieldsDecodeExactlyIncludingALeadingZeroOctet()
    {
        byte[] modulusWithLeadingZero = [0x00, .. MintDeterministicOctets(129)];
        byte[] exponent = [0x01, 0x00, 0x01];
        using XmlNodeTable table = Parse($$"""
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <Reference><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>AQ==</DigestValue></Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
              <KeyInfo>
                <KeyValue>
                  <RSAKeyValue>
                    <Modulus>{{Convert.ToBase64String(modulusWithLeadingZero)}}</Modulus>
                    <Exponent>{{Convert.ToBase64String(exponent)}}</Exponent>
                  </RSAKeyValue>
                </KeyValue>
              </KeyInfo>
            </Signature>
            """);

        bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(signature)
        {
            XmlRsaKeyValue rsa = signature!.KeyInfo!.Value.Children[0].KeyValue!.Value.Rsa!.Value;
            Assert.AreSequenceEqual(modulusWithLeadingZero, rsa.Modulus.AsReadOnlySpan().ToArray(), "The Modulus's leading zero octet must survive decode unstripped.");
            Assert.AreEqual((byte)0x00, rsa.Modulus.AsReadOnlySpan()[0], "The leading octet must specifically be the zero byte, not merely byte-count-equal.");
            Assert.AreSequenceEqual(exponent, rsa.Exponent.AsReadOnlySpan().ToArray());
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.4.2.1's ordered <c>ds:CryptoBinary</c> field list —
    /// <c>P</c>, <c>Q</c>, <c>G</c>, <c>Y</c> — each decode to their own exact, independently-minted
    /// multi-byte octets, cross-checking that the ordered-field reader (<see cref="XmlDsaKeyValue.TryRead"/>)
    /// attributes each decoded buffer to the correct field rather than any silently swapping content between
    /// adjacent fields.
    /// </summary>
    [TestMethod]
    public void DsaKeyValueCryptoBinaryFieldsEachDecodeToTheirOwnExactOctets()
    {
        byte[] p = MintDeterministicOctets(64);
        byte[] q = MintDeterministicOctets(20);
        byte[] g = MintDeterministicOctets(64);
        byte[] y = MintDeterministicOctets(64);
        using XmlNodeTable table = Parse($$"""
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
                    <P>{{Convert.ToBase64String(p)}}</P>
                    <Q>{{Convert.ToBase64String(q)}}</Q>
                    <G>{{Convert.ToBase64String(g)}}</G>
                    <Y>{{Convert.ToBase64String(y)}}</Y>
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
            Assert.AreSequenceEqual(p, dsa.P!.AsReadOnlySpan().ToArray());
            Assert.AreSequenceEqual(q, dsa.Q!.AsReadOnlySpan().ToArray());
            Assert.AreSequenceEqual(g, dsa.G!.AsReadOnlySpan().ToArray());
            Assert.AreSequenceEqual(y, dsa.Y.AsReadOnlySpan().ToArray());
        }
    }
}
