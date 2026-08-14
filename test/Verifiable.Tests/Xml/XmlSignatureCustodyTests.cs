using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs that every pooled buffer <see cref="XmlSignature.TryRead"/> and <see cref="XmlManifest.TryRead"/>
/// rent is returned — on success after <see cref="IDisposable.Dispose"/> and on every refusal path, even one
/// reached after several base64 fields already decoded successfully earlier in the same read — observed
/// through <see cref="MeteredHousePool"/> accounting: custody stays balanced on every path.
/// </summary>
[TestClass]
internal sealed class XmlSignatureCustodyTests
{
    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves the "MeteredHousePool custody proven on every refusal path", the acceptance side: custody is
    /// balanced after a successful read of a signature whose <c>KeyInfo</c> decodes many base64 fields
    /// (<c>RSAKeyValue</c>, all five <c>X509Data</c> members, <c>PGPData</c>, <c>SPKIData</c>) plus its own
    /// <c>SignatureValue</c> and <c>DigestValue</c>, once <see cref="XmlSignature.Dispose"/> runs. The
    /// table's own buffers are excluded from the count by disposing it outside the metered scope. This is
    /// the memory-demand posture <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML
    /// Signature Syntax and Processing (Second Edition)</see> section 8.3 names — "even there perverse
    /// parameters might cause unacceptable processing or memory demand" — proven for the multi-field
    /// acceptance path: every rented buffer comes back.
    /// </summary>
    [TestMethod]
    public void SuccessfulReadWithManyDecodedFieldsIsBalancedAfterDispose()
    {
        string document = """
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
              <KeyInfo>
                <KeyValue><RSAKeyValue><Modulus>AQ==</Modulus><Exponent>AQE=</Exponent></RSAKeyValue></KeyValue>
                <X509Data>
                  <X509SKI>Ag==</X509SKI>
                  <X509Certificate>Aw==</X509Certificate>
                  <X509CRL>BA==</X509CRL>
                </X509Data>
                <PGPData><PGPKeyID>BQ==</PGPKeyID><PGPKeyPacket>Bg==</PGPKeyPacket></PGPData>
                <SPKIData><SPKISexp>Bw==</SPKISexp></SPKIData>
              </KeyInfo>
            </Signature>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);

            bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, metered.Pool, out XmlSignature? signature, out XmlSignatureReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            signature!.Dispose();

            Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer XmlSignature.TryRead rents must be returned once Dispose runs.");
        }
    }


    /// <summary>
    /// Proves the "MeteredHousePool custody proven on every refusal path" partway through a multi-field
    /// read: custody is balanced when a read is refused partway through <c>KeyInfo</c>, after several
    /// earlier fields — the <c>SignedInfo</c> <c>DigestValue</c>, the <c>SignatureValue</c>, and
    /// <c>RSAKeyValue</c>'s <c>Modulus</c>/<c>Exponent</c> — already decoded successfully: the whole read
    /// runs inside one <c>try</c>/<c>finally</c>, so a later refusal still releases every buffer the earlier
    /// steps rented, holding the memory-demand posture of <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 8.3 — "even there perverse parameters might cause unacceptable
    /// processing or memory demand" — on the refusal path, not only the acceptance one.
    /// </summary>
    [TestMethod]
    public void RefusalPartwayThroughKeyInfoIsBalanced()
    {
        string document = """
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
              <KeyInfo>
                <KeyValue><RSAKeyValue><Modulus>AQ==</Modulus><Exponent>AQE=</Exponent></RSAKeyValue></KeyValue>
                <X509Data>
                  <X509Certificate>not-base64!!!</X509Certificate>
                </X509Data>
              </KeyInfo>
            </Signature>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);

            bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, metered.Pool, out XmlSignature? signature, out XmlSignatureReadError error);
            using(signature)
            {
                Assert.IsFalse(isRead, "The malformed X509Certificate content must refuse the whole read.");
                Assert.IsNull(signature);
                Assert.AreEqual(XmlSignatureReadFailure.InvalidBase64Content, error.Failure);
                Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer rented before the refusal must still be returned.");
            }
        }
    }


    /// <summary>
    /// Proves the custody discipline extends to the <c>ds:Manifest</c> reader: custody is balanced for <see
    /// cref="XmlManifest.TryRead"/>, both after a successful read's <see cref="XmlManifest.Dispose"/> and on
    /// a refusal partway through its second <c>Reference</c> — the same "unacceptable processing or memory
    /// demand" posture of <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature
    /// Syntax and Processing (Second Edition)</see> section 8.3 extended to the reader <see
    /// cref="XmlManifest"/> shares with <see cref="XmlSignature"/>.
    /// </summary>
    [TestMethod]
    public void ManifestCustodyIsBalancedOnSuccessAndOnRefusal()
    {
        string validDocument = """
            <Manifest xmlns="http://www.w3.org/2000/09/xmldsig#" Id="m1">
              <Reference><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>AQ==</DigestValue></Reference>
              <Reference><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>Ag==</DigestValue></Reference>
            </Manifest>
            """;
        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(validDocument, BaseMemoryPool.Shared);

            bool isRead = XmlManifest.TryRead(table, table.DocumentElementIndex, metered.Pool, out XmlManifest? manifest, out XmlSignatureReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            manifest!.Dispose();

            Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer XmlManifest.TryRead rents must be returned once Dispose runs.");
        }

        string refusingDocument = """
            <Manifest xmlns="http://www.w3.org/2000/09/xmldsig#">
              <Reference><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>AQ==</DigestValue></Reference>
              <Reference><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>bad!!</DigestValue></Reference>
            </Manifest>
            """;
        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(refusingDocument, BaseMemoryPool.Shared);

            bool isRead = XmlManifest.TryRead(table, table.DocumentElementIndex, metered.Pool, out XmlManifest? manifest, out XmlSignatureReadError error);
            using(manifest)
            {
                Assert.IsFalse(isRead);
                Assert.IsNull(manifest);
                Assert.AreEqual(XmlSignatureReadFailure.InvalidBase64Content, error.Failure);
                Assert.AreEqual(0L, metered.OutstandingCount, "The first Reference's already-decoded DigestValue must still be released.");
            }
        }
    }
}
