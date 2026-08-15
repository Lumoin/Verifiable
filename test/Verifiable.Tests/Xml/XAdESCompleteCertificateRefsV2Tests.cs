using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESCompleteCertificateRefsV2.TryRead"/> against Annex A.1.1's
/// <c>CompleteCertificateRefsV2</c> qualifying property and Annex A.1.3's <c>AttributeCertificateRefsV2</c>
/// qualifying property of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see> — both bound to the SAME <c>CompleteCertificateRefsTypeV2</c> schema type.
/// </summary>
[TestClass]
internal sealed class XAdESCompleteCertificateRefsV2Tests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static string Document(string elementName, string certRefsContent, string? id = null)
    {
        string idAttribute = id is null ? string.Empty : $" Id=\"{id}\"";

        return $"""
            <{elementName} xmlns="{XAdESIdentifiers.XAdESNamespaceV141}" xmlns:xades="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}"{idAttribute}>
              <CertRefs>
                {certRefsContent}
              </CertRefs>
            </{elementName}>
            """;
    }


    private static string Cert(byte[] digest) => $"""
        <xades:Cert>
          <xades:CertDigest>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <ds:DigestValue>{Convert.ToBase64String(digest)}</ds:DigestValue>
          </xades:CertDigest>
        </xades:Cert>
        """;


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.1's syntax rule — "The
    /// <c>CertRefs</c> element is of type <c>xades:CertIDListV2Type</c>, already defined in clause 5.2.2" —
    /// a minimal <c>CompleteCertificateRefsV2</c> with one <c>Cert</c> reads, and custody balances to zero
    /// once the caller disposes the returned value.
    /// </summary>
    [TestMethod]
    public void MinimalCompleteCertificateRefsV2ReadsAndCustodyBalances()
    {
        byte[] digest = [0x01, 0x02, 0x03];
        string document = Document("CompleteCertificateRefsV2", Cert(digest));

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESCompleteCertificateRefsV2.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESCompleteCertificateRefsV2? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.HasCount(1, value!.CertRefs);
            Assert.AreSequenceEqual(digest, value.CertRefs[0].CertDigest.DigestValueOctets.AsReadOnlySpan().ToArray());
            Assert.IsFalse(value.HasId);

            value.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "Every rented buffer must be returned once the caller disposes the value.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.3's syntax rule — "shall
    /// be defined as in XML Schema file ... <c>&lt;xsd:element name="AttributeCertificateRefsV2"
    /// type="CompleteCertificateRefsTypeV2"/&gt;</c>" — the SAME reader accepts <c>AttributeCertificateRefsV2</c>
    /// by wire content alone, since <see cref="XAdESCompleteCertificateRefsV2.TryRead"/> does not itself check
    /// the wrapping element's local name.
    /// </summary>
    [TestMethod]
    public void AttributeCertificateRefsV2ReadsThroughTheSameReader()
    {
        byte[] digest = [0xAA];
        string document = Document("AttributeCertificateRefsV2", Cert(digest));

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteCertificateRefsV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESCompleteCertificateRefsV2? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.HasCount(1, value!.CertRefs);
        }
    }


    /// <summary>
    /// Proves the optional <c>Id</c> attribute of <c>CompleteCertificateRefsTypeV2</c> (Annex A.1.1) reads
    /// exact-character when present, per
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>.
    /// </summary>
    [TestMethod]
    public void OptionalIdAttributeSurfacesWhenPresent()
    {
        string document = Document("CompleteCertificateRefsV2", Cert([0x01]), id: "ccr1");

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteCertificateRefsV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESCompleteCertificateRefsV2? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.HasId);
            Assert.AreEqual("ccr1", Encoding.UTF8.GetString(value.Id));
        }
    }


    /// <summary>
    /// Proves multiple <c>Cert</c> entries preserve document order — the reused
    /// <see cref="XAdESSigningCertificateV2.TryReadCertIdListV2"/> core's own positional contract, exercised
    /// here through <c>CertRefs</c> rather than <c>SigningCertificateV2</c>. Anchored to
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.1.
    /// </summary>
    [TestMethod]
    public void MultipleCertsPreserveDocumentOrder()
    {
        byte[] first = [0xAA];
        byte[] second = [0xBB];
        string document = Document("CompleteCertificateRefsV2", Cert(first) + Cert(second));

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteCertificateRefsV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESCompleteCertificateRefsV2? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.HasCount(2, value!.CertRefs);
            Assert.AreSequenceEqual(first, value.CertRefs[0].CertDigest.DigestValueOctets.AsReadOnlySpan().ToArray());
            Assert.AreSequenceEqual(second, value.CertRefs[1].CertDigest.DigestValueOctets.AsReadOnlySpan().ToArray());
        }
    }


    /// <summary>
    /// Proves clause 6.3 letter j)'s SHOULD-NOT-observable half at BOTH sites this shared reader serves:
    /// <c>IssuerSerialV2</c> "SHOULD NOT be included" in <c>CompleteCertificateRefsV2</c> (row XA-6.3-t27) and
    /// <c>AttributeCertificateRefsV2</c> (row XA-6.3-t30) is a fact this reader already surfaces
    /// (<see cref="XAdESCertIdV2.HasIssuerSerialV2"/>), reused unchanged from <c>SigningCertificateV2</c>'s own
    /// <c>Cert</c> shape.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.1/A.1.3, clause 6.3 letter j.
    /// </summary>
    [TestMethod]
    [DataRow("CompleteCertificateRefsV2")]
    [DataRow("AttributeCertificateRefsV2")]
    public void LetterJsIssuerSerialV2ObservationSurfacesAtBothSites(string elementName)
    {
        byte[] digest = [0x01];
        string certWithIssuerSerial = $"""
            <xades:Cert>
              <xades:CertDigest>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>{Convert.ToBase64String(digest)}</ds:DigestValue>
              </xades:CertDigest>
              <xades:IssuerSerialV2>{Convert.ToBase64String([0x30, 0x03, 0x02, 0x01, 0x2A])}</xades:IssuerSerialV2>
            </xades:Cert>
            """;
        string document = Document(elementName, certWithIssuerSerial);

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteCertificateRefsV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESCompleteCertificateRefsV2? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.CertRefs[0].HasIssuerSerialV2, "The letter-j) SHOULD-NOT signal must be observable when IssuerSerialV2 is present.");
        }
    }


    /// <summary>
    /// Proves a <c>CompleteCertificateRefsV2</c> with no <c>CertRefs</c> child at all is refused —
    /// <c>CertRefs</c> is mandatory (default <c>minOccurs="1"</c>) in <c>CompleteCertificateRefsTypeV2</c>'s
    /// sequence, per
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.1.
    /// </summary>
    [TestMethod]
    public void MissingCertRefsIsRefused()
    {
        string document = $"""<CompleteCertificateRefsV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV141}"/>""";

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteCertificateRefsV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A CompleteCertificateRefsV2 with no CertRefs child must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves a <c>CertRefs</c> element with zero <c>Cert</c> children is refused — <c>CertIDListV2Type</c>'s
    /// own <c>Cert</c> sequence carries a default <c>minOccurs="1"</c>, per
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.2 (Annex A.1.1's
    /// own dependency on that clause).
    /// </summary>
    [TestMethod]
    public void EmptyCertRefsIsRefused()
    {
        string document = $"""
            <CompleteCertificateRefsV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV141}">
              <CertRefs/>
            </CompleteCertificateRefsV2>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteCertificateRefsV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An empty CertRefs must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves a second <c>CertRefs</c> child is refused as a duplicate — <c>CompleteCertificateRefsTypeV2</c>'s
    /// sequence permits exactly one, per
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.1.
    /// </summary>
    [TestMethod]
    public void DuplicateCertRefsIsRefused()
    {
        string document = $"""
            <CompleteCertificateRefsV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV141}" xmlns:xades="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              <CertRefs>{Cert([0x01])}</CertRefs>
              <CertRefs>{Cert([0x02])}</CertRefs>
            </CompleteCertificateRefsV2>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteCertificateRefsV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A second CertRefs child must be refused.");
        Assert.AreEqual(XAdESReadFailure.DuplicateCoreChild, error.Failure);
    }


    /// <summary>
    /// Proves an unrecognized trailing element after <c>CertRefs</c> is refused fail-closed, per
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.1's fixed one-element
    /// sequence.
    /// </summary>
    [TestMethod]
    public void TrailingUnknownElementIsRefused()
    {
        string document = $"""
            <CompleteCertificateRefsV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV141}" xmlns:xades="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              <CertRefs>{Cert([0x01])}</CertRefs>
              <TrailingUnknown/>
            </CompleteCertificateRefsV2>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCompleteCertificateRefsV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized trailing element must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves custody is balanced on a refusal path: when the first <c>Cert</c>'s <c>CertDigest</c> value already decoded successfully before a second, malformed
    /// <c>Cert</c> causes the whole read to refuse, <see cref="XAdESCompleteCertificateRefsV2.TryRead"/>'s own outer <c>try</c>/<c>finally</c> releases every buffer
    /// already rented, leaving nothing outstanding, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI
    /// EN 319 132-1 V1.3.1</see> Annex A.1.1 and the pooling discipline.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnARefusalAfterPartialDecoding()
    {
        string document = $"""
            <CompleteCertificateRefsV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV141}" xmlns:xades="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              <CertRefs>
                {Cert([0x01])}
                <xades:Cert unexpected="value">
                  <xades:CertDigest>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>AQ==</ds:DigestValue>
                  </xades:CertDigest>
                </xades:Cert>
              </CertRefs>
            </CompleteCertificateRefsV2>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESCompleteCertificateRefsV2.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESCompleteCertificateRefsV2? value, out XAdESReadError error);
            using(value)
            {
                Assert.IsFalse(isRead, "A malformed second Cert must refuse the whole read.");
                Assert.IsNull(value);
                Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
                Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer rented before the refusal was determined must already be released.");
            }
        }
    }
}
