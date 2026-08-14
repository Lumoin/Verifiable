using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESSigningCertificateV2.TryRead"/> against clause 5.2.2's <c>SigningCertificateV2</c>
/// qualifying property of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>.
/// </summary>
[TestClass]
internal sealed class XAdESSigningCertificateV2Tests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static string Cert(byte[] digest, string? issuerSerialV2 = null, string? uri = null)
    {
        string uriAttribute = uri is null ? string.Empty : $" URI=\"{uri}\"";
        string issuerSerial = issuerSerialV2 is null ? string.Empty : $"<IssuerSerialV2>{issuerSerialV2}</IssuerSerialV2>";

        return $"""
            <Cert{uriAttribute}>
              <CertDigest>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>{Convert.ToBase64String(digest)}</ds:DigestValue>
              </CertDigest>
              {issuerSerial}
            </Cert>
            """;
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.2's minimal shape — one <c>Cert</c> carrying only the mandatory
    /// <c>CertDigest</c> — reads, and that custody balances to zero once the caller disposes the returned
    /// value.
    /// </summary>
    [TestMethod]
    public void MinimalSingleCertReadsAndCustodyBalancesAfterDispose()
    {
        byte[] digest = [0x01, 0x02, 0x03];
        string document = $"""
            <SigningCertificateV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              {Cert(digest)}
            </SigningCertificateV2>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESSigningCertificateV2.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESSigningCertificateV2? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.HasCount(1, value!.Certs);
            Assert.AreSequenceEqual(digest, value.Certs[0].CertDigest.DigestValueOctets.AsReadOnlySpan().ToArray());
            Assert.IsFalse(value.Certs[0].HasIssuerSerialV2);
            Assert.IsFalse(value.Certs[0].HasUri);

            value.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "Every rented buffer must be returned once the caller disposes the value.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.2's "The first reference in
    /// <c>SigningCertificateV2</c> qualifying property shall be the reference of the signing certificate" — a
    /// positional fact this reader preserves via document order: with multiple <c>Cert</c> entries,
    /// <c>Certs[0]</c> is always the first one written, identifiable here by its distinct digest value.
    /// </summary>
    [TestMethod]
    public void FirstCertIsPreservedAsTheSigningCertificateByPosition()
    {
        byte[] signingCertDigest = [0xAA];
        byte[] pathCertDigest = [0xBB];
        string document = $"""
            <SigningCertificateV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              {Cert(signingCertDigest)}
              {Cert(pathCertDigest)}
            </SigningCertificateV2>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSigningCertificateV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSigningCertificateV2? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.HasCount(2, value!.Certs);
            Assert.AreSequenceEqual(signingCertDigest, value.Certs[0].CertDigest.DigestValueOctets.AsReadOnlySpan().ToArray());
            Assert.AreSequenceEqual(pathCertDigest, value.Certs[1].CertDigest.DigestValueOctets.AsReadOnlySpan().ToArray());
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.2, <c>IssuerSerialV2</c> is carried as
    /// opaque, base64-decoded DER bytes without any ASN.1 interpretation — "The content of <c>IssuerSerialV2</c> element shall be the base-64 encoding of one DER-encoded instance of type <c>IssuerSerial</c>
    /// ... IETF RFC 5035" — ASN.1 decoding stays Pki territory.
    /// </summary>
    [TestMethod]
    public void IssuerSerialV2IsCarriedAsOpaqueBytes()
    {
        byte[] digest = [0x01];
        byte[] issuerSerialDer = [0x30, 0x03, 0x02, 0x01, 0x2A];
        string document = $"""
            <SigningCertificateV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              {Cert(digest, Convert.ToBase64String(issuerSerialDer))}
            </SigningCertificateV2>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSigningCertificateV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSigningCertificateV2? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.Certs[0].HasIssuerSerialV2);
            Assert.AreSequenceEqual(issuerSerialDer, value.Certs[0].IssuerSerialV2Octets!.AsReadOnlySpan().ToArray());
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.2, the optional, advisory <c>URI</c>
    /// attribute of <c>CertIDTypeV2</c> reads exact-character when present.
    /// </summary>
    [TestMethod]
    public void OptionalUriAttributeSurfacesWhenPresent()
    {
        byte[] digest = [0x01];
        string document = $"""
            <SigningCertificateV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              {Cert(digest, uri: "http://example.com/cert1.cer")}
            </SigningCertificateV2>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSigningCertificateV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSigningCertificateV2? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.Certs[0].HasUri);
            Assert.AreEqual("http://example.com/cert1.cer", Encoding.UTF8.GetString(value.Certs[0].Uri));
        }
    }


    /// <summary>
    /// Proves clause 6.3 letter i)'s SHOULD-NOT-observable half: <c>Cert</c>'s optional <c>URI</c> attribute
    /// "shall not be generated" is a fact this reader already surfaces (<see cref="XAdESCertIdV2.HasUri"/>) —
    /// present when the wire carries one, absent when it does not, ready for a caller-side SHOULD-NOT judgment.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, row XA-6.3-t06, letter i.
    /// </summary>
    [TestMethod]
    public void LetterIsUriObservationSurfacesOnCert()
    {
        byte[] digest = [0x01];
        string withUri = $"""
            <SigningCertificateV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              {Cert(digest, uri: "http://example.com/cert1.cer")}
            </SigningCertificateV2>
            """;
        using XmlNodeTable withUriTable = Parse(withUri, BaseMemoryPool.Shared);
        bool isWithUriRead = XAdESSigningCertificateV2.TryRead(withUriTable, withUriTable.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSigningCertificateV2? withUriValue, out XAdESReadError withUriError);
        Assert.IsTrue(isWithUriRead, $"Must read but was refused with {withUriError.Failure}.");
        using(withUriValue)
        {
            Assert.IsTrue(withUriValue!.Certs[0].HasUri, "The letter-i) SHOULD-NOT signal must be observable when URI is present.");
        }

        string withoutUri = $"""
            <SigningCertificateV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              {Cert(digest)}
            </SigningCertificateV2>
            """;
        using XmlNodeTable withoutUriTable = Parse(withoutUri, BaseMemoryPool.Shared);
        bool isWithoutUriRead = XAdESSigningCertificateV2.TryRead(withoutUriTable, withoutUriTable.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSigningCertificateV2? withoutUriValue, out XAdESReadError withoutUriError);
        Assert.IsTrue(isWithoutUriRead, $"Must read but was refused with {withoutUriError.Failure}.");
        using(withoutUriValue)
        {
            Assert.IsFalse(withoutUriValue!.Certs[0].HasUri);
        }
    }


    /// <summary>
    /// Proves clause 6.3 letter j)'s SHOULD-NOT-observable half at the <c>SigningCertificateV2</c> site:
    /// <c>IssuerSerialV2</c> "SHOULD NOT be used" is a fact this reader already surfaces
    /// (<see cref="XAdESCertIdV2.HasIssuerSerialV2"/>).
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, row XA-6.3-t06, letter j.
    /// </summary>
    [TestMethod]
    public void LetterJsIssuerSerialV2ObservationSurfacesOnCert()
    {
        byte[] digest = [0x01];
        string document = $"""
            <SigningCertificateV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              {Cert(digest, Convert.ToBase64String([0x30, 0x03, 0x02, 0x01, 0x2A]))}
            </SigningCertificateV2>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSigningCertificateV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSigningCertificateV2? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.Certs[0].HasIssuerSerialV2, "The letter-j) SHOULD-NOT signal must be observable when IssuerSerialV2 is present.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.2's "shall contain one reference to the signing certificate" —
    /// a <c>SigningCertificateV2</c> with zero <c>Cert</c> children is refused.
    /// </summary>
    [TestMethod]
    public void ZeroCertsIsRefused()
    {
        using XmlNodeTable table = Parse($"""<SigningCertificateV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}"/>""", BaseMemoryPool.Shared);
        bool isRead = XAdESSigningCertificateV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "Zero Cert entries must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.2, "For each certificate, the
    /// <c>SigningCertificateV2</c> qualifying property shall contain a digest value" — a <c>Cert</c> without
    /// <c>CertDigest</c> is refused.
    /// </summary>
    [TestMethod]
    public void CertWithoutCertDigestIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SigningCertificateV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <Cert/>
            </SigningCertificateV2>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSigningCertificateV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A Cert without CertDigest must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.2, an unrecognized attribute on the
    /// <c>SigningCertificateV2</c> element itself is refused — <c>CertIDListV2Type</c> declares no attribute
    /// of its own.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeOnWrappingElementIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SigningCertificateV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}" unexpected="value">
              {Cert([0x01])}
            </SigningCertificateV2>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSigningCertificateV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.2, an unrecognized attribute on a
    /// <c>Cert</c> element — beyond the schema's own optional <c>URI</c> — is refused fail-closed.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeOnCertIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SigningCertificateV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              <Cert unexpected="value">
                <CertDigest>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </CertDigest>
              </Cert>
            </SigningCertificateV2>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESSigningCertificateV2.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized attribute on Cert must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.2 and the pooling discipline,
    /// custody is balanced even on a refusal path: when the first <c>Cert</c>'s <c>CertDigest</c> value already decoded successfully before a second, malformed <c>Cert</c> causes the whole read to
    /// refuse, <see cref="XAdESSigningCertificateV2.TryRead"/>'s own outer <c>try</c>/<c>finally</c> — this type owns its custody list outright, unlike the shared caller-supplied-list primitives it
    /// composes — releases every buffer already rented, leaving nothing outstanding.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnARefusalAfterPartialDecoding()
    {
        string document = $"""
            <SigningCertificateV2 xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              {Cert([0x01])}
              <Cert>
                <CertDigest>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                  <ds:DigestValue>AQ==</ds:DigestValue>
                </CertDigest>
                <TrailingUnknown/>
              </Cert>
            </SigningCertificateV2>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESSigningCertificateV2.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESSigningCertificateV2? value, out XAdESReadError error);
            using(value)
            {
                Assert.IsFalse(isRead, "A malformed second Cert must refuse the whole read.");
                Assert.IsNull(value);
                Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
                Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer rented before the refusal was determined must already be released.");
            }
        }
    }
}
