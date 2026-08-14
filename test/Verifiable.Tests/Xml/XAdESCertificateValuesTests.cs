using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESCertificateValues.TryRead"/> against clause 5.4.2's <c>CertificateValues</c>
/// qualifying property and clause 5.4.4's <c>AttrAuthoritiesCertValues</c> qualifying property of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see> — both bound to the SAME <c>CertificateValuesType</c> schema type.
/// </summary>
[TestClass]
internal sealed class XAdESCertificateValuesTests
{
    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.2's "The
    /// <c>EncapsulatedX509Certificate</c> element shall contain the base-64 encoding of a DER-encoded X.509
    /// certificate," an <c>EncapsulatedX509Certificate</c> entry decodes its content, and custody balances to
    /// zero once the caller disposes the returned value.
    /// </summary>
    [TestMethod]
    public void EncapsulatedX509CertificateEntryDecodesAndCustodyBalances()
    {
        byte[] der = [0x30, 0x03, 0x02, 0x01, 0x2A];
        string document = $"""
            <CertificateValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <EncapsulatedX509Certificate>{Convert.ToBase64String(der)}</EncapsulatedX509Certificate>
            </CertificateValues>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESCertificateValues.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESCertificateValues? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.HasCount(1, value!.Entries);
            Assert.AreEqual(XAdESCertificateValueKind.EncapsulatedX509Certificate, value.Entries[0].Kind);
            Assert.AreSequenceEqual(der, value.Entries[0].EncapsulatedX509Certificate.Content.AsReadOnlySpan().ToArray());

            value.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "The decoded EncapsulatedX509Certificate buffer must be released on Dispose.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.2's "The
    /// <c>OtherCertificate</c> element is a placeholder for potential future new formats of certificates," an
    /// <c>OtherCertificate</c> entry is carried unmodeled with no pooled content decoded at all.
    /// </summary>
    [TestMethod]
    public void OtherCertificateEntryIsCarriedUnmodeled()
    {
        string document = $"""
            <CertificateValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <OtherCertificate><Foreign>content</Foreign></OtherCertificate>
            </CertificateValues>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESCertificateValues.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESCertificateValues? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.HasCount(1, value!.Entries);
            Assert.AreEqual(XAdESCertificateValueKind.OtherCertificate, value.Entries[0].Kind);
            Assert.HasCount(1, value.Entries[0].OtherCertificate.ContentNodeIndices);

            value.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "OtherCertificate carries no pooled content.");
        }
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.2's acquired
    /// v132 <c>CertificateValuesType</c> schema (<c>xsd:choice minOccurs="0" maxOccurs="unbounded"</c>), mixed
    /// <c>EncapsulatedX509Certificate</c>/<c>OtherCertificate</c> entries read together, in document order.
    /// </summary>
    [TestMethod]
    public void MixedEntryKindsPreserveDocumentOrder()
    {
        string document = $"""
            <CertificateValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <OtherCertificate><Foreign/></OtherCertificate>
              <EncapsulatedX509Certificate>AQ==</EncapsulatedX509Certificate>
            </CertificateValues>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESCertificateValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESCertificateValues? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.HasCount(2, value!.Entries);
            Assert.AreEqual(XAdESCertificateValueKind.OtherCertificate, value.Entries[0].Kind);
            Assert.AreEqual(XAdESCertificateValueKind.EncapsulatedX509Certificate, value.Entries[1].Kind);
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.2's acquired
    /// v132 <c>CertificateValuesType</c> schema (<c>xsd:choice minOccurs="0" maxOccurs="unbounded"</c>) — with
    /// no matching "empty ... shall not be generated" prose the way clauses 5.2.5/5.2.6 carry for
    /// <c>SignatureProductionPlaceV2</c>/<c>SignerRoleV2</c> — a completely empty <c>CertificateValues</c>
    /// element reads successfully with zero entries.
    /// </summary>
    [TestMethod]
    public void EmptyElementReadsWithZeroEntries()
    {
        using XmlNodeTable table = Parse($"""<CertificateValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}"/>""", BaseMemoryPool.Shared);
        bool isRead = XAdESCertificateValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESCertificateValues? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"An empty CertificateValues element must read, per the schema's minOccurs=\"0\" choice, but was refused with {error.Failure}.");
        using(value)
        {
            Assert.HasCount(0, value!.Entries);
        }
    }


    /// <summary>
    /// Proves clause 5.4.2's DER-narrowing of <c>EncapsulatedX509Certificate</c> — "shall contain the base-64
    /// encoding of a DER-encoded X.509 certificate" — refuses a non-DER <c>Encoding</c> value that
    /// <see cref="XAdESEncapsulatedPkiData"/>'s own general five-encoding enumeration (clause 5.1.3) would
    /// otherwise accept, per clause 5.1.3 NOTE 2's "specific XAdES qualifying properties related to these data
    /// restrict the encoding options to only one certain type."
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.2.
    /// </summary>
    [TestMethod]
    public void NonDerEncapsulatedX509CertificateIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <CertificateValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <EncapsulatedX509Certificate Encoding="{XAdESIdentifiers.BerEncodingUri}">AQ==</EncapsulatedX509Certificate>
            </CertificateValues>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESCertificateValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A BER-encoded EncapsulatedX509Certificate must be refused: clause 5.4.2 narrows the encoding to DER.");
        Assert.AreEqual(XAdESReadFailure.EncapsulatedPkiDataNotDerEncoded, error.Failure);
    }


    /// <summary>
    /// Proves an absent <c>Encoding</c> attribute is never refused as non-DER — clause 5.1.3's own default
    /// rule ("If the <c>Encoding</c> attribute is not present, then the PKI data shall be ASN.1 data encoded
    /// in DER") already satisfies clause 5.4.2's DER narrowing.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.2.
    /// </summary>
    [TestMethod]
    public void AbsentEncodingIsNotRefusedAsNonDer()
    {
        using XmlNodeTable table = Parse($"""
            <CertificateValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <EncapsulatedX509Certificate>AQ==</EncapsulatedX509Certificate>
            </CertificateValues>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESCertificateValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESCertificateValues? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"An EncapsulatedX509Certificate with no Encoding attribute must read, but was refused with {error.Failure}.");
        using(value)
        {
            Assert.AreEqual(XAdESPkiDataEncoding.Der, value!.Entries[0].EncapsulatedX509Certificate.Encoding);
        }
    }


    /// <summary>
    /// Proves clause 5.4.2's <c>Id</c> attribute reads when present — the only attribute
    /// <c>CertificateValuesType</c> declares.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.2.
    /// </summary>
    [TestMethod]
    public void IdAttributeReadsWhenPresent()
    {
        using XmlNodeTable table = Parse($"""<CertificateValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" Id="cv1"/>""", BaseMemoryPool.Shared);
        bool isRead = XAdESCertificateValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESCertificateValues? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.HasId);
            Assert.AreEqual("cv1", Encoding.UTF8.GetString(value.Id));
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.2, an unrecognized
    /// attribute is refused — <c>CertificateValuesType</c> declares only <c>Id</c>.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeIsRefused()
    {
        using XmlNodeTable table = Parse($"""<CertificateValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" unexpected="value"/>""", BaseMemoryPool.Shared);
        bool isRead = XAdESCertificateValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }


    /// <summary>
    /// Proves a child that is neither choice member of <c>CertificateValuesType</c> — clause 5.4.2's
    /// <c>xsd:choice</c> of <c>EncapsulatedX509Certificate</c>/<c>OtherCertificate</c> — is refused.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.2.
    /// </summary>
    [TestMethod]
    public void UnrecognizedChildIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <CertificateValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <Unexpected/>
            </CertificateValues>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESCertificateValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized child must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.4's "shall be
    /// defined as in XML Schema file ... <c>&lt;xsd:element name="AttrAuthoritiesCertValues"
    /// type="CertificateValuesType"/&gt;</c>," an <c>AttrAuthoritiesCertValues</c> element — a different
    /// wrapping element name over the identical schema type — reads through the SAME
    /// <see cref="XAdESCertificateValues.TryRead"/>, since it does not itself check the wrapping element's
    /// local name.
    /// </summary>
    [TestMethod]
    public void AttrAuthoritiesCertValuesReadsThroughTheSharedReader()
    {
        using XmlNodeTable table = Parse($"""
            <AttrAuthoritiesCertValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <EncapsulatedX509Certificate>AQ==</EncapsulatedX509Certificate>
            </AttrAuthoritiesCertValues>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESCertificateValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESCertificateValues? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.HasCount(1, value!.Entries);
            Assert.AreEqual(XAdESCertificateValueKind.EncapsulatedX509Certificate, value.Entries[0].Kind);
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.2 and the
    /// pooling discipline, custody is balanced even on a refusal path: when the first entry already decoded successfully before a second, malformed entry causes the whole read to
    /// refuse, <see cref="XAdESCertificateValues.TryRead"/>'s own outer <c>try</c>/<c>finally</c> releases every buffer already rented, leaving nothing outstanding.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnARefusalAfterPartialDecoding()
    {
        string document = $"""
            <CertificateValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <EncapsulatedX509Certificate>AQ==</EncapsulatedX509Certificate>
              <EncapsulatedX509Certificate Encoding="{XAdESIdentifiers.CerEncodingUri}">AQ==</EncapsulatedX509Certificate>
            </CertificateValues>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESCertificateValues.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESCertificateValues? value, out XAdESReadError error);
            using(value)
            {
                Assert.IsFalse(isRead, "A non-DER second entry must refuse the whole read.");
                Assert.IsNull(value);
                Assert.AreEqual(XAdESReadFailure.EncapsulatedPkiDataNotDerEncoded, error.Failure);
                Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer rented before the refusal was determined must already be released.");
            }
        }
    }
}
