using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESRevocationValues.TryRead"/> against clause 5.4.3's <c>RevocationValues</c>
/// qualifying property and clause 5.4.5's <c>AttributeRevocationValues</c> qualifying property of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see> — both bound to the SAME <c>RevocationValuesType</c> schema type.
/// </summary>
[TestClass]
internal sealed class XAdESRevocationValuesTests
{
    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.3's "Each
    /// <c>EncapsulatedCRLValue</c> child of <c>CRLValues</c> element shall contain the base-64 encoding of a
    /// DER-encoded X.509 CRL," a <c>CRLValues</c>-only instance decodes its content, and custody balances to
    /// zero once the caller disposes the returned value.
    /// </summary>
    [TestMethod]
    public void CrlValuesAloneDecodesAndCustodyBalances()
    {
        byte[] der = [0x30, 0x03, 0x02, 0x01, 0x2A];
        string document = $"""
            <RevocationValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <CRLValues><EncapsulatedCRLValue>{Convert.ToBase64String(der)}</EncapsulatedCRLValue></CRLValues>
            </RevocationValues>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESRevocationValues? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.IsTrue(value!.HasCrlValues);
            Assert.HasCount(1, value.CrlValues);
            Assert.AreSequenceEqual(der, value.CrlValues[0].Content.AsReadOnlySpan().ToArray());
            Assert.IsFalse(value.HasOcspValues);
            Assert.IsFalse(value.HasOtherValues);

            value.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "The decoded EncapsulatedCRLValue buffer must be released on Dispose.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.3's "Each
    /// <c>EncapsulatedOCSPValue</c> child of <c>OCSPValues</c> element shall contain the base-64 encoding of a
    /// DER-encoded <c>OCSPResponse</c>," an <c>OCSPValues</c>-only instance decodes its content.
    /// </summary>
    [TestMethod]
    public void OcspValuesAloneDecodes()
    {
        string document = $"""
            <RevocationValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <OCSPValues><EncapsulatedOCSPValue>AQ==</EncapsulatedOCSPValue></OCSPValues>
            </RevocationValues>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESRevocationValues? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.HasOcspValues);
            Assert.HasCount(1, value.OcspValues);
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.3's "The
    /// <c>OtherValues</c> element provides a placeholder for other revocation information," an
    /// <c>OtherValues</c>-only instance is carried unmodeled with no pooled content decoded.
    /// </summary>
    [TestMethod]
    public void OtherValuesAloneIsCarriedUnmodeled()
    {
        string document = $"""
            <RevocationValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <OtherValues><OtherValue><Foreign/></OtherValue></OtherValues>
            </RevocationValues>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESRevocationValues? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.IsTrue(value!.HasOtherValues);
            Assert.HasCount(1, value.OtherValues);

            value.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "OtherValues carries no pooled content.");
        }
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.3's acquired
    /// v132 <c>RevocationValuesType</c> schema, all three children, in their fixed schema order (<c>CRLValues,
    /// OCSPValues, OtherValues</c>), read together.
    /// </summary>
    [TestMethod]
    public void AllThreeChildrenInFixedOrderRead()
    {
        string document = $"""
            <RevocationValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <CRLValues><EncapsulatedCRLValue>AQ==</EncapsulatedCRLValue></CRLValues>
              <OCSPValues><EncapsulatedOCSPValue>AQ==</EncapsulatedOCSPValue></OCSPValues>
              <OtherValues><OtherValue>content</OtherValue></OtherValues>
            </RevocationValues>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESRevocationValues? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.HasCrlValues);
            Assert.IsTrue(value.HasOcspValues);
            Assert.IsTrue(value.HasOtherValues);
        }
    }


    /// <summary>
    /// Proves, per clause 5.4.3's acquired v132 <c>RevocationValuesType</c> schema — every child of its
    /// <c>xsd:sequence</c> individually <c>minOccurs="0"</c>, with no matching clause-5.4 "empty ... shall not
    /// be generated" floor — a completely empty <c>RevocationValues</c> element reads successfully with none
    /// of the three lists present.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.3.
    /// </summary>
    [TestMethod]
    public void EmptyElementReadsWithNoListsPresent()
    {
        using XmlNodeTable table = Parse($"""<RevocationValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}"/>""", BaseMemoryPool.Shared);
        bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESRevocationValues? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"An empty RevocationValues element must read, but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsFalse(value!.HasCrlValues);
            Assert.IsFalse(value.HasOcspValues);
            Assert.IsFalse(value.HasOtherValues);
        }
    }


    /// <summary>
    /// Proves, per clause 5.4.3's <c>CRLValuesType</c> — <c>EncapsulatedCRLValue</c> declared
    /// <c>maxOccurs="unbounded"</c> with the schema default <c>minOccurs="1"</c> — a present-but-empty
    /// <c>CRLValues</c> element is refused, the same "non-empty sequence" enforcement
    /// <see cref="XAdESSignerRoleV2"/> already applies to its own optional lists.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.3.
    /// </summary>
    [TestMethod]
    public void EmptyCrlValuesListIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <RevocationValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <CRLValues/>
            </RevocationValues>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An empty CRLValues element must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves the same "non-empty sequence" enforcement as <see cref="EmptyCrlValuesListIsRefused"/> for
    /// <c>OCSPValues</c>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.3.
    /// </summary>
    [TestMethod]
    public void EmptyOcspValuesListIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <RevocationValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <OCSPValues/>
            </RevocationValues>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An empty OCSPValues element must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves the same "non-empty sequence" enforcement as <see cref="EmptyCrlValuesListIsRefused"/> for
    /// <c>OtherValues</c>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.3.
    /// </summary>
    [TestMethod]
    public void EmptyOtherValuesListIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <RevocationValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <OtherValues/>
            </RevocationValues>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An empty OtherValues element must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves clause 5.4.3's fixed sequence order — an out-of-order child (<c>OCSPValues</c> before
    /// <c>CRLValues</c>) — is refused.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.3.
    /// </summary>
    [TestMethod]
    public void OutOfOrderChildIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <RevocationValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <OCSPValues><EncapsulatedOCSPValue>AQ==</EncapsulatedOCSPValue></OCSPValues>
              <CRLValues><EncapsulatedCRLValue>AQ==</EncapsulatedCRLValue></CRLValues>
            </RevocationValues>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An out-of-order child must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves clause 5.4.3's fixed at-most-once sequence — a repeated <c>CRLValues</c> child — is refused as a
    /// duplicate.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.3.
    /// </summary>
    [TestMethod]
    public void DuplicateChildIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <RevocationValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <CRLValues><EncapsulatedCRLValue>AQ==</EncapsulatedCRLValue></CRLValues>
              <CRLValues><EncapsulatedCRLValue>AQ==</EncapsulatedCRLValue></CRLValues>
            </RevocationValues>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A duplicate child must be refused.");
        Assert.AreEqual(XAdESReadFailure.DuplicateCoreChild, error.Failure);
    }


    /// <summary>
    /// Proves clause 5.4.3's DER-narrowing of <c>EncapsulatedCRLValue</c> — "shall contain the base-64
    /// encoding of a DER-encoded X.509 CRL" — refuses a non-DER <c>Encoding</c> value.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.3.
    /// </summary>
    [TestMethod]
    public void NonDerEncapsulatedCrlValueIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <RevocationValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <CRLValues><EncapsulatedCRLValue Encoding="{XAdESIdentifiers.PerEncodingUri}">AQ==</EncapsulatedCRLValue></CRLValues>
            </RevocationValues>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A PER-encoded EncapsulatedCRLValue must be refused: clause 5.4.3 narrows the encoding to DER.");
        Assert.AreEqual(XAdESReadFailure.EncapsulatedPkiDataNotDerEncoded, error.Failure);
    }


    /// <summary>
    /// Proves clause 5.4.3's DER-narrowing of <c>EncapsulatedOCSPValue</c> — "shall contain the base-64
    /// encoding of a DER-encoded <c>OCSPResponse</c>" — refuses a non-DER <c>Encoding</c> value.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.3.
    /// </summary>
    [TestMethod]
    public void NonDerEncapsulatedOcspValueIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <RevocationValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <OCSPValues><EncapsulatedOCSPValue Encoding="{XAdESIdentifiers.XerEncodingUri}">AQ==</EncapsulatedOCSPValue></OCSPValues>
            </RevocationValues>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An XER-encoded EncapsulatedOCSPValue must be refused: clause 5.4.3 narrows the encoding to DER.");
        Assert.AreEqual(XAdESReadFailure.EncapsulatedPkiDataNotDerEncoded, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.3, an
    /// unrecognized attribute on the <c>RevocationValues</c> element itself is refused — <c>RevocationValuesType</c>
    /// declares only <c>Id</c>.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeOnWrappingElementIsRefused()
    {
        using XmlNodeTable table = Parse($"""<RevocationValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" unexpected="value"/>""", BaseMemoryPool.Shared);
        bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }


    /// <summary>
    /// Proves an unrecognized attribute on the <c>CRLValues</c> list element itself is refused —
    /// <c>CRLValuesType</c> declares no attribute of its own.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.3.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeOnCrlValuesIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <RevocationValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <CRLValues unexpected="value"><EncapsulatedCRLValue>AQ==</EncapsulatedCRLValue></CRLValues>
            </RevocationValues>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized attribute on CRLValues must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.5's "shall be
    /// defined as in XML Schema file ... <c>&lt;xsd:element name="AttributeRevocationValues"
    /// type="RevocationValuesType"/&gt;</c>," an <c>AttributeRevocationValues</c> element — a different
    /// wrapping element name over the identical schema type — reads through the SAME
    /// <see cref="XAdESRevocationValues.TryRead"/>, since it does not itself check the wrapping element's
    /// local name.
    /// </summary>
    [TestMethod]
    public void AttributeRevocationValuesReadsThroughTheSharedReader()
    {
        using XmlNodeTable table = Parse($"""
            <AttributeRevocationValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <CRLValues><EncapsulatedCRLValue>AQ==</EncapsulatedCRLValue></CRLValues>
            </AttributeRevocationValues>
            """, BaseMemoryPool.Shared);
        bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESRevocationValues? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.HasCrlValues);
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.3 and the
    /// pooling discipline, custody is balanced even on a refusal path: when <c>CRLValues</c> already decoded successfully before a non-DER <c>OCSPValues</c> entry causes the whole
    /// read to refuse, custody still balances to zero.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnARefusalAfterPartialDecoding()
    {
        string document = $"""
            <RevocationValues xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <CRLValues><EncapsulatedCRLValue>AQ==</EncapsulatedCRLValue></CRLValues>
              <OCSPValues><EncapsulatedOCSPValue Encoding="{XAdESIdentifiers.CerEncodingUri}">AQ==</EncapsulatedOCSPValue></OCSPValues>
            </RevocationValues>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESRevocationValues.TryRead(table, table.DocumentElementIndex, metered.Pool, out XAdESRevocationValues? value, out XAdESReadError error);
            using(value)
            {
                Assert.IsFalse(isRead, "A non-DER OCSPValues entry must refuse the whole read.");
                Assert.IsNull(value);
                Assert.AreEqual(XAdESReadFailure.EncapsulatedPkiDataNotDerEncoded, error.Failure);
                Assert.AreEqual(0L, metered.OutstandingCount, "Every buffer rented before the refusal was determined must already be released.");
            }
        }
    }
}
