using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESValidationData.TryRead"/>/<see cref="XAdESValidationData.TryReadAnyValidationData"/>
/// against clause 5.4.6's <c>AnyValidationData</c> qualifying property and the shared <c>ValidationDataType</c>
/// core of <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>.
/// </summary>
[TestClass]
internal sealed class XAdESValidationDataTests
{
    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static string Document(string body, bool includeUri = false)
    {
        string uriAttribute = includeUri ? """ URI="#ts1" """ : string.Empty;

        return $"""
            <AnyValidationData xmlns="{XAdESIdentifiers.XAdESNamespaceV141}" xmlns:xades="{XAdESIdentifiers.XAdESNamespaceV132}"{uriAttribute}>
              {body}
            </AnyValidationData>
            """;
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.6's "The
    /// <c>CertificateValues</c> child element shall contain the base-64 encoding of DER-encoded X.509
    /// certificates used in the validation of the XAdES signature," a <c>CertificateValues</c>-only instance
    /// reads through the shared <see cref="XAdESCertificateValues"/> reader, and custody balances to zero once
    /// the caller disposes the returned value.
    /// </summary>
    [TestMethod]
    public void CertificateValuesChildAloneReadsAndCustodyBalances()
    {
        string document = Document("""<xades:CertificateValues><xades:EncapsulatedX509Certificate>AQ==</xades:EncapsulatedX509Certificate></xades:CertificateValues>""");

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESValidationData.TryReadAnyValidationData(table, table.DocumentElementIndex, metered.Pool, out XAdESValidationData? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.IsTrue(value!.HasCertificateValues);
            Assert.HasCount(1, value.CertificateValues!.Entries);
            Assert.IsFalse(value.HasRevocationValues);

            value.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "The decoded EncapsulatedX509Certificate buffer must be released on Dispose.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.6's "The
    /// <c>RevocationValues</c> child element ... Its syntax shall be as specified in clause 5.4.3," a
    /// <c>RevocationValues</c>-only instance reads through the shared <see cref="XAdESRevocationValues"/>
    /// reader.
    /// </summary>
    [TestMethod]
    public void RevocationValuesChildAloneReads()
    {
        string document = Document("""<xades:RevocationValues><xades:CRLValues><xades:EncapsulatedCRLValue>AQ==</xades:EncapsulatedCRLValue></xades:CRLValues></xades:RevocationValues>""");

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESValidationData.TryReadAnyValidationData(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESValidationData? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsFalse(value!.HasCertificateValues);
            Assert.IsTrue(value.HasRevocationValues);
            Assert.IsTrue(value.RevocationValues!.HasCrlValues);
        }
    }


    /// <summary>
    /// Proves, against clause 5.4.6's acquired v141 <c>ValidationDataType</c> schema, both children — in
    /// their fixed sequence order, <c>CertificateValues</c> then <c>RevocationValues</c> — read together.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.6.
    /// </summary>
    [TestMethod]
    public void BothChildrenInFixedOrderRead()
    {
        string document = Document("""
            <xades:CertificateValues><xades:EncapsulatedX509Certificate>AQ==</xades:EncapsulatedX509Certificate></xades:CertificateValues>
            <xades:RevocationValues><xades:CRLValues><xades:EncapsulatedCRLValue>AQ==</xades:EncapsulatedCRLValue></xades:CRLValues></xades:RevocationValues>
            """);

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESValidationData.TryReadAnyValidationData(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESValidationData? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.HasCertificateValues);
            Assert.IsTrue(value.HasRevocationValues);
        }
    }


    /// <summary>
    /// Proves clause 5.4.6's "The <c>AnyValidationData</c> qualifying property shall contain the certificates
    /// identified in 1), or the revocation data identified in 2), or both of them": a completely empty
    /// <c>AnyValidationData</c> element — neither child present, even though both are individually
    /// schema-optional — is refused, the same schema-permits/prose-forbids pattern
    /// <see cref="XAdESSignerRoleV2"/>'s own empty-property rule applies.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.6.
    /// </summary>
    [TestMethod]
    public void EmptyElementWithNeitherChildIsRefused()
    {
        using XmlNodeTable table = Parse(Document(string.Empty), BaseMemoryPool.Shared);
        bool isRead = XAdESValidationData.TryReadAnyValidationData(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESValidationData? value, out XAdESReadError error);
        using(value)
        {
            Assert.IsFalse(isRead, "An AnyValidationData element with neither child must be refused.");
            Assert.IsNull(value);
            Assert.AreEqual(XAdESReadFailure.EmptyAnyValidationData, error.Failure);
        }
    }


    /// <summary>
    /// Proves the shared <see cref="XAdESValidationData.TryRead"/> core itself — unlike
    /// <see cref="XAdESValidationData.TryReadAnyValidationData"/> — does NOT enforce the at-least-one-child
    /// floor: a completely empty <c>ValidationDataType</c> instance reads successfully through the shared
    /// core, since the schema itself declares both children <c>minOccurs="0"</c> and the floor is clause
    /// 5.4.6's own per-property narrowing, enforced only by <see cref="XAdESValidationData.TryReadAnyValidationData"/>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.6.
    /// </summary>
    [TestMethod]
    public void SharedCoreReadsACompletelyEmptyInstance()
    {
        using XmlNodeTable table = Parse(Document(string.Empty), BaseMemoryPool.Shared);
        bool isRead = XAdESValidationData.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESValidationData? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"The shared ValidationDataType core must read an empty instance, but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsFalse(value!.HasCertificateValues);
            Assert.IsFalse(value.HasRevocationValues);
        }
    }


    /// <summary>
    /// Proves clause 5.4.6's "The <c>AnyValidationData</c> qualifying property shall not have the <c>URI</c>
    /// attribute": a present <c>URI</c> attribute is refused by <see cref="XAdESValidationData.TryReadAnyValidationData"/>,
    /// even though the shared <c>ValidationDataType</c> schema itself declares <c>URI</c> as optional (clause
    /// 5.5.1.2 permits it for the sibling <c>TimeStampValidationData</c> property that reuses the same type).
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.6.
    /// </summary>
    [TestMethod]
    public void PresentUriAttributeIsRefused()
    {
        using XmlNodeTable table = Parse(Document(string.Empty, includeUri: true), BaseMemoryPool.Shared);
        bool isRead = XAdESValidationData.TryReadAnyValidationData(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESValidationData? value, out XAdESReadError error);
        using(value)
        {
            Assert.IsFalse(isRead, "A URI attribute on AnyValidationData must be refused.");
            Assert.IsNull(value);
            Assert.AreEqual(XAdESReadFailure.AnyValidationDataUriNotPermitted, error.Failure);
        }
    }


    /// <summary>
    /// Proves the shared <see cref="XAdESValidationData.TryRead"/> core itself — unlike
    /// <see cref="XAdESValidationData.TryReadAnyValidationData"/> — does NOT refuse a present <c>URI</c>
    /// attribute: the schema's own <c>ValidationDataType</c> declares it optional, and the URI-forbidden rule
    /// is clause 5.4.6's own per-property narrowing, applied at the <c>AnyValidationData</c> binding only —
    /// the shared type keeps the slot; the binding forbids it.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.6.
    /// </summary>
    [TestMethod]
    public void SharedCoreDoesNotRefuseAPresentUriAttribute()
    {
        using XmlNodeTable table = Parse(Document(string.Empty, includeUri: true), BaseMemoryPool.Shared);
        bool isRead = XAdESValidationData.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESValidationData? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"The shared ValidationDataType core must read a present URI attribute, but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.HasUri);
            Assert.AreEqual("#ts1", Encoding.UTF8.GetString(value.Uri));
        }
    }


    /// <summary>
    /// Proves clause 5.4.6's <c>Id</c> attribute reads when present — "The <c>Id</c> attribute shall be used
    /// for referencing this element from elsewhere."
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.6.
    /// </summary>
    [TestMethod]
    public void IdAttributeReadsWhenPresent()
    {
        string document = $"""
            <AnyValidationData xmlns="{XAdESIdentifiers.XAdESNamespaceV141}" xmlns:xades="{XAdESIdentifiers.XAdESNamespaceV132}" Id="avd1">
              <xades:CertificateValues><xades:EncapsulatedX509Certificate>AQ==</xades:EncapsulatedX509Certificate></xades:CertificateValues>
            </AnyValidationData>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESValidationData.TryReadAnyValidationData(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESValidationData? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(value!.HasId);
            Assert.AreEqual("avd1", Encoding.UTF8.GetString(value.Id));
        }
    }


    /// <summary>
    /// Proves an unrecognized attribute is refused — <c>ValidationDataType</c> declares only <c>Id</c> and
    /// <c>URI</c>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.6.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeIsRefused()
    {
        string document = $"""
            <AnyValidationData xmlns="{XAdESIdentifiers.XAdESNamespaceV141}" xmlns:xades="{XAdESIdentifiers.XAdESNamespaceV132}" unexpected="value"/>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESValidationData.TryReadAnyValidationData(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }


    /// <summary>
    /// Proves clause 5.4.6's fixed sequence order — <c>RevocationValues</c> before <c>CertificateValues</c> —
    /// is refused.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.6.
    /// </summary>
    [TestMethod]
    public void OutOfOrderChildIsRefused()
    {
        string document = Document("""
            <xades:RevocationValues><xades:CRLValues><xades:EncapsulatedCRLValue>AQ==</xades:EncapsulatedCRLValue></xades:CRLValues></xades:RevocationValues>
            <xades:CertificateValues><xades:EncapsulatedX509Certificate>AQ==</xades:EncapsulatedX509Certificate></xades:CertificateValues>
            """);

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESValidationData.TryReadAnyValidationData(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An out-of-order child must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves clause 5.4.6's fixed at-most-once sequence — a repeated <c>CertificateValues</c> child — is
    /// refused as a duplicate.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.6.
    /// </summary>
    [TestMethod]
    public void DuplicateChildIsRefused()
    {
        string document = Document("""
            <xades:CertificateValues><xades:EncapsulatedX509Certificate>AQ==</xades:EncapsulatedX509Certificate></xades:CertificateValues>
            <xades:CertificateValues><xades:EncapsulatedX509Certificate>AQ==</xades:EncapsulatedX509Certificate></xades:CertificateValues>
            """);

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESValidationData.TryReadAnyValidationData(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A duplicate child must be refused.");
        Assert.AreEqual(XAdESReadFailure.DuplicateCoreChild, error.Failure);
    }


    /// <summary>
    /// Proves a child that is neither <c>CertificateValues</c> nor <c>RevocationValues</c> is refused.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.6.
    /// </summary>
    [TestMethod]
    public void UnrecognizedChildIsRefused()
    {
        string document = Document("<Unexpected/>");

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESValidationData.TryReadAnyValidationData(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized child must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.4.6 and the
    /// pooling discipline, custody is balanced even on a refusal path: when a well-formed <c>CertificateValues</c> child already decoded successfully before the trailing
    /// <c>URI</c>-forbidden narrowing refuses the whole read, <see cref="XAdESValidationData.TryReadAnyValidationData"/> disposes the nested <see
    /// cref="XAdESValidationData.CertificateValues"/> reader before returning, leaving nothing outstanding.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedWhenTheUriNarrowingRefusesAfterSuccessfulDecoding()
    {
        string document = Document("""<xades:CertificateValues><xades:EncapsulatedX509Certificate>AQ==</xades:EncapsulatedX509Certificate></xades:CertificateValues>""", includeUri: true);

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isRead = XAdESValidationData.TryReadAnyValidationData(table, table.DocumentElementIndex, metered.Pool, out XAdESValidationData? value, out XAdESReadError error);
            using(value)
            {
                Assert.IsFalse(isRead, "A URI attribute must refuse the whole read even after successful child decoding.");
                Assert.IsNull(value);
                Assert.AreEqual(XAdESReadFailure.AnyValidationDataUriNotPermitted, error.Failure);
                Assert.AreEqual(0L, metered.OutstandingCount, "The nested CertificateValues reader's buffer must already be released.");
            }
        }
    }
}
