using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESOtherTimeStamp.TryRead"/> against the <c>OtherTimeStampType</c> data type of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.5: one-or-more <c>ReferenceInfo</c>, an optional
/// <c>ds:CanonicalizationMethod</c>, then EXACTLY ONE <c>EncapsulatedTimeStamp</c>/<c>XMLTimeStamp</c> —
/// every fragment verified against the acquired v132 XSD (lines 103-120), which declares the trailing choice
/// with neither <c>minOccurs</c> nor <c>maxOccurs</c> (both default to one), confirming the cardinality
/// asymmetry with <c>XAdESTimeStampType</c>'s own <c>maxOccurs="unbounded"</c> choice. This type
/// is modeled at grammar level only, — no Part-1 qualifying property instantiates it.
/// </summary>
[TestClass]
internal sealed class XAdESOtherTimeStampTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static string ReferenceInfoFragment(string id)
    {
        return $"""<ReferenceInfo Id="{id}"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>QQ==</ds:DigestValue></ReferenceInfo>""";
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.5, the minimal shape reads: exactly one <c>ReferenceInfo</c>, no
    /// <c>ds:CanonicalizationMethod</c>, exactly one <c>EncapsulatedTimeStamp</c>.
    /// </summary>
    [TestMethod]
    public void MinimalShapeReads()
    {
        string document = $"""
            <OtherTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              {ReferenceInfoFragment("r1")}
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </OtherTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        var owned = new List<PooledMemory>();
        bool isRead = XAdESOtherTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, owned, out XAdESOtherTimeStamp value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.HasCount(1, value.ReferenceInfos);
        Assert.IsFalse(value.HasCanonicalizationMethod);
        Assert.AreEqual(XAdESTimeStampEntryKind.EncapsulatedTimeStamp, value.TimeStamp.Kind);

        foreach(PooledMemory buffer in owned)
        {
            buffer.Dispose();
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.5, multiple <c>ReferenceInfo</c> elements all read, in document order — the acquired v132 XSD's
    /// <c>maxOccurs="unbounded"</c> with no <c>minOccurs</c> (one-or-more).
    /// </summary>
    [TestMethod]
    public void MultipleReferenceInfosReadInDocumentOrder()
    {
        string document = $"""
            <OtherTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              {ReferenceInfoFragment("r1")}
              {ReferenceInfoFragment("r2")}
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </OtherTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        var owned = new List<PooledMemory>();
        bool isRead = XAdESOtherTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, owned, out XAdESOtherTimeStamp value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.HasCount(2, value.ReferenceInfos);
        Assert.AreEqual("r1", Encoding.UTF8.GetString(value.ReferenceInfos[0].Id));
        Assert.AreEqual("r2", Encoding.UTF8.GetString(value.ReferenceInfos[1].Id));

        foreach(PooledMemory buffer in owned)
        {
            buffer.Dispose();
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.5, zero <c>ReferenceInfo</c> elements is refused — the acquired v132 XSD gives it no
    /// <c>minOccurs="0"</c>, so at least one is mandatory.
    /// </summary>
    [TestMethod]
    public void ZeroReferenceInfosIsRefused()
    {
        string document = $"""
            <OtherTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </OtherTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESOtherTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, [], out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "Zero ReferenceInfo elements must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Pins, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.5, the cardinality asymmetry directly: a SECOND <c>EncapsulatedTimeStamp</c> is
    /// refused, because <c>OtherTimeStampType</c>'s trailing choice — unlike <c>XAdESTimeStampType</c>'s own
    /// <c>maxOccurs="unbounded"</c> — carries no <c>maxOccurs</c> at all, defaulting to exactly one.
    /// </summary>
    [TestMethod]
    public void ASecondTimeStampEntryIsRefused()
    {
        string document = $"""
            <OtherTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              {ReferenceInfoFragment("r1")}
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
              <EncapsulatedTimeStamp>Qg==</EncapsulatedTimeStamp>
            </OtherTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESOtherTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, [], out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A second time-stamp entry must be refused — OtherTimeStampType permits exactly one.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.5, the optional <c>ds:CanonicalizationMethod</c> reads its <c>Algorithm</c> when present, in its
    /// fixed position between the <c>ReferenceInfo</c> sequence and the time-stamp entry.
    /// </summary>
    [TestMethod]
    public void CanonicalizationMethodReadsWhenPresent()
    {
        string document = $"""
            <OtherTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              {ReferenceInfoFragment("r1")}
              <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </OtherTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        var owned = new List<PooledMemory>();
        bool isRead = XAdESOtherTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, owned, out XAdESOtherTimeStamp value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasCanonicalizationMethod);
        Assert.AreEqual("http://www.w3.org/2001/10/xml-exc-c14n#", Encoding.UTF8.GetString(value.CanonicalizationMethod.Algorithm));

        foreach(PooledMemory buffer in owned)
        {
            buffer.Dispose();
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.5, the optional <c>Id</c> attribute reads when present.
    /// </summary>
    [TestMethod]
    public void IdAttributeReadsWhenPresent()
    {
        string document = $"""
            <OtherTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}" Id="ots1">
              {ReferenceInfoFragment("r1")}
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </OtherTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        var owned = new List<PooledMemory>();
        bool isRead = XAdESOtherTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, owned, out XAdESOtherTimeStamp value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasId);
        Assert.AreEqual("ots1", Encoding.UTF8.GetString(value.Id));

        foreach(PooledMemory buffer in owned)
        {
            buffer.Dispose();
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.5, custody balances across a <c>ReferenceInfo</c>'s decoded digest AND the trailing
    /// <c>EncapsulatedTimeStamp</c>'s decoded content, via <see cref="MeteredHousePool"/>.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedAfterDisposingAllDecodedContent()
    {
        string document = $"""
            <OtherTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              {ReferenceInfoFragment("r1")}
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </OtherTimeStamp>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            var owned = new List<PooledMemory>();
            bool isRead = XAdESOtherTimeStamp.TryRead(table, table.DocumentElementIndex, metered.Pool, owned, out XAdESOtherTimeStamp value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.HasCount(2, owned);

            foreach(PooledMemory buffer in owned)
            {
                buffer.Dispose();
            }

            Assert.AreEqual(0L, metered.OutstandingCount, "Every decoded buffer must be returned once the caller disposes them.");
        }
    }
}
