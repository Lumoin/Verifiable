using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESTimeStamp.TryRead"/> against the <c>XAdESTimeStampType</c> data type of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.1 (XA-5.1.4.4.1-2): zero-or-more <c>Include</c>, an optional
/// <c>ds:CanonicalizationMethod</c>, then one-or-more <c>EncapsulatedTimeStamp</c>/<c>XMLTimeStamp</c> entries —
/// every fragment verified against the acquired v132 XSD (lines 85-102), incl. the <c>Include</c> document-order
/// preservation XA-5.1.4.4.2.1-2 requires.
/// </summary>
[TestClass]
internal sealed class XAdESTimeStampTests
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves the minimal shape reads: no <c>Include</c>, no <c>ds:CanonicalizationMethod</c>, exactly one
    /// <c>EncapsulatedTimeStamp</c> — the implicit-mechanism shape <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.1's XA-5.1.4.4.1-4 describes.
    /// </summary>
    [TestMethod]
    public void MinimalShapeReads()
    {
        string document = $"""
            <SignatureTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </SignatureTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        var owned = new List<PooledMemory>();
        bool isRead = XAdESTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, owned, out XAdESTimeStamp value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsFalse(value.HasId);
        Assert.HasCount(0, value.Includes);
        Assert.IsFalse(value.HasCanonicalizationMethod);
        Assert.HasCount(1, value.TimeStamps);
        Assert.AreEqual(XAdESTimeStampEntryKind.EncapsulatedTimeStamp, value.TimeStamps[0].Kind);

        foreach(PooledMemory buffer in owned)
        {
            buffer.Dispose();
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.1's XA-5.1.4.4.2.1-2's ordering rule: the document order of <c>Include</c> elements is preserved
    /// in <see cref="XAdESTimeStamp.Includes"/>, unreordered — the order the message-imprint concatenation
    /// (XA-5.1.4.4.2.3-4) depends on.
    /// </summary>
    [TestMethod]
    public void IncludeDocumentOrderIsPreserved()
    {
        string document = $"""
            <SignatureTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <Include URI="#third"/>
              <Include URI="#first"/>
              <Include URI="#second"/>
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </SignatureTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        var owned = new List<PooledMemory>();
        bool isRead = XAdESTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, owned, out XAdESTimeStamp value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.HasCount(3, value.Includes);
        Assert.AreEqual("#third", Encoding.UTF8.GetString(value.Includes[0].Uri));
        Assert.AreEqual("#first", Encoding.UTF8.GetString(value.Includes[1].Uri));
        Assert.AreEqual("#second", Encoding.UTF8.GetString(value.Includes[2].Uri));

        foreach(PooledMemory buffer in owned)
        {
            buffer.Dispose();
        }
    }


    /// <summary>
    /// Proves the trailing choice permits <c>EncapsulatedTimeStamp</c> and <c>XMLTimeStamp</c> to interleave in any combination and multiplicity (<c>maxOccurs="unbounded"</c>, <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.3's XA-5.1.4.3-1's "allow encapsulating more than one electronic time-stamp ... for instance"), and that
    /// <c>XMLTimeStamp</c> content is carried unmodeled.
    /// </summary>
    [TestMethod]
    public void MixedEncapsulatedAndXmlTimeStampEntriesAllRead()
    {
        string document = $"""
            <SignatureTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
              <XMLTimeStamp><SomeVendorTimeStampFormat/></XMLTimeStamp>
              <EncapsulatedTimeStamp>Qg==</EncapsulatedTimeStamp>
            </SignatureTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        var owned = new List<PooledMemory>();
        bool isRead = XAdESTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, owned, out XAdESTimeStamp value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.HasCount(3, value.TimeStamps);
        Assert.AreEqual(XAdESTimeStampEntryKind.EncapsulatedTimeStamp, value.TimeStamps[0].Kind);
        Assert.AreEqual(XAdESTimeStampEntryKind.XmlTimeStamp, value.TimeStamps[1].Kind);
        Assert.AreEqual(XAdESTimeStampEntryKind.EncapsulatedTimeStamp, value.TimeStamps[2].Kind);
        Assert.HasCount(1, value.TimeStamps[1].XmlTimeStamp.ContentNodeIndices);

        foreach(PooledMemory buffer in owned)
        {
            buffer.Dispose();
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.1, the optional <c>ds:CanonicalizationMethod</c> reads its <c>Algorithm</c> when present.
    /// </summary>
    [TestMethod]
    public void CanonicalizationMethodReadsWhenPresent()
    {
        string document = $"""
            <SignatureTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </SignatureTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        var owned = new List<PooledMemory>();
        bool isRead = XAdESTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, owned, out XAdESTimeStamp value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasCanonicalizationMethod);
        Assert.AreEqual("http://www.w3.org/2001/10/xml-exc-c14n#", Encoding.UTF8.GetString(value.CanonicalizationMethod.Algorithm));

        foreach(PooledMemory buffer in owned)
        {
            buffer.Dispose();
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.1, a second <c>ds:CanonicalizationMethod</c> is refused — the acquired v132 XSD's restriction
    /// carries <c>minOccurs="0"</c> with no <c>maxOccurs</c>, i.e. at most one.
    /// </summary>
    [TestMethod]
    public void DuplicateCanonicalizationMethodIsRefused()
    {
        string document = $"""
            <SignatureTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" xmlns:ds="{DsNamespace}">
              <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
              <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </SignatureTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, [], out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A second CanonicalizationMethod must be refused.");
        Assert.AreEqual(XAdESReadFailure.DuplicateCoreChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.1, zero <c>EncapsulatedTimeStamp</c>/<c>XMLTimeStamp</c> entries is refused — the trailing choice
    /// carries no explicit <c>minOccurs</c>, so it defaults to one, applied <c>maxOccurs="unbounded"</c>
    /// times: one-or-more, never zero.
    /// </summary>
    [TestMethod]
    public void ZeroTimeStampEntriesIsRefused()
    {
        string document = $"""<SignatureTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}"><Include URI="#x"/></SignatureTimeStamp>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, [], out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "Zero time-stamp entries must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.1, an <c>Include</c> appearing after the choice has started is refused — the fixed
    /// <c>xsd:sequence</c> (<c>Include*, ds:CanonicalizationMethod?, choice+</c>) never permits it to appear
    /// there, regardless of the fact that <c>Include</c> is itself a recognized element name elsewhere in
    /// this same type.
    /// </summary>
    [TestMethod]
    public void IncludeAfterATimeStampEntryIsRefused()
    {
        string document = $"""
            <SignatureTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
              <Include URI="#late"/>
            </SignatureTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, [], out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An out-of-order Include must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.1, a wholly unrecognized trailing element is refused.
    /// </summary>
    [TestMethod]
    public void UnknownTrailingElementIsRefused()
    {
        string document = $"""
            <SignatureTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
              <NotPartOfThisType/>
            </SignatureTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, [], out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized trailing element must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.1, the optional <c>Id</c> attribute reads when present.
    /// </summary>
    [TestMethod]
    public void IdAttributeReadsWhenPresent()
    {
        string document = $"""
            <SignatureTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" Id="ts1">
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </SignatureTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        var owned = new List<PooledMemory>();
        bool isRead = XAdESTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, owned, out XAdESTimeStamp value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasId);
        Assert.AreEqual("ts1", Encoding.UTF8.GetString(value.Id));

        foreach(PooledMemory buffer in owned)
        {
            buffer.Dispose();
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.1, an unrecognized attribute is refused fail-closed.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeIsRefused()
    {
        string document = $"""
            <SignatureTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" unexpected="value">
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </SignatureTimeStamp>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, [], out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.1, custody balances on the success path across multiple <c>EncapsulatedTimeStamp</c> entries, via
    /// <see cref="MeteredHousePool"/>.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedAfterDisposingAllDecodedEntries()
    {
        string document = $"""
            <SignatureTimeStamp xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
              <EncapsulatedTimeStamp>Qg==</EncapsulatedTimeStamp>
            </SignatureTimeStamp>
            """;

        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            var owned = new List<PooledMemory>();
            bool isRead = XAdESTimeStamp.TryRead(table, table.DocumentElementIndex, metered.Pool, owned, out XAdESTimeStamp value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
            Assert.HasCount(2, owned);

            foreach(PooledMemory buffer in owned)
            {
                buffer.Dispose();
            }

            Assert.AreEqual(0L, metered.OutstandingCount, "Every decoded EncapsulatedTimeStamp buffer must be returned once the caller disposes them.");
        }
    }
}
