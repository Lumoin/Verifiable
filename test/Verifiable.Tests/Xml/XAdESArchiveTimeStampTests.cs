using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESArchiveTimeStamp.TryRead"/> against clause 5.5.2.1's <c>ArchiveTimeStamp</c>
/// qualifying property "defined in the namespace whose URI is
/// <c>http://uri.etsi.org/01903/v1.4.1#</c>" of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>.
/// </summary>
[TestClass]
internal sealed class XAdESArchiveTimeStampTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string V141 = "http://uri.etsi.org/01903/v1.4.1#";


    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves the v1.4.1-namespace <c>ArchiveTimeStamp</c> reads through the shared <see cref="XAdESTimeStamp"/>
    /// grammar with zero <c>Include</c> elements — the not-distributed (Implicit-mechanism) shape. The default
    /// namespace on the wrapping <c>root</c> stays v1.3.2 — <c>XAdESTimeStampType</c>'s own children
    /// (<c>EncapsulatedTimeStamp</c>) are declared by the v1.3.2 schema regardless of which namespace wraps
    /// them via this type — and <c>ArchiveTimeStamp</c> itself is bound to the v1.4.1 namespace through an
    /// explicit prefix.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.2.1.
    /// </summary>
    [TestMethod]
    public void V141ArchiveTimeStampWithNoIncludesReads()
    {
        string document = $"""
            <root xmlns="{V132}" xmlns:ats="{V141}">
              <ats:ArchiveTimeStamp Id="ats1"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></ats:ArchiveTimeStamp>
            </root>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isFound = table.TryFindElementById("ats1"u8, out int archiveTimeStampIndex, out _);
        Assert.IsTrue(isFound, "The fixture ArchiveTimeStamp must resolve by Id.");
        bool isRead = XAdESArchiveTimeStamp.TryRead(table, archiveTimeStampIndex, BaseMemoryPool.Shared, out XAdESArchiveTimeStamp? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.HasCount(0, value!.TimeStamp.Includes);
        }
    }


    /// <summary>
    /// Proves this reader imposes NO Implicit-mechanism lock — unlike <see cref="XAdESSignatureTimeStamp"/> and
    /// <see cref="XAdESAllDataObjectsTimeStamp"/>, an <c>ArchiveTimeStamp</c> instance carrying <c>Include</c>
    /// elements (the distributed case's Explicit mechanism, clause 5.5.2.4) is accepted at read time, since
    /// clause 5.5.2.3's Implicit-mechanism requirement is scoped to the not-distributed case only.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.2.1.
    /// </summary>
    [TestMethod]
    public void V141ArchiveTimeStampWithIncludesIsNotRefused()
    {
        string document = $"""
            <root xmlns="{V132}" xmlns:ats="{V141}">
              <Target Id="t1"/>
              <ats:ArchiveTimeStamp Id="ats1">
                <Include URI="#t1"/>
                <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
              </ats:ArchiveTimeStamp>
            </root>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isFound = table.TryFindElementById("ats1"u8, out int archiveTimeStampIndex, out _);
        Assert.IsTrue(isFound, "The fixture ArchiveTimeStamp must resolve by Id.");
        bool isRead = XAdESArchiveTimeStamp.TryRead(table, archiveTimeStampIndex, BaseMemoryPool.Shared, out XAdESArchiveTimeStamp? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.HasCount(1, value!.TimeStamp.Includes);
        }
    }


    /// <summary>
    /// Proves this reader's own identity check is scoped to the v1.4.1 namespace exclusively: the deprecated
    /// v1.3.2-namespace <c>ArchiveTimeStamp</c> (Annex D) is a different, unrelated element this type never
    /// accepts.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.2.1.
    /// </summary>
    [TestMethod]
    public void V132NamespacedArchiveTimeStampIsRefused()
    {
        string document = $"""<ArchiveTimeStamp xmlns="{V132}"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></ArchiveTimeStamp>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESArchiveTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "The v1.3.2-namespace element must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves clause 6.3 letter z): "Each <c>ArchiveTimeStamp</c> qualifying property ... may contain more than
    /// one electronic time-stamp issued by different TSAs" — a structural fact this reader already accepts
    /// without narrowing, unlike <see cref="XAdESSignatureTimeStampCardinality"/>'s letter n) narrowing for its
    /// sibling property: TWO <c>EncapsulatedTimeStamp</c> entries within one <c>ArchiveTimeStamp</c> read
    /// successfully.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter z).
    /// </summary>
    [TestMethod]
    public void MultipleEncapsulatedTimeStampEntriesReadPerLetterZ()
    {
        string document = $"""
            <root xmlns="{V132}" xmlns:ats="{V141}">
              <ats:ArchiveTimeStamp Id="ats1">
                <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
                <EncapsulatedTimeStamp>Ag==</EncapsulatedTimeStamp>
              </ats:ArchiveTimeStamp>
            </root>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isFound = table.TryFindElementById("ats1"u8, out int archiveTimeStampIndex, out _);
        Assert.IsTrue(isFound, "The fixture ArchiveTimeStamp must resolve by Id.");
        bool isRead = XAdESArchiveTimeStamp.TryRead(table, archiveTimeStampIndex, BaseMemoryPool.Shared, out XAdESArchiveTimeStamp? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.HasCount(2, value!.TimeStamp.TimeStamps);
        }
    }


    /// <summary>
    /// Proves custody is balanced on the success path via <see cref="MeteredHousePool"/>: the decoded
    /// <c>EncapsulatedTimeStamp</c> content is released once the caller disposes the returned value. The
    /// document itself parses over <see cref="BaseMemoryPool.Shared"/> — the table's own buffers are excluded
    /// from the metered count, per the <see cref="MeteredHousePool"/> fixture idiom.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.2.1.
    /// </summary>
    [TestMethod]
    public void CustodyIsBalancedOnSuccess()
    {
        string document = $"""
            <root xmlns="{V132}" xmlns:ats="{V141}">
              <ats:ArchiveTimeStamp Id="ats1"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></ats:ArchiveTimeStamp>
            </root>
            """;
        using(var metered = new MeteredHousePool())
        {
            using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
            bool isFound = table.TryFindElementById("ats1"u8, out int archiveTimeStampIndex, out _);
            Assert.IsTrue(isFound, "The fixture ArchiveTimeStamp must resolve by Id.");
            bool isRead = XAdESArchiveTimeStamp.TryRead(table, archiveTimeStampIndex, metered.Pool, out XAdESArchiveTimeStamp? value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");

            value!.Dispose();
            Assert.AreEqual(0L, metered.OutstandingCount, "The decoded EncapsulatedTimeStamp buffer must be released on Dispose.");
        }
    }
}
