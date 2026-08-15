using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs anchoring clause 6.3 letter l) of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see> — "the number of occurrences allowed of the concerned XML component within one
/// <c>DataObjectFormat</c> element, shall be as indicated in column 'Cardinality'" — to the reader that already
/// enforces every one of those cardinalities, <see cref="XAdESDataObjectFormat.TryRead"/>: no new production
/// code, since Table 2's own rows t09-t13 (<c>Description</c>/<c>ObjectIdentifier</c>/<c>MimeType</c>/
/// <c>Encoding</c> each 0-or-1, <c>ObjectReference</c> exactly 1) are already read-time refusals, per the
/// "verifier-checkable letter" framing.
/// </summary>
[TestClass]
internal sealed class XAdESDataObjectFormatChildCardinalityTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";


    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves letter l)'s <c>ObjectReference</c> cardinality — Table 2 row t13, "shall be present ... 1" — by
    /// its absence: <see cref="XAdESReadFailure.MissingRequiredAttribute"/>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter l).
    /// </summary>
    [TestMethod]
    public void ObjectReferenceIsMandatoryPerLetterL()
    {
        using XmlNodeTable table = Parse($"""<DataObjectFormat xmlns="{V132}"><MimeType>text/plain</MimeType></DataObjectFormat>""");
        bool isRead = XAdESDataObjectFormat.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An absent ObjectReference must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredAttribute, error.Failure);
    }


    /// <summary>
    /// Proves letter l)'s <c>MimeType</c> cardinality — Table 2 row t11, "0 or 1" — a second <c>MimeType</c>
    /// child is refused as a duplicate.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter l).
    /// </summary>
    [TestMethod]
    public void MimeTypeIsAtMostOnePerLetterL()
    {
        using XmlNodeTable table = Parse($"""
            <DataObjectFormat xmlns="{V132}" ObjectReference="#ref1">
              <MimeType>text/plain</MimeType>
              <MimeType>text/html</MimeType>
            </DataObjectFormat>
            """);
        bool isRead = XAdESDataObjectFormat.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A second MimeType child must be refused.");
        Assert.AreEqual(XAdESReadFailure.DuplicateCoreChild, error.Failure);
    }


    /// <summary>
    /// Proves letter l)'s <c>Description</c>/<c>ObjectIdentifier</c>/<c>MimeType</c>/<c>Encoding</c>
    /// cardinalities — Table 2 rows t09-t12, all "0 or 1" — every one of the four may be present TOGETHER,
    /// each exactly once, in the fixed schema order.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter l).
    /// </summary>
    [TestMethod]
    public void AllFourOptionalChildrenAtCardinalityOneReadTogether()
    {
        using XmlNodeTable table = Parse($"""
            <DataObjectFormat xmlns="{V132}" ObjectReference="#ref1">
              <Description>A plain text document</Description>
              <ObjectIdentifier><Identifier>http://example.com/format/1</Identifier></ObjectIdentifier>
              <MimeType>text/plain</MimeType>
              <Encoding>http://uri.etsi.org/01903/v1.2.2#DER</Encoding>
            </DataObjectFormat>
            """);
        bool isRead = XAdESDataObjectFormat.TryRead(table, table.DocumentElementIndex, out XAdESDataObjectFormat value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasDescription);
        Assert.IsTrue(value.HasObjectIdentifier);
        Assert.IsTrue(value.HasMimeType);
        Assert.IsTrue(value.HasEncoding);
    }
}
