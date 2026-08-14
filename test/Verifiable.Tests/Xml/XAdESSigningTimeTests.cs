using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESSigningTime.TryRead"/> against clause 5.2.1's <c>SigningTime</c> qualifying
/// property of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: element-reading wiring only — the <c>xsd:dateTime</c> lexical grammar
/// itself is proven exhaustively in <see cref="XAdESDateTimeTests"/> against the raw span.
/// </summary>
[TestClass]
internal sealed class XAdESSigningTimeTests
{
    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's minimal shape — the bare
    /// <c>&lt;xsd:element name="SigningTime" type="xsd:dateTime"/&gt;</c> declaration — reads, and that the
    /// decomposed value round-trips through <see cref="XAdESSigningTime.Value"/>.
    /// </summary>
    [TestMethod]
    public void ValidSigningTimeReads()
    {
        using XmlNodeTable table = Parse($"""<SigningTime xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">2024-06-15T12:30:45Z</SigningTime>""");
        bool isRead = XAdESSigningTime.TryRead(table, table.DocumentElementIndex, out XAdESSigningTime value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.AreEqual(2024L, value.Value.Year);
        Assert.AreEqual(6, value.Value.Month);
        Assert.AreEqual(15, value.Value.Day);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's content is genuinely mandatory: empty
    /// element content is refused through <see cref="XAdESReadFailure.InvalidDateTimeLexicalForm"/> — the
    /// empty span matches no <c>xsd:dateTime</c> production, so "content absent" is not a distinct read
    /// failure from "content malformed."
    /// </summary>
    [TestMethod]
    public void EmptyContentIsRefused()
    {
        using XmlNodeTable table = Parse($"""<SigningTime xmlns="{XAdESIdentifiers.XAdESNamespaceV132}"/>""");
        bool isRead = XAdESSigningTime.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "Empty content must be refused.");
        Assert.AreEqual(XAdESReadFailure.InvalidDateTimeLexicalForm, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1, malformed <c>xsd:dateTime</c> content (here,
    /// a value missing its seconds field) is refused through the same
    /// <see cref="XAdESReadFailure.InvalidDateTimeLexicalForm"/> member.
    /// </summary>
    [TestMethod]
    public void MalformedContentIsRefused()
    {
        using XmlNodeTable table = Parse($"""<SigningTime xmlns="{XAdESIdentifiers.XAdESNamespaceV132}">2024-06-15T12:30Z</SigningTime>""");
        bool isRead = XAdESSigningTime.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "Malformed content must be refused.");
        Assert.AreEqual(XAdESReadFailure.InvalidDateTimeLexicalForm, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1, an unrecognized attribute is refused
    /// fail-closed — the acquired v132 XSD's bare <c>xsd:element name="SigningTime" type="xsd:dateTime"</c>
    /// declaration carries no attribute of any kind.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeIsRefused()
    {
        using XmlNodeTable table = Parse($"""<SigningTime xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" unexpected="value">2024-06-15T12:30:45Z</SigningTime>""");
        bool isRead = XAdESSigningTime.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1, an element child is refused —
    /// <c>xsd:dateTime</c> is simple content, so an element child can never be part of it.
    /// </summary>
    [TestMethod]
    public void ElementChildIsRefused()
    {
        using XmlNodeTable table = Parse($"""<SigningTime xmlns="{XAdESIdentifiers.XAdESNamespaceV132}"><Unexpected/></SigningTime>""");
        bool isRead = XAdESSigningTime.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An element child must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnexpectedElementContent, error.Failure);
    }
}
