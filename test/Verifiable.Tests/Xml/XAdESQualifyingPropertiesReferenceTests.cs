using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESQualifyingPropertiesReference"/> against clause 4.4.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: the attribute-only <c>QualifyingPropertiesReferenceType</c> shape
/// (XA-4.4.3-2/-5) and the permanent verification refusal requires for indirect incorporation.
/// </summary>
[TestClass]
internal sealed class XAdESQualifyingPropertiesReferenceTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.3's XA-4.4.3-2/-5: a well-formed <c>QualifyingPropertiesReference</c> with a mandatory <c>URI</c>
    /// and optional <c>Id</c> reads, capturing both exact-character.
    /// </summary>
    [TestMethod]
    public void WellFormedReferenceReads()
    {
        string document = $"""<QualifyingPropertiesReference xmlns="{V132}" URI="external.xml#qp1" Id="qpr1"/>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESQualifyingPropertiesReference.TryRead(table, table.DocumentElementIndex, out XAdESQualifyingPropertiesReference value, out XAdESReadError error);

        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.AreSequenceEqual("external.xml#qp1"u8.ToArray(), value.Uri.ToArray());
        Assert.IsTrue(value.HasId);
        Assert.AreSequenceEqual("qpr1"u8.ToArray(), value.Id.ToArray());
    }


    /// <summary>
    /// Proves the mandatory <c>URI</c> attribute (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.3's XA-4.4.3-2's <c>use="required"</c>) is refused when absent.
    /// </summary>
    [TestMethod]
    public void MissingUriAttributeIsRefused()
    {
        string document = $"""<QualifyingPropertiesReference xmlns="{V132}"/>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESQualifyingPropertiesReference.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "A missing URI attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredAttribute, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.3, the type declares no child elements at all — a stray element content refuses.
    /// </summary>
    [TestMethod]
    public void ChildElementContentIsRefused()
    {
        string document = $"""<QualifyingPropertiesReference xmlns="{V132}" URI="external.xml#qp1"><Bogus/></QualifyingPropertiesReference>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESQualifyingPropertiesReference.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "Child element content must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves <see cref="XAdESQualifyingPropertiesReference.RefuseVerification"/> always refuses with <see cref="XAdESProcessingFailure.IndirectIncorporationNotSupported"/> — the "modeled at read, refused at verification, no retrieval"
    /// disposition assigns indirect incorporation: this library performs no network or filesystem access, and <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1
    /// V1.3.1</see> clause 6.3 forbids indirect incorporation in every XAdES baseline level regardless.
    /// </summary>
    [TestMethod]
    public void VerificationIsAlwaysRefused()
    {
        string document = $"""<QualifyingPropertiesReference xmlns="{V132}" URI="external.xml#qp1"/>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESQualifyingPropertiesReference.TryRead(table, table.DocumentElementIndex, out XAdESQualifyingPropertiesReference value, out XAdESReadError readError);
        Assert.IsTrue(isRead, $"The fixture must read but was refused with {readError.Failure}.");

        XAdESProcessingError error = value.RefuseVerification();

        Assert.AreEqual(XAdESProcessingFailure.IndirectIncorporationNotSupported, error.Failure);
    }
}
