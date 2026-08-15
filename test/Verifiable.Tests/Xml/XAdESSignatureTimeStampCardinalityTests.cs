using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESSignatureTimeStampCardinality"/> against clause 6.3 letter n) of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>.
/// </summary>
[TestClass]
internal sealed class XAdESSignatureTimeStampCardinalityTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";


    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter n): "Each
    /// <c>SignatureTimeStamp</c> element shall contain only one electronic time-stamp" — a single
    /// <c>EncapsulatedTimeStamp</c> satisfies it.
    /// </summary>
    [TestMethod]
    public void ExactlyOneTimeStampSatisfiesTheRequirement()
    {
        string document = $"""
            <SignatureTimeStamp xmlns="{V132}">
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
            </SignatureTimeStamp>
            """;
        using XmlNodeTable table = Parse(document);
        bool isRead = XAdESSignatureTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSignatureTimeStamp? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.IsTrue(XAdESSignatureTimeStampCardinality.HasExactlyOneTimeStamp(value!));
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 letter n): NOTE 10 permits
    /// "[s]everal instances of these qualifying properties" — meaning several separate
    /// <c>SignatureTimeStamp</c> ELEMENTS — but never more than one electronic time-stamp WITHIN one such
    /// element; the shared <c>XAdESTimeStampType</c> grammar's own one-or-more choice (clause 5.1.4.4.1) would
    /// otherwise accept two <c>EncapsulatedTimeStamp</c> entries inside a single element, so letter n)'s
    /// narrowing is genuinely load-bearing here, not a restatement of something the grammar already refuses.
    /// </summary>
    [TestMethod]
    public void TwoTimeStampsWithinOneElementFailsTheRequirement()
    {
        string document = $"""
            <SignatureTimeStamp xmlns="{V132}">
              <EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp>
              <EncapsulatedTimeStamp>Ag==</EncapsulatedTimeStamp>
            </SignatureTimeStamp>
            """;
        using XmlNodeTable table = Parse(document);
        bool isRead = XAdESSignatureTimeStamp.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XAdESSignatureTimeStamp? value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(value)
        {
            Assert.HasCount(2, value!.TimeStamp.TimeStamps);
            Assert.IsFalse(XAdESSignatureTimeStampCardinality.HasExactlyOneTimeStamp(value));
        }
    }
}
