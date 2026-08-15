using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESUnsignedDataObjectProperties.TryRead"/> against clause 4.3.7 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: the closed <c>UnsignedDataObjectProperty+</c> sequence of type
/// <c>AnyType</c> (XA-4.3.7-3) and the empty-container refusal (XA-4.3.7-5).
/// </summary>
[TestClass]
internal sealed class XAdESUnsignedDataObjectPropertiesTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves XA-4.3.7-3: one-or-more <c>UnsignedDataObjectProperty</c> children, each carried unmodeled —
    /// arbitrary child content under <c>AnyType</c> (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.1) never refuses.
    /// </summary>
    [TestMethod]
    public void MultipleUnsignedDataObjectPropertyChildrenReadUnmodeled()
    {
        string document = $"""
            <UnsignedDataObjectProperties xmlns="{V132}" Id="udop1">
              <UnsignedDataObjectProperty><Anything xmlns="urn:example:whatever"/></UnsignedDataObjectProperty>
              <UnsignedDataObjectProperty>plain text</UnsignedDataObjectProperty>
            </UnsignedDataObjectProperties>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESUnsignedDataObjectProperties.TryRead(table, table.DocumentElementIndex, out XAdESUnsignedDataObjectProperties value, out XAdESReadError error);

        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasId);
        Assert.HasCount(2, value.Properties);
        Assert.HasCount(1, value.Properties[0].ContentNodeIndices, "The first UnsignedDataObjectProperty's one Anything child must be captured.");
        Assert.HasCount(1, value.Properties[1].ContentNodeIndices, "The second UnsignedDataObjectProperty's text node must be captured.");
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.7's XA-4.3.7-5: "A XAdES signature shall not incorporate empty <c>UnsignedDataObjectProperties</c>
    /// element."
    /// </summary>
    [TestMethod]
    public void EmptyElementIsRefused()
    {
        string document = $"""<UnsignedDataObjectProperties xmlns="{V132}"/>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESUnsignedDataObjectProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "An empty UnsignedDataObjectProperties must be refused.");
        Assert.AreEqual(XAdESReadFailure.EmptyQualifyingPropertiesContainer, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.7, the closed sequence: unlike <see cref="XAdESUnsignedSignatureProperties"/>, this container has
    /// no <c>##other</c> extension point at all — a differently-named child is a plain grammar violation,
    /// <see cref="XAdESReadFailure.UnknownCoreElement"/>, never tolerated as unmodeled.
    /// </summary>
    [TestMethod]
    public void DifferentlyNamedChildIsRefused()
    {
        string document = $"""<UnsignedDataObjectProperties xmlns="{V132}"><Bogus/></UnsignedDataObjectProperties>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESUnsignedDataObjectProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "A differently-named child must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }
}
