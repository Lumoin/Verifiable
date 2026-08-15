using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESUnsignedProperties.TryRead"/> against clause 4.3.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: the <c>UnsignedPropertiesType</c> sequence shape and the empty-container
/// refusal.
/// </summary>
[TestClass]
internal sealed class XAdESUnsignedPropertiesTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.3's XA-4.3.3-3/-6: <c>UnsignedProperties</c> with an <c>Id</c> and both optional children reads.
    /// </summary>
    [TestMethod]
    public void UnsignedPropertiesWithBothChildrenAndIdReads()
    {
        string document = $"""
            <UnsignedProperties xmlns="{V132}" Id="up1">
              <UnsignedSignatureProperties><CounterSignature/></UnsignedSignatureProperties>
              <UnsignedDataObjectProperties><UnsignedDataObjectProperty/></UnsignedDataObjectProperties>
            </UnsignedProperties>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESUnsignedProperties.TryRead(table, table.DocumentElementIndex, out XAdESUnsignedProperties value, out XAdESReadError error);

        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasId);
        Assert.AreSequenceEqual("up1"u8.ToArray(), value.Id.ToArray());
        Assert.IsTrue(value.HasUnsignedSignatureProperties);
        Assert.IsTrue(value.HasUnsignedDataObjectProperties);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.3's XA-4.3.3-7: "A XAdES signature shall not incorporate empty <c>UnsignedProperties</c> elements."
    /// </summary>
    [TestMethod]
    public void EmptyUnsignedPropertiesIsRefused()
    {
        string document = $"""<UnsignedProperties xmlns="{V132}"/>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESUnsignedProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "An empty UnsignedProperties must be refused.");
        Assert.AreEqual(XAdESReadFailure.EmptyQualifyingPropertiesContainer, error.Failure);
    }


    /// <summary>
    /// Proves the fixed <c>UnsignedSignatureProperties, UnsignedDataObjectProperties</c> sequence order
    /// (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.3's XA-4.3.3-3): reversing them refuses.
    /// </summary>
    [TestMethod]
    public void ChildrenOutOfOrderAreRefused()
    {
        string document = $"""
            <UnsignedProperties xmlns="{V132}">
              <UnsignedDataObjectProperties><UnsignedDataObjectProperty/></UnsignedDataObjectProperties>
              <UnsignedSignatureProperties><CounterSignature/></UnsignedSignatureProperties>
            </UnsignedProperties>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESUnsignedProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "UnsignedDataObjectProperties before UnsignedSignatureProperties violates the fixed sequence order.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.3, only <c>UnsignedSignatureProperties</c> present (no <c>UnsignedDataObjectProperties</c>) is not
    /// empty and reads successfully.
    /// </summary>
    [TestMethod]
    public void OnlyUnsignedSignaturePropertiesPresentIsNotEmpty()
    {
        string document = $"""<UnsignedProperties xmlns="{V132}"><UnsignedSignatureProperties><CounterSignature/></UnsignedSignatureProperties></UnsignedProperties>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESUnsignedProperties.TryRead(table, table.DocumentElementIndex, out XAdESUnsignedProperties value, out XAdESReadError error);

        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasUnsignedSignatureProperties);
        Assert.IsFalse(value.HasUnsignedDataObjectProperties);
    }
}
