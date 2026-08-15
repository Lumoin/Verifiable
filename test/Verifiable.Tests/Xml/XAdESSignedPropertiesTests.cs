using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESSignedProperties.TryRead"/> against clause 4.3.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: the <c>SignedPropertiesType</c> sequence shape and the empty-container
/// refusal.
/// </summary>
[TestClass]
internal sealed class XAdESSignedPropertiesTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.2's XA-4.3.2-4/-7: <c>SignedProperties</c> with an <c>Id</c> and both optional children reads,
    /// preserving the Id and both children.
    /// </summary>
    [TestMethod]
    public void SignedPropertiesWithBothChildrenAndIdReads()
    {
        string document = $"""
            <SignedProperties xmlns="{V132}" Id="sp1">
              <SignedSignatureProperties><SigningTime/></SignedSignatureProperties>
              <SignedDataObjectProperties><DataObjectFormat/></SignedDataObjectProperties>
            </SignedProperties>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignedProperties.TryRead(table, table.DocumentElementIndex, out XAdESSignedProperties value, out XAdESReadError error);

        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasId);
        Assert.AreSequenceEqual("sp1"u8.ToArray(), value.Id.ToArray());
        Assert.IsTrue(value.HasSignedSignatureProperties);
        Assert.IsTrue(value.HasSignedDataObjectProperties);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.2's XA-4.3.2-8: "A XAdES signature shall not incorporate empty <c>SignedProperties</c> element" —
    /// neither optional child present refuses.
    /// </summary>
    [TestMethod]
    public void EmptySignedPropertiesIsRefused()
    {
        string document = $"""<SignedProperties xmlns="{V132}"/>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignedProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "An empty SignedProperties must be refused.");
        Assert.AreEqual(XAdESReadFailure.EmptyQualifyingPropertiesContainer, error.Failure);
    }


    /// <summary>
    /// Proves the fixed <c>SignedSignatureProperties, SignedDataObjectProperties</c> sequence order (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.2's XA-4.3.2-4):
    /// reversing them refuses.
    /// </summary>
    [TestMethod]
    public void ChildrenOutOfOrderAreRefused()
    {
        string document = $"""
            <SignedProperties xmlns="{V132}">
              <SignedDataObjectProperties><DataObjectFormat/></SignedDataObjectProperties>
              <SignedSignatureProperties><SigningTime/></SignedSignatureProperties>
            </SignedProperties>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignedProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "SignedDataObjectProperties before SignedSignatureProperties violates the fixed sequence order.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.2, a wrong-content-model child (neither name the sequence declares) refuses.
    /// </summary>
    [TestMethod]
    public void ForeignChildIsRefused()
    {
        string document = $"""<SignedProperties xmlns="{V132}"><Bogus/></SignedProperties>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignedProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "A foreign child must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }
}
