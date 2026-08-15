using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESSignedDataObjectProperties.TryRead"/> against clause 4.3.5 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: the four-group unbounded-repetition fixed sequence (XA-4.3.5-2), the
/// closed <c>##other</c> extension point (XA-4.3.5-3/-4) and the empty-container refusal (XA-4.3.5-6).
/// </summary>
[TestClass]
internal sealed class XAdESSignedDataObjectPropertiesTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.5's XA-4.3.5-2: multiple instances of the SAME group name (unbounded cardinality, unlike
    /// <see cref="XAdESSignedSignatureProperties"/>'s at-most-once slots) all read as separate ordered
    /// entries.
    /// </summary>
    [TestMethod]
    public void MultipleInstancesOfTheSameGroupRead()
    {
        string document = $"""
            <SignedDataObjectProperties xmlns="{V132}" Id="sdop1">
              <DataObjectFormat/>
              <DataObjectFormat/>
              <CommitmentTypeIndication/>
            </SignedDataObjectProperties>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignedDataObjectProperties.TryRead(table, table.DocumentElementIndex, out XAdESSignedDataObjectProperties value, out XAdESReadError error);

        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasId);
        Assert.HasCount(3, value.Properties);
        Assert.AreEqual(XAdESSignedDataObjectPropertyName.DataObjectFormat, value.Properties[0].Name);
        Assert.AreEqual(XAdESSignedDataObjectPropertyName.DataObjectFormat, value.Properties[1].Name);
        Assert.AreEqual(XAdESSignedDataObjectPropertyName.CommitmentTypeIndication, value.Properties[2].Name);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.5, all four groups, in their fixed schema order, read correctly.
    /// </summary>
    [TestMethod]
    public void AllFourGroupsInOrderRead()
    {
        string document = $"""
            <SignedDataObjectProperties xmlns="{V132}">
              <DataObjectFormat/>
              <CommitmentTypeIndication/>
              <AllDataObjectsTimeStamp/>
              <IndividualDataObjectsTimeStamp/>
            </SignedDataObjectProperties>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignedDataObjectProperties.TryRead(table, table.DocumentElementIndex, out XAdESSignedDataObjectProperties value, out XAdESReadError error);

        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.HasCount(4, value.Properties);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.5's XA-4.3.5-6: "A XAdES signature shall not incorporate an empty <c>SignedDataObjectProperties</c>
    /// element."
    /// </summary>
    [TestMethod]
    public void EmptyElementIsRefused()
    {
        string document = $"""<SignedDataObjectProperties xmlns="{V132}"/>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignedDataObjectProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "An empty SignedDataObjectProperties must be refused.");
        Assert.AreEqual(XAdESReadFailure.EmptyQualifyingPropertiesContainer, error.Failure);
    }


    /// <summary>
    /// Proves a group appearing again after a later group already started is refused — the fixed group order
    /// forbids interleaving, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.5's XA-4.3.5-2's plain <c>xsd:sequence</c> (not a nested repeatable group).
    /// </summary>
    [TestMethod]
    public void GroupRepeatedAfterALaterGroupIsRefused()
    {
        string document = $"""
            <SignedDataObjectProperties xmlns="{V132}">
              <CommitmentTypeIndication/>
              <DataObjectFormat/>
            </SignedDataObjectProperties>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignedDataObjectProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "DataObjectFormat after CommitmentTypeIndication violates the fixed group order.");
        Assert.AreEqual(XAdESReadFailure.UnknownQualifyingProperty, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.5's XA-4.3.5-4: foreign content filling the <c>##other</c> slot is refused as
    /// <see cref="XAdESReadFailure.UnknownQualifyingProperty"/>, the same signed-container disposition
    /// <see cref="XAdESSignedSignaturePropertiesTests.ForeignOtherContentIsRefusedAsUnknownQualifyingProperty"/>
    /// proves for the sibling container.
    /// </summary>
    [TestMethod]
    public void ForeignOtherContentIsRefusedAsUnknownQualifyingProperty()
    {
        string document = $"""
            <SignedDataObjectProperties xmlns="{V132}">
              <DataObjectFormat/>
              <Bogus xmlns="urn:example:foreign"/>
            </SignedDataObjectProperties>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignedDataObjectProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "Foreign content in the ##other position must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownQualifyingProperty, error.Failure);
    }
}
