using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESQualifyingProperties.TryRead"/> against clause 4.3.1 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: the <c>QualifyingPropertiesType</c> sequence shape, cardinality and
/// attribute rules, and the empty-container refusal.
/// </summary>
[TestClass]
internal sealed class XAdESQualifyingPropertiesTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }

    /// <summary>A minimal, well-formed <c>SignedProperties</c> body, one recognized property.</summary>
    private const string SignedPropertiesBody = $"""<SignedProperties xmlns="{V132}"><SignedSignatureProperties><SigningTime/></SignedSignatureProperties></SignedProperties>""";

    /// <summary>A minimal, well-formed <c>UnsignedProperties</c> body, one recognized property.</summary>
    private const string UnsignedPropertiesBody = $"""<UnsignedProperties xmlns="{V132}"><UnsignedSignatureProperties><CounterSignature/></UnsignedSignatureProperties></UnsignedProperties>""";


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.1's XA-4.3.1-3/XA-4.3.1-8: a <c>QualifyingProperties</c> element with a well-formed <c>Target</c>,
    /// an <c>Id</c>, and both optional children reads with both present and their attributes captured
    /// exact-character.
    /// </summary>
    [TestMethod]
    public void QualifyingPropertiesWithBothChildrenAndIdReads()
    {
        string document = $"""
            <QualifyingProperties xmlns="{V132}" Target="#sig" Id="qp1">
              {SignedPropertiesBody}
              {UnsignedPropertiesBody}
            </QualifyingProperties>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESQualifyingProperties.TryRead(table, table.DocumentElementIndex, out XAdESQualifyingProperties value, out XAdESReadError error);

        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasId, "Id must be recognized.");
        Assert.AreSequenceEqual("qp1"u8.ToArray(), value.Id.ToArray(), "Id value must be captured exact-character.");
        Assert.AreSequenceEqual("#sig"u8.ToArray(), value.Target.ToArray(), "Target must be captured exact-character, unvalidated.");
        Assert.IsTrue(value.HasSignedProperties, "SignedProperties must be recognized.");
        Assert.IsTrue(value.HasUnsignedProperties, "UnsignedProperties must be recognized.");
    }


    /// <summary>
    /// Proves the mandatory <c>Target</c> attribute (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.1's XA-4.3.1-4/-5, schema <c>use="required"</c>) is refused
    /// when absent.
    /// </summary>
    [TestMethod]
    public void MissingTargetAttributeIsRefused()
    {
        string document = $"""<QualifyingProperties xmlns="{V132}">{SignedPropertiesBody}</QualifyingProperties>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESQualifyingProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "A missing Target attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredAttribute, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.1's XA-4.3.1-9: "A XAdES signature shall not incorporate empty <c>QualifyingProperties</c>
    /// elements" — neither optional child present refuses, even though both are individually
    /// <c>minOccurs="0"</c> and so schema-valid alone (XA-4.3.1-3's note on the schema-vs-prose gap).
    /// </summary>
    [TestMethod]
    public void EmptyQualifyingPropertiesIsRefused()
    {
        string document = $"""<QualifyingProperties xmlns="{V132}" Target="#sig"/>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESQualifyingProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "An empty QualifyingProperties must be refused.");
        Assert.AreEqual(XAdESReadFailure.EmptyQualifyingPropertiesContainer, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.1, a <c>QualifyingProperties</c> carrying only <c>SignedProperties</c> (no <c>UnsignedProperties</c>)
    /// is NOT empty and reads successfully — the "shall not incorporate empty" rule requires neither optional
    /// child, not both.
    /// </summary>
    [TestMethod]
    public void OnlySignedPropertiesPresentIsNotEmpty()
    {
        string document = $"""<QualifyingProperties xmlns="{V132}" Target="#sig">{SignedPropertiesBody}</QualifyingProperties>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESQualifyingProperties.TryRead(table, table.DocumentElementIndex, out XAdESQualifyingProperties value, out XAdESReadError error);

        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasSignedProperties);
        Assert.IsFalse(value.HasUnsignedProperties);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.1's XA-4.3.1-3's fixed <c>SignedProperties, UnsignedProperties</c> sequence order: reversing them
    /// refuses rather than being tolerated as an unordered pair.
    /// </summary>
    [TestMethod]
    public void ChildrenOutOfOrderAreRefused()
    {
        string document = $"""
            <QualifyingProperties xmlns="{V132}" Target="#sig">
              {UnsignedPropertiesBody}
              {SignedPropertiesBody}
            </QualifyingProperties>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESQualifyingProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "SignedProperties after UnsignedProperties violates the fixed sequence order.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.1, a duplicate <c>SignedProperties</c> child refuses as <see cref="XAdESReadFailure.DuplicateCoreChild"/>.
    /// </summary>
    [TestMethod]
    public void DuplicateSignedPropertiesIsRefused()
    {
        string document = $"""
            <QualifyingProperties xmlns="{V132}" Target="#sig">
              {SignedPropertiesBody}
              {SignedPropertiesBody}
            </QualifyingProperties>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESQualifyingProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "A second SignedProperties must be refused.");
        Assert.AreEqual(XAdESReadFailure.DuplicateCoreChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.1, an un-prefixed attribute beyond <c>Target</c>/<c>Id</c> is refused, per the shared
    /// <see cref="XmlSignatureModelGrammar.TryValidateAttributeCount"/> primitive.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeIsRefused()
    {
        string document = $"""<QualifyingProperties xmlns="{V132}" Target="#sig" Bogus="x">{SignedPropertiesBody}</QualifyingProperties>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESQualifyingProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "An unrecognized attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.1, element identity is exact: the wrong local name at document root refuses, mirroring
    /// <see cref="XmlSignatureProperties.TryRead"/>'s own identity-check posture.
    /// </summary>
    [TestMethod]
    public void WrongElementNameIsRefused()
    {
        string document = $"""<NotQualifyingProperties xmlns="{V132}" Target="#sig"/>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESQualifyingProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "A differently-named element must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }
}
