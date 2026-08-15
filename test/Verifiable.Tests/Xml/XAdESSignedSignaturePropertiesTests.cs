using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESSignedSignatureProperties.TryRead"/> against clause 4.3.4 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: the eight-slot fixed sequence (XA-4.3.4-2), the obsoletion rule
/// (XA-4.3.4-6), the closed <c>##other</c> extension point (XA-4.3.4-3/-4) and the empty-container refusal
/// (XA-4.3.4-7).
/// </summary>
[TestClass]
internal sealed class XAdESSignedSignaturePropertiesTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.4's XA-4.3.4-2: all five non-deprecated named slots, in their fixed schema order, read as ordered
    /// recognized entries — none of the eight slots' own body content is interpreted, only element identity
    /// and position, per this container's own "expose child properties as ordered recognized-name entries"
    /// design.
    /// </summary>
    [TestMethod]
    public void AllFiveNonDeprecatedSlotsInOrderRead()
    {
        string document = $"""
            <SignedSignatureProperties xmlns="{V132}" Id="ssp1">
              <SigningTime/>
              <SigningCertificateV2/>
              <SignaturePolicyIdentifier/>
              <SignatureProductionPlaceV2/>
              <SignerRoleV2/>
            </SignedSignatureProperties>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out XAdESSignedSignatureProperties value, out XAdESReadError error);

        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasId);
        Assert.HasCount(5, value.Properties);
        XAdESSignedSignaturePropertyName[] expected =
        [
            XAdESSignedSignaturePropertyName.SigningTime,
            XAdESSignedSignaturePropertyName.SigningCertificateV2,
            XAdESSignedSignaturePropertyName.SignaturePolicyIdentifier,
            XAdESSignedSignaturePropertyName.SignatureProductionPlaceV2,
            XAdESSignedSignaturePropertyName.SignerRoleV2
        ];
        for(int i = 0; i < expected.Length; ++i)
        {
            Assert.AreEqual(expected[i], value.Properties[i].Name, $"Entry {i} must preserve document order.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.4, a single recognized child (any one of the five) is enough to satisfy the non-empty rule and
    /// read successfully — every slot is individually optional.
    /// </summary>
    [TestMethod]
    public void SingleRecognizedChildReads()
    {
        string document = $"""<SignedSignatureProperties xmlns="{V132}"><SigningTime/></SignedSignatureProperties>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out XAdESSignedSignatureProperties value, out XAdESReadError error);

        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.HasCount(1, value.Properties);
        Assert.AreEqual(XAdESSignedSignaturePropertyName.SigningTime, value.Properties[0].Name);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.4's XA-4.3.4-7: "A XAdES signature shall not incorporate an empty <c>SignedSignatureProperties</c>
    /// element."
    /// </summary>
    [TestMethod]
    public void EmptyElementIsRefused()
    {
        string document = $"""<SignedSignatureProperties xmlns="{V132}"/>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "An empty SignedSignatureProperties must be refused.");
        Assert.AreEqual(XAdESReadFailure.EmptyQualifyingPropertiesContainer, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.4's XA-4.3.4-6's obsoletion rule for each of the three V1 names individually: "the aforementioned
    /// obsoleted qualifying properties shall not be incorporated into the signature," refused with the distinct <see cref="XAdESReadFailure.DeprecatedQualifyingProperty"/> disposition names, not treated as merely-unrecognized content.
    /// </summary>
    [TestMethod]
    [DataRow("SigningCertificate")]
    [DataRow("SignatureProductionPlace")]
    [DataRow("SignerRole")]
    public void DeprecatedV1NameIsRefused(string localName)
    {
        string document = $"""<SignedSignatureProperties xmlns="{V132}"><{localName}/></SignedSignatureProperties>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, $"{localName} is obsoleted and must be refused.");
        Assert.AreEqual(XAdESReadFailure.DeprecatedQualifyingProperty, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.4's XA-4.3.4-4: "shall not incorporate any elements as an instantiation of <c>xsd:any</c> that are
    /// not specified within any version of this multi-part deliverable" — a foreign element filling the schema's trailing <c>##other</c> slot is refused as <see cref="XAdESReadFailure.UnknownQualifyingProperty"/>, the signed-container-specific disposition names,
    /// distinct from the plain grammar-level <see cref="XAdESReadFailure.UnknownCoreElement"/>.
    /// </summary>
    [TestMethod]
    public void ForeignOtherContentIsRefusedAsUnknownQualifyingProperty()
    {
        string document = $"""
            <SignedSignatureProperties xmlns="{V132}">
              <SigningTime/>
              <Bogus xmlns="urn:example:foreign"/>
            </SignedSignatureProperties>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "Foreign content in the ##other position must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownQualifyingProperty, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.4, a legitimate name repeated a second time refuses as <see cref="XAdESReadFailure.DuplicateCoreChild"/>.
    /// </summary>
    [TestMethod]
    public void DuplicateNamedSlotIsRefused()
    {
        string document = $"""<SignedSignatureProperties xmlns="{V132}"><SigningTime/><SigningTime/></SignedSignatureProperties>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "A duplicate SigningTime must be refused.");
        Assert.AreEqual(XAdESReadFailure.DuplicateCoreChild, error.Failure);
    }


    /// <summary>
    /// Proves a legitimate name appearing out of its fixed sequence position — but not a literal repeat —
    /// refuses as <see cref="XAdESReadFailure.UnknownQualifyingProperty"/>, per the signed-container's
    /// closed-allowlist posture: <c>SigningTime</c> after <c>SigningCertificateV2</c> violates
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.4's XA-4.3.4-2's schema order.
    /// </summary>
    [TestMethod]
    public void LegitimateNameOutOfOrderIsRefused()
    {
        string document = $"""<SignedSignatureProperties xmlns="{V132}"><SigningCertificateV2/><SigningTime/></SignedSignatureProperties>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "SigningTime after SigningCertificateV2 violates the fixed sequence order.");
        Assert.AreEqual(XAdESReadFailure.UnknownQualifyingProperty, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.4, an unrecognized un-prefixed attribute is refused via the shared grammar primitive.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeIsRefused()
    {
        string document = $"""<SignedSignatureProperties xmlns="{V132}" Bogus="x"><SigningTime/></SignedSignatureProperties>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESSignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "An unrecognized attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }
}
