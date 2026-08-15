using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESSignatureProductionPlaceV2.TryRead"/> against clause 5.2.5's
/// <c>SignatureProductionPlaceV2</c> qualifying property of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>.
/// </summary>
[TestClass]
internal sealed class XAdESSignatureProductionPlaceV2Tests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.5, the minimal shape — a single
    /// <c>City</c> child, one of the five individually optional children — reads.
    /// </summary>
    [TestMethod]
    public void MinimalShapeWithCityReads()
    {
        using XmlNodeTable table = Parse($"""<SignatureProductionPlaceV2 xmlns="{V132}"><City>Tallinn</City></SignatureProductionPlaceV2>""");
        bool isRead = XAdESSignatureProductionPlaceV2.TryRead(table, table.DocumentElementIndex, out XAdESSignatureProductionPlaceV2 value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasCity);
        Assert.AreEqual("Tallinn", Encoding.UTF8.GetString(value.City));
        Assert.IsFalse(value.HasStreetAddress);
        Assert.IsFalse(value.HasStateOrProvince);
        Assert.IsFalse(value.HasPostalCode);
        Assert.IsFalse(value.HasCountryName);
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.5's acquired v132
    /// <c>SignatureProductionPlaceV2Type</c> schema, all five children, in their fixed schema order
    /// (<c>City, StreetAddress, StateOrProvince, PostalCode, CountryName</c>), read together.
    /// </summary>
    [TestMethod]
    public void AllFiveChildrenInFixedOrderRead()
    {
        using XmlNodeTable table = Parse($"""
            <SignatureProductionPlaceV2 xmlns="{V132}">
              <City>Tallinn</City>
              <StreetAddress>Narva mnt 5</StreetAddress>
              <StateOrProvince>Harju</StateOrProvince>
              <PostalCode>10117</PostalCode>
              <CountryName>Estonia</CountryName>
            </SignatureProductionPlaceV2>
            """);
        bool isRead = XAdESSignatureProductionPlaceV2.TryRead(table, table.DocumentElementIndex, out XAdESSignatureProductionPlaceV2 value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.AreEqual("Tallinn", Encoding.UTF8.GetString(value.City));
        Assert.AreEqual("Narva mnt 5", Encoding.UTF8.GetString(value.StreetAddress));
        Assert.AreEqual("Harju", Encoding.UTF8.GetString(value.StateOrProvince));
        Assert.AreEqual("10117", Encoding.UTF8.GetString(value.PostalCode));
        Assert.AreEqual("Estonia", Encoding.UTF8.GetString(value.CountryName));
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.5's "Empty
    /// <c>SignatureProductionPlaceV2</c> qualifying properties shall not be generated" — an entirely empty
    /// element is refused, even though every child is individually schema-optional.
    /// </summary>
    [TestMethod]
    public void NoChildrenAtAllIsRefused()
    {
        using XmlNodeTable table = Parse($"""<SignatureProductionPlaceV2 xmlns="{V132}"/>""");
        bool isRead = XAdESSignatureProductionPlaceV2.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An entirely empty SignatureProductionPlaceV2 must be refused.");
        Assert.AreEqual(XAdESReadFailure.EmptySignatureProductionPlaceV2, error.Failure);
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.5's fixed
    /// <c>City, StreetAddress, StateOrProvince, PostalCode, CountryName</c> sequence, a child out of order —
    /// here, <c>CountryName</c> before <c>City</c> — is refused.
    /// </summary>
    [TestMethod]
    public void OutOfOrderChildIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SignatureProductionPlaceV2 xmlns="{V132}">
              <CountryName>Estonia</CountryName>
              <City>Tallinn</City>
            </SignatureProductionPlaceV2>
            """);
        bool isRead = XAdESSignatureProductionPlaceV2.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An out-of-order child must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves, against <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.5's fixed at-most-once
    /// sequence, a repeated child — two <c>City</c> elements — is refused as a duplicate, distinct from a
    /// generic unknown-element refusal.
    /// </summary>
    [TestMethod]
    public void DuplicateChildIsRefused()
    {
        using XmlNodeTable table = Parse($"""
            <SignatureProductionPlaceV2 xmlns="{V132}">
              <City>Tallinn</City>
              <City>Tartu</City>
            </SignatureProductionPlaceV2>
            """);
        bool isRead = XAdESSignatureProductionPlaceV2.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A duplicate child must be refused.");
        Assert.AreEqual(XAdESReadFailure.DuplicateCoreChild, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.5, an unrecognized attribute is
    /// refused fail-closed — <c>SignatureProductionPlaceV2Type</c> declares no attribute of its own.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeIsRefused()
    {
        using XmlNodeTable table = Parse($"""<SignatureProductionPlaceV2 xmlns="{V132}" unexpected="value"><City>Tallinn</City></SignatureProductionPlaceV2>""");
        bool isRead = XAdESSignatureProductionPlaceV2.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Table 2 (clause 6.3), the V1
    /// <c>SignatureProductionPlace</c> sibling remains recognized-and-refused by
    /// <see cref="XAdESSignedSignatureProperties"/> as a deprecated name, while the V2 property this reader
    /// targets is accepted at the same container position — the V1-to-V2 supersession the container's own
    /// slot table encodes.
    /// </summary>
    [TestMethod]
    public void V1SignatureProductionPlaceStaysDeprecatedAtContainerLevel()
    {
        using XmlNodeTable table = Parse($"""
            <SignedSignatureProperties xmlns="{V132}">
              <SignatureProductionPlace/>
            </SignedSignatureProperties>
            """);
        bool isRead = XAdESSignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "The V1 SignatureProductionPlace must still be refused as deprecated.");
        Assert.AreEqual(XAdESReadFailure.DeprecatedQualifyingProperty, error.Failure);
    }
}
