using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESUnsignedSignatureProperties.TryRead"/> against clause 4.3.6 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: the <c>xsd:choice maxOccurs="unbounded"</c> content model (XA-4.3.6-3),
/// the obsoletion rules (XA-4.3.6-7/-8/-9), the tolerant (never-refused) <c>##other</c> posture gives this
/// container specifically, and the empty-container refusal (XA-4.3.6-10).
/// </summary>
[TestClass]
internal sealed class XAdESUnsignedSignaturePropertiesTests
{
    private const string V132 = "http://uri.etsi.org/01903/v1.3.2#";

    private const string V141 = "http://uri.etsi.org/01903/v1.4.1#";

    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves XA-4.3.6-3: unlike every other <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause-4.3 container (all <c>xsd:sequence</c>), the choice
    /// content model permits children in ANY order and repeated any number of times — two
    /// <c>CounterSignature</c> instances followed by a <c>SignatureTimeStamp</c> before a THIRD
    /// <c>CounterSignature</c> all read successfully, with document order preserved in
    /// <see cref="XAdESUnsignedSignatureProperties.Properties"/>.
    /// </summary>
    [TestMethod]
    public void ChildrenInAnyOrderAndRepeatedAreAccepted()
    {
        string document = $"""
            <UnsignedSignatureProperties xmlns="{V132}" Id="usp1">
              <CounterSignature/>
              <CounterSignature/>
              <SignatureTimeStamp/>
              <CounterSignature/>
            </UnsignedSignatureProperties>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESUnsignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out XAdESUnsignedSignatureProperties value, out XAdESReadError error);

        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.IsTrue(value.HasId, "XA-4.3.6-6: the Id attribute shall be used to reference UnsignedSignatureProperties.");
        Assert.AreSequenceEqual("usp1"u8.ToArray(), value.Id.ToArray());
        Assert.HasCount(4, value.Properties);
        XAdESUnsignedSignaturePropertyName[] expected =
        [
            XAdESUnsignedSignaturePropertyName.CounterSignature,
            XAdESUnsignedSignaturePropertyName.CounterSignature,
            XAdESUnsignedSignaturePropertyName.SignatureTimeStamp,
            XAdESUnsignedSignaturePropertyName.CounterSignature
        ];
        for(int i = 0; i < expected.Length; ++i)
        {
            Assert.AreEqual(expected[i], value.Properties[i].Name, $"Entry {i} must preserve document order.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.6's XA-4.3.6-10: "A XAdES signature shall not incorporate an empty <c>UnsignedSignatureProperties</c>
    /// element."
    /// </summary>
    [TestMethod]
    public void EmptyElementIsRefused()
    {
        string document = $"""<UnsignedSignatureProperties xmlns="{V132}"/>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESUnsignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "An empty UnsignedSignatureProperties must be refused.");
        Assert.AreEqual(XAdESReadFailure.EmptyQualifyingPropertiesContainer, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.6's XA-4.3.6-7's obsoletion rule for each of the four V1 refs/timestamp names individually,
    /// refused with the distinct <see cref="XAdESReadFailure.DeprecatedQualifyingProperty"/> disposition —
    /// each is still schema-legal (a named choice member, not <c>##other</c>) but prose-forbidden.
    /// </summary>
    [TestMethod]
    [DataRow("CompleteCertificateRefs")]
    [DataRow("AttributeCertificateRefs")]
    [DataRow("SigAndRefsTimeStamp")]
    [DataRow("RefsOnlyTimeStamp")]
    public void DeprecatedV1RefsNameIsRefused(string localName)
    {
        string document = $"""<UnsignedSignatureProperties xmlns="{V132}"><{localName}/></UnsignedSignatureProperties>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESUnsignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, $"{localName} is obsoleted and must be refused.");
        Assert.AreEqual(XAdESReadFailure.DeprecatedQualifyingProperty, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.6's XA-4.3.6-8's namespace-borne obsoletion: an <c>ArchiveTimeStamp</c> in the
    /// <c>http://uri.etsi.org/01903/v1.3.2#</c> namespace is the obsoleted form and refuses, while the identically-named element in the CURRENT <c>http://uri.etsi.org/01903/v1.4.1#</c> namespace is a different global element entirely and is
    /// tolerated as an unmodeled entry — the namespace is part of the property's identity.
    /// </summary>
    [TestMethod]
    public void V132NamespaceArchiveTimeStampIsRefusedButV141NamespaceIsUnmodeled()
    {
        string deprecatedDocument = $"""<UnsignedSignatureProperties xmlns="{V132}"><ArchiveTimeStamp/></UnsignedSignatureProperties>""";
        using(XmlNodeTable deprecatedTable = Parse(deprecatedDocument, BaseMemoryPool.Shared))
        {
            bool isDeprecatedRead = XAdESUnsignedSignatureProperties.TryRead(deprecatedTable, deprecatedTable.DocumentElementIndex, out _, out XAdESReadError deprecatedError);
            Assert.IsFalse(isDeprecatedRead, "The v1.3.2-namespace ArchiveTimeStamp is obsoleted and must be refused.");
            Assert.AreEqual(XAdESReadFailure.DeprecatedQualifyingProperty, deprecatedError.Failure);
        }

        string currentDocument = $"""<UnsignedSignatureProperties xmlns="{V132}"><ArchiveTimeStamp xmlns="{V141}"/></UnsignedSignatureProperties>""";
        using XmlNodeTable currentTable = Parse(currentDocument, BaseMemoryPool.Shared);
        bool isCurrentRead = XAdESUnsignedSignatureProperties.TryRead(currentTable, currentTable.DocumentElementIndex, out XAdESUnsignedSignatureProperties value, out XAdESReadError currentError);
        Assert.IsTrue(isCurrentRead, $"The v1.4.1-namespace ArchiveTimeStamp must read but was refused with {currentError.Failure}.");
        Assert.HasCount(1, value.Properties);
        Assert.AreEqual(XAdESUnsignedSignaturePropertyName.Unrecognized, value.Properties[0].Name);
    }


    /// <summary>
    /// Proves clause A.2.2's deprecated <c>RenewedDigests</c> (defined in ETSI EN 319 132-1 V1.1.1, "shall not be
    /// added to any new XAdES signature") is recognized-and-refused even though it sits OUTSIDE the thirteen-
    /// member choice and, unlike the five Annex-D names, shares its CURRENT replacement's own v1.4.1 namespace —
    /// distinguished from <c>RenewedDigestsV2</c> by exact local name only.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.2.2.
    /// </summary>
    [TestMethod]
    public void DeprecatedV141NamespaceRenewedDigestsIsRefused()
    {
        string document = $"""<UnsignedSignatureProperties xmlns="{V132}"><RenewedDigests xmlns="{V141}"/></UnsignedSignatureProperties>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESUnsignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "The deprecated v1.4.1-namespace RenewedDigests must be refused.");
        Assert.AreEqual(XAdESReadFailure.DeprecatedQualifyingProperty, error.Failure);
    }


    /// <summary>
    /// Proves <c>RenewedDigests</c>'s deprecated-name check matches by EXACT local name only, never as a prefix:
    /// the current <c>RenewedDigestsV2</c> — same v1.4.1 namespace, distinct local name — is tolerated as an
    /// unmodeled entry, never refused. Complements <see cref="DeprecatedV141NamespaceRenewedDigestsIsRefused"/>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause A.2.2.
    /// </summary>
    [TestMethod]
    public void RenewedDigestsV2IsUnmodeledNotRefused()
    {
        string document = $"""<UnsignedSignatureProperties xmlns="{V132}"><RenewedDigestsV2 xmlns="{V141}"/></UnsignedSignatureProperties>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESUnsignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out XAdESUnsignedSignatureProperties value, out XAdESReadError error);

        Assert.IsTrue(isRead, $"RenewedDigestsV2 must be tolerated but was refused with {error.Failure}.");
        Assert.HasCount(1, value.Properties);
        Assert.AreEqual(XAdESUnsignedSignaturePropertyName.Unrecognized, value.Properties[0].Name);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.6, the tolerant posture: genuinely foreign content — never a Part-1 name at all — is carried as
    /// an unmodeled entry, never refused, since <c>UnsignedSignatureProperties</c>'s own content is unsigned. Contrast <see cref="XAdESSignedSignaturePropertiesTests.ForeignOtherContentIsRefusedAsUnknownQualifyingProperty"/>.
    /// </summary>
    [TestMethod]
    public void GenuinelyForeignContentIsUnmodeledNotRefused()
    {
        string document = $"""
            <UnsignedSignatureProperties xmlns="{V132}">
              <Bogus xmlns="urn:example:foreign"/>
            </UnsignedSignatureProperties>
            """;
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESUnsignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out XAdESUnsignedSignatureProperties value, out XAdESReadError error);

        Assert.IsTrue(isRead, $"Foreign content must be tolerated but was refused with {error.Failure}.");
        Assert.HasCount(1, value.Properties);
        Assert.AreEqual(XAdESUnsignedSignaturePropertyName.Unrecognized, value.Properties[0].Name);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.6, every one of the eight non-deprecated named choice members classifies correctly.
    /// </summary>
    [TestMethod]
    [DataRow("CounterSignature", XAdESUnsignedSignaturePropertyName.CounterSignature)]
    [DataRow("SignatureTimeStamp", XAdESUnsignedSignaturePropertyName.SignatureTimeStamp)]
    [DataRow("CompleteRevocationRefs", XAdESUnsignedSignaturePropertyName.CompleteRevocationRefs)]
    [DataRow("AttributeRevocationRefs", XAdESUnsignedSignaturePropertyName.AttributeRevocationRefs)]
    [DataRow("CertificateValues", XAdESUnsignedSignaturePropertyName.CertificateValues)]
    [DataRow("RevocationValues", XAdESUnsignedSignaturePropertyName.RevocationValues)]
    [DataRow("AttrAuthoritiesCertValues", XAdESUnsignedSignaturePropertyName.AttrAuthoritiesCertValues)]
    [DataRow("AttributeRevocationValues", XAdESUnsignedSignaturePropertyName.AttributeRevocationValues)]
    public void NonDeprecatedNamedChoiceMemberClassifiesCorrectly(string localName, XAdESUnsignedSignaturePropertyName expected)
    {
        string document = $"""<UnsignedSignatureProperties xmlns="{V132}"><{localName}/></UnsignedSignatureProperties>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESUnsignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out XAdESUnsignedSignatureProperties value, out XAdESReadError error);

        Assert.IsTrue(isRead, $"{localName} must read but was refused with {error.Failure}.");
        Assert.HasCount(1, value.Properties);
        Assert.AreEqual(expected, value.Properties[0].Name);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.6, an unrecognized un-prefixed attribute is refused via the shared grammar primitive.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeIsRefused()
    {
        string document = $"""<UnsignedSignatureProperties xmlns="{V132}" Bogus="x"><CounterSignature/></UnsignedSignatureProperties>""";
        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRead = XAdESUnsignedSignatureProperties.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);

        Assert.IsFalse(isRead, "An unrecognized attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }
}
