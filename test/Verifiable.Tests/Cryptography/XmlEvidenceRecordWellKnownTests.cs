using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="XmlEvidenceRecordWellKnown"/>: the wire names of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-8">IETF RFC 6283 clause 8</see>'s schema and the
/// two closed enumerations clauses 3.1.2 and 3.1.3 place on the <c>Type</c> attributes.
/// </summary>
[TestClass]
internal sealed class XmlEvidenceRecordWellKnownTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The namespace and the element names are the ones clause 8's schema states, letter for letter — including
    /// that the schema spells <c>ArchiveTimeStamp</c> with an inner capital S, which a name written from the
    /// prose alone gets wrong.
    /// </summary>
    [TestMethod]
    public void TheNamesAreTheOnesTheSchemaStates()
    {
        Assert.AreEqual("urn:ietf:params:xml:ns:ers", XmlEvidenceRecordWellKnown.EvidenceRecordNamespace);
        Assert.AreEqual("EvidenceRecord", XmlEvidenceRecordWellKnown.EvidenceRecordElementName);
        Assert.AreEqual("EncryptionInformation", XmlEvidenceRecordWellKnown.EncryptionInformationElementName);
        Assert.AreEqual("SupportingInformationList", XmlEvidenceRecordWellKnown.SupportingInformationListElementName);
        Assert.AreEqual("SupportingInformation", XmlEvidenceRecordWellKnown.SupportingInformationElementName);
        Assert.AreEqual("ArchiveTimeStampSequence", XmlEvidenceRecordWellKnown.ArchiveTimeStampSequenceElementName);
        Assert.AreEqual("ArchiveTimeStampChain", XmlEvidenceRecordWellKnown.ArchiveTimeStampChainElementName);
        Assert.AreEqual("ArchiveTimeStamp", XmlEvidenceRecordWellKnown.ArchiveTimeStampElementName);
        Assert.AreEqual("DigestMethod", XmlEvidenceRecordWellKnown.DigestMethodElementName);
        Assert.AreEqual("CanonicalizationMethod", XmlEvidenceRecordWellKnown.CanonicalizationMethodElementName);
        Assert.AreEqual("HashTree", XmlEvidenceRecordWellKnown.HashTreeElementName);
        Assert.AreEqual("Sequence", XmlEvidenceRecordWellKnown.SequenceElementName);
        Assert.AreEqual("DigestValue", XmlEvidenceRecordWellKnown.DigestValueElementName);
        Assert.AreEqual("TimeStamp", XmlEvidenceRecordWellKnown.TimeStampElementName);
        Assert.AreEqual("TimeStampToken", XmlEvidenceRecordWellKnown.TimeStampTokenElementName);
        Assert.AreEqual("CryptographicInformationList", XmlEvidenceRecordWellKnown.CryptographicInformationListElementName);
        Assert.AreEqual("CryptographicInformation", XmlEvidenceRecordWellKnown.CryptographicInformationElementName);
        Assert.AreEqual("Attributes", XmlEvidenceRecordWellKnown.AttributesElementName);
        Assert.AreEqual("Attribute", XmlEvidenceRecordWellKnown.AttributeElementName);
        Assert.AreEqual("Version", XmlEvidenceRecordWellKnown.VersionAttributeName);
        Assert.AreEqual("1.0", XmlEvidenceRecordWellKnown.Version10);
        Assert.AreEqual("Order", XmlEvidenceRecordWellKnown.OrderAttributeName);
        Assert.AreEqual("Type", XmlEvidenceRecordWellKnown.TypeAttributeName);
        Assert.AreEqual(XmlSignatureWellKnown.AlgorithmAttributeName, XmlEvidenceRecordWellKnown.AlgorithmAttributeName,
            "The attribute a DigestMethod names its algorithm in is the XML Signature one, stated in one place for both profiles.");
    }


    /// <summary>
    /// Clause 3.1.2 registers two time-stamp formats and clause 10 makes the set extensible only by IANA
    /// registration, so a third value is not an unknown extension a validator may pass over.
    /// </summary>
    [TestMethod]
    public void TheTimeStampTokenTypesAreTheTwoTheRegistryHolds()
    {
        Assert.AreEqual("RFC3161", XmlEvidenceRecordWellKnown.Rfc3161TimeStampTokenType);
        Assert.AreEqual("XMLENTRUST", XmlEvidenceRecordWellKnown.XmlEntrustTimeStampTokenType);

        Assert.IsTrue(XmlEvidenceRecordWellKnown.IsRfc3161TimeStampTokenType("RFC3161"));
        Assert.IsFalse(XmlEvidenceRecordWellKnown.IsRfc3161TimeStampTokenType("rfc3161"), "The values are NMTOKEN values compared as written.");
        Assert.IsTrue(XmlEvidenceRecordWellKnown.IsXmlTimeStampTokenType("XMLENTRUST"));

        Assert.IsTrue(XmlEvidenceRecordWellKnown.IsRegisteredTimeStampTokenType("RFC3161"));
        Assert.IsTrue(XmlEvidenceRecordWellKnown.IsRegisteredTimeStampTokenType("XMLENTRUST"));
        Assert.IsFalse(XmlEvidenceRecordWellKnown.IsRegisteredTimeStampTokenType("MYFORMAT"));
        Assert.IsFalse(XmlEvidenceRecordWellKnown.IsRegisteredTimeStampTokenType(null));
    }


    /// <summary>
    /// Clause 3.1.3 closes the <c>CryptographicInformation</c> type enumeration at four values, including the
    /// certificate validation response this library recognises and never interprets.
    /// </summary>
    [TestMethod]
    public void TheCryptographicInformationTypesAreTheFourTheRegistryHolds()
    {
        Assert.AreEqual("CRL", XmlEvidenceRecordWellKnown.CertificateRevocationListInformationType);
        Assert.AreEqual("OCSP", XmlEvidenceRecordWellKnown.OcspResponseInformationType);
        Assert.AreEqual("SCVP", XmlEvidenceRecordWellKnown.CertificateValidationResponseInformationType);
        Assert.AreEqual("CERT", XmlEvidenceRecordWellKnown.CertificateInformationType);

        Assert.IsTrue(XmlEvidenceRecordWellKnown.IsRegisteredCryptographicInformationType("CRL"));
        Assert.IsTrue(XmlEvidenceRecordWellKnown.IsRegisteredCryptographicInformationType("OCSP"));
        Assert.IsTrue(XmlEvidenceRecordWellKnown.IsRegisteredCryptographicInformationType("SCVP"));
        Assert.IsTrue(XmlEvidenceRecordWellKnown.IsRegisteredCryptographicInformationType("CERT"));
        Assert.IsFalse(XmlEvidenceRecordWellKnown.IsRegisteredCryptographicInformationType("crl"), "The values are NMTOKEN values compared as written.");
        Assert.IsFalse(XmlEvidenceRecordWellKnown.IsRegisteredCryptographicInformationType("TIMESTAMP"));
        Assert.IsFalse(XmlEvidenceRecordWellKnown.IsRegisteredCryptographicInformationType(null));
    }
}
