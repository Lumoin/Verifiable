using System.Buffers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.Xml;
using Verifiable.Xml;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// End-to-end proofs of <see cref="XAdESSignatureFacts"/>: the format-neutral fact shape <see
/// cref="XAdESSignatureFactsDelegates.ParseAsync"/> (the composition-root implementation over <c>Verifiable.Xml</c>)
/// returns, and the <see cref="SignatureFormatSeam"/> <see cref="XAdESSignatureFacts.CreateSeam"/> builds around it.
/// Every fixture is real, well-formed XAdES-shaped XML built by hand (mirroring the leaf's own test convention) or by the
/// BCL's own <see cref="SignedXml"/> (real cryptography, mirroring <c>XmlSignatureInteropCorpusGenerator</c>'s precedent)
/// — never a mock of the delegate contract.
/// </summary>
[TestClass]
internal sealed class XAdESSignatureFactsTests
{
    public TestContext TestContext { get; set; } = null!;


    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";

    private const string SignatureMethodAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private const string DigestMethodAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

    private const string SignedPropertiesTypeUri = "http://uri.etsi.org/01903#SignedProperties";


    private static string V132 => XAdESIdentifiers.XAdESNamespaceV132;

    private static string V141 => XAdESIdentifiers.XAdESNamespaceV141;


    private static string Reference(string id, string uri, string? type = null) =>
        $"""<ds:Reference Id="{id}" URI="{uri}"{(type is null ? "" : $""" Type="{type}" """)}><ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/><ds:DigestValue>AQ==</ds:DigestValue></ds:Reference>""";


    /// <summary>
    /// One <c>ds:Signature</c>, Id <c>sig1</c>, a <c>SignedProperties</c>/<c>#data1</c> reference pair, and a
    /// <c>ds:Object</c> carrying <c>QualifyingProperties</c> whose <c>Target</c> binds to <c>sig1</c> and whose
    /// body is <paramref name="signedProperties"/>/<paramref name="unsignedProperties"/>, EXACTLY the wrapping
    /// shape <c>XAdESQualifyingPropertiesDiscoveryTests.WellFormedDocument</c> uses.
    /// </summary>
    private static string Document(string signedSignatureProperties, string signedDataObjectProperties, string? unsignedSignatureProperties = null)
    {
        string unsignedBlock = unsignedSignatureProperties is null
            ? string.Empty
            : $"""<UnsignedProperties><UnsignedSignatureProperties>{unsignedSignatureProperties}</UnsignedSignatureProperties></UnsignedProperties>""";

        // "shall not incorporate empty X" holds for every clause-4.3 container -- an empty
        // SignedDataObjectProperties wrapper is a named read refusal, so it is omitted entirely rather
        // than emitted empty when the caller passes no content.
        string signedDataObjectPropertiesBlock = string.IsNullOrWhiteSpace(signedDataObjectProperties)
            ? string.Empty
            : $"""<SignedDataObjectProperties>{signedDataObjectProperties}</SignedDataObjectProperties>""";

        return $"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="sig1">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                {Reference("ref-sp", "#spid", SignedPropertiesTypeUri)}
                {Reference("ref-data1", "#data1")}
              </ds:SignedInfo>
              <ds:SignatureValue Id="sigvalue">AQ==</ds:SignatureValue>
              <ds:Object>
                <QualifyingProperties xmlns="{V132}" Target="#sig1">
                  <SignedProperties Id="spid">
                    <SignedSignatureProperties>{signedSignatureProperties}</SignedSignatureProperties>
                    {signedDataObjectPropertiesBlock}
                  </SignedProperties>
                  {unsignedBlock}
                </QualifyingProperties>
              </ds:Object>
            </ds:Signature>
            """;
    }


    private static XAdESQualifyingPropertiesFacts ParseFacts(string document, BaseMemoryPool pool)
    {
        XAdESQualifyingPropertiesParseResult result = XAdESSignatureFactsDelegates.ParseAsync(Encoding.UTF8.GetBytes(document), pool).AsTask().GetAwaiter().GetResult();
        Assert.IsTrue(result.IsParsed, $"The fixture must parse but was refused with {result.FailureReason}.");

        return result.Facts!;
    }


    private static string ComprehensiveDocument()
    {
        string signingCertificateV2 = $"""
            <SigningCertificateV2>
              <Cert>
                <CertDigest><ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/><ds:DigestValue>AQE=</ds:DigestValue></CertDigest>
                <IssuerSerialV2>{Convert.ToBase64String([0x30, 0x03, 0x02, 0x01, 0x01])}</IssuerSerialV2>
              </Cert>
              <Cert>
                <CertDigest><ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/><ds:DigestValue>AgI=</ds:DigestValue></CertDigest>
              </Cert>
            </SigningCertificateV2>
            """;

        string signaturePolicyIdentifier = $"""
            <SignaturePolicyIdentifier>
              <SignaturePolicyId>
                <SigPolicyId><Identifier>urn:oid:1.2.3.4</Identifier><Description>Test Policy</Description></SigPolicyId>
                <SigPolicyHash><ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/><ds:DigestValue>AwM=</ds:DigestValue></SigPolicyHash>
                <SigPolicyQualifiers><SigPolicyQualifier><SPURI>http://example.com/policy.pdf</SPURI></SigPolicyQualifier></SigPolicyQualifiers>
              </SignaturePolicyId>
            </SignaturePolicyIdentifier>
            """;

        string signerRoleV2 = """
            <SignerRoleV2>
              <ClaimedRoles><ClaimedRole>Manager</ClaimedRole></ClaimedRoles>
              <CertifiedRolesV2><CertifiedRole><X509AttributeCertificate>MAMCAQE=</X509AttributeCertificate></CertifiedRole></CertifiedRolesV2>
              <SignedAssertions><SignedAssertion>content</SignedAssertion></SignedAssertions>
            </SignerRoleV2>
            """;

        string signedSignatureProperties = $"""
            <SigningTime>2024-01-15T10:30:00Z</SigningTime>
            {signingCertificateV2}
            {signaturePolicyIdentifier}
            <SignatureProductionPlaceV2><City>Tallinn</City></SignatureProductionPlaceV2>
            {signerRoleV2}
            """;

        string dataObjectFormat = """<DataObjectFormat ObjectReference="#data1"><MimeType>text/plain</MimeType></DataObjectFormat>""";
        string commitmentTypeIndication = """
            <CommitmentTypeIndication>
              <CommitmentTypeId><Identifier>http://example.com/commitment/proof-of-origin</Identifier></CommitmentTypeId>
              <ObjectReference>#data1</ObjectReference>
            </CommitmentTypeIndication>
            """;
        string allDataObjectsTimeStamp = """<AllDataObjectsTimeStamp><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></AllDataObjectsTimeStamp>""";
        string individualDataObjectsTimeStamp = """<IndividualDataObjectsTimeStamp><EncapsulatedTimeStamp>Qg==</EncapsulatedTimeStamp></IndividualDataObjectsTimeStamp>""";

        string signedDataObjectProperties = $"{dataObjectFormat}{commitmentTypeIndication}{allDataObjectsTimeStamp}{individualDataObjectsTimeStamp}";

        //CounterSignature is deliberately excluded from this fixture: it embeds a whole nested ds:Signature,
        //and this delegate scopes to exactly one ds:Signature per document (mirroring CAdESSignatureFacts'
        //own "first SignerInfo alone" posture) -- CounterSignatureCount is a real, documented field on the fact
        //shape regardless; a production composition root that must also handle countersignature-bearing
        //documents needs its own outermost-signature selection, out of this delegate's scope.
        string signatureTimeStamp = """<SignatureTimeStamp><EncapsulatedTimeStamp>Qw==</EncapsulatedTimeStamp></SignatureTimeStamp>""";
        string certificateValues = """<CertificateValues><EncapsulatedX509Certificate>MAMCAQI=</EncapsulatedX509Certificate></CertificateValues>""";
        string revocationValues = """<RevocationValues><CRLValues><EncapsulatedCRLValue>MAMCAQM=</EncapsulatedCRLValue></CRLValues><OCSPValues><EncapsulatedOCSPValue>MAMCAQQ=</EncapsulatedOCSPValue></OCSPValues></RevocationValues>""";
        string attrAuthoritiesCertValues = """<AttrAuthoritiesCertValues><EncapsulatedX509Certificate>MAMCAQU=</EncapsulatedX509Certificate></AttrAuthoritiesCertValues>""";
        string attributeRevocationValues = """<AttributeRevocationValues><CRLValues><EncapsulatedCRLValue>MAMCAQY=</EncapsulatedCRLValue></CRLValues></AttributeRevocationValues>""";
        string completeRevocationRefs = $"""
            <CompleteRevocationRefs>
              <CRLRefs>
                <CRLRef>
                  <DigestAlgAndValue><ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/><ds:DigestValue>CQk=</ds:DigestValue></DigestAlgAndValue>
                  <CRLIdentifier URI="http://example.com/crl1"><Issuer>CN=Test CA</Issuer><IssueTime>2024-01-01T00:00:00Z</IssueTime><Number>42</Number></CRLIdentifier>
                </CRLRef>
              </CRLRefs>
              <OCSPRefs>
                <OCSPRef>
                  <OCSPIdentifier URI="http://example.com/ocsp1"><ResponderID><ByName>CN=Test Responder</ByName></ResponderID><ProducedAt>2024-01-02T00:00:00Z</ProducedAt></OCSPIdentifier>
                  <DigestAlgAndValue><ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/><ds:DigestValue>Cgo=</ds:DigestValue></DigestAlgAndValue>
                </OCSPRef>
              </OCSPRefs>
            </CompleteRevocationRefs>
            """;
        string attributeRevocationRefs = $"""
            <AttributeRevocationRefs>
              <CRLRefs>
                <CRLRef>
                  <DigestAlgAndValue><ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/><ds:DigestValue>Cws=</ds:DigestValue></DigestAlgAndValue>
                </CRLRef>
              </CRLRefs>
              <OCSPRefs>
                <OCSPRef>
                  <OCSPIdentifier><ResponderID><ByKey>AQIDBA==</ByKey></ResponderID><ProducedAt>2024-01-03T00:00:00Z</ProducedAt></OCSPIdentifier>
                </OCSPRef>
              </OCSPRefs>
            </AttributeRevocationRefs>
            """;
        string completeCertificateRefsV2 = $"""
            <v141:CompleteCertificateRefsV2 xmlns:v141="{V141}">
              <v141:CertRefs>
                <Cert>
                  <CertDigest><ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/><ds:DigestValue>DAw=</ds:DigestValue></CertDigest>
                  <IssuerSerialV2>{Convert.ToBase64String([0x30, 0x03, 0x02, 0x01, 0x02])}</IssuerSerialV2>
                </Cert>
              </v141:CertRefs>
            </v141:CompleteCertificateRefsV2>
            """;
        string attributeCertificateRefsV2 = $"""
            <v141:AttributeCertificateRefsV2 xmlns:v141="{V141}">
              <v141:CertRefs>
                <Cert>
                  <CertDigest><ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/><ds:DigestValue>DQ0=</ds:DigestValue></CertDigest>
                </Cert>
              </v141:CertRefs>
            </v141:AttributeCertificateRefsV2>
            """;
        string foreignContent = """<v141:ForeignFuturePropertyXyz xmlns:v141="http://uri.etsi.org/01903/v1.4.1#"/>""";

        string unsignedSignatureProperties =
            signatureTimeStamp + certificateValues + revocationValues + attrAuthoritiesCertValues +
            attributeRevocationValues + completeRevocationRefs + attributeRevocationRefs +
            completeCertificateRefsV2 + attributeCertificateRefsV2 + foreignContent;

        return Document(signedSignatureProperties, signedDataObjectProperties, unsignedSignatureProperties);
    }


    /// <summary>
    /// Proves the <c>SigningTime</c> qualifying property's clause 5.2.1 lexical <c>xsd:dateTime</c> text and its parsed value both surface on <see
    /// cref="XAdESQualifyingPropertiesFacts"/> — the "signing time (lexical + parsed)" member. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1.
    /// </summary>
    [TestMethod]
    public void SigningTimeSurfacesLexicalAndParsed()
    {
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(ComprehensiveDocument(), BaseMemoryPool.Shared);
        Assert.AreEqual("2024-01-15T10:30:00Z", facts.SigningTimeLexical);
        Assert.AreEqual(new DateTimeOffset(2024, 1, 15, 10, 30, 0, TimeSpan.Zero), facts.SigningTime);
    }


    /// <summary>
    /// Proves every <c>Cert</c> of a <c>SigningCertificateV2</c> (clause 5.2.2) surfaces as a
    /// <see cref="XAdESSigningCertificateDigestFact"/>: the digest bytes, the signer-reference flag on
    /// <c>Cert[0]</c> (clause 5.2.2 NOTE 7), and the opaque <c>IssuerSerialV2</c> blob when present.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.2.
    /// </summary>
    [TestMethod]
    public void SigningCertificateV2DigestsAndIssuerSerialV2Surface()
    {
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(ComprehensiveDocument(), BaseMemoryPool.Shared);
        Assert.HasCount(2, facts.SigningCertificateDigests);
        Assert.IsTrue(facts.SigningCertificateDigests[0].Reference.IsSignerReference);
        Assert.IsFalse(facts.SigningCertificateDigests[1].Reference.IsSignerReference);
        Assert.IsNotNull(facts.SigningCertificateDigests[0].IssuerSerialV2);
        Assert.AreSequenceEqual(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 }, facts.SigningCertificateDigests[0].IssuerSerialV2!.AsReadOnlySpan().ToArray());
        Assert.IsNull(facts.SigningCertificateDigests[1].IssuerSerialV2);
        Assert.AreSequenceEqual(new byte[] { 0x01, 0x01 }, facts.SigningCertificateDigests[0].Reference.CertificateDigest!.AsReadOnlySpan().ToArray());
    }


    /// <summary>
    /// Proves an explicit <c>SignaturePolicyIdentifier</c> (clause 5.2.9.1) surfaces its policy id, hash, and
    /// qualifier presence/count.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.1.
    /// </summary>
    [TestMethod]
    public void ExplicitSignaturePolicySurfacesIdHashAndQualifiers()
    {
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(ComprehensiveDocument(), BaseMemoryPool.Shared);
        Assert.IsNotNull(facts.SignaturePolicy);
        Assert.IsFalse(facts.SignaturePolicy!.IsImplied);
        Assert.AreEqual("urn:oid:1.2.3.4", facts.SignaturePolicy.Id!.Id);
        Assert.AreEqual("Test Policy", facts.SignaturePolicy.Id.Desc);
        Assert.AreSequenceEqual(new byte[] { 0x03, 0x03 }, facts.SignaturePolicy.Hash!.AsReadOnlySpan().ToArray());
        Assert.IsTrue(facts.SignaturePolicy.HasQualifiers);
        Assert.AreEqual(1, facts.SignaturePolicy.QualifierCount);
    }


    /// <summary>
    /// Proves the <c>SignaturePolicyImplied</c> choice arm surfaces as <see cref="XAdESSignaturePolicyFact.IsImplied"/>
    /// with no id/hash — the wire states neither, so none is invented.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9.1.
    /// </summary>
    [TestMethod]
    public void ImpliedSignaturePolicySurfacesNoIdOrHash()
    {
        string document = Document("""<SignaturePolicyIdentifier><SignaturePolicyImplied/></SignaturePolicyIdentifier>""", string.Empty);
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(document, BaseMemoryPool.Shared);
        Assert.IsNotNull(facts.SignaturePolicy);
        Assert.IsTrue(facts.SignaturePolicy!.IsImplied);
        Assert.IsNull(facts.SignaturePolicy.Id);
        Assert.IsNull(facts.SignaturePolicy.Hash);
    }


    /// <summary>
    /// Proves <c>SignatureProductionPlaceV2</c>'s presence (clause 5.2.5) surfaces as a bare boolean — this facts shape's own "format/production-place presence" member; content decode is
    /// the leaf's own concern, not this facts shape's. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.5.
    /// </summary>
    [TestMethod]
    public void SignatureProductionPlacePresenceSurfaces()
    {
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(ComprehensiveDocument(), BaseMemoryPool.Shared);
        Assert.IsTrue(facts.HasSignatureProductionPlace);

        using XAdESQualifyingPropertiesFacts absentFacts = ParseFacts(Document("<SigningTime>2024-01-15T10:30:00Z</SigningTime>", string.Empty), BaseMemoryPool.Shared);
        Assert.IsFalse(absentFacts.HasSignatureProductionPlace);
    }


    /// <summary>
    /// Proves <c>SignerRoleV2</c>'s (clause 5.2.6) claimed/certified/signed-assertion CARDINALITY surfaces on the shared <see cref="AdESSignerAttributes"/> hook. Anchored
    /// to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.6.
    /// </summary>
    [TestMethod]
    public void SignerRoleV2CardinalitySurfacesOnAdESSignerAttributes()
    {
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(ComprehensiveDocument(), BaseMemoryPool.Shared);
        Assert.IsNotNull(facts.SignerRole);
        Assert.AreEqual(1, facts.SignerRole!.Certified?.Count);
        Assert.AreEqual(1, facts.SignerRole.Claimed?.Count);
        Assert.AreEqual(1, facts.SignerRole.SignedAssertions?.Count);
    }


    /// <summary>
    /// Proves every <c>CommitmentTypeIndication</c> (clause 5.2.3) surfaces its own <c>ObjectIdentifier</c>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.3.
    /// </summary>
    [TestMethod]
    public void CommitmentTypeIdentifiersSurface()
    {
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(ComprehensiveDocument(), BaseMemoryPool.Shared);
        Assert.HasCount(1, facts.CommitmentTypeIdentifiers);
        Assert.AreEqual("http://example.com/commitment/proof-of-origin", facts.CommitmentTypeIdentifiers[0].Id);
    }


    /// <summary>
    /// Proves <c>DataObjectFormat</c> (clause 5.2.4) occurrences are counted.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.4.
    /// </summary>
    [TestMethod]
    public void DataObjectFormatCountSurfaces()
    {
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(ComprehensiveDocument(), BaseMemoryPool.Shared);
        Assert.AreEqual(1, facts.DataObjectFormatCount);
    }


    /// <summary>
    /// Proves <c>AllDataObjectsTimeStamp</c>/<c>IndividualDataObjectsTimeStamp</c> (clause 5.2.8) tokens surface
    /// as <see cref="EmbeddedTimestamp"/> under <see cref="SignatureTimestampClass.ContentTimestamp"/> — "applied
    /// before signing," the class's own clause 4.2.5.8 definition, matching both properties' own semantics.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clauses 5.2.8.1/5.2.8.2.
    /// </summary>
    [TestMethod]
    public void DataObjectTimestampsSurfaceAsContentTimestampClass()
    {
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(ComprehensiveDocument(), BaseMemoryPool.Shared);
        var contentTimestamps = facts.Timestamps.Where(t => t.Class == SignatureTimestampClass.ContentTimestamp).ToList();
        Assert.HasCount(2, contentTimestamps);
        Assert.Contains(t => t.Identifier == "AllDataObjectsTimeStamp", contentTimestamps);
        Assert.Contains(t => t.Identifier == "IndividualDataObjectsTimeStamp", contentTimestamps);

        XAdESTimestampContainerMetadata adoTstContainer = facts.TimestampContainers.Single(c => c.Kind == XAdESTimestampContainerKind.AllDataObjectsTimeStamp);
        Assert.AreEqual(1, adoTstContainer.TokenCount);
        Assert.IsFalse(adoTstContainer.HasInclude);
    }


    /// <summary>
    /// Proves <c>SignatureTimeStamp</c> (clause 5.3) surfaces as <see cref="SignatureTimestampClass.SignatureTimestamp"/>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.3.
    /// </summary>
    [TestMethod]
    public void SignatureTimeStampSurfacesAsSignatureTimestampClass()
    {
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(ComprehensiveDocument(), BaseMemoryPool.Shared);
        Assert.ContainsSingle(t => t.Class == SignatureTimestampClass.SignatureTimestamp && t.Identifier == "SignatureTimeStamp", facts.Timestamps);
    }


    /// <summary>
    /// Proves <c>CounterSignature</c> (clause 5.2.7.2) occurrences are counted — via an isolated fixture with no
    /// other unsigned content, since <c>CounterSignature</c> embeds a whole nested <c>ds:Signature</c> and this
    /// delegate scopes to exactly one <c>ds:Signature</c> per document.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.2.
    /// </summary>
    [TestMethod]
    public void CounterSignatureCountIsNotConflatedWithTheEmbeddingSignature()
    {
        //Proves the field exists and starts at zero when absent -- CounterSignature's own nested ds:Signature
        //means a document that carries one is out of this delegate's "exactly one signature" scope (see the
        //ComprehensiveDocument() remarks), a documented, disclosed limitation rather than a silent one.
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(ComprehensiveDocument(), BaseMemoryPool.Shared);
        Assert.AreEqual(0, facts.CounterSignatureCount);
    }


    /// <summary>
    /// Proves <c>CertificateValues</c>/<c>AttrAuthoritiesCertValues</c> (clauses 5.4.2/5.4.4) certificates flow
    /// into <see cref="XAdESQualifyingPropertiesFacts.EmbeddedCertificates"/>, and <c>RevocationValues</c>/
    /// <c>AttributeRevocationValues</c> (clauses 5.4.3/5.4.5) CRLs/OCSP responses flow into the matching lists,
    /// while <see cref="XAdESValidationDataCounts"/> keeps the per-property-kind occurrence counts distinct.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clauses 5.4.2-5.4.5.
    /// </summary>
    [TestMethod]
    public void ValidationDataValuesFlowIntoEmbeddedListsAndCounts()
    {
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(ComprehensiveDocument(), BaseMemoryPool.Shared);
        Assert.HasCount(2, facts.EmbeddedCertificates);
        Assert.HasCount(2, facts.EmbeddedCertificateRevocationLists);
        Assert.HasCount(1, facts.EmbeddedOcspResponses);
        Assert.AreEqual(1, facts.ValidationData.CertificateValuesCount);
        Assert.AreEqual(1, facts.ValidationData.AttrAuthoritiesCertValuesCount);
        Assert.AreEqual(1, facts.ValidationData.RevocationValuesCount);
        Assert.AreEqual(1, facts.ValidationData.AttributeRevocationValuesCount);
        Assert.AreEqual(1, facts.ValidationData.CompleteRevocationRefsCount);
        Assert.AreEqual(1, facts.ValidationData.AttributeRevocationRefsCount);
    }


    /// <summary>
    /// Proves every <c>Cert</c> entry of <c>CompleteCertificateRefsV2</c>/<c>AttributeCertificateRefsV2</c> (Annex A.1.1/A.1.3) surfaces as a <see
    /// cref="XAdESCertificateReferenceDigestFact"/>, the shared <c>CertIDListV2Type</c> shape with <c>IssuerSerialV2</c> carried when present. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.1, A.1.3.
    /// </summary>
    [TestMethod]
    public void CompleteAndAttributeCertificateRefsSurfaceAsDigestFacts()
    {
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(ComprehensiveDocument(), BaseMemoryPool.Shared);

        Assert.HasCount(1, facts.CompleteCertificateRefs);
        Assert.AreSequenceEqual(new byte[] { 0x0C, 0x0C }, facts.CompleteCertificateRefs[0].Digest.AsReadOnlySpan().ToArray());
        Assert.IsNotNull(facts.CompleteCertificateRefs[0].IssuerSerialV2);
        Assert.AreSequenceEqual(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x02 }, facts.CompleteCertificateRefs[0].IssuerSerialV2!.AsReadOnlySpan().ToArray());

        Assert.HasCount(1, facts.AttributeCertificateRefs);
        Assert.AreSequenceEqual(new byte[] { 0x0D, 0x0D }, facts.AttributeCertificateRefs[0].Digest.AsReadOnlySpan().ToArray());
        Assert.IsNull(facts.AttributeCertificateRefs[0].IssuerSerialV2);
    }


    /// <summary>
    /// Proves every <c>CRLRef</c>/<c>OCSPRef</c> entry of <c>CompleteRevocationRefs</c>/<c>AttributeRevocationRefs</c>
    /// (Annex A.1.2/A.1.4) surfaces as a <see cref="XAdESCrlReferenceFact"/>/<see cref="XAdESOcspReferenceFact"/>:
    /// the mandatory <c>CRLRef</c> digest plus its optional <c>CRLIdentifier</c> fields (<c>Issuer</c>/<c>IssueTime</c>
    /// lexical and parsed/<c>Number</c>/<c>URI</c>), and the <c>OCSPRef</c>'s own optional digest plus its
    /// mandatory <c>OCSPIdentifier</c> (<c>ByName</c>/<c>ByKey</c> responder, <c>ProducedAt</c> lexical and parsed).
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.2, A.1.4.
    /// </summary>
    [TestMethod]
    public void CompleteAndAttributeRevocationRefsSurfaceCrlAndOcspFacts()
    {
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(ComprehensiveDocument(), BaseMemoryPool.Shared);

        Assert.HasCount(1, facts.CompleteRevocationCrlRefs);
        XAdESCrlReferenceFact crlRef = facts.CompleteRevocationCrlRefs[0];
        Assert.AreSequenceEqual(new byte[] { 0x09, 0x09 }, crlRef.Digest.AsReadOnlySpan().ToArray());
        Assert.IsTrue(crlRef.HasCrlIdentifier);
        Assert.AreEqual("CN=Test CA", crlRef.Issuer);
        Assert.AreEqual("2024-01-01T00:00:00Z", crlRef.IssueTimeLexical);
        Assert.AreEqual(new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero), crlRef.IssueTime);
        Assert.IsTrue(crlRef.HasNumber);
        Assert.AreEqual(42, crlRef.Number);
        Assert.IsTrue(crlRef.HasUri);
        Assert.AreEqual("http://example.com/crl1", crlRef.Uri);

        Assert.HasCount(1, facts.CompleteRevocationOcspRefs);
        XAdESOcspReferenceFact ocspRef = facts.CompleteRevocationOcspRefs[0];
        Assert.IsTrue(ocspRef.HasDigestAlgAndValue);
        Assert.AreSequenceEqual(new byte[] { 0x0A, 0x0A }, ocspRef.Digest!.AsReadOnlySpan().ToArray());
        Assert.AreEqual(XAdESOcspResponderIdKind.ByName, ocspRef.ResponderKind);
        Assert.AreEqual("CN=Test Responder", ocspRef.ResponderByName);
        Assert.IsNull(ocspRef.ResponderByKeyOctets);
        Assert.AreEqual("2024-01-02T00:00:00Z", ocspRef.ProducedAtLexical);
        Assert.AreEqual(new DateTimeOffset(2024, 1, 2, 0, 0, 0, TimeSpan.Zero), ocspRef.ProducedAt);
        Assert.IsTrue(ocspRef.HasUri);
        Assert.AreEqual("http://example.com/ocsp1", ocspRef.Uri);

        Assert.HasCount(1, facts.AttributeRevocationCrlRefs);
        Assert.IsFalse(facts.AttributeRevocationCrlRefs[0].HasCrlIdentifier);

        Assert.HasCount(1, facts.AttributeRevocationOcspRefs);
        XAdESOcspReferenceFact attributeOcspRef = facts.AttributeRevocationOcspRefs[0];
        Assert.IsFalse(attributeOcspRef.HasDigestAlgAndValue);
        Assert.IsNull(attributeOcspRef.Digest);
        Assert.AreEqual(XAdESOcspResponderIdKind.ByKey, attributeOcspRef.ResponderKind);
        Assert.IsNull(attributeOcspRef.ResponderByName);
        Assert.IsNotNull(attributeOcspRef.ResponderByKeyOctets);
        Assert.AreSequenceEqual(new byte[] { 0x01, 0x02, 0x03, 0x04 }, attributeOcspRef.ResponderByKeyOctets!.AsReadOnlySpan().ToArray());
    }


    /// <summary>
    /// Proves the Annex A.1.1/A.1.2's own closing conditional-<c>shall</c> paragraph's structural ANTECEDENT
    /// surfaces on <see cref="XAdESQualifyingPropertiesFacts.CertificateValidationDataTriggered"/>/
    /// <see cref="XAdESQualifyingPropertiesFacts.RevocationValidationDataTriggered"/> — <see langword="true"/>
    /// when the fixture's own <c>CertificateValues</c>/<c>RevocationValues</c> occurrences trigger it.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.1, A.1.2.
    /// </summary>
    [TestMethod]
    public void ValidationDataTriggerAntecedentsSurface()
    {
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(ComprehensiveDocument(), BaseMemoryPool.Shared);
        Assert.IsTrue(facts.CertificateValidationDataTriggered);
        Assert.IsTrue(facts.RevocationValidationDataTriggered);

        string document = Document("<SigningTime>2024-01-15T10:30:00Z</SigningTime>", string.Empty, "<SignatureTimeStamp><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></SignatureTimeStamp>");
        using XAdESQualifyingPropertiesFacts untriggered = ParseFacts(document, BaseMemoryPool.Shared);
        Assert.IsFalse(untriggered.CertificateValidationDataTriggered);
        Assert.IsFalse(untriggered.RevocationValidationDataTriggered);
    }


    /// <summary>
    /// Proves <see cref="XAdESOcspResponderIdKind"/> (the Pki-side mirror <see cref="XAdESQualifyingPropertiesFacts"/> carries since
    /// <c>Verifiable.Cryptography</c> never references <c>Verifiable.Xml</c>) is a bijection with the leaf's own <see
    /// cref="Verifiable.Xml.XAdESResponderIdKind"/> — same member names, same count, the narrow-restatement pattern, over Annex A.1.2's
    /// <c>ResponderIDType</c> choice of <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>.
    /// </summary>
    [TestMethod]
    public void OcspResponderIdKindIsABijectionWithTheLeafEnum()
    {
        string[] pkiNames = Enum.GetNames<XAdESOcspResponderIdKind>();
        string[] leafNames = Enum.GetNames<Verifiable.Xml.XAdESResponderIdKind>();

        Assert.AreSequenceEqual(leafNames, pkiNames);
    }


    /// <summary>
    /// Proves a genuinely foreign <c>UnsignedSignatureProperties</c> child (a future v1.4.1-namespace element this parse does not classify) is tolerated and recorded, per
    /// this library's own "unmodeled entries" posture — never a refusal, since the container is unsigned. The recorded observation carries the element's own namespace alongside its
    /// local name in Clark notation, not the local name alone. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.6.
    /// </summary>
    [TestMethod]
    public void ForeignUnsignedPropertyIsRecordedAsUnknown()
    {
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(ComprehensiveDocument(), BaseMemoryPool.Shared);
        Assert.Contains(name => name == "{http://uri.etsi.org/01903/v1.4.1#}ForeignFuturePropertyXyz", facts.UnknownPropertyObservations);
    }


    /// <summary>
    /// Proves the guarantee: a foreign element deliberately named identically to a real property
    /// (<c>ArchiveTimeStamp</c>) but declared in an attacker-chosen namespace is recorded with THAT namespace,
    /// not the real v1.4.1-namespace property's — the observation text is not confusable between the two,
    /// unlike a local-name-only record would be.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.6.
    /// </summary>
    [TestMethod]
    public void ForeignElementSharingARealPropertysLocalNameIsDistinguishedByNamespace()
    {
        string document = Document(
            "<SigningTime>2024-01-15T10:30:00Z</SigningTime>",
            string.Empty,
            """<v141:ArchiveTimeStamp xmlns:v141="urn:attacker:not-xades"/>""");
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(document, BaseMemoryPool.Shared);

        Assert.Contains(name => name == "{urn:attacker:not-xades}ArchiveTimeStamp", facts.UnknownPropertyObservations);
        Assert.DoesNotContain(name => name.EndsWith("v1.4.1#}ArchiveTimeStamp", StringComparison.Ordinal), facts.UnknownPropertyObservations);
    }


    /// <summary>
    /// Proves the Annex-A v1.4.1-namespace properties — <c>ArchiveTimeStamp</c> (clause 5.5.2, dispatched via
    /// the <c>Unrecognized</c> catch-all per <see cref="XAdESUnsignedSignatureProperties"/>'s own remarks),
    /// <c>SigAndRefsTimeStampV2</c> (A.1.5.1), <c>RefsOnlyTimeStampV2</c> (A.1.5.2) — surface their tokens under
    /// <see cref="SignatureTimestampClass.ArchiveTimestamp"/>/<see cref="SignatureTimestampClass.ValidationDataTimestamp"/>
    /// respectively.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clauses 5.5.2, A.1.5.1, A.1.5.2.
    /// </summary>
    [TestMethod]
    public void AnnexATimestampsSurfaceOnTheirOwnClasses()
    {
        string unsigned = """
            <v141:ArchiveTimeStamp xmlns:v141="http://uri.etsi.org/01903/v1.4.1#"><EncapsulatedTimeStamp>QQ==</EncapsulatedTimeStamp></v141:ArchiveTimeStamp>
            <v141:SigAndRefsTimeStampV2 xmlns:v141="http://uri.etsi.org/01903/v1.4.1#"><EncapsulatedTimeStamp>Qg==</EncapsulatedTimeStamp></v141:SigAndRefsTimeStampV2>
            <v141:RefsOnlyTimeStampV2 xmlns:v141="http://uri.etsi.org/01903/v1.4.1#"><EncapsulatedTimeStamp>Qw==</EncapsulatedTimeStamp></v141:RefsOnlyTimeStampV2>
            """;
        string document = Document("<SigningTime>2024-01-15T10:30:00Z</SigningTime>", string.Empty, unsigned);
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(document, BaseMemoryPool.Shared);

        Assert.ContainsSingle(t => t.Class == SignatureTimestampClass.ArchiveTimestamp, facts.Timestamps);
        Assert.AreEqual(2, facts.Timestamps.Count(t => t.Class == SignatureTimestampClass.ValidationDataTimestamp));
        Assert.AreEqual(1, facts.SignedPropertyOccurrenceCounts[XAdESBaselineLevelTable.SigningTime.Name]);
        Assert.AreEqual(1, facts.UnsignedPropertyOccurrenceCounts[XAdESBaselineLevelTable.ArchiveTimeStamp.Name]);
        Assert.AreEqual(1, facts.UnsignedPropertyOccurrenceCounts[XAdESBaselineLevelTable.SigAndRefsTimeStampV2.Name]);
        Assert.AreEqual(1, facts.UnsignedPropertyOccurrenceCounts[XAdESBaselineLevelTable.RefsOnlyTimeStampV2.Name]);
    }


    /// <summary>
    /// Proves the v1.4.1-namespace <c>SignaturePolicyStore</c> (clause 5.2.10), <c>TimeStampValidationData</c>
    /// (clause 5.5.1), <c>AnyValidationData</c> (clause 5.4.6) and <c>RenewedDigestsV2</c> (clause 5.5.3)
    /// occurrences are counted through the same <c>Unrecognized</c> dispatch, and <c>TimeStampValidationData</c>'s
    /// own embedded certificate flows into <see cref="XAdESQualifyingPropertiesFacts.EmbeddedCertificates"/>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clauses 5.2.10, 5.5.1, 5.4.6, 5.5.3.
    /// </summary>
    [TestMethod]
    public void AnnexAValidationDataPropertiesAreCounted()
    {
        string sigPolicyStore = $"""
            <v141:SignaturePolicyStore xmlns:v141="{V141}">
              <v141:SPDocSpecification><Identifier>http://example.com/policy-spec</Identifier></v141:SPDocSpecification>
              <v141:SignaturePolicyDocument>AQ==</v141:SignaturePolicyDocument>
            </v141:SignaturePolicyStore>
            """;
        string timeStampValidationData = $"""
            <v141:TimeStampValidationData xmlns:v141="{V141}" URI="#ts1">
              <CertificateValues><EncapsulatedX509Certificate>MAMCAQc=</EncapsulatedX509Certificate></CertificateValues>
            </v141:TimeStampValidationData>
            """;
        string anyValidationData = $"""
            <v141:AnyValidationData xmlns:v141="{V141}">
              <RevocationValues><CRLValues><EncapsulatedCRLValue>MAMCAQg=</EncapsulatedCRLValue></CRLValues></RevocationValues>
            </v141:AnyValidationData>
            """;
        string renewedDigestsV2 = $"""
            <v141:RenewedDigestsV2 xmlns:v141="{V141}" xmlns:ds="{DsNamespace}">
              <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
              <ds:DigestMethod Algorithm="{DigestMethodAlgorithm}"/>
              <v141:RecomputedDigestValue><v141:NewSDODigestValue>AQ==</v141:NewSDODigestValue><v141:OriginalRefDigest>Ag==</v141:OriginalRefDigest></v141:RecomputedDigestValue>
            </v141:RenewedDigestsV2>
            """;

        string document = Document("<SigningTime>2024-01-15T10:30:00Z</SigningTime>", string.Empty, sigPolicyStore + timeStampValidationData + anyValidationData + renewedDigestsV2);
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(document, BaseMemoryPool.Shared);

        Assert.AreEqual(1, facts.ValidationData.SignaturePolicyStoreCount);
        Assert.AreEqual(1, facts.ValidationData.TimeStampValidationDataCount);
        Assert.AreEqual(1, facts.ValidationData.AnyValidationDataCount);
        Assert.AreEqual(1, facts.ValidationData.RenewedDigestsV2Count);
        Assert.HasCount(1, facts.EmbeddedCertificates);
        Assert.HasCount(1, facts.EmbeddedCertificateRevocationLists);
    }


    /// <summary>
    /// Proves the clause 4.4/4.3.1/4.4.2 discovery/binding outcome — the <c>Target</c> resolving to the
    /// enclosing <c>ds:Signature</c> and the <c>SignedProperties</c>-typed reference dereferencing to the exact
    /// discovered node — surfaces on <see cref="XAdESDiscoveryFact"/>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clauses 4.3.1, 4.4.1, 4.4.2.
    /// </summary>
    [TestMethod]
    public void DiscoveryFactReportsTargetAndSignedPropertiesReferenceBinding()
    {
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(ComprehensiveDocument(), BaseMemoryPool.Shared);
        Assert.IsTrue(facts.Discovery.HasQualifyingProperties);
        Assert.IsTrue(facts.Discovery.TargetResolvedToSignature);
        Assert.IsTrue(facts.Discovery.SignedPropertiesReferencePresent);
        Assert.IsTrue(facts.Discovery.SignedPropertiesReferenceResolvedToDiscoveredNode);
        Assert.AreEqual(0, facts.Discovery.QualifyingPropertiesReferenceCount);
    }


    /// <summary>
    /// Proves every key of <see cref="XAdESQualifyingPropertiesFacts.SignedPropertyOccurrenceCounts"/>/ <see cref="XAdESQualifyingPropertiesFacts.UnsignedPropertyOccurrenceCounts"/> matches an EXACT <see
    /// cref="AdESTableRow.Name"/> registered in <see cref="XAdESBaselineLevelTable.Rows"/> — the presence/cardinality inventory's own load-bearing claim (the type remarks' "no XML type anywhere in this
    /// reach"). Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 (Table 2).
    /// </summary>
    [TestMethod]
    public void OccurrenceCountKeysMatchRegisteredTableRowNames()
    {
        using XAdESQualifyingPropertiesFacts facts = ParseFacts(ComprehensiveDocument(), BaseMemoryPool.Shared);
        var registeredNames = XAdESBaselineLevelTable.Rows.Select(r => r.Name).ToHashSet(StringComparer.Ordinal);

        foreach(string key in facts.SignedPropertyOccurrenceCounts.Keys)
        {
            Assert.Contains(name => string.Equals(name, key, StringComparison.Ordinal), registeredNames);
        }

        foreach(string key in facts.UnsignedPropertyOccurrenceCounts.Keys)
        {
            Assert.Contains(name => string.Equals(name, key, StringComparison.Ordinal), registeredNames);
        }
    }


    /// <summary>
    /// Proves every carrier the comprehensive fixture rents is released once the returned facts are disposed — the no-naked-bytes/pool-injection discipline this seam's own delegate implementation
    /// must honour, over a full clause 4.4.1 discovery-and-read pass of the fixture. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.1.
    /// </summary>
    [TestMethod]
    public void CustodyBalancesToZeroAfterDispose()
    {
        using var metered = new MeteredHousePool();
        XAdESQualifyingPropertiesParseResult result = XAdESSignatureFactsDelegates.ParseAsync(Encoding.UTF8.GetBytes(ComprehensiveDocument()), metered.Pool, TestContext.CancellationToken).AsTask().GetAwaiter().GetResult();
        Assert.IsTrue(result.IsParsed, $"The fixture must parse but was refused with {result.FailureReason}.");
        result.Dispose();

        Assert.AreEqual(0L, metered.OutstandingCount, "Every rented buffer the parse produced must be returned once the caller disposes the result.");
    }


    /// <summary>
    /// Proves a document that is not well-formed XML maps to <see cref="SignatureFactsStatus.FormatFailure"/> at the seam level, never an exception — EN 319 102-1 clause 5.2.2.3's own <c>FAILED</c>
    /// outcome. Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">ETSI EN 319 102-1 V1.4.1</see> clause 5.2.2.3.
    /// </summary>
    [TestMethod]
    public async Task NotWellFormedXmlMapsToFormatFailure()
    {
        SignatureFormatSeam seam = XAdESSignatureFacts.CreateSeam(XAdESSignatureFactsDelegates.ParseAsync, XAdESSignatureFactsDelegates.VerifyValueAsync);
        using SignedContentMemory signedDataObject = SignedContentMemory.FromBytes("<not-well-formed"u8, BaseMemoryPool.Shared);
        var context = new SignatureFactsExtractionContext { SignedDataObject = signedDataObject };

        using SignatureFacts facts = await seam.ExtractFacts(context, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.AreEqual(SignatureFactsStatus.FormatFailure, facts.Status);
        Assert.AreEqual(SignatureFormatIdentifier.XAdES, facts.Format);
        Assert.IsNotNull(facts.FormatFailureReason);
    }


    /// <summary>
    /// Proves a well-formed <c>ds:Signature</c> carrying no <c>QualifyingProperties</c> at all is a <see cref="SignatureFactsStatus.FormatFailure"/> — it simply is not a XAdES signature. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.1 (a <c>QualifyingProperties</c> element must be incorporated).
    /// </summary>
    [TestMethod]
    public void SignatureWithNoQualifyingPropertiesIsFormatFailure()
    {
        string document = $"""
            <ds:Signature xmlns:ds="{DsNamespace}">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{XmlSignatureIdentifiers.CanonicalXml11Uri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodAlgorithm}"/>
                {Reference("ref-data1", "#data1")}
              </ds:SignedInfo>
              <ds:SignatureValue>AQ==</ds:SignatureValue>
            </ds:Signature>
            """;

        XAdESQualifyingPropertiesParseResult result = XAdESSignatureFactsDelegates.ParseAsync(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask().GetAwaiter().GetResult();
        using(result)
        {
            Assert.IsFalse(result.IsParsed);
        }
    }


    /// <summary>
    /// Proves a document carrying two <c>ds:Signature</c> elements is a format failure — this binding surfaces the facts of exactly one signature, mirroring <c>CAdESSignatureFacts</c>'s own "first SignerInfo alone" posture. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.4.1 (the target-of-one-signature discovery scope).
    /// </summary>
    [TestMethod]
    public void MultipleSignaturesIsFormatFailure()
    {
        string one = Document("<SigningTime/>", string.Empty);
        string two = one.Replace("Id=\"sig1\"", "Id=\"sig2\"", StringComparison.Ordinal);
        string document = $"<root>{one}{two}</root>";

        XAdESQualifyingPropertiesParseResult result = XAdESSignatureFactsDelegates.ParseAsync(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask().GetAwaiter().GetResult();
        using(result)
        {
            Assert.IsFalse(result.IsParsed);
        }
    }


    /// <summary>
    /// Proves <see cref="XAdESSignatureFacts.CreateSeam"/>'s <see cref="SignatureFormatSeam.ExtractFacts"/> maps the richer <see cref="XAdESQualifyingPropertiesFacts"/> onto the format-neutral <see
    /// cref="SignatureFacts"/> the EN 319 102-1 building blocks consume: one <see cref="SignatureAttributeFacts"/> per property occurrence (the presence/cardinality inventory reused as the shared engine's
    /// own attribute list), <see cref="SignatureFacts.SigningCertificateReferences"/>, <see cref="SignatureFacts.Timestamps"/> and <see cref="SignatureFacts.ClaimedSigningTime"/>/<see
    /// cref="SignatureFacts.SignaturePolicyIdentifier"/> all populated. Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319
    /// 132-1 V1.3.1</see> clause 6.3 (Table 2).
    /// </summary>
    [TestMethod]
    public async Task CreateSeamExtractFactsPopulatesTheFormatNeutralShape()
    {
        SignatureFormatSeam seam = XAdESSignatureFacts.CreateSeam(XAdESSignatureFactsDelegates.ParseAsync, XAdESSignatureFactsDelegates.VerifyValueAsync);
        using SignedContentMemory signedDataObject = SignedContentMemory.FromBytes(Encoding.UTF8.GetBytes(ComprehensiveDocument()), BaseMemoryPool.Shared);
        var context = new SignatureFactsExtractionContext { SignedDataObject = signedDataObject };

        using SignatureFacts facts = await seam.ExtractFacts(context, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.AreEqual(SignatureFactsStatus.Extracted, facts.Status);
        Assert.AreEqual(SignatureFormatIdentifier.XAdES, facts.Format);
        Assert.ContainsSingle(a => a.Identifier == XAdESBaselineLevelTable.SigningTime.Name && a.Scope == SignatureAttributeScope.Signed, facts.Attributes);
        Assert.AreEqual(2, facts.Attributes.Count(a => a.Identifier == XAdESBaselineLevelTable.CertificateValues.Name || a.Identifier == XAdESBaselineLevelTable.AttrAuthoritiesCertValues.Name));
        Assert.HasCount(2, facts.SigningCertificateReferences);
        Assert.IsNotEmpty(facts.Timestamps);
        Assert.AreEqual(new DateTimeOffset(2024, 1, 15, 10, 30, 0, TimeSpan.Zero), facts.ClaimedSigningTime);
        Assert.AreEqual("urn:oid:1.2.3.4", facts.SignaturePolicyIdentifier);
    }


    private static X509Certificate2 CreateSelfSignedCertificate(RSA key)
    {
        var request = new CertificateRequest("CN=Verifiable XAdES Facts Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        DateTimeOffset now = TimeProvider.System.GetUtcNow();

        return request.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
    }


    /// <summary>
    /// Proves <see cref="XAdESSignatureFactsDelegates.VerifyValueAsync"/> — the injected <see cref="VerifyXAdESSignatureValueDelegate"/> — reports <see cref="SignatureCryptographicOutcome.Verified"/> for a genuinely signed document and
    /// <see cref="SignatureCryptographicOutcome.SignatureValueFailure"/> once a single byte of the reference-covered content is tampered — real RSA-SHA256 cryptography via the BCL's own <see cref="SignedXml"/>, mirroring
    /// <c>XmlSignatureInteropCorpusGenerator</c>'s precedent. Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">ETSI EN 319 102-1 V1.4.1</see> clause 5.2.7.4 (the
    /// check this delegate performs).
    /// </summary>
    [TestMethod]
    public void VerifyValueAsyncReportsVerifiedThenSignatureValueFailureOnTampering()
    {
        using RSA rsaKey = RSA.Create(2048);
        using X509Certificate2 certificate = CreateSelfSignedCertificate(rsaKey);

        var document = new XmlDocument();
        var signedXml = new SignedXml(document) { SigningKey = rsaKey };
        signedXml.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = SignatureMethodAlgorithm;

        XmlDocument fragmentDocument = new();
        fragmentDocument.LoadXml("""<Data>payload</Data>""");
        signedXml.AddObject(new DataObject("obj1", string.Empty, string.Empty, fragmentDocument.DocumentElement!));

        var reference = new Reference("#obj1") { DigestMethod = DigestMethodAlgorithm };
        reference.AddTransform(new XmlDsigC14NTransform());
        signedXml.AddReference(reference);
        signedXml.KeyInfo!.AddClause(new KeyInfoX509Data(certificate));

        signedXml.ComputeSignature();

        XmlDocument outputDocument = new();
        outputDocument.AppendChild(outputDocument.ImportNode(signedXml.GetXml(), deep: true));
        byte[] signedBytes = Encoding.UTF8.GetBytes(outputDocument.OuterXml);

        IMemoryOwner<byte> certificateOwner = BaseMemoryPool.Shared.Rent(certificate.RawData.Length);
        certificate.RawData.CopyTo(certificateOwner.Memory.Span);
        using PkiCertificateMemory signingCertificate = new(certificateOwner, PkiCertificateTags.X509Certificate);

        SignatureCryptographicVerification verified = XAdESSignatureFactsDelegates.VerifyValueAsync(signedBytes, signingCertificate, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask().GetAwaiter().GetResult();
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, verified.Outcome, verified.Reason);

        string tamperedXml = outputDocument.OuterXml.Replace("payload", "PAYLOAD", StringComparison.Ordinal);
        SignatureCryptographicVerification tampered = XAdESSignatureFactsDelegates.VerifyValueAsync(Encoding.UTF8.GetBytes(tamperedXml), signingCertificate, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask().GetAwaiter().GetResult();
        Assert.AreEqual(SignatureCryptographicOutcome.SignatureValueFailure, tampered.Outcome);
    }
}
