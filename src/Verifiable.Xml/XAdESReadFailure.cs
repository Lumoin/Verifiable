namespace Verifiable.Xml;

/// <summary>
/// The reason a XAdES qualifying-property structural read was refused, per
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// A separate enumeration from <see cref="XmlSignatureReadFailure"/>: that type's own doc comment scopes it
/// to "the <c>ds</c>-namespace element and attribute grammar ... sections 4 and 5" of XMLDSIG, and XAdES is a
/// different specification with its own clause numbering. This leaf's XAdES readers reuse the XMLDSIG
/// grammar PRIMITIVES (<see cref="XmlSignatureModelGrammar"/>, bridged through <see cref="XAdESGrammar"/>)
/// but report their own refusals exclusively through this type: a XAdES layer needs its own parallel failure
/// enum rather than overloading the XMLDSIG one.
/// </para>
/// <para>
/// Reading is result-shaped: a structural refusal is reported as an <see cref="XAdESReadError"/> carrying one
/// of these reasons and the byte offset at which it was determined, never as an exception. This is the one
/// shared XAdES structural-read failure enum for the whole leaf: every XAdES-family reader reports through
/// it, mirroring the role <see cref="XmlSignatureReadFailure"/> plays for the <c>ds</c> family.
/// </para>
/// </remarks>
public enum XAdESReadFailure
{
    /// <summary>
    /// A mandatory child element is absent: <c>ObjectIdentifierType</c>'s <c>Identifier</c> (clause 5.1.2);
    /// a <c>DigestAlgAndValueType</c>-shaped element's <c>ds:DigestMethod</c> or <c>ds:DigestValue</c> (first
    /// declared at clause 5.2.2 as <c>CertDigest</c>'s content, reused unchanged for <c>SigPolicyHash</c>/
    /// <c>DigestAlgAndValue</c>); or
    /// <c>ObjectIdentifierType</c>'s <c>DocumentationReferences</c> present but carrying zero
    /// <c>DocumentationReference</c> children, where the schema's <c>maxOccurs="unbounded"</c> sequence
    /// carries a default <c>minOccurs="1"</c>. Annex A.1.1–A.1.4 add: the mandatory <c>CertRefs</c> child of
    /// <c>CompleteCertificateRefsV2</c>/<c>AttributeCertificateRefsV2</c>, or a <c>CertIDListV2Type</c>-shaped
    /// element (either binding) carrying zero <c>Cert</c> entries; a present <c>CRLRefs</c>/<c>OCSPRefs</c>/
    /// <c>OtherRefs</c> list carrying zero <c>CRLRef</c>/<c>OCSPRef</c>/<c>OtherRef</c> entries, where the
    /// schema's <c>maxOccurs="unbounded"</c> children default to <c>minOccurs="1"</c>; a <c>CRLRef</c>'s
    /// mandatory <c>DigestAlgAndValue</c>, a <c>CRLIdentifier</c>'s mandatory <c>Issuer</c>/<c>IssueTime</c>,
    /// an <c>OCSPRef</c>'s mandatory <c>OCSPIdentifier</c>, an <c>OCSPIdentifier</c>'s mandatory
    /// <c>ResponderID</c>/<c>ProducedAt</c>, or a <c>ResponderID</c> choice with neither <c>ByName</c> nor
    /// <c>ByKey</c> present.
    /// </summary>
    MissingRequiredChild,

    /// <summary>
    /// A mandatory attribute is absent: a <c>ds:DigestMethod</c> child of a <c>DigestAlgAndValueType</c>-
    /// shaped element without its <c>Algorithm</c> attribute.
    /// </summary>
    MissingRequiredAttribute,

    /// <summary>
    /// An element the fixed-order content model of <c>ObjectIdentifierType</c> (clause 5.1.2) already
    /// consumed once — <c>Description</c> or <c>DocumentationReferences</c> — appears a second time. Annex
    /// A.1.1–A.1.4 add: a second <c>CertRefs</c> child of <c>CompleteCertificateRefsV2</c>/
    /// <c>AttributeCertificateRefsV2</c>, or a second <c>CRLRefs</c>/<c>OCSPRefs</c>/<c>OtherRefs</c>/
    /// <c>Issuer</c>/<c>IssueTime</c>/<c>Number</c>/<c>ResponderID</c>/<c>ProducedAt</c>/
    /// <c>DigestAlgAndValue</c>/<c>CRLIdentifier</c> child of a content model that already consumed one.
    /// </summary>
    DuplicateCoreChild,

    /// <summary>
    /// An element appears at a position its content model does not declare it for: a trailing or out-of-
    /// order element in <c>ObjectIdentifierType</c>'s <c>Identifier, Description?, DocumentationReferences?</c>
    /// sequence (clause 5.1.2); a <c>DocumentationReferences</c> child other than <c>DocumentationReference</c>;
    /// or a <c>DigestAlgAndValueType</c>-shaped element's children in the wrong order or naming an element
    /// other than <c>ds:DigestMethod</c>/<c>ds:DigestValue</c>. Annex A.1.1–A.1.4 add: a
    /// <c>CertRefs</c>/<c>CRLRefs</c>/<c>OCSPRefs</c>/<c>OtherRefs</c>/<c>CRLRef</c>/<c>OCSPRef</c>/
    /// <c>CRLIdentifier</c>/<c>OCSPIdentifier</c>/<c>ResponderID</c> child out of its own type's fixed
    /// sequence order, or a name none of those content models declares at that position — including a
    /// <c>ResponderID</c> carrying both a <c>ByName</c> and a <c>ByKey</c> where the schema's <c>xsd:choice</c>
    /// permits exactly one.
    /// </summary>
    UnknownCoreElement,

    /// <summary>
    /// An element carries an un-prefixed attribute beyond the ones its content model declares — bridged from
    /// <see cref="XmlSignatureModelGrammar.TryValidateAttributeCount"/>, reused unchanged for XAdES elements.
    /// </summary>
    UnknownCoreAttribute,

    /// <summary>
    /// Element content typed <c>base64Binary</c> — <c>EncapsulatedPKIDataType</c>'s simple content (clause
    /// 5.1.3) or a <c>DigestAlgAndValueType</c>-shaped element's <c>ds:DigestValue</c> — does not match the
    /// <c>base64Binary</c> lexical space, bridged from <see cref="XmlBase64Content.TryDecode"/>.
    /// </summary>
    InvalidBase64Content,

    /// <summary>
    /// An element's actual content does not match its content model's shape: an element child, or a comment
    /// or processing instruction splitting simple content into more than one text node, or non-whitespace
    /// text between element children — bridged from <see cref="XmlSignatureModelGrammar"/>'s simple-content
    /// and element-child primitives, reused unchanged for XAdES elements.
    /// </summary>
    UnexpectedElementContent,

    /// <summary>
    /// <c>IdentifierType</c>'s <c>Qualifier</c> attribute (clause 5.1.2) is present with a value other than
    /// the two the schema's <c>QualifierType</c> enumeration declares, <c>OIDAsURI</c> and <c>OIDAsURN</c> —
    /// the schema's exact casing governs, not the prose's <c>"OIDASURN"</c> (clause 4.2's
    /// schema-precedence rule resolves the mismatch in the schema's favour).
    /// </summary>
    UnrecognizedObjectIdentifierQualifier,

    /// <summary>
    /// <c>EncapsulatedPKIDataType</c>'s <c>Encoding</c> attribute (clause 5.1.3) is present with a value
    /// other than the five URIs the clause enumerates (<c>DER</c>/<c>BER</c>/<c>CER</c>/<c>PER</c>/<c>XER</c>).
    /// Absence of the attribute is never this failure — clause 5.1.3 defaults absence to DER.
    /// </summary>
    UnrecognizedPkiDataEncoding,

    /// <summary>
    /// An <c>xsd:boolean</c>-typed attribute's value — <c>IncludeType</c>'s <c>referencedData</c> (clause
    /// 5.1.4.4.2.1) — is not one of the four literals
    /// <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#boolean">XML Schema Part 2:
    /// Datatypes</see> section 3.2.2 permits: <c>true</c>, <c>false</c>, <c>1</c> or <c>0</c>, exact-character.
    /// </summary>
    InvalidBooleanAttributeValue,

    /// <summary>
    /// One of the seven clause 4.3 qualifying-properties containers (<c>QualifyingProperties</c>,
    /// <c>SignedProperties</c>, <c>UnsignedProperties</c>, <c>SignedSignatureProperties</c>,
    /// <c>SignedDataObjectProperties</c>, <c>UnsignedSignatureProperties</c>,
    /// <c>UnsignedDataObjectProperties</c>) carries no children at all — every one of clauses 4.3.1–4.3.7's
    /// "A XAdES signature shall not incorporate empty X" rules, closed at read time.
    /// </summary>
    EmptyQualifyingPropertiesContainer,

    /// <summary>
    /// A child of <c>SignedSignatureProperties</c> (clause 4.3.4) or <c>UnsignedSignatureProperties</c>
    /// (clause 4.3.6) is one of the obsoleted V1 qualifying properties clause 4.3.4/4.3.6 and Annex D name —
    /// <c>SigningCertificate</c>, <c>SignatureProductionPlace</c>, <c>SignerRole</c>,
    /// <c>CompleteCertificateRefs</c>, <c>AttributeCertificateRefs</c>, <c>SigAndRefsTimeStamp</c>,
    /// <c>RefsOnlyTimeStamp</c>, or the <c>http://uri.etsi.org/01903/v1.3.2#</c>-namespace
    /// <c>ArchiveTimeStamp</c> — each "shall not be incorporated into the [XAdES] signature" per its own
    /// obsoletion rule. Also the <c>http://uri.etsi.org/01903/v1.4.1#</c>-namespace
    /// <c>RenewedDigests</c> (clause A.2.2, outside Annex D's own seven-item list) — "as defined in clause 5.5.3
    /// of ETSI EN 319 132-1 (V1.1.1)... shall not be added to any new XAdES signature," superseded by
    /// <c>RenewedDigestsV2</c> (clause 5.5.3 of the present document, same namespace, distinct local name).
    /// </summary>
    DeprecatedQualifyingProperty,

    /// <summary>
    /// A child of the closed-allowlist positions of <c>SignedSignatureProperties</c> (clause 4.3.4) or
    /// <c>SignedDataObjectProperties</c> (clause 4.3.5) — the two containers whose <c>xsd:any
    /// namespace="##other"</c> extension point clause 4.3.4/4.3.5 prose closes to "elements ... specified
    /// within any version of this multi-part deliverable" — is neither one of the schema's own named
    /// children in its correct sequence position nor a recognized obsoleted name: unrecognized foreign
    /// content, or a legitimate name repeated or out of its fixed sequence position. Unknown content signed
    /// by the XML signature changes what was signed, so it is refused rather than tolerated
    /// — contrast the analogous shape in <c>UnsignedSignatureProperties</c>
    /// (<see cref="XAdESUnsignedSignaturePropertyName.Unrecognized"/>), which is deliberately never refused,
    /// since that container's own <c>##other</c> content is unsigned and is tolerated as unmodeled entries
    /// instead.
    /// </summary>
    UnknownQualifyingProperty,

    /// <summary>
    /// A simple-content element typed <c>xsd:dateTime</c> — <c>SigningTime</c> (clause 5.2.1) — does not match
    /// the lexical grammar
    /// <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime">XML Schema Part 2:
    /// Datatypes</see> section 3.2.7.1 defines, bridged from <see cref="XAdESDateTime.TryParse"/>: a missing or
    /// malformed field, embedded whitespace, an out-of-range field, the disallowed year <c>0000</c>, an empty
    /// fractional-second run, or a timezone whose hour magnitude exceeds 14 or is 14 with a non-zero minute.
    /// </summary>
    InvalidDateTimeLexicalForm,

    /// <summary>
    /// A <c>CommitmentTypeIndication</c>'s <c>CommitmentTypeId</c> (clause 5.2.3) carries a <c>Qualifier</c>
    /// attribute on its <c>Identifier</c> child — clause 5.2.3's "its <c>Identifier</c> child shall not have a
    /// <c>Qualifier</c> attribute (i.e. the aforementioned URI shall not represent an OID value)," a
    /// restriction narrower than <c>ObjectIdentifierType</c>'s own general schema, which permits one.
    /// </summary>
    CommitmentTypeIdQualifierNotPermitted,

    /// <summary>
    /// A <c>DataObjectFormat</c> (clause 5.2.4) carries none of its three descriptive children —
    /// <c>Description</c>, <c>ObjectIdentifier</c>, <c>MimeType</c> — per clause 5.2.4's "this qualifying
    /// property shall contain at least one of the following elements: Description, ObjectIdentifier and
    /// MimeType," a cross-child floor the schema's individually-optional <c>minOccurs="0"</c> children cannot
    /// themselves express (<c>Encoding</c> is excluded from this floor).
    /// </summary>
    DataObjectFormatMissingDescriptiveChild,

    /// <summary>
    /// A <c>SignatureProductionPlaceV2</c> (clause 5.2.5) carries none of its five individually optional
    /// children — <c>City</c>, <c>StreetAddress</c>, <c>StateOrProvince</c>, <c>PostalCode</c>,
    /// <c>CountryName</c> — per clause 5.2.5's "Empty <c>SignatureProductionPlaceV2</c> qualifying properties
    /// shall not be generated," a floor the schema's individually-optional <c>minOccurs="0"</c> children
    /// cannot themselves express.
    /// </summary>
    EmptySignatureProductionPlaceV2,

    /// <summary>
    /// A <c>SignerRoleV2</c> (clause 5.2.6) carries none of its three individually optional children —
    /// <c>ClaimedRoles</c>, <c>CertifiedRolesV2</c>, <c>SignedAssertions</c> — per clause 5.2.6's "Empty
    /// <c>SignerRoleV2</c> qualifying properties shall not be generated," the same schema-permits/prose-
    /// forbids pattern as <see cref="EmptySignatureProductionPlaceV2"/>.
    /// </summary>
    EmptySignerRoleV2,

    /// <summary>
    /// The <c>ds:Signature</c> child of a <c>CounterSignature</c> qualifying property (clause 5.2.7.2) does
    /// not itself read as a well-formed <c>ds:Signature</c> element per XMLDSIG's own structural grammar,
    /// bridged from <see cref="XmlSignature.TryRead"/>'s own refusal (the byte offset carried here is the
    /// embedded read's own offset; the specific inner <see cref="XmlSignatureReadFailure"/> reason is not
    /// preserved, the same lossy-bridge posture <see cref="XAdESGrammar.FromGrammarFailure"/> already takes
    /// for the small set of grammar primitives it narrows).
    /// </summary>
    MalformedEmbeddedSignature,

    /// <summary>
    /// An <c>AllDataObjectsTimeStamp</c> (clause 5.2.8.1) carries at least one <c>Include</c> element. Clause
    /// 5.2.8.1 requires the Implicit mechanism ("The Implicit mechanism ... shall be used for generating this
    /// qualifying property"), and clause 5.1.4.4.1 defines <c>Include</c> as the Explicit mechanism's own
    /// exclusive marker ("Explicit. This mechanism shall use the <c>Include</c> element ...") — so any
    /// <c>Include</c> present here would mean the Explicit mechanism was actually used, contradicting the
    /// Implicit-mechanism requirement.
    /// </summary>
    AllDataObjectsTimeStampIncludeNotPermitted,

    /// <summary>
    /// An <c>IndividualDataObjectsTimeStamp</c> (clause 5.2.8.2) carries an <c>Include</c> element whose
    /// <c>referencedData</c> attribute is absent, or present with a value other than the literal <c>"true"</c>
    /// — clause 5.2.8.2's "The <c>referencedData</c> attribute shall be present in each and every <c>Include</c>
    /// element, and set to <c>"true"</c>," a constraint the shared <c>IncludeType</c> schema (clause
    /// 5.1.4.4.2.1) leaves optional and so cannot itself express.
    /// </summary>
    IndividualDataObjectsTimeStampIncludeReferencedDataNotTrue,

    /// <summary>
    /// A <c>SignatureTimeStamp</c> (clause 5.3) carries at least one <c>Include</c> element — the same
    /// Implicit-mechanism lock <see cref="AllDataObjectsTimeStampIncludeNotPermitted"/> enforces for clause
    /// 5.2.8.1, adjudicated identically here: clause 5.3's "The Implicit mechanism (see clause 5.1.4.4.1)
    /// shall be used for generating this qualifying property" and clause 5.1.4.4.1's own definition of
    /// <c>Include</c> as the Explicit mechanism's exclusive marker together mean any <c>Include</c> present
    /// contradicts the Implicit-mechanism requirement.
    /// </summary>
    SignatureTimeStampIncludeNotPermitted,

    /// <summary>
    /// An <c>SPDocSpecification</c> (clause 5.2.9.2, reused unchanged by clause 5.2.10) carries a
    /// <c>Qualifier</c> attribute value other than <c>OIDAsURN</c> — clause 5.2.9.2's narrower, directional
    /// pair: "If the technical specification is identified using an OID, then the <c>Identifier</c> child
    /// shall contain a URN encoding this OID ..., and its <c>QualifierType</c> attribute shall be present
    /// with its value set to <c>\"OIDAsURN\"</c>," and "If the technical specification is identified using a
    /// URI, then the <c>Identifier</c> child shall contain this URI and its <c>QualifierType</c> attribute
    /// shall not be present." <c>Qualifier="OIDAsURI"</c> — permitted by <c>ObjectIdentifierType</c>'s own
    /// general schema (clause 5.1.2) — satisfies neither branch here, so it refuses; a present <c>Qualifier</c>
    /// with any other value is already refused one layer down by
    /// <see cref="UnrecognizedObjectIdentifierQualifier"/>.
    /// </summary>
    SPDocSpecificationQualifierNotOIDAsURN,

    /// <summary>
    /// A <c>SignaturePolicyId</c> (clause 5.2.9.1) carries a <c>ds:Transforms</c> child whose chain includes
    /// the <c>SPDocDigestAsInSpecification</c> transform
    /// (<see cref="XAdESIdentifiers.SPDocDigestAsInSpecificationTransformUri"/>), but its
    /// <c>SigPolicyQualifiers</c> carries no <c>SPDocSpecification</c> qualifier — clause 5.2.9.1's "If this
    /// transform is used, then the <c>SignaturePolicyIdentifier</c> shall be qualified at least by the
    /// <c>SPDocSpecification</c> qualifier ..., which identifies the aforementioned technical specification."
    /// The rule is directional: an <c>SPDocSpecification</c> qualifier without the transform never triggers
    /// this refusal.
    /// </summary>
    SPDocDigestAsInSpecificationRequiresSPDocSpecification,

    /// <summary>
    /// An <c>EncapsulatedX509Certificate</c> child of a <c>CertificateValues</c>/<c>AttrAuthoritiesCertValues</c>
    /// qualifying property (clause 5.4.2/5.4.4), or an <c>EncapsulatedCRLValue</c>/<c>EncapsulatedOCSPValue</c>
    /// child of a <c>RevocationValues</c>/<c>AttributeRevocationValues</c> qualifying property's <c>CRLValues</c>/
    /// <c>OCSPValues</c> (clause 5.4.3/5.4.5), carries an <c>Encoding</c> attribute naming an encoding other than
    /// DER. Each of these four sites narrows the general <c>EncapsulatedPKIDataType</c> five-encoding
    /// enumeration (clause 5.1.3) down to DER specifically — "The <c>EncapsulatedX509Certificate</c> element
    /// shall contain the base-64 encoding of a DER-encoded X.509 certificate" (5.4.2), the parallel
    /// <c>EncapsulatedCRLValue</c>/<c>EncapsulatedOCSPValue</c> sentences of 5.4.3 — per clause 5.1.3 NOTE 2:
    /// "In some clauses of the present document, specific XAdES qualifying properties related to these data
    /// restrict the encoding options to only one certain type of the aforementioned PKI data." An absent
    /// <c>Encoding</c> attribute is never this failure — clause 5.1.3 already defaults absence to DER.
    /// </summary>
    EncapsulatedPkiDataNotDerEncoded,

    /// <summary>
    /// An <c>AnyValidationData</c> qualifying property (clause 5.4.6) carries a <c>URI</c> attribute — "The
    /// <c>AnyValidationData</c> qualifying property shall not have the <c>URI</c> attribute," a narrowing
    /// clause 5.4.6's own binding imposes on the schema's shared <c>ValidationDataType</c>, whose <c>URI</c>
    /// attribute is otherwise optional (and, per clause 5.5.1.2, conditionally meaningful for the sibling
    /// <c>TimeStampValidationData</c> property that reuses the same type).
    /// </summary>
    AnyValidationDataUriNotPermitted,

    /// <summary>
    /// An <c>AnyValidationData</c> qualifying property (clause 5.4.6) carries neither a <c>CertificateValues</c>
    /// nor a <c>RevocationValues</c> child — "The <c>AnyValidationData</c> qualifying property shall contain
    /// the certificates identified in 1), or the revocation data identified in 2), or both of them," an
    /// at-least-one-of-two floor the shared <c>ValidationDataType</c> schema's own individually-optional
    /// children cannot themselves express, the same schema-permits/prose-forbids pattern
    /// <see cref="DataObjectFormatMissingDescriptiveChild"/> and <see cref="EmptySignerRoleV2"/> both apply.
    /// This checks child-element PRESENCE only, not the deeper question of whether a present child's own
    /// optional lists carry any entries — a present-but-structurally-empty <c>CertificateValues</c>/
    /// <c>RevocationValues</c> child is never this failure (Annex A's own "with a non empty
    /// <c>CertificateValues</c> child element" phrasing, distinguishing that condition from a merely-present
    /// one, is this reader's textual grounds for not enforcing a deeper reading).
    /// </summary>
    EmptyAnyValidationData,

    /// <summary>
    /// A simple-content element typed <c>xsd:integer</c> — <c>CRLIdentifier</c>'s <c>Number</c> (Annex A.1.2/
    /// A.1.4) — does not match the lexical grammar
    /// <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#integer">XML Schema Part 2:
    /// Datatypes</see> section 3.3.13 defines, bridged from <see cref="XAdESGrammar.TryParseXsdInteger"/>: a
    /// missing or non-digit character, embedded whitespace, an empty digit run (including empty content), or
    /// a digit run exceeding the reader's own hardening bound.
    /// </summary>
    InvalidIntegerLexicalForm,

    /// <summary>
    /// A <c>CompleteRevocationRefs</c> qualifying property (Annex A.1.2 — NOT its sibling
    /// <c>AttributeRevocationRefs</c>, Annex A.1.4, which states no equivalent rule) carries none of its three
    /// individually optional children — <c>CRLRefs</c>, <c>OCSPRefs</c>, <c>OtherRefs</c> — per A.1.2's "Empty
    /// <c>CompleteRevocationRefs</c> qualifying properties shall not be incorporated," a floor the schema's
    /// individually-optional <c>minOccurs="0"</c> children cannot themselves express, the same
    /// schema-permits/prose-forbids pattern <see cref="EmptySignatureProductionPlaceV2"/> and
    /// <see cref="EmptySignerRoleV2"/> both apply. Raised only by
    /// <see cref="XAdESCompleteRevocationRefs.TryReadCompleteRevocationRefs"/>, never by
    /// <see cref="XAdESCompleteRevocationRefs.TryReadAttributeRevocationRefs"/>.
    /// </summary>
    EmptyCompleteRevocationRefs,

    /// <summary>
    /// A wire list whose schema content model is genuinely unbounded (<c>xsd:choice</c>/<c>xsd:sequence
    /// maxOccurs="unbounded"</c>) carried more entries than this reader's own documented hardening bound
    /// permits — a defense-in-depth cap the
    /// schema itself sets no numeric limit for, the same posture <see cref="XmlReferenceProcessing.MaximumTransformCount"/>
    /// already takes at the XMLDSIG-core layer. Shared by every site whose own bound constant names it:
    /// <see cref="XAdESUnsignedSignatureProperties.MaximumPropertyCount"/> (<c>UnsignedSignatureProperties</c>
    /// children, clause 4.3.6 — covers every named property AND every unmodeled <c>##other</c>/foreign entry
    /// alike, since both ride the same list); <see cref="XAdESSigningCertificateV2.MaximumCertIdListEntryCount"/>
    /// (<c>CertIDListV2Type</c>'s <c>Cert</c> entries — <c>SigningCertificateV2</c> clause 5.2.2 and
    /// <c>CompleteCertificateRefsV2</c>/<c>AttributeCertificateRefsV2</c> Annex A.1.1/A.1.3 alike, the one
    /// shared reader); <see cref="XAdESCompleteRevocationRefs.MaximumRevocationRefEntryCount"/>
    /// (<c>CRLRefs</c>/<c>OCSPRefs</c> entries, Annex A.1.2/A.1.4); <see cref="XAdESCertificateValues.MaximumEntryCount"/>
    /// (<c>CertificateValues</c>/<c>AttrAuthoritiesCertValues</c> entries, clause 5.4.2/5.4.4);
    /// <see cref="XAdESRevocationValues.MaximumEncapsulatedEntryCount"/> (<c>CRLValues</c>/<c>OCSPValues</c>
    /// entries, clause 5.4.3/5.4.5); <see cref="XAdESRevocationValues.MaximumUnmodeledEntryCount"/>
    /// (<c>OtherValues</c>/<c>OtherRefs</c> entries — the shared unmodeled-list core clause 5.4.3 and Annex
    /// A.1.2/A.1.4 both call); <see cref="XAdESTimeStamp.MaximumIncludeCount"/> (<c>Include</c> children of one
    /// time-stamp container, clause 5.1.4.4.2.1).
    /// </summary>
    EntryCountLimitExceeded
}
