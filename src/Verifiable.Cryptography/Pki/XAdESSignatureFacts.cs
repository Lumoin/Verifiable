using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Which <c>XAdESTimeStampType</c>-shaped qualifying property one <see cref="EmbeddedTimestamp"/>/
/// <see cref="XAdESTimestampContainerMetadata"/> pair describes — the classification
/// <see cref="XAdESSignatureFacts"/> derives from the property's own wire name, mirroring the class every
/// sibling binding (<see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// JAdES</see>'s <c>adoTst</c>/<c>sigTst</c>/<c>sigRTst</c>/<c>rfsTst</c>/<c>arcTst</c>) maps onto
/// <see cref="SignatureTimestampClass"/>.
/// </summary>
public enum XAdESTimestampContainerKind
{
    /// <summary>The binding could not classify the container. The value of an unset field, by design.</summary>
    Unknown = 0,

    /// <summary>The <c>AllDataObjectsTimeStamp</c> qualifying property (clause 5.2.8.1).</summary>
    AllDataObjectsTimeStamp = 1,

    /// <summary>The <c>IndividualDataObjectsTimeStamp</c> qualifying property (clause 5.2.8.2).</summary>
    IndividualDataObjectsTimeStamp = 2,

    /// <summary>The <c>SignatureTimeStamp</c> qualifying property (clause 5.3).</summary>
    SignatureTimeStamp = 3,

    /// <summary>The <c>SigAndRefsTimeStampV2</c> qualifying property (Annex A.1.5.1).</summary>
    SigAndRefsTimeStampV2 = 4,

    /// <summary>The <c>RefsOnlyTimeStampV2</c> qualifying property (Annex A.1.5.2).</summary>
    RefsOnlyTimeStampV2 = 5,

    /// <summary>The <c>ArchiveTimeStamp</c> qualifying property, v1.4.1 namespace (clause 5.5.2).</summary>
    ArchiveTimeStamp = 6
}


/// <summary>
/// The container-level facts of one <c>XAdESTimeStampType</c>-shaped qualifying property occurrence — the
/// <c>Include</c>/<c>ds:CanonicalizationMethod</c> members that steer message-imprint reconstruction (clause
/// 5.1.4.4.2), reported alongside (never instead of) the tokens themselves, which ride the format-neutral
/// <see cref="SignatureFacts.Timestamps"/>/<see cref="EmbeddedTimestamp"/> shape every sibling binding already
/// uses.
/// </summary>
/// <remarks>
/// One instance per qualifying-property OCCURRENCE (not per token): a signature carrying two
/// <c>AllDataObjectsTimeStamp</c> instances (Table 2's own "&#8805; 0" cardinality) reports two entries here,
/// each with its own <see cref="TokenCount"/>.
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "A canonicalization-algorithm identifier is compared as written, mirroring XmlSignatureWellKnown's own identical suppression for the same shape: System.Uri normalises case, escaping and default ports, which would make two identifiers that name different algorithms compare equal.")]
public sealed record XAdESTimestampContainerMetadata
{
    /// <summary>Gets which qualifying property this occurrence is.</summary>
    public required XAdESTimestampContainerKind Kind { get; init; }

    /// <summary>Gets how many <c>EncapsulatedTimeStamp</c>/<c>XMLTimeStamp</c> entries this occurrence carries (clause 5.1.4.4.1's one-or-more choice).</summary>
    public required int TokenCount { get; init; }

    /// <summary>Gets whether this occurrence carries at least one <c>Include</c> child — the explicit-selection form of clause 5.1.4.4.2.2, as opposed to the implicit mechanism (XA-5.1.4.4.1-4).</summary>
    public required bool HasInclude { get; init; }

    /// <summary>Gets how many <c>Include</c> children this occurrence carries.</summary>
    public required int IncludeCount { get; init; }

    /// <summary>Gets the <c>ds:CanonicalizationMethod Algorithm</c> URI this occurrence states, or <see langword="null"/> when the child is absent.</summary>
    public string? CanonicalizationUri { get; init; }

    /// <summary>
    /// Gets whether every <c>EncapsulatedTimeStamp</c>/<c>XMLTimeStamp</c> entry this occurrence carries is an
    /// <c>EncapsulatedTimeStamp</c> (an RFC 3161 token) — clause 6.3's XA-6.3-04: "the qualifying properties
    /// that act as electronic time-stamps containers shall encapsulate only IETF RFC 3161 ... electronic
    /// time-stamps." Populated by the delegate from the leaf's <c>XAdESBaselineIncorporationRequirements.ContainsOnlyRfc3161TimeStamps</c>;
    /// <see langword="false"/> when at least one entry is an <c>XMLTimeStamp</c>, including when
    /// <see cref="TokenCount"/> is zero because the sole entry is unmodeled content.
    /// </summary>
    public required bool CarriesOnlyRfc3161Tokens { get; init; }
}


/// <summary>
/// One <c>Cert</c> entry of a <c>SigningCertificateV2</c> qualifying property (clause 5.2.2) — the digest the
/// clause 5.2.3.4 identification building block matches a candidate certificate against, reusing the
/// format-neutral <see cref="SigningCertificateReference"/> shape every sibling binding populates
/// <see cref="SignatureFacts.SigningCertificateReferences"/> with, plus the ASN.1 <c>IssuerSerial</c> blob
/// clause 5.2.2's <c>IssuerSerialV2</c> carries opaque — a DER structure, not the plain issuer-name/serial-number
/// strings <see cref="SigningCertificateReference.IssuerName"/>/<see cref="SigningCertificateReference.SerialNumber"/>
/// exist for (those two stay <see langword="null"/> here; a caller that needs the parsed <c>GeneralNames</c>/
/// <c>CertificateSerialNumber</c> pair decodes <see cref="IssuerSerialV2"/> itself).
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> This instance owns <see cref="Reference"/>'s
/// <see cref="SigningCertificateReference.CertificateDigest"/> and <see cref="IssuerSerialV2"/>; disposing this
/// instance disposes both.
/// </remarks>
[DebuggerDisplay("XAdESSigningCertificateDigestFact: {Reference.DigestAlgorithm.Oid}, signer reference {Reference.IsSignerReference}")]
public sealed class XAdESSigningCertificateDigestFact: IDisposable
{
    /// <summary>Gets the format-neutral reference — algorithm, digest, and whether this is <c>Cert[0]</c>, the signer's own reference (clause 5.2.2 NOTE 7).</summary>
    public required SigningCertificateReference Reference { get; init; }

    /// <summary>Gets the opaque <c>IssuerSerialV2</c> ASN.1 <c>IssuerSerial</c> blob, tagged <see cref="PkiCertificateTags.IssuerSerial"/>, or <see langword="null"/> when the <c>Cert</c> entry carries none.</summary>
    public PkiCertificateMemory? IssuerSerialV2 { get; init; }


    /// <summary>Disposes <see cref="SigningCertificateReference.CertificateDigest"/> and <see cref="IssuerSerialV2"/>.</summary>
    public void Dispose()
    {
        Reference.CertificateDigest?.Dispose();
        IssuerSerialV2?.Dispose();
    }
}


/// <summary>
/// One <c>Cert</c> entry of a <c>CompleteCertificateRefsV2</c>/<c>AttributeCertificateRefsV2</c> qualifying
/// property (Annex A.1.1/A.1.3) — the <c>CertIDListV2Type</c> shape shared with <c>SigningCertificateV2</c>
/// (clause 5.2.2), mirroring <see cref="XAdESSigningCertificateDigestFact"/>'s own
/// digest/<c>IssuerSerialV2</c> shape one clause over, minus the <c>Cert[0]</c> signer-reference notion clause
/// 5.2.2 NOTE 7 defines: a refs-family entry names a certificate elsewhere in the signature, never "the signer's
/// own reference".
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> This instance owns <see cref="Digest"/> and <see cref="IssuerSerialV2"/>;
/// disposing this instance disposes both.
/// </remarks>
[DebuggerDisplay("XAdESCertificateReferenceDigestFact: {DigestAlgorithm.Oid}")]
public sealed class XAdESCertificateReferenceDigestFact: IDisposable
{
    /// <summary>Gets the digest algorithm the reference declares its certificate hash was taken under.</summary>
    public required AlgorithmIdentifier DigestAlgorithm { get; init; }

    /// <summary>Gets the certificate hash the reference carries.</summary>
    public required DigestValue Digest { get; init; }

    /// <summary>Gets the opaque <c>IssuerSerialV2</c> ASN.1 <c>IssuerSerial</c> blob, tagged <see cref="PkiCertificateTags.IssuerSerial"/>, or <see langword="null"/> when the <c>Cert</c> entry carries none.</summary>
    public PkiCertificateMemory? IssuerSerialV2 { get; init; }


    /// <summary>Disposes <see cref="Digest"/> and <see cref="IssuerSerialV2"/>.</summary>
    public void Dispose()
    {
        Digest.Dispose();
        IssuerSerialV2?.Dispose();
    }
}


/// <summary>
/// One <c>CRLRef</c> entry of a <c>CompleteRevocationRefs</c>/<c>AttributeRevocationRefs</c> qualifying property
/// (Annex A.1.2/A.1.4): the mandatory <c>DigestAlgAndValue</c> digest plus the optional <c>CRLIdentifier</c>'s
/// own fields, carried opaque exactly as the leaf reads them (an XMLDSIG clause 4.5.4.1 Distinguished Name
/// string for <see cref="Issuer"/>, never parsed).
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> This instance owns <see cref="Digest"/>; disposing this instance disposes it.
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "CRLIdentifier/@URI is a retrieval hint only, never authoritative and never dereferenced here (no-HTTP-in-library house rule) — carried opaquely exactly as the leaf reads it, mirroring the leaf's own XAdESCrlIdentifier.Uri, which is untyped for the identical reason.")]
[DebuggerDisplay("XAdESCrlReferenceFact: {DigestAlgorithm.Oid}, HasCrlIdentifier={HasCrlIdentifier}")]
public sealed class XAdESCrlReferenceFact: IDisposable
{
    /// <summary>Gets the digest algorithm the reference declares its CRL hash was taken under.</summary>
    public required AlgorithmIdentifier DigestAlgorithm { get; init; }

    /// <summary>Gets the CRL hash the reference carries.</summary>
    public required DigestValue Digest { get; init; }

    /// <summary>Gets whether the optional <c>CRLIdentifier</c> child is present.</summary>
    public bool HasCrlIdentifier { get; init; }

    /// <summary>Gets the <c>CRLIdentifier/Issuer</c> Distinguished Name string, opaque, or <see langword="null"/> when <see cref="HasCrlIdentifier"/> is <see langword="false"/>.</summary>
    public string? Issuer { get; init; }

    /// <summary>Gets the <c>CRLIdentifier/IssueTime</c>'s lexical <c>xsd:dateTime</c> text, or <see langword="null"/> when <see cref="HasCrlIdentifier"/> is <see langword="false"/>.</summary>
    public string? IssueTimeLexical { get; init; }

    /// <summary>Gets the <c>CRLIdentifier/IssueTime</c>'s parsed value, or <see langword="null"/> when absent or lexically unrepresentable (see <see cref="XAdESQualifyingPropertiesFacts.SigningTime"/>'s own remarks for the same best-effort posture).</summary>
    public DateTimeOffset? IssueTime { get; init; }

    /// <summary>Gets whether the optional <c>CRLIdentifier/Number</c> child is present.</summary>
    public bool HasNumber { get; init; }

    /// <summary>Gets whether <see cref="Number"/> carried a leading <c>'-'</c>; meaningful only when <see cref="HasNumber"/> is <see langword="true"/>.</summary>
    public bool IsNumberNegative { get; init; }

    /// <summary>Gets the <c>CRLIdentifier/Number</c> child's parsed magnitude; meaningful only when <see cref="HasNumber"/> is <see langword="true"/>.</summary>
    public long Number { get; init; }

    /// <summary>Gets whether the optional <c>CRLIdentifier/@URI</c> attribute is present.</summary>
    public bool HasUri { get; init; }

    /// <summary>Gets the <c>CRLIdentifier/@URI</c> attribute value — a retrieval hint only, never authoritative.</summary>
    public string? Uri { get; init; }


    /// <summary>Disposes <see cref="Digest"/>.</summary>
    public void Dispose() => Digest.Dispose();
}


/// <summary>
/// Which arm of <c>ResponderIDType</c>'s <c>ByName</c>/<c>ByKey</c> choice a <see cref="XAdESOcspReferenceFact"/>
/// holds — the Pki-side mirror of the leaf's own <c>XAdESResponderIdKind</c> (Pki never
/// references <c>Verifiable.Xml</c>, so the facts shape carries its own copy of the two-member vocabulary,
/// bijection-pinned by test against the leaf's enum).
/// </summary>
public enum XAdESOcspResponderIdKind
{
    /// <summary>The responder is identified by name — an XMLDSIG clause 4.5.4.1 Distinguished Name string, carried opaquely.</summary>
    ByName,

    /// <summary>The responder is identified by the digest of its public key — the base-64 DER encoding of RFC 6960's <c>byKey</c> field.</summary>
    ByKey
}


/// <summary>
/// One <c>OCSPRef</c> entry of a <c>CompleteRevocationRefs</c>/<c>AttributeRevocationRefs</c> qualifying property
/// (Annex A.1.2/A.1.4): the optional <c>DigestAlgAndValue</c> digest (A.1.2's own "should be included" — this
/// fact carries presence, never enforces it) plus the mandatory <c>OCSPIdentifier</c>'s own fields.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> This instance owns <see cref="Digest"/> and <see cref="ResponderByKeyOctets"/>;
/// disposing this instance disposes both.
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "OCSPIdentifier/@URI is a retrieval hint only, never authoritative and never dereferenced here (no-HTTP-in-library house rule) — carried opaquely exactly as the leaf reads it, mirroring the leaf's own XAdESOcspIdentifier.Uri, which is untyped for the identical reason.")]
[DebuggerDisplay("XAdESOcspReferenceFact: HasDigestAlgAndValue={HasDigestAlgAndValue}, ResponderKind={ResponderKind}")]
public sealed class XAdESOcspReferenceFact: IDisposable
{
    /// <summary>Gets whether the optional <c>DigestAlgAndValue</c> child is present.</summary>
    public required bool HasDigestAlgAndValue { get; init; }

    /// <summary>Gets the digest algorithm the reference declares its OCSP-response hash was taken under, or <see langword="null"/> when <see cref="HasDigestAlgAndValue"/> is <see langword="false"/>.</summary>
    public AlgorithmIdentifier? DigestAlgorithm { get; init; }

    /// <summary>Gets the OCSP-response hash the reference carries, or <see langword="null"/> when <see cref="HasDigestAlgAndValue"/> is <see langword="false"/>.</summary>
    public DigestValue? Digest { get; init; }

    /// <summary>Gets which arm of <c>ResponderIDType</c>'s choice this instance holds.</summary>
    public required XAdESOcspResponderIdKind ResponderKind { get; init; }

    /// <summary>Gets the <c>ByName</c> Distinguished Name string, opaque, or <see langword="null"/> when <see cref="ResponderKind"/> is <see cref="XAdESOcspResponderIdKind.ByKey"/>.</summary>
    public string? ResponderByName { get; init; }

    /// <summary>Gets the decoded <c>ByKey</c> octets, tagged <see cref="PkiCertificateTags.OcspResponderKeyHash"/>, or <see langword="null"/> when <see cref="ResponderKind"/> is <see cref="XAdESOcspResponderIdKind.ByName"/>.</summary>
    public PkiCertificateMemory? ResponderByKeyOctets { get; init; }

    /// <summary>Gets the <c>ProducedAt</c>'s lexical <c>xsd:dateTime</c> text.</summary>
    public required string ProducedAtLexical { get; init; }

    /// <summary>Gets the <c>ProducedAt</c>'s parsed value, or <see langword="null"/> when lexically unrepresentable — "shall indicate the same time as the referenced OCSP response's own <c>ProducedAt</c> field" (A.1.2), the antecedent <see cref="XAdESLevelRules.CheckOcspProducedAtConsistencyAsync"/> checks against the actual referenced response.</summary>
    public DateTimeOffset? ProducedAt { get; init; }

    /// <summary>Gets whether the optional <c>OCSPIdentifier/@URI</c> attribute is present.</summary>
    public bool HasUri { get; init; }

    /// <summary>Gets the <c>OCSPIdentifier/@URI</c> attribute value — a retrieval hint only, never authoritative.</summary>
    public string? Uri { get; init; }


    /// <summary>Disposes <see cref="Digest"/> and <see cref="ResponderByKeyOctets"/>.</summary>
    public void Dispose()
    {
        Digest?.Dispose();
        ResponderByKeyOctets?.Dispose();
    }
}


/// <summary>
/// The facts of one <c>SignaturePolicyIdentifier</c> qualifying property (clause 5.2.9): either an explicit
/// policy, identified by <see cref="Id"/> and (mandatorily, unlike CB-AdES/JAdES's own optional digest)
/// <see cref="Hash"/>, or the <c>SignaturePolicyImplied</c> choice arm (<see cref="IsImplied"/>).
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> This instance owns <see cref="Hash"/>; disposing this instance disposes it.
/// </remarks>
[DebuggerDisplay("XAdESSignaturePolicyFact: implied={IsImplied}, {Id}")]
public sealed class XAdESSignaturePolicyFact: IDisposable
{
    /// <summary>Gets whether the signature declares the <c>SignaturePolicyImplied</c> choice arm — an out-of-band, agreed policy the wire states no identifier for. <see cref="Id"/>/<see cref="HashAlgorithm"/>/<see cref="Hash"/> are <see langword="null"/> when this is <see langword="true"/>.</summary>
    public required bool IsImplied { get; init; }

    /// <summary>Gets the policy's permanent identifier (<c>SigPolicyId/Identifier</c>), or <see langword="null"/> when <see cref="IsImplied"/> is <see langword="true"/>.</summary>
    public AdESObjectIdentifier? Id { get; init; }

    /// <summary>Gets the <c>SigPolicyHash</c>'s digest-algorithm identifier, or <see langword="null"/> when <see cref="IsImplied"/> is <see langword="true"/>.</summary>
    public AlgorithmIdentifier? HashAlgorithm { get; init; }

    /// <summary>Gets the <c>SigPolicyHash</c>'s digest value, or <see langword="null"/> when <see cref="IsImplied"/> is <see langword="true"/>.</summary>
    public DigestValue? Hash { get; init; }

    /// <summary>Gets whether the policy carries a non-empty <c>SigPolicyQualifiers</c> — content this type counts, not decodes.</summary>
    public bool HasQualifiers { get; init; }

    /// <summary>Gets how many <c>SigPolicyQualifier</c> entries <c>SigPolicyQualifiers</c> carries.</summary>
    public int QualifierCount { get; init; }


    /// <summary>Disposes <see cref="Hash"/>, when present.</summary>
    public void Dispose() => Hash?.Dispose();
}


/// <summary>
/// The presence/cardinality facts of the §5.4/Annex A validation-data-shaped qualifying properties — every
/// count is the number of wire occurrences of that property (never the number of certificates/CRLs/OCSP
/// responses inside one occurrence; those flow into <see cref="XAdESQualifyingPropertiesFacts.EmbeddedCertificates"/>/
/// <see cref="XAdESQualifyingPropertiesFacts.EmbeddedCertificateRevocationLists"/>/
/// <see cref="XAdESQualifyingPropertiesFacts.EmbeddedOcspResponses"/>), zero meaning absent — the shape Table 2's
/// own presence/cardinality columns (t25/t26/t27/t29/t30/t32/t33/t34/t35/t41/t46) turn on.
/// </summary>
public sealed record XAdESValidationDataCounts
{
    /// <summary>Gets the <c>CertificateValues</c> occurrence count (clause 5.4.2, Table 2 row t25).</summary>
    public int CertificateValuesCount { get; init; }

    /// <summary>Gets the <c>AttrAuthoritiesCertValues</c> occurrence count (clause 5.4.4, Table 2 row t29).</summary>
    public int AttrAuthoritiesCertValuesCount { get; init; }

    /// <summary>Gets the <c>RevocationValues</c> occurrence count (clause 5.4.3, Table 2 row t32).</summary>
    public int RevocationValuesCount { get; init; }

    /// <summary>Gets the <c>AttributeRevocationValues</c> occurrence count (clause 5.4.5, Table 2 row t34).</summary>
    public int AttributeRevocationValuesCount { get; init; }

    /// <summary>Gets the <c>AnyValidationData</c> occurrence count (clause 5.4.6, Table 2 rows t26/t43).</summary>
    public int AnyValidationDataCount { get; init; }

    /// <summary>Gets the <c>TimeStampValidationData</c> occurrence count (clause 5.5.1, Table 2 row t41).</summary>
    public int TimeStampValidationDataCount { get; init; }

    /// <summary>Gets the <c>CompleteCertificateRefsV2</c> occurrence count (Annex A.1.1, Table 2 row t27).</summary>
    public int CompleteCertificateRefsV2Count { get; init; }

    /// <summary>Gets the <c>AttributeCertificateRefsV2</c> occurrence count (Annex A.1.3, Table 2 row t30).</summary>
    public int AttributeCertificateRefsV2Count { get; init; }

    /// <summary>Gets the <c>CompleteRevocationRefs</c> occurrence count (Annex A.1.2, Table 2 row t33).</summary>
    public int CompleteRevocationRefsCount { get; init; }

    /// <summary>Gets the <c>AttributeRevocationRefs</c> occurrence count (Annex A.1.4, Table 2 row t35).</summary>
    public int AttributeRevocationRefsCount { get; init; }

    /// <summary>Gets the <c>SignaturePolicyStore</c> occurrence count (clause 5.2.10, Table 2 row t23).</summary>
    public int SignaturePolicyStoreCount { get; init; }

    /// <summary>Gets the <c>RenewedDigestsV2</c> occurrence count (clause 5.5.3, Table 2 row t46).</summary>
    public int RenewedDigestsV2Count { get; init; }
}


/// <summary>
/// The clause 4.4 discovery/binding outcome for one <c>ds:Signature</c>: whether a directly-incorporated
/// <c>QualifyingProperties</c> was found and bound to it (clause 4.3.1's <c>Target</c>), and whether the
/// <c>SignedProperties</c> it carries is the one a <c>ds:Reference</c> of the enclosing <c>ds:SignedInfo</c>
/// actually signs (clause 4.4.2) — the table-identity pin this library requires.
/// </summary>
public sealed record XAdESDiscoveryFact
{
    /// <summary>Gets whether a directly-incorporated <c>QualifyingProperties</c> element was found (clause 4.4.1).</summary>
    public required bool HasQualifyingProperties { get; init; }

    /// <summary>Gets whether the discovered <c>QualifyingProperties</c>'s <c>Target</c> resolves to the exact <c>ds:Signature</c> it was discovered within (clause 4.3.1).</summary>
    public required bool TargetResolvedToSignature { get; init; }

    /// <summary>Gets whether a <c>ds:Reference</c> whose <c>Type</c> matches the SignedProperties Type-URI was located in <c>ds:SignedInfo</c>.</summary>
    public required bool SignedPropertiesReferencePresent { get; init; }

    /// <summary>Gets whether the located reference dereferences to the EXACT <c>SignedProperties</c> node of the discovered container (clause 4.4.2, the anti-wrapping table-identity pin).</summary>
    public required bool SignedPropertiesReferenceResolvedToDiscoveredNode { get; init; }

    /// <summary>
    /// Gets how many indirectly-incorporated <c>QualifyingPropertiesReference</c> instances the signature
    /// carries (clause 4.4.1) — clause 6.3's XA-6.3-02 forbids indirect incorporation in every baseline level;
    /// <see cref="XAdESLevelRules.Check"/> reports a nonzero count as a <see cref="XAdESIndirectIncorporationViolation"/>.
    /// </summary>
    public int QualifyingPropertiesReferenceCount { get; init; }
}


/// <summary>
/// Everything one XAdES signature's qualifying properties state, in a shape carrying no <c>Verifiable.Xml</c>
/// type anywhere — the format-neutral wire-facts shape <see cref="ParseXAdESQualifyingPropertiesDelegate"/>
/// returns, which <see cref="XAdESSignatureFacts.BuildFacts"/> maps onto the
/// shared, cross-format <see cref="SignatureFacts"/> the format-neutral validation-algorithm building blocks
/// consume.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why a second shape beside <see cref="SignatureFacts"/>.</strong> <see cref="SignatureFacts"/> is
/// deliberately thin (one <see cref="SignatureFacts.SignaturePolicyIdentifier"/> string, one flat
/// <see cref="SignatureFacts.Attributes"/> presence list) because it is shared, unchanged, across five base
/// formats. XAdES's own clause 5 vocabulary is richer than that shape can carry — a signing-certificate digest's
/// own <c>IssuerSerialV2</c> blob, a policy's own hash-algorithm identifier, per-timestamp <c>Include</c>
/// cardinality, the per-property-kind validation-data breakdown — so this type carries the richer shape
/// <see cref="XAdESSignatureFacts.CreateSeam"/>'s own injected parse delegate populates, and
/// <see cref="XAdESSignatureFacts.BuildFacts"/> folds a format-neutral PROJECTION of it into the
/// <see cref="SignatureFacts"/> the engine actually runs against — never the reverse; nothing here is
/// reconstructed FROM a <see cref="SignatureFacts"/>.
/// </para>
/// <para>
/// <strong>The presence/cardinality inventory.</strong> <see cref="SignedPropertyOccurrenceCounts"/>/
/// <see cref="UnsignedPropertyOccurrenceCounts"/> count, per qualifying-property KIND, how many wire occurrences
/// the signature carries, keyed by the EXACT <see cref="AdESTableRow.Name"/> string
/// <see cref="XAdESBaselineLevelTable"/>'s own rows use — the presence/cardinality inventory
/// <see cref="XAdESLevelRules"/> (the XAdES analogue of <c>JAdESLevelRules</c>/<c>CBAdESLevelRules</c>)
/// consumes against <see cref="XAdESBaselineLevelTable.Rows"/> with no XML type anywhere in this reach.
/// Deliberately scoped to the 42 qualifying-
/// property/service/SPO rows: the four <c>ds:</c>-native rows (<c>ds:KeyInfo/X509Data</c>,
/// <c>ds:SignedInfo/ds:CanonicalizationMethod</c>, <c>ds:Reference</c>, <c>ds:Reference/ds:Transforms</c>) are
/// XMLDSIG-core facts a consumer reads off the signature's own <c>ds:SignedInfo</c>/<c>ds:KeyInfo</c> — not
/// qualifying-property content this shape's own parse seam decodes — a disclosed, documented boundary rather
/// than a silently-narrowed one.
/// </para>
/// <para>
/// <strong>Deprecated content never reaches a successful parse.</strong> Every V1 property name and
/// the v1.3.2-namespace <c>ArchiveTimeStamp</c> is a READ-TIME refusal at the container reader
/// (<c>XAdESReadFailure.DeprecatedQualifyingProperty</c>): a document carrying one never produces a
/// <see cref="XAdESQualifyingPropertiesParseResult.Parsed"/> outcome at all, so
/// <see cref="DeprecatedPropertyObservations"/> is always empty on a successfully-extracted instance — kept for
/// symmetry with <see cref="UnknownPropertyObservations"/> (which IS reachable: clause 4.3.6's own
/// <c>UnsignedSignatureProperties</c> tolerates unknown <c>##other</c> content) and so a future
/// extension that downgrades rather than refuses the deprecated case needs no shape change to populate it.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns every carrier reachable through
/// <see cref="SigningCertificateDigests"/>, <see cref="SignaturePolicy"/>, <see cref="Timestamps"/>,
/// <see cref="EmbeddedCertificates"/>, <see cref="EmbeddedCertificateRevocationLists"/> and
/// <see cref="EmbeddedOcspResponses"/>; <see cref="Dispose"/> releases them all. Once
/// <see cref="XAdESSignatureFacts.BuildFacts"/> has folded this instance into a <see cref="SignatureFacts"/>,
/// ownership of every carrier it took has TRANSFERRED — the caller that received the <see cref="SignatureFacts"/>
/// disposes them through it, and this instance's own <see cref="Dispose"/> must not run a second time over the
/// same carriers (<see cref="XAdESSignatureFacts.ExtractAsync"/> never calls it on that path).
/// </para>
/// </remarks>
[DebuggerDisplay("XAdESQualifyingPropertiesFacts: {SigningCertificateDigests.Count} cert digests, {Timestamps.Count} timestamps")]
public sealed class XAdESQualifyingPropertiesFacts: IDisposable
{
    /// <summary>Gets the clause 4.4 discovery/binding outcome.</summary>
    public required XAdESDiscoveryFact Discovery { get; init; }

    /// <summary>Gets the <c>SigningTime</c> qualifying property's lexical <c>xsd:dateTime</c> text, or <see langword="null"/> when absent.</summary>
    public string? SigningTimeLexical { get; init; }

    /// <summary>Gets the <c>SigningTime</c> qualifying property's parsed value, or <see langword="null"/> when absent or lexically invalid.</summary>
    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>Gets every <c>Cert</c> entry of the <c>SigningCertificateV2</c> qualifying property, in wire order (<c>[0]</c> is the signer's own reference, clause 5.2.2 NOTE 7); empty when the property is absent.</summary>
    public IReadOnlyList<XAdESSigningCertificateDigestFact> SigningCertificateDigests { get; init; } = [];

    /// <summary>Gets the <c>SignaturePolicyIdentifier</c> qualifying property's facts, or <see langword="null"/> when absent.</summary>
    public XAdESSignaturePolicyFact? SignaturePolicy { get; init; }

    /// <summary>Gets every <c>CommitmentTypeIndication</c>'s own <c>ObjectIdentifier</c>, in wire order; empty when absent.</summary>
    public IReadOnlyList<AdESObjectIdentifier> CommitmentTypeIdentifiers { get; init; } = [];

    /// <summary>
    /// Gets the <c>SignerRoleV2</c> qualifying property's claimed/certified/signed-assertion CARDINALITY, on the
    /// shared <see cref="AdESSignerAttributes"/> hook, or <see langword="null"/> when absent.
    /// Every element is a content-empty placeholder: this type counts occurrences only —
    /// <c>ClaimedRole</c>/<c>CertifiedRoleV2</c>/<c>SignedAssertion</c> CONTENT decode is a disclosed, out-of-
    /// scope residue (mirroring how <see cref="AdESSignerAttributes.SignedAssertions"/>/<see cref="AdESSignerAttributes.Claimed"/>
    /// already document "a caller down-casts each element to the concrete type the format it is holding actually
    /// produces" — XAdES's own concrete type is deliberately empty).
    /// </summary>
    public AdESSignerAttributes? SignerRole { get; init; }

    /// <summary>Gets whether the <c>SignatureProductionPlaceV2</c> qualifying property is present.</summary>
    public bool HasSignatureProductionPlace { get; init; }

    /// <summary>Gets how many <c>DataObjectFormat</c> occurrences the signature carries.</summary>
    public int DataObjectFormatCount { get; init; }

    /// <summary>
    /// Gets whether clause 6.3 letter k)'s <c>DataObjectFormat</c> coverage bijection holds: one
    /// <c>DataObjectFormat</c> per signed data object except <c>SignedProperties</c> (and, when countersigning,
    /// the countersigned-signature reference), no more, no fewer, none targeting an excluded reference —
    /// computed by the delegate via the leaf's <c>XAdESDataObjectFormatCoverage.TryVerify</c>, since the
    /// bijection needs the decoded <c>ds:SignedInfo</c>/<c>DataObjectFormat</c> structure this crypto-free shape
    /// does not itself carry. <see langword="true"/> when the signature carries zero <c>DataObjectFormat</c>
    /// occurrences and zero data objects requiring one.
    /// </summary>
    public required bool IsDataObjectFormatCoverageSatisfied { get; init; }

    /// <summary>Gets how many <c>CounterSignature</c> occurrences the signature carries.</summary>
    public int CounterSignatureCount { get; init; }

    /// <summary>
    /// Gets every embedded time-stamp TOKEN, classified onto the shared, cross-format
    /// <see cref="SignatureTimestampClass"/> vocabulary — the same list <see cref="XAdESSignatureFacts.BuildFacts"/>
    /// copies straight into <see cref="SignatureFacts.Timestamps"/>.
    /// </summary>
    public IReadOnlyList<EmbeddedTimestamp> Timestamps { get; init; } = [];

    /// <summary>Gets the container-level facts (<c>Include</c>/<c>ds:CanonicalizationMethod</c>) of every timestamp-shaped qualifying property occurrence, in wire order — one entry per occurrence, not per token (see <see cref="XAdESTimestampContainerMetadata"/>'s own remarks).</summary>
    public IReadOnlyList<XAdESTimestampContainerMetadata> TimestampContainers { get; init; } = [];

    /// <summary>Gets the presence/cardinality facts of the validation-data-shaped qualifying properties.</summary>
    public required XAdESValidationDataCounts ValidationData { get; init; }

    /// <summary>
    /// Gets whether at least one <c>TimeStampValidationData</c> or <c>AnyValidationData</c> occurrence carries
    /// at least one certificate/CRL/OCSP-response child — clause 6.3 letter x)'s own "the validation data for
    /// electronic time-stamps shall be present WITHIN" requirement, measured on CONTENT rather than mere
    /// container presence: an empty <c>&lt;TimeStampValidationData/&gt;</c> does not satisfy it. Only
    /// <c>CertificateValues</c>/<c>RevocationValues</c>/<c>AttrAuthoritiesCertValues</c>/<c>AttributeRevocationValues</c>
    /// content is excluded from this signal even though it flows into the same <see cref="EmbeddedCertificates"/>/
    /// <see cref="EmbeddedCertificateRevocationLists"/>/<see cref="EmbeddedOcspResponses"/> lists — those describe
    /// the SIGNER's own material, not the time-stamps'.
    /// </summary>
    public required bool ValidationDataForTimestampsHasContent { get; init; }

    /// <summary>Gets every certificate the signature's <c>CertificateValues</c>/<c>AttrAuthoritiesCertValues</c>/<c>AnyValidationData</c>/<c>TimeStampValidationData</c> occurrences carry, tagged <see cref="PkiCertificateTags.X509Certificate"/>.</summary>
    public IReadOnlyList<PkiCertificateMemory> EmbeddedCertificates { get; init; } = [];

    /// <summary>Gets every CRL the signature's <c>RevocationValues</c>/<c>AttributeRevocationValues</c>/<c>AnyValidationData</c>/<c>TimeStampValidationData</c> occurrences carry, tagged <see cref="PkiCertificateTags.X509Crl"/>.</summary>
    public IReadOnlyList<PkiCertificateMemory> EmbeddedCertificateRevocationLists { get; init; } = [];

    /// <summary>Gets every OCSP response the signature's <c>RevocationValues</c>/<c>AttributeRevocationValues</c>/<c>AnyValidationData</c>/<c>TimeStampValidationData</c> occurrences carry, tagged <see cref="PkiCertificateTags.OcspResponse"/>.</summary>
    public IReadOnlyList<PkiCertificateMemory> EmbeddedOcspResponses { get; init; } = [];

    /// <summary>Gets every <c>Cert</c> entry of every <c>CompleteCertificateRefsV2</c> occurrence (Annex A.1.1), in wire order; empty when absent.</summary>
    public IReadOnlyList<XAdESCertificateReferenceDigestFact> CompleteCertificateRefs { get; init; } = [];

    /// <summary>Gets every <c>Cert</c> entry of every <c>AttributeCertificateRefsV2</c> occurrence (Annex A.1.3), in wire order; empty when absent.</summary>
    public IReadOnlyList<XAdESCertificateReferenceDigestFact> AttributeCertificateRefs { get; init; } = [];

    /// <summary>Gets every <c>CRLRef</c> entry of every <c>CompleteRevocationRefs</c> occurrence (Annex A.1.2), in wire order; empty when absent.</summary>
    public IReadOnlyList<XAdESCrlReferenceFact> CompleteRevocationCrlRefs { get; init; } = [];

    /// <summary>Gets every <c>OCSPRef</c> entry of every <c>CompleteRevocationRefs</c> occurrence (Annex A.1.2), in wire order; empty when absent.</summary>
    public IReadOnlyList<XAdESOcspReferenceFact> CompleteRevocationOcspRefs { get; init; } = [];

    /// <summary>Gets every <c>CRLRef</c> entry of every <c>AttributeRevocationRefs</c> occurrence (Annex A.1.4), in wire order; empty when absent.</summary>
    public IReadOnlyList<XAdESCrlReferenceFact> AttributeRevocationCrlRefs { get; init; } = [];

    /// <summary>Gets every <c>OCSPRef</c> entry of every <c>AttributeRevocationRefs</c> occurrence (Annex A.1.4), in wire order; empty when absent.</summary>
    public IReadOnlyList<XAdESOcspReferenceFact> AttributeRevocationOcspRefs { get; init; } = [];

    /// <summary>
    /// Gets the structural antecedent of Annex A.1.1/A.1.3's own closing conditional-<c>shall</c> paragraph — "if
    /// at least one of <c>CertificateValues</c>, <c>AttrAuthoritiesCertValues</c>, <c>AnyValidationData</c> with a
    /// non-empty <c>CertificateValues</c> child, or [a v1.4.1] <c>ArchiveTimeStamp</c> is incorporated ..." —
    /// computed by the leaf's <c>XAdESValidationDataTrigger.TryDetermine</c> (the certificate-family arm) at the
    /// composition root, since it needs the decoded <c>UnsignedSignatureProperties</c> container this crypto-free
    /// shape does not itself carry. The
    /// consequent — every <see cref="CompleteCertificateRefs"/>/<see cref="AttributeCertificateRefs"/> digest
    /// resolving to a candidate in <see cref="EmbeddedCertificates"/> — is
    /// <see cref="XAdESLevelRules.CheckReferencesResolveToValidationDataAsync"/>'s own concern.
    /// </summary>
    public bool CertificateValidationDataTriggered { get; init; }

    /// <summary>
    /// Gets the structural antecedent of Annex A.1.2/A.1.4's own closing conditional-<c>shall</c> paragraph — the
    /// same shape as <see cref="CertificateValidationDataTriggered"/>, for <c>RevocationValues</c>/
    /// <c>AttributeRevocationValues</c>/<c>AnyValidationData</c>'s <c>RevocationValues</c> child instead.
    /// </summary>
    public bool RevocationValidationDataTriggered { get; init; }

    /// <summary>
    /// Gets the presence/cardinality inventory of every SIGNED qualifying-property kind this parse found, keyed
    /// by the exact <see cref="AdESTableRow.Name"/> string <see cref="XAdESBaselineLevelTable"/>'s own rows use
    /// — see the type remarks.
    /// </summary>
    public required IReadOnlyDictionary<string, int> SignedPropertyOccurrenceCounts { get; init; }

    /// <summary>Gets the presence/cardinality inventory of every UNSIGNED qualifying-property kind this parse found, keyed the same way as <see cref="SignedPropertyOccurrenceCounts"/>.</summary>
    public required IReadOnlyDictionary<string, int> UnsignedPropertyOccurrenceCounts { get; init; }

    /// <summary>Gets every deprecated (V1 or v1.3.2-namespace) property name this parse observed — see the type remarks (always empty on a successfully-extracted instance, per this library's read-time refusal).</summary>
    public IReadOnlyList<string> DeprecatedPropertyObservations { get; init; } = [];

    /// <summary>
    /// Gets every unrecognized <c>##other</c> child of <c>UnsignedSignatureProperties</c> this parse observed,
    /// tolerated here. Each entry carries the element's own (namespace URI, local name) pair in Clark
    /// notation, <c>"{namespace}local-name"</c>, exact-character — the namespace is load-bearing: a foreign
    /// element deliberately named e.g. <c>ArchiveTimeStamp</c> in an attacker-chosen namespace must stay
    /// distinguishable in violation text from the real, v1.4.1-namespace property of the same local name
    ///. Clark notation's braces cannot collide with a namespace URI that itself ends in <c>#</c> or
    /// <c>/</c>, unlike a bare separator would.
    /// </summary>
    public IReadOnlyList<string> UnknownPropertyObservations { get; init; } = [];


    /// <summary>Disposes every owned carrier — see the type remarks for the ownership-transfer contract this method's callers must honour.</summary>
    public void Dispose()
    {
        for(int i = 0; i < SigningCertificateDigests.Count; ++i)
        {
            SigningCertificateDigests[i].Dispose();
        }

        SignaturePolicy?.Dispose();

        for(int i = 0; i < Timestamps.Count; ++i)
        {
            Timestamps[i].Token.Dispose();
        }

        DisposeAll(EmbeddedCertificates);
        DisposeAll(EmbeddedCertificateRevocationLists);
        DisposeAll(EmbeddedOcspResponses);

        for(int i = 0; i < CompleteCertificateRefs.Count; ++i)
        {
            CompleteCertificateRefs[i].Dispose();
        }

        for(int i = 0; i < AttributeCertificateRefs.Count; ++i)
        {
            AttributeCertificateRefs[i].Dispose();
        }

        for(int i = 0; i < CompleteRevocationCrlRefs.Count; ++i)
        {
            CompleteRevocationCrlRefs[i].Dispose();
        }

        for(int i = 0; i < CompleteRevocationOcspRefs.Count; ++i)
        {
            CompleteRevocationOcspRefs[i].Dispose();
        }

        for(int i = 0; i < AttributeRevocationCrlRefs.Count; ++i)
        {
            AttributeRevocationCrlRefs[i].Dispose();
        }

        for(int i = 0; i < AttributeRevocationOcspRefs.Count; ++i)
        {
            AttributeRevocationOcspRefs[i].Dispose();
        }

        static void DisposeAll(IReadOnlyList<PkiCertificateMemory> carriers)
        {
            for(int i = 0; i < carriers.Count; ++i)
            {
                carriers[i].Dispose();
            }
        }
    }
}


/// <summary>
/// Whether <see cref="ParseXAdESQualifyingPropertiesDelegate"/> did, or did not, produce
/// <see cref="XAdESQualifyingPropertiesFacts"/>.
/// </summary>
/// <remarks><see cref="Parsed"/> is deliberately not zero, matching every other status enumeration this seam family uses.</remarks>
public enum XAdESQualifyingPropertiesParseStatus
{
    /// <summary>No parse has been attempted. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The wire bytes decoded into a well-formed <see cref="XAdESQualifyingPropertiesFacts"/>.</summary>
    Parsed = 1,

    /// <summary>The wire bytes are not a processable XAdES signature — the <c>FAILED</c> outcome of EN 319 102-1 clause 5.2.2.3.</summary>
    Malformed = 2
}


/// <summary>
/// The outcome of <see cref="ParseXAdESQualifyingPropertiesDelegate"/>. On success it owns
/// <see cref="Facts"/> and every carrier it holds; the caller disposes it. On failure it owns nothing.
/// </summary>
[DebuggerDisplay("XAdESQualifyingPropertiesParseResult: {Status}")]
public sealed class XAdESQualifyingPropertiesParseResult: IDisposable
{
    /// <summary>Gets the parse outcome; <see cref="XAdESQualifyingPropertiesParseStatus.Parsed"/> is the only success.</summary>
    public required XAdESQualifyingPropertiesParseStatus Status { get; init; }

    /// <summary>Gets the parsed facts; non-<see langword="null"/> only when <see cref="Status"/> is <see cref="XAdESQualifyingPropertiesParseStatus.Parsed"/>.</summary>
    public XAdESQualifyingPropertiesFacts? Facts { get; init; }

    /// <summary>Gets a short, human-readable reason, present on every non-<see cref="XAdESQualifyingPropertiesParseStatus.Parsed"/> outcome.</summary>
    public string? FailureReason { get; init; }

    /// <summary>Gets whether <see cref="Status"/> is <see cref="XAdESQualifyingPropertiesParseStatus.Parsed"/>.</summary>
    public bool IsParsed => Status == XAdESQualifyingPropertiesParseStatus.Parsed;


    /// <summary>Creates a successful result owning <paramref name="facts"/>.</summary>
    /// <param name="facts">The parsed facts; ownership transfers to the result.</param>
    /// <returns>A <see cref="XAdESQualifyingPropertiesParseStatus.Parsed"/> result.</returns>
    public static XAdESQualifyingPropertiesParseResult Parsed(XAdESQualifyingPropertiesFacts facts) =>
        new() { Status = XAdESQualifyingPropertiesParseStatus.Parsed, Facts = facts };

    /// <summary>Creates a failed result that owns nothing.</summary>
    /// <param name="reason">A short, human-readable reason.</param>
    /// <returns>A <see cref="XAdESQualifyingPropertiesParseStatus.Malformed"/> result.</returns>
    public static XAdESQualifyingPropertiesParseResult Failed(string reason) =>
        new() { Status = XAdESQualifyingPropertiesParseStatus.Malformed, FailureReason = reason };


    /// <summary>Disposes <see cref="Facts"/>, when present.</summary>
    public void Dispose() => Facts?.Dispose();
}


/// <summary>
/// Parses one XAdES signature's wire bytes — an XML document carrying exactly one <c>ds:Signature</c>, per the
/// same "first/only signature" posture <see cref="CAdESSignatureFacts"/> takes for a CMS <c>SignerInfo</c> — into
/// the format-neutral <see cref="XAdESQualifyingPropertiesFacts"/>. This is the pure seam this format binding mints; the
/// library ships no implementation, mirroring <see cref="ParseTrustedListDelegate"/>: XML decoding is an
/// operation of the sibling <c>Verifiable.Xml</c> leaf, which <c>Verifiable.Cryptography</c> does not reference.
/// An implementation is composed over <c>Verifiable.Xml</c> at the caller's own composition root.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Fail-closed, never an exception.</strong> A document that does not parse as XML, carries no (or more
/// than one) <c>ds:Signature</c>, carries no <c>QualifyingProperties</c> the clause 4.4.1 discovery engine binds
/// to that signature, or whose <c>SignedProperties</c>/<c>UnsignedProperties</c> content this implementation
/// cannot read (including a recognized-and-refused deprecated property) MUST return
/// <see cref="XAdESQualifyingPropertiesParseResult.Failed(string)"/> rather than throwing — the wire bytes are
/// attacker-reachable input, and clause 5.2.2.3 of EN 319 102-1 defines an indication for this, not an exception.
/// </para>
/// <para>
/// <strong>Never a trust decision.</strong> This seam decodes and counts; it does not verify the signature value,
/// does not chain-build the signing certificate, and does not decide a baseline level — those stay above this
/// seam (<see cref="VerifyXAdESSignatureValueDelegate"/> for the first, <see cref="XAdESLevelRules"/> for the
/// third, consuming <see cref="XAdESQualifyingPropertiesFacts.SignedPropertyOccurrenceCounts"/>/
/// <see cref="XAdESQualifyingPropertiesFacts.UnsignedPropertyOccurrenceCounts"/> for the second half of that
/// question).
/// </para>
/// </remarks>
/// <param name="xmlDocument">The XML document octets. The caller retains ownership.</param>
/// <param name="pool">The memory pool every carrier the returned facts own is rented from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The parse result.</returns>
public delegate ValueTask<XAdESQualifyingPropertiesParseResult> ParseXAdESQualifyingPropertiesDelegate(
    ReadOnlyMemory<byte> xmlDocument,
    BaseMemoryPool pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Performs the cryptographic checks of EN 319 102-1 clause 5.2.7.4 over one XAdES signature: obtaining the
/// signed data items (the reference-processed content every <c>ds:Reference</c> of <c>ds:SignedInfo</c> names),
/// checking their integrity against the declared <c>ds:DigestValue</c>s, and verifying <c>ds:SignatureValue</c>
/// under <paramref name="signingCertificate"/>'s public key. The pure seam this format binding mints for the crypto half of
/// <see cref="XAdESSignatureFacts.CreateSeam"/>; the library ships no implementation, for the same reason
/// <see cref="ParseXAdESQualifyingPropertiesDelegate"/> ships none — canonicalization and reference processing
/// are <c>Verifiable.Xml</c> operations <c>Verifiable.Cryptography</c> cannot reach.
/// </summary>
/// <remarks>
/// An implementation composes the sibling leaf's canonicalization/reference-processing engines with this
/// library's own registered digest and signature-verification seams (<see cref="XmlSignatureWellKnown"/> already
/// resolves a <c>ds:DigestMethod</c>/<c>ds:SignatureMethod</c> URI onto this library's algorithm vocabulary with
/// no XML type involved), returning the outcome in Table 15's own vocabulary: a hash mismatch on any
/// <c>ds:Reference</c> is <see cref="SignatureCryptographicOutcome.HashFailure"/>; a signature value that was
/// checked and did not verify is <see cref="SignatureCryptographicOutcome.SignatureValueFailure"/>; a document
/// this implementation cannot even process (malformed, or dereferencing failed) is
/// <see cref="SignatureCryptographicOutcome.SignedDataNotFound"/>.
/// </remarks>
/// <param name="xmlDocument">The XML document octets carrying the <c>ds:Signature</c> to verify. The caller retains ownership.</param>
/// <param name="signingCertificate">The signing certificate identified by an earlier building block.</param>
/// <param name="pool">The memory pool any scratch buffer is rented from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The outcome in the vocabulary of Table 15 of clause 5.2.7.3.</returns>
public delegate ValueTask<SignatureCryptographicVerification> VerifyXAdESSignatureValueDelegate(
    ReadOnlyMemory<byte> xmlDocument,
    PkiCertificateMemory signingCertificate,
    BaseMemoryPool pool,
    CancellationToken cancellationToken = default);


/// <summary>
/// The XAdES binding of the format-facts seam: a <see cref="CreateSeam"/>
/// factory — mirroring <c>JAdESSignatureFacts</c>'s own factory shape — taking injected parse/verify delegates,
/// because <c>Verifiable.Cryptography</c> cannot reference the sibling <c>Verifiable.Xml</c> leaf that decodes
/// the wire (the same sibling-leaf reasoning <c>CBAdESSignatureFacts</c>/<c>JAdESSignatureFacts</c> record for
/// their own one-layer-up placement, except here Pki itself defines the returned shape rather than reusing a
/// decoder-owning assembly's own model types — <see cref="XAdESQualifyingPropertiesFacts"/> IS that shape).
/// <see cref="SignatureFormatIdentifier.XAdES"/> becomes the
/// fifth registrant on the <see cref="SignatureFacts"/>/<see cref="SignatureFormatSeam"/> engine.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Fact/verification split, unchanged.</strong> <see cref="ExtractAsync"/> is purely descriptive: a
/// parse-delegate failure maps to <see cref="SignatureFactsStatus.FormatFailure"/>, never an exception, and
/// nothing here computes a digest or makes a trust decision. <see cref="VerifyCryptographyAsync"/> is the one
/// place this binding touches cryptography, and it does so by handing the whole clause 5.2.7.4 check to the
/// injected <see cref="VerifyXAdESSignatureValueDelegate"/> — the same coarse-grained delegation
/// <c>CAdESSignatureFacts</c> makes to <c>VerifyCmsSignedDataDelegate</c> for the CMS core, needed here because
/// canonicalization is leaf territory this assembly cannot reach directly.
/// </para>
/// <para>
/// <strong>Not wired (disclosed, not silent).</strong> <see cref="SignatureFormatSeam.StateTimestampCoverage"/>/
/// <see cref="SignatureFormatSeam.StateTimestampProtectsObject"/> stay <see langword="null"/>: four
/// message-imprint-input engines already live in the leaf, but wiring the POE extraction building block
/// (EN 319 102-1 clause 5.6.2.3) to them is a distinct follow-on this binding does not attempt — a
/// <see langword="null"/> value is <see cref="SignatureFormatSeam"/>'s own documented "states nothing" case, not
/// a gap this binding hides.
/// </para>
/// </remarks>
public static class XAdESSignatureFacts
{
    /// <summary>
    /// Builds the <see cref="SignatureFormatSeam"/> bundle for XAdES, closing over the concrete
    /// <c>Verifiable.Xml</c>-backed delegates the composition root supplies (see the type remarks for why this
    /// is a factory rather than a fixed property, mirroring <c>TrustedListDelegates</c>'s pure-seam shape).
    /// </summary>
    /// <param name="parse">The fail-closed XAdES qualifying-properties parse seam.</param>
    /// <param name="verifySignatureValue">The clause 5.2.7.4 cryptographic-verification seam.</param>
    /// <returns>The seam, tagged <see cref="SignatureFormatIdentifier.XAdES"/>.</returns>
    /// <exception cref="ArgumentNullException">Either parameter is <see langword="null"/>.</exception>
    public static SignatureFormatSeam CreateSeam(
        ParseXAdESQualifyingPropertiesDelegate parse,
        VerifyXAdESSignatureValueDelegate verifySignatureValue)
    {
        ArgumentNullException.ThrowIfNull(parse);
        ArgumentNullException.ThrowIfNull(verifySignatureValue);

        return new SignatureFormatSeam
        {
            Format = SignatureFormatIdentifier.XAdES,
            ExtractFacts = (context, pool, cancellationToken) => ExtractAsync(context, parse, pool, cancellationToken),
            VerifyCryptography = (context, pool, cancellationToken) => VerifyCryptographyAsync(context, verifySignatureValue, pool, cancellationToken)
        };
    }


    /// <summary>
    /// Extracts the facts of a XAdES signature — the <see cref="ExtractSignatureFactsAsyncDelegate"/>
    /// implementation of the bundle in <see cref="CreateSeam"/>'s own return value.
    /// </summary>
    /// <param name="context">The Signed Data Object — the whole XML document octets carrying the <c>ds:Signature</c>.</param>
    /// <param name="parse">The injected XAdES qualifying-properties parse seam.</param>
    /// <param name="pool">The memory pool every carrier the returned facts own is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The extracted facts, or a <see cref="SignatureFactsStatus.FormatFailure"/>. The caller disposes them.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="context"/>, <paramref name="parse"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static async ValueTask<SignatureFacts> ExtractAsync(
        SignatureFactsExtractionContext context,
        ParseXAdESQualifyingPropertiesDelegate parse,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(parse);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        XAdESQualifyingPropertiesParseResult result = await parse(context.SignedDataObject.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        if(!result.IsParsed || result.Facts is null)
        {
            string reason = result.FailureReason ?? "The wire bytes do not decode as a well-formed XAdES signature.";
            result.Dispose();

            return SignatureFacts.FormatFailure(SignatureFormatIdentifier.XAdES, reason);
        }

        //Ownership of every carrier result.Facts holds transfers into the SignatureFacts BuildFacts returns
        //below (see XAdESQualifyingPropertiesFacts's own remarks) -- result itself is never disposed on this
        //path, so the transferred carriers are not released out from under their new owner.
        return BuildFacts(context, result.Facts);
    }


    /// <summary>
    /// Maps <see cref="XAdESQualifyingPropertiesFacts"/> onto the format-neutral <see cref="SignatureFacts"/> the
    /// engine consumes, transferring ownership of every carrier the richer shape holds.
    /// </summary>
    /// <param name="context">The extraction context (for <see cref="SignatureFactsExtractionContext.SignedDataObject"/>).</param>
    /// <param name="facts">The richer XAdES facts. Every owned carrier reachable through it is transferred, never copied.</param>
    /// <returns>The extracted, format-neutral facts.</returns>
    public static SignatureFacts BuildFacts(SignatureFactsExtractionContext context, XAdESQualifyingPropertiesFacts facts)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(facts);

        var signingCertificateReferences = new List<SigningCertificateReference>(facts.SigningCertificateDigests.Count);
        for(int i = 0; i < facts.SigningCertificateDigests.Count; ++i)
        {
            signingCertificateReferences.Add(facts.SigningCertificateDigests[i].Reference);
        }

        List<SignatureAttributeFacts> attributes = BuildAttributes(facts);

        string? signaturePolicyIdentifier = facts.SignaturePolicy is { IsImplied: false, Id: not null } policy
            ? policy.Id.Id
            : null;

        return new SignatureFacts
        {
            Status = SignatureFactsStatus.Extracted,
            Format = SignatureFormatIdentifier.XAdES,
            SignedDataObject = context.SignedDataObject,
            SignedContent = null,
            SignedContentPlacement = SignedContentPlacement.NotPresent,
            SignatureValue = null,
            Attributes = attributes,
            SigningCertificateReferences = signingCertificateReferences,
            SigningCertificate = null,
            EmbeddedCertificates = facts.EmbeddedCertificates,
            EmbeddedCertificateRevocationLists = facts.EmbeddedCertificateRevocationLists,
            EmbeddedOcspResponses = facts.EmbeddedOcspResponses,
            Timestamps = facts.Timestamps,
            ClaimedSigningTime = facts.SigningTime,
            SignaturePolicyIdentifier = signaturePolicyIdentifier,
            AlgorithmUses = []
        };
    }


    /// <summary>
    /// Builds one <see cref="SignatureAttributeFacts"/> entry per wire occurrence recorded in
    /// <see cref="XAdESQualifyingPropertiesFacts.SignedPropertyOccurrenceCounts"/>/
    /// <see cref="XAdESQualifyingPropertiesFacts.UnsignedPropertyOccurrenceCounts"/> — every clause 5 qualifying
    /// property lives inside <c>SignedProperties</c>/<c>UnsignedProperties</c> by construction, so a caller's
    /// <see cref="SignatureFacts.TryGetAttribute"/>/mandated-attribute check can name a XAdES property the same
    /// way <see cref="XAdESBaselineLevelTable"/>'s own rows do, and a repeated identifier naturally counts
    /// cardinality (one entry per occurrence, not one entry with a count).
    /// </summary>
    /// <param name="facts">The richer facts to project.</param>
    /// <returns>One entry per occurrence, in no particular cross-kind order.</returns>
    private static List<SignatureAttributeFacts> BuildAttributes(XAdESQualifyingPropertiesFacts facts)
    {
        var attributes = new List<SignatureAttributeFacts>();
        AddOccurrences(facts.SignedPropertyOccurrenceCounts, SignatureAttributeScope.Signed, attributes);
        AddOccurrences(facts.UnsignedPropertyOccurrenceCounts, SignatureAttributeScope.Unsigned, attributes);

        return attributes;

        static void AddOccurrences(IReadOnlyDictionary<string, int> occurrences, SignatureAttributeScope scope, List<SignatureAttributeFacts> collected)
        {
            foreach(KeyValuePair<string, int> occurrence in occurrences)
            {
                for(int i = 0; i < occurrence.Value; ++i)
                {
                    collected.Add(new SignatureAttributeFacts(occurrence.Key, scope, IsWellFormed: true));
                }
            }
        }
    }


    /// <summary>
    /// Performs the cryptographic checks of clause 5.2.7.4 over a XAdES signature — the
    /// <see cref="VerifySignatureCryptographyAsyncDelegate"/> implementation of the bundle in
    /// <see cref="CreateSeam"/>'s own return value. Delegates the WHOLE check to the injected
    /// <see cref="VerifyXAdESSignatureValueDelegate"/>: canonicalization and reference processing are leaf
    /// territory this assembly cannot reach, so — unlike <c>CAdESSignatureFacts</c>, which walks the CMS
    /// structure itself — nothing here re-implements any part of the check.
    /// </summary>
    /// <param name="context">The signature's facts and the signing certificate.</param>
    /// <param name="verifySignatureValue">The injected clause 5.2.7.4 verification seam.</param>
    /// <param name="pool">The memory pool any scratch buffer is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The outcome in the vocabulary of Table 15 of clause 5.2.7.3.</returns>
    /// <exception cref="ArgumentNullException">Any parameter is <see langword="null"/>.</exception>
    public static async ValueTask<SignatureCryptographicVerification> VerifyCryptographyAsync(
        SignatureCryptographicVerificationContext context,
        VerifyXAdESSignatureValueDelegate verifySignatureValue,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(verifySignatureValue);
        ArgumentNullException.ThrowIfNull(pool);

        if(context.Signature.SignedDataObject is not SensitiveMemory signedDataObject)
        {
            return new SignatureCryptographicVerification
            {
                Outcome = SignatureCryptographicOutcome.SignedDataNotFound,
                Reason = "The signed data object of a XAdES signature has to be the XML document octets carrying the ds:Signature."
            };
        }

        SignatureCryptographicVerification verification = await verifySignatureValue(
            signedDataObject.AsReadOnlyMemory(), context.SigningCertificate, pool, cancellationToken).ConfigureAwait(false);

        //The certificate Table 14 supplied as this call's own "Signing Certificate" input is the one the
        //injected delegate verified under; carried forward here rather than trusting every delegate
        //implementation to have set it itself, so this seam is the single point of truth the certificate-binding gate depends on.
        return verification.Outcome == SignatureCryptographicOutcome.Verified
            ? verification with { SigningCertificate = context.SigningCertificate }
            : verification;
    }
}
