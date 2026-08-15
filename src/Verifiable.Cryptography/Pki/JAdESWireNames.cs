namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The JSON member names of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>'s shared-syntax types and Annex B.1 schemas — per-format serialization facts
/// kept beside the unified <c>AdES*</c> semantic model for the codecs and delegates that frame the JSON wire.
/// Every constant group below (named by its shared-syntax type's concept, e.g. <c>ObjectIdentifier*</c>)
/// corresponds to one shared-syntax type; every constant reproduces, unchanged, the JSON key name one of that
/// type's former per-format sibling files (<c>JAdES*.cs</c>) declared.
/// </summary>
public static class JAdESWireNames
{
    /// <summary>The <c>id</c> member's JSON key name (clause 5.4.1, Annex B.1 schema).</summary>
    /// <remarks>
    /// This constant is one of the <c>oId</c> shared-syntax type's JSON key names (clause 5.4.1, Annex B.1
    /// schema). See <see cref="AdESObjectIdentifier"/> for the unified semantic type.
    /// </remarks>
    public const string ObjectIdentifierId = "id";


    /// <summary>The <c>desc</c> member's JSON key name (clause 5.4.1, Annex B.1 schema).</summary>
    public const string ObjectIdentifierDesc = "desc";


    /// <summary>The <c>docRefs</c> member's JSON key name (clause 5.4.1, Annex B.1 schema).</summary>
    public const string ObjectIdentifierDocRefs = "docRefs";


    /// <summary>The <c>val</c> member's JSON key name (clause 5.4.2, Annex B.1 schema).</summary>
    /// <remarks>
    /// This constant is one of the <c>pkiOb</c> shared-syntax type's JSON key names (clause 5.4.2, Annex B.1
    /// schema). See <see cref="AdESPkiObject"/> for the unified semantic type.
    /// </remarks>
    public const string PkiObjectVal = "val";


    /// <summary>The <c>encoding</c> member's JSON key name (clause 5.4.2, Annex B.1 schema).</summary>
    public const string PkiObjectEncoding = "encoding";


    /// <summary>The <c>specRef</c> member's JSON key name (clause 5.4.2, Annex B.1 schema).</summary>
    public const string PkiObjectSpecRef = "specRef";


    /// <summary>The <c>canonAlg</c> member's JSON key name (clause 5.4.3.3, Annex B.1 schema).</summary>
    /// <remarks>
    /// This constant is one of the <c>tstContainer</c> shared-syntax type's JSON key names (clause 5.4.3.3,
    /// Annex B.1 schema). See <see cref="AdESTimestampContainer"/> for the unified semantic type.
    /// </remarks>
    public const string TimestampContainerCanonAlg = "canonAlg";


    /// <summary>The <c>tstTokens</c> member's JSON key name (clause 5.4.3.3, Annex B.1 schema).</summary>
    public const string TimestampContainerTstTokens = "tstTokens";


    /// <summary>The <c>val</c> member's JSON key name (clause 5.4.3.3, Annex B.1 schema).</summary>
    /// <remarks>
    /// This constant is one of the <c>tstToken</c> shared-syntax type's JSON key names (clause 5.4.3.3, Annex B.1
    /// schema). See <see cref="AdESTimestampToken"/> for the unified semantic type.
    /// </remarks>
    public const string TimestampTokenVal = "val";


    /// <summary>The <c>type</c> member's JSON key name (clause 5.4.3.3, Annex B.1 schema).</summary>
    public const string TimestampTokenType = "type";


    /// <summary>The <c>encoding</c> member's JSON key name (clause 5.4.3.3, Annex B.1 schema).</summary>
    public const string TimestampTokenEncoding = "encoding";


    /// <summary>The <c>specRef</c> member's JSON key name (clause 5.4.3.3, Annex B.1 schema).</summary>
    public const string TimestampTokenSpecRef = "specRef";


    /// <summary>The <c>addressCountry</c> member's JSON key name (clause 5.2.4, Annex B.1 schema).</summary>
    /// <remarks>
    /// This constant is one of the <c>sigPl</c> signed header parameter's JSON key names (clause 5.2.4, Annex
    /// B.1 schema). See <see cref="AdESSignatureProductionPlace"/> for the unified semantic type.
    /// </remarks>
    public const string SignatureProductionPlaceAddressCountry = "addressCountry";


    /// <summary>The <c>addressLocality</c> member's JSON key name (clause 5.2.4, Annex B.1 schema).</summary>
    public const string SignatureProductionPlaceAddressLocality = "addressLocality";


    /// <summary>The <c>addressRegion</c> member's JSON key name (clause 5.2.4, Annex B.1 schema).</summary>
    public const string SignatureProductionPlaceAddressRegion = "addressRegion";


    /// <summary>The <c>postOfficeBoxNumber</c> member's JSON key name (clause 5.2.4, Annex B.1 schema).</summary>
    public const string SignatureProductionPlacePostOfficeBoxNumber = "postOfficeBoxNumber";


    /// <summary>The <c>postalCode</c> member's JSON key name (clause 5.2.4, Annex B.1 schema).</summary>
    public const string SignatureProductionPlacePostalCode = "postalCode";


    /// <summary>The <c>streetAddress</c> member's JSON key name (clause 5.2.4, Annex B.1 schema).</summary>
    public const string SignatureProductionPlaceStreetAddress = "streetAddress";


    /// <summary>The <c>digAlg</c> member's JSON key name (clause 5.2.2.2, Annex B.1 schema).</summary>
    /// <remarks>
    /// This constant is one of the <c>x5t#o</c> shared-syntax type's JSON key names (clause 5.2.2.2, Annex B.1
    /// schema). See <see cref="AdESCertificateThumbprint"/> for the unified semantic type.
    /// </remarks>
    public const string CertificateThumbprintHashAlgorithm = "digAlg";


    /// <summary>The <c>digVal</c> member's JSON key name (clause 5.2.2.2, Annex B.1 schema).</summary>
    public const string CertificateThumbprintDigest = "digVal";


    /// <summary>The <c>commId</c> member's JSON key name (clause 5.2.3, Annex B.1 schema).</summary>
    /// <remarks>
    /// This constant is one of the <c>srCms</c> array entry shape's JSON key names (clause 5.2.3, Annex B.1
    /// schema). See <see cref="AdESCommitment"/> for the unified semantic type.
    /// </remarks>
    public const string SignerCommitmentsCommitmentId = "commId";


    /// <summary>The <c>commQuals</c> member's JSON key name (clause 5.2.3, Annex B.1 schema).</summary>
    public const string SignerCommitmentsCommitmentQualifiers = "commQuals";


    /// <summary>The <c>id</c> member's JSON key name (clause 5.2.7.1, Annex B.1 schema).</summary>
    /// <remarks>
    /// This constant is one of the <c>sigPId</c> signed header parameter's JSON key names (clause 5.2.7.1, Annex
    /// B.1 schema). See <see cref="AdESSignaturePolicyIdentifier"/> for the unified semantic type.
    /// </remarks>
    public const string SignaturePolicyIdentifierId = "id";


    /// <summary>The <c>digAlg</c> member's JSON key name (clause 5.2.7.1, Annex B.1 schema).</summary>
    public const string SignaturePolicyIdentifierHashAlgorithm = "digAlg";


    /// <summary>The <c>digVal</c> member's JSON key name (clause 5.2.7.1, Annex B.1 schema).</summary>
    public const string SignaturePolicyIdentifierDigest = "digVal";


    /// <summary>The <c>digPSp</c> member's JSON key name (clause 5.2.7.1, Annex B.1 schema).</summary>
    public const string SignaturePolicyIdentifierDigestIsPerSpecification = "digPSp";


    /// <summary>The <c>sigPQuals</c> member's JSON key name (clause 5.2.7.1, Annex B.1 schema).</summary>
    public const string SignaturePolicyIdentifierQualifiers = "sigPQuals";


    /// <summary>The <c>spURI</c> arm's JSON key name (clause 5.2.7.2, Annex B.1 schema).</summary>
    /// <remarks>
    /// This constant is one of the <c>sigPQual</c> shared-syntax type's JSON key names (clause 5.2.7.2, Annex
    /// B.1 schema). See <see cref="AdESSignaturePolicyQualifier"/> for the unified semantic type.
    ///
    /// Unlike CB-AdES's CDDL <c>*label =&gt; value</c> catch-all, JAdES's schema enumerates exactly these
    /// three named properties with no open extension point (<c>"minProperties": 1, "maxProperties": 1</c>) —
    /// there is no JAdES counterpart to <see cref="CBAdESWireKeys.SignaturePolicyQualifierSpUri"/>'s absent
    /// <c>otherQuals</c> constant, because JAdES has no <c>otherQuals</c> arm at all.
    /// </remarks>
    public const string SignaturePolicyQualifierSpUri = "spURI";


    /// <summary>The <c>spUserNotice</c> arm's JSON key name (clause 5.2.7.2, Annex B.1 schema).</summary>
    public const string SignaturePolicyQualifierSpUserNotice = "spUserNotice";


    /// <summary>The <c>spDSpec</c> arm's JSON key name (clause 5.2.7.2, Annex B.1 schema).</summary>
    public const string SignaturePolicyQualifierSpDSpec = "spDSpec";


    /// <summary>The <c>noticeRef</c> member's JSON key name, within <c>spUserNotice</c> (clause 5.2.7.2, Annex B.1 schema).</summary>
    /// <remarks>
    /// This constant is one of the <c>spUserNotice</c> shape's JSON key names (clause 5.2.7.2, Annex B.1
    /// schema). See <see cref="AdESSignaturePolicyUserNotice"/> for the unified semantic type.
    /// </remarks>
    public const string SignaturePolicyUserNoticeNoticeReference = "noticeRef";


    /// <summary>The <c>explText</c> member's JSON key name, within <c>spUserNotice</c> (clause 5.2.7.2, Annex B.1 schema).</summary>
    public const string SignaturePolicyUserNoticeExplicitText = "explText";


    /// <summary>The <c>organization</c> member's JSON key name, within <c>noticeRef</c> (clause 5.2.7.2, Annex B.1 schema).</summary>
    /// <remarks>
    /// This constant is one of the <c>noticeRef</c> shape's JSON key names (clause 5.2.7.2, Annex B.1 schema).
    /// See <see cref="AdESSignaturePolicyNoticeReference"/> for the unified semantic type.
    /// </remarks>
    public const string SignaturePolicyNoticeReferenceOrganization = "organization";


    /// <summary>The <c>noticeNumbers</c> member's JSON key name, within <c>noticeRef</c> (clause 5.2.7.2, Annex B.1 schema).</summary>
    public const string SignaturePolicyNoticeReferenceNoticeNumbers = "noticeNumbers";


    /// <summary>The <c>certified</c> member's JSON key name (clause 5.2.5, Annex B.1 schema).</summary>
    /// <remarks>
    /// This constant is one of the <c>srAts</c> signed header parameter's JSON key names (clause 5.2.5, Annex
    /// B.1 schema). See <see cref="AdESSignerAttributes"/> for the unified semantic type.
    /// </remarks>
    public const string SignerAttributesCertified = "certified";


    /// <summary>The <c>signedAssertions</c> member's JSON key name (clause 5.2.5, Annex B.1 schema).</summary>
    public const string SignerAttributesSignedAssertions = "signedAssertions";


    /// <summary>The <c>claimed</c> member's JSON key name (clause 5.2.5, Annex B.1 schema).</summary>
    public const string SignerAttributesClaimed = "claimed";


    /// <summary>The <c>x509AttrCert</c> arm's JSON key name (clause 5.2.5, Annex B.1 schema).</summary>
    /// <remarks>
    /// This constant is one of the <c>certifiedAttrs</c> shape's JSON key names (clause 5.2.5, Annex B.1
    /// schema). See <see cref="AdESCertifiedAttribute"/> for the unified semantic type.
    /// </remarks>
    public const string CertifiedAttributeX509AttrCert = "x509AttrCert";


    /// <summary>The <c>otherAttrCert</c> arm's JSON key name (clause 5.2.5, Annex B.1 schema).</summary>
    public const string CertifiedAttributeOtherAttrCert = "otherAttrCert";
}
