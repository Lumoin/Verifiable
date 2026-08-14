namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The CBOR map keys of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>'s shared-syntax types — per-format serialization facts kept beside the
/// unified <c>AdES*</c> semantic model for the codecs and delegates that frame the CBOR wire. Every constant
/// group below (named by its shared-syntax type's concept, e.g. <c>ObjectIdentifier*</c>) corresponds to one
/// shared-syntax type; every constant reproduces, unchanged, the map key one of that type's former per-format
/// sibling files (<c>CBAdES*.cs</c>) declared.
/// </summary>
public static class CBAdESWireKeys
{
    /// <summary>The <c>id</c> member's map key (Table 11, clause 5.4.1).</summary>
    /// <remarks>
    /// This constant is one of the <c>oId</c> shared-syntax type's map keys (Table 11, clause 5.4.1). See
    /// <see cref="AdESObjectIdentifier"/> for the unified semantic type.
    /// </remarks>
    public const int ObjectIdentifierId = 1;


    /// <summary>The <c>desc</c> member's map key (Table 11, clause 5.4.1).</summary>
    public const int ObjectIdentifierDesc = 2;


    /// <summary>The <c>docRefs</c> member's map key (Table 11, clause 5.4.1).</summary>
    public const int ObjectIdentifierDocRefs = 3;


    /// <summary>The <c>val</c> member's map key (Table 12, clause 5.4.2).</summary>
    /// <remarks>
    /// This constant is one of the <c>pkiOb</c> shared-syntax type's map keys (Table 12, clause 5.4.2). See
    /// <see cref="AdESPkiObject"/> for the unified semantic type.
    /// </remarks>
    public const int PkiObjectVal = 1;


    /// <summary>The <c>encoding</c> member's map key (Table 12, clause 5.4.2).</summary>
    public const int PkiObjectEncoding = 2;


    /// <summary>The <c>specRef</c> member's map key (Table 12, clause 5.4.2).</summary>
    public const int PkiObjectSpecRef = 3;


    /// <summary>The <c>tstTokens</c> member's map key (Table 13, clause 5.4.3.3).</summary>
    /// <remarks>
    /// This is the <c>tstContainer</c> shared-syntax type's sole map key (Table 13, clause 5.4.3.3). See
    /// <see cref="AdESTimestampContainer"/> for the unified semantic type.
    /// </remarks>
    public const int TimestampContainerTstTokens = 1;


    /// <summary>The <c>val</c> member's map key (Table 13, clause 5.4.3.3).</summary>
    /// <remarks>
    /// This constant is one of the <c>TstToken</c> shared-syntax type's map keys (Table 13, clause 5.4.3.3). See
    /// <see cref="AdESTimestampToken"/> for the unified semantic type.
    /// </remarks>
    public const int TimestampTokenVal = 1;


    /// <summary>The <c>type</c> member's map key (Table 13, clause 5.4.3.3).</summary>
    public const int TimestampTokenType = 2;


    /// <summary>The <c>encoding</c> member's map key (Table 13, clause 5.4.3.3).</summary>
    public const int TimestampTokenEncoding = 3;


    /// <summary>The <c>specRef</c> member's map key (Table 13, clause 5.4.3.3).</summary>
    public const int TimestampTokenSpecRef = 4;


    /// <summary>The <c>addressCountry</c> member's map key (Table 3, clause 5.2.4).</summary>
    /// <remarks>
    /// This constant is one of the <c>sigPl</c> signed header parameter's map keys (Table 3, clause 5.2.4). See
    /// <see cref="AdESSignatureProductionPlace"/> for the unified semantic type.
    /// </remarks>
    public const int SignatureProductionPlaceAddressCountry = 1;


    /// <summary>The <c>addressLocality</c> member's map key (Table 3, clause 5.2.4).</summary>
    public const int SignatureProductionPlaceAddressLocality = 2;


    /// <summary>The <c>addressRegion</c> member's map key (Table 3, clause 5.2.4).</summary>
    public const int SignatureProductionPlaceAddressRegion = 3;


    /// <summary>The <c>postOfficeBoxNumber</c> member's map key (Table 3, clause 5.2.4).</summary>
    public const int SignatureProductionPlacePostOfficeBoxNumber = 4;


    /// <summary>The <c>postalCode</c> member's map key (Table 3, clause 5.2.4).</summary>
    public const int SignatureProductionPlacePostalCode = 5;


    /// <summary>The <c>streetAddress</c> member's map key (Table 3, clause 5.2.4).</summary>
    public const int SignatureProductionPlaceStreetAddress = 6;


    /// <summary>The <c>commId</c> member's map key (Table 2, clause 5.2.3).</summary>
    /// <remarks>
    /// This constant is one of the <c>SrCm</c> shared-syntax type's map keys (Table 2, clause 5.2.3). See
    /// <see cref="AdESCommitment"/> for the unified semantic type.
    /// </remarks>
    public const int CommitmentCommId = 1;


    /// <summary>The <c>commQuals</c> member's map key (Table 2, clause 5.2.3).</summary>
    public const int CommitmentCommQuals = 2;


    /// <summary>The <c>id</c> member's map key (Table 5, clause 5.2.7.1).</summary>
    /// <remarks>
    /// This constant is one of the <c>sigPId</c> signed header parameter's map keys (Table 5, clause 5.2.7.1). See
    /// <see cref="AdESSignaturePolicyIdentifier"/> for the unified semantic type.
    ///
    /// Read as corrected: Table 5's own printed row for key <c>4</c> mislabels
    /// <c>sigPQuals</c> as a member of <c>CertifiedAttrChoice</c>; read as corrected, it belongs to
    /// <c>sigPId</c>, exactly as the CDDL states.
    /// </remarks>
    public const int SignaturePolicyIdentifierId = 1;


    /// <summary>The <c>digAlgVal</c> member's map key (Table 5, clause 5.2.7.1).</summary>
    public const int SignaturePolicyIdentifierDigAlgVal = 2;


    /// <summary>The <c>digPSp</c> member's map key (Table 5, clause 5.2.7.1).</summary>
    public const int SignaturePolicyIdentifierDigPSp = 3;


    /// <summary>The <c>sigPQuals</c> member's map key (Table 5, clause 5.2.7.1; see the remarks above).</summary>
    public const int SignaturePolicyIdentifierSigPQuals = 4;


    /// <summary>The <c>spURI</c> choice arm's map key (Table 6, clause 5.2.7.2).</summary>
    /// <remarks>
    /// This constant is one of the <c>SigPQual</c> choice arms' map keys (Table 6, clause 5.2.7.2). See
    /// <see cref="AdESSignaturePolicyQualifier"/> for the unified semantic type.
    ///
    /// The ruled reading: the wire shape is one-entry maps keyed per Table 6, notwithstanding the
    /// CDDL's <c>*label =&gt; value</c> catch-all syntax and CB-5.2.7-15/16/17/18's "tagged data item" prose —
    /// see <see cref="AdESSignaturePolicyQualifier"/>'s own remarks for the full ruling. <c>otherQuals</c>
    /// (Table 6 key <c>4</c>) flows through the catch-all with the qualifier's own label as key, never a
    /// literal key <c>4</c>, so it has no constant here.
    /// </remarks>
    public const int SignaturePolicyQualifierSpUri = 1;


    /// <summary>The <c>spUserNotice</c> choice arm's map key (Table 6, clause 5.2.7.2).</summary>
    public const int SignaturePolicyQualifierSpUserNotice = 2;


    /// <summary>The <c>spDSpec</c> choice arm's map key (Table 6, clause 5.2.7.2).</summary>
    public const int SignaturePolicyQualifierSpDSpec = 3;


    /// <summary>The <c>noticeRef</c> member's map key, within <c>SpUserNotice</c> (Table 6, clause 5.2.7.2).</summary>
    /// <remarks>
    /// This constant is one of the <c>SpUserNotice</c> shape's map keys (Table 6, clause 5.2.7.2). See
    /// <see cref="AdESSignaturePolicyUserNotice"/> for the unified semantic type.
    /// </remarks>
    public const int SignaturePolicyUserNoticeNoticeRef = 1;


    /// <summary>The <c>explText</c> member's map key, within <c>SpUserNotice</c> (Table 6, clause 5.2.7.2).</summary>
    public const int SignaturePolicyUserNoticeExplText = 2;


    /// <summary>The <c>org</c> member's map key, within <c>NoticeRef</c> (Table 6, clause 5.2.7.2).</summary>
    /// <remarks>
    /// This constant is one of the <c>NoticeRef</c> shape's map keys (Table 6, clause 5.2.7.2). See
    /// <see cref="AdESSignaturePolicyNoticeReference"/> for the unified semantic type.
    /// </remarks>
    public const int SignaturePolicyNoticeReferenceOrg = 1;


    /// <summary>The <c>noticeNumbers</c> member's map key, within <c>NoticeRef</c> (Table 6, clause 5.2.7.2).</summary>
    public const int SignaturePolicyNoticeReferenceNoticeNumbers = 2;


    /// <summary>The <c>certified</c> member's map key (Table 4, clause 5.2.5).</summary>
    /// <remarks>
    /// This constant is one of the <c>srAts</c> signed header parameter's map keys (Table 4, clause 5.2.5).
    /// See <see cref="AdESSignerAttributes"/> for the unified semantic type.
    /// </remarks>
    public const int SignerAttributesCertified = 1;


    /// <summary>The <c>signedAssertions</c> member's map key (Table 4, clause 5.2.5).</summary>
    public const int SignerAttributesSignedAssertions = 2;


    /// <summary>The <c>claimed</c> member's map key (Table 4, clause 5.2.5).</summary>
    public const int SignerAttributesClaimed = 3;


    /// <summary>The <c>x509AttrCert</c> choice arm's map key (Table 4, clause 5.2.5, <c>CertifiedAttrChoice</c>).</summary>
    /// <remarks>
    /// This constant is one of the <c>CertifiedAttrChoice</c> shape's map keys (Table 4, clause 5.2.5). See
    /// <see cref="AdESCertifiedAttribute"/> for the unified semantic type.
    /// </remarks>
    public const int CertifiedAttributeX509AttrCert = 1;


    /// <summary>The <c>otherAttrCert</c> choice arm's map key (Table 4, clause 5.2.5, <c>CertifiedAttrChoice</c>).</summary>
    public const int CertifiedAttributeOtherAttrCert = 2;
}
