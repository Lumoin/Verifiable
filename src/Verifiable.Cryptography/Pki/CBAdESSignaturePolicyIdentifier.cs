using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>sigPId</c> (label 266, clause 5.2.1 Table 1) signed header parameter: an explicit
/// identifier of a signature policy document, by digest plus optional qualifiers, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 5.2.7.1.
/// </summary>
/// <remarks>
/// <para>
/// CDDL (clause 5.2.7.1):
/// </para>
/// <code>
/// sigPId = {
///     1 =&gt; oId,                     ; id
///     2 =&gt; DigAlgVal,                ; digAlgVal
///     ? 3 =&gt; bool .default false,    ; digPSp
///     ? 4 =&gt; [+SigPQual]             ; sigPQuals
/// }
/// DigAlgVal = [ hashAlg: (int / tstr), hashValue: bstr ]
/// </code>
/// <para>
/// Table 5 (clause 5.2.7.1) assigns the map key values: <c>id</c> = <c>1</c>, <c>digAlgVal</c> = <c>2</c>,
/// <c>digPSp</c> = <c>3</c>, <c>sigPQuals</c> = <c>4</c>.
/// <strong>D6 (contract R-6, "read as corrected"):</strong> Table 5's own printed row for key <c>4</c> reads
/// "<c>sigPQuals(in CertifiedAttrChoice)</c>" — <c>CertifiedAttrChoice</c> is a <c>srAts</c> type (clause
/// 5.2.5, see <see cref="CBAdESSignerAttributeCertifiedAttribute"/>), not a member of <c>sigPId</c>; this is a
/// spec-original copy/paste defect (CB-AdES preflight leg 2, "Traps and cross-references": "Table 5 mislabels
/// its last row ... <c>sigPQuals</c> is actually a member of <c>sigPId</c> (clause 5.2.7.1), not of
/// <c>CertifiedAttrChoice</c>"). Read as corrected: <c>sigPQuals</c> belongs to <c>sigPId</c>, exactly as the
/// CDDL above already states.
/// </para>
/// <para>
/// <c>digAlgVal</c>'s two-element array is flattened onto this record as <see cref="HashAlgorithm"/> and
/// <see cref="Digest"/> rather than a separate nested type, mirroring
/// <see cref="CBAdESCertificateThumbprint"/>'s flattening of <c>COSE_CertHash</c> (the same <c>[hashAlg,
/// hashValue]</c> shape, RFC 9360 §2). <see cref="HashAlgorithm"/> models the CDDL's permissive <c>int /
/// tstr</c> union faithfully as <see cref="CBAdESDigestAlgorithmIdentifier"/>, matching
/// <see cref="CBAdESCertificateThumbprint.HashAlgorithm"/> — clause 5.2.7.1's identifier-registry prose ("the
/// digest-algorithm identifiers registered in the IANA COSE Algorithms registry, or one defined in IETF RFC
/// 9053 [4]") constrains which registry an identifier comes from, not which CDDL arm it must use.
/// <c>hashValue</c> is the digest of the signature policy document, carried in <see cref="Digest"/> — never a
/// naked <c>byte[]</c>.
/// </para>
/// <para>
/// <c>sigPId</c> is a signature-qualifying header parameter (clause 5.2.7.1) and, in a <c>COSE_Sign</c>
/// structure, is placed at the signer layer (CB-5.2.7-14) — the signature builder's responsibility, not this
/// type's.
/// </para>
/// <para>
/// <strong>Cross-field invariant (CB-5.2.7-12):</strong> "If <c>digPSp</c> is present and <c>true</c>, then
/// the <c>spDSpec</c> qualifier shall be present and shall identify the technical specification." Unlike the
/// simple "at least one of several optional members" presence rules elsewhere in this wave (e.g.
/// <see cref="CBAdESSignatureProductionPlace"/>), this rule spans two independently-supplied constructor
/// parameters of a record that already requires a constructor for <see cref="Digest"/>'s ownership transfer;
/// it is therefore enforced here, at construction, throwing <see cref="ArgumentException"/> — trusted caller
/// input, not wire parsing, so a hard failure at the point of misuse is preferable to a silently
/// policy-non-compliant instance reaching a signature.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns <see cref="Digest"/>; disposing this instance disposes it.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESSignaturePolicyIdentifier: HashAlgorithm={HashAlgorithm}, DigestIsPerSpecification={DigestIsPerSpecification}")]
public sealed record CBAdESSignaturePolicyIdentifier: IDisposable
{
    /// <summary>The <c>id</c> member's map key (Table 5, clause 5.2.7.1).</summary>
    public const int IdKey = 1;

    /// <summary>The <c>digAlgVal</c> member's map key (Table 5, clause 5.2.7.1).</summary>
    public const int DigAlgValKey = 2;

    /// <summary>The <c>digPSp</c> member's map key (Table 5, clause 5.2.7.1).</summary>
    public const int DigPSpKey = 3;

    /// <summary>The <c>sigPQuals</c> member's map key (Table 5, clause 5.2.7.1; see the D6 remarks above).</summary>
    public const int SigPQualsKey = 4;

    /// <summary>
    /// Initializes a new <see cref="CBAdESSignaturePolicyIdentifier"/>. Ownership of <paramref name="digest"/>
    /// transfers to this instance.
    /// </summary>
    /// <param name="id">The <c>id</c> member (map key 1) uniquely identifying a specific version of the signature policy.</param>
    /// <param name="hashAlgorithm">The <c>digAlgVal.hashAlg</c> element — the digest algorithm identifier.</param>
    /// <param name="digest">The <c>digAlgVal.hashValue</c> element — the digest of the signature policy document.</param>
    /// <param name="digestIsPerSpecification">
    /// The <c>digPSp</c> member (map key 3): <see langword="true"/> when the digest was computed as specified
    /// in a technical specification. Absence on the wire is equivalent to <see langword="false"/>
    /// (CB-5.2.7-11), which this parameter's default reproduces.
    /// </param>
    /// <param name="qualifiers">
    /// The <c>sigPQuals</c> member (map key 4), or <see langword="null"/> to omit it. When present, must be
    /// non-empty (CB-5.2.7-13).
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="id"/>, <paramref name="hashAlgorithm"/>, or <paramref name="digest"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="qualifiers"/> is non-null but empty; or <paramref name="digestIsPerSpecification"/> is
    /// <see langword="true"/> and <paramref name="qualifiers"/> carries no
    /// <see cref="CBAdESSignaturePolicyDocumentSpecification"/> entry (CB-5.2.7-12).
    /// </exception>
    public CBAdESSignaturePolicyIdentifier(
        CBAdESObjectIdentifier id,
        CBAdESDigestAlgorithmIdentifier hashAlgorithm,
        DigestValue digest,
        bool digestIsPerSpecification = false,
        IReadOnlyList<CBAdESSignaturePolicyQualifier>? qualifiers = null)
    {
        ArgumentNullException.ThrowIfNull(id);
        ArgumentNullException.ThrowIfNull(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(digest);

        if(qualifiers is not null && qualifiers.Count == 0)
        {
            throw new ArgumentException(
                "When present, 'sigPQuals' shall be a non-empty array (ETSI TS 119 152-1 V1.1.1, clause 5.2.7.1, CB-5.2.7-13).",
                nameof(qualifiers));
        }

        if(digestIsPerSpecification && !HasDocumentSpecification(qualifiers))
        {
            throw new ArgumentException(
                "When 'digPSp' is true, an 'spDSpec' qualifier identifying the technical specification shall " +
                "be present in 'sigPQuals' (ETSI TS 119 152-1 V1.1.1, clause 5.2.7.1, CB-5.2.7-12).",
                nameof(qualifiers));
        }

        Id = id;
        HashAlgorithm = hashAlgorithm;
        Digest = digest;
        DigestIsPerSpecification = digestIsPerSpecification;
        Qualifiers = qualifiers;

        static bool HasDocumentSpecification(IReadOnlyList<CBAdESSignaturePolicyQualifier>? candidates)
        {
            if(candidates is null)
            {
                return false;
            }

            for(int i = 0; i < candidates.Count; i++)
            {
                if(candidates[i] is CBAdESSignaturePolicyDocumentSpecification)
                {
                    return true;
                }
            }

            return false;
        }
    }


    /// <summary>Gets the <c>id</c> member (map key 1) identifying the signature policy.</summary>
    public CBAdESObjectIdentifier Id { get; }

    /// <summary>
    /// Gets the <c>digAlgVal.hashAlg</c> element. See <see cref="CBAdESDigestAlgorithmIdentifier"/> for the
    /// CDDL's <c>int / tstr</c> union this member models.
    /// </summary>
    public CBAdESDigestAlgorithmIdentifier HashAlgorithm { get; }

    /// <summary>
    /// Gets the <c>digAlgVal.hashValue</c> element — the digest of the signature policy document. Owned by
    /// this instance; disposed via <see cref="Dispose"/>.
    /// </summary>
    public DigestValue Digest { get; }

    /// <summary>
    /// Gets the <c>digPSp</c> member (map key 3): <see langword="true"/> when the digest was computed as
    /// specified in a technical specification (CB-5.2.7-10). Defaults to <see langword="false"/>, matching the
    /// wire default for absence (CB-5.2.7-11).
    /// </summary>
    public bool DigestIsPerSpecification { get; }

    /// <summary>
    /// Gets the <c>sigPQuals</c> member (map key 4), or <see langword="null"/> when absent. Non-empty when
    /// present (enforced at construction — see the type remarks).
    /// </summary>
    public IReadOnlyList<CBAdESSignaturePolicyQualifier>? Qualifiers { get; }


    /// <summary>Disposes <see cref="Digest"/>.</summary>
    public void Dispose() => Digest.Dispose();
}


/// <summary>
/// One element of <see cref="CBAdESSignaturePolicyIdentifier.Qualifiers"/> (<c>SigPQual</c>, clause 5.2.7.2):
/// a closed sum of the three qualifiers this document names plus an open escape for any other. A DU-ready
/// closed sum: no external type may derive from it.
/// </summary>
/// <remarks>
/// <para>
/// CDDL (clause 5.2.7.2):
/// </para>
/// <code>
/// SigPQual = {
///     ? 1 =&gt; #6.32(tstr) // ; spURI
///     ? 2 =&gt; SpUserNotice// ; spUserNotice
///     ? 3 =&gt; SpDesc //      ; spDSpec (the CDDL names the type SpDesc; the type definition itself is
///                            ; named SpDSpec — a spec-original spelling inconsistency, same character as the
///                            ; oId/obId one clause 5.4.1 exhibits; read as the same type)
///     *label =&gt; value       ; otherQuals
/// }
/// SpUserNotice = { ? 1 =&gt; NoticeRef, ? 2 =&gt; tstr }
/// NoticeRef = { 1 =&gt; tstr, 2 =&gt; [+uint] }
/// SpDSpec = obId
/// </code>
/// <para>
/// Table 6 (clause 5.2.7.2) assigns FIXED map key values to all four members, including <c>otherQuals</c>:
/// <c>spUri</c> = <c>1</c>, <c>spUserNotice</c> = <c>2</c>, <c>spDSpec</c> = <c>3</c>, <c>otherQuals</c> =
/// <c>4</c>. <strong>D11 (contract R-6, RULED):</strong> on its surface this is in tension with the CDDL's
/// <c>*label =&gt; value</c> catch-all syntax, which denotes a variable-key group repeated zero or more times,
/// not one entry fixed at key <c>4</c>, and with CB-5.2.7-15/16/17/18's prose, which calls
/// <c>1</c>/<c>2</c>/<c>3</c> "choice tag[s]" and states "each signature-policy qualifier shall be a CBOR
/// tagged data item" — language suggesting CBOR major-type-6 tagging rather than the map keys Table 6
/// documents. Ruled: the wire shape is one-entry MAPS keyed per Table 6 — the CDDL and Table 6's own "keys in
/// maps" title govern; the prose's "tagged data item" is loose drafting, the same character of imprecision as
/// the same CDDL block writing <c>#6.32</c> where a real CBOR tag is meant (the <c>spURI</c> arm above) while
/// <c>spUserNotice</c> and <c>spDSpec</c> carry no tag at all — "tagged" reads as the drafter's loose gloss for
/// "identified by its key", not a CBOR major-type-6 requirement. <c>otherQuals</c> flows through the
/// <c>*label =&gt; value</c> catch-all with the qualifier's own label as key, never a literal key <c>4</c>.
/// Each element of <see cref="CBAdESSignaturePolicyIdentifier.Qualifiers"/> is one decoded qualifier of one of
/// the four kinds below; the codec (<c>CBAdESSerialization</c>'s <c>WriteSignaturePolicyQualifier</c>/
/// <c>ReadSignaturePolicyQualifier</c>) cites D11 at the resolution site, mirroring how
/// <see cref="CBAdESDetachedObjects"/> collapses <c>sigD</c>'s positionally-coupled parallel arrays into one
/// per-object model, leaving the CBOR projection to the codec.
/// </para>
/// </remarks>
public abstract record CBAdESSignaturePolicyQualifier
{
    /// <summary>The <c>spURI</c> choice arm's map key (Table 6, clause 5.2.7.2).</summary>
    public const int SpUriKey = 1;

    /// <summary>The <c>spUserNotice</c> choice arm's map key (Table 6, clause 5.2.7.2).</summary>
    public const int SpUserNoticeKey = 2;

    /// <summary>The <c>spDSpec</c> choice arm's map key (Table 6, clause 5.2.7.2).</summary>
    public const int SpDSpecKey = 3;

    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESSignaturePolicyQualifier()
    {
    }
}


/// <summary>
/// The <c>spURI</c> qualifier (clause 5.2.7.2, map key 1, Table 6): a URL where a copy of the signature
/// policy document can be obtained (CB-5.2.7-19).
/// </summary>
/// <param name="Location">The URL, carried as a CBOR tag-32 URI on the wire (<c>#6.32(tstr)</c>), matching <see cref="CBAdESObjectIdentifier.Id"/>'s convention for the same wire type.</param>
[DebuggerDisplay("CBAdESSignaturePolicyUri: {Location}")]
public sealed record CBAdESSignaturePolicyUri(Uri Location) : CBAdESSignaturePolicyQualifier;


/// <summary>
/// The <c>spUserNotice</c> qualifier (clause 5.2.7.2, map key 2, Table 6): information intended for display
/// whenever the signature is validated (CB-5.2.7-20).
/// </summary>
/// <remarks>
/// CDDL: <c>SpUserNotice = { ?1 =&gt; NoticeRef, ?2 =&gt; tstr }</c>. At least one of <see cref="NoticeReference"/>
/// and <see cref="ExplicitText"/> shall be present (CB-5.2.7-23); mirroring
/// <see cref="CBAdESSignatureProductionPlace"/>'s "at least one field present" convention, that invariant is
/// documented here rather than runtime-enforced — this type owns no disposable resources, so no constructor
/// is otherwise required.
/// </remarks>
[DebuggerDisplay("CBAdESSignaturePolicyUserNotice: NoticeReference={NoticeReference != null}, ExplicitText={ExplicitText != null}")]
public sealed record CBAdESSignaturePolicyUserNotice : CBAdESSignaturePolicyQualifier
{
    /// <summary>The <c>noticeRef</c> member's map key, within <c>SpUserNotice</c> (Table 6, clause 5.2.7.2).</summary>
    public const int NoticeRefKey = 1;

    /// <summary>The <c>explText</c> member's map key, within <c>SpUserNotice</c> (Table 6, clause 5.2.7.2).</summary>
    public const int ExplTextKey = 2;

    /// <summary>
    /// Gets the <c>noticeRef</c> member (map key 1, in <c>SpUserNotice</c>, Table 6): a pointer into an
    /// out-of-band, organization-maintained notices catalogue (CB-5.2.7-25), or <see langword="null"/> when
    /// absent.
    /// </summary>
    public CBAdESSignaturePolicyNoticeReference? NoticeReference { get; init; }

    /// <summary>
    /// Gets the <c>explText</c> member (map key 2, in <c>SpUserNotice</c>, Table 6): the text of the notice
    /// to display (CB-5.2.7-24), or <see langword="null"/> when absent.
    /// </summary>
    public string? ExplicitText { get; init; }
}


/// <summary>
/// The <c>NoticeRef</c> shape (clause 5.2.7.2): names an organization and identifies, by
/// <see cref="NoticeNumbers"/>, a group of textual statements prepared by that organization (CB-5.2.7-25).
/// </summary>
/// <remarks>
/// CDDL: <c>NoticeRef = { 1 =&gt; tstr, 2 =&gt; [+uint] }</c>. Table 6 assigns the map key values:
/// <c>org</c> (in <c>NoticeRef</c>) = <c>1</c>, <c>noticeNumbers</c> (in <c>NoticeRef</c>) = <c>2</c>.
/// <see cref="NoticeNumbers"/> should be non-empty (the CDDL <c>+</c> occurrence operator); mirroring
/// <see cref="CBAdESSignerCommitments"/>'s convention, that invariant is documented here rather than
/// runtime-enforced.
/// </remarks>
[DebuggerDisplay("CBAdESSignaturePolicyNoticeReference: {Organization}, {NoticeNumbers.Count} numbers")]
public sealed record CBAdESSignaturePolicyNoticeReference
{
    /// <summary>The <c>org</c> member's map key, within <c>NoticeRef</c> (Table 6, clause 5.2.7.2).</summary>
    public const int OrgKey = 1;

    /// <summary>The <c>noticeNumbers</c> member's map key, within <c>NoticeRef</c> (Table 6, clause 5.2.7.2).</summary>
    public const int NoticeNumbersKey = 2;

    /// <summary>Gets the <c>org</c> member (map key 1): the name of the organization (CB-5.2.7-21).</summary>
    public required string Organization { get; init; }

    /// <summary>
    /// Gets the <c>noticeNumbers</c> member (map key 2): the notice numbers identifying textual statements
    /// prepared by <see cref="Organization"/> (CB-5.2.7-22).
    /// </summary>
    public required IReadOnlyList<uint> NoticeNumbers { get; init; }
}


/// <summary>
/// The <c>spDSpec</c> qualifier (clause 5.2.7.2, map key 3, Table 6): identifies the technical specification
/// that defines the syntax used for producing the signature policy document (CB-5.2.7-26).
/// </summary>
/// <param name="Specification">
/// The identifying <c>oId</c> instance. CDDL: <c>SpDSpec = obId</c> — read as <c>oId</c> (clause 5.4.1,
/// <see cref="CBAdESObjectIdentifier"/>), the same spelling inconsistency the leg 2 preflight notes for this
/// clause: "almost certainly a typo for <c>oId</c> ... reproduced verbatim; treat as <c>oId</c> pending
/// confirmation."
/// </param>
[DebuggerDisplay("CBAdESSignaturePolicyDocumentSpecification: {Specification}")]
public sealed record CBAdESSignaturePolicyDocumentSpecification(CBAdESObjectIdentifier Specification)
    : CBAdESSignaturePolicyQualifier;


/// <summary>
/// The <c>otherQuals</c> extension point (clause 5.2.7.2, map key 4, Table 6; the CDDL's <c>*label =&gt;
/// value</c> catch-all — see the D3-adjacent tension noted on <see cref="CBAdESSignaturePolicyQualifier"/>):
/// a qualifier not specified in the present document (CB-5.2.7-27/28, NOTE 3).
/// </summary>
/// <param name="Label">
/// The catch-all key identifying this qualifier — the CDDL's <c>label</c> rule, defined once in clause 5.2.5
/// (<c>label = int / tstr</c>) and reused here per clause 5.2.7.2's own reminder comment ("label is defined
/// in clause 5.2.5").
/// </param>
/// <param name="Value">
/// The qualifier's value — the CDDL's <c>value = any</c>, carried opaque (boxed), matching the convention
/// <see cref="CBAdESCommitment.CommitmentQualifiers"/> already uses for open-ended <c>[+any]</c> content; a
/// caller that needs a specific value type down-casts.
/// </param>
[DebuggerDisplay("CBAdESSignaturePolicyOtherQualifier: {Label}")]
public sealed record CBAdESSignaturePolicyOtherQualifier(CBAdESSignaturePolicyQualifierLabel Label, object Value)
    : CBAdESSignaturePolicyQualifier;


/// <summary>
/// The <c>label</c> CDDL rule (clause 5.2.5: <c>label = int / tstr</c>), reused by
/// <see cref="CBAdESSignaturePolicyOtherQualifier.Label"/> per clause 5.2.7.2's own reminder comment. A
/// DU-ready closed sum over the two CDDL choice arms: no external type may derive from it.
/// </summary>
public abstract record CBAdESSignaturePolicyQualifierLabel
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESSignaturePolicyQualifierLabel()
    {
    }
}


/// <summary>The <c>int</c> arm of the <c>label</c> CDDL rule (clause 5.2.5).</summary>
/// <param name="Value">The integer label.</param>
[DebuggerDisplay("CBAdESSignaturePolicyQualifierIntegerLabel: {Value}")]
public sealed record CBAdESSignaturePolicyQualifierIntegerLabel(int Value) : CBAdESSignaturePolicyQualifierLabel;


/// <summary>The <c>tstr</c> arm of the <c>label</c> CDDL rule (clause 5.2.5).</summary>
/// <param name="Value">The text label.</param>
[DebuggerDisplay("CBAdESSignaturePolicyQualifierTextLabel: {Value}")]
public sealed record CBAdESSignaturePolicyQualifierTextLabel(string Value) : CBAdESSignaturePolicyQualifierLabel;
