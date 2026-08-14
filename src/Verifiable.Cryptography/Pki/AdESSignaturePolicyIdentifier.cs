using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>sigPId</c> signature policy identifier signed/signature-qualifying header parameter, common to
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 5.2.7.1 (CB-5.2.7-*) and
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>, clause 5.2.7.1 (JA-5.2.7.1-*): either an explicit identifier of a signature
/// policy document, by digest plus optional qualifiers, or an indication of an implied signature policy the
/// relying party should be aware of.
/// </summary>
/// <remarks>
/// <para>
/// CB-AdES CDDL (clause 5.2.7.1, Table 5 map keys <c>id</c>=1, <c>digAlgVal</c>=2, <c>digPSp</c>=3,
/// <c>sigPQuals</c>=4):
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
/// <strong>Read as corrected.</strong> Table 5's own printed row for key <c>4</c> reads
/// "<c>sigPQuals(in CertifiedAttrChoice)</c>" — <c>CertifiedAttrChoice</c> is a <c>srAts</c> type (clause
/// 5.2.5, see <see cref="AdESCertifiedAttribute"/>), not a member of <c>sigPId</c>; this is a
/// spec-original copy/paste defect — Table 5 mislabels its last row: <c>sigPQuals</c> is actually a member of
/// <c>sigPId</c> (clause 5.2.7.1), not of <c>CertifiedAttrChoice</c>. Read as corrected: <c>sigPQuals</c>
/// belongs to <c>sigPId</c>, exactly as the CDDL above already states.
/// </para>
/// <para>
/// JAdES JSON Schema (clause 5.2.7.1, Annex B.1):
/// </para>
/// <code>
/// "sigPId": {
///   "type": "object",
///   "properties": {
///     "id": {"$ref": "#/definitions/oId"},
///     "digAlg": {"type": "string"},
///     "digVal": {"type": "string", "contentEncoding": "base64"},
///     "digPSp": {"type": "boolean"},
///     "sigPQuals": {"type": "array", "items": {"$ref": "#/definitions/sigPQual"}, "minItems": 1}
///   },
///   "required": ["id"],
///   "additionalProperties": false
/// }
/// </code>
/// <para>
/// <strong>Digest presence coupling is per-format, not enforced by this type.</strong> CB-AdES's
/// <c>digAlgVal</c> is a single two-element CDDL array — <see cref="HashAlgorithm"/> and <see cref="Digest"/>
/// are present or absent as a unit on that wire, a pairing the CBOR codec enforces (refusing one without the
/// other) rather than this constructor. JAdES flattens the digest into two independent JSON members
/// (<c>digAlg</c>/<c>digVal</c>); clause 5.2.7.1's own text states what they contain when present
/// (JA-5.2.7.1-07) and notes their presence is "use-case or policy dependent", but neither the schema (no
/// <c>dependentRequired</c>) nor the prose states a presence coupling, so on that wire the two members stay
/// independently optional. <see cref="HashAlgorithm"/> and <see cref="Digest"/> are therefore both nullable
/// here, matching the union of what both wires allow; each format's codec is where the format-specific
/// coupling (or lack of it) is enforced. Whether a <see cref="HashAlgorithm"/>-without-<see cref="Digest"/> (or
/// the reverse) shape should itself be flagged for JAdES in practice — despite the specification stating no
/// such coupling — is a forward note for a future validation rule, not a
/// constructor invariant this type adds unasked.
/// </para>
/// <para>
/// <see cref="HashAlgorithm"/> models <see cref="AdESDigestAlgorithmIdentifier"/>'s CDDL-shaped <c>int / tstr</c>
/// union: CB-AdES rides either arm per its identifier-registry prose (clause 5.2.7.1, "the digest-algorithm
/// identifiers registered in the IANA COSE Algorithms registry, or one defined in IETF RFC 9053 [4]"), while
/// JAdES's <c>digAlg</c> is always textual and is carried on the text arm.
/// </para>
/// <para>
/// <c>sigPId</c>/<c>digAlgVal.hashValue</c>/<c>digVal</c> place the digest of the signature policy document in
/// <see cref="Digest"/> — never a naked <c>byte[]</c>.
/// </para>
/// <para>
/// <c>sigPId</c> is a signature-qualifying header parameter and, in CB-AdES's <c>COSE_Sign</c> structure, is
/// placed at the signer layer (CB-5.2.7-14); in JAdES it is carried in the JWS Protected Header
/// (JA-5.2.7.1-03). Placing it there is the signature builder's responsibility, not this type's.
/// </para>
/// <para>
/// <strong>Cross-field invariant (CB-5.2.7-12, JA-5.2.7.1-11/-12).</strong> "If <c>digPSp</c> is present and
/// <c>true</c> (resp. \"true\"), then the <c>spDSpec</c> qualifier shall be present and shall identify the
/// technical specification." Unlike the simple "at least one of several optional members" presence rules
/// elsewhere in this library (e.g. <see cref="AdESSignatureProductionPlace"/>), this rule spans two independently
/// -supplied constructor parameters of a type that already requires a constructor for <see cref="Digest"/>'s
/// ownership transfer; it is therefore enforced here, at construction, throwing <see cref="ArgumentException"/>
/// — trusted caller input, not wire parsing, so a hard failure at the point of misuse is preferable to a
/// silently policy-non-compliant instance reaching a signature. Both specs state the constraint identically.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns <see cref="Digest"/> when supplied; disposing this instance
/// disposes it.
/// </para>
/// </remarks>
[DebuggerDisplay("AdESSignaturePolicyIdentifier: HashAlgorithm={HashAlgorithm}, DigestIsPerSpecification={DigestIsPerSpecification}")]
public sealed class AdESSignaturePolicyIdentifier: IDisposable
{
    /// <summary>
    /// Initializes a new <see cref="AdESSignaturePolicyIdentifier"/>. Ownership of <paramref name="digest"/>,
    /// when supplied, transfers to this instance.
    /// </summary>
    /// <param name="id">The <c>id</c> member uniquely identifying a specific version of the signature policy.</param>
    /// <param name="hashAlgorithm">The <c>digAlgVal.hashAlg</c>/<c>digAlg</c> element, or <see langword="null"/> to omit it — see the type remarks on per-format presence coupling.</param>
    /// <param name="digest">The <c>digAlgVal.hashValue</c>/<c>digVal</c> element — the digest of the signature policy document, or <see langword="null"/> to omit it.</param>
    /// <param name="digestIsPerSpecification">
    /// The <c>digPSp</c> member: <see langword="true"/> when the digest was computed as specified in a
    /// technical specification. Absence on the wire is equivalent to <see langword="false"/>
    /// (CB-5.2.7-11, JA-5.2.7.1-10), which this parameter's default reproduces.
    /// </param>
    /// <param name="qualifiers">
    /// The <c>sigPQuals</c> member, or <see langword="null"/> to omit it. When present, must be non-empty
    /// (CB-5.2.7-13, JA-5.2.7.1-13).
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="id"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="qualifiers"/> is non-null but empty; or <paramref name="digestIsPerSpecification"/> is
    /// <see langword="true"/> and <paramref name="qualifiers"/> carries no
    /// <see cref="AdESSignaturePolicyDocumentSpecification"/> entry (CB-5.2.7-12, JA-5.2.7.1-11/-12).
    /// </exception>
    public AdESSignaturePolicyIdentifier(
        AdESObjectIdentifier id,
        AdESDigestAlgorithmIdentifier? hashAlgorithm = null,
        DigestValue? digest = null,
        bool digestIsPerSpecification = false,
        IReadOnlyList<AdESSignaturePolicyQualifier>? qualifiers = null)
    {
        ArgumentNullException.ThrowIfNull(id);

        if(qualifiers is not null && qualifiers.Count == 0)
        {
            throw new ArgumentException(
                "When present, 'sigPQuals' shall be a non-empty array (ETSI TS 119 152-1 V1.1.1, clause " +
                "5.2.7.1, CB-5.2.7-13; ETSI TS 119 182-1 V1.2.1, clause 5.2.7.1, JA-5.2.7.1-13).",
                nameof(qualifiers));
        }

        if(digestIsPerSpecification && !HasDocumentSpecification(qualifiers))
        {
            throw new ArgumentException(
                "When 'digPSp' is true, an 'spDSpec' qualifier identifying the technical specification shall " +
                "be present in 'sigPQuals' (ETSI TS 119 152-1 V1.1.1, clause 5.2.7.1, CB-5.2.7-12; ETSI TS " +
                "119 182-1 V1.2.1, clause 5.2.7.1, JA-5.2.7.1-11/-12).",
                nameof(qualifiers));
        }

        Id = id;
        HashAlgorithm = hashAlgorithm;
        Digest = digest;
        DigestIsPerSpecification = digestIsPerSpecification;
        Qualifiers = qualifiers;

        static bool HasDocumentSpecification(IReadOnlyList<AdESSignaturePolicyQualifier>? candidates)
        {
            if(candidates is null)
            {
                return false;
            }

            for(int i = 0; i < candidates.Count; i++)
            {
                if(candidates[i] is AdESSignaturePolicyDocumentSpecification)
                {
                    return true;
                }
            }

            return false;
        }
    }


    /// <summary>Gets the <c>id</c> member identifying the signature policy.</summary>
    public AdESObjectIdentifier Id { get; }

    /// <summary>
    /// Gets the <c>digAlgVal.hashAlg</c>/<c>digAlg</c> element, or <see langword="null"/> when absent. See
    /// <see cref="AdESDigestAlgorithmIdentifier"/> for the value-domain the two formats each draw from.
    /// </summary>
    public AdESDigestAlgorithmIdentifier? HashAlgorithm { get; }

    /// <summary>
    /// Gets the <c>digAlgVal.hashValue</c>/<c>digVal</c> element — the digest of the signature policy document,
    /// or <see langword="null"/> when absent. Owned by this instance when present; disposed via
    /// <see cref="Dispose"/>.
    /// </summary>
    public DigestValue? Digest { get; }

    /// <summary>
    /// Gets the <c>digPSp</c> member: <see langword="true"/> when the digest was computed as specified in a
    /// technical specification (CB-5.2.7-10, JA-5.2.7.1-09). Defaults to <see langword="false"/>, matching the
    /// wire default for absence (CB-5.2.7-11, JA-5.2.7.1-10).
    /// </summary>
    public bool DigestIsPerSpecification { get; }

    /// <summary>
    /// Gets the <c>sigPQuals</c> member, or <see langword="null"/> when absent. Non-empty when present
    /// (enforced at construction — see the type remarks).
    /// </summary>
    public IReadOnlyList<AdESSignaturePolicyQualifier>? Qualifiers { get; }


    /// <summary>Disposes <see cref="Digest"/> when present.</summary>
    public void Dispose() => Digest?.Dispose();
}


/// <summary>
/// One element of <see cref="AdESSignaturePolicyIdentifier.Qualifiers"/> (CB-AdES <c>SigPQual</c>, clause
/// 5.2.7.2, CB-5.2.7-15..28; JAdES <c>sigPQual</c>, clause 5.2.7.2, JA-5.2.7.2-*): a closed sum over the three
/// qualifiers both formats name, plus a CB-AdES-only open escape. A DU-ready closed sum: no external type may
/// derive from it.
/// </summary>
/// <remarks>
/// <para>CB-AdES CDDL (clause 5.2.7.2):</para>
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
/// <c>4</c>. <strong>Ruled reading:</strong> on its surface this is in tension with the CDDL's
/// <c>*label =&gt; value</c> catch-all syntax, which denotes a variable-key group repeated zero or more times,
/// not one entry fixed at key <c>4</c>, and with CB-5.2.7-15/16/17/18's prose, which calls
/// <c>1</c>/<c>2</c>/<c>3</c> "choice tag[s]" and states "each signature-policy qualifier shall be a CBOR
/// tagged data item" — language suggesting CBOR major-type-6 tagging rather than the map keys Table 6
/// documents: the wire shape is one-entry MAPS keyed per Table 6 — the CDDL and Table 6's own "keys in
/// maps" title govern; the prose's "tagged data item" is loose drafting, the same character of imprecision as
/// the same CDDL block writing <c>#6.32</c> where a real CBOR tag is meant (the <c>spURI</c> arm above) while
/// <c>spUserNotice</c> and <c>spDSpec</c> carry no tag at all — "tagged" reads as the drafter's loose gloss for
/// "identified by its key", not a CBOR major-type-6 requirement. <c>otherQuals</c> flows through the
/// <c>*label =&gt; value</c> catch-all with the qualifier's own label as key, never a literal key <c>4</c>. The
/// CBOR codec applies this reading at the resolution site, mirroring how <see cref="CBAdESDetachedObjects"/> collapses
/// <c>sigD</c>'s positionally-coupled parallel arrays into one per-object model, leaving the CBOR projection to
/// the codec.
/// </para>
/// <para>JAdES JSON Schema (clause 5.2.7.2, Annex B.1):</para>
/// <code>
/// "sigPQual": {
///   "type": "object",
///   "properties": {
///     "spUserNotice": {"$ref": "#/definitions/spUserNotice"},
///     "spURI": {"$ref": "#/definitions/spURI"},
///     "spDSpec": {"$ref": "#/definitions/spDSpec"}
///   },
///   "minProperties": 1,
///   "maxProperties": 1
/// }
/// </code>
/// <para>
/// Unlike CB-AdES's <c>*label =&gt; value</c> catch-all (<c>otherQuals</c>), JAdES's <c>sigPQual</c> schema
/// enumerates exactly these three named properties with no open extension point — a JAdES <c>sigPQual</c> is
/// always exactly one of the three arms below, never a fourth, vendor-defined kind.
/// <see cref="AdESSignaturePolicyOtherQualifier"/> exists only because CB-AdES's CDDL states it; JAdES's JSON
/// codec neither emits nor accepts it.
/// </para>
/// </remarks>
public abstract class AdESSignaturePolicyQualifier
{
    /// <summary>Restricts direct subtyping to the sibling types declared in this file.</summary>
    private protected AdESSignaturePolicyQualifier()
    {
    }
}


/// <summary>
/// The <c>spURI</c> qualifier (CB-AdES clause 5.2.7.2, map key 1, Table 6, CB-5.2.7-19; JAdES clause 5.2.7.2,
/// JA-5.2.7.2-02): a URL where a copy of the signature policy document can be obtained.
/// </summary>
/// <remarks>
/// The qualifier is the location it states, so equality is an ordinal comparison of <see cref="Location"/> —
/// the same character-sequence discipline the property itself documents: two spellings that differ by escaping
/// or case name different locations and stay unequal.
/// </remarks>
[DebuggerDisplay("AdESSignaturePolicyUri: {Location}")]
public sealed class AdESSignaturePolicyUri : AdESSignaturePolicyQualifier, IEquatable<AdESSignaturePolicyUri>
{
    /// <summary>Initializes a new <see cref="AdESSignaturePolicyUri"/>.</summary>
    /// <param name="location">
    /// The URL, carried as an exact character sequence — not <see cref="Uri"/> (mirroring
    /// <see cref="CBAdESDetachedMechanisms"/>'s CA1056 justification: <see cref="System.Uri"/>
    /// normalizes on construction, and two spellings differing only by escaping or case would name different
    /// locations, which the "once assigned, never re-assigned" invariant treats as distinct). CB-AdES carries it as
    /// a CBOR tag-32 URI on the wire (<c>#6.32(tstr)</c>, matching <see cref="AdESObjectIdentifier.Id"/>'s
    /// convention for the same wire type); JAdES's wire schema is <c>{"type": "string", "format": "uri"}</c>. Which
    /// wire shape a given <see cref="AdESSignaturePolicyIdentifier"/> rides is a property of the containing
    /// signature's format, enforced by that format's codec.
    /// </param>
    public AdESSignaturePolicyUri(string location)
    {
        Location = location;
    }

    /// <summary>
    /// The URL, carried as an exact character sequence — not <see cref="Uri"/> (mirroring
    /// <see cref="CBAdESDetachedMechanisms"/>'s CA1056 justification: <see cref="System.Uri"/>
    /// normalizes on construction, and two spellings differing only by escaping or case would name different
    /// locations, which the "once assigned, never re-assigned" invariant treats as distinct). CB-AdES carries it as
    /// a CBOR tag-32 URI on the wire (<c>#6.32(tstr)</c>, matching <see cref="AdESObjectIdentifier.Id"/>'s
    /// convention for the same wire type); JAdES's wire schema is <c>{"type": "string", "format": "uri"}</c>. Which
    /// wire shape a given <see cref="AdESSignaturePolicyIdentifier"/> rides is a property of the containing
    /// signature's format, enforced by that format's codec.
    /// </summary>
    public string Location { get; }

    /// <inheritdoc/>
    public bool Equals(AdESSignaturePolicyUri? other)
    {
        return other is not null && string.Equals(Location, other.Location, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as AdESSignaturePolicyUri);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Location);
    }

    /// <summary>Reports whether two policy URIs name the same location.</summary>
    public static bool operator ==(AdESSignaturePolicyUri? left, AdESSignaturePolicyUri? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two policy URIs name different locations.</summary>
    public static bool operator !=(AdESSignaturePolicyUri? left, AdESSignaturePolicyUri? right)
    {
        return !(left == right);
    }
}


/// <summary>
/// The <c>spUserNotice</c> qualifier (CB-AdES clause 5.2.7.2, map key 2, Table 6, CB-5.2.7-20; JAdES clause
/// 5.2.7.2): information intended for display whenever the signature is validated.
/// </summary>
/// <remarks>
/// <para>
/// CB-AdES CDDL: <c>SpUserNotice = { ?1 =&gt; NoticeRef, ?2 =&gt; tstr }</c>. JAdES JSON Schema: <c>{"type":
/// "object", "properties": {"noticeRef": {...}, "explText": {"type": "string"}}, "minProperties": 1,
/// "additionalProperties": false}</c>.
/// </para>
/// <para>
/// At least one of <see cref="NoticeReference"/> and <see cref="ExplicitText"/> shall be present (CB-5.2.7-23;
/// JAdES schema <c>"minProperties": 1</c>) — both specs state the constraint, and the union type enforces it
/// here at construction, adopting JAdES's explicit constructor-validated shape (the J-side enforcement) over
/// CB-AdES's own documented-only convention for the same invariant.
/// </para>
/// </remarks>
[DebuggerDisplay("AdESSignaturePolicyUserNotice: NoticeReference={NoticeReference != null}, ExplicitText={ExplicitText != null}")]
public sealed class AdESSignaturePolicyUserNotice : AdESSignaturePolicyQualifier
{
    /// <summary>
    /// Initializes a new <see cref="AdESSignaturePolicyUserNotice"/>.
    /// </summary>
    /// <param name="noticeReference">The <c>noticeRef</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="explicitText">The <c>explText</c> member (JA-5.2.7.2's own "The explText member shall contain the text of the notice to be displayed"), or <see langword="null"/> to omit it.</param>
    /// <exception cref="ArgumentException">Both <paramref name="noticeReference"/> and <paramref name="explicitText"/> are <see langword="null"/>.</exception>
    public AdESSignaturePolicyUserNotice(AdESSignaturePolicyNoticeReference? noticeReference = null, string? explicitText = null)
    {
        if(noticeReference is null && explicitText is null)
        {
            throw new ArgumentException(
                "spUserNotice shall carry at least one of 'noticeRef'/'explText' (ETSI TS 119 152-1 V1.1.1, " +
                "clause 5.2.7.2, CB-5.2.7-23; ETSI TS 119 182-1 V1.2.1, clause 5.2.7.2, Annex B.1 schema " +
                "'minProperties: 1').");
        }

        NoticeReference = noticeReference;
        ExplicitText = explicitText;
    }


    /// <summary>
    /// Gets the <c>noticeRef</c> member: a pointer into an out-of-band, organization-maintained notices
    /// catalogue (CB-5.2.7-25, JA-5.2.7.2's own noticeRef sentence), or <see langword="null"/> when absent.
    /// </summary>
    public AdESSignaturePolicyNoticeReference? NoticeReference { get; }

    /// <summary>
    /// Gets the <c>explText</c> member: the text of the notice to display (CB-5.2.7-24), or
    /// <see langword="null"/> when absent.
    /// </summary>
    public string? ExplicitText { get; }
}


/// <summary>
/// The <c>NoticeRef</c>/<c>noticeRef</c> shape (CB-AdES clause 5.2.7.2, CB-5.2.7-21/-22, CB-5.2.7-25; JAdES
/// clause 5.2.7.2): names an organization and identifies, by <see cref="NoticeNumbers"/>, a group of textual
/// statements prepared by that organization.
/// </summary>
/// <remarks>
/// <para>
/// CB-AdES CDDL: <c>NoticeRef = { 1 =&gt; tstr, 2 =&gt; [+uint] }</c> (Table 6 keys: <c>org</c> = <c>1</c>,
/// <c>noticeNumbers</c> = <c>2</c>). JAdES JSON Schema: <c>{"type": "object", "properties": {"organization":
/// {"type": "string"}, "noticeNumbers": {"type": "array", "items": {"type": "integer"}, "minItems": 1}},
/// "required": ["organization", "noticeNumbers"], "additionalProperties": false}</c>.
/// </para>
/// <para>
/// Both members are required and <see cref="NoticeNumbers"/> is non-empty — both specs back this (CB-AdES's
/// CDDL <c>+</c> occurrence operator; JAdES's <c>"required"</c> plus <c>"minItems": 1</c>) and this type
/// enforces it at construction, adopting JAdES's explicit constructor-validated shape (the stricter,
/// runtime-enforced posture) over CB-AdES's own documented-only convention for the same invariant.
/// <see cref="NoticeNumbers"/> is typed <c>uint</c> per the CDDL's own <c>uint</c> element type; JAdES's JSON
/// Schema states the looser <c>integer</c>, whose non-negativity the JSON codec validates on decode before it
/// reaches this carrier.
/// </para>
/// </remarks>
[DebuggerDisplay("AdESSignaturePolicyNoticeReference: {Organization}, {NoticeNumbers.Count} numbers")]
public sealed class AdESSignaturePolicyNoticeReference
{
    /// <summary>
    /// Initializes a new <see cref="AdESSignaturePolicyNoticeReference"/>.
    /// </summary>
    /// <param name="organization">The <c>org</c>/<c>organization</c> member — the name of the organization.</param>
    /// <param name="noticeNumbers">The <c>noticeNumbers</c> member — the notice numbers identifying textual statements prepared by <paramref name="organization"/>. Must be non-empty.</param>
    /// <exception cref="ArgumentException"><paramref name="organization"/> is <see langword="null"/> or empty; or <paramref name="noticeNumbers"/> is empty.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="noticeNumbers"/> is <see langword="null"/>.</exception>
    public AdESSignaturePolicyNoticeReference(string organization, IReadOnlyList<uint> noticeNumbers)
    {
        ArgumentException.ThrowIfNullOrEmpty(organization);
        ArgumentNullException.ThrowIfNull(noticeNumbers);
        if(noticeNumbers.Count == 0)
        {
            throw new ArgumentException(
                "'noticeNumbers' shall be a non-empty array (ETSI TS 119 152-1 V1.1.1, clause 5.2.7.2, CDDL " +
                "'+uint'; ETSI TS 119 182-1 V1.2.1, clause 5.2.7.2, Annex B.1 schema 'minItems: 1').",
                nameof(noticeNumbers));
        }

        Organization = organization;
        NoticeNumbers = noticeNumbers;
    }


    /// <summary>Gets the <c>org</c>/<c>organization</c> member: the name of the organization.</summary>
    public string Organization { get; }

    /// <summary>
    /// Gets the <c>noticeNumbers</c> member: the notice numbers identifying textual statements prepared by
    /// <see cref="Organization"/>. Non-empty (constructor-enforced).
    /// </summary>
    public IReadOnlyList<uint> NoticeNumbers { get; }
}


/// <summary>
/// The <c>spDSpec</c> qualifier (CB-AdES clause 5.2.7.2, map key 3, Table 6, CB-5.2.7-26; JAdES clause 5.2.7.2,
/// JA-5.2.7.2-07): identifies the technical specification that defines the syntax used for producing the
/// signature policy document.
/// </summary>
/// <remarks>
/// Equality is <see cref="Specification"/>'s: this qualifier says nothing beyond which object identifier names
/// the syntax specification, and <see cref="AdESObjectIdentifier"/> already compares by value, so two arms
/// naming the same specification are interchangeable.
/// </remarks>
[DebuggerDisplay("AdESSignaturePolicyDocumentSpecification: {Specification}")]
public sealed class AdESSignaturePolicyDocumentSpecification : AdESSignaturePolicyQualifier, IEquatable<AdESSignaturePolicyDocumentSpecification>
{
    /// <summary>Initializes a new <see cref="AdESSignaturePolicyDocumentSpecification"/>.</summary>
    /// <param name="specification">
    /// The identifying object-identifier instance. CB-AdES CDDL: <c>SpDSpec = obId</c> — read as <c>oId</c>
    /// (clause 5.4.1, <see cref="AdESObjectIdentifier"/>): this library treats the CDDL spelling as a typo and
    /// reproduces it verbatim, treating it as <c>oId</c> pending confirmation.
    /// </param>
    public AdESSignaturePolicyDocumentSpecification(AdESObjectIdentifier specification)
    {
        Specification = specification;
    }

    /// <summary>
    /// The identifying object-identifier instance. CB-AdES CDDL: <c>SpDSpec = obId</c> — read as <c>oId</c>
    /// (clause 5.4.1, <see cref="AdESObjectIdentifier"/>): this library treats the CDDL spelling as a typo and
    /// reproduces it verbatim, treating it as <c>oId</c> pending confirmation.
    /// </summary>
    public AdESObjectIdentifier Specification { get; }

    /// <inheritdoc/>
    public bool Equals(AdESSignaturePolicyDocumentSpecification? other)
    {
        return other is not null && Specification == other.Specification;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as AdESSignaturePolicyDocumentSpecification);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Specification);
    }

    /// <summary>Reports whether two document specifications name the same syntax specification.</summary>
    public static bool operator ==(AdESSignaturePolicyDocumentSpecification? left, AdESSignaturePolicyDocumentSpecification? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two document specifications name different syntax specifications.</summary>
    public static bool operator !=(AdESSignaturePolicyDocumentSpecification? left, AdESSignaturePolicyDocumentSpecification? right)
    {
        return !(left == right);
    }
}


/// <summary>
/// The <c>otherQuals</c> extension point (CB-AdES clause 5.2.7.2, map key 4, Table 6; the CDDL's <c>*label =&gt;
/// value</c> catch-all — see the remarks on <see cref="AdESSignaturePolicyQualifier"/>): a qualifier not
/// specified in TS 119 152-1 (CB-5.2.7-27/28, NOTE 3).
/// </summary>
/// <remarks>
/// This arm exists only in CB-AdES's CDDL catch-all. JAdES's <c>sigPQual</c> JSON Schema is closed — exactly
/// one of three named properties, <c>maxProperties: 1</c>, no fourth arm — and its JSON codec neither emits nor
/// accepts an <see cref="AdESSignaturePolicyOtherQualifier"/>.
/// </remarks>
[DebuggerDisplay("AdESSignaturePolicyOtherQualifier: {Label}")]
public sealed class AdESSignaturePolicyOtherQualifier : AdESSignaturePolicyQualifier
{
    /// <summary>Initializes a new <see cref="AdESSignaturePolicyOtherQualifier"/>.</summary>
    /// <param name="label">
    /// The catch-all key identifying this qualifier — the CDDL's <c>label</c> rule, defined once in clause 5.2.5
    /// (<c>label = int / tstr</c>) and reused here per clause 5.2.7.2's own reminder comment ("label is defined
    /// in clause 5.2.5").
    /// </param>
    /// <param name="value">
    /// The qualifier's value — the CDDL's <c>value = any</c>, carried opaque (boxed), matching the convention
    /// <see cref="AdESCommitment.CommitmentQualifiers"/> already uses for open-ended <c>[+any]</c> content; a
    /// caller that needs a specific value type down-casts.
    /// </param>
    public AdESSignaturePolicyOtherQualifier(AdESSignaturePolicyQualifierLabel label, object value)
    {
        Label = label;
        Value = value;
    }

    /// <summary>
    /// The catch-all key identifying this qualifier — the CDDL's <c>label</c> rule, defined once in clause 5.2.5
    /// (<c>label = int / tstr</c>) and reused here per clause 5.2.7.2's own reminder comment ("label is defined
    /// in clause 5.2.5").
    /// </summary>
    public AdESSignaturePolicyQualifierLabel Label { get; }

    /// <summary>
    /// The qualifier's value — the CDDL's <c>value = any</c>, carried opaque (boxed), matching the convention
    /// <see cref="AdESCommitment.CommitmentQualifiers"/> already uses for open-ended <c>[+any]</c> content; a
    /// caller that needs a specific value type down-casts.
    /// </summary>
    public object Value { get; }
}


/// <summary>
/// The CB-AdES <c>label</c> CDDL rule (clause 5.2.5: <c>label = int / tstr</c>), reused by
/// <see cref="AdESSignaturePolicyOtherQualifier.Label"/> per clause 5.2.7.2's own reminder comment. A DU-ready
/// closed sum over the two CDDL choice arms: no external type may derive from it. Has no JAdES counterpart —
/// see <see cref="AdESSignaturePolicyOtherQualifier"/>.
/// </summary>
public abstract record AdESSignaturePolicyQualifierLabel
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected AdESSignaturePolicyQualifierLabel()
    {
    }
}


/// <summary>The <c>int</c> arm of the CB-AdES <c>label</c> CDDL rule (clause 5.2.5).</summary>
/// <param name="Value">The integer label.</param>
[DebuggerDisplay("AdESSignaturePolicyQualifierIntegerLabel: {Value}")]
public sealed record AdESSignaturePolicyQualifierIntegerLabel(int Value) : AdESSignaturePolicyQualifierLabel;


/// <summary>The <c>tstr</c> arm of the CB-AdES <c>label</c> CDDL rule (clause 5.2.5).</summary>
/// <param name="Value">The text label.</param>
[DebuggerDisplay("AdESSignaturePolicyQualifierTextLabel: {Value}")]
public sealed record AdESSignaturePolicyQualifierTextLabel(string Value) : AdESSignaturePolicyQualifierLabel;
