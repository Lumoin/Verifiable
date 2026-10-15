using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>srAts</c> (signer attributes) signed header parameter, common to
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.2.5</see> (CB-AdES) and
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 5.2.5</see> (JA-5.2.5-01/-02): attributes the signer claims, has certified
/// by an Attribute Authority, or has as third-party-signed assertions.
/// </summary>
/// <remarks>
/// <para>
/// CB-AdES CDDL (clause 5.2.5): <c>srAts = { ?1 =&gt; CertifiedAttrs, ?2 =&gt; AttrArrays, ?3 =&gt; AttrArrays
/// }</c> (Table 4 map keys — see <see cref="CBAdESWireKeys"/>). JAdES JSON Schema (clause 5.2.5, copied from
/// Annex B.1):
/// </para>
/// <code>
/// "srAts": {
///   "type": "object",
///   "properties": {
///     "certified": {"type": "array", "items": {"$ref": "#/definitions/certifiedAttrs"}, "minItems": 1},
///     "claimed": {"$ref": "#/definitions/qArrays"},
///     "signedAssertions": {"$ref": "#/definitions/qArrays"}
///   },
///   "minProperties": 1,
///   "additionalProperties": false
/// }
/// </code>
/// <para>
/// All three members are independently optional and, when present, non-empty (CB-5.2.5-05/-06/-07,
/// JA-5.2.5-05/-06/-07, constructor-enforced below — both specifications back this with explicit normative
/// text, using near-identical wording). Clause 5.2.5 also states "Empty <c>srAts</c> header parameters shall
/// not be generated" (CB-5.2.5-14, JA-5.2.5-18, the JAdES schema's <c>"minProperties": 1</c>) — at least one of
/// the three shall be non-empty; that wider cross-member invariant is documented here rather than
/// runtime-enforced — the codec/builder layer that produces <c>srAts</c> is that invariant's enforcement
/// point.
/// </para>
/// <para>
/// <c>srAts</c> is a signer-qualifying header parameter (CB-AdES clause 5.2.5, "The <c>srAts</c> header
/// parameter shall be a signed header parameter that qualifies the signer"; JAdES JA-5.2.5-01) and is carried
/// in the protected/signed headers (CB-AdES clause 5.2.5; JAdES JA-5.2.5-03). Placing it there is the
/// signature builder's responsibility — this type models only the parameter's own content.
/// </para>
/// <para>
/// <strong><see cref="Certified"/> is fully shared</strong> across both formats: CB-AdES's
/// <c>CertifiedAttrChoice</c> and JAdES's <c>certifiedAttrs</c> are the identical X.509-or-other two-arm union
/// over an <see cref="AdESPkiObject"/> — see <see cref="AdESCertifiedAttribute"/>.
/// </para>
/// <para>
/// <strong><see cref="SignedAssertions"/> and <see cref="Claimed"/> stay opaque</strong> (each element is
/// <see langword="object"/>, matching <see cref="AdESCommitment.CommitmentQualifiers"/>'s open-value
/// convention): CB-AdES's <c>NotCertifiedItem</c> CDDL is internally inconsistent with its own prose (see the
/// remarks on <see cref="CBAdESSignerAttributeNotCertifiedItem"/>), while JAdES's <c>qArrays</c> item
/// (<see cref="JAdESQualifyingAttribute"/>) is unambiguously specified with a required <c>encoding</c> member
/// CB-AdES's own text never names — two genuinely different item shapes (one a per-value raw-bytes-plus-kind
/// carrier, the other a decoded-value carrier with an explicit encoding) this type does not force into one; a
/// caller down-casts each element to the concrete type the format it is holding actually produces.
/// </para>
/// </remarks>
[DebuggerDisplay("AdESSignerAttributes: {Certified?.Count} certified, {SignedAssertions?.Count} signedAssertions, {Claimed?.Count} claimed")]
public sealed record AdESSignerAttributes
{
    /// <summary>
    /// Initializes a new <see cref="AdESSignerAttributes"/>.
    /// </summary>
    /// <param name="certified">
    /// The certified attributes (<c>certified</c>), or <see langword="null"/> to omit it. When present, must
    /// be non-empty (CB-5.2.5-05, JA-5.2.5-05).
    /// </param>
    /// <param name="signedAssertions">
    /// The third-party-signed assertions (<c>signedAssertions</c>), or <see langword="null"/> to omit it. When
    /// present, must be non-empty (CB-5.2.5-06, JA-5.2.5-06).
    /// </param>
    /// <param name="claimed">
    /// The signer-claimed attributes (<c>claimed</c>), or <see langword="null"/> to omit it. When present,
    /// must be non-empty (CB-5.2.5-07, JA-5.2.5-07).
    /// </param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="certified"/>, <paramref name="signedAssertions"/>, or
    /// <paramref name="claimed"/> is non-null but empty.
    /// </exception>
    public AdESSignerAttributes(
        IReadOnlyList<AdESCertifiedAttribute>? certified = null,
        IReadOnlyList<object>? signedAssertions = null,
        IReadOnlyList<object>? claimed = null)
    {
        if(certified is not null && certified.Count == 0)
        {
            throw new ArgumentException(
                "When present, srAts's 'certified' member shall be a non-empty array (ETSI TS 119 152-1 " +
                "V1.1.1, clause 5.2.5, CB-5.2.5-05; ETSI TS 119 182-1 V1.2.1, clause 5.2.5, JA-5.2.5-05).",
                nameof(certified));
        }

        if(signedAssertions is not null && signedAssertions.Count == 0)
        {
            throw new ArgumentException(
                "When present, srAts's 'signedAssertions' member shall be a non-empty array (ETSI TS 119 " +
                "152-1 V1.1.1, clause 5.2.5, CB-5.2.5-06; ETSI TS 119 182-1 V1.2.1, clause 5.2.5, " +
                "JA-5.2.5-06).",
                nameof(signedAssertions));
        }

        if(claimed is not null && claimed.Count == 0)
        {
            throw new ArgumentException(
                "When present, srAts's 'claimed' member shall be a non-empty array (ETSI TS 119 152-1 " +
                "V1.1.1, clause 5.2.5, CB-5.2.5-07; ETSI TS 119 182-1 V1.2.1, clause 5.2.5, JA-5.2.5-07).",
                nameof(claimed));
        }

        Certified = certified;
        SignedAssertions = signedAssertions;
        Claimed = claimed;
    }


    /// <summary>
    /// Gets the certified attributes (<c>certified</c>, clause 5.2.5): X.509 or other-syntax attribute
    /// certificates issued by an Attribute Authority. <see langword="null"/> when absent; non-empty when
    /// present (constructor-enforced, CB-5.2.5-05, JA-5.2.5-05).
    /// </summary>
    public IReadOnlyList<AdESCertifiedAttribute>? Certified { get; }

    /// <summary>
    /// Gets the third-party-signed assertions (<c>signedAssertions</c>, clause 5.2.5). <see langword="null"/>
    /// when absent; non-empty when present (constructor-enforced, CB-5.2.5-06, JA-5.2.5-06). Each element is a
    /// <see cref="CBAdESSignerAttributeNotCertifiedItem"/> (CB-AdES-produced) or a
    /// <see cref="JAdESQualifyingAttribute"/> (JAdES-produced) — see the type remarks for why the two item
    /// shapes stay distinct.
    /// </summary>
    public IReadOnlyList<object>? SignedAssertions { get; }

    /// <summary>
    /// Gets the signer-claimed attributes (<c>claimed</c>, clause 5.2.5) — neither certified by an Attribute
    /// Authority nor signed by any assertion-issuing entity, the lowest-trust tier of the three.
    /// <see langword="null"/> when absent; non-empty when present (constructor-enforced, CB-5.2.5-07,
    /// JA-5.2.5-07). See <see cref="SignedAssertions"/>'s remarks for each element's actual type.
    /// </summary>
    public IReadOnlyList<object>? Claimed { get; }
}


/// <summary>
/// One element of <see cref="AdESSignerAttributes.Certified"/> — CB-AdES's <c>CertifiedAttr</c> (clause 5.2.5,
/// Table 4) and JAdES's <c>certifiedAttrs</c> (clause 5.2.5, Annex B.1 schema) are the identical shape: a
/// two-arm discriminated union over whether the encapsulated attribute certificate is X.509 or another syntax.
/// A DU-ready closed sum: no external type may derive from it.
/// </summary>
/// <remarks>
/// <para>
/// CB-AdES CDDL: <c>CertifiedAttrChoice = ( 1 =&gt; pkiObj // 2 =&gt; pkiObj )</c>, wrapped in a one-member map
/// (<c>CertifiedAttr = { CertifiedAttrChoice }</c>). JAdES JSON Schema (clause 5.2.5, copied from Annex B.1):
/// </para>
/// <code>
/// "certifiedAttrs": {
///   "type": "object",
///   "properties": {
///     "x509AttrCert": {"$ref": "#/definitions/pkiOb"},
///     "otherAttrCert": {"$ref": "#/definitions/pkiOb"}
///   },
///   "oneOf": [{"required": ["x509AttrCert"]}, {"required": ["otherAttrCert"]}],
///   "additionalProperties": false
/// }
/// </code>
/// <para>
/// <see cref="CBAdESWireKeys"/> carries Table 4's CB-AdES map keys for this choice; <see cref="JAdESWireNames"/>
/// carries the JAdES JSON member names — per-format serialization facts kept beside this shared semantic type.
/// </para>
/// </remarks>
public abstract record AdESCertifiedAttribute
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected AdESCertifiedAttribute()
    {
    }
}


/// <summary>
/// The <c>x509AttrCert</c> arm (CB-AdES clause 5.2.5, Table 4 map key 1; JAdES clause 5.2.5, JA-5.2.5-05): a
/// DER-encoded X.509 attribute certificate (ITU-T X.509) encapsulated in an <see cref="AdESPkiObject"/>.
/// </summary>
/// <param name="Certificate">The encapsulated X.509 attribute certificate.</param>
[DebuggerDisplay("AdESX509AttributeCertificate: {Certificate}")]
public sealed record AdESX509AttributeCertificate(AdESPkiObject Certificate) : AdESCertifiedAttribute;


/// <summary>
/// The <c>otherAttrCert</c> arm (CB-AdES clause 5.2.5, Table 4 map key 2; JAdES clause 5.2.5, JA-5.2.5-05): an
/// attribute certificate in a non-X.509 syntax (definition out of this document's scope) encapsulated in an
/// <see cref="AdESPkiObject"/>.
/// </summary>
/// <param name="Certificate">The encapsulated non-X.509 attribute certificate.</param>
[DebuggerDisplay("AdESOtherAttributeCertificate: {Certificate}")]
public sealed record AdESOtherAttributeCertificate(AdESPkiObject Certificate) : AdESCertifiedAttribute;
