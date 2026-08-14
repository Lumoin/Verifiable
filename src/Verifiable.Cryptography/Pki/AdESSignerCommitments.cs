using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The signed header parameter carrying the commitments a signer makes when signing: CB-AdES's <c>srCms</c>
/// (label 262, clause 5.2.1 Table 1) of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 5.2.3, and JAdES's <c>srCms</c> of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>, clause 5.2.3 (JA-5.2.3-01/-02). Both are a non-empty, ordered collection of
/// commitments.
/// </summary>
/// <remarks>
/// <para>
/// CB-AdES CDDL (clause 5.2.3): <c>srCms = [+SrCm]</c> — the CDDL <c>+</c> occurrence operator requires at least
/// one entry ("Each element of the <c>srCms</c> CBOR array shall indicate one commitment made by the signer,
/// which may be further qualified"). JAdES's JSON Schema states the same requirement (JA-5.2.3-01/-02, "srCms
/// shall indicate at least one commitment made by the signer"). Both specifications back the non-empty invariant
/// with explicit normative text, so this type enforces it at construction rather than merely documenting it —
/// JAdES's own source type already validated it this way; CB-AdES's did not, deferring to its codec/builder
/// layer, but clause 5.2.3's wording is equally an enforceable "at least one" requirement.
/// </para>
/// <para>
/// <c>srCms</c> is a payload-qualifying header parameter in both families (CB-AdES clause 5.2.3, "The
/// <c>srCms</c> header parameter shall be a signed header parameter that qualifies the COSE Payload"; JAdES
/// JA-5.2.3-01, qualifying the JWS Payload) and is carried in the protected/signed headers (CB-AdES clause 5.2.3;
/// JAdES JA-5.2.3-04). Placing it there is the signature builder's responsibility — this type models only the
/// parameter's own content.
/// </para>
/// <para>
/// Well-known commitment-type URIs are registered in Annex B of ETSI TS 119 172-1 [i.7] and reproduced in Annex C
/// of TS 119 152-1 (clause 5.2.3 NOTE 2) and referenced identically by JAdES clause 5.2.3 NOTE 2;
/// <see cref="AdESCommitment.CommitmentId"/> accepts any identifier, well-known or not — the value space is an
/// open registry, not a closed enum.
/// </para>
/// </remarks>
[DebuggerDisplay("AdESSignerCommitments: {Commitments.Count} commitments")]
public sealed record AdESSignerCommitments
{
    /// <summary>
    /// Initializes a new <see cref="AdESSignerCommitments"/>.
    /// </summary>
    /// <param name="commitments">The commitments, in wire order — see <see cref="Commitments"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="commitments"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="commitments"/> is empty.</exception>
    public AdESSignerCommitments(IReadOnlyList<AdESCommitment> commitments)
    {
        ArgumentNullException.ThrowIfNull(commitments);
        if(commitments.Count == 0)
        {
            throw new ArgumentException(
                "srCms shall indicate at least one commitment made by the signer (ETSI TS 119 152-1 V1.1.1, "
                + "clause 5.2.3; ETSI TS 119 182-1 V1.2.1, clause 5.2.3, JA-5.2.3-01/-02).",
                nameof(commitments));
        }

        Commitments = commitments;
    }


    /// <summary>Gets the commitments, in wire order. Non-empty (constructor-enforced).</summary>
    public IReadOnlyList<AdESCommitment> Commitments { get; init; }
}


/// <summary>
/// One entry within <see cref="AdESSignerCommitments"/>: CB-AdES's <c>SrCm</c> (clause 5.2.3) or JAdES's
/// <c>srCms</c> array element (clause 5.2.3, JA-5.2.3-06) — the commitment identifier plus optional qualifiers.
/// </summary>
/// <remarks>
/// <para>CB-AdES CDDL (clause 5.2.3): <c>SrCm = { 1 =&gt; oId, ?2 =&gt; [+any] }</c>. JAdES JSON Schema (clause 5.2.3,
/// Annex B.1):</para>
/// <code>
/// {
///   "type": "object",
///   "properties": {
///     "commId": {"$ref": "#/definitions/oId"},
///     "commQuals": {"type": "array", "items": {}, "minItems": 1}
///   },
///   "required": ["commId"],
///   "additionalProperties": false
/// }
/// </code>
/// <para>
/// <see cref="CommitmentId"/> is an instance of <see cref="AdESObjectIdentifier"/> (the <c>oId</c> type, clause
/// 5.4.1 both families); its <c>Id</c> member is a URI uniquely identifying the commitment made by the signer
/// (CB-AdES clause 5.2.3, "The <c>id</c> member of <c>oId</c> shall have a URI as value, uniquely identifying one
/// commitment made by the signer"; JAdES JA-5.2.3-07).
/// </para>
/// <para>
/// <see cref="CommitmentQualifiers"/> is an open extension point in both families — CB-AdES's CDDL <c>[+any]</c>
/// and JAdES's schema <c>"minItems": 1</c> array both require non-emptiness when present, enforced here by a
/// shared validating constructor: "Any specification defining a new commitment type that requires additional
/// qualifying information shall provide a full definition of the semantics and syntax of that qualifying
/// information" (clause 5.2.3, both specifications). This registry does not know that shape, so each qualifier is
/// carried as an opaque wire value (<see langword="object"/>), matching the convention
/// <c>CoseSign1Message.UnprotectedHeader</c> already uses for open-ended header content; a caller that needs a
/// specific qualifier type down-casts.
/// </para>
/// </remarks>
[DebuggerDisplay("AdESCommitment: {CommitmentId}")]
public sealed record AdESCommitment
{
    /// <summary>
    /// Initializes a new <see cref="AdESCommitment"/>.
    /// </summary>
    /// <param name="commitmentId">The commitment identifier — the <c>commId</c> member.</param>
    /// <param name="commitmentQualifiers">
    /// The commitment qualifiers — the <c>commQuals</c> member, or <see langword="null"/> to omit it. When
    /// present, must be non-empty (CB-AdES CDDL <c>[+any]</c>; JAdES schema <c>"minItems": 1</c>).
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="commitmentId"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="commitmentQualifiers"/> is non-null but empty.</exception>
    public AdESCommitment(AdESObjectIdentifier commitmentId, IReadOnlyList<object>? commitmentQualifiers = null)
    {
        ArgumentNullException.ThrowIfNull(commitmentId);

        if(commitmentQualifiers is not null && commitmentQualifiers.Count == 0)
        {
            throw new ArgumentException(
                "When present, 'commQuals' shall be a non-empty array (ETSI TS 119 152-1 V1.1.1, clause 5.2.3, "
                + "CDDL '[+any]'; ETSI TS 119 182-1 V1.2.1, clause 5.2.3, Annex B.1 schema 'minItems: 1').",
                nameof(commitmentQualifiers));
        }

        CommitmentId = commitmentId;
        CommitmentQualifiers = commitmentQualifiers;
    }


    /// <summary>Gets the commitment identifier — the <c>commId</c> member.</summary>
    public AdESObjectIdentifier CommitmentId { get; }

    /// <summary>
    /// Gets the commitment qualifiers — the <c>commQuals</c> member, or <see langword="null"/> when absent.
    /// Non-empty when present (constructor-enforced); the qualifier's own syntax is defined by whichever
    /// specification registers the commitment type carried in <see cref="CommitmentId"/>, not by this document.
    /// </summary>
    public IReadOnlyList<object>? CommitmentQualifiers { get; }
}
