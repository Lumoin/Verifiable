using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>srCms</c> (label 262, clause 5.2.1 Table 1) signed header parameter: a non-empty,
/// ordered collection of commitments the signer makes when signing, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 5.2.3.
/// </summary>
/// <remarks>
/// <para>
/// CDDL (clause 5.2.3): <c>srCms = [+SrCm]</c> — the CDDL <c>+</c> occurrence operator requires at least one
/// entry. Each entry of <see cref="Commitments"/> indicates one commitment made by the signer, independently and
/// optionally further qualified (clause 5.2.3, "Each element of the <c>srCms</c> CBOR array shall indicate one
/// commitment made by the signer, which may be further qualified"). Mirroring
/// <see cref="Verifiable.Cryptography.Pki.CAdESSignerAttributesV2.ClaimedAttributes"/>'s "at least one" convention, the
/// non-empty invariant is documented here rather than runtime-enforced by this record; the codec/builder layer
/// that produces <c>srCms</c> is the enforcement point (clause 5.2.3's own "Empty ... shall not be generated"
/// sibling rule appears on <c>srAts</c>, clause 5.2.5, and applies by the same reasoning here).
/// </para>
/// <para>
/// <c>srCms</c> is a payload-qualifying header parameter (clause 5.2.3, "The <c>srCms</c> header parameter shall
/// be a signed header parameter that qualifies the COSE Payload"). Placing it in the protected headers map at
/// the signer layer of a <c>COSE_Sign</c> structure (clause 5.2.3) is the signature builder's responsibility —
/// this type models only the parameter's own content.
/// </para>
/// <para>
/// Well-known commitment-type URIs are registered in Annex B of ETSI TS 119 172-1 [i.7] and reproduced in Annex
/// C of the present document (clause 5.2.3 NOTE 2); this record's <see cref="CBAdESCommitment.CommitmentId"/>
/// accepts any URI, well-known or not — the value space is an open registry, not a closed enum.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESSignerCommitments: {Commitments.Count} commitments")]
public sealed record CBAdESSignerCommitments
{
    /// <summary>
    /// Gets the commitments, in wire order. Should contain at least one entry — see the remarks on
    /// <see cref="CBAdESSignerCommitments"/> for the non-empty invariant's enforcement point.
    /// </summary>
    public required IReadOnlyList<CBAdESCommitment> Commitments { get; init; }
}


/// <summary>
/// One <c>SrCm</c> entry within <see cref="CBAdESSignerCommitments"/> (clause 5.2.3): the commitment identifier
/// plus optional qualifiers.
/// </summary>
/// <remarks>
/// <para>
/// CDDL (clause 5.2.3): <c>SrCm = { 1 =&gt; oId, ?2 =&gt; [+any] }</c>. Table 2 (clause 5.2.3) assigns the map key
/// values: <c>commId</c> = <c>1</c>, <c>commQuals</c> = <c>2</c>.
/// </para>
/// <para>
/// The <c>commId</c> member is an instance of <see cref="CBAdESObjectIdentifier"/> (the <c>oId</c> type, clause
/// 5.4.1); its <c>id</c> member is a URI uniquely identifying the commitment (clause 5.2.3, "The <c>id</c> member
/// of <c>oId</c> shall have a URI as value, uniquely identifying one commitment made by the signer").
/// </para>
/// <para>
/// <c>commQuals</c> is an open extension point (CDDL <c>[+any]</c>, non-empty when present — constructor-enforced
/// below): "Any specification defining a new commitment type that requires additional qualifying information
/// shall provide a full definition of the semantics and syntax of that qualifying information" (clause 5.2.3).
/// This registry does not know that shape, so each qualifier is carried as an opaque CBOR value
/// (<see langword="object"/>), matching the convention <c>CoseSign1Message.UnprotectedHeader</c> already uses
/// for open-ended header content; a caller that needs a specific qualifier type down-casts.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESCommitment: {CommitmentId}")]
public sealed record CBAdESCommitment
{
    /// <summary>The <c>commId</c> member's map key (Table 2, clause 5.2.3).</summary>
    public const int CommIdKey = 1;

    /// <summary>The <c>commQuals</c> member's map key (Table 2, clause 5.2.3).</summary>
    public const int CommQualsKey = 2;

    /// <summary>
    /// Initializes a new <see cref="CBAdESCommitment"/>.
    /// </summary>
    /// <param name="commitmentId">The commitment identifier — <c>SrCm</c>'s <c>commId</c> member (map key <c>1</c>).</param>
    /// <param name="commitmentQualifiers">
    /// The commitment qualifiers — <c>SrCm</c>'s <c>commQuals</c> member (map key <c>2</c>), or
    /// <see langword="null"/> to omit it. When present, must be non-empty (CDDL <c>[+any]</c>).
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="commitmentId"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="commitmentQualifiers"/> is non-null but empty.</exception>
    public CBAdESCommitment(CBAdESObjectIdentifier commitmentId, IReadOnlyList<object>? commitmentQualifiers = null)
    {
        ArgumentNullException.ThrowIfNull(commitmentId);

        if(commitmentQualifiers is not null && commitmentQualifiers.Count == 0)
        {
            throw new ArgumentException(
                "When present, SrCm's 'commQuals' member shall be a non-empty array (ETSI TS 119 152-1 V1.1.1, clause 5.2.3, CDDL '[+any]').",
                nameof(commitmentQualifiers));
        }

        CommitmentId = commitmentId;
        CommitmentQualifiers = commitmentQualifiers;
    }


    /// <summary>Gets the commitment identifier — <c>SrCm</c>'s <c>commId</c> member (map key <c>1</c>).</summary>
    public CBAdESObjectIdentifier CommitmentId { get; }

    /// <summary>
    /// Gets the commitment qualifiers — <c>SrCm</c>'s <c>commQuals</c> member (map key <c>2</c>), or
    /// <see langword="null"/> when absent. Non-empty when present (constructor-enforced); the qualifier's own
    /// syntax is defined by whichever specification registers the commitment type carried in
    /// <see cref="CommitmentId"/>, not by this document.
    /// </summary>
    public IReadOnlyList<object>? CommitmentQualifiers { get; }
}
