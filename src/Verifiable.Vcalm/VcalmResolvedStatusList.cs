using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Core.StatusList;

namespace Verifiable.Vcalm;

/// <summary>
/// A resolved, proof-verified, and decoded W3C Bitstring Status List the
/// <see cref="ResolveVcalmStatusListDelegate"/> returns for a credential's
/// <see cref="BitstringStatusListEntry"/>: the decoded bit array, the purpose(s) the list declares,
/// and the list credential's optional validity window. The VCALM 1.0 §3.3 verifier reads the
/// credential's status bit from this via
/// <see cref="BitstringStatusListValidation.GetStatus(BitstringStatusListEntry, StatusList, System.Collections.Generic.IReadOnlyCollection{string}, System.DateTimeOffset, System.DateTimeOffset?, System.DateTimeOffset?)"/>.
/// </summary>
/// <remarks>
/// The carried <see cref="StatusList"/> owns pooled memory: the verifier disposes it after reading
/// the bit. The application's resolver decodes it (via
/// <see cref="BitstringStatusListCodec.DecodeList"/>) and hands ownership across the seam — the same
/// ownership-transfer shape the resolver seams use elsewhere.
/// </remarks>
[DebuggerDisplay("VcalmResolvedStatusList Purposes={Purposes.Length}")]
public sealed record VcalmResolvedStatusList
{
    /// <summary>
    /// The decoded status list (most-significant-first), obtained from the status list credential's
    /// <c>encodedList</c> via <see cref="BitstringStatusListCodec.DecodeList"/>. The verifier owns
    /// and disposes it after reading the bit.
    /// </summary>
    public required StatusList StatusList { get; init; }

    /// <summary>
    /// The <c>statusPurpose</c> value(s) the status list credential declares (a single list MAY
    /// carry multiple purposes). The §3.2 purpose check requires the credential entry's purpose to
    /// be one of these.
    /// </summary>
    public required ImmutableArray<string> Purposes { get; init; }

    /// <summary>The status list credential's <c>validFrom</c>, when present (the §3.2 validity-window check).</summary>
    public DateTimeOffset? ValidFrom { get; init; }

    /// <summary>The status list credential's <c>validUntil</c>, when present (the §3.2 validity-window check).</summary>
    public DateTimeOffset? ValidUntil { get; init; }
}
