using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography;

/// <summary>
/// Detects reuse of values by checking each value's commitment against an application-owned store,
/// through the <see cref="IsCommitmentSeenDelegate"/> / <see cref="RecordCommitmentDelegate"/> seam.
/// </summary>
/// <remarks>
/// <para>
/// A general cryptographic-hygiene primitive: given commitments to values that are meant to be unique
/// (selective-disclosure salts per RFC 9901 §9.4, replay nonces, JTIs, …), it reports which were seen
/// before. The library holds no state across calls — detection is a stateless engine driven by two
/// application delegates that own the store. It depends only on <see cref="DigestValue"/> commitments,
/// so it knows nothing about salts, OID4VP, or any protocol; callers commit whatever they need (e.g.
/// via <see cref="Salt.ComputeCommitment"/>) and feed the commitments here.
/// </para>
/// <para>
/// The delegates are passed in per call (never captured by a closure), and the commitments are owned by
/// the caller, who created and disposes them; this engine only reads them.
/// </para>
/// </remarks>
public static class CommitmentReuseDetection
{
    /// <summary>
    /// Checks each commitment against the application store and records it, returning those that had
    /// been seen before.
    /// </summary>
    /// <param name="commitments">
    /// The commitments for one operation, in any order. Owned by the caller; this method only reads them.
    /// </param>
    /// <param name="isSeen">
    /// The lookup delegate. When <see langword="null"/>, reuse detection is disabled and the result is
    /// always empty — the same opt-in shape as the DPoP-JTI seam.
    /// </param>
    /// <param name="record">
    /// The persistence delegate. When <see langword="null"/>, commitments are checked but not recorded
    /// (detection without persistence). Recorded after the check so a duplicate appearing twice within
    /// <paramref name="commitments"/> is itself caught.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The commitments that were already present in the store (reuses), in encounter order; empty when
    /// none were reused or when <paramref name="isSeen"/> is <see langword="null"/>.
    /// </returns>
    public static async ValueTask<IReadOnlyList<DigestValue>> DetectAsync(
        IReadOnlyList<DigestValue> commitments,
        IsCommitmentSeenDelegate? isSeen,
        RecordCommitmentDelegate? record,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(commitments);

        if(isSeen is null)
        {
            return [];
        }

        List<DigestValue>? reused = null;
        foreach(DigestValue commitment in commitments)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if(await isSeen(commitment, cancellationToken).ConfigureAwait(false))
            {
                reused ??= [];
                reused.Add(commitment);
            }

            if(record is not null)
            {
                await record(commitment, cancellationToken).ConfigureAwait(false);
            }
        }

        return reused ?? (IReadOnlyList<DigestValue>)[];
    }
}
