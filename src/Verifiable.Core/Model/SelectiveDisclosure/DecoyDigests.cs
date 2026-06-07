using System;
using System.Collections.Generic;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Augments the per-location digest map produced during redaction with decoy digests.
/// </summary>
/// <remarks>
/// <para>
/// Format-agnostic, shared by the SD-JWT and SD-CWT redaction pipelines. The redactor first walks
/// the credential and collects the real disclosure digests grouped by parent
/// <see cref="CredentialPath"/>; this class then appends decoy digests at each of those locations
/// before <see cref="DigestPlacement.PlaceDigests"/> emits the <c>_sd</c> arrays.
/// </para>
/// <para>
/// Decoys are appended, not interleaved here, because <see cref="DigestPlacement.PlaceDigests"/>
/// sorts each <c>_sd</c> array ordinally per
/// <see href="https://www.rfc-editor.org/rfc/rfc9901.html#section-4.2.4.1">RFC 9901 §4.2.4.1</see>;
/// the sort places decoys among the real digests by hash value, so their position carries no signal.
/// </para>
/// </remarks>
public static class DecoyDigests
{
    /// <summary>
    /// Appends decoy digests to each existing <c>_sd</c> location in <paramref name="digestsByParent"/>.
    /// </summary>
    /// <param name="digestsByParent">
    /// The per-parent digest lists collected during redaction. Modified in place: each list grows by
    /// the number of decoys drawn for its location. Locations with no real disclosures are not present
    /// in this map and therefore receive no decoys — decoys only pad objects that already have an
    /// <c>_sd</c> array, so they never reveal selective disclosure on an object that otherwise had none.
    /// </param>
    /// <param name="decoyCount">
    /// Policy returning how many decoys to add; invoked once per location. See <see cref="DecoyDigestPolicy"/>.
    /// </param>
    /// <param name="makeDecoyDigest">
    /// Format-specific factory that produces one decoy digest — the same digest function used for real
    /// disclosures, computed over cryptographically-random bytes. Invoked once per decoy. The digest
    /// element type matches the format: a Base64Url <see cref="string"/> for SD-JWT, raw <c>byte[]</c>
    /// for SD-CWT.
    /// </param>
    /// <param name="state">
    /// The per-call data from <see cref="DecoyDigestOptions.State"/>, surfaced unchanged on each
    /// <see cref="DecoyDigestContext.State"/> so the policy can read it.
    /// </param>
    /// <typeparam name="TDigest">The format's digest element type (<see cref="string"/> for SD-JWT, <c>byte[]</c> for SD-CWT).</typeparam>
    public static void Augment<TDigest>(
        IReadOnlyDictionary<CredentialPath, List<TDigest>> digestsByParent,
        DecoyDigestCountDelegate decoyCount,
        object? state,
        Func<TDigest> makeDecoyDigest)
    {
        ArgumentNullException.ThrowIfNull(digestsByParent);
        ArgumentNullException.ThrowIfNull(decoyCount);
        ArgumentNullException.ThrowIfNull(makeDecoyDigest);

        foreach(KeyValuePair<CredentialPath, List<TDigest>> entry in digestsByParent)
        {
            List<TDigest> digests = entry.Value;

            //RealDisclosureCount is read before any decoys are appended, so the policy sees the count
            //an adversarial verifier would otherwise observe at this location.
            var context = new DecoyDigestContext(entry.Key, digests.Count, state);
            int count = decoyCount(context);
            for(int i = 0; i < count; i++)
            {
                digests.Add(makeDecoyDigest());
            }
        }
    }
}
