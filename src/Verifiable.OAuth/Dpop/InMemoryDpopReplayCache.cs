using System.Collections.Concurrent;
using System.Diagnostics;
using Verifiable.Core;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// In-process default backing for a resource server's <see cref="ConsultDpopProofJtiDelegate"/>: claims the first use of
/// a DPoP proof's <c>jti</c> in the context of the target URI it was presented at, in one atomic operation, and retains the
/// record only until the instant the caller claimed it until, per
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "In the context of the target
/// URI, servers can store the jti value of each DPoP proof for the time window in which the respective DPoP proof JWT
/// would be accepted to prevent multiple uses of the same DPoP proof." An expired record counts as no record and is
/// evicted rather than kept forever, so the tracked set stays bounded by the number of proofs currently inside their
/// window rather than growing for the lifetime of the process.
/// </summary>
/// <remarks>
/// <para>
/// Single-instance resource servers use this default directly, wiring <see cref="ConsultAsync"/> onto
/// <see cref="Verifiable.OAuth.ResourceServerIntegration.ConsultDpopProofJtiAsync"/>, the same method-group wiring
/// <see cref="InMemoryDpopNonceCache"/> uses for the client-side nonce slot. Distributed resource servers (multiple
/// instances behind a load balancer, or restart-durability requirements) need a shared, persistent store with an atomic
/// claim instead, wired through that slot in place of this one; this type is scoped to a single process's in-memory state
/// and is lost across restarts or across nodes.
/// </para>
/// <para>
/// A record is keyed by the target URI in the one normalized form the library compares a proof's <c>htu</c> in, stated
/// once at <see cref="ConsultDpopProofJtiDelegate"/>, and the <c>jti</c>, both compared ordinally, so every spelling of
/// one target URI names one record whoever calls <see cref="ConsultAsync"/> and however it spells the target. The form
/// normalized again is itself, so a target handed in the form keys the record the same target handed in any other
/// spelling keys. One <c>jti</c> presented at two target URIs is two records, as two proofs for two URIs are two proofs.
/// </para>
/// </remarks>
[DebuggerDisplay("InMemoryDpopReplayCache Count={Entries.Count}")]
public sealed class InMemoryDpopReplayCache
{
    /// <summary>The live and not yet swept records, each the pair of a target URI and a <c>jti</c> mapped to the instant it is kept until.</summary>
    private ConcurrentDictionary<(string TargetUri, string Jti), DateTimeOffset> Entries { get; } = new();

    /// <summary>The clock a record's instant is compared with.</summary>
    private TimeProvider TimeProvider { get; }

    /// <summary>The number of records currently retained, including any not yet swept past their instant.</summary>
    public int Count => Entries.Count;


    /// <summary>
    /// Creates a cache that measures freshness against <paramref name="timeProvider"/> — the same
    /// instance the resource server uses to compute the instant passed to <see cref="ConsultAsync"/>,
    /// so the two agree on "now".
    /// </summary>
    /// <param name="timeProvider">The time source for expiry checks.</param>
    public InMemoryDpopReplayCache(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        TimeProvider = timeProvider;
    }


    /// <summary>
    /// The <see cref="ConsultDpopProofJtiDelegate"/> implementation: claims the pair (<paramref name="targetUri"/> in its
    /// normalized form, <paramref name="jti"/>) atomically. With no record of the pair, or a record whose instant has
    /// passed, it records the pair until <paramref name="recordUntil"/>, sweeps every other record whose instant has passed
    /// and answers <see cref="JtiReplayOutcome.FirstUse"/>; with a live record it answers
    /// <see cref="JtiReplayOutcome.Replayed"/> and leaves the record as it is. Of concurrent claims of one pair whose
    /// <paramref name="recordUntil"/> lies after the clock, exactly one answers <see cref="JtiReplayOutcome.FirstUse"/>:
    /// the insertion and the replacement of an expired record are each one compare-and-set of the dictionary. A
    /// <paramref name="recordUntil"/> at or before the clock records a pair that already counts as none, so a later claim
    /// of it is a first use again; <see cref="ProtectedResource.DpopResourceAccess.DecideAsync"/> always passes an
    /// instant after the clock.
    /// </summary>
    /// <param name="jti">The DPoP proof's <c>jti</c>.</param>
    /// <param name="targetUri">
    /// The target URI the proof was presented at, keyed in the normalized form <see cref="ConsultDpopProofJtiDelegate"/>
    /// states.
    /// </param>
    /// <param name="recordUntil">The instant from which the record does not count.</param>
    /// <param name="context">The request context; unused by this in-memory default.</param>
    /// <param name="cancellationToken">Cancellation token; unused, the claim is synchronous.</param>
    /// <returns><see cref="JtiReplayOutcome.FirstUse"/> for a first use, <see cref="JtiReplayOutcome.Replayed"/> for a replay.</returns>
    public ValueTask<JtiReplayOutcome> ConsultAsync(
        string jti, Uri targetUri, DateTimeOffset recordUntil, ExchangeContext context, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(jti);
        ArgumentNullException.ThrowIfNull(targetUri);

        (string TargetUri, string Jti) key = (DpopProofValidator.NormalizeTargetUri(targetUri.OriginalString), jti);
        DateTimeOffset now = TimeProvider.GetUtcNow();
        while(true)
        {
            if(Entries.TryAdd(key, recordUntil))
            {
                EvictExpired(now);

                return ValueTask.FromResult(JtiReplayOutcome.FirstUse);
            }

            if(Entries.TryGetValue(key, out DateTimeOffset recordedUntil))
            {
                if(recordedUntil > now)
                {
                    return ValueTask.FromResult(JtiReplayOutcome.Replayed);
                }

                //Past its window the record counts as none: the claim replaces it only if no concurrent claim
                //replaced it first.
                if(Entries.TryUpdate(key, recordUntil, recordedUntil))
                {
                    EvictExpired(now);

                    return ValueTask.FromResult(JtiReplayOutcome.FirstUse);
                }
            }
        }
    }


    /// <summary>
    /// Removes every record whose instant has passed at <paramref name="now"/>, so the cache's size tracks the number of
    /// proofs currently inside their window even when a pair, once claimed, is never presented again.
    /// </summary>
    /// <param name="now">The instant the claim was made at.</param>
    private void EvictExpired(DateTimeOffset now)
    {
        foreach(KeyValuePair<(string TargetUri, string Jti), DateTimeOffset> entry in Entries)
        {
            if(entry.Value <= now)
            {
                _ = Entries.TryRemove(entry);
            }
        }
    }
}
