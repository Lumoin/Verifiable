using System.Collections.Concurrent;
using System.Diagnostics;
using Verifiable.Core;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// In-process default backing for a resource server's <see cref="IsDpopProofJtiSeenDelegate"/> and
/// <see cref="PersistDpopProofJtiDelegate"/>. Retains a DPoP proof <c>jti</c> only until the freshness
/// window the caller persisted it under has elapsed, per
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 §11.1</see>: an expired
/// entry is treated as unseen and is evicted rather than kept forever, so the tracked set stays bounded
/// by the number of proofs currently inside their freshness window rather than growing for the
/// lifetime of the process.
/// </summary>
/// <remarks>
/// <para>
/// Single-instance resource servers use this default directly, wiring <see cref="IsSeenAsync"/> and
/// <see cref="PersistAsync"/> onto
/// <see cref="Verifiable.OAuth.ResourceServerIntegration.IsDpopProofJtiSeenAsync"/> and
/// <see cref="Verifiable.OAuth.ResourceServerIntegration.PersistDpopProofJtiAsync"/> — the same
/// method-group wiring <see cref="InMemoryDpopNonceCache"/> uses for the client-side nonce slot.
/// Distributed resource servers (multiple instances behind a load balancer, or restart-durability
/// requirements) need a shared, persistent store instead — wire a different backing through those
/// delegate slots; this type is scoped to a single process's in-memory state and is lost across
/// restarts or across nodes.
/// </para>
/// </remarks>
[DebuggerDisplay("InMemoryDpopReplayCache Count={Entries.Count}")]
public sealed class InMemoryDpopReplayCache
{
    private ConcurrentDictionary<string, DateTimeOffset> Entries { get; } =
        new(StringComparer.Ordinal);

    private TimeProvider TimeProvider { get; }

    /// <summary>The number of <c>jti</c> entries currently retained, including any not yet swept past their expiry.</summary>
    public int Count => Entries.Count;


    /// <summary>
    /// Creates a cache that measures freshness against <paramref name="timeProvider"/> — the same
    /// instance the resource server uses to compute the <c>expiresAt</c> passed to
    /// <see cref="PersistAsync"/>, so the two agree on "now".
    /// </summary>
    /// <param name="timeProvider">The time source for expiry checks.</param>
    public InMemoryDpopReplayCache(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        TimeProvider = timeProvider;
    }


    /// <summary>
    /// The <see cref="IsDpopProofJtiSeenDelegate"/> implementation: <see langword="true"/> only when
    /// <paramref name="jti"/> was persisted and its recorded expiry has not yet passed. An entry found
    /// past its expiry is treated as not seen and is evicted here, closing the replay window instead of
    /// retaining the entry indefinitely.
    /// </summary>
    /// <param name="jti">The DPoP proof <c>jti</c> to check.</param>
    /// <param name="context">The request context; unused by this in-memory default.</param>
    /// <param name="cancellationToken">Cancellation token; unused, the lookup is synchronous.</param>
    /// <returns><see langword="true"/> when the proof is a live replay; otherwise <see langword="false"/>.</returns>
    public ValueTask<bool> IsSeenAsync(string jti, ExchangeContext context, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(jti);

        if(Entries.TryGetValue(jti, out DateTimeOffset expiresAt))
        {
            if(expiresAt > TimeProvider.GetUtcNow())
            {
                return ValueTask.FromResult(true);
            }

            //Past its freshness window: not a replay, and there is no reason to keep the entry.
            Entries.TryRemove(jti, out _);
        }

        return ValueTask.FromResult(false);
    }


    /// <summary>
    /// The <see cref="PersistDpopProofJtiDelegate"/> implementation: records <paramref name="jti"/>
    /// against <paramref name="expiresAt"/> and opportunistically sweeps every entry whose expiry has
    /// already passed, so entries persisted but never looked up again do not accumulate for the
    /// lifetime of the process.
    /// </summary>
    /// <param name="jti">The DPoP proof <c>jti</c> to record.</param>
    /// <param name="expiresAt">The instant after which the entry no longer counts as a replay.</param>
    /// <param name="context">The request context; unused by this in-memory default.</param>
    /// <param name="cancellationToken">Cancellation token; unused, the write is synchronous.</param>
    public ValueTask PersistAsync(string jti, DateTimeOffset expiresAt, ExchangeContext context, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(jti);

        Entries[jti] = expiresAt;
        EvictExpired();

        return ValueTask.CompletedTask;
    }


    //Removes every entry whose recorded expiry has already passed. Called from PersistAsync so the
    //cache's size tracks the number of proofs currently inside their freshness window even when a
    //jti, once persisted, is never looked up again.
    private void EvictExpired()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        foreach(KeyValuePair<string, DateTimeOffset> entry in Entries)
        {
            if(entry.Value <= now)
            {
                Entries.TryRemove(entry.Key, out _);
            }
        }
    }
}
