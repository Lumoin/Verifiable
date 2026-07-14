using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable;

/// <summary>
/// Subscribes to <see cref="CryptographicKeyEvents.Events"/> for the duration of a single workload call
/// and renders a compact provenance summary from what it captured.
/// </summary>
/// <remarks>
/// <para>
/// This is the sole production (non-test) consumer of the process-wide <see cref="CryptoEvent"/> stream
/// in this repository. The wave-7 consumer scout found that <c>EmitCbom --observe</c> already ran a
/// workload that emits <see cref="SignatureProducedEvent"/>/<see cref="VerificationCompletedEvent"/>/
/// <see cref="KeyMaterialGeneratedEvent"/> through the wired provider, but nothing in the CLI/MCP
/// composition root ever subscribed to <see cref="CryptographicKeyEvents.Events"/> — those events were
/// constructed and thrown away on every real invocation, observed only by transient test subscriptions.
/// This type is the fix: the CLI/MCP <c>cbom --observe --events</c> path listens for real, for the
/// duration of exactly one workload run.
/// </para>
/// <para>
/// <strong>Deliberately decoupled from the CBOM rendering.</strong>
/// <see cref="Verifiable.Cryptography.Cbom.CbomObserver"/> listens to <see cref="System.Diagnostics.Activity"/>
/// spans on <see cref="CryptoActivitySource"/> and renders the CycloneDX document from those; this type
/// listens to the independent <see cref="CryptographicKeyEvents.Events"/> stream and renders a separate,
/// sibling summary. The two mechanisms are never merged — the CBOM JSON a caller receives from
/// <c>EmitCbom --observe</c> is byte-for-byte the same whether or not the provenance summary is
/// requested; <see cref="RenderSummary"/>'s output is only ever appended after it, never folded into it.
/// This mirrors <see cref="CryptoEvent"/>'s own class docs, which name CloudEvents, a Merkle log, and
/// did:cel/did:keri correlation — not CBOM — as the stream's intended destinations.
/// </para>
/// </remarks>
internal static class CryptoEventProvenance
{
    /// <summary>
    /// The line separating the unchanged CBOM JSON from the appended provenance summary in the combined
    /// verb output. A caller that only wants the CBOM JSON can split on this marker — or simply not pass
    /// <c>--events</c>/<c>events: true</c>, in which case the marker and summary never appear at all and
    /// the output is exactly what it was before this wave.
    /// </summary>
    public const string SectionHeader = "--- Crypto event provenance ---";


    /// <summary>
    /// Subscribes a fresh collector to <see cref="CryptographicKeyEvents.Events"/>, runs
    /// <paramref name="workload"/>, and disposes the subscription before returning. The subscription's
    /// lifetime is exactly <paramref name="workload"/>'s duration — never longer — so no event delivered
    /// after the caller has already consumed the result can be attributed to this call, and the
    /// process-wide subscriber count this call added is always back to its starting value once this
    /// method returns (see <c>CryptographicKeyEvents.SubscriberCountForTests</c>, used to verify exactly
    /// that in tests).
    /// </summary>
    /// <typeparam name="TResult">The workload's result type.</typeparam>
    /// <param name="workload">The asynchronous workload to run under observation.</param>
    /// <returns>The workload's result, together with every <see cref="CryptoEvent"/> observed while it ran.</returns>
    public static async Task<(TResult Result, IReadOnlyList<CryptoEvent> Events)> CaptureAsync<TResult>(
        Func<Task<TResult>> workload)
    {
        ArgumentNullException.ThrowIfNull(workload);

        var collector = new Collector();
        TResult result;
        using(CryptographicKeyEvents.Events.Subscribe(collector))
        {
            result = await workload().ConfigureAwait(false);
        }

        return (result, collector.Snapshot());
    }


    /// <summary>
    /// Renders a compact, human-readable provenance summary: one line per distinct (event type, algorithm,
    /// backend) combination observed, with its occurrence count. Deterministically ordered, so the same
    /// captured set always renders the same text regardless of arrival order.
    /// </summary>
    /// <param name="events">The captured events, as returned by <see cref="CaptureAsync{TResult}"/>.</param>
    /// <returns>The rendered summary, or a placeholder line when <paramref name="events"/> is empty.</returns>
    public static string RenderSummary(IReadOnlyList<CryptoEvent> events)
    {
        ArgumentNullException.ThrowIfNull(events);

        if(events.Count == 0)
        {
            return "(no events captured)";
        }

        var counts = new Dictionary<(string EventType, string Algorithm, string Backend), int>();
        foreach(CryptoEvent cryptoEvent in events)
        {
            (string algorithm, string backend) = Describe(cryptoEvent);
            var key = (cryptoEvent.GetType().Name, algorithm, backend);
            counts[key] = counts.TryGetValue(key, out int existing) ? existing + 1 : 1;
        }

        return string.Join(
            Environment.NewLine,
            counts
                .OrderBy(entry => entry.Key.EventType, StringComparer.Ordinal)
                .ThenBy(entry => entry.Key.Algorithm, StringComparer.Ordinal)
                .ThenBy(entry => entry.Key.Backend, StringComparer.Ordinal)
                .Select(entry => $"{entry.Key.EventType} x{entry.Value} ({entry.Key.Algorithm} via {entry.Key.Backend})"));
    }


    /// <summary>
    /// Extracts the (algorithm, backend) pair the summary groups by. Not every <see cref="CryptoEvent"/>
    /// carries both: the entropy family carries a source instead of a backend string (its most analogous
    /// field), and the digest/HMAC family carry neither a <see cref="CryptoAlgorithm"/> nor a backend at
    /// all today (the wave-7 contract's design item 6 left those sites out of scope) — both cases render a
    /// documented placeholder rather than throwing, so an event type this method does not yet know about
    /// never breaks the summary; it renders as <c>(unknown)</c>/<c>(unknown)</c> instead.
    /// </summary>
    private static (string Algorithm, string Backend) Describe(CryptoEvent cryptoEvent) => cryptoEvent switch
    {
        KeyMaterialGeneratedEvent e => (e.Algorithm.ToString(), e.Backend),
        SignatureProducedEvent e => (e.Algorithm.ToString(), e.Backend),
        VerificationCompletedEvent e => (e.Algorithm.ToString(), e.Backend),
        SymmetricCipherPerformedEvent e => (e.Algorithm.ToString(), e.Backend),
        BlockCipherMacComputedEvent e => (e.Algorithm.ToString(), e.Backend),
        BlockCipherMacVerifiedEvent e => (e.Algorithm.ToString(), e.Backend),
        EntropyConsumedEvent e => (e.Purpose.ToString(), e.Source.ToString()),
        EntropyHealthAssessedEvent e => ("(health assessment)", e.Source.ToString()),
        DigestComputedEvent e => (e.AlgorithmName, "(not recorded)"),
        HmacComputedEvent e => (e.AlgorithmName, "(not recorded)"),
        HmacVerifiedEvent e => (e.AlgorithmName, "(not recorded)"),
        _ => ("(unknown)", "(unknown)")
    };


    /// <summary>
    /// A minimal <see cref="IObserver{T}"/> collecting every observed <see cref="CryptoEvent"/> into a
    /// <see cref="ConcurrentQueue{T}"/>. <see cref="CryptographicKeyEvents.Events"/> is process-wide and
    /// its dispatch makes no promise about which thread delivers, so a plain <see cref="List{T}"/> would
    /// risk data corruption under concurrent delivery — the exact "Collection was modified" hazard found
    /// (and fixed, same shape, this wave) in two test-only observers that predated this type.
    /// </summary>
    private sealed class Collector: IObserver<CryptoEvent>
    {
        private ConcurrentQueue<CryptoEvent> Events { get; } = new();


        /// <summary>A snapshot of every event observed so far.</summary>
        public CryptoEvent[] Snapshot() => Events.ToArray();


        /// <inheritdoc/>
        public void OnNext(CryptoEvent value) => Events.Enqueue(value);


        /// <inheritdoc/>
        public void OnError(Exception error)
        {
        }


        /// <inheritdoc/>
        public void OnCompleted()
        {
        }
    }
}
