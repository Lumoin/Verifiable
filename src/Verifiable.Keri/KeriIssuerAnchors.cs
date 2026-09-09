using Lumoin.Base;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cesr;
using Verifiable.Cryptography;
using Verifiable.Cryptography.EventLogs;

namespace Verifiable.Keri;

/// <summary>
/// Replays an issuer's KERI Key Event Log and collects the seals it anchors, each paired with the AID the replay
/// itself established for the verified event that carried it. This is the cross-log step
/// <c>Verifiable.Acdc.AcdcKeriBinding</c> documents as a validator's own responsibility, moved into production so
/// the AID a caller matches a seal against can never be a caller's own assertion — only the product of a KEL that
/// actually verified under <see cref="KeriKeyStateMachine"/> and the shipped <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/>.
/// </summary>
/// <remarks>
/// <para>
/// Each <see cref="KeriKelEvent"/> carries only its own serialization bytes and proofs; the typed
/// <see cref="KeriKeyEvent"/> (its <see cref="KeriKeyEvent.Prefix"/>, signing keys, and anchor list) is decoded
/// HERE, from those bytes, via <paramref name="events"/>'s own <see cref="KeriEventFieldMapDecoder"/> — never
/// taken from a caller-supplied object independent of the bytes. This closes the same class of hazard a public
/// method accepting a caller-built <c>LogEntry</c> would reopen: an event's <see cref="KeriKeyEvent.Prefix"/> is
/// bound to its own serialization the moment it is read, and the replayer's SAID check (over the same bytes) then
/// proves that reading was not tampered with.
/// </para>
/// <para>
/// The AID paired with each collected anchor is read directly off the entry the replayer just verified
/// (<see cref="LogReplayResult{TState,TOperation,TProof}.Entry"/>'s own <see cref="KeriKeyEvent.Prefix"/>), never
/// from a separately-threaded "expected" value: a self-addressing inception's identifier equals its own SAID
/// (<see cref="KeriKeyStateMachine.Incept"/>), and every later event's identifier is checked against the running
/// key state before it is applied, so every anchor a fully verified replay yields shares one AID — the KEL's own.
/// </para>
/// </remarks>
public static class KeriIssuerAnchors
{
    /// <summary>
    /// Replays an issuer's KEL from its per-event bytes and proofs, collecting the seals every verified event
    /// anchors.
    /// </summary>
    /// <param name="events">The issuer's KEL, in log order: each event's own serialization bytes and its proofs.</param>
    /// <param name="decodeFieldMap">The per-serialization decoder for one event's bytes.</param>
    /// <param name="serializationKind">The serialization <paramref name="events"/> is encoded in.</param>
    /// <param name="computeDigest">The digest implementation the replay verifies event SAIDs and pre-rotation commitments with.</param>
    /// <param name="pool">The pool every transient buffer is rented from.</param>
    /// <param name="timeProvider">The clock the replay consults for any time-bounded check.</param>
    /// <param name="resolveDelegationSeal">Resolves a delegated event's delegating seal from the delegator's KEL, or <see langword="null"/> for a non-delegated log.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    /// The replay outcome: whether every event verified, the AID the replay established, and the anchored seals
    /// collected from every verified event. A malformed event, an unverified signature, a broken hash chain, or a
    /// rejected threshold is reported fail-closed as an unverified result carrying the reason, not thrown, so a
    /// caller replaying an untrusted KEL cannot be made to crash on hostile input it forgot to guard. Only argument
    /// and cancellation faults surface as exceptions.
    /// </returns>
    /// <remarks>
    /// <strong>Manual disposal, not a <see langword="using"/> declaration.</strong> <c>owned</c> accumulates
    /// one pooled buffer owner per <see cref="Utf8(string, BaseMemoryPool, List{IDisposable})"/> call across
    /// the whole event loop — a collection of disposables, not one disposable value — so the
    /// <see langword="finally"/> below disposes every entry once the replay (successful or not) is done with
    /// them.
    /// </remarks>
    public static async Task<KeriIssuerAnchorReplayResult> ReplayAsync(
        IReadOnlyList<KeriKelEvent> events,
        KeriEventFieldMapDecoder decodeFieldMap,
        CesrSerializationKind serializationKind,
        ComputeDigestDelegate computeDigest,
        BaseMemoryPool pool,
        TimeProvider timeProvider,
        DelegationSealResolver? resolveDelegationSeal = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(events);
        ArgumentNullException.ThrowIfNull(decodeFieldMap);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(timeProvider);

        if(events.Count == 0)
        {
            return new KeriIssuerAnchorReplayResult(false, null, null, 0, "An issuer KEL replay requires at least one event (the inception).");
        }

        var owned = new List<IDisposable>();
        try
        {
            var entries = new List<LogEntry<KeriKeyEvent, CryptoProof>>(events.Count);
            var anchorsByIndex = new List<IReadOnlyList<KeriSeal>>(events.Count);
            string? priorSaid = null;

            for(int index = 0; index < events.Count; index++)
            {
                KeriKelEvent source = events[index];
                MessageFieldMap fields = decodeFieldMap(source.EventBytes, serializationKind);
                KeriKeyEvent keyEvent = KeriEventReader.Read(fields);
                anchorsByIndex.Add(KeriSealReader.ReadList(fields[KeriMessageFields.Anchors]));

                entries.Add(new LogEntry<KeriKeyEvent, CryptoProof>
                {
                    Index = (ulong)index,
                    //The explicit nullable cast keeps an absent prior digest (the genesis entry) distinct from an
                    //empty-but-present one — see KeriKeyEventStream's own identical cast for why the ternary's
                    //inferred type would otherwise collapse the null branch into a present, empty value.
                    PreviousDigest = priorSaid is null ? null : (ReadOnlyMemory<byte>?)Utf8(priorSaid, pool, owned),
                    Digest = Utf8(keyEvent.Said, pool, owned),
                    CanonicalBytes = source.EventBytes,
                    Operation = keyEvent,
                    Proofs = source.Proofs
                });

                priorSaid = keyEvent.Said;
            }

            LogReplayContext<KeriKeyState, KeriKeyEvent, CryptoProof, KeriReplayValidationContext> context =
                KeriKeyEventLog.CreateReplayContext(computeDigest, pool, timeProvider, resolveDelegationSeal);
            var replayer = new LogReplayer<KeriKeyState, KeriKeyEvent, CryptoProof, KeriReplayValidationContext>();

            var anchors = new List<KeriAnchoredSeal>();
            string? issuerAid = null;
            string? error = null;
            long processed = 0;

            await foreach(LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof> result in
                replayer.ReplayAsync(ToAsync(entries, cancellationToken), context, cancellationToken).ConfigureAwait(false))
            {
                processed++;
                if(result.Error is not null)
                {
                    error = result.Error;
                    break;
                }

                //Every verified entry in a single KEL shares one AID (KeriKeyStateMachine enforces Prefix ==
                //state.Prefix at every non-genesis event), so this converges on the KEL's own established AID.
                issuerAid = result.Entry.Operation!.Prefix;
                foreach(KeriSeal seal in anchorsByIndex[(int)result.Entry.Index])
                {
                    anchors.Add(KeriAnchoredSeal.Create(issuerAid, seal));
                }
            }

            bool isVerified = error is null;

            return new KeriIssuerAnchorReplayResult(
                isVerified,
                isVerified ? issuerAid : null,
                isVerified ? anchors : null,
                processed,
                error);
        }
        finally
        {
            foreach(IDisposable disposable in owned)
            {
                disposable.Dispose();
            }
        }
    }


    /// <summary>Rents a pooled buffer for a text's UTF-8 bytes, tracking the owner for disposal.</summary>
    private static ReadOnlyMemory<byte> Utf8(string text, BaseMemoryPool pool, List<IDisposable> owned)
    {
        int length = Encoding.UTF8.GetByteCount(text);
        IMemoryOwner<byte> owner = pool.Rent(length);
        Encoding.UTF8.GetBytes(text, owner.Memory.Span);
        owned.Add(owner);

        return owner.Memory[..length];
    }


    /// <summary>Adapts the reconstructed entries to the <see cref="IAsyncEnumerable{T}"/> the replayer consumes, observing cancellation per entry.</summary>
    private static async IAsyncEnumerable<LogEntry<KeriKeyEvent, CryptoProof>> ToAsync(
        List<LogEntry<KeriKeyEvent, CryptoProof>> entries,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach(LogEntry<KeriKeyEvent, CryptoProof> entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return entry;

            await Task.CompletedTask.ConfigureAwait(false);
        }
    }
}
