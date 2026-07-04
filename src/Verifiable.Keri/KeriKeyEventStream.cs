using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cesr;
using Verifiable.Cesr.Streaming;
using Verifiable.Cryptography;
using Verifiable.Cryptography.EventLogs;

namespace Verifiable.Keri;

/// <summary>
/// Verifies a KERI Key Event Log served as a CESR stream (a <c>keri.cesr</c>): it reads each event and its
/// attached controller signatures off the stream, reconstructs the log's entries, and replays them through the
/// shipped <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/> so the SAIDs, the prior-event hash chain,
/// the signing-threshold, and the pre-rotation commitments are all verified by the same path a KEL is verified by
/// anywhere else. The resolver-boundary use is did:webs, whose <c>keri.cesr</c> is exactly this stream.
/// </summary>
/// <remarks>
/// <para>
/// The controller signatures in a KERI stream are indexed: each references its signing key by an index into the
/// establishment event's current-key list (field <c>k</c>) — an interaction event's signatures index the current
/// keys carried forward from the most recent establishment event. This reader resolves each index to its key
/// string, decodes that CESR verification-key primitive to key material through the algorithm-agile
/// <see cref="CesrVerificationKeyCodes"/> seam (Ed25519 today; other algorithms register there), and pairs it
/// with the signature bytes into a <see cref="CryptoProof"/>. The resolution only supplies the key material; the
/// replayer performs the actual verification and rejects a proof whose key is not authorized or whose signature
/// does not verify, so a tampered stream fails closed.
/// </para>
/// <para>
/// Every rented buffer — the event and attachment bodies, the reconstructed keys and signatures, and the SAID
/// digest buffers the entries chain on — is tracked and returned to its pool once replay completes.
/// </para>
/// </remarks>
public static class KeriKeyEventStream
{
    /// <summary>
    /// Reads a KERI Key Event Log from a text-domain (qb64) <c>keri.cesr</c> stream and replays it through the
    /// shipped verifier, returning the verified key state.
    /// </summary>
    /// <param name="stream">The pipe the <c>keri.cesr</c> stream is read from. The caller owns and completes it.</param>
    /// <param name="decodeFieldMap">The per-serialization decoder for one event's bytes (a JSON decoder for a KERIpy-style stream).</param>
    /// <param name="computeDigest">The digest implementation the replayer recomputes each event SAID with.</param>
    /// <param name="pool">The pool every transient buffer is rented from.</param>
    /// <param name="timeProvider">The clock the replay consults for any time-bounded check.</param>
    /// <param name="resolveDelegationSeal">Resolves a delegated event's delegating seal from the delegator's KEL, or <see langword="null"/> for a non-delegated log.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    /// The replay outcome: whether every event verified and the final key state. A malformed or truncated stream, a
    /// structurally invalid attachment, an event that is not a well-formed KERI key event, a signature indexing a key
    /// the event does not carry, or a threshold whose evaluation is rejected are reported fail-closed as an unverified
    /// result carrying the reason, not thrown, so a caller verifying an untrusted <c>keri.cesr</c> cannot be made to
    /// crash on hostile input it forgot to guard. Only argument and cancellation faults surface as exceptions.
    /// </returns>
    public static async ValueTask<KeriKeyEventStreamReplayResult> ReplayAsync(
        PipeReader stream,
        KeriEventFieldMapDecoder decodeFieldMap,
        ComputeDigestDelegate computeDigest,
        MemoryPool<byte> pool,
        TimeProvider timeProvider,
        DelegationSealResolver? resolveDelegationSeal = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(decodeFieldMap);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(timeProvider);

        //The messages own the event and attachment bodies the entries read over; the owned carriers are the keys,
        //signatures, and SAID buffers the entries reference. Both are held for the whole replay and disposed once
        //it completes, so nothing the replayer reads is freed while it is still in use.
        var messages = new List<CesrMessage>();
        var owned = new List<IDisposable>();
        ulong index = 0;
        try
        {
            var entries = new List<LogEntry<KeriKeyEvent, CryptoProof>>();
            IReadOnlyList<string> currentSigningKeys = [];

            await foreach(CesrMessage message in CesrMessageReader.ReadTextAsync(stream, pool, cancellationToken).ConfigureAwait(false))
            {
                messages.Add(message);

                MessageFieldMap fields = decodeFieldMap(message.Message.BodyMemory, message.Message.Serialization);
                KeriKeyEvent keyEvent = KeriEventReader.Read(fields);

                //A controller signature indexes the current keys: an establishment event's own new keys, or the
                //keys carried forward from the last establishment event for a non-establishment (interaction) event.
                IReadOnlyList<string> authorizingKeys = keyEvent switch
                {
                    KeriInceptionEvent inception => inception.SigningKeys,
                    KeriRotationEvent rotation => rotation.SigningKeys,
                    _ => currentSigningKeys
                };

                ImmutableArray<CryptoProof> proofs = BuildControllerProofs(message.Attachments, authorizingKeys, pool, owned);

                string? priorSaid = keyEvent switch
                {
                    KeriInteractionEvent interaction => interaction.PriorSaid,
                    KeriRotationEvent rotation => rotation.PriorSaid,
                    _ => null
                };

                entries.Add(new LogEntry<KeriKeyEvent, CryptoProof>
                {
                    //The explicit nullable cast is required: without it the ternary's type is the non-nullable
                    //ReadOnlyMemory<byte> (via its implicit conversion from byte[]), so the null branch would
                    //become default(ReadOnlyMemory<byte>) — an EMPTY, present digest — rather than a null one,
                    //which the genesis chain check (an absent prior digest) requires.
                    Index = index,
                    PreviousDigest = priorSaid is null ? null : (ReadOnlyMemory<byte>?)RentUtf8(priorSaid, pool, owned),
                    Digest = RentUtf8(keyEvent.Said, pool, owned),
                    CanonicalBytes = message.Message.BodyMemory,
                    Operation = keyEvent,
                    Proofs = proofs
                });

                if(keyEvent is KeriInceptionEvent or KeriRotationEvent)
                {
                    currentSigningKeys = authorizingKeys;
                }

                index++;
            }

            LogReplayContext<KeriKeyState, KeriKeyEvent, CryptoProof, KeriReplayValidationContext> context =
                KeriKeyEventLog.CreateReplayContext(computeDigest, pool, timeProvider, resolveDelegationSeal);
            var replayer = new LogReplayer<KeriKeyState, KeriKeyEvent, CryptoProof, KeriReplayValidationContext>();

            KeriKeyState? finalState = null;
            string? error = null;
            await foreach(LogReplayResult<KeriKeyState, KeriKeyEvent, CryptoProof> result in
                replayer.ReplayAsync(ToAsync(entries, cancellationToken), context, cancellationToken).ConfigureAwait(false))
            {
                if(result.Error is not null)
                {
                    error = result.Error;
                    break;
                }

                finalState = result.State switch
                {
                    ActiveLogState<KeriKeyState> active => active.Value,
                    DeactivatedLogState<KeriKeyState> deactivated => deactivated.Value,
                    _ => finalState
                };
            }

            bool isVerified = error is null && finalState is not null;

            return new KeriKeyEventStreamReplayResult(isVerified, isVerified ? finalState : null, (long)index, error);
        }
        catch(KeriException exception)
        {
            //A structurally invalid event, attachment, or threshold in an untrusted stream is a fail-closed
            //rejection, not an exception the caller must remember to catch: report it as an unverified result so a
            //hostile keri.cesr cannot crash a resolver that forgot to guard the call.
            return new KeriKeyEventStreamReplayResult(false, null, (long)index, exception.Message);
        }
        catch(CesrFormatException exception)
        {
            return new KeriKeyEventStreamReplayResult(false, null, (long)index, exception.Message);
        }
        finally
        {
            foreach(IDisposable disposable in owned)
            {
                disposable.Dispose();
            }

            foreach(CesrMessage message in messages)
            {
                message.Dispose();
            }
        }
    }


    /// <summary>
    /// Builds the controller-signature proofs for one event from its attachment groups: for each indexed
    /// signature in a controller-signature group (<c>-K</c>), resolves the signing key from the event's
    /// authorizing keys at the signature's index and pairs it with the signature bytes. Witness signature groups
    /// and other attachments are left for the replayer's other checks and are not read here.
    /// </summary>
    /// <param name="attachments">The event's attachment groups.</param>
    /// <param name="authorizingKeys">The current signing keys a controller signature's index resolves against.</param>
    /// <param name="pool">The pool the key and signature buffers are rented from.</param>
    /// <param name="owned">The list the reconstructed keys and signatures are tracked on for disposal.</param>
    /// <returns>The controller-signature proofs, in stream order.</returns>
    /// <exception cref="KeriException">A signature indexes a key outside the event's authorizing key list.</exception>
    private static ImmutableArray<CryptoProof> BuildControllerProofs(
        IReadOnlyList<CesrToken> attachments,
        IReadOnlyList<string> authorizingKeys,
        MemoryPool<byte> pool,
        List<IDisposable> owned)
    {
        ImmutableArray<CryptoProof>.Builder proofs = ImmutableArray.CreateBuilder<CryptoProof>();
        foreach(CesrToken attachment in attachments)
        {
            if(!WellKnownKeriCountCodes.IsControllerSignatureGroup(attachment.Code))
            {
                continue;
            }

            foreach(CesrParsedIndexedSignature signature in CesrGroupReader.ReadIndexedSignaturesText(attachment.BodyMemory, pool))
            {
                using(signature)
                {
                    if(signature.Index < 0 || signature.Index >= authorizingKeys.Count)
                    {
                        throw new KeriException(
                            $"A controller signature indexes key {signature.Index}, outside the event's {authorizingKeys.Count} signing key(s).");
                    }

                    proofs.Add(BuildProof(authorizingKeys[signature.Index], signature.Raw, pool, owned));
                }
            }
        }

        return proofs.ToImmutable();
    }


    /// <summary>
    /// Builds one proof from a qualified signing key and raw signature bytes: decodes the CESR verification-key
    /// primitive to its algorithm and key material through the <see cref="CesrVerificationKeyCodes"/> seam, wraps
    /// the key and signature into pooled carriers, and pairs them under the resolved algorithm.
    /// </summary>
    /// <param name="qualifiedKey">The signing key as its qualified CESR text primitive (for example a <c>D</c>-coded Ed25519 key).</param>
    /// <param name="signatureRaw">The raw signature bytes read from the indexed-signature group.</param>
    /// <param name="pool">The pool the key and signature buffers are rented from.</param>
    /// <param name="owned">The list the reconstructed key and signature are tracked on for disposal.</param>
    /// <returns>The reconstructed proof.</returns>
    /// <exception cref="KeriException">The signing key's CESR code is not a supported verification-key algorithm.</exception>
    private static CryptoProof BuildProof(string qualifiedKey, ReadOnlySpan<byte> signatureRaw, MemoryPool<byte> pool, List<IDisposable> owned)
    {
        using CesrParsedPrimitive parsedKey = CesrPrimitiveCodec.DecodeText(qualifiedKey, pool);
        if(!CesrVerificationKeyCodes.TryGetVerificationKeyInfo(parsedKey.Code, out CesrVerificationKeyInfo? keyInfo))
        {
            throw new KeriException($"The signing key code '{parsedKey.Code}' is not a supported verification-key algorithm.");
        }

        //Copy the CESR-decoded key and the raw signature into pooled, auto-clearing carriers via the semantic-type
        //extensions rather than holding them as naked buffers; the caller tracks and disposes them after replay.
        PublicKeyMemory publicKey = parsedKey.Raw.ToPublicKeyMemory(keyInfo.PublicKeyTag, pool);
        owned.Add(publicKey);
        Signature signature = signatureRaw.ToSignature(keyInfo.SignatureTag, pool);
        owned.Add(signature);

        return new CryptoProof(signature, publicKey, keyInfo.Algorithm);
    }


    /// <summary>
    /// Copies a string's UTF-8 bytes into a pooled buffer tracked for disposal and returns a view over them — the
    /// event-SAID and prior-SAID digests the reconstructed entries chain on.
    /// </summary>
    /// <param name="text">The text to encode.</param>
    /// <param name="pool">The pool the buffer is rented from.</param>
    /// <param name="owned">The list the buffer owner is tracked on for disposal.</param>
    /// <returns>The UTF-8 bytes as a view over the tracked pooled buffer.</returns>
    private static ReadOnlyMemory<byte> RentUtf8(string text, MemoryPool<byte> pool, List<IDisposable> owned)
    {
        int length = Encoding.UTF8.GetByteCount(text);
        IMemoryOwner<byte> owner = pool.Rent(length);
        Encoding.UTF8.GetBytes(text, owner.Memory.Span);
        owned.Add(owner);

        return owner.Memory[..length];
    }


    /// <summary>
    /// Adapts the reconstructed entries to the <see cref="IAsyncEnumerable{T}"/> the
    /// <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/> consumes, observing cancellation per entry.
    /// </summary>
    /// <param name="entries">The reconstructed log entries.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The entries as an async stream.</returns>
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
