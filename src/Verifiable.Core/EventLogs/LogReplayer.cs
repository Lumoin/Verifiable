using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.EventLogs;

/// <summary>
/// Replays an authenticated append-only log as an infinite stream of
/// <see cref="LogReplayResult{TState,TOperation,TProof}"/> values.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/> is stateless.
/// All policy is injected through
/// <see cref="LogReplayContext{TState,TOperation,TProof,TContext}"/>. The
/// replayer drives the context delegates in order for each entry received
/// from the source stream and emits one result per entry.
/// </para>
/// <para>
/// <strong>Each entry is one verified link in a chain of trust.</strong>
/// Trust traces back through a chain of verified entries to an anchor the relying
/// party has decided to trust. Each entry reduces uncertainty about the current
/// state of the subject — measurable as information entropy — and the proof
/// attached to the entry is what makes that reduction verifiable rather than
/// merely claimed. The replayer carries the observed state of the preceding entry
/// forward to the caller-supplied
/// <see cref="LogReplayContext{TState,TOperation,TProof,TContext}.VerifyChainIntegrity"/>
/// delegate, which decides what it means for a link to hold. The log is therefore
/// as strong as its weakest verified link — the replayer ensures every link is
/// presented for verification, but what verification means is entirely the
/// caller's concern.
/// </para>
/// <para>
/// <strong>The same chain-of-trust pattern recurs across all trust domains.</strong>
/// An identifier is bound to a key, the binding has temporal validity, the binding
/// can be revoked, and trust in the binding traces back through a chain to an anchor
/// the relying party has decided to trust. This is true for X.509 certificate chains,
/// DID documents with verification methods, TPM endorsement key certificate chains,
/// and Trusted Lists pointing to QTSPs. The lifecycle operations are also isomorphic:
/// creation, rotation, revocation, and expiration. The mechanisms differ but the
/// semantics are identical. This replayer is the infrastructure that makes those
/// semantics replayable and verifiable regardless of which domain instantiates them.
/// See <see href="https://lumoin.com/writings/mydata2025entropy"/> for the broader
/// framing connecting trust chains, entropy, and the preservation of verifiable
/// continuity across systems.
/// </para>
/// <para>
/// <strong>Connection to selective disclosure.</strong>
/// The log and the selective disclosure structures in this library are dual in their
/// relationship to entropy. The log accumulates trust forward through time: each
/// entry is a verified reduction of uncertainty about the subject's current state.
/// Selective disclosure releases the minimum necessary slice of that accumulated
/// trust to a verifier: the disclosure lattice computes the smallest set of claims
/// that reduces the verifier's uncertainty to exactly the threshold they require,
/// no more. A verifier who trusts the log trusts the identity behind the credential;
/// a verifier who receives a selective disclosure trusts only what the lattice
/// determined was necessary to reveal. Both are entropy operations — one accumulating,
/// one minimizing — operating on the same underlying chain of trust.
/// </para>
/// <para>
/// <strong>Stream model.</strong>
/// The source is <see cref="IAsyncEnumerable{T}"/> so the same replayer handles
/// historical replay (enumerating a completed log file) and live streaming
/// (enumerating entries as they arrive from a network source or a
/// <see cref="System.Threading.Channels.Channel{T}"/>). From the replayer's
/// perspective a completed log and an unbounded live stream are the same thing:
/// a pull-based sequence with backpressure and cancellation. The caller decides
/// when the sequence ends.
/// </para>
/// <para>
/// <strong>What the replayer does not do.</strong>
/// The replayer has no opinion about what constitutes a valid proof, what state
/// transitions are legal, or what the domain semantics of an operation are.
/// All of that is injected by the caller through
/// <see cref="LogReplayContext{TState,TOperation,TProof,TContext}"/>. This
/// separation means the same replayer drives DID event logs (did:webvh, did:cel),
/// CRDT delta streams, supply chain event logs (UNTP), TPM attestation streams,
/// and eIDAS signature audit trails without modification.
/// </para>
/// <para>
/// <strong>Cross-stream composition.</strong>
/// Combining evidence from independent logs — for example, requiring that a CRDT
/// delta is valid only if the DID log confirms the author held the required role
/// at the time of authoring AND the TPM attestation log confirms the signing key
/// was hardware-bound at that moment — is the responsibility of the caller above
/// this layer. Each <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/>
/// instance processes a single homogeneous stream. The caller zips or joins
/// independent <see cref="IAsyncEnumerable{T}"/> streams to compose cross-stream
/// proofs.
/// </para>
/// <para>
/// Replay stops when the source stream ends, the cancellation token is signalled,
/// a chain integrity check fails, a proof validation fails, or the apply delegate
/// returns an error. In all failure cases the final emitted result carries a
/// non-null <see cref="LogReplayResult{TState,TOperation,TProof}.Error"/>.
/// </para>
/// </remarks>
/// <typeparam name="TState">The domain state type.</typeparam>
/// <typeparam name="TOperation">The domain operation type.</typeparam>
/// <typeparam name="TProof">The proof type.</typeparam>
/// <typeparam name="TContext">The caller-defined proof validation context type.</typeparam>
public sealed class LogReplayer<TState, TOperation, TProof, TContext>
{
    /// <summary>
    /// Replays <paramref name="entries"/> from the beginning, emitting one
    /// <see cref="LogReplayResult{TState,TOperation,TProof}"/> per entry.
    /// </summary>
    /// <param name="entries">The source entry stream.</param>
    /// <param name="context">The replay context supplying all delegates.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    /// An async stream of results, one per entry. The stream terminates when
    /// the source ends, the token is cancelled, or an error occurs.
    /// </returns>
    public IAsyncEnumerable<LogReplayResult<TState, TOperation, TProof>> ReplayAsync(
        IAsyncEnumerable<LogEntry<TOperation, TProof>> entries,
        LogReplayContext<TState, TOperation, TProof, TContext> context,
        CancellationToken cancellationToken) =>
        ReplayFromAsync(entries, startState: new EmptyLogState<TState>(), startDigest: null, context, cancellationToken);

    /// <summary>
    /// Replays <paramref name="entries"/> starting from a known checkpoint,
    /// emitting one <see cref="LogReplayResult{TState,TOperation,TProof}"/> per entry.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Use this overload for version-at-time queries — for example, resolving a DID
    /// at a past <c>versionId</c> or <c>versionTime</c> — where the caller has already
    /// replayed to a known checkpoint and wants to continue from there without
    /// re-processing earlier entries.
    /// </para>
    /// <para>
    /// <strong>Checkpoint integrity.</strong>
    /// The <paramref name="startDigest"/> parameter is the digest the caller observed
    /// from the last entry it processed. The replayer passes this as the authoritative
    /// previous digest when verifying the first entry of the resumed stream. If the
    /// caller provides a digest that does not match what was actually recorded, the
    /// chain integrity check on the first resumed entry will fail, making checkpoint
    /// forgery detectable.
    /// </para>
    /// </remarks>
    /// <param name="entries">The source entry stream, starting at the checkpoint.</param>
    /// <param name="startState">
    /// The log state at the checkpoint. Pass <see cref="EmptyLogState{TState}"/> to
    /// start from genesis.
    /// </param>
    /// <param name="startDigest">
    /// The digest of the last entry processed before the checkpoint, or
    /// <see langword="null"/> to start from genesis. The replayer passes this as the
    /// authoritative previous digest when processing the first entry of the resumed
    /// stream.
    /// </param>
    /// <param name="context">The replay context supplying all delegates.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    /// An async stream of results, one per entry. The stream terminates when
    /// the source ends, the token is cancelled, or an error occurs.
    /// </returns>
    public async IAsyncEnumerable<LogReplayResult<TState, TOperation, TProof>> ReplayFromAsync(
        IAsyncEnumerable<LogEntry<TOperation, TProof>> entries,
        LogState<TState> startState,
        ReadOnlyMemory<byte>? startDigest,
        LogReplayContext<TState, TOperation, TProof, TContext> context,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(startState);
        ArgumentNullException.ThrowIfNull(context);

        LogState<TState> currentState = startState;
        ReadOnlyMemory<byte>? previousEntryDigest = startDigest;

        await foreach(LogEntry<TOperation, TProof> entry in entries
            .WithCancellation(cancellationToken)
            .ConfigureAwait(false))
        {
            LogEntryClassification classification = context.Classify(entry);

            string? integrityError = await context.VerifyChainIntegrity(
                entry, previousEntryDigest, cancellationToken).ConfigureAwait(false);

            if(integrityError is not null)
            {
                yield return ErrorResult(entry, currentState, classification, integrityError);
                yield break;
            }

            string? proofError = await context.ValidateProof(
                entry, currentState, context.ValidationContext, cancellationToken).ConfigureAwait(false);

            if(proofError is not null)
            {
                yield return ErrorResult(entry, currentState, classification, proofError);
                yield break;
            }

            (LogState<TState> nextState, string? applyError) = await context.Apply(
                classification, currentState, entry, cancellationToken).ConfigureAwait(false);

            if(applyError is not null)
            {
                yield return ErrorResult(entry, currentState, classification, applyError);
                yield break;
            }

            LogReplayResult<TState, TOperation, TProof> result = new()
            {
                Entry = entry,
                State = nextState,
                Classification = classification,
                Error = null
            };

            if(context.OnEntryProcessed is not null)
            {
                await context.OnEntryProcessed(result, cancellationToken).ConfigureAwait(false);
            }

            yield return result;

            currentState = nextState;
            previousEntryDigest = entry.Digest;
        }
    }


    private static LogReplayResult<TState, TOperation, TProof> ErrorResult(
        LogEntry<TOperation, TProof> entry,
        LogState<TState> state,
        LogEntryClassification classification,
        string error) =>
        new()
        {
            Entry = entry,
            State = state,
            Classification = classification,
            Error = error
        };
}