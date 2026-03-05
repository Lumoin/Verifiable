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
/// The source stream is <see cref="IAsyncEnumerable{T}"/> so the same replayer
/// handles both historical replay (enumerating a completed log) and live
/// streaming (enumerating entries as they arrive from a network source or a
/// <see cref="System.Threading.Channels.Channel{T}"/>).
/// </para>
/// <para>
/// Replay stops when the source stream ends, the cancellation token is signalled,
/// a chain integrity check fails, a proof validation fails, or the apply delegate
/// returns an error. In all failure cases the final emitted result carries a
/// non-null <see cref="LogReplayResult{TState,TOperation,TProof}.Error"/>.
/// </para>
/// <para>
/// Cross-stream proof composition — combining evidence from independent logs —
/// is the responsibility of the caller above this layer. Each
/// <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/> instance
/// processes a single homogeneous stream.
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
    /// Use this overload for version-at-time queries — for example, resolving a DID
    /// at a past <c>versionId</c> or <c>versionTime</c> — where the caller has already
    /// replayed to a known checkpoint and wants to continue from there without
    /// re-processing earlier entries.
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