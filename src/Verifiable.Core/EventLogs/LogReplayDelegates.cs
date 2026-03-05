using System;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.EventLogs;

/// <summary>
/// Classifies a <see cref="LogEntry{TOperation,TProof}"/> by inspecting the
/// entry and returning a <see cref="LogEntryClassification"/>.
/// </summary>
/// <remarks>
/// The classification drives which branch of the <see cref="ApplyDelegate{TState,TOperation,TProof}"/>
/// is executed. Callers may use <see cref="OperationClassifiers"/> for common
/// strategies or supply their own implementation for method-specific logic.
/// </remarks>
/// <typeparam name="TOperation">The domain operation type.</typeparam>
/// <typeparam name="TProof">The proof type.</typeparam>
/// <param name="entry">The entry to classify.</param>
/// <returns>The classification of the entry.</returns>
public delegate LogEntryClassification ClassifyOperationDelegate<TOperation, TProof>(
    LogEntry<TOperation, TProof> entry);

/// <summary>
/// Validates the proofs carried by a <see cref="LogEntry{TOperation,TProof}"/>.
/// </summary>
/// <remarks>
/// <para>
/// The delegate receives the full entry including all proofs, the current log
/// state at the time of validation (before the entry is applied), and a
/// caller-defined context object that carries trust anchors, revocation
/// information, time provider, and any other verification inputs.
/// </para>
/// <para>
/// Returning a non-null error string causes the replay stream to emit a terminal
/// <see cref="LogReplayResult{TState,TOperation,TProof}"/> with that error and
/// stop processing further entries.
/// </para>
/// </remarks>
/// <typeparam name="TState">The domain state type.</typeparam>
/// <typeparam name="TOperation">The domain operation type.</typeparam>
/// <typeparam name="TProof">The proof type.</typeparam>
/// <typeparam name="TContext">The caller-defined proof validation context type.</typeparam>
/// <param name="entry">The entry whose proofs are to be validated.</param>
/// <param name="currentState">The log state before this entry is applied.</param>
/// <param name="context">The caller-supplied validation context.</param>
/// <param name="cancellationToken">The cancellation token.</param>
/// <returns>
/// <see langword="null"/> when validation succeeds, or an error message when
/// validation fails.
/// </returns>
public delegate ValueTask<string?> ValidateProofDelegate<TState, TOperation, TProof, TContext>(
    LogEntry<TOperation, TProof> entry,
    LogState<TState> currentState,
    TContext context,
    CancellationToken cancellationToken);

/// <summary>
/// Verifies the hash-chain integrity of a <see cref="LogEntry{TOperation,TProof}"/>
/// against the digest of the preceding entry as observed by the replayer.
/// </summary>
/// <remarks>
/// <para>
/// The <paramref name="previousEntryDigest"/> parameter is the digest the replayer
/// recorded from the previous successfully processed entry — not the value the
/// current entry claims in its <see cref="LogEntry{TOperation,TProof}.PreviousDigest"/>
/// field. The delegate compares the entry's claim against this authoritative value
/// to detect tampering.
/// </para>
/// <para>
/// For Merkle-tree backed logs the delegate may verify an inclusion proof instead
/// of a sequential hash chain.
/// </para>
/// </remarks>
/// <typeparam name="TOperation">The domain operation type.</typeparam>
/// <typeparam name="TProof">The proof type.</typeparam>
/// <param name="entry">The entry to verify.</param>
/// <param name="previousEntryDigest">
/// The digest the replayer observed from the preceding entry, or
/// <see langword="null"/> for the genesis entry.
/// </param>
/// <param name="cancellationToken">The cancellation token.</param>
/// <returns>
/// <see langword="null"/> when integrity holds, or an error message when
/// the chain is broken.
/// </returns>
public delegate ValueTask<string?> VerifyChainIntegrityDelegate<TOperation, TProof>(
    LogEntry<TOperation, TProof> entry,
    ReadOnlyMemory<byte>? previousEntryDigest,
    CancellationToken cancellationToken);

/// <summary>
/// Applies a classified log entry to the current log state, producing a new
/// log state or an error.
/// </summary>
/// <remarks>
/// <para>
/// This is the single dispatch point for all state transitions. The caller
/// implements this delegate as a pattern match over
/// <paramref name="classification"/> and <paramref name="currentState"/>,
/// handling every classification they define. Unknown classifications should
/// fall through to a default no-op or to a base delegate supplied by
/// <see cref="LogReplayDefaults"/>.
/// </para>
/// <para>
/// The library provides composable base implementations via
/// <see cref="LogReplayDefaults.CreateApplyDelegate{TState,TOperation,TProof}"/>.
/// Callers wrap the base delegate to handle custom classifications, exactly as
/// a key format reader delegate chains to its base for unrecognized properties.
/// </para>
/// <code>
/// ApplyDelegate&lt;MyState, MyOp, MyProof&gt; baseApply =
///     LogReplayDefaults.CreateApplyDelegate&lt;MyState, MyOp, MyProof&gt;(
///         genesis: (_, entry, ct) => ...,
///         update: (active, entry, ct) => ...,
///         deactivate: (active, entry, ct) => ...);
///
/// ApplyDelegate&lt;MyState, MyOp, MyProof&gt; myApply =
///     async (classification, state, entry, ct) =>
///     {
///         if(classification == MyClassifications.Checkpoint)
///         {
///             return (state, null);
///         }
///
///         return await baseApply(classification, state, entry, ct).ConfigureAwait(false);
///     };
/// </code>
/// </remarks>
/// <typeparam name="TState">The domain state type.</typeparam>
/// <typeparam name="TOperation">The domain operation type.</typeparam>
/// <typeparam name="TProof">The proof type.</typeparam>
/// <param name="classification">The classification of the entry.</param>
/// <param name="currentState">The current log state before this entry is applied.</param>
/// <param name="entry">The entry to apply.</param>
/// <param name="cancellationToken">The cancellation token.</param>
/// <returns>
/// The new log state and <see langword="null"/> on success, or the unchanged state
/// and an error message on failure.
/// </returns>
public delegate ValueTask<(LogState<TState> State, string? Error)> ApplyDelegate<TState, TOperation, TProof>(
    LogEntryClassification classification,
    LogState<TState> currentState,
    LogEntry<TOperation, TProof> entry,
    CancellationToken cancellationToken);

/// <summary>
/// Called after each entry is successfully processed during replay, delivering
/// the result to any attached listener.
/// </summary>
/// <remarks>
/// Use this delegate to drive audit sinks, UI notifications, webhook dispatchers,
/// or any other downstream consumer that needs to react to each state transition
/// without taking ownership of the replay stream.
/// </remarks>
/// <typeparam name="TState">The domain state type.</typeparam>
/// <typeparam name="TOperation">The domain operation type.</typeparam>
/// <typeparam name="TProof">The proof type.</typeparam>
/// <param name="result">The result produced for the processed entry.</param>
/// <param name="cancellationToken">The cancellation token.</param>
/// <returns>A <see cref="ValueTask"/> that completes when the listener is done.</returns>
public delegate ValueTask OnEntryProcessedDelegate<TState, TOperation, TProof>(
    LogReplayResult<TState, TOperation, TProof> result,
    CancellationToken cancellationToken);