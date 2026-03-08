using System;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.EventLogs;

/// <summary>
/// Provides composable default implementations of log replay delegates.
/// </summary>
/// <remarks>
/// <para>
/// Each factory method returns a delegate that handles the standard log lifecycle
/// classifications (<see cref="LogEntryClassification.Genesis"/>,
/// <see cref="LogEntryClassification.Update"/>,
/// <see cref="LogEntryClassification.Deactivate"/>,
/// <see cref="LogEntryClassification.Heartbeat"/>) and falls through to a
/// no-op for any unrecognized classification.
/// </para>
/// <para>
/// Callers wrap the returned delegate to handle custom classifications, exactly
/// as a key format reader delegate chains to its base for unrecognized properties:
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
public static class LogReplayDefaults
{
    /// <summary>
    /// Creates an <see cref="ApplyDelegate{TState,TOperation,TProof}"/> that handles
    /// the four standard lifecycle classifications and falls through to a no-op for
    /// any unrecognized classification.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The <paramref name="genesis"/> delegate receives an
    /// <see cref="EmptyLogState{TState}"/> and must return an
    /// <see cref="ActiveLogState{TState}"/>.
    /// </para>
    /// <para>
    /// The <paramref name="update"/> and <paramref name="deactivate"/> delegates
    /// receive an <see cref="ActiveLogState{TState}"/>. If either receives a
    /// non-active state the delegate returns an error without calling the
    /// inner function.
    /// </para>
    /// <para>
    /// Heartbeat entries are handled as a no-op — the current state is returned
    /// unchanged without invoking any inner function.
    /// </para>
    /// </remarks>
    /// <typeparam name="TState">The domain state type.</typeparam>
    /// <typeparam name="TOperation">The domain operation type.</typeparam>
    /// <typeparam name="TProof">The proof type.</typeparam>
    /// <param name="genesis">
    /// The function that produces the initial active state from a genesis entry.
    /// </param>
    /// <param name="update">
    /// The function that advances the active state from an update entry.
    /// </param>
    /// <param name="deactivate">
    /// The function that produces the deactivated state from a deactivation entry.
    /// </param>
    /// <returns>A composable apply delegate.</returns>
    public static ApplyDelegate<TState, TOperation, TProof> CreateApplyDelegate<TState, TOperation, TProof>(
        Func<EmptyLogState<TState>, LogEntry<TOperation, TProof>, CancellationToken, ValueTask<(ActiveLogState<TState> State, string? Error)>> genesis,
        Func<ActiveLogState<TState>, LogEntry<TOperation, TProof>, CancellationToken, ValueTask<(ActiveLogState<TState> State, string? Error)>> update,
        Func<ActiveLogState<TState>, LogEntry<TOperation, TProof>, CancellationToken, ValueTask<(DeactivatedLogState<TState> State, string? Error)>> deactivate)
    {
        ArgumentNullException.ThrowIfNull(genesis);
        ArgumentNullException.ThrowIfNull(update);
        ArgumentNullException.ThrowIfNull(deactivate);

        return async (classification, currentState, entry, cancellationToken) =>
        {
            if(classification == LogEntryClassification.Genesis)
            {
                if(currentState is not EmptyLogState<TState> empty)
                {
                    return (currentState, $"Genesis entry received in state '{currentState.GetType().Name}'; expected '{nameof(EmptyLogState<TState>)}'.");
                }

                (ActiveLogState<TState> activeState, string? genesisError) = await genesis(empty, entry, cancellationToken).ConfigureAwait(false);
                return (activeState, genesisError);
            }

            if(classification == LogEntryClassification.Heartbeat)
            {
                //Heartbeat entries validate the chain and proofs but do not mutate state.
                return (currentState, null);
            }

            if(classification == LogEntryClassification.Update)
            {
                if(currentState is not ActiveLogState<TState> active)
                {
                    return (currentState, $"Update entry received in state '{currentState.GetType().Name}'; expected '{nameof(ActiveLogState<TState>)}'.");
                }

                (ActiveLogState<TState> updatedState, string? updateError) = await update(active, entry, cancellationToken).ConfigureAwait(false);
                return (updatedState, updateError);
            }

            if(classification == LogEntryClassification.Deactivate)
            {
                if(currentState is not ActiveLogState<TState> active)
                {
                    return (currentState, $"Deactivate entry received in state '{currentState.GetType().Name}'; expected '{nameof(ActiveLogState<TState>)}'.");
                }

                (DeactivatedLogState<TState> deactivatedState, string? deactivateError) = await deactivate(active, entry, cancellationToken).ConfigureAwait(false);
                return (deactivatedState, deactivateError);
            }

            //Unknown classifications are no-ops — the caller wraps this delegate to handle them.
            return (currentState, null);
        };
    }
}
