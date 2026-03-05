using System;

namespace Verifiable.Core.EventLogs;

/// <summary>
/// Groups all delegates and configuration required to replay an
/// authenticated append-only log.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="LogReplayContext{TState,TOperation,TProof,TContext}"/> is the
/// single injection point for all caller-supplied behavior. The replayer
/// holds no state and no policy — it drives the delegates in order for each
/// entry and emits results.
/// </para>
/// <para>
/// <typeparamref name="TContext"/> is the caller-defined proof validation
/// context. It carries trust anchors, a <see cref="System.TimeProvider"/>,
/// revocation information, and any other inputs required by
/// <see cref="ValidateProof"/>. The replayer passes it through to the
/// delegate unchanged.
/// </para>
/// <para>
/// The <see cref="Apply"/> delegate is the single dispatch point for all state
/// transitions. The library provides composable base implementations via
/// <see cref="LogReplayDefaults.CreateApplyDelegate{TState,TOperation,TProof}"/>.
/// Callers wrap the base delegate to handle custom classifications, exactly as
/// a format reader delegate chains to its base for unrecognized inputs.
/// </para>
/// </remarks>
/// <typeparam name="TState">The domain state type.</typeparam>
/// <typeparam name="TOperation">The domain operation type.</typeparam>
/// <typeparam name="TProof">The proof type.</typeparam>
/// <typeparam name="TContext">The caller-defined proof validation context type.</typeparam>
public sealed class LogReplayContext<TState, TOperation, TProof, TContext>
{
    /// <summary>
    /// Gets the delegate that classifies each entry before dispatch.
    /// </summary>
    public required ClassifyOperationDelegate<TOperation, TProof> Classify { get; init; }

    /// <summary>
    /// Gets the delegate that verifies hash-chain or Merkle-inclusion integrity
    /// for each entry.
    /// </summary>
    public required VerifyChainIntegrityDelegate<TOperation, TProof> VerifyChainIntegrity { get; init; }

    /// <summary>
    /// Gets the delegate that validates the proofs carried by each entry.
    /// </summary>
    public required ValidateProofDelegate<TState, TOperation, TProof, TContext> ValidateProof { get; init; }

    /// <summary>
    /// Gets the caller-defined context passed to <see cref="ValidateProof"/>.
    /// </summary>
    public required TContext ValidationContext { get; init; }

    /// <summary>
    /// Gets the delegate that applies a classified entry to the current log state.
    /// </summary>
    /// <remarks>
    /// This single delegate replaces separate genesis, update, and deactivate
    /// delegates. The caller pattern-matches on the classification and log state
    /// variant to implement all required transitions. Use
    /// <see cref="LogReplayDefaults.CreateApplyDelegate{TState,TOperation,TProof}"/>
    /// to obtain a composable base implementation.
    /// </remarks>
    public required ApplyDelegate<TState, TOperation, TProof> Apply { get; init; }

    /// <summary>
    /// Gets the optional delegate called after each entry is successfully processed,
    /// or <see langword="null"/> when no listener is attached.
    /// </summary>
    public OnEntryProcessedDelegate<TState, TOperation, TProof>? OnEntryProcessed { get; init; }

    /// <summary>
    /// Gets the <see cref="System.TimeProvider"/> used to validate temporal
    /// constraints during replay, such as ensuring version times do not exceed
    /// the current time.
    /// </summary>
    public required System.TimeProvider TimeProvider { get; init; }
}