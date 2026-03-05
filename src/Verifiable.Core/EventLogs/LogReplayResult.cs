using System;
using System.Collections.Generic;

namespace Verifiable.Core.EventLogs;

/// <summary>
/// The result of processing a single <see cref="LogEntry{TOperation,TProof}"/>
/// during log replay.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/> emits one
/// <see cref="LogReplayResult{TState,TOperation,TProof}"/> per entry processed.
/// Downstream consumers receive the full entry, the log state after the entry
/// was applied, the classification of the entry, and any error that occurred.
/// </para>
/// <para>
/// When <see cref="Error"/> is non-null the replay stream has terminated. The
/// <see cref="State"/> reflects the last successfully applied log state before
/// the error, and <see cref="Entry"/> is the entry that caused the failure.
/// </para>
/// </remarks>
/// <typeparam name="TState">The domain state type.</typeparam>
/// <typeparam name="TOperation">The domain operation type.</typeparam>
/// <typeparam name="TProof">The proof type.</typeparam>
public sealed class LogReplayResult<TState, TOperation, TProof>
    : IEquatable<LogReplayResult<TState, TOperation, TProof>>
{
    /// <summary>
    /// Gets the entry that was processed to produce this result.
    /// </summary>
    public required LogEntry<TOperation, TProof> Entry { get; init; }

    /// <summary>
    /// Gets the log state after the entry was applied, or the last successfully
    /// applied log state when <see cref="Error"/> is non-null.
    /// </summary>
    public required LogState<TState> State { get; init; }

    /// <summary>
    /// Gets the classification of <see cref="Entry"/> as determined by the
    /// <see cref="ClassifyOperationDelegate{TOperation,TProof}"/> in the replay context.
    /// </summary>
    public required LogEntryClassification Classification { get; init; }

    /// <summary>
    /// Gets the error message when processing failed, or <see langword="null"/>
    /// when the entry was processed successfully.
    /// </summary>
    public required string? Error { get; init; }

    /// <summary>
    /// Gets a value indicating whether this result represents successful entry processing.
    /// </summary>
    public bool IsSuccess => Error is null;


    /// <inheritdoc/>
    public bool Equals(LogReplayResult<TState, TOperation, TProof>? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return Entry == other.Entry
            && EqualityComparer<LogState<TState>>.Default.Equals(State, other.State)
            && Classification == other.Classification
            && string.Equals(Error, other.Error, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is LogReplayResult<TState, TOperation, TProof> other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() =>
        HashCode.Combine(Entry, State, Classification, Error);

    /// <summary>
    /// Returns <see langword="true"/> if <paramref name="left"/> and
    /// <paramref name="right"/> are equal.
    /// </summary>
    public static bool operator ==(
        LogReplayResult<TState, TOperation, TProof>? left,
        LogReplayResult<TState, TOperation, TProof>? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>
    /// Returns <see langword="true"/> if <paramref name="left"/> and
    /// <paramref name="right"/> are not equal.
    /// </summary>
    public static bool operator !=(
        LogReplayResult<TState, TOperation, TProof>? left,
        LogReplayResult<TState, TOperation, TProof>? right) =>
        !(left == right);
}