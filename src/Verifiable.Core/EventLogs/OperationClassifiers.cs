using System;

namespace Verifiable.Core.EventLogs;

/// <summary>
/// Provides factory methods for common <see cref="ClassifyOperationDelegate{TOperation,TProof}"/>
/// implementations.
/// </summary>
public static class OperationClassifiers
{
    /// <summary>
    /// Returns a classifier that treats the entry at index zero as
    /// <see cref="LogEntryClassification.Genesis"/> and all subsequent entries
    /// as <see cref="LogEntryClassification.Update"/>.
    /// </summary>
    /// <remarks>
    /// This is the minimal correct classifier for logs that do not distinguish
    /// deactivation or heartbeat entries at the structural level, such as simple
    /// supply chain event logs or CRDT delta logs.
    /// </remarks>
    /// <typeparam name="TOperation">The domain operation type.</typeparam>
    /// <typeparam name="TProof">The proof type.</typeparam>
    /// <returns>A classifier delegate.</returns>
    public static ClassifyOperationDelegate<TOperation, TProof> ByIndex<TOperation, TProof>() =>
        static entry => entry.Index is 0
            ? LogEntryClassification.Genesis
            : LogEntryClassification.Update;

    /// <summary>
    /// Returns a classifier that delegates to <paramref name="classifyOperation"/>
    /// for entries that carry a non-null operation, and returns
    /// <see cref="LogEntryClassification.Heartbeat"/> for entries whose
    /// <see cref="LogEntry{TOperation,TProof}.Operation"/> is <see langword="null"/>.
    /// </summary>
    /// <remarks>
    /// Use this classifier for DID event logs that support heartbeat entries —
    /// entries that re-witness the current digest without mutating state.
    /// </remarks>
    /// <typeparam name="TOperation">The domain operation type.</typeparam>
    /// <typeparam name="TProof">The proof type.</typeparam>
    /// <param name="classifyOperation">
    /// The delegate to invoke for entries that carry an operation.
    /// </param>
    /// <returns>A classifier delegate.</returns>
    public static ClassifyOperationDelegate<TOperation, TProof> WithHeartbeat<TOperation, TProof>(
        ClassifyOperationDelegate<TOperation, TProof> classifyOperation)
    {
        ArgumentNullException.ThrowIfNull(classifyOperation);

        return entry => entry.Operation is null
            ? LogEntryClassification.Heartbeat
            : classifyOperation(entry);
    }
}