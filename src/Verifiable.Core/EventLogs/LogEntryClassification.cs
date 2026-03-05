using System;

namespace Verifiable.Core.EventLogs;

/// <summary>
/// An open, extensible discriminator that identifies the kind of operation
/// carried by a <see cref="LogEntry{TOperation,TProof}"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="LogEntryClassification"/> is a value-typed dynamic enum — a
/// thin wrapper over a string constant that allows callers to define their
/// own classifications without modifying the infrastructure. Built-in
/// constants cover the four operation kinds common across DID event logs:
/// <see cref="Genesis"/>, <see cref="Update"/>, <see cref="Deactivate"/>,
/// and <see cref="Heartbeat"/>.
/// </para>
/// <para>
/// Method-specific log implementations may define additional constants in
/// their own namespaces and pass them through the
/// <see cref="ClassifyOperationDelegate{TOperation,TProof}"/> injected into
/// <see cref="LogReplayContext{TState,TOperation,TProof,TContext}"/>.
/// </para>
/// </remarks>
public readonly struct LogEntryClassification
    : IEquatable<LogEntryClassification>
{
    /// <summary>
    /// The genesis entry — the first entry in a log that establishes the
    /// initial state. Exactly one genesis entry exists per log, at index zero.
    /// </summary>
    public static readonly LogEntryClassification Genesis = new("genesis");

    /// <summary>
    /// An update entry — an entry that transitions the current state forward.
    /// </summary>
    public static readonly LogEntryClassification Update = new("update");

    /// <summary>
    /// A deactivation entry — an entry that marks the subject of the log as
    /// permanently deactivated. No further state-mutating entries are valid
    /// after a deactivation entry.
    /// </summary>
    public static readonly LogEntryClassification Deactivate = new("deactivate");

    /// <summary>
    /// A heartbeat entry — an entry that re-witnesses the current digest to
    /// establish liveness without mutating state. The
    /// <see cref="LogEntry{TOperation,TProof}.Operation"/> of a heartbeat
    /// entry is <see langword="null"/>.
    /// </summary>
    public static readonly LogEntryClassification Heartbeat = new("heartbeat");


    private readonly string Value { get; }

    /// <summary>
    /// Initializes a new <see cref="LogEntryClassification"/> with the given value.
    /// </summary>
    /// <param name="value">The string value identifying the classification.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="value"/> is <see langword="null"/>.
    /// </exception>
    public LogEntryClassification(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        Value = value;
    }


    /// <inheritdoc/>
    public bool Equals(LogEntryClassification other) =>
        string.Equals(Value, other.Value, StringComparison.Ordinal);

    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is LogEntryClassification other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() =>
        Value?.GetHashCode(StringComparison.Ordinal) ?? 0;

    /// <inheritdoc/>
    public override string ToString() => Value ?? string.Empty;

    /// <summary>
    /// Returns <see langword="true"/> if <paramref name="left"/> and
    /// <paramref name="right"/> are equal.
    /// </summary>
    public static bool operator ==(LogEntryClassification left, LogEntryClassification right) =>
        left.Equals(right);

    /// <summary>
    /// Returns <see langword="true"/> if <paramref name="left"/> and
    /// <paramref name="right"/> are not equal.
    /// </summary>
    public static bool operator !=(LogEntryClassification left, LogEntryClassification right) =>
        !(left == right);
}