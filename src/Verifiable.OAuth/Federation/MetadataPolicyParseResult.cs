using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Result of <see cref="MetadataPolicyParser.Parse"/>. Either carries a
/// <see cref="MetadataPolicySnapshot"/> (success) or a structural-failure
/// reason. Mirrors the <see cref="EntityStatementParseResult"/> shape:
/// single sealed record with nullable fields + static factories.
/// </summary>
[DebuggerDisplay("MetadataPolicyParseResult Success={IsSuccess} Reason={FailureReason,nq}")]
public sealed record MetadataPolicyParseResult
{
    /// <summary>The parsed snapshot when parsing succeeded; otherwise <see langword="null"/>.</summary>
    public MetadataPolicySnapshot? Snapshot { get; init; }

    /// <summary>The reason structural parsing failed; <see langword="null"/> on success.</summary>
    public string? FailureReason { get; init; }

    /// <summary><see langword="true"/> when structural parsing succeeded.</summary>
    public bool IsSuccess => FailureReason is null;


    /// <summary>Builds a success result wrapping the snapshot.</summary>
    public static MetadataPolicyParseResult Parsed(MetadataPolicySnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        return new MetadataPolicyParseResult { Snapshot = snapshot };
    }


    /// <summary>Builds a failure result with the given reason.</summary>
    public static MetadataPolicyParseResult Invalid(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return new MetadataPolicyParseResult { FailureReason = reason };
    }
}
