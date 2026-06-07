using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Result of <see cref="TrustMarkParser.Parse"/>. Either carries a
/// classified <see cref="TrustMark"/> (success) or a structural failure
/// reason. Mirrors the
/// <see cref="EntityStatementParseResult"/> shape: single sealed record
/// with nullable fields + static factories.
/// </summary>
[DebuggerDisplay("TrustMarkParseResult Success={IsSuccess} Reason={FailureReason,nq}")]
public sealed record TrustMarkParseResult
{
    /// <summary>The classified trust mark when parsing succeeded; otherwise <see langword="null"/>.</summary>
    public TrustMark? Mark { get; init; }

    /// <summary>The reason structural parsing failed; <see langword="null"/> on success.</summary>
    public string? FailureReason { get; init; }

    /// <summary><see langword="true"/> when structural classification succeeded.</summary>
    public bool IsSuccess => FailureReason is null;


    /// <summary>Builds a success result wrapping the classified mark.</summary>
    public static TrustMarkParseResult Parsed(TrustMark mark)
    {
        ArgumentNullException.ThrowIfNull(mark);
        return new TrustMarkParseResult { Mark = mark };
    }


    /// <summary>Builds a failure result with the given reason.</summary>
    public static TrustMarkParseResult Invalid(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return new TrustMarkParseResult { FailureReason = reason };
    }
}
