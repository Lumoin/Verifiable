using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Result of <see cref="TrustMarkDelegationParser.Parse"/>. Mirrors the
/// other federation parse-result shapes: sealed record with nullable
/// fields + static factories.
/// </summary>
[DebuggerDisplay("TrustMarkDelegationParseResult Success={IsSuccess} Reason={FailureReason,nq}")]
public sealed record TrustMarkDelegationParseResult
{
    /// <summary>The classified delegation when parsing succeeded.</summary>
    public TrustMarkDelegation? Delegation { get; init; }

    /// <summary>The reason structural parsing failed.</summary>
    public string? FailureReason { get; init; }

    /// <summary><see langword="true"/> when structural classification succeeded.</summary>
    public bool IsSuccess => FailureReason is null;


    /// <summary>Builds a success result.</summary>
    public static TrustMarkDelegationParseResult Parsed(TrustMarkDelegation delegation)
    {
        ArgumentNullException.ThrowIfNull(delegation);
        return new TrustMarkDelegationParseResult { Delegation = delegation };
    }


    /// <summary>Builds a failure result.</summary>
    public static TrustMarkDelegationParseResult Invalid(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return new TrustMarkDelegationParseResult { FailureReason = reason };
    }
}
