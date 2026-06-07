using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Result of <see cref="EntityStatementParser.Parse"/>. Either carries a
/// classified <see cref="EntityStatement"/> (success) or a failure
/// reason describing why structural parsing failed.
/// </summary>
/// <remarks>
/// Structural-only outcome. <see cref="IsSuccess"/> does not imply
/// signature validity, expiry validity, or any deeper check — those
/// belong to <see cref="EntityStatementValidator"/> in chunk 4.
/// Mirrors the
/// <see cref="Verifiable.OAuth.Dpop.DpopProofValidationResult"/>
/// single-record-with-nullable-fields precedent.
/// </remarks>
[DebuggerDisplay("EntityStatementParseResult Success={IsSuccess} Reason={FailureReason,nq}")]
public sealed record EntityStatementParseResult
{
    /// <summary>The classified statement when parsing succeeded; otherwise <see langword="null"/>.</summary>
    public EntityStatement? Statement { get; init; }

    /// <summary>The reason structural parsing failed; <see langword="null"/> on success.</summary>
    public string? FailureReason { get; init; }

    /// <summary><see langword="true"/> when structural classification succeeded.</summary>
    public bool IsSuccess => FailureReason is null;


    /// <summary>Builds a success result wrapping the classified statement.</summary>
    public static EntityStatementParseResult Parsed(EntityStatement statement)
    {
        ArgumentNullException.ThrowIfNull(statement);
        return new EntityStatementParseResult { Statement = statement };
    }


    /// <summary>Builds a failure result with the given reason.</summary>
    public static EntityStatementParseResult Invalid(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return new EntityStatementParseResult { FailureReason = reason };
    }
}
