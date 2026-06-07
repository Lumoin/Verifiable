using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Result of <see cref="MetadataPolicyApplicator.Apply"/> and its
/// raw-dictionary overload. Either carries the effective metadata
/// (success) or a structured failure reason (constraint violation,
/// missing essential parameter, malformed operator value).
/// </summary>
/// <remarks>
/// Mirrors the
/// <see cref="MetadataPolicyParseResult"/> / <see cref="MetadataPolicyMergeResult"/>
/// shape: single sealed record with nullable fields + static factories.
/// </remarks>
[DebuggerDisplay("MetadataPolicyApplyResult Success={IsSuccess} Reason={FailureReason,nq}")]
public sealed record MetadataPolicyApplyResult
{
    /// <summary>The effective metadata when success; otherwise <see langword="null"/>.</summary>
    public IReadOnlyDictionary<string, object>? EffectiveMetadata { get; init; }

    /// <summary>The reason apply failed; <see langword="null"/> on success.</summary>
    public string? FailureReason { get; init; }

    /// <summary><see langword="true"/> when apply succeeded.</summary>
    public bool IsSuccess => FailureReason is null;


    /// <summary>Builds a success result wrapping the effective metadata.</summary>
    public static MetadataPolicyApplyResult Applied(IReadOnlyDictionary<string, object> effectiveMetadata)
    {
        ArgumentNullException.ThrowIfNull(effectiveMetadata);
        return new MetadataPolicyApplyResult { EffectiveMetadata = effectiveMetadata };
    }


    /// <summary>Builds a failure result with the given reason.</summary>
    public static MetadataPolicyApplyResult Failed(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return new MetadataPolicyApplyResult { FailureReason = reason };
    }
}
