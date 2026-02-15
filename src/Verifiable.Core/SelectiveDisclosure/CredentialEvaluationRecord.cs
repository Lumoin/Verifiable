using System.Diagnostics;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// Captures the outcome of evaluating a single credential against a query requirement.
/// </summary>
/// <remarks>
/// This is a diagnostic record for audit trails. The credential is stored as
/// <see cref="object"/> to avoid propagating generic type parameters through
/// the entire decision record hierarchy.
/// </remarks>
[DebuggerDisplay("Eval(QueryId={QueryRequirementId}, Matched={Matched})")]
public sealed class CredentialEvaluationRecord
{
    /// <summary>
    /// The credential that was evaluated.
    /// </summary>
    public required object Credential { get; init; }

    /// <summary>
    /// The query requirement this evaluation was against.
    /// </summary>
    public required string QueryRequirementId { get; init; }

    /// <summary>
    /// Whether the credential matched the requirement.
    /// </summary>
    public required bool Matched { get; init; }

    /// <summary>
    /// Human-readable reason for non-match, when <see cref="Matched"/> is <see langword="false"/>.
    /// </summary>
    public string? FailureReason { get; init; }
}