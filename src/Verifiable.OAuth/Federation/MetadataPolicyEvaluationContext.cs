using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// <see cref="ClaimContext"/> carrying the offending parameter and the
/// operator pair that violates the §6.1.3.1.8 compatibility table when
/// <see cref="MetadataPolicyEvaluator"/> rejects a policy.
/// </summary>
/// <remarks>
/// The first incompatible pair encountered during evaluation is the one
/// reported — the evaluator stops at the first violation rather than
/// enumerating every conflict, mirroring the structural-parse-first
/// pattern used elsewhere in Federation.
/// </remarks>
public sealed record MetadataPolicyEvaluationContext: ClaimContext
{
    /// <summary>The entity type whose policy contained the violation.</summary>
    public required EntityTypeIdentifier EntityType { get; init; }

    /// <summary>The parameter whose operator combination violated the table.</summary>
    public required string ParameterName { get; init; }

    /// <summary>The first operator in the incompatible pair (declaration order).</summary>
    public required MetadataPolicyOperator FirstOperator { get; init; }

    /// <summary>The second operator in the incompatible pair (declaration order).</summary>
    public required MetadataPolicyOperator SecondOperator { get; init; }
}
