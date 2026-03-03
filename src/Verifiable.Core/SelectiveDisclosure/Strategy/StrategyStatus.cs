namespace Verifiable.Core.SelectiveDisclosure.Strategy;

/// <summary>
/// The status of a strategy in the enumeration process.
/// </summary>
/// <remarks>
/// <para>
/// Strategies that are not <see cref="Feasible"/> are retained in the graph for
/// traceability — the decision record can explain why a lower-entropy strategy
/// was rejected by policy or found infeasible by constraints.
/// </para>
/// </remarks>
public enum StrategyStatus
{
    /// <summary>
    /// The strategy satisfies all requirements and passes all policy assessments.
    /// </summary>
    Feasible,

    /// <summary>
    /// The strategy was rejected by a policy assessor in the per-credential pipeline.
    /// </summary>
    PolicyRejected,

    /// <summary>
    /// The strategy was found infeasible by constraint satisfaction (e.g., the SAT solver
    /// determined no valid assignment exists under the mutual exclusion constraints).
    /// </summary>
    ConstraintInfeasible,

    /// <summary>
    /// The strategy is dominated by another strategy on all scoring dimensions.
    /// Retained in the graph for traceability but excluded from the Pareto frontier.
    /// </summary>
    Dominated
}