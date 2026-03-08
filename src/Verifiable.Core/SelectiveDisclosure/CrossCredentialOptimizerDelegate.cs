using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// Optimizes disclosure decisions across multiple credentials simultaneously.
/// </summary>
/// <remarks>
/// <para>
/// Cross-credential optimizers run after the per-credential policy pipeline completes.
/// They receive the full set of per-credential decisions and can redistribute paths
/// across credentials to achieve a global optimum while respecting each credential's
/// lattice bounds (Bottom ⊆ S ⊆ Top for every credential).
/// </para>
/// <para>
/// <strong>Bounded convergence:</strong> Every optimizer must produce decisions where
/// each credential's selected paths remain within its lattice bounds. The
/// <see cref="DisclosureComputation{TCredential}"/> validates this postcondition and
/// records any bound violations in the decision record. Convergence is guaranteed
/// because the combined space of valid disclosure strategies is finite (bounded by
/// the product of each credential's lattice cardinality).
/// </para>
/// <para>
/// <strong>Optimizer implementations:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// SAT solver: Models multi-credential constraints as boolean satisfiability.
/// For example, "disclose name from credential A OR credential B, but never both
/// SSNs" becomes a conjunction of clauses over boolean path variables. The solver
/// finds a satisfying assignment that minimizes total disclosure.
/// </description></item>
/// <item><description>
/// ILP solver: Models disclosure cost as a linear objective weighted by data
/// sensitivity scores with lattice bounds as constraints, and finds the
/// minimum-cost feasible solution across all credentials.
/// </description></item>
/// <item><description>
/// LLM-based reasoner: Evaluates the combined disclosure strategy against
/// contextual signals and proposes redistributions. Wrapped in a bounds-checking
/// harness that rejects any proposal violating lattice constraints.
/// </description></item>
/// </list>
/// <para>
/// <strong>Risk tolerance:</strong> Optimizers may receive a risk tolerance parameter
/// through the <paramref name="signals"/> dictionary. A risk-averse setting drives
/// toward minimum disclosure; a risk-tolerant setting may allow broader disclosure
/// when the verifier trust level is high.
/// </para>
/// </remarks>
/// <typeparam name="TCredential">The application-specific credential type.</typeparam>
/// <param name="decisions">
/// The per-credential decisions produced by the per-credential policy pipeline.
/// Each decision carries its lattice, enabling the optimizer to verify bounds.
/// </param>
/// <param name="signals">
/// Contextual signals from the requesting party and environment. May include
/// risk tolerance parameters, verifier trust assessments, and regulatory context.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The optimized decisions. May reorder, expand, or narrow individual decisions,
/// but each decision's selected paths must remain within its lattice bounds.
/// </returns>
public delegate Task<IReadOnlyList<CredentialDisclosureDecision<TCredential>>>
    CrossCredentialOptimizerDelegate<TCredential>(
        IReadOnlyList<CredentialDisclosureDecision<TCredential>> decisions,
        IReadOnlyDictionary<Type, object>? signals,
        CancellationToken cancellationToken);
