using System;
using System.Collections.Generic;

namespace Verifiable.Core.SelectiveDisclosure.Strategy;

/// <summary>
/// Delegate for computing the entropy of a disclosure strategy.
/// </summary>
/// <typeparam name="TCredential">The type representing credentials.</typeparam>
/// <param name="contributions">All credential contributions in the strategy.</param>
/// <param name="signals">Requesting party signals and attestation metadata.</param>
/// <returns>
/// The computed entropy score. Lower values indicate less identifying information released.
/// </returns>
/// <remarks>
/// <para>
/// The simplest implementation sums <see cref="PathContribution.EntropyWeight"/> across
/// all contributions. More sophisticated implementations can account for:
/// </para>
/// <list type="bullet">
/// <item><description>
/// Correlation effects: birthdate + postal code together is more identifying than
/// their individual weights summed, because they narrow the population multiplicatively.
/// </description></item>
/// <item><description>
/// Temporal context: a credential disclosed yesterday to the same verifier adds
/// zero marginal entropy (the verifier already knows the values).
/// </description></item>
/// <item><description>
/// Population-specific distributions: "Smith" as a family name in England has lower
/// entropy (common) than in Japan (rare).
/// </description></item>
/// </list>
/// <para>
/// Deployments provide their own entropy model via this delegate. The default
/// additive model (<see cref="DisclosureStrategyGraph{TCredential}.AdditiveEntropy"/>)
/// is suitable when path entropy weights are pre-computed and approximately independent.
/// </para>
/// </remarks>
public delegate double EntropyComputeDelegate<TCredential>(
    IReadOnlyList<CredentialContribution<TCredential>> contributions,
    IReadOnlyDictionary<Type, object>? signals);


/// <summary>
/// Delegate for extracting the Pareto frontier from a set of scored strategies.
/// </summary>
/// <typeparam name="TCredential">The type representing credentials.</typeparam>
/// <param name="strategies">All feasible strategies with their scores.</param>
/// <returns>
/// The subset of strategies on the Pareto frontier — those not dominated by any other
/// strategy across all scoring dimensions.
/// </returns>
/// <remarks>
/// <para>
/// A strategy A dominates strategy B if A is better than or equal to B on all dimensions
/// and strictly better on at least one. The Pareto frontier contains all non-dominated
/// strategies. Different deployments weight dimensions differently:
/// </para>
/// <list type="bullet">
/// <item><description>
/// Healthcare: heavily penalizes entropy (patient privacy paramount).
/// </description></item>
/// <item><description>
/// Supply chain: penalizes credential count (fewer round-trips, lower latency).
/// </description></item>
/// <item><description>
/// Regulatory compliance: requires minimum entropy disclosure that satisfies all
/// legal mandates (cannot trade entropy for fewer credentials if regulation requires
/// specific attributes).
/// </description></item>
/// </list>
/// </remarks>
public delegate IReadOnlyList<ScoredStrategy<TCredential>> FrontierExtractDelegate<TCredential>(
    IReadOnlyList<ScoredStrategy<TCredential>> strategies);