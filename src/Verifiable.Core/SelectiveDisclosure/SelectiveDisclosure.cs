using System;
using System.Collections.Generic;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// Result of a disclosure selection operation.
/// </summary>
/// <typeparam name="TClaim">The type representing individual claims.</typeparam>
/// <param name="SelectedClaims">The claims selected for disclosure.</param>
/// <param name="SatisfiesRequirements">Whether all verifier requirements are satisfied.</param>
/// <param name="UnavailableClaims">Claims requested but not available in the credential.</param>
/// <param name="ConflictingClaims">Claims that conflict with user exclusions.</param>
public readonly record struct DisclosureSelectionResult<TClaim>(
    IReadOnlySet<TClaim> SelectedClaims,
    bool SatisfiesRequirements,
    IReadOnlySet<TClaim>? UnavailableClaims = null,
    IReadOnlySet<TClaim>? ConflictingClaims = null)
{
    /// <summary>
    /// Gets whether the selection has any issues (unavailable or conflicting claims).
    /// </summary>
    public bool HasIssues => (UnavailableClaims?.Count ?? 0) > 0 || (ConflictingClaims?.Count ?? 0) > 0;
}


/// <summary>
/// Result of multi-credential selection.
/// </summary>
/// <typeparam name="TCredential">The type representing credentials.</typeparam>
/// <typeparam name="TClaim">The type representing individual claims.</typeparam>
/// <param name="Selections">The selected credentials with their disclosure sets.</param>
/// <param name="SatisfiesAllRequirements">Whether all requirements are satisfied.</param>
/// <param name="UnsatisfiedRequirements">Requirements that could not be satisfied, if any.</param>
public readonly record struct MultiCredentialSelectionResult<TCredential, TClaim>(
    IReadOnlyList<(TCredential Credential, IReadOnlySet<TClaim> Disclosures)> Selections,
    bool SatisfiesAllRequirements,
    IReadOnlySet<TClaim>? UnsatisfiedRequirements = null);


/// <summary>
/// Selective disclosure operations using lattice theory.
/// </summary>
/// <remarks>
/// <para>
/// This class provides algorithms for selecting which claims to disclose from
/// verifiable credentials. The operations are based on bounded lattice theory:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Minimum Disclosure</strong>: The smallest valid disclosure set satisfying all requirements.
/// Computed as Join(verifierRequested, regulatoryMandated, structurallyRequired).
/// </description></item>
/// <item><description>
/// <strong>Maximum Disclosure</strong>: The largest disclosure set respecting user preferences.
/// Computed as Top - userExclusions.
/// </description></item>
/// <item><description>
/// <strong>Optimal Disclosure</strong>: Minimum if it fits within Maximum, otherwise conflict.
/// </description></item>
/// </list>
/// <para>
/// <strong>Request Normalization</strong>
/// </para>
/// <para>
/// External requests (e.g., from verifiers) are normalized before processing:
/// </para>
/// <list type="bullet">
/// <item><description>Claims already mandatory are automatically satisfied.</description></item>
/// <item><description>Claims not in the credential are reported as unavailable.</description></item>
/// <item><description>Only selectable claims need actual selection decisions.</description></item>
/// </list>
/// </remarks>
public static class SelectiveDisclosure
{
    /// <summary>
    /// Computes the minimum disclosure set that satisfies all requirements.
    /// </summary>
    /// <typeparam name="TClaim">The type representing individual claims.</typeparam>
    /// <param name="lattice">The bounded disclosure lattice.</param>
    /// <param name="verifierRequested">Claims requested by the verifier.</param>
    /// <param name="regulatoryMandated">Claims mandated by regulations.</param>
    /// <param name="structurallyRequired">Claims structurally required (e.g., parent paths).</param>
    /// <returns>
    /// A tuple containing the minimum disclosure set and any unavailable claims.
    /// The disclosure set always includes all mandatory claims (Bottom).
    /// </returns>
    /// <remarks>
    /// <para>
    /// Minimum = Bottom ∪ (verifierRequested ∩ Selectable) ∪ (regulatoryMandated ∩ Selectable) ∪ (structurallyRequired ∩ Selectable).
    /// </para>
    /// <para>
    /// Claims not in Top are reported as unavailable but don't prevent selection.
    /// </para>
    /// </remarks>
    public static (IReadOnlySet<TClaim> Disclosures, IReadOnlySet<TClaim> Unavailable) ComputeMinimumDisclosure<TClaim>(
        IBoundedDisclosureLattice<TClaim> lattice,
        IReadOnlySet<TClaim>? verifierRequested = null,
        IReadOnlySet<TClaim>? regulatoryMandated = null,
        IReadOnlySet<TClaim>? structurallyRequired = null)
    {
        ArgumentNullException.ThrowIfNull(lattice);

        //Start with mandatory claims (bottom).
        var result = new HashSet<TClaim>(lattice.Bottom);
        var unavailable = new HashSet<TClaim>();

        //Process verifier requested.
        if(verifierRequested is not null)
        {
            var normalized = lattice.NormalizeRequest(verifierRequested);
            result.UnionWith(normalized.SelectableClaims);
            result.UnionWith(normalized.MandatoryClaims);
            unavailable.UnionWith(normalized.UnavailableClaims);
        }

        //Process regulatory mandated.
        if(regulatoryMandated is not null)
        {
            var normalized = lattice.NormalizeRequest(regulatoryMandated);
            result.UnionWith(normalized.SelectableClaims);
            result.UnionWith(normalized.MandatoryClaims);
            unavailable.UnionWith(normalized.UnavailableClaims);
        }

        //Process structurally required.
        if(structurallyRequired is not null)
        {
            var normalized = lattice.NormalizeRequest(structurallyRequired);
            result.UnionWith(normalized.SelectableClaims);
            result.UnionWith(normalized.MandatoryClaims);
            unavailable.UnionWith(normalized.UnavailableClaims);
        }

        return (result, unavailable);
    }


    /// <summary>
    /// Computes the maximum disclosure set respecting user preferences.
    /// </summary>
    /// <typeparam name="TClaim">The type representing individual claims.</typeparam>
    /// <param name="lattice">The bounded disclosure lattice.</param>
    /// <param name="userExclusions">Claims the user wants to exclude.</param>
    /// <returns>The maximum disclosure set.</returns>
    /// <remarks>
    /// <para>
    /// Maximum = Top - (userExclusions ∩ Selectable).
    /// </para>
    /// <para>
    /// User cannot exclude mandatory claims (Bottom). Exclusions of mandatory
    /// claims are silently ignored.
    /// </para>
    /// </remarks>
    public static IReadOnlySet<TClaim> ComputeMaximumDisclosure<TClaim>(
        IBoundedDisclosureLattice<TClaim> lattice,
        IReadOnlySet<TClaim>? userExclusions = null)
    {
        ArgumentNullException.ThrowIfNull(lattice);

        var result = new HashSet<TClaim>(lattice.Top);

        if(userExclusions is not null)
        {
            //Only exclude selectable claims, not mandatory ones.
            foreach(var claim in userExclusions)
            {
                if(lattice.Selectable.Contains(claim))
                {
                    result.Remove(claim);
                }
            }
        }

        return result;
    }


    /// <summary>
    /// Computes the optimal disclosure set.
    /// </summary>
    /// <typeparam name="TClaim">The type representing individual claims.</typeparam>
    /// <param name="lattice">The bounded disclosure lattice.</param>
    /// <param name="verifierRequested">Claims requested by the verifier.</param>
    /// <param name="userExclusions">Claims the user wants to exclude.</param>
    /// <param name="regulatoryMandated">Claims mandated by regulations.</param>
    /// <param name="structurallyRequired">Claims structurally required.</param>
    /// <returns>
    /// The optimal disclosure result containing the selected claims, satisfaction status,
    /// and any unavailable or conflicting claims.
    /// </returns>
    /// <remarks>
    /// <para>
    /// Optimal selection algorithm:
    /// </para>
    /// <list type="number">
    /// <item><description>Normalize all requests to filter out unavailable claims.</description></item>
    /// <item><description>Compute minimum disclosure from normalized requests.</description></item>
    /// <item><description>Compute maximum disclosure respecting user exclusions.</description></item>
    /// <item><description>If minimum ⊆ maximum, return minimum (requirements satisfied).</description></item>
    /// <item><description>Otherwise, return best effort with conflict information.</description></item>
    /// </list>
    /// <para>
    /// A conflict occurs when verifier/regulatory requirements include claims
    /// that the user has excluded. In this case, <see cref="DisclosureSelectionResult{TClaim}.SatisfiesRequirements"/>
    /// is false and <see cref="DisclosureSelectionResult{TClaim}.ConflictingClaims"/> contains the conflicts.
    /// </para>
    /// </remarks>
    public static DisclosureSelectionResult<TClaim> ComputeOptimalDisclosure<TClaim>(
        IBoundedDisclosureLattice<TClaim> lattice,
        IReadOnlySet<TClaim>? verifierRequested = null,
        IReadOnlySet<TClaim>? userExclusions = null,
        IReadOnlySet<TClaim>? regulatoryMandated = null,
        IReadOnlySet<TClaim>? structurallyRequired = null)
    {
        ArgumentNullException.ThrowIfNull(lattice);

        var (minimum, unavailable) = ComputeMinimumDisclosure(
            lattice,
            verifierRequested,
            regulatoryMandated,
            structurallyRequired);

        var maximum = ComputeMaximumDisclosure(lattice, userExclusions);

        //Check if minimum fits within maximum.
        if(minimum.IsSubsetOf(maximum))
        {
            //All requirements satisfied.
            return new DisclosureSelectionResult<TClaim>(
                SelectedClaims: minimum,
                SatisfiesRequirements: unavailable.Count == 0,
                UnavailableClaims: unavailable.Count > 0 ? unavailable : null);
        }

        //Conflict: minimum requires claims that user has excluded.
        var conflicts = new HashSet<TClaim>();
        foreach(var claim in minimum)
        {
            if(!maximum.Contains(claim))
            {
                conflicts.Add(claim);
            }
        }

        //Return best effort: intersection of minimum and maximum, plus mandatory.
        var bestEffort = new HashSet<TClaim>(minimum);
        bestEffort.IntersectWith(maximum);
        bestEffort.UnionWith(lattice.Bottom);

        return new DisclosureSelectionResult<TClaim>(
            SelectedClaims: bestEffort,
            SatisfiesRequirements: false,
            UnavailableClaims: unavailable.Count > 0 ? unavailable : null,
            ConflictingClaims: conflicts);
    }


    /// <summary>
    /// Selects credentials and disclosures to satisfy requirements from multiple credentials.
    /// </summary>
    /// <typeparam name="TCredential">The type representing credentials.</typeparam>
    /// <typeparam name="TClaim">The type representing individual claims.</typeparam>
    /// <param name="credentials">Available credentials with their lattices.</param>
    /// <param name="requirements">Required claims to satisfy.</param>
    /// <param name="userExclusions">Per-credential user exclusions.</param>
    /// <returns>The selection result with chosen credentials and disclosures.</returns>
    /// <remarks>
    /// <para>
    /// Uses a greedy algorithm to select credentials:
    /// </para>
    /// <list type="number">
    /// <item><description>For each credential, compute what requirements it can satisfy.</description></item>
    /// <item><description>Select the credential that satisfies the most remaining requirements.</description></item>
    /// <item><description>Repeat until all requirements are satisfied or no progress can be made.</description></item>
    /// </list>
    /// <para>
    /// This is a heuristic that may not find the optimal solution (minimum credentials)
    /// but runs in polynomial time.
    /// </para>
    /// </remarks>
    public static MultiCredentialSelectionResult<TCredential, TClaim> SelectCredentials<TCredential, TClaim>(
        IReadOnlyList<(TCredential Credential, IBoundedDisclosureLattice<TClaim> Lattice)> credentials,
        IReadOnlySet<TClaim> requirements,
        IReadOnlyDictionary<TCredential, IReadOnlySet<TClaim>>? userExclusions = null)
        where TCredential : notnull
    {
        ArgumentNullException.ThrowIfNull(credentials);
        ArgumentNullException.ThrowIfNull(requirements);

        var unsatisfied = new HashSet<TClaim>(requirements);
        var selections = new List<(TCredential Credential, IReadOnlySet<TClaim> Disclosures)>();
        var usedCredentials = new HashSet<TCredential>();

        while(unsatisfied.Count > 0)
        {
            //Find the best credential to satisfy remaining requirements.
            (TCredential Credential, IBoundedDisclosureLattice<TClaim> Lattice)? bestCandidate = null;
            IReadOnlySet<TClaim>? bestDisclosure = null;
            int bestCoverage = 0;

            foreach(var (credential, lattice) in credentials)
            {
                if(usedCredentials.Contains(credential))
                {
                    continue;
                }

                //Compute what this credential can satisfy.
                var canSatisfy = new HashSet<TClaim>(unsatisfied);
                canSatisfy.IntersectWith(lattice.Top);

                if(canSatisfy.Count == 0)
                {
                    continue;
                }

                //Compute optimal disclosure for this credential.
                IReadOnlySet<TClaim>? exclusions = null;
                userExclusions?.TryGetValue(credential, out exclusions);
                var result = ComputeOptimalDisclosure(
                    lattice,
                    verifierRequested: canSatisfy,
                    userExclusions: exclusions);

                //Count how many requirements this satisfies.
                var satisfies = new HashSet<TClaim>(result.SelectedClaims);
                satisfies.IntersectWith(unsatisfied);

                if(satisfies.Count > bestCoverage)
                {
                    bestCandidate = (credential, lattice);
                    bestDisclosure = result.SelectedClaims;
                    bestCoverage = satisfies.Count;
                }
            }

            //No credential can satisfy remaining requirements.
            if(bestCandidate is null || bestDisclosure is null)
            {
                break;
            }

            //Add selection.
            selections.Add((bestCandidate.Value.Credential, bestDisclosure));
            usedCredentials.Add(bestCandidate.Value.Credential);

            //Remove satisfied requirements.
            unsatisfied.ExceptWith(bestDisclosure);
        }

        return new MultiCredentialSelectionResult<TCredential, TClaim>(
            Selections: selections,
            SatisfiesAllRequirements: unsatisfied.Count == 0,
            UnsatisfiedRequirements: unsatisfied.Count > 0 ? unsatisfied : null);
    }


    /// <summary>
    /// Validates that a disclosure set satisfies the given requirements.
    /// </summary>
    /// <typeparam name="TClaim">The type representing individual claims.</typeparam>
    /// <param name="lattice">The bounded disclosure lattice.</param>
    /// <param name="disclosures">The disclosure set to validate.</param>
    /// <param name="requirements">The requirements to check against.</param>
    /// <returns><see langword="true"/> if all requirements are satisfied; otherwise <see langword="false"/>.</returns>
    public static bool ValidateDisclosure<TClaim>(
        IBoundedDisclosureLattice<TClaim> lattice,
        IReadOnlySet<TClaim> disclosures,
        IReadOnlySet<TClaim> requirements)
    {
        ArgumentNullException.ThrowIfNull(lattice);
        ArgumentNullException.ThrowIfNull(disclosures);
        ArgumentNullException.ThrowIfNull(requirements);

        //Must be valid within lattice bounds.
        if(!lattice.IsValid(disclosures))
        {
            return false;
        }

        //Must satisfy all requirements that are available in the credential.
        var normalized = lattice.NormalizeRequest(requirements);
        var satisfiableRequirements = new HashSet<TClaim>(normalized.SelectableClaims);
        satisfiableRequirements.UnionWith(normalized.MandatoryClaims);

        return satisfiableRequirements.IsSubsetOf(disclosures);
    }
}
