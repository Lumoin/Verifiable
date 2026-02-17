using System;
using System.Collections.Generic;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Core.Model.Dcql;

namespace Verifiable.Core.Dcql;

/// <summary>
/// Resolves DCQL <see cref="DcqlClaimPattern"/> query patterns into concrete
/// <see cref="CredentialPath"/> values suitable for lattice operations.
/// </summary>
/// <remarks>
/// <para>
/// DCQL claim patterns may contain wildcards (null elements in the wire format
/// meaning "all array items"). The lattice and disclosure computation operate
/// on concrete <see cref="CredentialPath"/> addresses. This class bridges
/// the two by resolving concrete patterns directly and providing matching
/// utilities for wildcard patterns.
/// </para>
/// <para>
/// <strong>Resolution rules:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// Concrete patterns (no wildcards) resolve directly via
/// <see cref="DcqlClaimPattern.TryResolve"/>.
/// </description></item>
/// <item><description>
/// Wildcard patterns are resolved by matching against a set of known
/// <see cref="CredentialPath"/> values from the credential's metadata.
/// </description></item>
/// </list>
/// </remarks>
public static class DcqlPathResolver
{
    /// <summary>
    /// Resolves a set of <see cref="DcqlClaimPattern"/> values to concrete
    /// <see cref="CredentialPath"/> values.
    /// </summary>
    /// <param name="patterns">The DCQL claim patterns to resolve.</param>
    /// <param name="availablePaths">
    /// All concrete paths available in the credential, used for wildcard expansion.
    /// When null, wildcard patterns are skipped.
    /// </param>
    /// <returns>The resolved credential paths.</returns>
    public static HashSet<CredentialPath> ResolveAll(
        IEnumerable<DcqlClaimPattern> patterns,
        IReadOnlySet<CredentialPath>? availablePaths = null)
    {
        ArgumentNullException.ThrowIfNull(patterns);

        var result = new HashSet<CredentialPath>();
        foreach(var pattern in patterns)
        {
            if(pattern.TryResolve(out var credentialPath))
            {
                result.Add(credentialPath);
            }
            else if(availablePaths is not null)
            {
                //Wildcard pattern: match against all available paths.
                foreach(var available in availablePaths)
                {
                    if(pattern.Matches(available))
                    {
                        result.Add(available);
                    }
                }
            }
        }

        return result;
    }


    /// <summary>
    /// Converts a <see cref="DcqlMatch{TCredential}"/> into a
    /// <see cref="DisclosureMatch{TCredential}"/> with resolved credential paths.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This bridges the DCQL evaluation output (which carries <see cref="DcqlClaimPattern"/>
    /// values) to the query-language-neutral disclosure computation input (which requires
    /// concrete <see cref="CredentialPath"/> values for lattice operations).
    /// </para>
    /// </remarks>
    /// <typeparam name="TCredential">The application-specific credential type.</typeparam>
    /// <param name="dcqlMatch">The DCQL match to convert.</param>
    /// <param name="allAvailablePaths">
    /// All paths available in the credential, for the lattice top element.
    /// Also used for wildcard expansion.
    /// </param>
    /// <param name="mandatoryPaths">
    /// Mandatory paths that cannot be excluded, for the lattice bottom element.
    /// </param>
    /// <param name="format">The credential format identifier.</param>
    /// <returns>A disclosure match ready for the computation pipeline.</returns>
    public static DisclosureMatch<TCredential> ToDisclosureMatch<TCredential>(
        DcqlMatch<TCredential> dcqlMatch,
        IReadOnlySet<CredentialPath> allAvailablePaths,
        IReadOnlySet<CredentialPath>? mandatoryPaths = null,
        string? format = null)
    {
        ArgumentNullException.ThrowIfNull(dcqlMatch);
        ArgumentNullException.ThrowIfNull(allAvailablePaths);

        return new DisclosureMatch<TCredential>
        {
            Credential = dcqlMatch.Credential,
            QueryRequirementId = dcqlMatch.CredentialQueryId,
            RequiredPaths = ResolveAll(dcqlMatch.RequiredDisclosurePatterns, allAvailablePaths),
            MatchedPaths = ResolveAll(dcqlMatch.MatchedPatterns, allAvailablePaths),
            AllAvailablePaths = allAvailablePaths,
            MandatoryPaths = mandatoryPaths,
            Format = format
        };
    }
}