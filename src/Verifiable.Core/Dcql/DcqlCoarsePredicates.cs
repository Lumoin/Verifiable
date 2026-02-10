using System;
using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Core.Model.Dcql;

namespace Verifiable.Core.Dcql;

/// <summary>
/// Pre-computed predicates extracted from a DCQL credential query for efficient
/// storage-level filtering before fine-grained evaluation.
/// </summary>
/// <remarks>
/// <para>
/// Coarse predicates enable a two-phase evaluation strategy:
/// </para>
/// <list type="number">
/// <item><description>
/// <strong>Phase 1 (storage):</strong> The application filters credentials using
/// these predicates against indexed metadata. This happens at the storage level
/// (database query, index lookup) and is fast.
/// </description></item>
/// <item><description>
/// <strong>Phase 2 (in-memory):</strong> Only credentials passing phase 1 are
/// loaded and evaluated against the full DCQL query by
/// <see cref="DcqlEvaluator.EvaluateSingle{TCredential}"/>. This is thorough
/// but more expensive.
/// </description></item>
/// </list>
/// <para>
/// Coarse predicates are intentionally over-inclusive: a credential passing coarse
/// filtering may still fail fine-grained evaluation, but a credential that would
/// pass fine-grained evaluation will never be filtered out by coarse predicates.
/// </para>
/// </remarks>
[DebuggerDisplay("Format={MustMatchFormat} Types={MustMatchAnyType?.Count ?? 0} Paths={MustHavePatterns?.Count ?? 0}")]
public record DcqlCoarsePredicates
{
    /// <summary>
    /// The credential query ID these predicates were extracted from.
    /// </summary>
    public required string CredentialQueryId { get; init; }

    /// <summary>
    /// The credential format that must match exactly.
    /// </summary>
    public required string MustMatchFormat { get; init; }

    /// <summary>
    /// The credential type must be one of these values, if specified.
    /// </summary>
    /// <remarks>
    /// When null, no type constraint applies.
    /// </remarks>
    public IReadOnlySet<string>? MustMatchAnyType { get; init; }

    /// <summary>
    /// The credential must contain claims at all of these patterns.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only includes patterns from required claims (not optional ones).
    /// A credential can only match if it has claims at all required patterns.
    /// </para>
    /// </remarks>
    public IReadOnlySet<DcqlClaimPattern>? MustHavePatterns { get; init; }

    /// <summary>
    /// The credential's issuer must be one of these values, if specified.
    /// </summary>
    /// <remarks>
    /// Extracted from trusted authority constraints. When null, no issuer constraint applies.
    /// </remarks>
    public IReadOnlySet<string>? MustMatchAnyIssuer { get; init; }


    /// <summary>
    /// Extracts coarse predicates from a DCQL credential query.
    /// </summary>
    /// <param name="credentialQuery">The credential query to extract from.</param>
    /// <returns>The coarse predicates.</returns>
    public static DcqlCoarsePredicates Extract(CredentialQuery credentialQuery)
    {
        ArgumentNullException.ThrowIfNull(credentialQuery);
        ArgumentNullException.ThrowIfNull(credentialQuery.Id);
        ArgumentNullException.ThrowIfNull(credentialQuery.Format);

        return new DcqlCoarsePredicates
        {
            CredentialQueryId = credentialQuery.Id,
            MustMatchFormat = credentialQuery.Format,
            MustMatchAnyType = ExtractTypeConstraints(credentialQuery),
            MustHavePatterns = ExtractMustHavePatterns(credentialQuery),
            MustMatchAnyIssuer = ExtractIssuerConstraints(credentialQuery)
        };
    }


    /// <summary>
    /// Extracts coarse predicates for all credential queries in a DCQL query.
    /// </summary>
    /// <param name="query">The DCQL query.</param>
    /// <returns>Coarse predicates for each credential query.</returns>
    public static IReadOnlyList<DcqlCoarsePredicates> ExtractAll(DcqlQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(query.Credentials);

        var result = new List<DcqlCoarsePredicates>(query.Credentials.Count);
        foreach(var credentialQuery in query.Credentials)
        {
            result.Add(Extract(credentialQuery));
        }

        return result;
    }


    private static HashSet<string>? ExtractTypeConstraints(CredentialQuery query)
    {
        if(query.Meta?.HasTypeConstraints != true || query.Format is null)
        {
            return null;
        }

        var constraints = query.Meta.GetTypeConstraints(query.Format);
        if(constraints is null)
        {
            return null;
        }

        return new HashSet<string>(constraints);
    }


    private static HashSet<DcqlClaimPattern>? ExtractMustHavePatterns(CredentialQuery query)
    {
        if(query.Claims is null or { Count: 0 })
        {
            return null;
        }

        var patterns = new HashSet<DcqlClaimPattern>();
        foreach(var claim in query.Claims)
        {
            if(claim.Required && claim.Path is not null)
            {
                patterns.Add(claim.Path);
            }
        }

        return patterns.Count > 0 ? patterns : null;
    }


    private static HashSet<string>? ExtractIssuerConstraints(CredentialQuery query)
    {
        if(query.TrustedAuthorities is null or { Count: 0 })
        {
            return null;
        }

        var issuers = new HashSet<string>();
        foreach(var authority in query.TrustedAuthorities)
        {
            if(authority.Values is not null)
            {
                foreach(var issuer in authority.Values)
                {
                    issuers.Add(issuer);
                }
            }
        }

        return issuers.Count > 0 ? issuers : null;
    }
}