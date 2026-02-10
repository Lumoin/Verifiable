using System;
using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Core.Model.Dcql;

namespace Verifiable.Core.Dcql;

/// <summary>
/// A DCQL query with pre-computed structures ready for evaluation.
/// </summary>
/// <remarks>
/// <para>
/// Preparing a query extracts all patterns, predicates, and computes structures upfront.
/// This enables:
/// <list type="bullet">
///   <item><description>Applications to inspect query requirements before fetching credentials.</description></item>
///   <item><description>Storage-level filtering using <see cref="CoarsePredicates"/>.</description></item>
///   <item><description>Efficient evaluation without re-parsing the query for each credential.</description></item>
/// </list>
/// </para>
/// <para>
/// The typical flow is:
/// <list type="number">
///   <item><description>Parse DCQL JSON and prepare the query.</description></item>
///   <item><description>Use <see cref="CoarsePredicates"/> for storage queries.</description></item>
///   <item><description>Pass candidates to <see cref="DcqlEvaluator"/> for fine evaluation.</description></item>
/// </list>
/// </para>
/// </remarks>
[DebuggerDisplay("IsValid={IsValid} Credentials={Query.Credentials.Count} Patterns={AllRequestedPatterns.Count}")]
public record PreparedDcqlQuery
{
    /// <summary>
    /// The original DCQL query.
    /// </summary>
    public required DcqlQuery Query { get; init; }

    /// <summary>
    /// Pre-computed coarse predicates for storage-level filtering.
    /// </summary>
    /// <remarks>
    /// Applications translate these to storage-specific queries (SQL, document queries, etc.)
    /// to retrieve candidate credentials without loading all credentials into memory.
    /// </remarks>
    public required IReadOnlyList<DcqlCoarsePredicates> CoarsePredicates { get; init; }

    /// <summary>
    /// All unique claim patterns requested across all credential queries.
    /// </summary>
    /// <remarks>
    /// This enables applications to inspect what data is being requested
    /// before fetching any credentials, useful for policy checks.
    /// </remarks>
    public required IReadOnlySet<DcqlClaimPattern> AllRequestedPatterns { get; init; }

    /// <summary>
    /// All unique credential formats requested.
    /// </summary>
    public required IReadOnlySet<string> RequestedFormats { get; init; }

    /// <summary>
    /// Validation issues found in the query, if any.
    /// </summary>
    /// <remarks>
    /// Empty if the query is structurally valid.
    /// Applications should check this before evaluation.
    /// </remarks>
    public required IReadOnlyList<string> ValidationIssues { get; init; }

    /// <summary>
    /// Gets a value indicating whether the query is valid.
    /// </summary>
    public bool IsValid => ValidationIssues.Count == 0;

    /// <summary>
    /// Gets the coarse predicates for a specific credential query.
    /// </summary>
    /// <param name="credentialQueryId">The credential query ID.</param>
    /// <returns>The coarse predicates, or null if not found.</returns>
    public DcqlCoarsePredicates? GetPredicatesFor(string credentialQueryId)
    {
        ArgumentNullException.ThrowIfNull(credentialQueryId);

        foreach(var predicates in CoarsePredicates)
        {
            if(string.Equals(predicates.CredentialQueryId, credentialQueryId, StringComparison.Ordinal))
            {
                return predicates;
            }
        }

        return null;
    }
}

/// <summary>
/// Prepares DCQL queries for evaluation by pre-computing patterns, predicates, and validation.
/// </summary>
public static class DcqlPreparer
{
    /// <summary>
    /// Prepares a DCQL query for evaluation.
    /// </summary>
    /// <param name="query">The DCQL query to prepare.</param>
    /// <returns>A prepared query ready for evaluation.</returns>
    public static PreparedDcqlQuery Prepare(DcqlQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);

        var coarsePredicates = DcqlCoarsePredicates.ExtractAll(query);
        var allPatterns = query.GetAllRequestedPatterns();
        var requestedFormats = query.GetRequestedFormats();
        var validationIssues = query.Validate();

        return new PreparedDcqlQuery
        {
            Query = query,
            CoarsePredicates = coarsePredicates,
            AllRequestedPatterns = allPatterns,
            RequestedFormats = requestedFormats,
            ValidationIssues = validationIssues
        };
    }
}