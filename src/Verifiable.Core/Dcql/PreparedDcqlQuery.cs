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
    public DcqlCoarsePredicates? GetPredicatesFor(CredentialQueryId credentialQueryId)
    {
        ArgumentNullException.ThrowIfNull(credentialQueryId);

        foreach(var predicates in CoarsePredicates)
        {
            if(predicates.CredentialQueryId == credentialQueryId)
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
    /// <remarks>
    /// Preparation is the step that REPORTS what is wrong with a query, so a credential query
    /// identifier that leaves
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OID4VP 1.0 §6.1</see>'s "The value MUST be a non-empty string consisting of alphanumeric,
    /// underscore (_), or hyphen (-) characters" is recorded in
    /// <see cref="PreparedDcqlQuery.ValidationIssues"/> rather than raised: the query reaching here
    /// can come off the wire, and a caller that asks what is wrong with it is answered, not thrown
    /// at. Validation therefore runs first and the coarse predicates are extracted only for the
    /// credential queries whose identifier holds — <see cref="DcqlCoarsePredicates.Extract"/> refuses
    /// an invalid identifier, which is the API-misuse boundary evaluation sits behind.
    /// </remarks>
    /// <param name="query">The DCQL query to prepare.</param>
    /// <returns>A prepared query ready for evaluation.</returns>
    public static PreparedDcqlQuery Prepare(DcqlQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);

        var validationIssues = query.Validate();
        var coarsePredicates = ExtractCoarsePredicatesForValidIdentifiers(query);
        var allPatterns = query.GetAllRequestedPatterns();
        var requestedFormats = query.GetRequestedFormats();

        return new PreparedDcqlQuery
        {
            Query = query,
            CoarsePredicates = coarsePredicates,
            AllRequestedPatterns = allPatterns,
            RequestedFormats = requestedFormats,
            ValidationIssues = validationIssues
        };
    }


    /// <summary>
    /// Extracts the coarse predicates of every credential query whose <c>id</c> meets OID4VP 1.0
    /// §6.1, skipping the ones whose identifier was already recorded as an issue. A partially
    /// invalid query still reports every issue it has and still offers the storage-level predicates
    /// of the credential queries that are well formed.
    /// </summary>
    /// <param name="query">The DCQL query being prepared.</param>
    /// <returns>The coarse predicates of the credential queries carrying a valid identifier.</returns>
    private static List<DcqlCoarsePredicates> ExtractCoarsePredicatesForValidIdentifiers(DcqlQuery query)
    {
        if(query.Credentials is null)
        {
            return [];
        }

        var predicates = new List<DcqlCoarsePredicates>(query.Credentials.Count);
        foreach(var credentialQuery in query.Credentials)
        {
            if(CredentialQueryId.TryCreate(credentialQuery.Id, out _))
            {
                predicates.Add(DcqlCoarsePredicates.Extract(credentialQuery));
            }
        }

        return predicates;
    }
}
