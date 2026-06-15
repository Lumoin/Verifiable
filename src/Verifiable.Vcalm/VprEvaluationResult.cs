using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.SelectiveDisclosure;

namespace Verifiable.Vcalm;

/// <summary>
/// The holder-side outcome of evaluating a §3.4 verifiable presentation request against a set of held
/// verifiable credentials: which §3.4.5 groups the holder can satisfy and the per-credential minimal
/// disclosure each satisfying match implies.
/// </summary>
/// <remarks>
/// §3.4.5 fixes the satisfaction algebra: query entries sharing a <c>group</c> value are ANDed (all
/// must be satisfiable from the held credentials), entries with a different or missing group are
/// ORed. <see cref="IsSatisfiable"/> is true when at least one OR-group is fully satisfiable. The
/// per-group results carry the matched credentials and, per the §3.4.2 selective-disclosure note, the
/// minimal set of claim paths the holder needs to disclose for each match.
/// </remarks>
[DebuggerDisplay("VprEvaluationResult Satisfiable={IsSatisfiable} Groups={Groups.Length}")]
public sealed record VprEvaluationResult
{
    /// <summary>
    /// Whether the holder can satisfy the request: at least one §3.4.5 OR-group is fully satisfiable.
    /// </summary>
    public bool IsSatisfiable { get; init; }

    /// <summary>The per-group satisfaction outcomes, in request order.</summary>
    public ImmutableArray<VprGroupResult> Groups { get; init; } = ImmutableArray<VprGroupResult>.Empty;
}


/// <summary>
/// The satisfaction outcome for a single §3.4.5 group — the AND-combination of the query entries that
/// share a <see cref="GroupKey"/> (a standalone OR-alternative is a group of one).
/// </summary>
[DebuggerDisplay("VprGroupResult GroupKey={GroupKey} Satisfied={IsSatisfied} Matches={QueryMatches.Length}")]
public sealed record VprGroupResult
{
    /// <summary>
    /// The §3.4.5 <c>group</c> label shared by the entries in this group, or <see langword="null"/>
    /// for an ungrouped (standalone OR-alternative) entry.
    /// </summary>
    public string? GroupKey { get; init; }

    /// <summary>
    /// Whether every query entry in this group is satisfiable from the held credentials (the §3.4.5
    /// "AND" — all conditions met).
    /// </summary>
    public bool IsSatisfied { get; init; }

    /// <summary>The per-query-entry match outcomes within this group, in request order.</summary>
    public ImmutableArray<VprQueryMatch> QueryMatches { get; init; } = ImmutableArray<VprQueryMatch>.Empty;
}


/// <summary>
/// The match outcome for a single query entry: whether the holder can satisfy it and, when it can,
/// the held credentials that match and the minimal disclosure each match implies.
/// </summary>
[DebuggerDisplay("VprQueryMatch Type={QueryType} Satisfied={IsSatisfied} Matches={Matches.Length}")]
public sealed record VprQueryMatch
{
    /// <summary>The §3.4.1 <c>type</c> of the query entry this outcome is for.</summary>
    public required string QueryType { get; init; }

    /// <summary>Whether at least one held credential (or, for DID Authentication, an accepted holder DID) satisfies this entry.</summary>
    public bool IsSatisfied { get; init; }

    /// <summary>The held-credential matches that satisfy this entry, each with its minimal disclosure.</summary>
    public ImmutableArray<VprCredentialMatch> Matches { get; init; } = ImmutableArray<VprCredentialMatch>.Empty;
}


/// <summary>
/// A single held credential that satisfies a query entry, paired with the minimal set of claim paths
/// the holder needs to disclose to satisfy the request (the §3.4.2 "any field included is a required
/// field" rule, or the DCQL required-disclosure patterns).
/// </summary>
[DebuggerDisplay("VprCredentialMatch Disclosures={Disclosures.Length}")]
public sealed record VprCredentialMatch
{
    /// <summary>The held credential that satisfies the query entry.</summary>
    public required VerifiableCredential Credential { get; init; }

    /// <summary>
    /// The minimal set of credential claim paths the holder needs to disclose for this match — the
    /// §3.4.2 requested example fields, or the DCQL matched claim patterns. Empty for a type-only
    /// match that requests no specific subject claims.
    /// </summary>
    public ImmutableArray<CredentialPath> Disclosures { get; init; } = ImmutableArray<CredentialPath>.Empty;
}
