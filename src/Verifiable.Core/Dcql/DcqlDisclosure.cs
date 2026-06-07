using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.Model.SelectiveDisclosure.Strategy;

namespace Verifiable.Core.Dcql;

/// <summary>
/// The result of <see cref="DcqlDisclosure.ComputeStrategyAsync{TCredential}"/>: the
/// disclosure strategy graph paired with the DCQL match verdict.
/// </summary>
/// <remarks>
/// <para>
/// Two orthogonal questions must both be answered <see langword="true"/> for a verifier to
/// accept a presented credential, and they come from different layers:
/// </para>
/// <list type="bullet">
/// <item><description><see cref="Graph"/><c>.Satisfied</c> — the query-language-neutral
/// <em>disclosure</em> verdict: are the required paths available and covered by the selected
/// disclosure set (the lattice). Computed by <see cref="Verifiable.Core.Model.SelectiveDisclosure.DisclosureComputation{TCredential}"/>,
/// which knows nothing about DCQL.</description></item>
/// <item><description><see cref="ConstraintsSatisfied"/> — the DCQL <em>match</em> verdict
/// from <see cref="DcqlEvaluator"/>: format, type, <c>trusted_authorities</c>, and claim
/// <c>values</c> constraints. A credential can have every requested path available to
/// disclose yet fail because its value or issuer is not accepted.</description></item>
/// </list>
/// <para>
/// <see cref="Satisfied"/> ANDs the two — the single fail-closed signal a verifier reads.
/// </para>
/// </remarks>
/// <typeparam name="TCredential">The credential representation the format adapter operates on.</typeparam>
public sealed record DcqlDisclosureResult<TCredential>
{
    /// <summary>The disclosure strategy graph — what to disclose, and lattice-level disclosure adequacy.</summary>
    public required DisclosureStrategyGraph<TCredential> Graph { get; init; }

    /// <summary>
    /// Whether the credential satisfies the DCQL query's MATCH constraints — format, type,
    /// <c>trusted_authorities</c>, and claim <c>values</c> — per <see cref="DcqlEvaluator.EvaluateSingle{TCredential}"/>.
    /// Distinct from the lattice's disclosure adequacy (<see cref="Graph"/><c>.Satisfied</c>).
    /// </summary>
    public required bool ConstraintsSatisfied { get; init; }

    /// <summary>Claim patterns whose value constraint failed, when <see cref="ConstraintsSatisfied"/> is <see langword="false"/>.</summary>
    public IReadOnlyList<DcqlClaimPattern>? FailedValueConstraints { get; init; }

    /// <summary>Required claim patterns absent from the credential, when <see cref="ConstraintsSatisfied"/> is <see langword="false"/>.</summary>
    public IReadOnlyList<DcqlClaimPattern>? MissingRequiredPatterns { get; init; }

    /// <summary>The match failure reason, when <see cref="ConstraintsSatisfied"/> is <see langword="false"/>.</summary>
    public string? MatchFailureReason { get; init; }

    /// <summary>
    /// The overall fail-closed verdict a verifier reads: the credential satisfies the query's
    /// match constraints AND its disclosure covers the required paths. Both must hold.
    /// </summary>
    public bool Satisfied => ConstraintsSatisfied && Graph.Satisfied;
}

/// <summary>
/// The single canonical entry point that takes one DCQL credential query and one
/// credential to the disclosure strategy graph, so every flow — wallet
/// presentation production and verifier disclosure assessment, across every
/// format — runs the same engine path instead of hand-rolling its own variant.
/// </summary>
/// <remarks>
/// <para>
/// The pipeline is:
/// </para>
/// <list type="number">
/// <item><description><see cref="DcqlEvaluator.EvaluateSingle{TCredential}"/> — match the credential against the query (format / type / trusted-authority / claim-value constraints), reporting the matched claim patterns. <see cref="DcqlEvaluator.EvaluateSingle{TCredential}"/> (not <c>Evaluate</c>) is used deliberately: it always returns a result carrying <see cref="DcqlEvaluationResult.MatchedPatterns"/> even when a required claim is absent, so a credential that only partially satisfies the query still produces a disclosure decision rather than vanishing.</description></item>
/// <item><description>The matched and required patterns are resolved to concrete <see cref="CredentialPath"/> values via <see cref="DcqlPathResolver"/> and lifted into the query-language-neutral <see cref="DisclosureMatch{TCredential}"/>.</description></item>
/// <item><description><see cref="DisclosureComputation{TCredential}.ComputeAsync"/> — run the lattice, async policy assessors, and cross-credential optimizers to the <see cref="DisclosureStrategyGraph{TCredential}"/>.</description></item>
/// </list>
/// <para>
/// The graph is the single result both directions read from:
/// </para>
/// <list type="bullet">
/// <item><description><strong>Presentation production</strong> (wallet) reads <c>graph.Decisions[i].SelectedPaths</c> as the minimal set to disclose, then drives the format primitive (SD-JWT <c>SelectDisclosures</c>, mdoc <c>Derive</c>, SD-CWT) to build the presentation. A partially-satisfying credential still yields a decision (<c>SatisfiesRequirements == false</c>), so a best-effort presentation is produced rather than throwing.</description></item>
/// <item><description><strong>Disclosure assessment</strong> (verifier) reads <c>graph.Satisfied</c> for DCQL satisfaction and computes over-disclosure as the disclosed paths minus <c>graph.Decisions[i].SelectedPaths</c> — anything disclosed beyond what the engine computes as appropriate for the query.</description></item>
/// </list>
/// <para>
/// The computation is genuinely asynchronous: <see cref="DisclosureComputation{TCredential}.ComputeAsync"/>
/// runs the wired policy assessors, so there is no synchronous form. Callers wire
/// their own <see cref="DisclosureComputation{TCredential}"/> (with policy
/// assessors / cross-credential optimizers) by passing <paramref name="computation"/>,
/// or accept the default empty-policy computation.
/// </para>
/// </remarks>
public static class DcqlDisclosure
{
    /// <summary>
    /// Evaluates <paramref name="credential"/> against <paramref name="credentialQuery"/>
    /// and computes its <see cref="DisclosureStrategyGraph{TCredential}"/>.
    /// </summary>
    /// <typeparam name="TCredential">
    /// The credential representation the format adapter operates on (e.g.
    /// <c>SdToken&lt;string&gt;</c>, <c>MdocDocument</c>) — opaque to the engine,
    /// which works on the resolved <see cref="CredentialPath"/> values.
    /// </typeparam>
    /// <param name="credentialQuery">The DCQL credential query to evaluate against.</param>
    /// <param name="credential">The credential to evaluate (the holder's credential when producing, the disclosed credential when assessing).</param>
    /// <param name="metadataExtractor">The format adapter's metadata extractor (<see cref="DcqlCredentialMetadata.AvailablePaths"/> bounds the lattice top).</param>
    /// <param name="claimExtractor">The format adapter's claim extractor (used for claim-value constraint checks).</param>
    /// <param name="mandatoryPaths">
    /// Paths that must always be disclosed (the lattice bottom) — e.g. SD-JWT
    /// <c>iss</c>/<c>vct</c>. Unioned into the available paths so always-visible
    /// claims that are not selective disclosures still participate in the lattice.
    /// </param>
    /// <param name="computation">
    /// The disclosure computation to run, carrying any policy assessors and
    /// cross-credential optimizers. When <see langword="null"/>, an empty-policy
    /// <see cref="DisclosureComputation{TCredential}"/> is used.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// A <see cref="DcqlDisclosureResult{TCredential}"/> pairing the disclosure strategy graph
    /// with the DCQL match verdict. <see cref="DcqlDisclosureResult{TCredential}.Graph"/>'s
    /// <see cref="DisclosureStrategyGraph{TCredential}.Satisfied"/> is <see langword="false"/>
    /// when a required claim is absent; <see cref="DcqlDisclosureResult{TCredential}.ConstraintsSatisfied"/>
    /// is <see langword="false"/> when a format / type / <c>trusted_authorities</c> / claim
    /// <c>values</c> constraint fails. A verifier reads
    /// <see cref="DcqlDisclosureResult{TCredential}.Satisfied"/> (both must hold); a wallet
    /// producing a presentation reads <c>Graph.Decisions[i].SelectedPaths</c>.
    /// </returns>
    public static async Task<DcqlDisclosureResult<TCredential>> ComputeStrategyAsync<TCredential>(
        CredentialQuery credentialQuery,
        TCredential credential,
        DcqlMetadataExtractor<TCredential> metadataExtractor,
        DcqlClaimExtractor<TCredential> claimExtractor,
        IReadOnlySet<CredentialPath>? mandatoryPaths = null,
        DisclosureComputation<TCredential>? computation = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credentialQuery);
        ArgumentNullException.ThrowIfNull(metadataExtractor);
        ArgumentNullException.ThrowIfNull(claimExtractor);

        DcqlCredentialMetadata metadata = metadataExtractor(credential);

        //EvaluateSingle (not Evaluate) so a partially-satisfying credential still
        //reports its matched patterns instead of being filtered out entirely.
        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            credentialQuery, credential, metadata, claimExtractor);

        var allAvailablePaths = metadata.AvailablePaths is null
            ? new HashSet<CredentialPath>()
            : new HashSet<CredentialPath>(metadata.AvailablePaths);
        if(mandatoryPaths is not null)
        {
            allAvailablePaths.UnionWith(mandatoryPaths);
        }

        IEnumerable<DcqlClaimPattern> matchedPatterns =
            (IEnumerable<DcqlClaimPattern>?)result.MatchedPatterns ?? [];

        var disclosureMatch = new DisclosureMatch<TCredential>
        {
            Credential = credential,
            QueryRequirementId = credentialQuery.Id ?? string.Empty,
            RequiredPaths = DcqlPathResolver.ResolveAll(credentialQuery.RequiredPatterns(), allAvailablePaths),
            MatchedPaths = DcqlPathResolver.ResolveAll(matchedPatterns, allAvailablePaths),
            AllAvailablePaths = allAvailablePaths,
            MandatoryPaths = mandatoryPaths,
            Format = metadata.Format
        };

        DisclosureComputation<TCredential> engine = computation ?? new DisclosureComputation<TCredential>();

        DisclosureStrategyGraph<TCredential> graph =
            await engine.ComputeAsync([disclosureMatch], cancellationToken: cancellationToken).ConfigureAwait(false);

        //The neutral engine answered the disclosure question (are the required paths
        //available and covered?). Carry the DCQL match verdict — format / type /
        //trusted_authorities / claim values, all folded into result.Matches — alongside
        //it so a verifier reads ConstraintsSatisfied && Graph.Satisfied as one fail-closed
        //signal. EvaluateSingle's Matches is false for any failed match constraint, which
        //the lattice (path availability) alone cannot see.
        return new DcqlDisclosureResult<TCredential>
        {
            Graph = graph,
            ConstraintsSatisfied = result.Matches,
            FailedValueConstraints = result.FailedValueConstraints,
            MissingRequiredPatterns = result.MissingRequiredPatterns,
            MatchFailureReason = result.FailureReason
        };
    }
}
