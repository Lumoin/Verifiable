using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// Computes optimal disclosure sets from evaluated credential matches.
/// </summary>
/// <remarks>
/// <para>
/// This class is the central orchestrator of the selective disclosure architecture.
/// It implements the computation and policy layers: lattice construction,
/// minimum/maximum/optimal disclosure computation, and policy assessment.
/// It is query-language-neutral and format-neutral — it consumes
/// <see cref="DisclosureMatch{TCredential}"/> instances produced by any evaluator
/// and produces a <see cref="DisclosurePlan{TCredential}"/>.
/// </para>
/// <para>
/// Evaluators that can feed matches into this pipeline include DCQL (Digital
/// Credentials Query Language), OpenID4VP Presentation Definition, DIF
/// Presentation Exchange, manual wallet selection, or any application-specific
/// credential matching logic. The pipeline operates purely on path sets and does
/// not know which query language or selection mechanism produced the matches.
/// </para>
/// <para>
/// <strong>Layered architecture:</strong>
/// </para>
/// <para>
/// The selective disclosure stack is organized into six layers. This class orchestrates
/// Layers 3 and 4; the remaining layers are handled by upstream evaluators, downstream
/// format encoders, and a cross-cutting audit trail:
/// </para>
/// <list type="number">
/// <item><description>
/// <strong>Layer 1 — Credential discovery:</strong> Wallet or storage backend locates
/// candidate credentials matching a query. Not handled by this class; the caller provides
/// already-matched <see cref="DisclosureMatch{TCredential}"/> instances.
/// </description></item>
/// <item><description>
/// <strong>Layer 2 — Query evaluation:</strong> A query-language-specific evaluator (DCQL,
/// Presentation Definition, manual selection) resolves query patterns to concrete
/// <see cref="CredentialPath"/> sets. This produces the <see cref="DisclosureMatch{TCredential}"/>
/// inputs consumed by Layer 3.
/// </description></item>
/// <item><description>
/// <strong>Layer 3 — Disclosure computation (this class):</strong> For each match, a
/// <see cref="SetDisclosureLattice{TClaim}"/> is built and the optimal disclosure set is
/// computed. The lattice defines M ⊆ S ⊆ A and enforces upward closure.
/// </description></item>
/// <item><description>
/// <strong>Layer 4 — Policy decision (this class):</strong> The
/// <see cref="PolicyAssessorDelegate{TCredential}"/> pipeline runs in sequence over the
/// lattice result. Each assessor receives the full <see cref="PolicyAssessmentContext{TCredential}"/>
/// and can narrow or reject. Assessor implementations include:
/// <list type="bullet">
/// <item><description>Rule-based engines enforcing organizational or regulatory policies
/// (GDPR data minimization, eIDAS attribute requirements, issuer-mandated disclosure rules).</description></item>
/// <item><description>SAT solvers that model multi-credential constraints as boolean
/// satisfiability problems — e.g. "disclose name from credential A OR credential B, but
/// never both SSNs" — and find optimal solutions over the combined lattices.</description></item>
/// <item><description>AI agents that evaluate risk, verifier trust level, request context,
/// and historical disclosure patterns to decide whether to narrow the disclosure set, with
/// SHAP-based explainability for the decision record.</description></item>
/// <item><description>Consent mediators that present the proposed disclosure to the user
/// through a wallet UI and translate user choices back into lattice operations.</description></item>
/// </list>
/// </description></item>
/// <item><description>
/// <strong>Layer 5 — Format encoding:</strong> The <see cref="DisclosurePlan{TCredential}"/>
/// is consumed by format-specific encoders — <c>SdJwtIssuance</c>, <c>SdCwtIssuance</c>,
/// <c>CredentialJwsExtensions</c>, <c>CredentialCoseExtensions</c> — that produce the
/// wire-format tokens. This layer is downstream and not handled by this class.
/// </description></item>
/// <item><description>
/// <strong>Layer 6 — Audit trail (cross-cutting):</strong> The
/// <see cref="DisclosureDecisionRecord{TCredential}"/> captures all intermediate results
/// from Layers 3–4 with W3C Trace Context for OpenTelemetry correlation. This record
/// serves as the foundation for ISO 27560 consent receipts and compliance artifacts.
/// </description></item>
/// </list>
/// <code>
/// ┌──────────────────────────────────────────────────────────────────────┐
/// │                  Selective Disclosure Architecture                    │
/// ├──────────────────────────────────────────────────────────────────────┤
/// │                                                                      │
/// │  ISSUANCE (defining what      │     PRESENTATION (deciding what      │
/// │  is selectively disclosable)  │     to reveal from a token)          │
/// │                               │                                      │
/// │  Credential + Policy ──►      │      ◄── Verifier Request            │
/// │                               │          (DCQL, PE, PD, manual)      │
/// │                               │      ◄── User Preferences            │
/// │         │                     │               │                      │
/// │         ▼                     │               ▼                      │
/// │  ┌─────────────────────────────────────────────────────┐             │
/// │  │  Layer 3   PathLattice / SetDisclosureLattice     │             │
/// │  │                                                     │             │
/// │  │  mandatory (⊥) ⊆ disclosure set ⊆ all paths (⊤)   │             │
/// │  │                                                     │             │
/// │  │  Operations: Join (∨), Meet (∧), ComputeClosure    │             │
/// │  └──────────────────────┬──────────────────────────────┘             │
/// │                         │                                            │
/// │                         ▼                                            │
/// │  ┌─────────────────────────────────────────────────────┐             │
/// │  │  Layer 4   PolicyAssessorDelegate Pipeline          │             │
/// │  │                                                     │             │
/// │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │             │
/// │  │  │ Rule-based  │  │ SAT solver  │  │  AI agent   │  │             │
/// │  │  │ (GDPR, org) │  │ (multi-cred │  │ (risk/trust │  │             │
/// │  │  │             │  │  constraint │  │  scoring,   │  │             │
/// │  │  │             │  │  optimizer) │  │  SHAP       │  │             │
/// │  │  │             │  │             │  │  explain)   │  │             │
/// │  │  └─────────────┘  └─────────────┘  └─────────────┘  │             │
/// │  └──────────────────────┬──────────────────────────────┘             │
/// │                         │                                            │
/// │                         ▼                                            │
/// │  ┌─────────────────────────────────────────────────────┐             │
/// │  │  Layer 6   DisclosurePlan + DecisionRecord         │             │
/// │  │            (audit, ISO 27560 consent, OTel trace)  │             │
/// │  └──────────────────────┬──────────────────────────────┘             │
/// │                         │                                            │
/// │         ┌───────────────┴───────────────┐                            │
/// │         ▼                               ▼                            │
/// │  Layer 5 format output          Layer 5 format output                │
/// │  (SdJwtIssuance,                (SdDisclosureSelection,              │
/// │   SdCwtIssuance)                 SdJwtToken.SelectDisclosures)       │
/// │                                                                      │
/// └──────────────────────────────────────────────────────────────────────┘
/// </code>
/// <para>
/// <strong>ComputeAsync execution flow (Layers 3–4):</strong>
/// </para>
/// <para>
/// For each <see cref="DisclosureMatch{TCredential}"/> passed to <see cref="ComputeAsync"/>:
/// </para>
/// <list type="number">
/// <item><description>
/// Build <see cref="SetDisclosureLattice{TClaim}"/> from the match's available and mandatory
/// paths (Layer 3).
/// </description></item>
/// <item><description>
/// Compute optimal disclosure via
/// <see cref="SelectiveDisclosure.ComputeOptimalDisclosure{TClaim}"/>: the smallest valid
/// set satisfying verifier requirements while respecting user exclusions. Conflicts between
/// exclusions and requirements are detected and reported (Layer 3).
/// </description></item>
/// <item><description>
/// Run <see cref="PolicyAssessorDelegate{TCredential}"/> pipeline in sequence. Each assessor
/// can narrow the set or reject entirely; rejection stops the pipeline for that credential
/// (Layer 4).
/// </description></item>
/// <item><description>
/// Capture all intermediate results into <see cref="DisclosureDecisionRecord{TCredential}"/>
/// with W3C Trace Context from <see cref="Activity.Current"/> (Layer 6).
/// </description></item>
/// </list>
/// <para>
/// <strong>Formal invariants:</strong>
/// </para>
/// <para>
/// Let M be the mandatory path set, A be all available paths, V be verifier-requested paths,
/// E be user exclusions, and S be the computed disclosure set. The following invariants hold
/// for every disclosure computation:
/// </para>
/// <list type="bullet">
/// <item><description>Lattice bounds: M ⊆ S ⊆ A (the disclosure set is bounded by mandatory below and available above).</description></item>
/// <item><description>Mandatory inviolability: ∀p ∈ M → p ∈ S (mandatory paths cannot be excluded by any means).</description></item>
/// <item><description>Minimality: S = M ∪ (V \ E) ∪ closure(V \ E) when no policy narrows further.</description></item>
/// <item><description>Upward closure: ∀p ∈ S, ∀q ancestor of p → q ∈ S (structural validity is preserved).</description></item>
/// <item><description>Policy monotonicity: each assessor can only narrow S or reject; no assessor can add paths beyond the lattice result.</description></item>
/// <item><description>Exclusion safety: E ∩ M = ∅ semantically (user exclusions of mandatory paths are silently ignored).</description></item>
/// </list>
/// <para>
/// <strong>Authority monotonicity and provenance:</strong>
/// </para>
/// <para>
/// The lattice structure enforces a fundamental property: authority over disclosed information
/// can only shrink along the credential chain. At issuance, the issuer defines the top of the
/// lattice (all available paths). The holder can only narrow this to a subset. The verifier
/// receives only what the holder chose to reveal. At no step can authority grow beyond what the
/// previous participant granted. This monotone decreasing property — ⊤ ⊇ S_issuer ⊇ S_holder ⊇
/// S_verifier ⊇ ⊥ — is an inherent structural guarantee of the bounded lattice, not an
/// application-level policy. The <see cref="DisclosureDecisionRecord{TCredential}"/> captures
/// the provenance trail at each step, enabling auditability of the authority narrowing across
/// the full issuance-to-verification flow.
/// </para>
/// <para>
/// <strong>Bidirectional applicability:</strong>
/// </para>
/// <para>
/// The lattice and policy pipeline serve both the <strong>presentation</strong> direction
/// (holder deciding what to reveal to a verifier) and the <strong>issuance</strong> direction
/// (issuer deciding which claims to make selectively disclosable). In the issuance direction,
/// the lattice defines which paths become mandatory (always visible in the token) versus
/// selectively disclosable (redacted with digests). The same
/// <see cref="PolicyAssessorDelegate{TCredential}"/> pipeline can enforce organizational
/// issuance policies such as "SSN must always be selectively disclosable" or "credential type
/// must always be mandatory." The format-specific output differs — issuance produces
/// <c>JwtPayload</c> + <c>SdDisclosure</c> list or CWT claims + CBOR disclosures, while
/// presentation produces filtered disclosure sets — but the path-level computation is identical.
/// </para>
/// <para>
/// <strong>Configuration vs. per-call parameters:</strong>
/// </para>
/// <para>
/// The constructor accepts configuration that is stable across calls: policy
/// assessors and discovery bounds. Per-call parameters (matches, user
/// exclusions) are passed to <see cref="ComputeAsync"/>. This allows a single
/// instance to serve multiple requests in a web server or agent runtime.
/// </para>
/// <para>
/// <strong>Thread safety:</strong> Instances are safe for concurrent use from
/// multiple threads, provided the policy assessor delegates are also thread-safe.
/// </para>
/// </remarks>
/// <typeparam name="TCredential">The application-specific credential type.</typeparam>
public sealed class DisclosureComputation<TCredential>
{
    /// <summary>
    /// OpenTelemetry activity source for tracing disclosure computation operations.
    /// All activities created by this class share this source, enabling distributed
    /// tracing correlation through W3C Trace Context.
    /// </summary>
    private static ActivitySource ActivitySourceInstance { get; } = new("Verifiable.SelectiveDisclosure.DisclosureComputation");

    /// <summary>
    /// Policy assessors executed in sequence after lattice computation. Each assessor
    /// can narrow or reject the proposed disclosure set. An empty list means no policy
    /// enforcement — the lattice result is used directly.
    /// </summary>
    private IReadOnlyList<PolicyAssessorDelegate<TCredential>> PolicyAssessors { get; }

    /// <summary>
    /// Time provider for decision record timestamps. Injected for testability —
    /// production uses <see cref="TimeProvider.System"/>, tests can supply a
    /// fixed or controllable provider.
    /// </summary>
    private TimeProvider TimeProvider { get; }

    /// <summary>
    /// Creates a new disclosure computation with the specified configuration.
    /// </summary>
    /// <param name="policyAssessors">
    /// Policy assessors to run in order after lattice computation. Pass an empty
    /// list for no policy enforcement. See <see cref="PolicyAssessorDelegate{TCredential}"/>
    /// for the range of assessor types, including rule-based engines, SAT solvers,
    /// AI risk scorers, and consent mediators.
    /// </param>
    /// <param name="timeProvider">
    /// Time provider for timestamps. Defaults to <see cref="TimeProvider.System"/>.
    /// Inject a <c>FakeTimeProvider</c> for deterministic testing.
    /// </param>
    public DisclosureComputation(
        IReadOnlyList<PolicyAssessorDelegate<TCredential>> policyAssessors,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(policyAssessors);
        PolicyAssessors = policyAssessors;
        TimeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Creates a new disclosure computation with no policy assessors.
    /// </summary>
    public DisclosureComputation() : this([])
    {
    }

    /// <summary>
    /// Computes the disclosure plan for a set of evaluated matches.
    /// </summary>
    /// <param name="matches">
    /// Credential matches produced by an evaluator (DCQL, Presentation Definition, etc.).
    /// Each match represents one credential that can satisfy a query requirement, with
    /// concrete paths resolved from the query patterns. The matches can originate from
    /// any storage backend — in-memory wallet, persistent database, hardware token, or
    /// cloud vault.
    /// </param>
    /// <param name="userExclusions">
    /// Per-requirement user exclusions. Keyed by <see cref="DisclosureMatch{TCredential}.QueryRequirementId"/>.
    /// Exclusions of mandatory paths are silently ignored by the lattice.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The disclosure plan with per-credential decisions and decision record.</returns>
    public async Task<DisclosurePlan<TCredential>> ComputeAsync(
        IReadOnlyList<DisclosureMatch<TCredential>> matches,
        IReadOnlyDictionary<string, IReadOnlySet<CredentialPath>>? userExclusions = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(matches);

        using var activity = ActivitySourceInstance.StartActivity("ComputeDisclosure");
        var startTime = TimeProvider.GetUtcNow();
        var stopwatch = Stopwatch.StartNew();

        var evaluationRecords = new List<CredentialEvaluationRecord>();
        var latticeRecords = new List<LatticeComputationRecord>();
        var policyRecords = new List<PolicyAssessmentRecord>();
        var decisions = new List<CredentialDisclosureDecision<TCredential>>();
        var satisfiedRequirements = new HashSet<string>();

        foreach(var match in matches)
        {
            cancellationToken.ThrowIfCancellationRequested();

            //Layers 1–2 have already completed: the caller discovered credentials
            //and evaluated them against a query. Record the evaluation result.
            evaluationRecords.Add(new CredentialEvaluationRecord
            {
                Credential = match.Credential!,
                QueryRequirementId = match.QueryRequirementId,
                Matched = true
            });

            //Layer 3: Build the disclosure lattice for this credential.
            var mandatoryPaths = match.MandatoryPaths ?? (IReadOnlySet<CredentialPath>)new HashSet<CredentialPath>();
            var lattice = new SetDisclosureLattice<CredentialPath>(
                match.AllAvailablePaths,
                mandatoryPaths);

            //Compute user exclusions for this requirement.
            IReadOnlySet<CredentialPath>? exclusions = null;
            userExclusions?.TryGetValue(match.QueryRequirementId, out exclusions);

            //Layer 3: Compute optimal disclosure via lattice.
            var latticeResult = SelectiveDisclosure.ComputeOptimalDisclosure(
                lattice,
                verifierRequested: match.RequiredPaths,
                userExclusions: exclusions);

            //Layer 6: Record the lattice computation for the audit trail.
            var (minimum, _) = SelectiveDisclosure.ComputeMinimumDisclosure(
                lattice,
                verifierRequested: match.RequiredPaths);
            var maximum = SelectiveDisclosure.ComputeMaximumDisclosure(lattice, exclusions);

            latticeRecords.Add(new LatticeComputationRecord
            {
                QueryRequirementId = match.QueryRequirementId,
                MinimumPaths = minimum,
                MaximumPaths = maximum,
                ConflictPaths = latticeResult.ConflictingClaims,
                SelectedPaths = latticeResult.SelectedClaims
            });

            //Layer 4: Run policy assessor pipeline.
            var currentPaths = latticeResult.SelectedClaims;
            bool currentSatisfies = latticeResult.SatisfiesRequirements;
            IReadOnlySet<CredentialPath>? currentConflicts = latticeResult.ConflictingClaims;
            bool policyRejected = false;

            foreach(var assessor in PolicyAssessors)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var context = new PolicyAssessmentContext<TCredential>
                {
                    Credential = match.Credential!,
                    QueryRequirementId = match.QueryRequirementId,
                    ProposedPaths = currentPaths,
                    Lattice = lattice,
                    SatisfiesRequirements = currentSatisfies,
                    ConflictingPaths = currentConflicts,
                    Format = match.Format
                };

                var outcome = await assessor(context, cancellationToken).ConfigureAwait(false);

                //Layer 6: Record the assessment for the audit trail.
                IReadOnlySet<CredentialPath>? removedPaths = null;
                if(outcome.ApprovedPaths is not null)
                {
                    var removed = new HashSet<CredentialPath>(currentPaths);
                    removed.ExceptWith(outcome.ApprovedPaths);
                    if(removed.Count > 0)
                    {
                        removedPaths = removed;
                    }
                }

                policyRecords.Add(new PolicyAssessmentRecord
                {
                    QueryRequirementId = match.QueryRequirementId,
                    AssessorName = outcome.AssessorName,
                    Approved = outcome.Approved,
                    RemovedPaths = removedPaths,
                    Reason = outcome.Reason
                });

                if(!outcome.Approved)
                {
                    policyRejected = true;
                    break;
                }

                if(outcome.ApprovedPaths is not null)
                {
                    currentPaths = outcome.ApprovedPaths;
                    currentSatisfies = match.RequiredPaths.IsSubsetOf(currentPaths);
                }
            }

            if(policyRejected)
            {
                continue;
            }

            var decision = new CredentialDisclosureDecision<TCredential>
            {
                Credential = match.Credential!,
                QueryRequirementId = match.QueryRequirementId,
                SelectedPaths = currentPaths,
                SatisfiesRequirements = currentSatisfies,
                ConflictingPaths = currentConflicts,
                UnavailablePaths = latticeResult.UnavailableClaims,
                Format = match.Format,
                Lattice = lattice
            };

            decisions.Add(decision);
            satisfiedRequirements.Add(match.QueryRequirementId);
        }

        //Determine unsatisfied requirements.
        var allRequirementIds = new HashSet<string>();
        foreach(var match in matches)
        {
            allRequirementIds.Add(match.QueryRequirementId);
        }

        var unsatisfied = new List<string>();
        foreach(var requirementId in allRequirementIds)
        {
            if(!satisfiedRequirements.Contains(requirementId))
            {
                unsatisfied.Add(requirementId);
            }
        }

        stopwatch.Stop();

        //Layer 6: Capture OTel trace context for the decision record.
        string? traceParent = null;
        string? traceState = null;
        string? spanId = null;
        if(activity is not null)
        {
            traceParent = activity.Id;
            traceState = activity.TraceStateString;
            spanId = activity.SpanId.ToString();
        }
        else if(Activity.Current is not null)
        {
            traceParent = Activity.Current.Id;
            traceState = Activity.Current.TraceStateString;
            spanId = Activity.Current.SpanId.ToString();
        }

        var decisionRecord = new DisclosureDecisionRecord<TCredential>
        {
            TraceParent = traceParent,
            TraceState = traceState,
            SpanId = spanId,
            Timestamp = startTime,
            Duration = stopwatch.Elapsed,
            CandidateCount = matches.Count,
            Evaluations = evaluationRecords,
            LatticeComputations = latticeRecords,
            PolicyAssessments = policyRecords.Count > 0 ? policyRecords : null,
            FinalDecisions = decisions,
            Satisfied = unsatisfied.Count == 0
        };

        return new DisclosurePlan<TCredential>
        {
            Satisfied = unsatisfied.Count == 0,
            Decisions = decisions,
            UnsatisfiedRequirements = unsatisfied.Count > 0 ? unsatisfied : null,
            DecisionRecord = decisionRecord
        };
    }
}