using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.SelectiveDisclosure.Strategy;


namespace Verifiable.Core.Model.SelectiveDisclosure;

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
/// and produces a <see cref="DisclosureStrategyGraph{TCredential}"/>.
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
/// <strong>Layer 4 — Policy decision (this class):</strong> A two-level pipeline.
/// Layer 4a runs per-credential <see cref="PolicyAssessorDelegate{TCredential}"/> assessors
/// in sequence; each can narrow, expand, or reject.
/// Layer 4b runs <see cref="CrossCredentialOptimizerDelegate{TCredential}"/> instances
/// that receive all per-credential decisions and can redistribute paths across credentials
/// for global optimization (SAT solvers, ILP, LLM-based reasoners).
/// Neither level is trusted with the bounds: every set either one returns is clamped into
/// the credential's own lattice before it is adopted, and an out-of-bounds return is recorded
/// (see <strong>Bound enforcement</strong> below).
/// Assessor implementations include:
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
/// <strong>Layer 5 — Format encoding:</strong> The <see cref="DisclosureStrategyGraph{TCredential}"/>
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
/// │  │  Layer 3   SetDisclosureLattice (ancestry-aware)  │             │
/// │  │                                                     │             │
/// │  │  mandatory (⊥) ⊆ disclosure set ⊆ all paths (⊤)   │             │
/// │  │                                                     │             │
/// │  │  Operations: Join (∨), Meet (∧), Closure, Clamp    │             │
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
/// │  │  Layer 6   DisclosureStrategyGraph + DecisionRecord         │             │
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
/// can narrow, expand, or reject entirely; rejection stops the pipeline for that credential.
/// Each returned set is clamped into the credential's lattice before the next assessor, the
/// decision, or the effect diff sees it (Layer 4a). Then run
/// <see cref="CrossCredentialOptimizerDelegate{TCredential}"/> instances that optimize
/// across all credential decisions, each returned decision clamped against its own lattice
/// (Layer 4b).
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
/// <item><description>Minimality: S = M ∪ ((V \ E) ∩ A) when no policy component runs — the lattice adds nothing the verifier did not ask for.</description></item>
/// <item><description>Upward closure: ∀p ∈ S, ∀q ancestor of p with q ∈ A → q ∈ S, for every S a policy component contributes (structural validity is preserved).</description></item>
/// <item><description>Policy bounding: an assessor or optimizer may narrow S or expand it, and either way the result is clamped to M ⊆ S ⊆ A and closed upward; the returned set is never adopted as given.</description></item>
/// <item><description>Exclusion safety: E ∩ M = ∅ semantically (user exclusions of mandatory paths are silently ignored).</description></item>
/// </list>
/// <para>
/// <strong>Bound enforcement:</strong>
/// </para>
/// <para>
/// The invariants hold because the pipeline treats every set arriving from a policy component
/// as a proposal, not a decision. A policy assessor is a plug-in — a rule engine, a solver, an
/// AI risk model, a consent mediator — and the architecture deliberately admits components
/// whose internal reasoning cannot be inspected. Trusting such a component to respect M ⊆ S ⊆ A
/// would leave the strongest structural guarantee in the hands of the least boundable
/// participant, so the pipeline does not: it clamps each returned set with
/// <see cref="SetDisclosureLattice{TClaim}.Clamp"/> — intersect with the top, union the
/// mandatory bottom, close upward — and only then adopts it. The same clamp runs on every
/// decision a cross-credential optimizer returns, against that decision's own lattice.
/// </para>
/// <para>
/// Clamping is not silence. A proposal that left the lattice is an auditable event, kept in
/// the provenance trail split by violation shape: <see cref="PolicyAssessmentRecord"/> carries
/// it for assessors and <see cref="DisclosureDecisionRecord{TCredential}.BoundViolations"/>
/// for optimizers. The effect diff runs against the clamped set, so
/// <see cref="PolicyAssessmentRecord.Effect"/>, <see cref="PolicyAssessmentRecord.AddedPaths"/>
/// and <see cref="PolicyAssessmentRecord.RemovedPaths"/> describe what happened to the
/// disclosure set while the violation fields describe what was attempted.
/// </para>
/// <para>
/// <strong>Authority monotonicity and provenance:</strong>
/// </para>
/// <para>
/// The lattice structure enforces a fundamental property: authority over disclosed information
/// can only shrink along the credential chain. At issuance, the issuer defines the top of the
/// lattice (all available paths). The holder can only narrow this to a subset. The verifier
/// receives only what the holder chose to reveal. At no step can authority grow beyond what the
/// previous participant granted. This monotone decreasing property — ⊤ ⊇ S_issuer ⊇ S_holder ⊇
/// S_verifier ⊇ ⊥ — is a structural guarantee of the bounded lattice rather than an
/// application-level policy, and it is structural precisely because the clamp described above
/// holds it against every component the pipeline runs, including the ones an application
/// supplies. The <see cref="DisclosureDecisionRecord{TCredential}"/> captures
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
    /// Per-credential policy assessors executed in sequence after lattice computation.
    /// </summary>
    private IReadOnlyList<PolicyAssessorDelegate<TCredential>> PolicyAssessors { get; }

    /// <summary>
    /// Cross-credential optimizers executed after per-credential assessment completes.
    /// </summary>
    private IReadOnlyList<CrossCredentialOptimizerDelegate<TCredential>> CrossCredentialOptimizers { get; }

    /// <summary>
    /// Entropy computation delegate for strategy scoring. When <see langword="null"/>,
    /// <see cref="DisclosureStrategyGraph{TCredential}.AdditiveEntropy"/> is used.
    /// </summary>
    private EntropyComputeDelegate<TCredential>? EntropyCompute { get; }

    /// <summary>
    /// Time provider for decision record timestamps.
    /// </summary>
    private TimeProvider TimeProvider { get; }

    /// <summary>
    /// Creates a new disclosure computation with the specified configuration.
    /// </summary>
    /// <param name="policyAssessors">
    /// Per-credential policy assessors to run in order after lattice computation.
    /// Pass an empty list for no per-credential policy enforcement.
    /// </param>
    /// <param name="crossCredentialOptimizers">
    /// Cross-credential optimizers to run after per-credential assessment. Pass an
    /// empty list or <see langword="null"/> for no cross-credential optimization.
    /// </param>
    /// <param name="entropyCompute">
    /// Custom entropy computation delegate for strategy scoring. If <see langword="null"/>,
    /// the default additive model sums per-path entropy weights.
    /// </param>
    /// <param name="timeProvider">
    /// Time provider for timestamps. Defaults to <see cref="TimeProvider.System"/>.
    /// </param>
    public DisclosureComputation(
        IReadOnlyList<PolicyAssessorDelegate<TCredential>> policyAssessors,
        IReadOnlyList<CrossCredentialOptimizerDelegate<TCredential>>? crossCredentialOptimizers = null,
        EntropyComputeDelegate<TCredential>? entropyCompute = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(policyAssessors);
        PolicyAssessors = policyAssessors;
        CrossCredentialOptimizers = crossCredentialOptimizers ?? [];
        EntropyCompute = entropyCompute;
        TimeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Creates a new disclosure computation with no policy assessors or optimizers.
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
    /// <param name="requestingPartySignals">
    /// Contextual signals from the requesting party and environment. Merged with
    /// per-credential attestation metadata and provided to policy assessors and
    /// cross-credential optimizers.
    /// </param>
    /// <param name="entropyWeights">
    /// Per-path entropy weights for strategy scoring. Maps credential paths to their
    /// identifying power (higher values indicate more identifying information). Paths
    /// not in the dictionary default to zero entropy weight. When <see langword="null"/>,
    /// all paths are treated as having zero entropy weight and strategy selection falls
    /// back to minimizing credential count.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The disclosure strategy graph with the lowest-entropy strategy selected by default.
    /// Access <c>Satisfied</c>, <c>Decisions</c>, and <c>DecisionRecord</c> for the flat
    /// projection. Access <c>Frontier</c>, <c>SelectedStrategy</c>, and
    /// <c>EnumerateStrategies()</c> for the full trade-off space.
    /// </returns>
    public async Task<DisclosureStrategyGraph<TCredential>> ComputeAsync(
        IReadOnlyList<DisclosureMatch<TCredential>> matches,
        IReadOnlyDictionary<string, IReadOnlySet<CredentialPath>>? userExclusions = null,
        IReadOnlyDictionary<Type, object>? requestingPartySignals = null,
        IReadOnlyDictionary<CredentialPath, double>? entropyWeights = null,
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
                mandatoryPaths,
                ancestors: CredentialPath.Ancestry);

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

            //Merge requesting party signals with attestation metadata for this credential.
            IReadOnlyDictionary<Type, object>? mergedSignals = MergeSignals(
                requestingPartySignals, match.AttestationMetadata);

            //Layer 4a: Run per-credential policy assessor pipeline.
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
                    Format = match.Format,
                    Signals = mergedSignals
                };

                var outcome = await assessor(context, cancellationToken).ConfigureAwait(false);

                //Layer 6: Compute effect by diffing input versus output paths.
                IReadOnlySet<CredentialPath>? removedPaths = null;
                IReadOnlySet<CredentialPath>? addedPaths = null;
                DisclosureClampResult<CredentialPath>? clamp = null;
                PolicyAssessmentEffect computedEffect = PolicyAssessmentEffect.Unchanged;

                if(!outcome.Approved)
                {
                    computedEffect = PolicyAssessmentEffect.Rejected;
                }
                else if(outcome.ApprovedPaths is not null)
                {
                    //An assessor returns a PROPOSAL. Clamping it back into the credential's own
                    //lattice happens before anything else observes it, so the set that reaches
                    //the next assessor, the decision, and the wire is one the lattice admits.
                    //The order matters: the diff below then describes what actually happened to
                    //the disclosure set, not what the assessor attempted. An assessor that
                    //"expands" entirely outside the lattice therefore records Unchanged plus the
                    //out-of-bounds paths, which is the truthful account of both facts.
                    clamp = lattice.Clamp(outcome.ApprovedPaths);

                    var removed = new HashSet<CredentialPath>(currentPaths);
                    removed.ExceptWith(clamp.ClampedClaims);

                    var added = new HashSet<CredentialPath>(clamp.ClampedClaims);
                    added.ExceptWith(currentPaths);

                    if(removed.Count > 0)
                    {
                        removedPaths = removed;
                    }

                    if(added.Count > 0)
                    {
                        addedPaths = added;
                    }

                    computedEffect = (removed.Count > 0, added.Count > 0) switch
                    {
                        (true, true) => PolicyAssessmentEffect.Modified,
                        (true, false) => PolicyAssessmentEffect.Narrowed,
                        (false, true) => PolicyAssessmentEffect.Expanded,
                        _ => PolicyAssessmentEffect.Unchanged
                    };
                }

                policyRecords.Add(new PolicyAssessmentRecord
                {
                    QueryRequirementId = match.QueryRequirementId,
                    AssessorName = outcome.AssessorName,
                    Approved = outcome.Approved,
                    Effect = computedEffect,
                    RemovedPaths = removedPaths,
                    AddedPaths = addedPaths,
                    OutOfBoundsPaths = clamp?.OutOfBoundsClaims,
                    RestoredMandatoryPaths = clamp?.RestoredMandatoryClaims,
                    RestoredAncestorPaths = clamp?.RestoredAncestorClaims,
                    Reason = outcome.Reason
                });

                if(!outcome.Approved)
                {
                    policyRejected = true;
                    break;
                }

                if(clamp is not null)
                {
                    currentPaths = clamp.ClampedClaims;
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

        //Layer 4b: Run cross-credential optimizer pipeline. Each pass returns a whole decision
        //list, so each pass is clamped: an optimizer redistributes paths across credentials and
        //must land inside every credential's lattice to do it legitimately.
        List<CredentialDisclosureDecision<TCredential>> optimizedDecisions = decisions;
        var boundViolations = new List<BoundViolationRecord>();

        for(int optimizerIndex = 0; optimizerIndex < CrossCredentialOptimizers.Count; optimizerIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var optimizerResult = await CrossCredentialOptimizers[optimizerIndex](
                optimizedDecisions, requestingPartySignals, cancellationToken).ConfigureAwait(false);

            optimizedDecisions = ClampToLatticeBounds(optimizerResult, optimizerIndex, boundViolations);
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
            BoundViolations = boundViolations.Count > 0 ? boundViolations : null,
            FinalDecisions = optimizedDecisions,
            Satisfied = unsatisfied.Count == 0
        };

        //Layer 5: Build the strategy graph from optimized decisions.
        IReadOnlyList<CredentialContribution<TCredential>>[] candidateArrays = [];

        if(optimizedDecisions.Count > 0)
        {
            //Group decisions by requirement to form per-requirement candidate arrays.
            var candidatesByRequirement = new Dictionary<string, List<CredentialContribution<TCredential>>>();

            foreach(var decision in optimizedDecisions)
            {
                if(!candidatesByRequirement.TryGetValue(decision.QueryRequirementId, out var candidates))
                {
                    candidates = [];
                    candidatesByRequirement[decision.QueryRequirementId] = candidates;
                }

                candidates.Add(BuildContribution(decision, entropyWeights));
            }

            candidateArrays = candidatesByRequirement.Values
                .Select(list => (IReadOnlyList<CredentialContribution<TCredential>>)list)
                .ToArray();
        }

        var graph = new DisclosureStrategyGraph<TCredential>(
            candidateArrays,
            entropyCompute: EntropyCompute,
            signals: requestingPartySignals)
        {
            Satisfied = unsatisfied.Count == 0,
            Decisions = optimizedDecisions,
            UnsatisfiedRequirements = unsatisfied.Count > 0 ? unsatisfied : null,
            DecisionRecord = decisionRecord
        };

        //Select the lowest-entropy strategy and project its decisions.
        var selectedStrategy = graph.SelectLowestEntropy();
        if(selectedStrategy is not null)
        {
            graph.Decisions = ProjectStrategyToDecisions(selectedStrategy, optimizedDecisions);
        }

        return graph;
    }


    /// <summary>
    /// Clamps every decision returned by a cross-credential optimizer back into that decision's
    /// own lattice, appending a <see cref="BoundViolationRecord"/> for each one that had left it.
    /// </summary>
    /// <param name="decisions">The decisions the optimizer returned.</param>
    /// <param name="optimizerIndex">The optimizer's position in the cross-credential pipeline.</param>
    /// <param name="boundViolations">The accumulating provenance list for the decision record.</param>
    /// <returns>The decisions with every bounded selection replaced by its clamped set.</returns>
    private static List<CredentialDisclosureDecision<TCredential>> ClampToLatticeBounds(
        IReadOnlyList<CredentialDisclosureDecision<TCredential>> decisions,
        int optimizerIndex,
        List<BoundViolationRecord> boundViolations)
    {
        var clampedDecisions = new List<CredentialDisclosureDecision<TCredential>>(decisions.Count);

        foreach(var decision in decisions)
        {
            //A decision carries the lattice it was computed against, and that lattice is what
            //bounds it. A decision arriving without one was not produced by this pipeline, so
            //there is nothing to clamp it to and it passes through as the optimizer returned it.
            //Identity beyond that — an optimizer that duplicates a decision or attaches a lattice
            //it did not receive — is the optimizer contract's to keep, not this clamp's: the
            //clamp bounds every set whose lattice travelled with it.
            if(decision.Lattice is null)
            {
                clampedDecisions.Add(decision);
                continue;
            }

            var clamp = decision.Lattice.Clamp(decision.SelectedPaths);
            if(clamp.IsWithinBounds)
            {
                clampedDecisions.Add(decision);
                continue;
            }

            boundViolations.Add(new BoundViolationRecord
            {
                QueryRequirementId = decision.QueryRequirementId,
                OptimizerIndex = optimizerIndex,
                OutOfBoundsPaths = clamp.OutOfBoundsClaims,
                RestoredMandatoryPaths = clamp.RestoredMandatoryClaims,
                RestoredAncestorPaths = clamp.RestoredAncestorClaims
            });

            //SatisfiesRequirements stays as the optimizer reported it. The clamp only ever drops
            //claims outside the lattice top, and a requirement resolved against that lattice
            //cannot name one — a requirement naming a path the credential does not have is
            //already reported through UnavailablePaths — so bounding the set does not silently
            //invalidate a satisfaction the optimizer computed over the credential's own claims.
            clampedDecisions.Add(new CredentialDisclosureDecision<TCredential>
            {
                Credential = decision.Credential,
                QueryRequirementId = decision.QueryRequirementId,
                SelectedPaths = clamp.ClampedClaims,
                SatisfiesRequirements = decision.SatisfiesRequirements,
                ConflictingPaths = decision.ConflictingPaths,
                UnavailablePaths = decision.UnavailablePaths,
                Format = decision.Format,
                Lattice = decision.Lattice
            });
        }

        return clampedDecisions;
    }


    /// <summary>
    /// Builds a <see cref="CredentialContribution{TCredential}"/> from a per-credential
    /// decision. All selected paths become disclosures with entropy weights from the
    /// provided weight dictionary.
    /// </summary>
    private static CredentialContribution<TCredential> BuildContribution(
        CredentialDisclosureDecision<TCredential> decision,
        IReadOnlyDictionary<CredentialPath, double>? entropyWeights)
    {
        //A decision may legitimately select zero paths: when the engine is run to
        //ASSESS a presentation (verifier side) rather than to produce one, a
        //credential that cannot satisfy the query — a required claim absent, or an
        //empty disclosed set — yields an empty selection and an unsatisfied decision.
        //That is a valid, expected outcome, not an invariant violation; the empty
        //contribution simply adds nothing to the strategy.
        var disclosures = new List<PathContribution>();
        foreach(var path in decision.SelectedPaths)
        {
            double weight = 0.0;
            entropyWeights?.TryGetValue(path, out weight);

            disclosures.Add(new PathContribution
            {
                Path = path,
                Mode = SatisfactionMode.Disclosure,
                EntropyWeight = weight
            });
        }

        Debug.Assert(disclosures.Count == decision.SelectedPaths.Count,
            "Every selected path must produce a disclosure contribution.");

        return new CredentialContribution<TCredential>
        {
            Credential = decision.Credential,
            QueryRequirementId = decision.QueryRequirementId,
            Disclosures = disclosures,
            Predicates = [],
            Lattice = decision.Lattice
        };
    }


    /// <summary>
    /// Projects a selected strategy's contributions back to the original decision list.
    /// Returns the original decisions filtered and reordered to match the strategy.
    /// Each contribution must find exactly one matching original decision.
    /// </summary>
    private static List<CredentialDisclosureDecision<TCredential>> ProjectStrategyToDecisions(
        ScoredStrategy<TCredential> strategy,
        IReadOnlyList<CredentialDisclosureDecision<TCredential>> originalDecisions)
    {
        Debug.Assert(strategy.Contributions.Count > 0,
            "Strategy must have at least one contribution to project.");

        //The strategy's contributions map 1:1 to requirement IDs + credentials.
        //Find the matching original decision for each contribution.
        var projected = new List<CredentialDisclosureDecision<TCredential>>();

        foreach(var contribution in strategy.Contributions)
        {
            foreach(var decision in originalDecisions)
            {
                if(decision.QueryRequirementId == contribution.QueryRequirementId &&
                   EqualityComparer<TCredential>.Default.Equals(decision.Credential, contribution.Credential))
                {
                    projected.Add(decision);
                    break;
                }
            }
        }

        Debug.Assert(projected.Count == strategy.Contributions.Count,
            "Every contribution must project to exactly one original decision.");

        return projected;
    }


    /// <summary>
    /// Merges requesting party signals with per-credential attestation metadata.
    /// Attestation metadata takes precedence when both contain the same type key.
    /// </summary>
    private static IReadOnlyDictionary<Type, object>? MergeSignals(
        IReadOnlyDictionary<Type, object>? requestingPartySignals,
        IReadOnlyDictionary<Type, object>? attestationMetadata)
    {
        if(requestingPartySignals is null && attestationMetadata is null)
        {
            return null;
        }

        if(requestingPartySignals is null)
        {
            return attestationMetadata;
        }

        if(attestationMetadata is null)
        {
            return requestingPartySignals;
        }

        //Both present: merge with attestation metadata taking precedence.
        var merged = new Dictionary<Type, object>(requestingPartySignals);
        foreach(var kvp in attestationMetadata)
        {
            merged[kvp.Key] = kvp.Value;
        }

        return merged;
    }
}
