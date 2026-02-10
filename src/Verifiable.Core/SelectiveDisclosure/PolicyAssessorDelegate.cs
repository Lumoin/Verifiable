using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// A policy assessor that evaluates a proposed disclosure and may approve,
/// narrow, or reject it.
/// </summary>
/// <remarks>
/// <para>
/// Assessors are composed in a pipeline within <see cref="DisclosureComputation{TCredential}"/>.
/// Each assessor receives the output of the previous assessor (or the lattice computation
/// for the first assessor). The pipeline processes assessors in order; a rejection stops
/// the pipeline for that credential.
/// </para>
/// <para>
/// <strong>Presentation-side assessors</strong> (holder deciding what to reveal):
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Consent mediator:</strong> Prompts the user for approval, possibly
/// through a UI callback or stored consent policy. In autonomous agent scenarios,
/// the mediator may consult pre-configured delegation tokens or intent projections
/// instead of a live user prompt.
/// </description></item>
/// <item><description>
/// <strong>SAT/constraint solver:</strong> For multi-credential queries with complex
/// cross-credential constraints (e.g., "disclose name from credential A OR credential B,
/// but never both SSNs"), a SAT solver or ILP solver assessor can model the selection
/// as a boolean satisfiability or linear optimization problem over the lattice and find
/// the globally optimal combination across all credentials in the plan.
/// </description></item>
/// <item><description>
/// <strong>AI risk assessor:</strong> Evaluates the disclosure against a risk model
/// considering factors such as verifier trust level, data sensitivity, request context
/// (time, location, purpose), and the holder's historical disclosure patterns. Can
/// produce SHAP-style explanations attached to the <see cref="PolicyAssessmentOutcome.Reason"/>
/// for auditability and transparency.
/// </description></item>
/// <item><description>
/// <strong>Regulatory filter:</strong> Ensures compliance with jurisdiction-specific
/// rules (e.g., GDPR data minimization, age data restrictions for certain verifier
/// categories, Chinese Wall policies in financial contexts).
/// </description></item>
/// <item><description>
/// <strong>Differential privacy:</strong> Removes or generalizes paths that
/// would exceed a privacy budget across repeated disclosures.
/// </description></item>
/// <item><description>
/// <strong>ZKP escalation:</strong> Detects predicate-friendly claims (e.g., age ≥ 18,
/// income thresholds, set membership) and marks them for zero-knowledge proof generation
/// instead of raw disclosure, working with format-specific ZKP provider plugins downstream.
/// </description></item>
/// </list>
/// <para>
/// <strong>Issuance-side assessors</strong> (issuer deciding what to make selectively disclosable):
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Organizational issuance policy:</strong> Enforces rules like "SSN must always
/// be selectively disclosable" or "credential type and issuer must always be mandatory."
/// Operates on the same lattice structure, where the policy determines which paths are
/// classified as mandatory (lattice bottom) versus selectively disclosable.
/// </description></item>
/// <item><description>
/// <strong>Regulatory issuance constraints:</strong> Ensures issued credentials comply
/// with data protection requirements at creation time, such as eIDAS or Digital Product
/// Passport mandates for which attributes must be present and which must be redactable.
/// </description></item>
/// </list>
/// <para>
/// <strong>Pipeline composition:</strong> Multiple assessors can run in sequence, with each
/// narrowing the proposed path set. The <see cref="DisclosureComputation{TCredential}"/>
/// aggregates all assessor outcomes into the <see cref="DisclosureDecisionRecord{TCredential}"/>
/// for full traceability. Assessors may also run concurrently in advanced deployments
/// (e.g., multiple AI models scoring independently), with results merged by a routing
/// assessor that applies a conflict resolution strategy.
/// </para>
/// </remarks>
/// <typeparam name="TCredential">The application-specific credential type.</typeparam>
/// <param name="context">The assessment context with proposed disclosure and lattice.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The assessment outcome.</returns>
public delegate Task<PolicyAssessmentOutcome> PolicyAssessorDelegate<TCredential>(
    PolicyAssessmentContext<TCredential> context,
    CancellationToken cancellationToken);