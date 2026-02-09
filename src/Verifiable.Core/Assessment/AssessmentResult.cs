using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.Assessment
{
    /// <summary>
    /// Delegate to assess a <see cref="ClaimIssueResult"/>.
    /// </summary>
    /// <param name="claimsToAssess">The claim issue result containing claims to assess.</param>
    /// <param name="assessorId">Identifier for the assessor.</param>
    /// <param name="creationTimestamp">
    /// UTC timestamp for the assessment result. Provided by the caller's time source.
    /// </param>
    /// <param name="traceId">Tracing identifier for the assessment operation.</param>
    /// <param name="spanId">Span identifier for the assessment operation.</param>
    /// <param name="baggage">Additional context for the assessment operation.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The assessment result.</returns>
    /// <remarks>
    /// <para>
    /// Assessment delegates evaluate the claims in a <see cref="ClaimIssueResult"/> and produce
    /// an overall <see cref="AssessmentResult"/>. The assessment logic can be as simple as checking
    /// if all claims succeeded, or as complex as applying domain-specific business rules.
    /// </para>
    /// <para>
    /// <strong>Time Handling:</strong>
    /// </para>
    /// <para>
    /// The <paramref name="creationTimestamp"/> is provided by the caller rather than generated
    /// internally. This ensures full testability and allows the caller to control the time source
    /// (e.g., using <see cref="TimeProvider"/> or a fake time provider in tests).
    /// </para>
    /// <para>
    /// <strong>Cancellation Handling:</strong>
    /// </para>
    /// <para>
    /// Assessment delegates should generally complete even when the <paramref name="cancellationToken"/>
    /// is cancelled. This allows partial claim results (from interrupted claim generation) to still
    /// be evaluated. The default assessors in <see cref="DefaultAssessors"/> follow this pattern.
    /// For long-running assessments, implementations may choose to check the token periodically.
    /// </para>
    /// </remarks>
    public delegate ValueTask<AssessmentResult> AssessDelegateAsync(
        ClaimIssueResult claimsToAssess,
        string assessorId,
        DateTime creationTimestamp,
        string? traceId,
        string? spanId,
        IReadOnlyDictionary<string, string>? baggage,
        CancellationToken cancellationToken = default);


    /// <summary>
    /// The context in which claims are assessed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="AssessmentContext"/> may hold information such as assessment rules, external
    /// references, and other contextual data that guides the assessment process. Extend this class
    /// to capture domain-specific assessment context.
    /// </para>
    /// </remarks>
    public class AssessmentContext
    {
    }


    /// <summary>
    /// Represents the result of an assessment operation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An <see cref="AssessmentResult"/> aggregates the outcome of assessing a <see cref="ClaimIssueResult"/>,
    /// providing a comprehensive record that includes:
    /// </para>
    /// <list type="bullet">
    /// <item><description>The overall success or failure of the assessment.</description></item>
    /// <item><description>The original claims that were assessed.</description></item>
    /// <item><description>Tracing information for distributed systems.</description></item>
    /// <item><description>Timestamps and version information for auditability.</description></item>
    /// </list>
    /// <para>
    /// <strong>Partial Claim Results:</strong>
    /// </para>
    /// <para>
    /// If the underlying <see cref="ClaimIssueResult.CompletionStatus"/> indicates that claim
    /// generation was cancelled or incomplete, assessors should consider this when determining
    /// the overall assessment success. A partial claim result may warrant special handling or
    /// a distinct assessment outcome.
    /// </para>
    /// </remarks>
    /// <param name="IsSuccess">
    /// Indicates if the assessment was successful based on the assessor's logic.
    /// </param>
    /// <param name="AssessorId">
    /// Identifier for the assessor that performed this assessment.
    /// </param>
    /// <param name="AssessmentId">
    /// Unique identifier for this particular assessment.
    /// </param>
    /// <param name="CorrelationId">
    /// User-supplied identifier to correlate the assessment with other operations.
    /// </param>
    /// <param name="AssessorVersion">
    /// Version information of the assessor, useful for tracking assessment logic changes.
    /// </param>
    /// <param name="CreationTimestampInUtc">
    /// UTC timestamp indicating when the assessment result was generated. Provided by the
    /// caller's time source.
    /// </param>
    /// <param name="AssessmentContext">
    /// Optional context data related to the assessment.
    /// </param>
    /// <param name="ClaimsResult">
    /// The claim issue result that was assessed, containing the original claims, inputs,
    /// and tracing information.
    /// </param>
    /// <param name="TraceId">
    /// Tracing identifier for the assessment operation.
    /// </param>
    /// <param name="SpanId">
    /// Span identifier for the assessment operation.
    /// </param>
    /// <param name="Baggage">
    /// Additional context for the assessment operation.
    /// </param>
    public record AssessmentResult(
        bool IsSuccess,
        string AssessorId,
        string AssessmentId,
        string CorrelationId,
        string AssessorVersion,
        DateTime CreationTimestampInUtc,
        AssessmentContext? AssessmentContext,
        ClaimIssueResult ClaimsResult,
        string? TraceId,
        string? SpanId,
        IReadOnlyDictionary<string, string>? Baggage);


    /// <summary>
    /// Provides default assessor implementations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These default assessors provide simple "all claims must succeed" logic. For more complex
    /// assessment requirements, implement custom <see cref="AssessDelegateAsync"/> delegates.
    /// </para>
    /// </remarks>
    public static class DefaultAssessors
    {
        /// <summary>
        /// The default assessor version string.
        /// </summary>
        private const string DefaultAssessorVersion = "1.0.0";


        /// <summary>
        /// Default assessor for <c>did:key</c> DID documents.
        /// </summary>
        /// <param name="claimsToAssess">The claims to assess.</param>
        /// <param name="assessorId">Identifier for the assessor.</param>
        /// <param name="creationTimestamp">UTC timestamp for the assessment.</param>
        /// <param name="traceId">Tracing identifier.</param>
        /// <param name="spanId">Span identifier.</param>
        /// <param name="baggage">Additional context.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// An <see cref="AssessmentResult"/> indicating success if all claims succeeded and the
        /// claim result is complete.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This assessor considers the assessment successful only if:
        /// </para>
        /// <list type="bullet">
        /// <item><description>
        /// The <see cref="ClaimIssueResult.CompletionStatus"/> is
        /// <see cref="ClaimIssueCompletionStatus.Complete"/>.
        /// </description></item>
        /// <item><description>
        /// All claims have <see cref="ClaimOutcome.Success"/> outcome.
        /// </description></item>
        /// </list>
        /// </remarks>
        public static ValueTask<AssessmentResult> DefaultKeyDidAssessorAsync(
            ClaimIssueResult claimsToAssess,
            string assessorId,
            DateTime creationTimestamp,
            string? traceId,
            string? spanId,
            IReadOnlyDictionary<string, string>? baggage,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(claimsToAssess);
            //Note: We intentionally do not throw on cancellation here.
            //Assessment is fast and we want to evaluate partial results
            //even when the token was cancelled during claim generation.

            var allClaimsValid = claimsToAssess.IsComplete
                && claimsToAssess.Claims.All(claim => claim.Outcome == ClaimOutcome.Success);

            var assessmentId = Guid.NewGuid().ToString();
            var assessmentContext = new AssessmentContext();

            var assessmentResult = new AssessmentResult(
                IsSuccess: allClaimsValid,
                AssessorId: assessorId,
                AssessmentId: assessmentId,
                CorrelationId: claimsToAssess.CorrelationId,
                AssessorVersion: DefaultAssessorVersion,
                CreationTimestampInUtc: creationTimestamp,
                AssessmentContext: assessmentContext,
                ClaimsResult: claimsToAssess,
                TraceId: traceId,
                SpanId: spanId,
                Baggage: baggage);

            return ValueTask.FromResult(assessmentResult);
        }


        /// <summary>
        /// Default assessor for <c>did:web</c> DID documents.
        /// </summary>
        /// <param name="claimsToAssess">The claims to assess.</param>
        /// <param name="assessorId">Identifier for the assessor.</param>
        /// <param name="creationTimestamp">UTC timestamp for the assessment.</param>
        /// <param name="traceId">Tracing identifier.</param>
        /// <param name="spanId">Span identifier.</param>
        /// <param name="baggage">Additional context.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// An <see cref="AssessmentResult"/> indicating success if all claims succeeded and the
        /// claim result is complete.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This assessor considers the assessment successful only if:
        /// </para>
        /// <list type="bullet">
        /// <item><description>
        /// The <see cref="ClaimIssueResult.CompletionStatus"/> is
        /// <see cref="ClaimIssueCompletionStatus.Complete"/>.
        /// </description></item>
        /// <item><description>
        /// All claims have <see cref="ClaimOutcome.Success"/> outcome.
        /// </description></item>
        /// </list>
        /// </remarks>
        public static ValueTask<AssessmentResult> DefaultWebDidAssessorAsync(
            ClaimIssueResult claimsToAssess,
            string assessorId,
            DateTime creationTimestamp,
            string? traceId,
            string? spanId,
            IReadOnlyDictionary<string, string>? baggage,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(claimsToAssess);
            //Note: We intentionally do not throw on cancellation here.
            //Assessment is fast and we want to evaluate partial results
            //even when the token was cancelled during claim generation.

            var allClaimsValid = claimsToAssess.IsComplete
                && claimsToAssess.Claims.All(claim => claim.Outcome == ClaimOutcome.Success);

            var assessmentId = Guid.NewGuid().ToString();
            var assessmentContext = new AssessmentContext();

            var assessmentResult = new AssessmentResult(
                IsSuccess: allClaimsValid,
                AssessorId: assessorId,
                AssessmentId: assessmentId,
                CorrelationId: claimsToAssess.CorrelationId,
                AssessorVersion: DefaultAssessorVersion,
                CreationTimestampInUtc: creationTimestamp,
                AssessmentContext: assessmentContext,
                ClaimsResult: claimsToAssess,
                TraceId: traceId,
                SpanId: spanId,
                Baggage: baggage);

            return ValueTask.FromResult(assessmentResult);
        }
    }
}