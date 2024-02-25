using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;


namespace Verifiable.Assessment
{
    /// <summary>
    /// Delegate to assess a <see cref="ClaimIssueResult"/>.
    /// </summary>
    /// <param name="claimsToAssess">List of claims to assess.</param>
    /// <param name="assessorId">Identifier for the assessor.</param>
    /// <param name="traceId">Tracing identifier for the assessment operation.</param>
    /// <param name="spanId">Span identifier for the assessment operation.</param>
    /// <param name="baggage">Additional context for the assessment operation.</param>
    /// <returns>The evaluation result.</returns>
    public delegate ValueTask<AssessmentResult> AssessDelegateAsync(
        ClaimIssueResult claimsToAssess,
        string assessorId,
        string? traceId,
        string? spanId,
        IReadOnlyDictionary<string, string>? baggage);


    /// <summary>
    /// The context in which claims are assessed.
    /// It may hold information such as assessment rules, external references, 
    /// and other contextual data that guides the assessment process.
    /// </summary>
    public class AssessmentContext
    {
    }


    /// <summary>
    /// Represents the result of an assessment operation.
    /// </summary>    
    /// <param name="IsSuccess">Indicates if the assessment was successful.</param>
    /// <param name="AssessorId">Identifier for the assessor.</param>
    /// <param name="AssessmentId">Identifier for this particular assessment for the given claims.</param>
    /// <param name="CorrelationId">User-supplied identifier to correlate the assessment with other operations.</param>
    /// <param name="AssessorVersion">Version information of the assessor.</param>
    /// <param name="CreationTimestampInUtc">UTC timestamp indicating when the assessment result was generated.</param>
    /// <param name="AssessmentContext">Optional context data related to the assessment.</param>
    /// <param name="ClaimsResult">The result of the claim issue operation, containing inputs, claims, and tracing information.</param>
    /// <param name="TraceId">Tracing identifier for the assessment operation.</param>
    /// <param name="SpanId">Span identifier for the assessment operation.</param>
    /// <param name="Baggage">Additional context for the assessment operation.</param>
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


    //Just a placehoder for now...
    public static class DefaultAssessors
    {
        public static async ValueTask<AssessmentResult> DefaultKeyDidAssessorAsync(
            ClaimIssueResult claimsToAssess,
            string assessorId,
            string? traceId,
            string? spanId,
            IReadOnlyDictionary<string, string>? baggage)
        {
            var allClaimsValid = claimsToAssess.Claims.All(claim => claim.Outcome == ClaimOutcome.Success);

            var assessmentId = Guid.NewGuid().ToString();
            var assessorVersion = "1.0.0";  // Assume a version for the assessor
            var creationTimestampInUtc = DateTime.UtcNow;
            var assessmentContext = new AssessmentContext();  // Assume an empty context

            var assessmentResult = new AssessmentResult(
                IsSuccess: allClaimsValid,
                assessorId,
                AssessmentId: assessmentId,
                CorrelationId: claimsToAssess.CorrelationId,
                AssessorVersion: assessorVersion,
                CreationTimestampInUtc: creationTimestampInUtc,
                AssessmentContext: assessmentContext,
                ClaimsResult: claimsToAssess,
                TraceId: traceId,
                SpanId: spanId,
                Baggage: baggage
            );

            return await ValueTask.FromResult(assessmentResult);
        }


        public static async ValueTask<AssessmentResult> DefaultWebDidAssessorAsync(
            ClaimIssueResult claimsToAssess,
            string assessorId,
            string? traceId,
            string? spanId,
            IReadOnlyDictionary<string, string>? baggage)
        {
            var allClaimsValid = claimsToAssess.Claims.All(claim => claim.Outcome == ClaimOutcome.Success);

            var assessmentId = Guid.NewGuid().ToString();
            var assessorVersion = "1.0.0";  // Assume a version for the assessor
            var creationTimestampInUtc = DateTime.UtcNow;
            var assessmentContext = new AssessmentContext();  // Assume an empty context

            var assessmentResult = new AssessmentResult(
                IsSuccess: allClaimsValid,
                assessorId,
                AssessmentId: assessmentId,
                CorrelationId: claimsToAssess.CorrelationId,
                AssessorVersion: assessorVersion,
                CreationTimestampInUtc: creationTimestampInUtc,
                AssessmentContext: assessmentContext,
                ClaimsResult: claimsToAssess,
                TraceId: traceId,
                SpanId: spanId,
                Baggage: baggage
            );

            return await ValueTask.FromResult(assessmentResult);
        }
    }
}
