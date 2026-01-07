using System;
using System.Collections.Generic;
using System.Linq;

namespace Verifiable.Core.Assessment
{
    /// <summary>
    /// Indicates the completion status of an individual assessor within a composite assessment.
    /// </summary>
    public enum AssessorCompletionStatus
    {
        /// <summary>
        /// The assessor completed successfully.
        /// </summary>
        Completed,

        /// <summary>
        /// The assessor was cancelled before completing.
        /// </summary>
        Cancelled,

        /// <summary>
        /// The assessor timed out before completing.
        /// </summary>
        TimedOut,

        /// <summary>
        /// The assessor threw an exception during execution.
        /// </summary>
        Faulted
    }


    /// <summary>
    /// Represents the result of a single assessor within a composite assessment,
    /// including its completion status and any error information.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When multiple assessors run in parallel, some may complete while others fail,
    /// time out, or get cancelled. This record captures the outcome of each individual
    /// assessor, enabling partial result aggregation and detailed diagnostics.
    /// </para>
    /// </remarks>
    /// <param name="AssessorId">Identifier of the assessor that produced this result.</param>
    /// <param name="CompletionStatus">Indicates how the assessor completed.</param>
    /// <param name="Result">
    /// The assessment result if <see cref="CompletionStatus"/> is <see cref="AssessorCompletionStatus.Completed"/>;
    /// otherwise <see langword="null"/>.
    /// </param>
    /// <param name="ErrorMessage">
    /// Error message if <see cref="CompletionStatus"/> is <see cref="AssessorCompletionStatus.Faulted"/>;
    /// otherwise <see langword="null"/>.
    /// </param>
    /// <param name="Duration">Time taken by this assessor, useful for performance analysis.</param>
    /// <param name="SpanId">
    /// OpenTelemetry span ID for this specific assessor invocation, enabling trace correlation.
    /// </param>
    public record IndividualAssessorResult(
        string AssessorId,
        AssessorCompletionStatus CompletionStatus,
        AssessmentResult? Result,
        string? ErrorMessage,
        TimeSpan Duration,
        string? SpanId)
    {
        /// <summary>
        /// Gets a value indicating whether this assessor completed successfully.
        /// </summary>
        public bool IsCompleted => CompletionStatus == AssessorCompletionStatus.Completed;

        /// <summary>
        /// Gets a value indicating whether this assessor's result indicates success.
        /// Returns <see langword="false"/> if the assessor did not complete.
        /// </summary>
        public bool IsSuccess => IsCompleted && (Result?.IsSuccess ?? false);
    }


    /// <summary>
    /// Represents the aggregated result of multiple assessors evaluating the same claims,
    /// supporting parallel execution with partial result collection.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The <see cref="AggregatedAssessmentResult"/> collects results from multiple assessors
    /// that may include:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Local rule-based assessors (fast, in-memory).</description></item>
    /// <item><description>Machine learning model inference (local or remote).</description></item>
    /// <item><description>Remote AI service calls (LLMs, specialized models).</description></item>
    /// <item><description>Compliance validation services.</description></item>
    /// </list>
    /// <para>
    /// <strong>Partial Results:</strong>
    /// </para>
    /// <para>
    /// When running assessors in parallel, some may complete while others fail or get cancelled.
    /// The aggregated result preserves all completed assessments, enabling:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Partial decision-making when some assessors are unavailable.</description></item>
    /// <item><description>Detailed diagnostics showing which assessors succeeded or failed.</description></item>
    /// <item><description>Retry logic for failed assessors without re-running successful ones.</description></item>
    /// </list>
    /// <para>
    /// <strong>Trace Correlation:</strong>
    /// </para>
    /// <para>
    /// Each assessor invocation gets its own <see cref="IndividualAssessorResult.SpanId"/>,
    /// all linked to the parent <see cref="TraceId"/>. This enables post-facto analysis
    /// of assessment decisions for regulatory compliance, auditing, and remediation.
    /// </para>
    /// </remarks>
    /// <param name="AggregatedAssessmentId">Unique identifier for this aggregated assessment.</param>
    /// <param name="CorrelationId">User-supplied identifier for cross-system correlation.</param>
    /// <param name="ClaimsResult">The claims that were assessed by all assessors.</param>
    /// <param name="IndividualResults">Results from each assessor, including completion status.</param>
    /// <param name="AggregationStrategy">The strategy used to determine overall success.</param>
    /// <param name="CreationTimestampInUtc">When this aggregated result was created.</param>
    /// <param name="TotalDuration">Total wall-clock time for the composite assessment.</param>
    /// <param name="TraceId">OpenTelemetry trace ID for the entire assessment operation.</param>
    /// <param name="SpanId">OpenTelemetry span ID for the aggregation operation.</param>
    /// <param name="Baggage">Distributed context propagated through the assessment pipeline.</param>
    public record AggregatedAssessmentResult(
        string AggregatedAssessmentId,
        string CorrelationId,
        ClaimIssueResult ClaimsResult,
        IReadOnlyList<IndividualAssessorResult> IndividualResults,
        AssessmentAggregationStrategy AggregationStrategy,
        DateTime CreationTimestampInUtc,
        TimeSpan TotalDuration,
        string? TraceId,
        string? SpanId,
        IReadOnlyDictionary<string, string>? Baggage)
    {
        /// <summary>
        /// Gets the number of assessors that completed successfully.
        /// </summary>
        public int CompletedCount => IndividualResults.Count(r => r.IsCompleted);

        /// <summary>
        /// Gets the number of assessors that were cancelled.
        /// </summary>
        public int CancelledCount => IndividualResults.Count(r => r.CompletionStatus == AssessorCompletionStatus.Cancelled);

        /// <summary>
        /// Gets the number of assessors that faulted.
        /// </summary>
        public int FaultedCount => IndividualResults.Count(r => r.CompletionStatus == AssessorCompletionStatus.Faulted);

        /// <summary>
        /// Gets a value indicating whether all assessors completed.
        /// </summary>
        public bool AllCompleted => IndividualResults.All(r => r.IsCompleted);

        /// <summary>
        /// Gets the overall success based on the <see cref="AggregationStrategy"/>.
        /// </summary>
        public bool IsSuccess => AggregationStrategy switch
        {
            AssessmentAggregationStrategy.AllMustSucceed =>
                ClaimsResult.IsComplete && AllCompleted && IndividualResults.All(r => r.IsSuccess),

            AssessmentAggregationStrategy.AnyMustSucceed =>
                ClaimsResult.IsComplete && IndividualResults.Any(r => r.IsSuccess),

            AssessmentAggregationStrategy.MajorityMustSucceed =>
                ClaimsResult.IsComplete && IndividualResults.Count(r => r.IsSuccess) > IndividualResults.Count / 2,

            AssessmentAggregationStrategy.QuorumMustSucceed =>
                ClaimsResult.IsComplete && CompletedCount >= RequiredQuorum &&
                IndividualResults.Where(r => r.IsCompleted).All(r => r.IsSuccess),

            _ => false
        };

        /// <summary>
        /// The minimum number of assessors required for quorum-based strategies.
        /// Defaults to majority if not explicitly set.
        /// </summary>
        public int RequiredQuorum { get; init; } = 0;

        /// <summary>
        /// Gets the successful assessment results.
        /// </summary>
        public IEnumerable<AssessmentResult> SuccessfulResults =>
            IndividualResults
                .Where(r => r.IsSuccess && r.Result != null)
                .Select(r => r.Result!);

        /// <summary>
        /// Gets the failed or incomplete assessor identifiers with their status.
        /// </summary>
        public IEnumerable<(string AssessorId, AssessorCompletionStatus Status, string? Error)> FailedAssessors =>
            IndividualResults
                .Where(r => !r.IsSuccess)
                .Select(r => (r.AssessorId, r.CompletionStatus, r.ErrorMessage));
    }


    /// <summary>
    /// Defines how multiple assessment results are aggregated to determine overall success.
    /// </summary>
    public enum AssessmentAggregationStrategy
    {
        /// <summary>
        /// All assessors must complete successfully for overall success.
        /// Use for high-assurance scenarios where every check matters.
        /// </summary>
        AllMustSucceed,

        /// <summary>
        /// At least one assessor must succeed for overall success.
        /// Use for redundant assessors where any positive signal is sufficient.
        /// </summary>
        AnyMustSucceed,

        /// <summary>
        /// More than half of the assessors must succeed for overall success.
        /// Use for voting/consensus scenarios.
        /// </summary>
        MajorityMustSucceed,

        /// <summary>
        /// A minimum quorum of assessors must complete and all completed must succeed.
        /// Use when some assessors may be unavailable but a minimum coverage is required.
        /// </summary>
        QuorumMustSucceed
    }
}