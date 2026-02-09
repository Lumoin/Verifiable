using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.Assessment
{
    /// <summary>
    /// Configuration for a single assessor within a composite assessment.
    /// </summary>
    /// <param name="AssessorId">Unique identifier for this assessor.</param>
    /// <param name="Assessor">The assessment delegate.</param>
    /// <param name="Timeout">
    /// Optional timeout for this specific assessor. If <see langword="null"/>,
    /// the assessor runs until the composite timeout or cancellation.
    /// </param>
    public record AssessorConfiguration(
        string AssessorId,
        AssessDelegateAsync Assessor,
        TimeSpan? Timeout = null);


    /// <summary>
    /// Runs multiple assessors in parallel against the same claims, collecting results
    /// from all assessors even when some fail, timeout, or are cancelled.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The <see cref="CompositeClaimAssessor{TInput}"/> enables sophisticated assessment
    /// scenarios where multiple independent assessors evaluate the same claims:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// <strong>Parallel Execution:</strong> All assessors run concurrently using
    /// <see cref="Task.WhenAll"/>, with individual timeout support.
    /// </description></item>
    /// <item><description>
    /// <strong>Partial Results:</strong> If some assessors fail or timeout, results
    /// from successful assessors are still collected and returned.
    /// </description></item>
    /// <item><description>
    /// <strong>Aggregation Strategies:</strong> Configure how individual results
    /// combine to determine overall success (all, any, majority, quorum).
    /// </description></item>
    /// <item><description>
    /// <strong>Trace Correlation:</strong> Each assessor gets its own span ID,
    /// linked to the parent trace for post-facto analysis.
    /// </description></item>
    /// </list>
    ///
    /// <para>
    /// <strong>Assessor Types:</strong>
    /// </para>
    /// <para>
    /// Assessors can range from fast in-memory rule checks to remote AI service calls:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Local rule-based validation (milliseconds).</description></item>
    /// <item><description>Local ML model inference (milliseconds to seconds).</description></item>
    /// <item><description>Remote AI/LLM service calls (seconds).</description></item>
    /// <item><description>Compliance validation services (variable latency).</description></item>
    /// </list>
    ///
    /// <para>
    /// <strong>Cancellation Behavior:</strong>
    /// </para>
    /// <para>
    /// When cancellation is requested:
    /// </para>
    /// <list type="number">
    /// <item><description>All running assessors receive the cancellation signal.</description></item>
    /// <item><description>Assessors that have already completed retain their results.</description></item>
    /// <item><description>Assessors that were cancelled are marked with <see cref="AssessorCompletionStatus.Cancelled"/>.</description></item>
    /// <item><description>The aggregated result is returned with partial data.</description></item>
    /// </list>
    ///
    /// <para>
    /// <strong>Regulatory and Audit Support:</strong>
    /// </para>
    /// <para>
    /// The composite assessor captures comprehensive trace information enabling:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Full lineage of which assessors ran and their outcomes.</description></item>
    /// <item><description>Timing information for performance analysis.</description></item>
    /// <item><description>Correlation with external systems via baggage propagation.</description></item>
    /// <item><description>Post-facto retrieval for compliance audits and remediation.</description></item>
    /// </list>
    /// </remarks>
    /// <typeparam name="TInput">The type of input to assess.</typeparam>
    public class CompositeClaimAssessor<TInput>
    {
        private ClaimIssuer<TInput> ClaimIssuer { get; }
        private IReadOnlyList<AssessorConfiguration> Assessors { get; }
        private AssessmentAggregationStrategy AggregationStrategy { get; }
        private TimeProvider TimeProvider { get; }
        private int RequiredQuorum { get; }


        /// <summary>
        /// Constructs a <see cref="CompositeClaimAssessor{TInput}"/> with the specified configuration.
        /// </summary>
        /// <param name="claimIssuer">The claim issuer to generate claims from input.</param>
        /// <param name="assessors">The assessors to run in parallel.</param>
        /// <param name="aggregationStrategy">How to aggregate individual results.</param>
        /// <param name="timeProvider">
        /// Time provider for timestamps. If <see langword="null"/>, uses <see cref="TimeProvider.System"/>.
        /// </param>
        /// <param name="requiredQuorum">
        /// Minimum assessors required for <see cref="AssessmentAggregationStrategy.QuorumMustSucceed"/>.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="claimIssuer"/> or <paramref name="assessors"/> is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="assessors"/> is empty.
        /// </exception>
        public CompositeClaimAssessor(
            ClaimIssuer<TInput> claimIssuer,
            IReadOnlyList<AssessorConfiguration> assessors,
            AssessmentAggregationStrategy aggregationStrategy = AssessmentAggregationStrategy.AllMustSucceed,
            TimeProvider? timeProvider = null,
            int requiredQuorum = 0)
        {
            ArgumentNullException.ThrowIfNull(claimIssuer, nameof(claimIssuer));
            ArgumentNullException.ThrowIfNull(assessors, nameof(assessors));

            if(assessors.Count == 0)
            {
                throw new ArgumentException("At least one assessor must be provided.", nameof(assessors));
            }

            ClaimIssuer = claimIssuer;
            Assessors = assessors;
            AggregationStrategy = aggregationStrategy;
            TimeProvider = timeProvider ?? TimeProvider.System;
            RequiredQuorum = requiredQuorum > 0 ? requiredQuorum : (assessors.Count / 2) + 1;
        }


        /// <summary>
        /// Generates claims and runs all assessors in parallel, collecting results.
        /// </summary>
        /// <param name="input">The input to validate and assess.</param>
        /// <param name="correlationId">User-supplied identifier for correlation.</param>
        /// <param name="cancellationToken">Token to monitor for cancellation.</param>
        /// <returns>
        /// An <see cref="AggregatedAssessmentResult"/> containing results from all assessors
        /// that completed, along with status information for those that failed or were cancelled.
        /// </returns>
        public async ValueTask<AggregatedAssessmentResult> AssessAsync(
            TInput input,
            string correlationId,
            CancellationToken cancellationToken = default)
        {
            var overallStopwatch = Stopwatch.StartNew();
            var traceId = TracingUtilities.GetOrCreateTraceId();
            var parentSpanId = TracingUtilities.GetOrCreateSpanId();
            var baggage = TracingUtilities.GetOrCreateBaggage();

            //Step 1: Generate claims.
            var claimsResult = await ClaimIssuer.GenerateClaimsAsync(
                input,
                correlationId,
                cancellationToken).ConfigureAwait(false);

            //Step 2: Run all assessors in parallel.
            var creationTimestamp = TimeProvider.GetUtcNow().UtcDateTime;
            var assessorTasks = Assessors.Select(config =>
                CompositeClaimAssessor<TInput>.RunAssessorWithTimeoutAsync(config, claimsResult, creationTimestamp, traceId, baggage, cancellationToken));

            var individualResults = await Task.WhenAll(assessorTasks).ConfigureAwait(false);

            overallStopwatch.Stop();

            //Step 3: Aggregate results.
            var aggregatedAssessmentId = Guid.NewGuid().ToString();

            return new AggregatedAssessmentResult(
                AggregatedAssessmentId: aggregatedAssessmentId,
                CorrelationId: correlationId,
                ClaimsResult: claimsResult,
                IndividualResults: individualResults,
                AggregationStrategy: AggregationStrategy,
                CreationTimestampInUtc: creationTimestamp,
                TotalDuration: overallStopwatch.Elapsed,
                TraceId: traceId,
                SpanId: parentSpanId,
                Baggage: baggage)
            {
                RequiredQuorum = RequiredQuorum
            };
        }


        /// <summary>
        /// Runs a single assessor with optional timeout, capturing all outcomes.
        /// </summary>
        private static async Task<IndividualAssessorResult> RunAssessorWithTimeoutAsync(
            AssessorConfiguration config,
            ClaimIssueResult claimsResult,
            DateTime creationTimestamp,
            string? traceId,
            IReadOnlyDictionary<string, string>? baggage,
            CancellationToken cancellationToken)
        {
            var stopwatch = Stopwatch.StartNew();
            var spanId = TracingUtilities.GetOrCreateSpanId();

            try
            {
                //Create a combined cancellation token if timeout is specified.
                using var timeoutCts = config.Timeout.HasValue
                    ? new CancellationTokenSource(config.Timeout.Value)
                    : null;

                using var linkedCts = timeoutCts != null
                    ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token)
                    : null;

                var effectiveToken = linkedCts?.Token ?? cancellationToken;

                var result = await config.Assessor(
                    claimsResult,
                    config.AssessorId,
                    creationTimestamp,
                    traceId,
                    spanId,
                    baggage,
                    effectiveToken).ConfigureAwait(false);

                stopwatch.Stop();

                return new IndividualAssessorResult(
                    AssessorId: config.AssessorId,
                    CompletionStatus: AssessorCompletionStatus.Completed,
                    Result: result,
                    ErrorMessage: null,
                    Duration: stopwatch.Elapsed,
                    SpanId: spanId);
            }
            catch(OperationCanceledException) when(cancellationToken.IsCancellationRequested)
            {
                stopwatch.Stop();
                return new IndividualAssessorResult(
                    AssessorId: config.AssessorId,
                    CompletionStatus: AssessorCompletionStatus.Cancelled,
                    Result: null,
                    ErrorMessage: "Assessment was cancelled.",
                    Duration: stopwatch.Elapsed,
                    SpanId: spanId);
            }
            catch(OperationCanceledException)
            {
                //Timeout (not external cancellation).
                stopwatch.Stop();
                return new IndividualAssessorResult(
                    AssessorId: config.AssessorId,
                    CompletionStatus: AssessorCompletionStatus.TimedOut,
                    Result: null,
                    ErrorMessage: $"Assessment timed out after {config.Timeout}.",
                    Duration: stopwatch.Elapsed,
                    SpanId: spanId);
            }
            catch(Exception ex)
            {
                stopwatch.Stop();
                return new IndividualAssessorResult(
                    AssessorId: config.AssessorId,
                    CompletionStatus: AssessorCompletionStatus.Faulted,
                    Result: null,
                    ErrorMessage: ex.Message,
                    Duration: stopwatch.Elapsed,
                    SpanId: spanId);
            }
        }
    }
}