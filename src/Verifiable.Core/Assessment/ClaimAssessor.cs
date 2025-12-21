using System;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.Assessment
{
    /// <summary>
    /// Performs assessment on a given input using an associated <see cref="ClaimIssuer{TInput}"/>
    /// to generate claims, and an assessor delegate to evaluate the claims.
    /// </summary>
    /// <typeparam name="TInput">The type of input to be assessed.</typeparam>
    /// <remarks>
    /// <para>
    /// The <see cref="ClaimAssessor{TInput}"/> class encapsulates a <see cref="ClaimIssuer{TInput}"/>
    /// instance and an assessor delegate, working together to first generate claims based on the input,
    /// and then assess the claims to produce an <see cref="AssessmentResult"/>.
    /// </para>
    ///
    /// <para>
    /// <strong>Time Handling:</strong>
    /// </para>
    /// <para>
    /// The <see cref="ClaimAssessor{TInput}"/> requires a <see cref="TimeProvider"/> to generate
    /// timestamps for assessment results. This ensures full testability and determinism.
    /// </para>
    ///
    /// <para>
    /// <strong>Cancellation Support:</strong>
    /// </para>
    /// <para>
    /// The <see cref="AssessAsync"/> method propagates cancellation to both the claim issuer and
    /// the assessor delegate. If cancellation occurs during claim generation, the assessor will
    /// receive a partial <see cref="ClaimIssueResult"/> and can decide how to handle it.
    /// </para>
    ///
    /// <para>
    /// <strong>Extended Assessment Parameters:</strong>
    /// </para>
    /// <para>
    /// If additional parameters are required for assessing, a custom assessor delegate can be provided
    /// that accepts these parameters. Here's an example using an extended assessor delegate:
    /// </para>
    /// <code>
    /// public class ExtendedAssessmentParameters
    /// {
    ///     public string SomeParameter { get; set; }
    /// }
    ///
    /// // Create a wrapper assessor that captures additional parameters
    /// public class ExtendedClaimAssessor&lt;TInput&gt;
    /// {
    ///     private readonly ClaimIssuer&lt;TInput&gt; _claimIssuer;
    ///     private readonly TimeProvider _timeProvider;
    ///     private readonly string _assessorId;
    ///
    ///     public ExtendedClaimAssessor(
    ///         ClaimIssuer&lt;TInput&gt; claimIssuer,
    ///         TimeProvider timeProvider,
    ///         string assessorId)
    ///     {
    ///         _claimIssuer = claimIssuer;
    ///         _timeProvider = timeProvider;
    ///         _assessorId = assessorId;
    ///     }
    ///
    ///     public async ValueTask&lt;AssessmentResult&gt; AssessAsync(
    ///         TInput input,
    ///         string correlationId,
    ///         ExtendedAssessmentParameters parameters,
    ///         CancellationToken cancellationToken = default)
    ///     {
    ///         var claimsResult = await _claimIssuer.GenerateClaimsAsync(
    ///             input, correlationId, cancellationToken);
    ///
    ///         // Use parameters in assessment logic...
    ///         var timestamp = _timeProvider.GetUtcNow().UtcDateTime;
    ///         // Custom assessment logic here
    ///     }
    /// }
    /// </code>
    /// </remarks>
    public class ClaimAssessor<TInput>
    {
        /// <summary>
        /// The claim issuer that produces claims for assessment.
        /// </summary>
        private ClaimIssuer<TInput> ClaimIssuer { get; }

        /// <summary>
        /// The delegate that performs the actual assessment logic.
        /// </summary>
        private AssessDelegateAsync Assessor { get; }

        /// <summary>
        /// Time provider for timestamps.
        /// </summary>
        private TimeProvider TimeProvider { get; }

        /// <summary>
        /// Unique identifier for this assessor instance.
        /// </summary>
        private string AssessorId { get; }


        /// <summary>
        /// Constructs a <see cref="ClaimAssessor{TInput}"/> with the specified parameters.
        /// </summary>
        /// <param name="claimIssuer">The claim issuer used to generate claims.</param>
        /// <param name="assessor">The assessor delegate used to evaluate the claims.</param>
        /// <param name="assessorId">The unique identifier for this assessor.</param>
        /// <param name="timeProvider">
        /// Time provider for generating timestamps. If <see langword="null"/>,
        /// <see cref="TimeProvider.System"/> is used.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="claimIssuer"/> or <paramref name="assessor"/> is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="assessorId"/> is null or empty.
        /// </exception>
        public ClaimAssessor(
            ClaimIssuer<TInput> claimIssuer,
            AssessDelegateAsync assessor,
            string assessorId,
            TimeProvider? timeProvider = null)
        {
            ArgumentNullException.ThrowIfNull(claimIssuer, nameof(claimIssuer));
            ArgumentNullException.ThrowIfNull(assessor, nameof(assessor));
            ArgumentException.ThrowIfNullOrEmpty(assessorId, nameof(assessorId));

            ClaimIssuer = claimIssuer;
            Assessor = assessor;
            AssessorId = assessorId;
            TimeProvider = timeProvider ?? TimeProvider.System;
        }


        /// <summary>
        /// Assesses the provided input and generates an <see cref="AssessmentResult"/>.
        /// </summary>
        /// <param name="input">The input to validate and assess.</param>
        /// <param name="correlationId">
        /// User-supplied identifier to correlate the assessment operation with other operations.
        /// </param>
        /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
        /// <returns>
        /// An <see cref="AssessmentResult"/> containing the assessment outcome. If cancellation
        /// was requested during claim generation, the assessment will be performed on the partial
        /// claims that were generated before cancellation.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This method performs the following steps:
        /// </para>
        /// <list type="number">
        /// <item><description>
        /// Generates claims using the <see cref="ClaimIssuer{TInput}"/>.
        /// </description></item>
        /// <item><description>
        /// Retrieves or generates tracing identifiers (trace ID, span ID, baggage).
        /// </description></item>
        /// <item><description>
        /// Gets the current timestamp from the <see cref="TimeProvider"/>.
        /// </description></item>
        /// <item><description>
        /// Invokes the assessor delegate to evaluate the claims.
        /// </description></item>
        /// </list>
        /// <para>
        /// If the <see cref="ClaimIssueResult.CompletionStatus"/> indicates partial completion
        /// (due to cancellation), the assessor delegate receives this information and can
        /// factor it into the assessment decision.
        /// </para>
        /// </remarks>
        public async ValueTask<AssessmentResult> AssessAsync(
            TInput input,
            string correlationId,
            CancellationToken cancellationToken = default)
        {
            var claimsResult = await ClaimIssuer.GenerateClaimsAsync(
                input,
                correlationId,
                cancellationToken).ConfigureAwait(false);

            var traceId = TracingUtilities.GetOrCreateTraceId();
            var spanId = TracingUtilities.GetOrCreateSpanId();
            var baggage = TracingUtilities.GetOrCreateBaggage();
            var creationTimestamp = TimeProvider.GetUtcNow().UtcDateTime;

            return await Assessor(
                claimsResult,
                AssessorId,
                creationTimestamp,
                traceId,
                spanId,
                baggage,
                cancellationToken).ConfigureAwait(false);
        }
    }
}