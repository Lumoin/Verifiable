using System;
using System.Threading.Tasks;


namespace Verifiable.Assessment
{    
    /// <summary>
    /// Performs assessment on a given input using an associated <see cref="ClaimIssuer{TInput}"/> to generate claims,
    /// and an assessor delegate to evaluate the claims.
    /// </summary>
    /// <typeparam name="TInput">The type of input to be assessed.</typeparam>
    /// <remarks>
    /// <para>
    /// The ClaimAssessor class encapsulates a <see cref="ClaimIssuer{TInput}"/> instance and an assessor delegate,
    /// working together to first generate claims based on the input, and then assess the claims to produce an <see cref="AssessmentResult"/>.
    /// </para>
    /// <para>
    /// If additional parameters are required for assessing, a custom assessor delegate can be provided that accepts these parameters.
    /// Here's an example using an extended assessor delegate:
    /// </para>
    /// <code>
    /// public class ExtendedAssessmentParameters
    /// {
    ///     public string SomeParameter { get; set; }
    /// }
    ///
    /// public async ValueTask&lt;AssessmentResult&gt; ExtendedAssessAsync(ClaimIssueResult claimsResult, object additionalParameters)
    /// {
    ///     var parameters = (ExtendedAssessmentParameters)additionalParameters;
    ///     // ...
    /// }
    ///
    /// var extendedAssessor = new ExtendedAssessDelegateAsync(ExtendedAssessAsync);
    /// var claimAssessor = new ClaimAssessor&lt;DidDocument&gt;(claimIssuer, extendedAssessor);
    /// var extendedParameters = new ExtendedAssessmentParameters { SomeParameter = "some value" };
    /// var assessmentResult = await claimAssessor.AssessAsync(input, correlationId, extendedParameters);
    /// </code>
    /// </remarks>
    public class ClaimAssessor<TInput>
    {
        private ClaimIssuer<TInput> ClaimIssuer { get; }

        private AssessDelegateAsync Assessor { get; }

        private string AssessorId { get; }


        /// <summary>
        /// Constructs a ClaimAssessor with the specified claim issuer and assessor delegate.
        /// </summary>
        /// <param name="claimIssuer">The claim issuer used to generate claims.</param>
        /// <param name="assessor">The assessor delegate used to evaluate the claims.</param>
        /// <param name="assessorId">The assessor identifier.</param>
        public ClaimAssessor(ClaimIssuer<TInput> claimIssuer, AssessDelegateAsync assessor, string assessorId)
        {
            ArgumentNullException.ThrowIfNull(claimIssuer, nameof(claimIssuer));
            ArgumentNullException.ThrowIfNull(assessor, nameof(assessor));
            ArgumentException.ThrowIfNullOrEmpty(assessorId, nameof(assessorId));

            ClaimIssuer = claimIssuer;
            Assessor = assessor;
            AssessorId = assessorId;
        }

        /// <summary>
        /// Assess the provided input and generate an <see cref="AssessmentResult"/>.
        /// </summary>
        /// <param name="input">The input to validate and assess.</param>
        /// <param name="correlationId">User-supplied identifier to correlate the assessment operation with other operations.</param>
        /// <returns>The <see cref="AssessmentResult"/> with the assessment outcome.</returns>
        public async ValueTask<AssessmentResult> AssessAsync(TInput input, string correlationId)
        {
            var claimsResult = await ClaimIssuer.GenerateClaimsAsync(input, correlationId).ConfigureAwait(false);

            var traceId = TracingUtilities.GetOrCreateTraceId();
            var spanId = TracingUtilities.GetOrCreateSpanId();
            var baggage = TracingUtilities.GetOrCreateBaggage();

            return await Assessor(claimsResult, AssessorId, traceId, spanId, baggage).ConfigureAwait(false);
        }
    }
}
