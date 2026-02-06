using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.Assessment
{
    /// <summary>
    /// Signature to generate <see cref="ClaimIssueResult.ClaimIssueResultId"/> values.
    /// </summary>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>A generated claim issue result identifier.</returns>
    public delegate ValueTask<string> GenerateClaimIdAsync(CancellationToken cancellationToken = default);


    /// <summary>
    /// Generates a set of validation claims against input.
    /// </summary>
    /// <typeparam name="TInput">The type of input to validate.</typeparam>
    /// <remarks>
    /// <para>
    /// The <see cref="ClaimIssuer{TInput}"/> class encapsulates a set of validation rules and applies
    /// them to a given input. The result is a collection of <see cref="Claim"/> objects that can be
    /// used for further assessment.
    /// </para>
    /// <para>
    /// This separation of concerns allows the validation logic to be decoupled from the assessment
    /// and archival steps, making it easier to maintain and extend the validation process.
    /// </para>
    ///
    /// <para>
    /// <strong>Time Handling:</strong>
    /// </para>
    /// <para>
    /// The <see cref="ClaimIssuer{TInput}"/> requires a <see cref="TimeProvider"/> to generate
    /// timestamps. This ensures full testability and determinism - the library never calls
    /// <c>DateTime.UtcNow</c> or similar APIs internally.
    /// </para>
    ///
    /// <para>
    /// <strong>Cancellation and Partial Results:</strong>
    /// </para>
    /// <para>
    /// The <see cref="GenerateClaimsAsync"/> method supports cancellation via <see cref="CancellationToken"/>.
    /// When cancellation is requested:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// The method checks for cancellation between validation rule executions.
    /// </description></item>
    /// <item><description>
    /// If cancellation is requested, the method returns a <see cref="ClaimIssueResult"/> containing
    /// the claims generated so far, with <see cref="ClaimIssueResult.CompletionStatus"/> set to
    /// <see cref="ClaimIssueCompletionStatus.Cancelled"/>.
    /// </description></item>
    /// <item><description>
    /// <see cref="ClaimIssueResult.RulesExecuted"/> indicates how many rules completed before
    /// cancellation.
    /// </description></item>
    /// </list>
    /// <para>
    /// This design ensures that partial validation work is not lost and can be inspected or logged
    /// even when the full validation cannot complete.
    /// </para>
    ///
    /// <para>
    /// <strong>Managing Multiple Issuers:</strong>
    /// </para>
    /// <para>
    /// If you need to manage multiple <see cref="ClaimIssuer{TInput}"/> instances of different generic
    /// types in a single collection, consider creating a custom wrapper:
    /// </para>
    /// <code>
    /// public class ClaimIssuerWrapper
    /// {
    ///     private readonly object _issuer;
    ///
    ///     public ClaimIssuerWrapper(object issuer)
    ///     {
    ///         _issuer = issuer;
    ///     }
    ///
    ///     public ValueTask&lt;ClaimIssueResult&gt; GenerateClaimsAsync(
    ///         object input,
    ///         string correlationId,
    ///         CancellationToken cancellationToken = default)
    ///     {
    ///         var method = _issuer.GetType().GetMethod("GenerateClaimsAsync");
    ///         if (method != null)
    ///         {
    ///             return (ValueTask&lt;ClaimIssueResult&gt;)method.Invoke(
    ///                 _issuer,
    ///                 new object[] { input, correlationId, cancellationToken });
    ///         }
    ///         throw new InvalidOperationException("GenerateClaimsAsync method not found.");
    ///     }
    /// }
    /// </code>
    /// </remarks>    
    public class ClaimIssuer<TInput>
    {
        /// <summary>
        /// A default implementation to generate <see cref="ClaimIssueResult.ClaimIssueResultId"/>
        /// values if the user does not provide one.
        /// </summary>
        /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
        /// <returns>A new GUID as a string.</returns>
        [SuppressMessage("Design", "CA1000:Do not declare static members on generic types", Justification = "This design is intentional to provide type-specific static members.")]
        public static ValueTask<string> DefaultClaimIdGenerator(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Guid.NewGuid().ToString());
        }

        /// <summary>
        /// Gets the list of validation rules to be applied on the input.
        /// </summary>
        private IList<ClaimDelegate<TInput>> ValidationRules { get; }

        /// <summary>
        /// Gets the delegate used to generate <see cref="ClaimIssueResult.ClaimIssueResultId"/> values.
        /// </summary>
        private GenerateClaimIdAsync ClaimIdGenerator { get; }

        /// <summary>
        /// Gets the time provider used to generate timestamps.
        /// </summary>
        private TimeProvider TimeProvider { get; }

        /// <summary>
        /// The unique identifier for this <see cref="ClaimIssuer{TInput}"/> instance.
        /// </summary>
        private string IssuerId { get; }


        /// <summary>
        /// Constructs a <see cref="ClaimIssuer{TInput}"/> with the specified parameters.
        /// </summary>
        /// <param name="issuerId">Unique identifier for this <see cref="ClaimIssuer{TInput}"/>.</param>
        /// <param name="validationRules">List of validation rules to apply.</param>
        /// <param name="timeProvider">
        /// Time provider for generating timestamps. If <see langword="null"/>,
        /// <see cref="TimeProvider.System"/> is used.
        /// </param>
        /// <param name="claimIdGenerator">
        /// Optional delegate to generate <see cref="ClaimIssueResult.ClaimIssueResultId"/> values.
        /// If <see langword="null"/>, <see cref="DefaultClaimIdGenerator"/> is used.
        /// </param>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="issuerId"/> is null or empty.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="validationRules"/> is null.
        /// </exception>
        public ClaimIssuer(
            string issuerId,
            IList<ClaimDelegate<TInput>> validationRules,
            TimeProvider? timeProvider = null,
            GenerateClaimIdAsync? claimIdGenerator = null)
        {
            ArgumentException.ThrowIfNullOrEmpty(issuerId, nameof(issuerId));
            ArgumentNullException.ThrowIfNull(validationRules, nameof(validationRules));

            IssuerId = issuerId;
            ValidationRules = validationRules;
            TimeProvider = timeProvider ?? TimeProvider.System;
            ClaimIdGenerator = claimIdGenerator ?? DefaultClaimIdGenerator;
        }


        /// <summary>
        /// Generates a <see cref="ClaimIssueResult"/> (a set of <see cref="Claim"/>s) based on
        /// the provided input.
        /// </summary>
        /// <param name="input">The input to validate.</param>
        /// <param name="correlationId">
        /// User-supplied identifier to correlate the claim generation operation with other operations.
        /// </param>
        /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
        /// <returns>
        /// A <see cref="ClaimIssueResult"/> containing the generated claims. If cancellation was
        /// requested, the result will have <see cref="ClaimIssueResult.CompletionStatus"/> set to
        /// <see cref="ClaimIssueCompletionStatus.Cancelled"/> and will contain only the claims
        /// generated before cancellation.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This method first generates a result ID, then iterates through all configured validation
        /// rules and collects the claims they generate. Cancellation is checked between rule executions,
        /// ensuring that:
        /// </para>
        /// <list type="bullet">
        /// <item><description>
        /// The result ID is generated before any rules execute, ensuring partial results are identifiable.
        /// </description></item>
        /// <item><description>
        /// A rule that has started will complete before cancellation is processed.
        /// </description></item>
        /// <item><description>
        /// Claims from completed rules are preserved in the result.
        /// </description></item>
        /// <item><description>
        /// The result clearly indicates whether it is complete or partial.
        /// </description></item>
        /// </list>
        /// <para>
        /// If a validation rule throws an exception, a <see cref="FailedClaim"/> is added to capture
        /// the failure context, and processing continues with the next rule.
        /// </para>
        /// </remarks>
        [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "All exceptions are treated likewise.")]
        public async ValueTask<ClaimIssueResult> GenerateClaimsAsync(
            TInput input,
            string correlationId,
            CancellationToken cancellationToken = default)
        {
            //Generate the result ID first, before processing rules.
            //This ensures we have an ID even if cancellation occurs during rule execution.
            var claimIssueResultId = await ClaimIdGenerator(cancellationToken).ConfigureAwait(false);

            List<Claim> claims = [];
            int rulesExecuted = 0;
            int totalRules = ValidationRules.Count;
            var completionStatus = ClaimIssueCompletionStatus.Complete;

            foreach(var ruleWrapper in ValidationRules)
            {
                //Check for cancellation before starting the next rule.
                if(cancellationToken.IsCancellationRequested)
                {
                    completionStatus = ClaimIssueCompletionStatus.Cancelled;
                    break;
                }

                try
                {
                    var ruleClaims = await ruleWrapper.Delegate(input, cancellationToken).ConfigureAwait(false);
                    claims.AddRange(ruleClaims);
                    rulesExecuted++;
                }
                catch(OperationCanceledException) when(cancellationToken.IsCancellationRequested)
                {
                    //Rule was cancelled - record partial progress and exit.
                    completionStatus = ClaimIssueCompletionStatus.Cancelled;
                    break;
                }
                catch(Exception ex)
                {
                    claims.Add(new FailedClaim(ruleWrapper.Delegate.Method.Name, ex.Message));
                    rulesExecuted++;
                }
            }

            var creationTimestamp = TimeProvider.GetUtcNow().UtcDateTime;

            return new ClaimIssueResult(
                ClaimIssueResultId: claimIssueResultId,
                ClaimIssuerId: IssuerId,
                CorrelationId: correlationId,
                Claims: claims,
                CreationTimestampInUtc: creationTimestamp,
                CompletionStatus: completionStatus,
                RulesExecuted: rulesExecuted,
                TotalRules: totalRules,
                IssuingContext: new ClaimIssueResultContext { Inputs = input },
                ClaimIssuerTraceId: TracingUtilities.GetOrCreateTraceId(),
                ClaimIssuerSpanId: TracingUtilities.GetOrCreateSpanId(),
                Baggage: TracingUtilities.GetOrCreateBaggage());
        }
    }
}