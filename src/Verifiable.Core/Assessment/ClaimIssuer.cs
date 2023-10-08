using System;
using System.Collections.Generic;
using System.Threading.Tasks;


namespace Verifiable.Assessment
{
    /// <summary>
    /// Signature to generate <see cref="ClaimIssueResult.ClaimIssueResultId"/> values.
    /// </summary>
    public delegate ValueTask<string> GenerateClaimIdAsync();


    /// <summary>
    /// Generates a set of validation claims against input.
    /// </summary>
    /// <typeparam name="TInput">The type of input.</typeparam>
    /// <remarks>
    /// <para>
    /// The ClaimIssuer class encapsulates a set of validation rules and applies them to a given input. 
    /// The result is a collection of <see cref="Claim"/> objects that can be used for further assessment.
    /// </para>
    /// <para>
    /// This separation of concerns allows the validation logic to be decoupled from the assessment and archival steps,
    /// making it easier to maintain and extend the validation process.
    /// </para>
    /// <para>
    /// If you need to manage multiple ClaimIssuer instances of different generic types in a single collection,
    /// consider creating a custom wrapper. Here's an example:
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
    ///     public ValueTask&lt;ClaimIssueResult&gt; GenerateClaimsAsync(object input, string correlationId)
    ///     {
    ///         var method = _issuer.GetType().GetMethod("GenerateClaimsAsync");
    ///         if (method != null)
    ///         {
    ///             return (ValueTask&lt;ClaimIssueResult&gt;)method.Invoke(_issuer, new object[] { input, correlationId });
    ///         }
    ///         throw new InvalidOperationException("GenerateClaimsAsync method not found.");
    ///     }
    /// }
    ///
    /// //Usage:
    /// var issuers = new List&lt;ClaimIssuerWrapper&gt;
    /// {
    ///     new ClaimIssuerWrapper(new ClaimIssuer&lt;Type1&gt;(...)),
    ///     new ClaimIssuerWrapper(new ClaimIssuer&lt;Type2&gt;(...))
    /// };
    /// </code>
    /// </remarks>
    public class ClaimIssuer<TInput>
    {
        /// <summary>
        /// A default implementation to generate <see cref="ClaimId"/> value if the user does not provide one.
        /// </summary>
        /// <returns>Generated <see cref="ClaimId"/> value.</returns>
        public static ValueTask<string> DefaultClaimIdGenerator() => ValueTask.FromResult(Guid.NewGuid().ToString());

        /// <summary>
        /// Gets the list of validation rules to be applied on the input.
        /// </summary>
        //TODO: Refactor to ImmutableArray.
        private IList<ClaimDelegate<TInput>> ValidationRules { get; }

        /// <summary>
        /// Gets the delegate used to generate <see cref="ClaimIssueResult.ClaimIssueResultId"/> values.
        /// </summary>
        private GenerateClaimIdAsync ClaimIdGenerator { get; }

        /// <summary>
        /// The unique identifier for this <see cref="ClaimIssuer{TInput}"/> instance.
        /// </summary>
        private string IssuerId { get; }


        /// <summary>
        /// Constructs <see cref="ClaimIssuer{TInput}"/> with the specified issuer identifier, validation rules, and an optional <see cref="ClaimId"/> generator.
        /// </summary>
        /// <param name="issuerId">Unique identifier for this <see cref="ClaimIssuer{TInput}"/>.</param>
        /// <param name="validationRules">List of validation rules to apply.</param>
        /// <param name="claimIdGenerator">Optional delegate to generate <see cref="ClaimId"/> values. If <see langword="null"/>, a default implementation <see cref="DefaultClaimIdGenerator"/> is used.</param>
        public ClaimIssuer(string issuerId, IList<ClaimDelegate<TInput>> validationRules, GenerateClaimIdAsync? claimIdGenerator = null)
        {
            ArgumentException.ThrowIfNullOrEmpty(issuerId, nameof(issuerId));
            ArgumentNullException.ThrowIfNull(validationRules, nameof(validationRules));

            IssuerId = issuerId;
            ValidationRules = validationRules;
            ClaimIdGenerator = claimIdGenerator ?? DefaultClaimIdGenerator;
        }


        /// <summary>
        /// Generates a <see cref="ClaimIssueResult"/> (a set of <see cref="Claim"/>s) based on the provided input.
        /// </summary>
        /// <param name="input">The input to validate.</param>
        /// <param name="correlationId">User-supplied identifier to correlate the claim generation operation with other operations.</param>
        /// <returns>The <see cref="ClaimIssueResult"/> with the generated claims.</returns>
        public async ValueTask<ClaimIssueResult> GenerateClaimsAsync(TInput input, string correlationId)
        {
            List<Claim> claims = new();
            foreach(var ruleWrapper in ValidationRules)
            {
                try
                {
                    var ruleClaims = await ruleWrapper.Delegate(input).ConfigureAwait(false);
                    claims.AddRange(ruleClaims);
                }
                catch(Exception ex)
                {
                    claims.Add(new FailedClaim(ruleWrapper.Delegate.Method.Name, ex.Message));
                }
            }

            var claimIssueResultId = await ClaimIdGenerator().ConfigureAwait(false);
            return new ClaimIssueResult(
                ClaimIssueResultId: claimIssueResultId,
                ClaimIssuerId: IssuerId,
                correlationId,
                Claims: claims,
                CreationTimestampInUtc: DateTime.UtcNow,
                IssuingContext: new ClaimIssueResultContext { Inputs = input },
                ClaimIssuerTraceId: TracingUtilities.GetOrCreateTraceId(),
                ClaimIssuerSpanId: TracingUtilities.GetOrCreateSpanId(),
                Baggage: TracingUtilities.GetOrCreateBaggage());
        }
    }
}
