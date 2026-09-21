using System.Diagnostics;
using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Result of the trust-chain-validation step in
/// <see cref="ValidateTrustChainAsyncDelegate"/>. Carries the parsed
/// chain plus the underlying
/// <see cref="Verifiable.Core.Assessment.ClaimIssueResult"/> from
/// <see cref="TrustChainValidator"/> on success; carries a typed
/// <see cref="FailureReason"/> on rejection.
/// </summary>
/// <remarks>
/// Same sealed-record-with-nullable-fields shape as the other Federation
/// result types (EntityStatementParseResult, MetadataPolicyParseResult,
/// etc.). Wallets and JAR-layer consumers compose against this to make
/// validate/reject decisions before extracting the JAR signing key.
/// </remarks>
[DebuggerDisplay("TrustChainValidationOutcome Valid={IsValid} Reason={FailureReason,nq}")]
public sealed record TrustChainValidationOutcome
{
    /// <summary>The parsed and validated chain when validation succeeded; otherwise <see langword="null"/>.</summary>
    public TrustChain? Chain { get; init; }

    /// <summary>
    /// The underlying claim issue result from <see cref="TrustChainValidator"/> when validation ran —
    /// on success, always; on rejection, only when the rejecting call site had one in hand
    /// (<see cref="Rejected"/>'s optional <c>validationResult</c> parameter), <see langword="null"/>
    /// otherwise. A consumer branches on this to see which <see cref="Verifiable.Core.Assessment.Claim"/>
    /// failed, not just that the chain was rejected.
    /// </summary>
    public ClaimIssueResult? ValidationResult { get; init; }

    /// <summary>The reason validation failed; <see langword="null"/> on success.</summary>
    public string? FailureReason { get; init; }

    /// <summary><see langword="true"/> when the chain validated cleanly.</summary>
    public bool IsValid => FailureReason is null;


    /// <summary>Builds a success result.</summary>
    public static TrustChainValidationOutcome Validated(TrustChain chain, ClaimIssueResult validationResult)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(validationResult);
        return new TrustChainValidationOutcome
        {
            Chain = chain,
            ValidationResult = validationResult,
        };
    }


    /// <summary>
    /// Builds a failure result with the given reason. The optional <paramref name="validationResult"/>
    /// is carried when the rejection came from <see cref="TrustChainValidator"/>'s own claim loop (so the
    /// caller keeps which <see cref="Verifiable.Core.Assessment.Claim"/> failed, not just the flattened
    /// reason string).
    /// </summary>
    /// <param name="reason">Why the chain was rejected, in words.</param>
    /// <param name="validationResult">
    /// The claim issue result the rejection came from, or <see langword="null"/> when the rejection
    /// happened before the validator produced one (an empty chain, an unreadable statement, a key that
    /// did not resolve, a signature that did not verify).
    /// </param>
    /// <returns>The rejected outcome; <see cref="IsValid"/> is <see langword="false"/>.</returns>
    public static TrustChainValidationOutcome Rejected(string reason, ClaimIssueResult? validationResult = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        return new TrustChainValidationOutcome { FailureReason = reason, ValidationResult = validationResult };
    }
}
