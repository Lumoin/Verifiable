using System.Diagnostics;
using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Wraps a <see cref="ClaimIssuer{TInput}"/> configured with
/// <see cref="FederationValidationProfiles.TrustChainRules"/> so an inline
/// trust chain can be validated against the OpenID Federation 1.0 §4.3 /
/// §10 rule set and the outcome surfaced as a
/// <see cref="ClaimIssueResult"/>.
/// </summary>
/// <remarks>
/// <para>
/// Inline path only — assumes the caller has the parsed
/// <see cref="TrustChain"/> in hand (via the <c>trust_chain</c> JWS header
/// parameter per §4.3 or via the FederationTestRing). HTTP
/// fetch (<c>federation_fetch_endpoint</c> walking) is a separate concern.
/// </para>
/// <para>
/// Thin orchestrator. Per-link JWS signature verification happens
/// <em>before</em> this validator runs; the caller (or the
/// <c>ResolveEntityKeyDelegate</c> + <c>Jws.VerifyAsync</c> composition)
/// populates the positional outcomes in
/// <see cref="TrustChainValidationContext.LinkSignaturesVerified"/>. The
/// validator then issues one <see cref="Claim"/> per rule in the configured
/// profile.
/// </para>
/// </remarks>
[DebuggerDisplay("TrustChainValidator")]
public sealed class TrustChainValidator
{
    private readonly ClaimIssuer<TrustChainValidationContext> issuer;


    /// <summary>
    /// Constructs a Trust Chain validator with the supplied rule list.
    /// </summary>
    /// <param name="issuerId">
    /// Identifier stamped on every emitted
    /// <see cref="ClaimIssueResult.ClaimIssuerId"/>. Pass
    /// <see cref="WellKnownFederationAssessorIds.ValidateTrustChain"/> for
    /// the standard profile.
    /// </param>
    /// <param name="validationRules">
    /// The rule list. Typically the result of
    /// <see cref="FederationValidationProfiles.TrustChainRules"/>, optionally
    /// extended with deployment-specific rules.
    /// </param>
    /// <param name="timeProvider">
    /// Time provider for <see cref="ClaimIssueResult.CreationTimestampInUtc"/>
    /// stamping. When <see langword="null"/>,
    /// <see cref="TimeProvider.System"/> is used.
    /// </param>
    public TrustChainValidator(
        string issuerId,
        IList<ClaimDelegate<TrustChainValidationContext>> validationRules,
        TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuerId);
        ArgumentNullException.ThrowIfNull(validationRules);

        issuer = new ClaimIssuer<TrustChainValidationContext>(
            issuerId, validationRules, timeProvider);
    }


    /// <summary>
    /// Builds a Trust Chain validator configured with the OpenID Federation
    /// 1.0 §4.3 / §10 baseline rule set.
    /// </summary>
    public static TrustChainValidator Default(TimeProvider? timeProvider = null) =>
        new(WellKnownFederationAssessorIds.ValidateTrustChain,
            FederationValidationProfiles.TrustChainRules(),
            timeProvider);


    /// <summary>
    /// Runs the configured rules against <paramref name="context"/>,
    /// producing a <see cref="ClaimIssueResult"/> with one
    /// <see cref="Claim"/> per rule.
    /// </summary>
    public ValueTask<ClaimIssueResult> ValidateAsync(
        TrustChainValidationContext context,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(correlationId);

        return issuer.GenerateClaimsAsync(context, correlationId, cancellationToken);
    }
}
