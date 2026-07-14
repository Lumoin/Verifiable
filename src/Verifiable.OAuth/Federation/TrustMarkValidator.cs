using System.Diagnostics;
using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Wraps a <see cref="ClaimIssuer{TInput}"/> configured with
/// <see cref="FederationValidationProfiles.TrustMarkRules"/> so a single
/// trust mark can be validated against the OpenID Federation 1.0 §7.3
/// shape-level checks (signature outcome + exp). Chain-aware checks
/// (1171 issuer authorization, 1173 delegation validity) live on
/// separate evaluator types and are orchestrated alongside this validator.
/// </summary>
/// <remarks>
/// Thin orchestrator. Signature verification happens before this
/// validator runs; the caller populates
/// <see cref="TrustMarkValidationContext.SignatureVerified"/>. Applications
/// can supply a custom rule list via the constructor to extend the §7.3
/// baseline with deployment-specific shape checks.
/// </remarks>
[DebuggerDisplay("TrustMarkValidator")]
public sealed class TrustMarkValidator
{
    private ClaimIssuer<TrustMarkValidationContext> Issuer { get; }


    /// <summary>
    /// Constructs a trust mark validator with the supplied rule list.
    /// </summary>
    public TrustMarkValidator(
        string issuerId,
        IList<ClaimDelegate<TrustMarkValidationContext>> validationRules,
        TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuerId);
        ArgumentNullException.ThrowIfNull(validationRules);

        Issuer = new ClaimIssuer<TrustMarkValidationContext>(
            issuerId, validationRules, timeProvider);
    }


    /// <summary>
    /// Builds a trust mark validator configured with the §7.3 baseline
    /// rule set (signature + exp).
    /// </summary>
    public static TrustMarkValidator Default(TimeProvider? timeProvider = null) =>
        new(WellKnownFederationAssessorIds.VerifyTrustMark,
            FederationValidationProfiles.TrustMarkRules(),
            timeProvider);


    /// <summary>
    /// Runs the configured rules against <paramref name="context"/>,
    /// producing a <see cref="ClaimIssueResult"/> with one
    /// <see cref="Claim"/> per rule.
    /// </summary>
    public ValueTask<ClaimIssueResult> ValidateAsync(
        TrustMarkValidationContext context,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(correlationId);

        return Issuer.GenerateClaimsAsync(context, correlationId, cancellationToken);
    }
}
