using System.Diagnostics;
using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Wraps a <see cref="ClaimIssuer{TInput}"/> configured with
/// <see cref="FederationValidationProfiles.EntityStatementRules"/> so a
/// single Entity Statement can be validated against the OpenID Federation
/// 1.0 §3.2 rule set and the outcome surfaced as a
/// <see cref="ClaimIssueResult"/>.
/// </summary>
/// <remarks>
/// <para>
/// Thin orchestrator. JWS signature verification and per-statement key
/// resolution happen <em>before</em> this validator runs; the caller (or
/// the <c>ResolveEntityKeyDelegate</c> + <c>Jws.VerifyAsync</c>
/// composition) populates
/// <see cref="EntityStatementValidationContext.SignatureVerified"/>. The
/// validator then issues one <see cref="Claim"/> per rule in the configured
/// profile.
/// </para>
/// <para>
/// Applications can supply a custom rule list via the
/// <see cref="EntityStatementValidator(string, IList{ClaimDelegate{EntityStatementValidationContext}}, TimeProvider?)"/>
/// constructor to extend the §3.2 baseline with deployment-specific checks.
/// </para>
/// </remarks>
[DebuggerDisplay("EntityStatementValidator")]
public sealed class EntityStatementValidator
{
    private readonly ClaimIssuer<EntityStatementValidationContext> issuer;


    /// <summary>
    /// Constructs an Entity Statement validator with the supplied rule list.
    /// </summary>
    /// <param name="issuerId">
    /// Identifier stamped on every emitted
    /// <see cref="ClaimIssueResult.ClaimIssuerId"/>. Pass
    /// <see cref="WellKnownFederationAssessorIds.ValidateEntityStatement"/>
    /// for the standard profile.
    /// </param>
    /// <param name="validationRules">
    /// The rule list. Typically the result of
    /// <see cref="FederationValidationProfiles.EntityStatementRules"/>,
    /// optionally extended with deployment-specific rules.
    /// </param>
    /// <param name="timeProvider">
    /// Time provider for <see cref="ClaimIssueResult.CreationTimestampInUtc"/>
    /// stamping. When <see langword="null"/>,
    /// <see cref="TimeProvider.System"/> is used.
    /// </param>
    public EntityStatementValidator(
        string issuerId,
        IList<ClaimDelegate<EntityStatementValidationContext>> validationRules,
        TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuerId);
        ArgumentNullException.ThrowIfNull(validationRules);

        issuer = new ClaimIssuer<EntityStatementValidationContext>(
            issuerId, validationRules, timeProvider);
    }


    /// <summary>
    /// Builds an Entity Statement validator configured with the OpenID
    /// Federation 1.0 §3.2 baseline rule set.
    /// </summary>
    public static EntityStatementValidator Default(TimeProvider? timeProvider = null) =>
        new(WellKnownFederationAssessorIds.ValidateEntityStatement,
            FederationValidationProfiles.EntityStatementRules(),
            timeProvider);


    /// <summary>
    /// Runs the configured rules against <paramref name="context"/>,
    /// producing a <see cref="ClaimIssueResult"/> with one
    /// <see cref="Claim"/> per rule.
    /// </summary>
    public ValueTask<ClaimIssueResult> ValidateAsync(
        EntityStatementValidationContext context,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(correlationId);

        return issuer.GenerateClaimsAsync(context, correlationId, cancellationToken);
    }
}
