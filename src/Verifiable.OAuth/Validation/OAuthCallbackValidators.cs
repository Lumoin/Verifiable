using Verifiable.Core.Assessment;
using Verifiable.OAuth.AuthCode;

namespace Verifiable.OAuth.Validation;

/// <summary>
/// Pre-built <see cref="ValidateCallbackDelegate"/> implementations for standard OAuth 2.0
/// security profiles.
/// </summary>
/// <remarks>
/// <para>
/// Each validator runs a fixed set of <see cref="Claim"/> checks
/// and returns the full list. <see cref="AuthCodeFlow"/> treats any claim whose
/// <c>Outcome</c> is not <c>Success</c> as a failure and rejects the callback.
/// The full claim list is available on <see cref="AuthCodeFlowEndpointResult.ValidationClaims"/>
/// for audit and telemetry.
/// </para>
/// <para>
/// Callers may compose their own validator by combining checks from
/// <see cref="OAuthCallbackChecks"/> rather than using a pre-built one.
/// </para>
/// </remarks>
public static class OAuthCallbackValidators
{
    /// <summary>
    /// Validates a callback according to plain RFC 6749 with PKCE.
    /// </summary>
    /// <remarks>
    /// Checks applied:
    /// <list type="bullet">
    ///   <item><description><see cref="OAuthCallbackClaimIds.CallbackCodePresent"/> — <c>code</c> must be present.</description></item>
    ///   <item><description><see cref="OAuthCallbackClaimIds.CallbackStatePresent"/> — <c>state</c> must be present per <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.7">RFC 9700 §4.7</see>.</description></item>
    ///   <item><description><see cref="OAuthCallbackClaimIds.StateMatchesActiveFlow"/> — <c>state</c> must match a live flow.</description></item>
    ///   <item><description><see cref="OAuthCallbackClaimIds.FlowStateNotExpired"/> — the flow must not have expired.</description></item>
    /// </list>
    /// The <c>iss</c> parameter is not required by this profile.
    /// </remarks>
    public static readonly ValidateCallbackDelegate Rfc6749WithPkce =
        static (fields, flowState, timeProvider, cancellationToken) =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            List<Claim> claims = [];

            OAuthCallbackChecks.CheckCodePresent(fields, claims);
            OAuthCallbackChecks.CheckStatePresent(fields, claims);
            OAuthCallbackChecks.CheckStateMatchesFlow(fields, flowState, claims);
            OAuthCallbackChecks.CheckFlowNotExpired(flowState, timeProvider, claims);

            return claims;
        };

    /// <summary>
    /// Validates a callback according to HAIP 1.0 and FAPI 2.0, which require the
    /// <c>iss</c> parameter as a countermeasure against mix-up attacks.
    /// </summary>
    /// <remarks>
    /// Checks applied:
    /// <list type="bullet">
    ///   <item><description><see cref="OAuthCallbackClaimIds.CallbackCodePresent"/> — <c>code</c> must be present.</description></item>
    ///   <item><description><see cref="OAuthCallbackClaimIds.CallbackStatePresent"/> — <c>state</c> must be present.</description></item>
    ///   <item><description><see cref="OAuthCallbackClaimIds.CallbackIssPresent"/> — <c>iss</c> must be present per <see href="https://www.rfc-editor.org/rfc/rfc9207">RFC 9207</see>.</description></item>
    ///   <item><description><see cref="OAuthCallbackClaimIds.IssuerMatchesExpected"/> — <c>iss</c> must exactly equal the registered issuer per <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>.</description></item>
    ///   <item><description><see cref="OAuthCallbackClaimIds.StateMatchesActiveFlow"/> — <c>state</c> must match a live flow.</description></item>
    ///   <item><description><see cref="OAuthCallbackClaimIds.FlowStateNotExpired"/> — the flow must not have expired.</description></item>
    /// </list>
    /// </remarks>
    public static readonly ValidateCallbackDelegate Haip10 =
        static (fields, flowState, timeProvider, cancellationToken) =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            List<Claim> claims = [];

            OAuthCallbackChecks.CheckCodePresent(fields, claims);
            OAuthCallbackChecks.CheckStatePresent(fields, claims);
            OAuthCallbackChecks.CheckIssPresent(fields, claims);
            OAuthCallbackChecks.CheckIssuerMatches(fields, flowState, claims);
            OAuthCallbackChecks.CheckStateMatchesFlow(fields, flowState, claims);
            OAuthCallbackChecks.CheckFlowNotExpired(flowState, timeProvider, claims);

            return claims;
        };
}
