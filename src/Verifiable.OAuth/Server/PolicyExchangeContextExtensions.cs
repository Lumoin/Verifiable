using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Typed accessor extensions for per-request policy entries on a
/// <see cref="ExchangeContext"/>. Mirrors the
/// <see cref="Verifiable.OAuth.Oid4Vp.Oid4VpServerExchangeContextExtensions"/>
/// pattern.
/// </summary>
/// <remarks>
/// <para>
/// Policy values are resolved at dispatch entry by
/// <see cref="AuthorizationServerIntegration.ResolvePolicyAsync"/>. The
/// underlying keys are defined in <see cref="PolicyContextKeys"/> and remain
/// stable across versions.
/// </para>
/// <para>
/// Each accessor's getter returns a strict-reading default when the policy
/// has not been populated. The default matters because not every consumer
/// invokes <c>ResolvePolicyAsync</c>: tests construct
/// <see cref="ExchangeContext"/> directly and read policy fields. The strict
/// default is the safe behaviour when policy hasn't been resolved.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 13 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class PolicyExchangeContextExtensions
{
    extension(ExchangeContext context)
    {
        /// <summary>
        /// Gets the JAR <c>aud</c> validation mode. Defaults to
        /// <see cref="JarAudienceMode.IssuerOnly"/> (the FAPI 2.0 reading) when
        /// not set.
        /// </summary>
        public JarAudienceMode JarAudienceValidation =>
            context.TryGetValue(PolicyContextKeys.JarAudienceValidation, out object? v)
                && v is JarAudienceMode m ? m : JarAudienceMode.IssuerOnly;

        /// <summary>Sets the JAR <c>aud</c> validation mode.</summary>
        public void SetJarAudienceValidation(JarAudienceMode value)
        {
            context[PolicyContextKeys.JarAudienceValidation] = value;
        }


        /// <summary>
        /// Gets the set of JAR timing claims required. Defaults to
        /// <see cref="TimingClaimSet.All"/> (strict).
        /// </summary>
        public TimingClaimSet RequiredJarTimingClaims =>
            context.TryGetValue(PolicyContextKeys.RequiredJarTimingClaims, out object? v)
                && v is TimingClaimSet s ? s : TimingClaimSet.All;

        /// <summary>Sets the required JAR timing claims.</summary>
        public void SetRequiredJarTimingClaims(TimingClaimSet value)
        {
            context[PolicyContextKeys.RequiredJarTimingClaims] = value;
        }


        /// <summary>
        /// Gets the maximum allowed JAR lifetime. Defaults to 60 seconds (FAPI
        /// 2.0 §5.2.2 Clause 13).
        /// </summary>
        public TimeSpan JarLifetimeCeiling =>
            context.TryGetValue(PolicyContextKeys.JarLifetimeCeiling, out object? v)
                && v is TimeSpan t ? t : TimeSpan.FromSeconds(60);

        /// <summary>Sets the maximum allowed JAR lifetime.</summary>
        public void SetJarLifetimeCeiling(TimeSpan value)
        {
            context[PolicyContextKeys.JarLifetimeCeiling] = value;
        }


        /// <summary>
        /// Gets the accepted PKCE method set. Defaults to
        /// <see cref="PkceMethodSet.S256Only"/> (FAPI 2.0 / HAIP).
        /// </summary>
        public PkceMethodSet AllowedPkceMethods =>
            context.TryGetValue(PolicyContextKeys.AllowedPkceMethods, out object? v)
                && v is PkceMethodSet s ? s : PkceMethodSet.S256Only;

        /// <summary>Sets the accepted PKCE method set.</summary>
        public void SetAllowedPkceMethods(PkceMethodSet value)
        {
            context[PolicyContextKeys.AllowedPkceMethods] = value;
        }


        /// <summary>
        /// Gets the authorization-code lifetime. Defaults to 600 seconds
        /// (RFC 6749 §4.1.2 recommended ceiling).
        /// </summary>
        public TimeSpan AuthorizationCodeLifetime =>
            context.TryGetValue(PolicyContextKeys.AuthorizationCodeLifetime, out object? v)
                && v is TimeSpan t ? t : TimeSpan.FromSeconds(600);

        /// <summary>Sets the authorization-code lifetime.</summary>
        public void SetAuthorizationCodeLifetime(TimeSpan value)
        {
            context[PolicyContextKeys.AuthorizationCodeLifetime] = value;
        }


        /// <summary>
        /// Gets the default access-token lifetime. Defaults to one hour.
        /// </summary>
        public TimeSpan AccessTokenLifetime =>
            context.TryGetValue(PolicyContextKeys.AccessTokenLifetime, out object? v)
                && v is TimeSpan t ? t : TimeSpan.FromHours(1);

        /// <summary>Sets the default access-token lifetime.</summary>
        public void SetAccessTokenLifetime(TimeSpan value)
        {
            context[PolicyContextKeys.AccessTokenLifetime] = value;
        }


        /// <summary>
        /// Gets the default ID-token lifetime. Defaults to one hour.
        /// </summary>
        public TimeSpan IdTokenLifetime =>
            context.TryGetValue(PolicyContextKeys.IdTokenLifetime, out object? v)
                && v is TimeSpan t ? t : TimeSpan.FromHours(1);

        /// <summary>Sets the default ID-token lifetime.</summary>
        public void SetIdTokenLifetime(TimeSpan value)
        {
            context[PolicyContextKeys.IdTokenLifetime] = value;
        }


        /// <summary>
        /// Gets the default refresh-token lifetime per RFC 6749 §6. Defaults
        /// to 30 days. Deployments range from 24 hours (high-security) to
        /// 90 days (long-lived sessions); per-deployment override via the
        /// policy resolver.
        /// </summary>
        public TimeSpan RefreshTokenLifetime =>
            context.TryGetValue(PolicyContextKeys.RefreshTokenLifetime, out object? v)
                && v is TimeSpan t ? t : TimeSpan.FromDays(30);

        /// <summary>Sets the default refresh-token lifetime.</summary>
        public void SetRefreshTokenLifetime(TimeSpan value)
        {
            context[PolicyContextKeys.RefreshTokenLifetime] = value;
        }


        /// <summary>
        /// Gets the <c>request_uri</c> handle lifetime issued by PAR. Defaults
        /// to 60 seconds (HAIP / FAPI 2.0 alignment).
        /// </summary>
        public TimeSpan RequestUriLifetime =>
            context.TryGetValue(PolicyContextKeys.RequestUriLifetime, out object? v)
                && v is TimeSpan t ? t : TimeSpan.FromSeconds(60);

        /// <summary>Sets the <c>request_uri</c> handle lifetime.</summary>
        public void SetRequestUriLifetime(TimeSpan value)
        {
            context[PolicyContextKeys.RequestUriLifetime] = value;
        }


        /// <summary>
        /// Gets the clock-skew tolerance. Defaults to 60 seconds (RFC 7519
        /// §4.1.4 leeway guidance).
        /// </summary>
        public TimeSpan ClockSkewTolerance =>
            context.TryGetValue(PolicyContextKeys.ClockSkewTolerance, out object? v)
                && v is TimeSpan t ? t : TimeSpan.FromSeconds(60);

        /// <summary>Sets the clock-skew tolerance.</summary>
        public void SetClockSkewTolerance(TimeSpan value)
        {
            context[PolicyContextKeys.ClockSkewTolerance] = value;
        }


        /// <summary>
        /// Gets the clock-skew tolerance as a nullable value: the per-flow policy
        /// value when set, otherwise <see langword="null"/>. The nullable sibling
        /// of <see cref="ClockSkewTolerance"/> for the
        /// "policy override, else <see cref="Verifiable.OAuth.Validation.ValidationContext.ClockSkew"/> field"
        /// pattern — mirrors <see cref="KbJwtMaxAgeWindow"/>. Validators that want
        /// the per-flow value with a ValidationContext fallback read this; callers
        /// wanting the unconditional 60-second default read
        /// <see cref="ClockSkewTolerance"/>.
        /// </summary>
        public TimeSpan? ClockSkewToleranceOverride =>
            context.TryGetValue(PolicyContextKeys.ClockSkewTolerance, out object? v)
                && v is TimeSpan t ? t : null;


        /// <summary>
        /// Gets the KB-JWT max-age window. Returns <see langword="null"/> when
        /// unset; consumers fall back to the application-supplied value via
        /// <see cref="Verifiable.OAuth.Validation.ValidationContext.KbJwtMaxAge"/>.
        /// </summary>
        public TimeSpan? KbJwtMaxAgeWindow =>
            context.TryGetValue(PolicyContextKeys.KbJwtMaxAgeWindow, out object? v)
                && v is TimeSpan t ? t : null;

        /// <summary>Sets the KB-JWT max-age window.</summary>
        public void SetKbJwtMaxAgeWindow(TimeSpan value)
        {
            context[PolicyContextKeys.KbJwtMaxAgeWindow] = value;
        }


        /// <summary>
        /// Whether the verifier rejects an over-disclosing presentation. Defaults
        /// to <see langword="true"/> (enforce) when the policy key is absent.
        /// Set <see langword="false"/> to record over-disclosure as a non-failing
        /// signal instead of rejecting.
        /// </summary>
        public bool EnforceNoOverDisclosure =>
            !context.TryGetValue(PolicyContextKeys.EnforceNoOverDisclosure, out object? v)
                || v is not bool b || b;

        /// <summary>Sets whether the verifier rejects an over-disclosing presentation.</summary>
        public void SetEnforceNoOverDisclosure(bool value)
        {
            context[PolicyContextKeys.EnforceNoOverDisclosure] = value;
        }


        /// <summary>
        /// Whether the verifier rejects a presentation whose disclosure salts are shorter than the
        /// recommended minimum length. Defaults to <see langword="false"/> (observe, do not reject) when
        /// the policy key is absent — the salt length is surfaced as a signal and the deployment opts in.
        /// </summary>
        public bool EnforceMinimumSaltLength =>
            context.TryGetValue(PolicyContextKeys.EnforceMinimumSaltLength, out object? v)
                && v is bool b && b;

        /// <summary>Sets whether the verifier rejects a presentation with under-length disclosure salts.</summary>
        public void SetEnforceMinimumSaltLength(bool value)
        {
            context[PolicyContextKeys.EnforceMinimumSaltLength] = value;
        }


        /// <summary>
        /// Gets whether the Authorize-completed redirect emits the RFC 9207
        /// <c>iss</c> response parameter. Defaults to <see langword="true"/>
        /// (FAPI 2.0 §5.3.1.2).
        /// </summary>
        public bool EmitIssOnRedirect =>
            context.TryGetValue(PolicyContextKeys.EmitIssOnRedirect, out object? v)
                && v is bool b ? b : true;

        /// <summary>Sets whether to emit <c>iss</c> on the Authorize redirect.</summary>
        public void SetEmitIssOnRedirect(bool value)
        {
            context[PolicyContextKeys.EmitIssOnRedirect] = value;
        }


        /// <summary>
        /// Gets whether <c>scope</c> is required on PKCE PAR / direct
        /// Authorize / JAR requests. Defaults to <see langword="true"/>.
        /// </summary>
        public bool ScopeRequiredOnRequest =>
            context.TryGetValue(PolicyContextKeys.ScopeRequiredOnRequest, out object? v)
                && v is bool b ? b : true;

        /// <summary>Sets whether <c>scope</c> is required on requests.</summary>
        public void SetScopeRequiredOnRequest(bool value)
        {
            context[PolicyContextKeys.ScopeRequiredOnRequest] = value;
        }


        /// <summary>
        /// Gets whether Pushed Authorization Requests are mandatory — when
        /// <see langword="true"/>, the AS refuses the direct-Authorize and JAR-by-value
        /// paths and requires the client to push the request first. Defaults to
        /// <see langword="true"/> (FAPI 2.0 §5.2.2 mandates PAR).
        /// </summary>
        public bool RequirePushedAuthorizationRequests =>
            context.TryGetValue(PolicyContextKeys.RequirePushedAuthorizationRequests, out object? v)
                && v is bool b ? b : true;

        /// <summary>Sets whether Pushed Authorization Requests are mandatory.</summary>
        public void SetRequirePushedAuthorizationRequests(bool value)
        {
            context[PolicyContextKeys.RequirePushedAuthorizationRequests] = value;
        }


        /// <summary>
        /// Gets whether the deployment accepts an OID4VCI 1.0 §6 Pre-Authorized Code Token
        /// Request without a <c>client_id</c>. Defaults to <see langword="false"/> — the §12.3
        /// default for <c>pre-authorized_grant_anonymous_access_supported</c>.
        /// </summary>
        public bool PreAuthorizedGrantAnonymousAccessSupported =>
            context.TryGetValue(PolicyContextKeys.PreAuthorizedGrantAnonymousAccessSupported, out object? v)
                && v is bool b && b;

        /// <summary>Sets whether the §6 Pre-Authorized Code grant accepts anonymous (no <c>client_id</c>) Token Requests.</summary>
        public void SetPreAuthorizedGrantAnonymousAccessSupported(bool value)
        {
            context[PolicyContextKeys.PreAuthorizedGrantAnonymousAccessSupported] = value;
        }


        /// <summary>
        /// Gets the wire shape of the issuer URL. Defaults to
        /// <see cref="IssuerShape.FullUrl"/> (multi-tenant FAPI 2.0).
        /// </summary>
        public IssuerShape DiscoveryIssuerShape =>
            context.TryGetValue(PolicyContextKeys.DiscoveryIssuerShape, out object? v)
                && v is IssuerShape s ? s : IssuerShape.FullUrl;

        /// <summary>Sets the wire shape of the issuer URL.</summary>
        public void SetDiscoveryIssuerShape(IssuerShape value)
        {
            context[PolicyContextKeys.DiscoveryIssuerShape] = value;
        }


        /// <summary>
        /// Gets the access-token <c>aud</c> policy. Defaults to
        /// <see cref="Server.AccessTokenAudPolicy.Required"/> (RFC 9068 §2.2).
        /// </summary>
        public AccessTokenAudPolicy AccessTokenAudPolicy =>
            context.TryGetValue(PolicyContextKeys.AccessTokenAudPolicy, out object? v)
                && v is AccessTokenAudPolicy p ? p : Server.AccessTokenAudPolicy.Required;

        /// <summary>Sets the access-token <c>aud</c> policy.</summary>
        public void SetAccessTokenAudPolicy(AccessTokenAudPolicy value)
        {
            context[PolicyContextKeys.AccessTokenAudPolicy] = value;
        }


        /// <summary>
        /// Gets the wire shape of the ID-token <c>aud</c> claim. Defaults to
        /// <see cref="AudClaimFormat.Either"/>.
        /// </summary>
        public AudClaimFormat IdTokenAudFormat =>
            context.TryGetValue(PolicyContextKeys.IdTokenAudFormat, out object? v)
                && v is AudClaimFormat f ? f : AudClaimFormat.Either;

        /// <summary>Sets the wire shape of the ID-token <c>aud</c> claim.</summary>
        public void SetIdTokenAudFormat(AudClaimFormat value)
        {
            context[PolicyContextKeys.IdTokenAudFormat] = value;
        }


        /// <summary>
        /// Gets the <c>state</c> matching mode. Defaults to
        /// <see cref="Server.StateMatchingMode.ExactOrdinal"/>.
        /// </summary>
        public StateMatchingMode StateMatchingMode =>
            context.TryGetValue(PolicyContextKeys.StateMatchingMode, out object? v)
                && v is StateMatchingMode m ? m : Server.StateMatchingMode.ExactOrdinal;

        /// <summary>Sets the <c>state</c> matching mode.</summary>
        public void SetStateMatchingMode(StateMatchingMode value)
        {
            context[PolicyContextKeys.StateMatchingMode] = value;
        }


        /// <summary>
        /// Gets the <c>jti</c> replay policy. Defaults to
        /// <see cref="Server.JtiReplayPolicy.OptionalIfStorePresent"/> while the
        /// replay-store surface is being finalised.
        /// </summary>
        public JtiReplayPolicy JtiReplayPolicy =>
            context.TryGetValue(PolicyContextKeys.JtiReplayPolicy, out object? v)
                && v is JtiReplayPolicy p ? p : Server.JtiReplayPolicy.OptionalIfStorePresent;

        /// <summary>Sets the <c>jti</c> replay policy.</summary>
        public void SetJtiReplayPolicy(JtiReplayPolicy value)
        {
            context[PolicyContextKeys.JtiReplayPolicy] = value;
        }
    }
}
