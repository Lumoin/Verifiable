using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Well-known context bag key constants for the per-request policy axes the
/// Authorization Server consults at dispatch time. Mirrors the
/// <see cref="Verifiable.OAuth.Oid4Vp.Oid4VpContextKeys"/> pattern but for
/// policy values rather than per-flow inputs.
/// </summary>
/// <remarks>
/// <para>
/// Policy values are resolved at dispatch entry by
/// <see cref="AuthorizationServerIntegration.ResolvePolicyAsync"/>; their
/// lifetime is per-request, their consumers span every downstream context
/// (<see cref="ExchangeContext"/>, <see cref="Verifiable.OAuth.IssuanceContext"/>,
/// <see cref="Verifiable.OAuth.Validation.ValidationContext"/>). Pattern fit:
/// policy values live on <see cref="ExchangeContext"/> via typed extensions
/// in <see cref="PolicyExchangeContextExtensions"/>.
/// </para>
/// <para>
/// Each constant documents (a) the value's runtime type, (b) the lifecycle
/// phase ("input — set by <c>ResolvePolicyAsync</c> at dispatch entry"), (c)
/// the RFC anchor or library-invariant rationale, and (d) the audit row
/// originating the axis.
/// </para>
/// <para>
/// Defaults exposed via <see cref="PolicyExchangeContextExtensions"/> match the
/// strict (FAPI 2.0 / HAIP-aligned) reading. Tests that construct
/// <see cref="ExchangeContext"/> directly without invoking
/// <c>ResolvePolicyAsync</c> read defaults; that is the safe behaviour.
/// </para>
/// </remarks>
[DebuggerDisplay("PolicyContextKeys")]
public static class PolicyContextKeys
{
    /// <summary>The UTF-8 source literal of <see cref="JarAudienceValidation"/>.</summary>
    public static ReadOnlySpan<byte> JarAudienceValidationUtf8 => "policy.jarAudienceValidation"u8;

    /// <summary>
    /// The reading of JAR <c>aud</c> per RFC 9101 §10.2 the deployment accepts.
    /// Value type: <see cref="JarAudienceMode"/>. Audit row: "JAR <c>aud</c>
    /// semantic".
    /// </summary>
    public static readonly string JarAudienceValidation = Utf8Constants.ToInternedString(JarAudienceValidationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RequiredJarTimingClaims"/>.</summary>
    public static ReadOnlySpan<byte> RequiredJarTimingClaimsUtf8 => "policy.requiredJarTimingClaims"u8;

    /// <summary>
    /// The set of timing claims (<c>iat</c>/<c>nbf</c>/<c>exp</c>) required on
    /// inbound JARs. Value type: <see cref="TimingClaimSet"/>. Audit row:
    /// "JAR all-three-timing-claims required".
    /// </summary>
    public static readonly string RequiredJarTimingClaims = Utf8Constants.ToInternedString(RequiredJarTimingClaimsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="JarLifetimeCeiling"/>.</summary>
    public static ReadOnlySpan<byte> JarLifetimeCeilingUtf8 => "policy.jarLifetimeCeiling"u8;

    /// <summary>
    /// The maximum allowed JAR lifetime (<c>exp - iat</c>) per FAPI 2.0 §5.2.2
    /// Clause 13. Value type: <see cref="TimeSpan"/>. Audit row: "JAR
    /// lifetime ceiling".
    /// </summary>
    public static readonly string JarLifetimeCeiling = Utf8Constants.ToInternedString(JarLifetimeCeilingUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AllowedPkceMethods"/>.</summary>
    public static ReadOnlySpan<byte> AllowedPkceMethodsUtf8 => "policy.allowedPkceMethods"u8;

    /// <summary>
    /// The set of accepted PKCE <c>code_challenge_method</c> values. Value
    /// type: <see cref="PkceMethodSet"/>. Audit row: "PKCE method enforcement".
    /// </summary>
    public static readonly string AllowedPkceMethods = Utf8Constants.ToInternedString(AllowedPkceMethodsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthorizationCodeLifetime"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationCodeLifetimeUtf8 => "policy.authorizationCodeLifetime"u8;

    /// <summary>
    /// Lifetime of authorization codes per RFC 6749 §4.1.2. Value type:
    /// <see cref="TimeSpan"/>. Audit row: "Authorization-code lifetime".
    /// </summary>
    public static readonly string AuthorizationCodeLifetime = Utf8Constants.ToInternedString(AuthorizationCodeLifetimeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AccessTokenLifetime"/>.</summary>
    public static ReadOnlySpan<byte> AccessTokenLifetimeUtf8 => "policy.accessTokenLifetime"u8;

    /// <summary>
    /// Default lifetime of RFC 9068 access tokens when the registration does
    /// not specify a per-registration override. Value type:
    /// <see cref="TimeSpan"/>. Audit row: "Access token lifetime".
    /// </summary>
    public static readonly string AccessTokenLifetime = Utf8Constants.ToInternedString(AccessTokenLifetimeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IdTokenLifetime"/>.</summary>
    public static ReadOnlySpan<byte> IdTokenLifetimeUtf8 => "policy.idTokenLifetime"u8;

    /// <summary>
    /// Default lifetime of OIDC ID tokens when the registration does not
    /// specify a per-registration override. Value type: <see cref="TimeSpan"/>.
    /// Audit row: "ID token lifetime".
    /// </summary>
    public static readonly string IdTokenLifetime = Utf8Constants.ToInternedString(IdTokenLifetimeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RefreshTokenLifetime"/>.</summary>
    public static ReadOnlySpan<byte> RefreshTokenLifetimeUtf8 => "policy.refreshTokenLifetime"u8;

    /// <summary>
    /// Default lifetime of refresh tokens issued at the token endpoint per
    /// RFC 6749 §6. Value type: <see cref="TimeSpan"/>. Audit row:
    /// "Refresh token lifetime".
    /// </summary>
    public static readonly string RefreshTokenLifetime = Utf8Constants.ToInternedString(RefreshTokenLifetimeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RequestUriLifetime"/>.</summary>
    public static ReadOnlySpan<byte> RequestUriLifetimeUtf8 => "policy.requestUriLifetime"u8;

    /// <summary>
    /// Lifetime of <c>request_uri</c> handles issued by PAR per RFC 9126 §2.2.
    /// Value type: <see cref="TimeSpan"/>. Audit row: "AuthCode PAR
    /// <c>request_uri</c> lifetime".
    /// </summary>
    public static readonly string RequestUriLifetime = Utf8Constants.ToInternedString(RequestUriLifetimeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClockSkewTolerance"/>.</summary>
    public static ReadOnlySpan<byte> ClockSkewToleranceUtf8 => "policy.clockSkewTolerance"u8;

    /// <summary>
    /// Clock-skew tolerance applied when validating <c>iat</c>/<c>nbf</c>/<c>exp</c>
    /// claims on inbound JWTs. Value type: <see cref="TimeSpan"/>. Audit row:
    /// "Clock skew".
    /// </summary>
    public static readonly string ClockSkewTolerance = Utf8Constants.ToInternedString(ClockSkewToleranceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="KbJwtMaxAgeWindow"/>.</summary>
    public static ReadOnlySpan<byte> KbJwtMaxAgeWindowUtf8 => "policy.kbJwtMaxAgeWindow"u8;

    /// <summary>
    /// Maximum acceptable age for KB-JWT <c>iat</c> claim per OID4VP 1.0 §6.4
    /// freshness expectations. Value type: <see cref="TimeSpan"/>? (nullable —
    /// <see langword="null"/> means the application supplies the value
    /// per-call via the existing <see cref="Verifiable.OAuth.Validation.ValidationContext.KbJwtMaxAge"/>
    /// path). Audit row: "KB-JWT <c>iat</c>-too-old window".
    /// </summary>
    public static readonly string KbJwtMaxAgeWindow = Utf8Constants.ToInternedString(KbJwtMaxAgeWindowUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EnforceNoOverDisclosure"/>.</summary>
    public static ReadOnlySpan<byte> EnforceNoOverDisclosureUtf8 => "policy.enforceNoOverDisclosure"u8;

    /// <summary>
    /// Whether the verifier rejects a presentation that discloses more claims
    /// than the DCQL query requested (data-minimization enforcement). Value
    /// type: <see cref="bool"/>. Absent defaults to enforce (reject) — see
    /// <see cref="Verifiable.OAuth.Validation.ValidationChecks.CheckNoOverDisclosure"/>.
    /// Base OID4VP/SD-JWT VC treat minimization as a holder duty and do not
    /// mandate verifier rejection, so deployments may set this <see langword="false"/>.
    /// </summary>
    public static readonly string EnforceNoOverDisclosure = Utf8Constants.ToInternedString(EnforceNoOverDisclosureUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EnforceMinimumSaltLength"/>.</summary>
    public static ReadOnlySpan<byte> EnforceMinimumSaltLengthUtf8 => "policy.enforceMinimumSaltLength"u8;

    /// <summary>
    /// Whether the verifier rejects a presentation whose disclosure salts are shorter than the
    /// recommended minimum length. Value type: <see cref="bool"/>. Absent defaults to
    /// <see langword="false"/> (observe, do not reject) — RFC 9901 §9.3 RECOMMENDS 128-bit salts but
    /// does not mandate verifier rejection, so the length is surfaced as a signal and the deployment
    /// opts in to enforcement. See
    /// <see cref="Verifiable.OAuth.Validation.ValidationChecks.CheckDisclosureSaltLength"/>.
    /// </summary>
    public static readonly string EnforceMinimumSaltLength = Utf8Constants.ToInternedString(EnforceMinimumSaltLengthUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EmitIssOnRedirect"/>.</summary>
    public static ReadOnlySpan<byte> EmitIssOnRedirectUtf8 => "policy.emitIssOnRedirect"u8;

    /// <summary>
    /// Whether the Authorize-completed redirect emits the RFC 9207 / FAPI 2.0
    /// <c>iss</c> response parameter. Value type: <see cref="bool"/>. Audit
    /// row: "<c>iss</c> response parameter on Authorize redirect".
    /// </summary>
    public static readonly string EmitIssOnRedirect = Utf8Constants.ToInternedString(EmitIssOnRedirectUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ScopeRequiredOnRequest"/>.</summary>
    public static ReadOnlySpan<byte> ScopeRequiredOnRequestUtf8 => "policy.scopeRequiredOnRequest"u8;

    /// <summary>
    /// Whether <c>scope</c> is required on PKCE PAR / direct Authorize / JAR
    /// requests. Value type: <see cref="bool"/>. Audit row: "AuthCode JAR
    /// scope required" / "AuthCode PAR scope handling".
    /// </summary>
    public static readonly string ScopeRequiredOnRequest = Utf8Constants.ToInternedString(ScopeRequiredOnRequestUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RequirePushedAuthorizationRequests"/>.</summary>
    public static ReadOnlySpan<byte> RequirePushedAuthorizationRequestsUtf8 => "policy.requirePushedAuthorizationRequests"u8;

    /// <summary>
    /// Whether Pushed Authorization Requests are mandatory — when set, the AS refuses
    /// the direct-Authorize and JAR-by-value paths and requires the client to push the
    /// request first (FAPI 2.0 §5.2.2). Value type: <see cref="bool"/>. Audit row:
    /// "require_pushed_authorization_requests".
    /// </summary>
    public static readonly string RequirePushedAuthorizationRequests = Utf8Constants.ToInternedString(RequirePushedAuthorizationRequestsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PreAuthorizedGrantAnonymousAccessSupported"/>.</summary>
    public static ReadOnlySpan<byte> PreAuthorizedGrantAnonymousAccessSupportedUtf8 => "policy.preAuthorizedGrantAnonymousAccessSupported"u8;

    /// <summary>
    /// Whether the deployment accepts a Pre-Authorized Code Token Request without a
    /// <c>client_id</c> — the OID4VCI 1.0 §12.3 anonymous-access advertisement. Value type:
    /// <see cref="bool"/>. The §12.3 default is <see langword="false"/>, so the AS Metadata
    /// document advertises <c>pre-authorized_grant_anonymous_access_supported</c> only when a
    /// deployment opts in. Audit row: "<c>pre-authorized_grant_anonymous_access_supported</c>".
    /// </summary>
    public static readonly string PreAuthorizedGrantAnonymousAccessSupported = Utf8Constants.ToInternedString(PreAuthorizedGrantAnonymousAccessSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DiscoveryIssuerShape"/>.</summary>
    public static ReadOnlySpan<byte> DiscoveryIssuerShapeUtf8 => "policy.discoveryIssuerShape"u8;

    /// <summary>
    /// The wire shape of the issuer URL in metadata documents and the
    /// <c>iss</c> claim of issued tokens. Value type: <see cref="IssuerShape"/>.
    /// Audit row: "Discovery / token <c>iss</c> shape".
    /// </summary>
    public static readonly string DiscoveryIssuerShape = Utf8Constants.ToInternedString(DiscoveryIssuerShapeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AccessTokenAudPolicy"/>.</summary>
    public static ReadOnlySpan<byte> AccessTokenAudPolicyUtf8 => "policy.accessTokenAudPolicy"u8;

    /// <summary>
    /// The policy applied to the <c>aud</c> claim on RFC 9068 access tokens.
    /// Value type: <see cref="AccessTokenAudPolicy"/>. Audit row: "RFC 9068
    /// access-token <c>aud</c> claim shape".
    /// </summary>
    public static readonly string AccessTokenAudPolicy = Utf8Constants.ToInternedString(AccessTokenAudPolicyUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IdTokenAudFormat"/>.</summary>
    public static ReadOnlySpan<byte> IdTokenAudFormatUtf8 => "policy.idTokenAudFormat"u8;

    /// <summary>
    /// The wire shape used for the <c>aud</c> claim on ID tokens per OIDC
    /// Core §2 (string vs array per RFC 7519 §4.1.3). Value type:
    /// <see cref="AudClaimFormat"/>. Audit row: "ID-token <c>aud</c> claim
    /// format".
    /// </summary>
    public static readonly string IdTokenAudFormat = Utf8Constants.ToInternedString(IdTokenAudFormatUtf8);

    /// <summary>The UTF-8 source literal of <see cref="StateMatchingMode"/>.</summary>
    public static ReadOnlySpan<byte> StateMatchingModeUtf8 => "policy.stateMatchingMode"u8;

    /// <summary>
    /// The matching mode applied to the OAuth <c>state</c> parameter when
    /// validating callbacks. Value type: <see cref="StateMatchingMode"/>.
    /// Audit row: "<c>state</c> matching mode".
    /// </summary>
    public static readonly string StateMatchingMode = Utf8Constants.ToInternedString(StateMatchingModeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="JtiReplayPolicy"/>.</summary>
    public static ReadOnlySpan<byte> JtiReplayPolicyUtf8 => "policy.jtiReplayPolicy"u8;

    /// <summary>
    /// The replay-defense policy applied to inbound JAR <c>jti</c> claims.
    /// Value type: <see cref="JtiReplayPolicy"/>. Audit row: "JAR <c>jti</c>
    /// replay defense".
    /// </summary>
    public static readonly string JtiReplayPolicy = Utf8Constants.ToInternedString(JtiReplayPolicyUtf8);
}
