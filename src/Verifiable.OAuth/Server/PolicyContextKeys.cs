using System.Diagnostics;

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
/// (<see cref="RequestContext"/>, <see cref="Verifiable.OAuth.IssuanceContext"/>,
/// <see cref="Verifiable.OAuth.Validation.ValidationContext"/>). Pattern fit:
/// policy values live on <see cref="RequestContext"/> via typed extensions
/// in <see cref="PolicyRequestContextExtensions"/>.
/// </para>
/// <para>
/// Each constant documents (a) the value's runtime type, (b) the lifecycle
/// phase ("input — set by <c>ResolvePolicyAsync</c> at dispatch entry"), (c)
/// the RFC anchor or library-invariant rationale, and (d) the audit row
/// originating the axis.
/// </para>
/// <para>
/// Defaults exposed via <see cref="PolicyRequestContextExtensions"/> match the
/// strict (FAPI 2.0 / HAIP-aligned) reading. Tests that construct
/// <see cref="RequestContext"/> directly without invoking
/// <c>ResolvePolicyAsync</c> read defaults; that is the safe behaviour.
/// </para>
/// </remarks>
[DebuggerDisplay("PolicyContextKeys")]
public static class PolicyContextKeys
{
    /// <summary>
    /// The reading of JAR <c>aud</c> per RFC 9101 §10.2 the deployment accepts.
    /// Value type: <see cref="JarAudienceMode"/>. Audit row: "JAR <c>aud</c>
    /// semantic".
    /// </summary>
    public static readonly string JarAudienceValidation = "policy.jarAudienceValidation";

    /// <summary>
    /// The set of timing claims (<c>iat</c>/<c>nbf</c>/<c>exp</c>) required on
    /// inbound JARs. Value type: <see cref="TimingClaimSet"/>. Audit row:
    /// "JAR all-three-timing-claims required".
    /// </summary>
    public static readonly string RequiredJarTimingClaims = "policy.requiredJarTimingClaims";

    /// <summary>
    /// The maximum allowed JAR lifetime (<c>exp - iat</c>) per FAPI 2.0 §5.2.2
    /// Clause 13. Value type: <see cref="TimeSpan"/>. Audit row: "JAR
    /// lifetime ceiling".
    /// </summary>
    public static readonly string JarLifetimeCeiling = "policy.jarLifetimeCeiling";

    /// <summary>
    /// The set of accepted PKCE <c>code_challenge_method</c> values. Value
    /// type: <see cref="PkceMethodSet"/>. Audit row: "PKCE method enforcement".
    /// </summary>
    public static readonly string AllowedPkceMethods = "policy.allowedPkceMethods";

    /// <summary>
    /// Lifetime of authorization codes per RFC 6749 §4.1.2. Value type:
    /// <see cref="TimeSpan"/>. Audit row: "Authorization-code lifetime".
    /// </summary>
    public static readonly string AuthorizationCodeLifetime = "policy.authorizationCodeLifetime";

    /// <summary>
    /// Default lifetime of RFC 9068 access tokens when the registration does
    /// not specify a per-registration override. Value type:
    /// <see cref="TimeSpan"/>. Audit row: "Access token lifetime".
    /// </summary>
    public static readonly string AccessTokenLifetime = "policy.accessTokenLifetime";

    /// <summary>
    /// Default lifetime of OIDC ID tokens when the registration does not
    /// specify a per-registration override. Value type: <see cref="TimeSpan"/>.
    /// Audit row: "ID token lifetime".
    /// </summary>
    public static readonly string IdTokenLifetime = "policy.idTokenLifetime";

    /// <summary>
    /// Lifetime of <c>request_uri</c> handles issued by PAR per RFC 9126 §2.2.
    /// Value type: <see cref="TimeSpan"/>. Audit row: "AuthCode PAR
    /// <c>request_uri</c> lifetime".
    /// </summary>
    public static readonly string RequestUriLifetime = "policy.requestUriLifetime";

    /// <summary>
    /// Clock-skew tolerance applied when validating <c>iat</c>/<c>nbf</c>/<c>exp</c>
    /// claims on inbound JWTs. Value type: <see cref="TimeSpan"/>. Audit row:
    /// "Clock skew".
    /// </summary>
    public static readonly string ClockSkewTolerance = "policy.clockSkewTolerance";

    /// <summary>
    /// Maximum acceptable age for KB-JWT <c>iat</c> claim per OID4VP 1.0 §6.4
    /// freshness expectations. Value type: <see cref="TimeSpan"/>? (nullable —
    /// <see langword="null"/> means the application supplies the value
    /// per-call via the existing <see cref="Verifiable.OAuth.Validation.ValidationContext.MaxAge"/>
    /// path). Audit row: "KB-JWT <c>iat</c>-too-old window".
    /// </summary>
    public static readonly string KbJwtMaxAgeWindow = "policy.kbJwtMaxAgeWindow";

    /// <summary>
    /// Whether the Authorize-completed redirect emits the RFC 9207 / FAPI 2.0
    /// <c>iss</c> response parameter. Value type: <see cref="bool"/>. Audit
    /// row: "<c>iss</c> response parameter on Authorize redirect".
    /// </summary>
    public static readonly string EmitIssOnRedirect = "policy.emitIssOnRedirect";

    /// <summary>
    /// Whether <c>scope</c> is required on PKCE PAR / direct Authorize / JAR
    /// requests. Value type: <see cref="bool"/>. Audit row: "AuthCode JAR
    /// scope required" / "AuthCode PAR scope handling".
    /// </summary>
    public static readonly string ScopeRequiredOnRequest = "policy.scopeRequiredOnRequest";

    /// <summary>
    /// The wire shape of the issuer URL in metadata documents and the
    /// <c>iss</c> claim of issued tokens. Value type: <see cref="IssuerShape"/>.
    /// Audit row: "Discovery / token <c>iss</c> shape".
    /// </summary>
    public static readonly string DiscoveryIssuerShape = "policy.discoveryIssuerShape";

    /// <summary>
    /// The policy applied to the <c>aud</c> claim on RFC 9068 access tokens.
    /// Value type: <see cref="AccessTokenAudPolicy"/>. Audit row: "RFC 9068
    /// access-token <c>aud</c> claim shape".
    /// </summary>
    public static readonly string AccessTokenAudPolicy = "policy.accessTokenAudPolicy";

    /// <summary>
    /// The wire shape used for the <c>aud</c> claim on ID tokens per OIDC
    /// Core §2 (string vs array per RFC 7519 §4.1.3). Value type:
    /// <see cref="AudClaimFormat"/>. Audit row: "ID-token <c>aud</c> claim
    /// format".
    /// </summary>
    public static readonly string IdTokenAudFormat = "policy.idTokenAudFormat";

    /// <summary>
    /// The matching mode applied to the OAuth <c>state</c> parameter when
    /// validating callbacks. Value type: <see cref="StateMatchingMode"/>.
    /// Audit row: "<c>state</c> matching mode".
    /// </summary>
    public static readonly string StateMatchingMode = "policy.stateMatchingMode";

    /// <summary>
    /// The replay-defense policy applied to inbound JAR <c>jti</c> claims.
    /// Value type: <see cref="JtiReplayPolicy"/>. Audit row: "JAR <c>jti</c>
    /// replay defense".
    /// </summary>
    public static readonly string JtiReplayPolicy = "policy.jtiReplayPolicy";
}
