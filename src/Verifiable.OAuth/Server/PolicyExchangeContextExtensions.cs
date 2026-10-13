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
/// <see cref="Verifiable.Server.ServerIntegration.ResolvePolicyAsync"/>. The
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
        /// Gets the maximum allowed JAR lifetime: the policy value when set, else the request server's
        /// <see cref="TimingPolicy.AuthCodeRequestObjectLifetime"/>, else <see cref="TimingPolicy.Default"/>'s (60
        /// seconds, the library's own ceiling) when no server is on the context. A request no built-in profile ran on
        /// is held to the deployment's own value, the one the profiles derive theirs from.
        /// </summary>
        public TimeSpan JarLifetimeCeiling =>
            context.TryGetValue(PolicyContextKeys.JarLifetimeCeiling, out object? v)
                && v is TimeSpan t ? t : (context.RequestServer?.OAuth().Timings ?? TimingPolicy.Default).AuthCodeRequestObjectLifetime;

        /// <summary>Sets the maximum allowed JAR lifetime.</summary>
        public void SetJarLifetimeCeiling(TimeSpan value)
        {
            context[PolicyContextKeys.JarLifetimeCeiling] = value;
        }


        /// <summary>
        /// Gets the authorization-code lifetime: the policy value when set, else the request server's
        /// <see cref="TimingPolicy.AuthorizationCodeLifetime"/>, else <see cref="TimingPolicy.Default"/>'s (600
        /// seconds, the maximum <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 Section
        /// 4.1.2</see> recommends) when no server is on the context. A request no built-in profile ran on is held to
        /// the deployment's own value, the one the profiles derive theirs from. The getter answers the configured
        /// duration; the endpoints issue its whole seconds.
        /// </summary>
        public TimeSpan AuthorizationCodeLifetime =>
            context.TryGetValue(PolicyContextKeys.AuthorizationCodeLifetime, out object? v)
                && v is TimeSpan t ? t : (context.RequestServer?.OAuth().Timings ?? TimingPolicy.Default).AuthorizationCodeLifetime;

        /// <summary>Sets the authorization-code lifetime.</summary>
        public void SetAuthorizationCodeLifetime(TimeSpan value)
        {
            context[PolicyContextKeys.AuthorizationCodeLifetime] = value;
        }


        /// <summary>
        /// Gets the request's access-token lifetime: the policy value when set, else the request server's
        /// <see cref="TimingPolicy.AccessTokenLifetime"/>, else <see cref="TimingPolicy.Default"/>'s when no server
        /// is on the context. The getter answers the configured duration. When the policy value is absent or is an
        /// issuable <see cref="TimeSpan"/> and the registration sets no override, <see cref="TokenLifetimes.TryResolve"/>
        /// issues the token with this duration's whole seconds; a present value of another type, or one that is not
        /// issuable, is read here as it is (the server's value for another type) while
        /// <see cref="TokenLifetimes.TryResolve"/> refuses it and no token is issued.
        /// </summary>
        public TimeSpan AccessTokenLifetime =>
            context.TryGetValue(PolicyContextKeys.AccessTokenLifetime, out object? v)
                && v is TimeSpan t ? t : (context.RequestServer?.OAuth().Timings ?? TimingPolicy.Default).AccessTokenLifetime;

        /// <summary>Sets the request's access-token lifetime.</summary>
        /// <param name="value">The access-token lifetime the request's policy holds.</param>
        public void SetAccessTokenLifetime(TimeSpan value)
        {
            context[PolicyContextKeys.AccessTokenLifetime] = value;
        }


        /// <summary>
        /// Gets the request's ID-token lifetime: the policy value when set, else the request server's
        /// <see cref="TimingPolicy.IdTokenLifetime"/>, else <see cref="TimingPolicy.Default"/>'s when no server is
        /// on the context. The getter answers the configured duration. When the policy value is absent or is an
        /// issuable <see cref="TimeSpan"/> and the registration sets no override, <see cref="TokenLifetimes.TryResolve"/>
        /// issues the token with this duration's whole seconds; a present value of another type, or one that is not
        /// issuable, is read here as it is (the server's value for another type) while
        /// <see cref="TokenLifetimes.TryResolve"/> refuses it and no token is issued.
        /// </summary>
        public TimeSpan IdTokenLifetime =>
            context.TryGetValue(PolicyContextKeys.IdTokenLifetime, out object? v)
                && v is TimeSpan t ? t : (context.RequestServer?.OAuth().Timings ?? TimingPolicy.Default).IdTokenLifetime;

        /// <summary>Sets the request's ID-token lifetime.</summary>
        /// <param name="value">The ID Token lifetime the request's policy holds.</param>
        public void SetIdTokenLifetime(TimeSpan value)
        {
            context[PolicyContextKeys.IdTokenLifetime] = value;
        }


        /// <summary>
        /// Gets the request's refresh-token lifetime per
        /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 Section 6</see>: the policy value
        /// when set, else the request server's <see cref="TimingPolicy.RefreshTokenLifetime"/>, else
        /// <see cref="TimingPolicy.Default"/>'s when no server is on the context. The getter answers the configured
        /// duration. When the policy value is absent or is an issuable <see cref="TimeSpan"/> and the registration sets
        /// no override, <see cref="TokenLifetimes.TryResolve"/> issues the refresh token with this duration's whole
        /// seconds; a present value of another type, or one that is not issuable, is read here as it is (the server's
        /// value for another type) while <see cref="TokenLifetimes.TryResolve"/> refuses it and no token is issued.
        /// Deployments range from 24 hours
        /// (high-security) to 90 days (long-lived sessions), set through the <see cref="TimingPolicy"/> or the policy
        /// resolver.
        /// </summary>
        public TimeSpan RefreshTokenLifetime =>
            context.TryGetValue(PolicyContextKeys.RefreshTokenLifetime, out object? v)
                && v is TimeSpan t ? t : (context.RequestServer?.OAuth().Timings ?? TimingPolicy.Default).RefreshTokenLifetime;

        /// <summary>Sets the request's refresh-token lifetime.</summary>
        /// <param name="value">The refresh-token lifetime the request's policy holds.</param>
        public void SetRefreshTokenLifetime(TimeSpan value)
        {
            context[PolicyContextKeys.RefreshTokenLifetime] = value;
        }


        /// <summary>
        /// Gets the <c>request_uri</c> handle lifetime issued by PAR: the policy value when set, else the request
        /// server's <see cref="TimingPolicy.AuthCodeParLifetime"/>, else <see cref="TimingPolicy.Default"/>'s (60
        /// seconds) when no server is on the context. A request no built-in profile ran on is held to the
        /// deployment's own value, the one the profiles derive theirs from. The getter answers the configured
        /// duration; the pushed authorization endpoint issues its whole seconds.
        /// </summary>
        public TimeSpan RequestUriLifetime =>
            context.TryGetValue(PolicyContextKeys.RequestUriLifetime, out object? v)
                && v is TimeSpan t ? t : (context.RequestServer?.OAuth().Timings ?? TimingPolicy.Default).AuthCodeParLifetime;

        /// <summary>Sets the <c>request_uri</c> handle lifetime.</summary>
        public void SetRequestUriLifetime(TimeSpan value)
        {
            context[PolicyContextKeys.RequestUriLifetime] = value;
        }


        /// <summary>
        /// Gets the clock-skew tolerance: the policy value when set, else the request server's
        /// <see cref="TimingPolicy.ClockSkewTolerance"/>, else <see cref="TimingPolicy.Default"/>'s when no server is on
        /// the context: 60 seconds, the library's own default, within the leeway
        /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4">RFC 7519 Sections 4.1.4</see> and
        /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5">4.1.5</see> allow ("some small leeway, usually
        /// no more than a few minutes, to account for clock skew"), which names no number. A request no built-in profile
        /// ran on is held to the deployment's own value, the one the profiles derive theirs from.
        /// </summary>
        public TimeSpan ClockSkewTolerance =>
            context.TryGetValue(PolicyContextKeys.ClockSkewTolerance, out object? v)
                && v is TimeSpan t ? t : (context.RequestServer?.OAuth().Timings ?? TimingPolicy.Default).ClockSkewTolerance;

        /// <summary>Sets the clock-skew tolerance.</summary>
        public void SetClockSkewTolerance(TimeSpan value)
        {
            context[PolicyContextKeys.ClockSkewTolerance] = value;
        }


        /// <summary>
        /// Gets the clock-skew tolerance as a nullable value: the per-flow policy
        /// value when set, otherwise <see langword="null"/>. The nullable sibling
        /// of <c>ClockSkewTolerance</c> for the
        /// "policy override, else <see cref="Verifiable.OAuth.Validation.ValidationContext.ClockSkew"/> field"
        /// pattern — mirrors <c>KbJwtMaxAgeWindow</c>. Validators that want
        /// the per-flow value with a ValidationContext fallback read this; callers
        /// wanting the request server's own value when no policy value is set read
        /// <c>ClockSkewTolerance</c>.
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
        /// (<see href="https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.2">FAPI 2.0
        /// Security Profile Section 5.3.2.2</see> item 7: "shall return an iss parameter in the authorization
        /// response according to [RFC9207]").
        /// </summary>
        /// <remarks>
        /// A ternary rather than the De Morgan-equivalent boolean expression, here and on the two
        /// other true-default getters below: the ternary keeps the "policy key absent or the wrong
        /// shape" case reading as its own true default rather than folding it into a negated
        /// conjunction.
        /// </remarks>
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
        /// <remarks>A ternary for the reason stated on <c>EmitIssOnRedirect</c>.</remarks>
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
        /// <see langword="true"/> (FAPI 2.0 Security Profile Section 5.3.2.2 mandates PAR).
        /// </summary>
        /// <remarks>A ternary for the reason stated on <c>EmitIssOnRedirect</c>.</remarks>
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
        /// Gets the <c>jti</c> replay policy the <see cref="JtiReplayGuard"/> enforces. Defaults to
        /// <see cref="Server.JtiReplayPolicy.OptionalIfStorePresent"/>: the guard consults the store
        /// when one is wired and proves it can resolve what it records, and treats an unwired store as
        /// a no-op. A store that cannot resolve what it saved yields
        /// <see cref="JtiReplayOutcome.StoreUnavailable"/> under this policy and under
        /// <see cref="Server.JtiReplayPolicy.Required"/> alike.
        /// </summary>
        public JtiReplayPolicy JtiReplayPolicy =>
            context.TryGetValue(PolicyContextKeys.JtiReplayPolicy, out object? v)
                && v is JtiReplayPolicy p ? p : Server.JtiReplayPolicy.OptionalIfStorePresent;

        /// <summary>Sets the <c>jti</c> replay policy.</summary>
        public void SetJtiReplayPolicy(JtiReplayPolicy value)
        {
            context[PolicyContextKeys.JtiReplayPolicy] = value;
        }


        /// <summary>
        /// Gets whether the RFC 8252 §7.3 loopback redirect fallback
        /// (<see cref="RedirectUriMatching.IsRegisteredLoopback"/>) recognizes the <c>localhost</c>
        /// host literal alongside the two IP literals. Defaults to <see langword="false"/> when
        /// unset — <see href="https://www.rfc-editor.org/rfc/rfc8252#section-8.3">RFC 8252 §8.3</see>:
        /// "the use of localhost is NOT RECOMMENDED. Specifying a redirect URI with the loopback IP
        /// literal rather than localhost avoids inadvertently listening on network interfaces other
        /// than the loopback interface. It is also less susceptible to client-side firewalls and
        /// misconfigured host name resolution on the user's device." A deployment opts in when its
        /// native clients present <c>http://localhost:{port}/...</c> (the
        /// <see href="https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization">
        /// MCP authorization specification</see>'s "All redirect URIs MUST be either `localhost` or
        /// use HTTPS.") and accepts the residual risk sec 8.3 names — a hosts-file or resolver
        /// misconfiguration that maps <c>localhost</c> off the loopback interface.
        /// </summary>
        /// <remarks>
        /// See <c>EmitIssOnRedirect</c>'s remark for why a "defaults false" getter here would
        /// read as a ternary elsewhere in this file; this one instead mirrors
        /// <c>EnforceMinimumSaltLength</c>'s "observe, do not reject by default" shape, since
        /// both default to the safer, narrower reading.
        /// </remarks>
        public bool IsLocalhostNameAcceptedForLoopbackRedirects =>
            context.TryGetValue(PolicyContextKeys.IsLocalhostNameAcceptedForLoopbackRedirects, out object? v)
                && v is bool b && b;

        /// <summary>Sets whether the loopback redirect fallback recognizes the <c>localhost</c> host literal.</summary>
        public void SetIsLocalhostNameAcceptedForLoopbackRedirects(bool value)
        {
            context[PolicyContextKeys.IsLocalhostNameAcceptedForLoopbackRedirects] = value;
        }
    }
}
