using Verifiable.Core;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Built-in policy profile apply functions and the default
/// <see cref="ResolvePolicyDelegate"/>. Each apply function populates the
/// <see cref="PolicyContextKeys"/> entries on a
/// <see cref="ExchangeContext"/> in one call.
/// </summary>
/// <remarks>
/// <para>
/// Profiles are applied at dispatch entry once per request. Downstream
/// consumers (matchers, validators, token producers) read policy via the
/// typed extensions in <see cref="PolicyExchangeContextExtensions"/>. When a
/// lifetime or the clock skew is absent, because no profile ran on the request,
/// the extensions answer the request server's own <see cref="TimingPolicy"/>
/// value (<see cref="TimingPolicy.Default"/>'s when no server is on the
/// context), the record the profiles derive their values from: the defaults
/// are equal, and a customised <see cref="TimingPolicy"/> governs a request no
/// profile ran on as it governs the profiles. Every other absent policy value
/// reads its strict default.
/// </para>
/// <para>
/// Adding a built-in profile means adding a new <c>ApplyXxx</c> function
/// here plus a new static readonly value on <see cref="PolicyProfile"/>
/// plus a dispatch arm in <see cref="DefaultResolvePolicyAsync"/>.
/// Tenant-specific profiles do not modify this class; instead they use
/// <see cref="PolicyProfile.Create"/> and supply a custom
/// <see cref="ResolvePolicyDelegate"/>. See the remarks on
/// <see cref="PolicyProfile"/> for the full extensibility shape.
/// </para>
/// </remarks>
public static class PolicyProfiles
{
    /// <summary>
    /// The FAPI 2.0 ceiling of an authorization code's lifetime.
    /// <see href="https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1">FAPI 2.0 Security
    /// Profile Section 5.3.2.1</see> item 11: "shall issue authorization codes with a maximum lifetime of 60 seconds;"
    /// </summary>
    private static TimeSpan Fapi20AuthorizationCodeLifetimeCeiling { get; } = TimeSpan.FromSeconds(60);


    /// <summary>
    /// The FAPI 2.0 ceiling of a pushed <c>request_uri</c>'s lifetime: 599 seconds, the largest whole number of
    /// seconds below 600, because the pushed authorization response states the lifetime as a whole-second
    /// <c>expires_in</c>.
    /// <see href="https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.2">FAPI 2.0 Security
    /// Profile Section 5.3.2.2</see> item 12: "shall issue pushed authorization requests request_uri with expires_in
    /// values of less than 600 seconds;"
    /// </summary>
    private static TimeSpan Fapi20RequestUriLifetimeCeiling { get; } = TimeSpan.FromSeconds(599);


    /// <summary>
    /// The FAPI 2.0 floor of the clock skew applied to an inbound JWT's <c>iat</c> or <c>nbf</c> in the future.
    /// <see href="https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1">FAPI 2.0 Security
    /// Profile Section 5.3.2.1</see> item 13: "to accommodate clock offsets, shall accept JWTs with an iat or nbf
    /// timestamp between 0 and 10 seconds in the future but shall reject JWTs with an iat or nbf timestamp greater than
    /// 60 seconds in the future. See Note 3 for further details and rationale; and"
    /// </summary>
    private static TimeSpan Fapi20ClockSkewFloor { get; } = TimeSpan.FromSeconds(10);


    /// <summary>
    /// The FAPI 2.0 ceiling of the clock skew applied to an inbound JWT's <c>iat</c> or <c>nbf</c> in the future,
    /// from the same sentence as <see cref="Fapi20ClockSkewFloor"/>.
    /// </summary>
    private static TimeSpan Fapi20ClockSkewCeiling { get; } = TimeSpan.FromSeconds(60);


    /// <summary>
    /// The floor of every lifetime a profile holds to a ceiling: one second, the smallest lifetime the one rule of
    /// <see cref="TokenLifetimes.IsIssuable"/> issues, so no derived lifetime states <c>expires_in</c> 0.
    /// </summary>
    private static TimeSpan LifetimeFloor { get; } = TimeSpan.FromSeconds(1);


    /// <summary>
    /// The library's own ceiling of the pushed <c>request_uri</c> lifetime and the request object lifetime under the
    /// HAIP 1.0 profile: 60 seconds. No HAIP 1.0 or FAPI 2.0 sentence sets this value; it is the library's own.
    /// </summary>
    private static TimeSpan Haip10LifetimeCeiling { get; } = TimeSpan.FromSeconds(60);


    /// <summary>
    /// Holds <paramref name="value"/> within <paramref name="floor"/> and <paramref name="ceiling"/>: the floor when
    /// the value is below it, the ceiling when the value is above it, else the value.
    /// </summary>
    /// <param name="value">The value the server's <see cref="TimingPolicy"/> holds.</param>
    /// <param name="floor">The smallest value the profile allows.</param>
    /// <param name="ceiling">The largest value the profile allows.</param>
    /// <returns>The value the profile sets on the request.</returns>
    private static TimeSpan Within(TimeSpan value, TimeSpan floor, TimeSpan ceiling) => value switch
    {
        _ when value < floor => floor,
        _ when value > ceiling => ceiling,
        _ => value
    };


    /// <summary>
    /// Populates the FAPI 2.0 Security Profile axes. Used as the default
    /// when no <c>Profile</c> is set on a registration, and as the base for
    /// <see cref="ApplyHaip10"/>.
    /// </summary>
    /// <remarks>
    /// The lifetimes and the clock skew derive from the server's <see cref="TimingPolicy"/>, each held to the
    /// profile's ceiling: the authorization code lifetime is the smaller of
    /// <see cref="TimingPolicy.AuthorizationCodeLifetime"/> and 60 seconds, the <c>request_uri</c> lifetime the
    /// smaller of <see cref="TimingPolicy.AuthCodeParLifetime"/> and 599 seconds, each at least one second, and the
    /// clock skew <see cref="TimingPolicy.ClockSkewTolerance"/> raised to 10 seconds when below and lowered to 60
    /// seconds when above. The ceilings bound the values the profile derives; an application's
    /// <see cref="ResolvePolicyDelegate"/> that sets one of them after the profile ran owns the value it set.
    /// </remarks>
    /// <param name="context">The request's exchange context the profile's values are set on.</param>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> is null.</exception>
    public static void ApplyFapi20(ExchangeContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        //Single source of truth: the lifetimes and the clock skew derive from the
        //deployment's TimingPolicy, falling back to TimingPolicy.Default when no
        //server is on the context (out-of-dispatch / unit-test use), and are held to
        //the profile's ceilings. A request's token lifetimes are read through
        //TokenLifetimes.TryResolve, where a registration's own override wins over
        //these values.
        TimingPolicy timings = context.RequestServer?.OAuth().Timings ?? TimingPolicy.Default;
        context.SetJarAudienceValidation(JarAudienceMode.IssuerOnly);
        context.SetRequiredJarTimingClaims(TimingClaimSet.All);
        context.SetJarLifetimeCeiling(timings.AuthCodeRequestObjectLifetime);
        context.SetAuthorizationCodeLifetime(
            Within(timings.AuthorizationCodeLifetime, LifetimeFloor, Fapi20AuthorizationCodeLifetimeCeiling));
        context.SetAccessTokenLifetime(timings.AccessTokenLifetime);
        context.SetIdTokenLifetime(timings.IdTokenLifetime);
        context.SetRefreshTokenLifetime(timings.RefreshTokenLifetime);
        context.SetRequestUriLifetime(Within(timings.AuthCodeParLifetime, LifetimeFloor, Fapi20RequestUriLifetimeCeiling));
        context.SetClockSkewTolerance(Within(timings.ClockSkewTolerance, Fapi20ClockSkewFloor, Fapi20ClockSkewCeiling));
        context.SetEmitIssOnRedirect(true);
        context.SetScopeRequiredOnRequest(true);
        context.SetDiscoveryIssuerShape(IssuerShape.FullUrl);
        context.SetIdTokenAudFormat(AudClaimFormat.Either);
        context.SetStateMatchingMode(StateMatchingMode.ExactOrdinal);
        context.SetJtiReplayPolicy(JtiReplayPolicy.Required);
        context.SetRequirePushedAuthorizationRequests(true);
    }


    /// <summary>
    /// Populates the
    /// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html">HAIP 1.0</see>
    /// profile. <see cref="ApplyFapi20"/> with HAIP-specific tightenings.
    /// </summary>
    /// <remarks>
    /// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html#section-4">HAIP
    /// 1.0 Section 4</see>: "MUST comply with the provisions of [FAPI2_Security_Profile] that are applicable to this
    /// specification." The profile inherits the FAPI 2.0 ceilings through <see cref="ApplyFapi20"/> and holds the
    /// <c>request_uri</c> lifetime and the request object lifetime to the library's own ceiling of 60 seconds: each is
    /// the smaller of the server's <see cref="TimingPolicy"/> value and 60 seconds, at least one second, so a shorter
    /// deployment value is kept as it is.
    /// </remarks>
    /// <param name="context">The request's exchange context the profile's values are set on.</param>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> is null.</exception>
    public static void ApplyHaip10(ExchangeContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ApplyFapi20(context);
        //The library's own 60-second ceilings, held over the values the TimingPolicy
        //sets: a longer deployment value is lowered to them and a shorter one is
        //kept. HAIP-specific axes that the library does not expose (for example
        //mandatory A128GCM/A256GCM advertisement on verifier client metadata) live
        //outside the policy bag on VerifierClientMetadata directly.
        TimingPolicy timings = context.RequestServer?.OAuth().Timings ?? TimingPolicy.Default;
        context.SetJarLifetimeCeiling(Within(timings.AuthCodeRequestObjectLifetime, LifetimeFloor, Haip10LifetimeCeiling));
        context.SetRequestUriLifetime(Within(timings.AuthCodeParLifetime, LifetimeFloor, Haip10LifetimeCeiling));
    }


    /// <summary>
    /// Populates the RFC 6749 with PKCE profile, relaxing the redirect issuer, scope,
    /// replay-store and pushed-authorization requirements of <see cref="ApplyFapi20"/>.
    /// PKCE accepts S256 under every profile.
    /// </summary>
    /// <remarks>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-7.5.2">OAuth 2.1 §7.5.2</see>:
    /// "The plain code challenge method, defined in [RFC7636], is explicitly forbidden in OAuth 2.1."
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.4.1">RFC 7636 §4.4.1</see>:
    /// "If the server supporting PKCE does not support the requested transformation, the authorization
    /// endpoint MUST return the authorization error response with "error" value set to "invalid_request"."
    /// The profile holds none of the FAPI 2.0 ceilings: it sets the authorization code lifetime, the
    /// <c>request_uri</c> lifetime and the clock skew from the server's <see cref="TimingPolicy"/> as they are.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 Section 4.1.2</see>: "A maximum
    /// authorization code lifetime of 10 minutes is RECOMMENDED."
    /// </remarks>
    /// <param name="context">The request's exchange context the profile's values are set on.</param>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> is null.</exception>
    public static void ApplyRfc6749WithPkce(ExchangeContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ApplyFapi20(context);
        TimingPolicy timings = context.RequestServer?.OAuth().Timings ?? TimingPolicy.Default;
        context.SetAuthorizationCodeLifetime(timings.AuthorizationCodeLifetime);
        context.SetRequestUriLifetime(timings.AuthCodeParLifetime);
        context.SetClockSkewTolerance(timings.ClockSkewTolerance);
        context.SetEmitIssOnRedirect(false);
        context.SetScopeRequiredOnRequest(false);
        context.SetJtiReplayPolicy(JtiReplayPolicy.OptionalIfStorePresent);
        //RFC 6749 + PKCE has no PAR mandate; allow the direct and JAR-by-value paths.
        context.SetRequirePushedAuthorizationRequests(false);
    }


    /// <summary>
    /// Populates the OID4VP <em>Verifier</em> (presentation) axes. A focused
    /// profile that does NOT layer <see cref="ApplyFapi20"/>: an OID4VP verifier
    /// registration issues the signed Authorization Request and verifies the
    /// returned <c>vp_token</c>, but exposes no token/authorize endpoint, so the
    /// FAPI 2.0 token-endpoint axes (PKCE, token lifetimes, scope-required,
    /// ID Token <c>aud</c>, JTI replay) and the inbound-JAR audience/timing
    /// axes do not apply. The OID4VP verification pipeline reads only the two
    /// KB-JWT timing-leeway axes from the policy bag; this sets exactly those.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="PolicyExchangeContextExtensions.SetClockSkewTolerance"/>: the server's
    /// <see cref="TimingPolicy.ClockSkewTolerance"/>, else 60 seconds, the library's own default,
    /// matching its own 60-second ceilings. <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4">RFC 7519
    /// Section 4.1.4</see> permits "some small leeway, usually no more than a few minutes, to account for clock skew"
    /// and names no number.
    /// </para>
    /// <para>
    /// <see cref="PolicyExchangeContextExtensions.SetKbJwtMaxAgeWindow"/> — 60s.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901</see> requires
    /// the KB-JWT <c>iat</c> to be "within an acceptable window" but pins no
    /// number — it is explicitly the Verifier's policy, because credential
    /// replay/freshness is already guaranteed by the mandatory <c>nonce</c>/<c>aud</c>
    /// binding. 60s is the defense-in-depth window aligned with the library's own
    /// 60-second ceilings; deployments override via a custom <see cref="ResolvePolicyDelegate"/>.
    /// </para>
    /// <para>
    /// JAR/request-object lifetimes for the verifier come from
    /// <see cref="Server.TimingPolicy"/> (<c>Oid4VpRequestObjectLifetime</c> /
    /// <c>Oid4VpRequestUriLifetime</c>), not the policy bag, so they are not set here.
    /// </para>
    /// </remarks>
    public static void ApplyOid4VpVerifier(ExchangeContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        //Single source of truth: derive both presentation timing axes from the
        //deployment's TimingPolicy, falling back to the 60s defaults when no
        //server is on the context (out-of-dispatch / unit-test use).
        TimingPolicy? timings = context.RequestServer?.OAuth().Timings;
        context.SetClockSkewTolerance(timings?.ClockSkewTolerance ?? TimeSpan.FromSeconds(60));
        context.SetKbJwtMaxAgeWindow(timings?.KbJwtIatMaxAge ?? TimeSpan.FromSeconds(60));

        //Data minimization: an OID4VP verifier rejects a presentation that
        //discloses more than the DCQL query asked for. Base OID4VP/SD-JWT VC
        //leave this to the holder, so it is configurable — deployments override
        //via a custom ResolvePolicyDelegate; the verifier profile defaults to
        //enforce.
        context.SetEnforceNoOverDisclosure(true);
    }


    /// <summary>
    /// The library's default <see cref="ResolvePolicyDelegate"/>. Dispatches
    /// on the registration's <c>Profile</c> across the three shipped
    /// profiles via <see cref="PolicyProfile"/> code equality; falls back to
    /// <see cref="ApplyFapi20"/> when the profile is absent or
    /// application-defined (the application's own resolver handles its own
    /// codes; this default is the fail-safe baseline).
    /// </summary>
    public static ValueTask DefaultResolvePolicyAsync(
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        PolicyProfile profile = registration.Profile ?? PolicyProfile.Fapi20;

        if(profile == PolicyProfile.Fapi20)
        {
            ApplyFapi20(context);
        }
        else if(profile == PolicyProfile.Haip10)
        {
            ApplyHaip10(context);
        }
        else if(profile == PolicyProfile.Rfc6749WithPkce)
        {
            ApplyRfc6749WithPkce(context);
        }
        else if(profile == PolicyProfile.Oid4VpVerifier)
        {
            ApplyOid4VpVerifier(context);
        }
        else
        {
            //Unknown custom code — application must supply its own
            //ResolvePolicyDelegate to handle codes it registered via
            //PolicyProfile.Create. Falling back to Fapi20 is fail-safe.
            ApplyFapi20(context);
        }

        return ValueTask.CompletedTask;
    }
}
