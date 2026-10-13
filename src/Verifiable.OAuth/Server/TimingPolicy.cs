using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Deployment defaults for artifact lifetimes and inbound timing tolerances.
/// </summary>
/// <remarks>
/// <para>
/// Every token lifetime default lives here: <see cref="AccessTokenLifetime"/>,
/// <see cref="IdTokenLifetime"/>, <see cref="RefreshTokenLifetime"/> and <see cref="IdJagLifetime"/>.
/// Every site that issues one of those tokens, or states or checks its lifetime, reads it through
/// <see cref="TokenLifetimes.TryResolve"/>: a registration's override
/// (<see cref="ClientRecord.GetTokenLifetime"/>) wins, else the request's policy value of that kind,
/// else this record's value. The first of the three that holds a value for the kind is the lifetime
/// the token is issued with, within the profile's ceilings.
/// </para>
/// <para>
/// The built-in FAPI 2.0 profile (<see cref="PolicyProfiles.ApplyFapi20"/>, and the profiles built
/// on it) derives the request's policy values from this record: the access, ID and refresh token
/// lifetimes, the authorization code lifetime, the pushed <c>request_uri</c> lifetime, the request
/// object lifetime ceiling and the clock skew. It holds the derived authorization code lifetime to
/// at most 60 seconds, the <c>request_uri</c> lifetime to at most 599 seconds and the clock skew to
/// between 10 and 60 seconds, the ceilings of the FAPI 2.0 Security Profile; the RFC 6749 with PKCE
/// profile derives the same three from this record without those ceilings. The HAIP 1.0 profile
/// holds the derived <c>request_uri</c> and request object values to the library's own 60-second
/// ceilings, keeping a shorter value as it is. Key-binding timing derives from this record too. An
/// admitted request retains this immutable record through its captured authorization wiring. A
/// timing alteration affects subsequent admissions.
/// </para>
/// <para>
/// The profiles' ceilings bound the values the profile derives from this record. An application's
/// <see cref="ResolvePolicyDelegate"/> that sets a lifetime on the request after the profile ran owns
/// the value it set: the library issues with it and does not hold it to the profile's ceilings.
/// </para>
/// <para>
/// Every lifetime this record holds is at least one and at most <see cref="int.MaxValue"/> whole
/// seconds, the rule of <see cref="TokenLifetimes.IsIssuable"/>: its <c>init</c> accessor refuses
/// any other value with <see cref="ArgumentOutOfRangeException"/> and holds an issuable value as its
/// whole seconds, the fraction dropped, so every reader issues whole seconds. The clock skew and
/// <see cref="KbJwtIatMaxAge"/> refuse a negative value, and the sender-constraint threshold a value that is not
/// positive.
/// </para>
/// <para>
/// The defaults together with the FAPI 2.0 profile's ceilings are conformant with the timing
/// requirements of FAPI 2.0 and HAIP 1.0: the profile holds the 600-second
/// <see cref="AuthorizationCodeLifetime"/> default to 60 seconds and the clock skew to its window,
/// and the other defaults are within those profiles' bounds as they are. Less demanding profiles
/// can copy <see cref="Default"/> and relax individual entries; more demanding deployments can
/// shorten them.
/// </para>
/// <para>
/// All durations are <see cref="TimeSpan"/> values. The library converts to
/// JWT NumericDate (Unix seconds) at the wire boundary; in-process arithmetic
/// always uses <see cref="TimeSpan"/> against
/// <see cref="System.TimeProvider.GetUtcNow"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("TimingPolicy ClockSkew={ClockSkewTolerance}")]
public sealed record TimingPolicy
{
    /// <summary>
    /// The lifetime of an OID4VP <c>request_uri</c> handle returned by PAR per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see>.
    /// Default 60 seconds, matching the typical
    /// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html">HAIP 1.0</see>
    /// deployment.
    /// </summary>
    /// <remarks>
    /// This is the lifetime of the external token, not of the JAR's <c>exp</c>
    /// claim. The two are distinct values per
    /// <see href="https://darutk.medium.com/implementers-note-about-jar-fff4cbd158fe">Kawasaki, Implementer's note about JAR</see>:
    /// the request URI may be valid for one window while the request object
    /// it dereferences to has its own expiry.
    /// </remarks>
    public TimeSpan Oid4VpRequestUriLifetime { get; init => field = RequireIssuable(value); } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// The lifetime of the OID4VP JAR's <c>exp</c> claim relative to its
    /// <c>iat</c> claim. Default 60 seconds, the library's own ceiling.
    /// </summary>
    public TimeSpan Oid4VpRequestObjectLifetime { get; init => field = RequireIssuable(value); } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// The lifetime of an Authorization Code Pushed Authorization Request handle
    /// per <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see>.
    /// Default 60 seconds. <see cref="PolicyProfiles.ApplyFapi20"/> sets it, at most 599 seconds,
    /// as the request's <c>request_uri</c> lifetime, which the pushed authorization response's
    /// <c>expires_in</c> states; the RFC 6749 with PKCE profile sets it as it is; the HAIP 1.0
    /// profile holds it to the library's own ceiling of 60 seconds.
    /// </summary>
    public TimeSpan AuthCodeParLifetime { get; init => field = RequireIssuable(value); } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// The lifetime of an Authorization Code JAR's <c>exp</c> claim relative to its
    /// <c>iat</c> claim. Default 60 seconds, the library's own ceiling.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="AuthCodeParLifetime"/>: that value is the lifetime of
    /// the external <c>request_uri</c> handle the AS issues, this value is the lifetime
    /// of the signed Request Object the client pushes. RFC 9101 leaves the JAR
    /// lifetime profile-defined; the library sets 60 seconds as its own ceiling.
    /// <see cref="PolicyProfiles.ApplyFapi20"/> sets it as the request's request object lifetime
    /// ceiling: a Request Object whose <c>exp</c> lies further than this after its <c>iat</c> or
    /// <c>nbf</c> is refused <c>invalid_request_object</c>. The HAIP 1.0 profile holds it to the
    /// library's own ceiling of 60 seconds.
    /// </remarks>
    public TimeSpan AuthCodeRequestObjectLifetime { get; init => field = RequireIssuable(value); } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// The lifetime of an OAuth 2.0 authorization code per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>,
    /// which recommends a maximum of 10 minutes. Default 600 seconds.
    /// <see cref="PolicyProfiles.ApplyFapi20"/> sets it, at most 60 seconds, as the request's
    /// authorization code lifetime, the stored expiry of every code the authorization endpoint
    /// issues; the RFC 6749 with PKCE profile sets it as it is, and a request no built-in profile
    /// ran on reads it as it is.
    /// </summary>
    public TimeSpan AuthorizationCodeLifetime { get; init => field = RequireIssuable(value); } = TimeSpan.FromSeconds(600);

    /// <summary>
    /// The default lifetime of an RFC 9068 access token when the client
    /// registration does not specify a per-registration override via
    /// <see cref="ClientRecord.GetTokenLifetime"/> and the request's policy sets none.
    /// Default 1 hour. The access-token producer and the long-lived Credential token guard read
    /// it through <see cref="TokenLifetimes.TryResolve"/>.
    /// </summary>
    public TimeSpan AccessTokenLifetime { get; init => field = RequireIssuable(value); } = TimeSpan.FromHours(1);

    /// <summary>
    /// The default lifetime of an OIDC 1.0 ID token when the client registration
    /// does not specify a per-registration override via
    /// <see cref="ClientRecord.GetTokenLifetime"/> and the request's policy sets none.
    /// Default 1 hour. The ID Token producer reads it through <see cref="TokenLifetimes.TryResolve"/>.
    /// </summary>
    public TimeSpan IdTokenLifetime { get; init => field = RequireIssuable(value); } = TimeSpan.FromHours(1);

    /// <summary>
    /// The default lifetime of a refresh token when the client registration does not specify a
    /// per-registration override via <see cref="ClientRecord.GetTokenLifetime"/> and the request's
    /// policy sets none. Default 30 days. The code grant, the token exchange and the refresh
    /// grant's rotation read it through <see cref="TokenLifetimes.TryResolve"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-1.5">RFC 6749 Section 1.5</see>:
    /// "Refresh tokens are credentials used to obtain access tokens." and "Unlike access tokens,
    /// refresh tokens are intended for use only with authorization servers and are never sent to
    /// resource servers." <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 Section 6</see>:
    /// "Because refresh tokens are typically long-lasting credentials used to request additional
    /// access tokens, the refresh token is bound to the client to which it was issued." The value
    /// sets both the stored expiry of an issued refresh token and the <c>expires_in</c> a token
    /// exchange answers for one.
    /// </remarks>
    public TimeSpan RefreshTokenLifetime { get; init => field = RequireIssuable(value); } = TimeSpan.FromDays(30);

    /// <summary>
    /// The default lifetime of an Identity Assertion JWT Authorization Grant when the client
    /// registration does not specify a per-registration override via
    /// <see cref="ClientRecord.GetTokenLifetime"/>. Default 5 minutes. The ID-JAG mint reads it
    /// through <see cref="TokenLifetimes.TryResolve"/>; the grant has no policy value of its own.
    /// </summary>
    /// <remarks>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.3.4">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 4.3.4</see>:
    /// "expires_in:  RECOMMENDED - The lifetime in seconds of the authorization grant." The draft's
    /// response example answers <c>"expires_in": 300</c>, the default here. The grant is presented
    /// once at the Resource Authorization Server and is not stored, so it is short-lived.
    /// </remarks>
    public TimeSpan IdJagLifetime { get; init => field = RequireIssuable(value); } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The default lifetime of an OpenID Federation 1.0 Entity Configuration
    /// JWT (the body of <c>/.well-known/openid-federation</c>). Default 1 hour.
    /// </summary>
    /// <remarks>
    /// Federation deployments typically pick lifetimes from minutes (frequent
    /// key rotation) to hours (longer cache); 1 hour is a conservative middle
    /// ground for the library default. Per-tenant overrides can come from the
    /// application's <see cref="AuthorizationServerIntegration.ContributeFederationMetadataAsync"/>
    /// delegate when richer policy is required.
    /// </remarks>
    public TimeSpan FederationEntityConfigurationLifetime { get; init => field = RequireIssuable(value); } = TimeSpan.FromHours(1);

    /// <summary>
    /// The OID4VCI 1.0 §13.10 threshold above which an Access Token giving access to
    /// Credentials is "long lived" and therefore MUST NOT be issued as a plain bearer token —
    /// it must be sender-constrained (DPoP / <c>cnf.jkt</c>). Default 5 minutes.
    /// </summary>
    /// <remarks>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-13.10">OID4VCI 1.0 §13.10</see>:
    /// "Long-lived Access Tokens giving access to Credentials MUST not be issued unless
    /// sender-constrained. Access Tokens with lifetimes longer than 5 minutes are, in general,
    /// considered long lived." The library enforces this fail-closed at the OID4VCI token
    /// endpoints: when the access token the request would mint outlives this threshold and is
    /// not sender-constrained, the request is refused rather than a long-lived bearer Credential
    /// token issued. A deployment that wants a different "long lived" boundary shortens or
    /// lengthens this value; the spec's number is the default. The value is positive: its
    /// <c>init</c> accessor refuses zero or a negative value with
    /// <see cref="ArgumentOutOfRangeException"/>. A threshold above the access-token lifetime
    /// the token is issued with disables the refusal for that token.
    /// </remarks>
    public TimeSpan CredentialAccessTokenSenderConstraintThreshold { get; init => field = RequirePositive(value); } = TimeSpan.FromMinutes(5);


    /// <summary>
    /// The clock-skew tolerance applied when validating <c>nbf</c>, <c>iat</c>,
    /// and <c>exp</c> claims on inbound JWTs. Default 60 seconds.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both directions: a JAR observed before its <c>nbf</c> is accepted if
    /// the interval is within <see cref="ClockSkewTolerance"/>; a JAR observed
    /// after its <c>exp</c> is accepted if the interval is within
    /// <see cref="ClockSkewTolerance"/>. Validators that consume timing claims
    /// — wallet-side JAR validation, server-side request-object validation,
    /// token validation — read this value rather than embedding their own.
    /// </para>
    /// <para>
    /// 60 seconds matches
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4">RFC 7519 §4.1.4</see>'s
    /// guidance to allow for "a small leeway" and is consistent with FAPI
    /// deployments that combine RFC 9068 access tokens with strict request-
    /// object lifetime checks.
    /// </para>
    /// <para>
    /// <see cref="PolicyProfiles.ApplyFapi20"/> sets it on the request held within 10 and 60
    /// seconds (<see href="https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1">FAPI 2.0
    /// Security Profile Section 5.3.2.1</see> item 13: "to accommodate clock offsets, shall accept
    /// JWTs with an iat or nbf timestamp between 0 and 10 seconds in the future but shall reject JWTs
    /// with an iat or nbf timestamp greater than 60 seconds in the future. See Note 3 for further
    /// details and rationale; and"); the RFC 6749 with PKCE profile sets it as it is. The value is
    /// zero or positive: its <c>init</c> accessor refuses a negative value with
    /// <see cref="ArgumentOutOfRangeException"/>, and zero is a strict deployment's choice.
    /// </para>
    /// </remarks>
    public TimeSpan ClockSkewTolerance { get; init => field = RequireNotNegative(value); } = TimeSpan.FromSeconds(60);


    /// <summary>
    /// Maximum acceptable age of an SD-JWT/SD-CWT Key Binding Token <c>iat</c> —
    /// the holder proof-of-possession freshness window. Default 60 seconds.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The single source of truth for the OID4VP verifier's KB-JWT <c>iat</c>
    /// freshness check: <c>PolicyProfiles.ApplyOid4VpVerifier</c> derives the
    /// per-flow <c>KbJwtMaxAgeWindow</c> policy value from this, which
    /// <c>ValidationChecks.CheckKbJwtIatNotTooOld</c> reads.
    /// </para>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901</see> requires
    /// the KB-JWT <c>iat</c> to be "within an acceptable window" but pins no
    /// number — it is explicitly the Verifier's policy, because credential
    /// replay/freshness is already guaranteed by the mandatory <c>nonce</c>/
    /// <c>aud</c> binding. 60 seconds is the defense-in-depth default aligned
    /// with <see cref="ClockSkewTolerance"/> and the library's own 60-second ceilings.
    /// </para>
    /// <para>
    /// The value is zero or positive: its <c>init</c> accessor refuses a negative value with
    /// <see cref="ArgumentOutOfRangeException"/>.
    /// </para>
    /// </remarks>
    public TimeSpan KbJwtIatMaxAge { get; init => field = RequireNotNegative(value); } = TimeSpan.FromSeconds(60);


    /// <summary>
    /// The library default policy. HAIP 1.0 / FAPI 2.0 aligned. Suitable as a
    /// starting point for any deployment; copy and modify individual entries
    /// when a specific profile demands different values.
    /// </summary>
    public static TimingPolicy Default { get; } = new();


    /// <summary>
    /// Refuses a lifetime that is not issuable by the one rule of <see cref="TokenLifetimes.IsIssuable"/>: its whole
    /// seconds are under one, so an artifact issued with it would be born expired, or above
    /// <see cref="int.MaxValue"/>, more than the library writes in a response's 32-bit <c>expires_in</c>. The rule is
    /// the library's own: it writes <c>iat</c>, <c>exp</c> and <c>expires_in</c> in whole seconds. The value is the
    /// deployment's own argument, so the refusal throws. An issuable value is held as its whole seconds, the lifetime
    /// the rule answers, so every reader of the record, the token resolution and the direct readers alike, issues whole
    /// seconds, and an inbound comparison against a stored lifetime, such as the request object ceiling, compares
    /// against those whole seconds.
    /// </summary>
    /// <param name="value">The lifetime an <c>init</c> accessor receives.</param>
    /// <returns>The whole seconds of <paramref name="value"/> when it is issuable.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The whole seconds of <paramref name="value"/> are under one or above <see cref="int.MaxValue"/>.
    /// </exception>
    private static TimeSpan RequireIssuable(TimeSpan value)
    {
        if(!TokenLifetimes.IsIssuable(value, out TimeSpan lifetime))
        {
            throw new ArgumentOutOfRangeException(
                nameof(value), value, "A lifetime is at least one and at most int.MaxValue whole seconds.");
        }

        return lifetime;
    }


    /// <summary>
    /// Refuses a tolerance that is negative: a negative clock skew or key binding age would refuse every fresh JWT.
    /// Zero is accepted, the choice of a strict deployment. The value is the deployment's own argument, so the refusal
    /// throws.
    /// </summary>
    /// <param name="value">The tolerance an <c>init</c> accessor receives.</param>
    /// <returns><paramref name="value"/> when it is zero or positive.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="value"/> is negative.</exception>
    private static TimeSpan RequireNotNegative(TimeSpan value)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero);

        return value;
    }


    /// <summary>
    /// Refuses a threshold that is not positive: a threshold of zero or less would call every access token long
    /// lived. The value is the deployment's own argument, so the refusal throws.
    /// </summary>
    /// <param name="value">The threshold an <c>init</c> accessor receives.</param>
    /// <returns><paramref name="value"/> when it is positive.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="value"/> is zero or negative.</exception>
    private static TimeSpan RequirePositive(TimeSpan value)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(value, TimeSpan.Zero);

        return value;
    }
}
