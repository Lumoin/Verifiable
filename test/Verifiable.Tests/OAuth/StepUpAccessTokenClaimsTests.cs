using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// RFC 9470 §5 (step-up authentication) / RFC 9068 §2.2.1 — the <c>acr</c> and
/// <c>auth_time</c> authentication-context claims on the JWT <strong>access token</strong>,
/// end-to-end through PAR → Authorize → Token. The application stamps the established
/// authentication-context reference and time on the authorize-time
/// <see cref="ExchangeContext"/> (<c>SetAcr</c> / <c>SetAuthTime</c>), exactly as it
/// stamps <c>SubjectId</c> / <c>SessionId</c>; the values thread through the flow state
/// into the access token so a Resource Server can read the authentication strength
/// actually achieved (RFC 9470 §6.1). Firewalled: the RS reads the claims from the issued
/// token's wire bytes — not a host-side accessor. Asserts the claims are present, equal
/// the stamped values, and are omitted when the deployment stamps no <c>acr</c>.
/// </summary>
[TestClass]
internal sealed class StepUpAccessTokenClaimsTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so issued artefacts are reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://client.example.com";
    private const string SubjectId = "subject-stepup-1";
    private static readonly Uri ClientBaseUri = new("https://client.example.com");
    private static readonly Uri RedirectUri = new("https://client.example.com/callback");

    /// <summary>
    /// An <c>auth_time</c> distinct from the request clock so the assertion proves the
    /// access token carries the <em>stamped</em> authentication instant, not "now".
    /// </summary>
    private static readonly DateTimeOffset StampedAuthTime =
        new(2026, 6, 1, 11, 30, 0, TimeSpan.Zero);


    /// <summary>
    /// The stamped <c>acr</c> appears verbatim as the access token's <c>acr</c> claim,
    /// and the stamped authentication instant appears as <c>auth_time</c>.
    /// </summary>
    [TestMethod]
    public async Task AcrAndAuthTimeEmittedOnAccessTokenFromStampedAuthContext()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse tokenResponse = await DriveCodeExchangeAsync(
            host, material, WellKnownScopes.OpenId,
            acr: "loa-substantial", authTime: StampedAuthTime).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        using JsonDocument payload = ParseAccessTokenPayload(tokenResponse);

        Assert.IsTrue(payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.Acr, out JsonElement acr),
            $"Access token must carry acr when an authentication-context reference was stamped. Body: {tokenResponse.Body}");
        Assert.AreEqual("loa-substantial", acr.GetString());

        Assert.IsTrue(payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.AuthTime, out JsonElement authTime),
            $"Access token must carry auth_time for an End-User authentication. Body: {tokenResponse.Body}");
        Assert.AreEqual(StampedAuthTime.ToUnixTimeSeconds(), authTime.GetInt64(),
            "auth_time must equal the stamped authentication instant, not the request clock.");
    }


    /// <summary>
    /// No <c>acr</c> is stamped → the access token omits the <c>acr</c> claim — <c>acr</c>
    /// is OPTIONAL (RFC 9068 §2.2.1) and present only when the AS established it — while
    /// <c>auth_time</c>, always available for an auth-code End-User authentication, is
    /// still emitted.
    /// </summary>
    [TestMethod]
    public async Task AcrOmittedOnAccessTokenWhenNoAuthContextStamped()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse tokenResponse = await DriveCodeExchangeAsync(
            host, material, WellKnownScopes.OpenId,
            acr: null, authTime: StampedAuthTime).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        using JsonDocument payload = ParseAccessTokenPayload(tokenResponse);

        Assert.IsFalse(payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.Acr, out _),
            "acr must be omitted when the application stamped no authentication-context reference.");
        Assert.IsTrue(payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.AuthTime, out _),
            "auth_time is available for every auth-code End-User authentication and must still be emitted.");
    }


    /// <summary>
    /// The access token's <c>acr</c> is per-authentication: two logins of the same
    /// subject that establish different authentication-context references carry the
    /// respective stamped value on each access token.
    /// </summary>
    [TestMethod]
    public async Task AccessTokenAcrReflectsTheAuthenticationThatIssuedIt()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse low = await DriveCodeExchangeAsync(
            host, material, WellKnownScopes.OpenId,
            acr: "loa-low", authTime: StampedAuthTime).ConfigureAwait(false);
        ServerHttpResponse high = await DriveCodeExchangeAsync(
            host, material, WellKnownScopes.OpenId,
            acr: "loa-substantial", authTime: StampedAuthTime).ConfigureAwait(false);

        using JsonDocument lowPayload = ParseAccessTokenPayload(low);
        using JsonDocument highPayload = ParseAccessTokenPayload(high);

        Assert.AreEqual("loa-low",
            lowPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Acr).GetString());
        Assert.AreEqual("loa-substantial",
            highPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Acr).GetString());
    }


    /// <summary>
    /// RFC 9068 §2.2.1 — the authentication-context claims "remain the same across all
    /// access tokens that derive from a given authorization response ... or after one or
    /// more token exchanges (e.g., ... refreshing an access token)." The refreshed access
    /// token carries the <em>original</em> <c>acr</c> and <c>auth_time</c>, fixed at the
    /// authorize-time authentication — not re-derived from the (later) refresh clock.
    /// </summary>
    [TestMethod]
    public async Task RefreshedAccessTokenCarriesOriginalAcrAndAuthTime()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse tokenResponse = await DriveCodeExchangeAsync(
            host, material, WellKnownScopes.OpenId,
            acr: "loa-substantial", authTime: StampedAuthTime).ConfigureAwait(false);
        string refreshToken = ExtractFromBody(tokenResponse.Body, "refresh_token");

        //Advance the clock so a re-derived auth_time would differ from the stamped one.
        TimeProvider.Advance(TimeSpan.FromMinutes(10));

        ServerHttpResponse refreshResponse = await DispatchRefreshAsync(
            host, material, refreshToken).ConfigureAwait(false);

        Assert.AreEqual(200, refreshResponse.StatusCode, refreshResponse.Body);
        using JsonDocument payload = ParseAccessTokenPayload(refreshResponse);

        Assert.AreEqual("loa-substantial",
            payload.RootElement.GetProperty(WellKnownJwtClaimNames.Acr).GetString(),
            "The refreshed access token must carry the acr established at authorize time.");
        Assert.AreEqual(StampedAuthTime.ToUnixTimeSeconds(),
            payload.RootElement.GetProperty(WellKnownJwtClaimNames.AuthTime).GetInt64(),
            "auth_time must remain fixed across refresh (RFC 9068 §2.2.1), not track the refresh clock.");
    }


    /// <summary>
    /// The authentication-context claims survive refresh-token <em>rotation</em>
    /// (RFC 9700 §2.2.2): a second refresh — exchanging the rotated token — still carries
    /// the original <c>acr</c>/<c>auth_time</c>, proving the rotation path threads them
    /// from the stored refresh state, not only the first issuance.
    /// </summary>
    [TestMethod]
    public async Task AcrAndAuthTimeSurviveRefreshRotation()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse tokenResponse = await DriveCodeExchangeAsync(
            host, material, WellKnownScopes.OpenId,
            acr: "loa-substantial", authTime: StampedAuthTime).ConfigureAwait(false);

        ServerHttpResponse firstRefresh = await DispatchRefreshAsync(
            host, material, ExtractFromBody(tokenResponse.Body, "refresh_token")).ConfigureAwait(false);
        Assert.AreEqual(200, firstRefresh.StatusCode, firstRefresh.Body);

        ServerHttpResponse secondRefresh = await DispatchRefreshAsync(
            host, material, ExtractFromBody(firstRefresh.Body, "refresh_token")).ConfigureAwait(false);
        Assert.AreEqual(200, secondRefresh.StatusCode, secondRefresh.Body);

        using JsonDocument payload = ParseAccessTokenPayload(secondRefresh);
        Assert.AreEqual("loa-substantial",
            payload.RootElement.GetProperty(WellKnownJwtClaimNames.Acr).GetString());
        Assert.AreEqual(StampedAuthTime.ToUnixTimeSeconds(),
            payload.RootElement.GetProperty(WellKnownJwtClaimNames.AuthTime).GetInt64());
    }


    /// <summary>Parses the issued access token's payload from the token response body.</summary>
    private static JsonDocument ParseAccessTokenPayload(ServerHttpResponse tokenResponse)
    {
        using JsonDocument body = JsonDocument.Parse(tokenResponse.Body);
        string accessToken = body.RootElement.GetProperty("access_token").GetString()!;

        return JwtPayloadReader.ParsePayloadJson(accessToken);
    }


    /// <summary>Exchanges a refresh token at the token endpoint for a rotated token set.</summary>
    private async Task<ServerHttpResponse> DispatchRefreshAsync(
        TestHostShell host, VerifierKeyMaterial material, string refreshToken)
    {
        RequestFields refreshFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
            [OAuthRequestParameterNames.RefreshToken] = refreshToken,
            [OAuthRequestParameterNames.ClientId] = ClientId
        };

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken, "POST",
            refreshFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Drives PAR → Authorize → Token, stamping <paramref name="acr"/> (when non-null)
    /// and <paramref name="authTime"/> on the authorize-time context — mirroring the
    /// application's authentication middleware — and returns the token endpoint response.
    /// </summary>
    private async Task<ServerHttpResponse> DriveCodeExchangeAsync(
        TestHostShell host, VerifierKeyMaterial material, string scope,
        string? acr, DateTimeOffset authTime)
    {
        PkceParameters pkce = PkceGeneration.Generate(
            TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = scope
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = ExtractFromBody(parResponse.Body, "request_uri");

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);
        authorizeContext.SetAuthTime(authTime);
        if(acr is not null)
        {
            authorizeContext.SetAcr(acr);
        }

        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode);
        string code = ExtractCode(authorizeResponse.Location!);

        RequestFields tokenFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
        };

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken, "POST",
            tokenFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Reads a string property from a JSON response body.</summary>
    private static string ExtractFromBody(string body, string property)
    {
        using JsonDocument doc = JsonDocument.Parse(body);

        return doc.RootElement.GetProperty(property).GetString()!;
    }


    /// <summary>Extracts the <c>code</c> query parameter from an authorize redirect Location.</summary>
    private static string ExtractCode(string location)
    {
        int q = location.IndexOf('?', StringComparison.Ordinal);
        foreach(string pair in location[(q + 1)..].Split('&'))
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            if(eq > 0 && string.Equals(
                pair[..eq], OAuthRequestParameterNames.Code, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(pair[(eq + 1)..]);
            }
        }

        throw new InvalidOperationException(
            $"Authorize redirect did not carry a code parameter: {location}");
    }
}
