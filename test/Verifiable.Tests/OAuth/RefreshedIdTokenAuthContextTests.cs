using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Oidc;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// OpenID Connect Core 1.0 §12.2 real-wire proving test: a REFRESHED id_token must pin
/// <c>auth_time</c> and <c>acr</c> to the values established at the original End-User
/// authentication — carried across refresh-token rotation via
/// <see cref="Verifiable.OAuth.AuthCode.Server.States.ServerRefreshTokenIssuedState"/> — rather than
/// to whatever the application's <see cref="AuthorizationServerIntegration.ResolveOidcClaimsAsync"/>
/// seam reports at the moment of the refresh call. <see cref="AcrAmrClaimContributor"/> is the seam
/// under test.
/// </summary>
/// <remarks>
/// <para>
/// Drives PAR → Authorize → Token → Refresh against a real Kestrel <see cref="LoopbackTls"/> host.
/// The PAR, token, and refresh legs run over the genuine TLS wire
/// (<see cref="OAuthTestTransport.PostFormAsync(System.Net.Http.HttpClient, Uri, IReadOnlyDictionary{string, string}, System.Threading.CancellationToken)"/>);
/// the authorize leg dispatches in-process on the SAME <see cref="EndpointServer"/> instance the
/// Kestrel host serves (<see cref="TestHostShell.DispatchAtEndpointAsync(string, string, string, RequestFields, ExchangeContext, System.Threading.CancellationToken)"/>)
/// because stamping the authorize-time authentication context (<c>SetAuthTime</c> / <c>SetAcr</c>)
/// has no HTTP-header carrier in <see cref="AuthorizationServerHttpApplication"/> — mirroring the
/// authorize-time stamping pattern <see cref="StepUpAccessTokenClaimsTests"/> uses for the
/// access-token analogue of this same invariant.
/// </para>
/// <para>
/// Non-vacuity: the wired <see cref="AuthorizationServerIntegration.ResolveOidcClaimsAsync"/> returns
/// a DIFFERENT <see cref="AuthenticationContext"/> depending on which call it answers — at the
/// initial authorization_code mint it echoes the established <c>acr</c> and leaves <c>auth_time</c>
/// unpopulated (so the established, stamped values are what the initial id_token actually shows,
/// regardless of which side of the fallback chain the initial mint resolves through); at the refresh
/// redemption it returns a genuinely later <c>auth_time</c>, a different <c>acr</c>, and a populated
/// <c>amr</c> — exactly the values a regression that re-reads the resolver on refresh would stamp
/// onto the refreshed id_token, violating §12.2. The test captures the initial id_token's claims off
/// the wire and asserts the refreshed id_token repeats them exactly.
/// </para>
/// </remarks>
[TestClass]
internal sealed class RefreshedIdTokenAuthContextTests
{
    /// <summary>MSTest's per-test context, supplying the cancellation token every wire call runs under.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock the host and the client share.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://refreshed-id-token.client.test";

    private const string SubjectId = "subject-refreshed-id-token-01";

    private static Uri ClientBaseUri { get; } = new(ClientId);

    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

    /// <summary>
    /// The <c>acr</c>/<c>auth_time</c> the application establishes at the original authorize-time
    /// authentication (<c>SetAuthTime</c>/<c>SetAcr</c>) — the §12.2 "original" the refreshed
    /// id_token must carry.
    /// </summary>
    private static readonly DateTimeOffset EstablishedAuthTime = TestClock.CanonicalEpoch.AddMinutes(-5);

    private const string EstablishedAcr = "urn:example:acr:established-loa";

    /// <summary>
    /// The DIVERGENT authentication context the app's OIDC-claims resolver reports specifically at
    /// refresh-redemption time — genuinely later and differently valued than the established
    /// original, so a regression that re-reads it on refresh produces an observably wrong id_token.
    /// </summary>
    private static readonly DateTimeOffset ResolverRefreshAuthTime = TestClock.CanonicalEpoch.AddHours(3);

    private const string ResolverRefreshAcr = "urn:example:acr:resolver-divergent-loa";

    private static readonly IReadOnlyList<string> ResolverRefreshAmr = ["mfa", "hwk"];


    /// <summary>
    /// Drives authorization_code + PKCE + PAR with <c>openid</c>, decodes the initial id_token,
    /// redeems the refresh token, and asserts the refreshed id_token's <c>auth_time</c> and
    /// <c>acr</c> equal the initial id_token's values — never the resolver's refresh-time divergent
    /// answer — with no <c>nonce</c> and no <c>amr</c> on the refreshed token.
    /// </summary>
    [TestMethod]
    public async Task RefreshedIdTokenPinsAuthTimeAndAcrToOriginalAuthentication()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);
        string segment = material.Registration.TenantId.Value;

        //The resolver answers differently depending on which call it is — see the remarks above for
        //why this is what makes the refresh assertions non-vacuous.
        bool isRefreshCall = false;
        host.Server.OAuth().ResolveOidcClaimsAsync = (subject, grantedScope, tenantId, context, cancellationToken) =>
        {
            AuthenticationContext resolvedAuthContext = isRefreshCall
                ? new AuthenticationContext
                {
                    AuthTime = ResolverRefreshAuthTime,
                    Acr = ResolverRefreshAcr,
                    Amr = ResolverRefreshAmr
                }
                : new AuthenticationContext { Acr = EstablishedAcr };

            return ValueTask.FromResult<OidcClaims?>(new OidcClaims
            {
                Subject = subject,
                AuthContext = resolvedAuthContext
            });
        };

        await host.StartHttpHostAsync(cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");

        //1. PAR over the real wire.
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Uri parUrl = new(
            hosted.HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodePar, segment));
        using HttpResponseMessage parResponse = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, parUrl, new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
                [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
                [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
                [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
            }, TestContext.CancellationToken).ConfigureAwait(false);
        string parBody = await parResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, (int)parResponse.StatusCode, parBody);
        string requestUri = ExtractRequestUri(parBody);

        //2. Authorize — in-process on the SAME EndpointServer the Kestrel host serves; the wire skin
        //   (AuthorizationServerHttpApplication) carries only the test subject header, not
        //   SetAuthTime/SetAcr, over HTTP.
        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);
        authorizeContext.SetAuthTime(EstablishedAuthTime);
        authorizeContext.SetAcr(EstablishedAcr);
        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        string code = TestBrowser.ExtractQueryParam(authorizeResponse.Location!, OAuthRequestParameterNames.Code)
            ?? throw new InvalidOperationException("Authorize redirect Location missing code.");

        //3. Token exchange over the real wire.
        Uri tokenUrl = new(hosted.HttpBaseAddress!, $"/connect/{segment}/token");
        using HttpResponseMessage tokenResponse = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
                [OAuthRequestParameterNames.Code] = code,
                [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
            }, TestContext.CancellationToken).ConfigureAwait(false);
        string tokenBody = await tokenResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)tokenResponse.StatusCode, tokenBody);

        using JsonDocument tokenDoc = JsonDocument.Parse(tokenBody);
        Assert.IsTrue(tokenDoc.RootElement.TryGetProperty(WellKnownTokenTypes.IdToken, out JsonElement initialIdTokenElement),
            $"openid in scope on authorization_code must mint an id_token. Body: {tokenBody}");
        string initialIdToken = initialIdTokenElement.GetString()!;
        string refreshToken = tokenDoc.RootElement.GetProperty(WellKnownTokenTypes.RefreshToken).GetString()!;

        using JsonDocument initialPayload = JwtPayloadDecoding.DecodePayload(initialIdToken, BaseMemoryPool.Shared);
        long tOrig = initialPayload.RootElement.GetProperty(WellKnownJwtClaimNames.AuthTime).GetInt64();
        string subOrig = initialPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Sub).GetString()!;
        string issOrig = initialPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Iss).GetString()!;
        string audOrig = initialPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Aud).GetString()!;
        string acrOrig = initialPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Acr).GetString()!;

        //Sanity: the initial mint actually carried the ESTABLISHED authentication context, not a
        //resolver-supplied one — otherwise the refresh assertions below would be comparing against a
        //value the fix has no obligation to reproduce, and this test would not be proving §12.2.
        Assert.AreEqual(EstablishedAuthTime.ToUnixTimeSeconds(), tOrig,
            "Sanity: the initial id_token's auth_time must be the established authentication instant.");
        Assert.AreEqual(EstablishedAcr, acrOrig,
            "Sanity: the initial id_token's acr must be the established authentication-context reference.");

        //4. Advance the clock and flip the resolver to its refresh-time (divergent) answer — a
        //   regression that re-reads the resolver on refresh would now produce an observably WRONG
        //   id_token.
        TimeProvider.Advance(TimeSpan.FromMinutes(30));
        isRefreshCall = true;

        //5. Refresh over the real wire.
        using HttpResponseMessage refreshResponse = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
                [OAuthRequestParameterNames.RefreshToken] = refreshToken,
                [OAuthRequestParameterNames.ClientId] = ClientId
            }, TestContext.CancellationToken).ConfigureAwait(false);
        string refreshBody = await refreshResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)refreshResponse.StatusCode, refreshBody);

        using JsonDocument refreshDoc = JsonDocument.Parse(refreshBody);
        Assert.IsTrue(refreshDoc.RootElement.TryGetProperty(WellKnownTokenTypes.IdToken, out JsonElement refreshedIdTokenElement),
            $"A refresh token minted alongside an authorization_code grant must still yield an id_token on redemption. Body: {refreshBody}");
        string refreshedIdToken = refreshedIdTokenElement.GetString()!;

        using JsonDocument refreshedPayload = JwtPayloadDecoding.DecodePayload(refreshedIdToken, BaseMemoryPool.Shared);
        JsonElement refreshedClaims = refreshedPayload.RootElement;

        //THE LOAD-BEARING §12.2 ASSERTION: auth_time is pinned to the original authentication, not
        //re-derived from the resolver's later value.
        Assert.AreEqual(tOrig, refreshedClaims.GetProperty(WellKnownJwtClaimNames.AuthTime).GetInt64(),
            "OIDC Core §12.2: a refreshed id_token's auth_time must equal the original authentication "
            + "instant, not the app resolver's value at refresh time.");

        Assert.AreEqual(subOrig, refreshedClaims.GetProperty(WellKnownJwtClaimNames.Sub).GetString(),
            "OIDC Core §12.2: sub must match the original id_token's sub.");
        Assert.AreEqual(issOrig, refreshedClaims.GetProperty(WellKnownJwtClaimNames.Iss).GetString(),
            "OIDC Core §12.2: iss must match the original id_token's iss.");
        Assert.AreEqual(audOrig, refreshedClaims.GetProperty(WellKnownJwtClaimNames.Aud).GetString(),
            "OIDC Core §12.2: aud must include the original id_token's aud.");

        Assert.IsFalse(refreshedClaims.TryGetProperty(WellKnownJwtClaimNames.Nonce, out _),
            "A refresh_token request carries no nonce; the refreshed id_token must not carry one either.");

        Assert.AreEqual(acrOrig, refreshedClaims.GetProperty(WellKnownJwtClaimNames.Acr).GetString(),
            "The refreshed id_token's acr must equal the original (carried) acr, not the resolver's "
            + "divergent refresh-time value.");

        Assert.IsFalse(refreshedClaims.TryGetProperty(WellKnownJwtClaimNames.Amr, out _),
            "amr has no carried representation across refresh rotation; the refreshed id_token must "
            + "not carry the resolver's refresh-time amr.");
    }


    /// <summary>Reads the <c>request_uri</c> from a PAR response body.</summary>
    private static string ExtractRequestUri(string body)
    {
        using JsonDocument doc = JsonDocument.Parse(body);

        return doc.RootElement.GetProperty("request_uri").GetString()!;
    }
}
