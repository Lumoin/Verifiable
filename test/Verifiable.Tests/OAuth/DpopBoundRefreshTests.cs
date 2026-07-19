using System.Linq;
using System.Net.Http;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Real-wire proof that <see cref="AuthCodeFlowHandlers.RefreshAsync(RefreshTokenRequest, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, ClientAssertionOptions?, System.Threading.CancellationToken)"/>
/// carries a DPoP-sender-constrained refresh token through the SAME internal DPoP-retry path the
/// code-exchange leg uses: a fresh proof for <see cref="OAuthClientInfrastructure.DpopKey"/> is attached to the refresh
/// POST and a <c>use_dpop_nonce</c> challenge (RFC 9449 §8.1) is honoured. Before this fix the refresh
/// leg posted through <see cref="OAuthClientInfrastructure.SendFormPostAsync"/> directly, carrying no
/// <c>DPoP</c> header at all, so a DPoP-bound refresh token always drew <c>invalid_dpop_proof</c> from
/// <see cref="Verifiable.OAuth.AuthCode.Server.DpopTokenEndpointValidation"/> (which requires DPoP on
/// the refresh grant whenever the stored <see cref="Verifiable.OAuth.AuthCode.Server.States.ServerRefreshTokenIssuedState.Confirmation"/>
/// is non-empty) — a passing refresh here therefore proves the proof was attached, not that the
/// server never checked.
/// </summary>
[TestClass]
internal sealed class DpopBoundRefreshTests
{
    /// <summary>MSTest's per-test context, supplying the cancellation token every wire call runs under.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock the host and the client share.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://dpop-refresh.client.test";

    private const string SubjectId = "subject-dpop-refresh-01";

    private static Uri ClientBaseUri { get; } = new(ClientId);

    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");


    /// <summary>
    /// A client whose access AND refresh tokens are DPoP-sender-constrained (HAIP 1.0, the profile
    /// <see cref="TestHostShell.RegisterDpopClient"/> requires by default) refreshes THROUGH the real
    /// <see cref="AuthCodeClient.RefreshAsync(ClientRegistration, RefreshTokenRequest, System.Threading.CancellationToken)"/>
    /// entry point and the AS accepts it — no <c>invalid_dpop_proof</c>. The refreshed access token
    /// still carries <c>token_type=DPoP</c> and the SAME <c>cnf.jkt</c> binding the original issuance
    /// established, proving the proof presented on refresh is for the same key.
    /// </summary>
    [TestMethod]
    public async Task DpopSenderConstrainedRefreshTokenRefreshesThroughRealClientAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri);
        host.EnableDpop();

        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        //Step 1 — PAR, over the real wire through the DPoP-wired client.
        AuthCodeFlowEndpointResult parResult = await fixture.Client.AuthCode.StartParAsync(
            fixture.Registration, RedirectUri, OAuthFormEncodedFields.Empty, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"Expected PAR to yield a redirect. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        string flowId = fixture.ClientFlowStore.Keys.Single();
        ParCompletedState parCompleted = (ParCompletedState)fixture.ClientFlowStore[flowId];

        //Step 2 — Authorize, dispatched in-process on the same EndpointServer instance the Kestrel
        //host serves (mirrors DpopEndToEndTests / EndSessionLogoutTests) — the user-agent stand-in
        //authenticates via a pre-set subject on the context rather than a real login UI.
        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = parCompleted.Par.RequestUri.ToString()
        };
        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);

        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value, WellKnownEndpointNames.AuthCodeAuthorize,
            WellKnownHttpMethods.Get, authorizeFields, authorizeContext, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode,
            $"Expected redirect from authorize. Body: {authorizeResponse.Body}");

        string code = TestBrowser.ExtractQueryParam(authorizeResponse.Location!, OAuthRequestParameterNames.Code)
            ?? throw new AssertFailedException($"Authorize redirect missing code. Location: {authorizeResponse.Location}");
        string? iss = TestBrowser.ExtractQueryParam(authorizeResponse.Location!, OAuthRequestParameterNames.Iss);

        //Step 3 — Callback: client-side state transition ready for token exchange.
        Dictionary<string, string> callbackFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.State] = flowId
        };
        if(iss is not null)
        {
            callbackFields[OAuthRequestParameterNames.Iss] = iss;
        }

        AuthCodeFlowEndpointResult callbackResult = await fixture.Client.AuthCode.HandleCallbackAsync(
            fixture.Registration, new OAuthFormEncodedFields(callbackFields), TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, callbackResult.Outcome,
            $"Callback must succeed. ErrorCode={callbackResult.ErrorCode} ErrorDescription={callbackResult.ErrorDescription}");

        //Step 4 — Token, over the real wire. The client has no cached DPoP nonce yet, so the AS
        //challenges once (RFC 9449 §8.1) and the client retries with the echoed nonce.
        AuthCodeFlowEndpointResult tokenResult = await fixture.Client.AuthCode.ExchangeTokenAsync(
            fixture.Registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Expected token issuance success. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");

        string originalAccessToken = (string)tokenResult.Body![OAuthRequestParameterNames.AccessToken];
        string originalRefreshToken = (string)tokenResult.Body![OAuthRequestParameterNames.RefreshToken];
        Assert.IsFalse(string.IsNullOrEmpty(originalRefreshToken), "The initial DPoP-bound issuance must include a refresh_token.");
        Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, (string)tokenResult.Body[OAuthRequestParameterNames.TokenType]!,
            "The initial issuance must be DPoP-bound (token_type=DPoP) for this test to prove anything.");

        //Step 5 — Refresh, over the real wire, through the same real client entry point. Before this
        //fix RefreshAsync posted with no DPoP header at all, and the AS — requiring DPoP on the
        //refresh grant because the stored binding is non-empty — rejected with invalid_dpop_proof.
        RefreshTokenRequest refreshRequest = new()
        {
            ClientId = fixture.Registration.ClientId.Value,
            RefreshToken = originalRefreshToken
        };
        AuthCodeFlowEndpointResult refreshResult = await fixture.Client.AuthCode.RefreshAsync(
            fixture.Registration, refreshRequest, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, refreshResult.Outcome,
            $"Refresh must succeed over the real wire. ErrorCode={refreshResult.ErrorCode} ErrorDescription={refreshResult.ErrorDescription}");

        string newAccessToken = (string)refreshResult.Body![OAuthRequestParameterNames.AccessToken];
        Assert.IsFalse(string.IsNullOrEmpty(newAccessToken), "The AS must mint a fresh access token on refresh.");
        Assert.AreNotEqual(originalAccessToken, newAccessToken,
            "Refresh must issue a fresh access token, not return the original.");
        Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, (string)refreshResult.Body[OAuthRequestParameterNames.TokenType]!,
            "The refreshed access token must remain DPoP-bound (token_type=DPoP).");

        string expectedThumbprint = fixture.DpopKey.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);
        string wireJkt = JwtPayloadReader.ReadCnfJkt(newAccessToken)
            ?? throw new AssertFailedException("The refreshed access-token JWT must carry cnf.jkt under DPoP issuance.");
        Assert.AreEqual(expectedThumbprint, wireJkt,
            "The refreshed access token's cnf.jkt must equal the SAME DPoP key's RFC 7638 thumbprint the refresh proof was built for.");
    }


    /// <summary>
    /// A public client with no DPoP wiring at all (<see cref="OAuthClientInfrastructure.DpopKey"/> and
    /// <see cref="OAuthClientInfrastructure.ConstructDpopProofAsync"/> both <see langword="null"/>)
    /// still refreshes unchanged through the same <see cref="AuthCodeClient.RefreshAsync(ClientRegistration, RefreshTokenRequest, System.Threading.CancellationToken)"/>
    /// entry point — the internal DPoP-retry path falls back to a plain
    /// <see cref="OAuthClientInfrastructure.SendFormPostAsync"/> with no <c>DPoP</c> header when DPoP is
    /// not wired, so routing the refresh leg through it must not regress the Bearer-only path.
    /// </summary>
    [TestMethod]
    public async Task NonDpopClientStillRefreshesThroughRealClientAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration, RedirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId,
            browserClient, scope: WellKnownScopes.OpenId, cancellationToken: TestContext.CancellationToken)
            .ConfigureAwait(false);

        string originalAccessToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.AccessToken];
        string originalRefreshToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.RefreshToken];
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, (string)drive.TokenResult.Body![OAuthRequestParameterNames.TokenType]!,
            "This client is not DPoP-wired — the initial issuance must be a plain Bearer token.");

        RefreshTokenRequest refreshRequest = new()
        {
            ClientId = registration.ClientId.Value,
            RefreshToken = originalRefreshToken
        };
        AuthCodeFlowEndpointResult refreshResult = await AuthCodeFlowDriver.DriveRefreshAsync(
            client, registration, refreshRequest, clientAssertionOptions: null, TestContext.CancellationToken)
            .ConfigureAwait(false);

        string newAccessToken = (string)refreshResult.Body![OAuthRequestParameterNames.AccessToken];
        Assert.AreNotEqual(originalAccessToken, newAccessToken,
            "Refresh must issue a fresh access token, not return the original.");
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, (string)refreshResult.Body[OAuthRequestParameterNames.TokenType]!,
            "Routing the refresh leg through SendTokenRequestWithDpopRetryAsync must not attach a DPoP header for a non-DPoP client.");
    }
}
