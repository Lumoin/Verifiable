using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
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
    /// <see cref="TestHostShell.RegisterDpopClientAsync"/> requires by default) refreshes THROUGH the real
    /// <see cref="AuthCodeClient.RefreshAsync(ClientRegistration, RefreshTokenRequest, System.Threading.CancellationToken)"/>
    /// entry point and the AS accepts it — no <c>invalid_dpop_proof</c>. The refreshed access token
    /// still carries <c>token_type=DPoP</c> and the SAME <c>cnf.jkt</c> binding the original issuance
    /// established, proving the proof presented on refresh is for the same key.
    /// </summary>
    [TestMethod]
    public async Task DpopSenderConstrainedRefreshTokenRefreshesThroughRealClientAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        //Step 1 — PAR, over the real wire through the DPoP-wired client.
        AuthCodeFlowEndpointResult parResult = await fixture.Client.AuthCode.StartParAsync(
            fixture.Registration, RedirectUri, OAuthFormEncodedFieldsFixtures.OpenIdScope, TestContext.CancellationToken)
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
        ExchangeContext authorizeContext = [];
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
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 Section 5</see>: "If the access token
    /// response contains a different token_type value than DPoP, the access token protection provided by DPoP is not
    /// given. The client MUST discard the response in this case if this protection is deemed important for the
    /// security of the application". A DPoP-wired client drives its authorization request and its callback over the
    /// wire and redeems the code for a DPoP access token and a refresh token; it then refreshes, and the listener emits
    /// the 200 answering the refresh request with its <c>token_type</c> naming <c>Bearer</c>. The client answers
    /// <c>invalid_response</c> naming <c>token_type</c> and surfaces no access token.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ClientDiscardsARefreshAnsweredWithAnotherTokenTypeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
            host.Host("default"), fixture.Client, fixture.Registration, fixture.ClientFlowStore, segment, RedirectUri, SubjectId,
            browserClient, scope: WellKnownScopes.OpenId, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        AuthCodeFlowEndpointResult tokenResult = await fixture.Client.AuthCode.ExchangeTokenAsync(
            fixture.Registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
        Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, (string)tokenResult.Body![OAuthRequestParameterNames.TokenType]);
        string refreshToken = (string)tokenResult.Body[OAuthRequestParameterNames.RefreshToken];

        List<(string Path, int StatusCode, string BodyBefore, string BodyAfter)> rewrittenAnswers = host.RewriteAnswerBody(
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment), 1,
            static body => TestHostShell.RewriteTokenTypeMember(body, WellKnownAuthenticationSchemes.Bearer));
        AuthCodeFlowEndpointResult refreshResult = await fixture.Client.AuthCode.RefreshAsync(
            fixture.Registration,
            new RefreshTokenRequest { ClientId = fixture.Registration.ClientId.Value, RefreshToken = refreshToken },
            TestContext.CancellationToken).ConfigureAwait(false);

        (_, int statusCode, string bodyBefore, string bodyAfter) = Assert.ContainsSingle(rewrittenAnswers,
            "The listener emitted one answer with a body other than the library's.");
        Assert.AreEqual(200, statusCode, "The altered answer is the refresh's 200.");
        Assert.Contains(TestHostShell.DpopTokenTypeMember, bodyBefore, StringComparison.Ordinal, bodyBefore);
        Assert.Contains("\"token_type\":\"Bearer\"", bodyAfter, StringComparison.Ordinal, bodyAfter);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, refreshResult.Outcome,
            $"ErrorCode={refreshResult.ErrorCode} ErrorDescription={refreshResult.ErrorDescription}");
        Assert.AreEqual("invalid_response", refreshResult.ErrorCode);
        Assert.AreEqual(
            "token_type: The token response to a request that carried a DPoP proof names a token_type other than DPoP.",
            refreshResult.ErrorDescription);
        Assert.IsNull(refreshResult.Body, "No access token is surfaced.");
    }


    /// <summary>
    /// Forces the RFC 9449 §8.1 <c>use_dpop_nonce</c> retry branch to fire on the REFRESH leg
    /// itself, not merely at token exchange. The nonce
    /// <see cref="DpopSenderConstrainedRefreshTokenRefreshesThroughRealClientAsync"/> caches during
    /// its exchange leg is still inside <see cref="WellKnownDpopValues.DefaultNonceValidityWindow"/>
    /// at refresh time under a non-advancing clock, so that test can pass whether or not
    /// <see cref="AuthCodeFlowHandlers.RefreshAsync(RefreshTokenRequest, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, ClientAssertionOptions?, System.Threading.CancellationToken)"/>
    /// actually retries on the refresh POST — it never has to. Advancing <see cref="TimeProvider"/>
    /// past the nonce's validity window between the two legs expires the cached nonce, so the first
    /// refresh attempt draws a fresh <c>400 error=use_dpop_nonce</c> challenge from
    /// <see cref="Verifiable.OAuth.AuthCode.Server.DpopTokenEndpointValidation"/> and only a working
    /// retry lets the refresh succeed at all.
    /// </summary>
    [TestMethod]
    public async Task DpopBoundRefreshRetriesOnUseDpopNonceChallengeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        //Step 1 — PAR, over the real wire through the DPoP-wired client.
        AuthCodeFlowEndpointResult parResult = await fixture.Client.AuthCode.StartParAsync(
            fixture.Registration, RedirectUri, OAuthFormEncodedFieldsFixtures.OpenIdScope, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"Expected PAR to yield a redirect. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        string flowId = fixture.ClientFlowStore.Keys.Single();
        ParCompletedState parCompleted = (ParCompletedState)fixture.ClientFlowStore[flowId];

        //Step 2 — Authorize, dispatched in-process on the same EndpointServer instance the Kestrel
        //host serves, exactly as the exchange-leg test above.
        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = parCompleted.Par.RequestUri.ToString()
        };
        ExchangeContext authorizeContext = [];
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
        //challenges once (RFC 9449 §8.1) and the client retries with the echoed nonce — the SAME
        //nonce that must be neutralised below before it can prove anything about the refresh leg.
        AuthCodeFlowEndpointResult tokenResult = await fixture.Client.AuthCode.ExchangeTokenAsync(
            fixture.Registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Expected token issuance success. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");

        string originalAccessToken = (string)tokenResult.Body![OAuthRequestParameterNames.AccessToken];
        string originalRefreshToken = (string)tokenResult.Body![OAuthRequestParameterNames.RefreshToken];
        Assert.IsFalse(string.IsNullOrEmpty(originalRefreshToken), "The initial DPoP-bound issuance must include a refresh_token.");

        //Confirm the exchange leg actually left a nonce cached for the token endpoint (its scheme,
        //authority and path); otherwise expiring it below would prove nothing about a genuine retry.
        string nonceEndpoint = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, material.Registration.TenantId.Value)
            .GetLeftPart(UriPartial.Path);
        Assert.IsNotNull(fixture.NonceCache.Lookup(nonceEndpoint),
            "Token exchange must have cached a DPoP nonce for the token endpoint before the refresh leg runs.");

        //Advance the shared clock (client and server alike) past the nonce's validity window. The
        //client still attaches the cached nonce on its first refresh attempt — LookupDpopNonce still
        //returns it — but the server's issuedAt check now rejects it, forcing a fresh
        //use_dpop_nonce challenge on the refresh POST specifically.
        TimeProvider.Advance(WellKnownDpopValues.DefaultNonceValidityWindow + TimeSpan.FromSeconds(1));

        //Step 5 — Refresh, over the real wire. If SendTokenRequestWithDpopRetryAsync's retry did not
        //fire on this leg, the first (and only) attempt would fail with use_dpop_nonce and this
        //assertion would fail outright.
        RefreshTokenRequest refreshRequest = new()
        {
            ClientId = fixture.Registration.ClientId.Value,
            RefreshToken = originalRefreshToken
        };
        AuthCodeFlowEndpointResult refreshResult = await fixture.Client.AuthCode.RefreshAsync(
            fixture.Registration, refreshRequest, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, refreshResult.Outcome,
            $"Refresh must succeed by retrying past the expired-nonce challenge on the refresh leg itself. ErrorCode={refreshResult.ErrorCode} ErrorDescription={refreshResult.ErrorDescription}");

        string newAccessToken = (string)refreshResult.Body![OAuthRequestParameterNames.AccessToken];
        Assert.IsFalse(string.IsNullOrEmpty(newAccessToken), "The AS must mint a fresh access token on refresh.");
        Assert.AreNotEqual(originalAccessToken, newAccessToken,
            "Refresh must issue a fresh access token, not return the original.");
        Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, (string)refreshResult.Body[OAuthRequestParameterNames.TokenType]!,
            "The refreshed access token must remain DPoP-bound (token_type=DPoP) after the nonce-retry round trip.");

        string expectedThumbprint = fixture.DpopKey.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);
        string wireJkt = JwtPayloadReader.ReadCnfJkt(newAccessToken)
            ?? throw new AssertFailedException("The refreshed access-token JWT must carry cnf.jkt under DPoP issuance.");
        Assert.AreEqual(expectedThumbprint, wireJkt,
            "The refreshed access token's cnf.jkt must equal the SAME DPoP key's RFC 7638 thumbprint the retried refresh proof was built for.");
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

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


    /// <summary>
    /// A VALID reuse presentation of a DPoP-bound rotated-out refresh token — the proof matches
    /// the retired token's own stored thumbprint, exactly as a live rotation would present it —
    /// exercises the DPoP branch of
    /// <c>AuthCodeEndpoints.HandleRefreshTokenReuseAsync</c> and
    /// revokes the current successor, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2">RFC 9700 §4.14.2</see>.
    /// Both the rotation and the reuse are driven through the same real
    /// <see cref="AuthCodeClient.RefreshAsync(ClientRegistration, RefreshTokenRequest, System.Threading.CancellationToken)"/>
    /// entry point with the SAME <see cref="OAuthClientInfrastructure.DpopKey"/>, so the reuse proof
    /// is cryptographically the legitimate client's own — the scenario this branch exists to detect
    /// (a stolen refresh token replayed by whoever holds it, key included).
    /// </summary>
    [TestMethod]
    public async Task DpopSenderConstrainedReuseWithMatchingProofRevokesTheSuccessorAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult parResult = await fixture.Client.AuthCode.StartParAsync(
            fixture.Registration, RedirectUri, OAuthFormEncodedFieldsFixtures.OpenIdScope, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"Expected PAR to yield a redirect. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        string flowId = fixture.ClientFlowStore.Keys.Single();
        ParCompletedState parCompleted = (ParCompletedState)fixture.ClientFlowStore[flowId];

        HostedAuthorizationServer hosted = host.Host("default");
        Uri authorizeUri = new(hosted.HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, material.Registration.TenantId.Value)
            + "?client_id=" + Uri.EscapeDataString(ClientId)
            + "&request_uri=" + Uri.EscapeDataString(parCompleted.Par.RequestUri.ToString()));
        using HttpResponseMessage authorizeResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, authorizeUri, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, (int)authorizeResponse.StatusCode);
        string location = authorizeResponse.Headers.Location!.OriginalString;
        string code = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Code)
            ?? throw new AssertFailedException("Authorize redirect missing code.");
        string? iss = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Iss);

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

        AuthCodeFlowEndpointResult tokenResult = await fixture.Client.AuthCode.ExchangeTokenAsync(
            fixture.Registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Expected token issuance success. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
        string originalRefreshToken = (string)tokenResult.Body![OAuthRequestParameterNames.RefreshToken];

        //A single legitimate, DPoP-proved rotation.
        RefreshTokenRequest rotateRequest = new()
        {
            ClientId = fixture.Registration.ClientId.Value,
            RefreshToken = originalRefreshToken
        };
        AuthCodeFlowEndpointResult rotation = await fixture.Client.AuthCode.RefreshAsync(
            fixture.Registration, rotateRequest, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, rotation.Outcome,
            $"The DPoP-proved rotation must succeed. ErrorCode={rotation.ErrorCode}");
        string successorRefreshToken = (string)rotation.Body![OAuthRequestParameterNames.RefreshToken];

        //A VALID reuse of the just-retired token, presented with a fresh proof from the SAME key —
        //the retired token's own stored thumbprint matches, so this exercises the DPoP branch of
        //HandleRefreshTokenReuseAsync rather than short-circuiting past it.
        RefreshTokenRequest reuseRequest = new()
        {
            ClientId = fixture.Registration.ClientId.Value,
            RefreshToken = originalRefreshToken
        };
        AuthCodeFlowEndpointResult reuse = await fixture.Client.AuthCode.RefreshAsync(
            fixture.Registration, reuseRequest, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Ok, reuse.Outcome,
            "A rotated-out refresh token must never be honoured, DPoP-bound or not.");
        Assert.AreEqual(OAuthErrors.InvalidGrant, reuse.ErrorCode);

        //The successor must now be refused too — the family was revoked.
        RefreshTokenRequest successorRequest = new()
        {
            ClientId = fixture.Registration.ClientId.Value,
            RefreshToken = successorRefreshToken
        };
        AuthCodeFlowEndpointResult successorAfterReuse = await fixture.Client.AuthCode.RefreshAsync(
            fixture.Registration, successorRequest, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Ok, successorAfterReuse.Outcome,
            "A VALID DPoP-proved reuse must revoke the successor of the same grant family.");
        Assert.AreEqual(OAuthErrors.InvalidGrant, successorAfterReuse.ErrorCode);
    }


    /// <summary>
    /// The mirror of
    /// <see cref="DpopSenderConstrainedReuseWithMatchingProofRevokesTheSuccessorAsync"/>: reuse of a
    /// DPoP-bound rotated-out refresh token presented with a proof from a DIFFERENT key is an
    /// INVALID presentation — the same denial-of-service reasoning
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1 draft-16
    /// §7.5.3</see> applies to a code replay applies here — and revokes nothing. A raw wire push
    /// carries the mismatched proof, since no real client entry point would ever sign with a key
    /// other than the one <see cref="ClientRegistration"/> is holding.
    /// </summary>
    [TestMethod]
    public async Task DpopSenderConstrainedReuseWithMismatchedProofLeavesSuccessorUsableAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult parResult = await fixture.Client.AuthCode.StartParAsync(
            fixture.Registration, RedirectUri, OAuthFormEncodedFieldsFixtures.OpenIdScope, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"Expected PAR to yield a redirect. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        string flowId = fixture.ClientFlowStore.Keys.Single();
        ParCompletedState parCompleted = (ParCompletedState)fixture.ClientFlowStore[flowId];

        HostedAuthorizationServer hosted = host.Host("default");
        Uri authorizeUri = new(hosted.HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, material.Registration.TenantId.Value)
            + "?client_id=" + Uri.EscapeDataString(ClientId)
            + "&request_uri=" + Uri.EscapeDataString(parCompleted.Par.RequestUri.ToString()));
        using HttpResponseMessage authorizeResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, authorizeUri, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, (int)authorizeResponse.StatusCode);
        string location = authorizeResponse.Headers.Location!.OriginalString;
        string code = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Code)
            ?? throw new AssertFailedException("Authorize redirect missing code.");
        string? iss = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Iss);

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

        AuthCodeFlowEndpointResult tokenResult = await fixture.Client.AuthCode.ExchangeTokenAsync(
            fixture.Registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Expected token issuance success. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
        string originalRefreshToken = (string)tokenResult.Body![OAuthRequestParameterNames.RefreshToken];

        //A single legitimate, DPoP-proved rotation.
        RefreshTokenRequest rotateRequest = new()
        {
            ClientId = fixture.Registration.ClientId.Value,
            RefreshToken = originalRefreshToken
        };
        AuthCodeFlowEndpointResult rotation = await fixture.Client.AuthCode.RefreshAsync(
            fixture.Registration, rotateRequest, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, rotation.Outcome,
            $"The DPoP-proved rotation must succeed. ErrorCode={rotation.ErrorCode}");
        string successorRefreshToken = (string)rotation.Body![OAuthRequestParameterNames.RefreshToken];

        //An INVALID reuse: the correct client_id and refresh token, but a proof signed by an
        //UNRELATED key — a raw wire push, since no client entry point would ever attach one. The
        //proof carries a currently-valid nonce (the one the legitimate rotation above already
        //obtained and cached) rather than none at all: DpopTokenEndpointValidation checks the
        //bound thumbprint BEFORE the nonce, so an otherwise well-formed proof isolates that
        //thumbprint check — without a valid nonce, removing the thumbprint check would still fail
        //this request for the UNRELATED reason of a missing nonce, and the test would not notice
        //the thumbprint check being gone.
        var attackerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey attackerKey = new(attackerKeys, WellKnownJwaValues.Es256);
            string segment = material.Registration.TenantId.Value;
            Uri tokenEndpoint = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);

            string nonceEndpoint = tokenEndpoint.GetLeftPart(UriPartial.Path);
            string validNonce = fixture.NonceCache.Lookup(nonceEndpoint)
                ?? throw new AssertFailedException(
                    "Expected a DPoP nonce cached by the legitimate rotation above.");

            string mismatchedProof = await DpopProofConstruction.BuildAsync(
                new DpopProofClaims
                {
                    Htm = WellKnownHttpMethods.Post,
                    Htu = tokenEndpoint.OriginalString,
                    Iat = TimeProvider.GetUtcNow(),
                    Jti = Guid.NewGuid().ToString("N"),
                    Nonce = validNonce
                },
                attackerKey,
                TestHostShell.Base64UrlEncoder,
                DpopTestSupport.Serializer,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async,
                TestHostShell.MemoryPool,
                TestContext.CancellationToken).ConfigureAwait(false);

            (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment,
                RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, originalRefreshToken),
                OutgoingHeaders.Empty.WithDpop(mismatchedProof),
                TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, StatusCode, Body);
            Assert.Contains(OAuthErrors.InvalidGrant, Body, StringComparison.Ordinal);
        }
        finally
        {
            attackerKeys.PublicKey.Dispose();
            attackerKeys.PrivateKey.Dispose();
        }

        //The successor must remain usable — the mismatched-key reuse presentation revoked nothing.
        RefreshTokenRequest successorRequest = new()
        {
            ClientId = fixture.Registration.ClientId.Value,
            RefreshToken = successorRefreshToken
        };
        AuthCodeFlowEndpointResult successorAfterReuse = await fixture.Client.AuthCode.RefreshAsync(
            fixture.Registration, successorRequest, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, successorAfterReuse.Outcome,
            $"An INVALID (mismatched-key) reuse presentation must revoke nothing. ErrorCode={successorAfterReuse.ErrorCode}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>'s
    /// invalid_grant response covers a retired refresh token. Issuer-resolution failure during
    /// a valid DPoP-bound reuse preserves the unknown-token response bytes and revokes nothing.
    /// </summary>
    [TestMethod]
    public async Task ReuseIssuerResolutionFailureHasTheUnknownTokenBody()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult parResult = await fixture.Client.AuthCode.StartParAsync(
            fixture.Registration, RedirectUri, OAuthFormEncodedFieldsFixtures.OpenIdScope, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"Expected PAR to yield a redirect. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        string flowId = fixture.ClientFlowStore.Keys.Single();
        ParCompletedState parCompleted = (ParCompletedState)fixture.ClientFlowStore[flowId];

        HostedAuthorizationServer hosted = host.Host("default");
        Uri authorizeUri = new(hosted.HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, material.Registration.TenantId.Value)
            + "?client_id=" + Uri.EscapeDataString(ClientId)
            + "&request_uri=" + Uri.EscapeDataString(parCompleted.Par.RequestUri.ToString()));
        using HttpResponseMessage authorizeResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, authorizeUri, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, (int)authorizeResponse.StatusCode);
        string location = authorizeResponse.Headers.Location!.OriginalString;
        string code = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Code)
            ?? throw new AssertFailedException("Authorize redirect missing code.");
        string? iss = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Iss);

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

        AuthCodeFlowEndpointResult tokenResult = await fixture.Client.AuthCode.ExchangeTokenAsync(
            fixture.Registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Expected token issuance success. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
        string originalRefreshToken = (string)tokenResult.Body![OAuthRequestParameterNames.RefreshToken];

        //A single legitimate, DPoP-proved rotation.
        RefreshTokenRequest rotateRequest = new()
        {
            ClientId = fixture.Registration.ClientId.Value,
            RefreshToken = originalRefreshToken
        };
        AuthCodeFlowEndpointResult rotation = await fixture.Client.AuthCode.RefreshAsync(
            fixture.Registration, rotateRequest, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, rotation.Outcome,
            $"The DPoP-proved rotation must succeed. ErrorCode={rotation.ErrorCode}");
        string successorRefreshToken = (string)rotation.Body![OAuthRequestParameterNames.RefreshToken];

        string segment = material.Registration.TenantId.Value;
        string nonceEndpoint = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment).GetLeftPart(UriPartial.Path);
        string proof = await DpopProofConstruction.BuildAsync(
            new DpopProofClaims
            {
                Htm = WellKnownHttpMethods.Post,
                Htu = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment).OriginalString,
                Iat = TimeProvider.GetUtcNow(),
                Jti = Guid.NewGuid().ToString("N"),
                Nonce = fixture.NonceCache.Lookup(nonceEndpoint)
                    ?? throw new AssertFailedException("The legitimate rotation must cache a valid nonce.")
            },
            fixture.DpopKey,
            TestHostShell.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);
        var originalResolver = host.Server.OAuth().ResolveIssuerAsync;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveIssuerAsync = (registration, ctx, ct) =>
            {
                if(ctx.FlowId is not null)
                {
                    throw new InvalidOperationException("issuer-configuration-private-detail");
                }

                return originalResolver is not null
                    ? originalResolver(registration, ctx, ct)
                    : ValueTask.FromResult<Uri?>(ctx.Issuer);
            };
        }).ConfigureAwait(false);

        (int StatusCode, string Body) reuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, originalRefreshToken),
            OutgoingHeaders.Empty.WithDpop(proof), TestContext.CancellationToken).ConfigureAwait(false);
        (int StatusCode, string Body) unknown = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, "unknown-refresh-token"),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, reuse.StatusCode, "Issuer resolution during reuse must preserve invalid_grant.");
        Assert.AreEqual(unknown, reuse, "Issuer resolution during reuse must preserve the constant response bytes.");
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveIssuerAsync = originalResolver;
        }).ConfigureAwait(false);
        AuthCodeFlowEndpointResult next = await fixture.Client.AuthCode.RefreshAsync(
            fixture.Registration, new RefreshTokenRequest
            {
                ClientId = ClientId,
                RefreshToken = successorRefreshToken
            }, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, next.Outcome,
            "Issuer failure during reuse must leave the successor usable.");
    }


    /// <summary>
    /// <see cref="Verifiable.Server.ResolveServerIssuerDelegate"/>'s return type is <c>Uri?</c> — a
    /// <see langword="null"/> result is an explicitly permitted outcome, not a configuration
    /// fault. During a valid DPoP-bound reuse, a resolver that returns <see langword="null"/>
    /// must fold onto the same constant <c>invalid_grant</c> response as issuer-resolution
    /// failure and an unknown refresh token, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ReuseWithNullResolvedIssuerHasTheUnknownTokenBody()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult parResult = await fixture.Client.AuthCode.StartParAsync(
            fixture.Registration, RedirectUri, OAuthFormEncodedFieldsFixtures.OpenIdScope, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"Expected PAR to yield a redirect. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        string flowId = fixture.ClientFlowStore.Keys.Single();
        ParCompletedState parCompleted = (ParCompletedState)fixture.ClientFlowStore[flowId];

        HostedAuthorizationServer hosted = host.Host("default");
        Uri authorizeUri = new(hosted.HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, material.Registration.TenantId.Value)
            + "?client_id=" + Uri.EscapeDataString(ClientId)
            + "&request_uri=" + Uri.EscapeDataString(parCompleted.Par.RequestUri.ToString()));
        using HttpResponseMessage authorizeResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, authorizeUri, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, (int)authorizeResponse.StatusCode);
        string location = authorizeResponse.Headers.Location!.OriginalString;
        string code = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Code)
            ?? throw new AssertFailedException("Authorize redirect missing code.");
        string? iss = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Iss);

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

        AuthCodeFlowEndpointResult tokenResult = await fixture.Client.AuthCode.ExchangeTokenAsync(
            fixture.Registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Expected token issuance success. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
        string originalRefreshToken = (string)tokenResult.Body![OAuthRequestParameterNames.RefreshToken];

        //A single legitimate, DPoP-proved rotation.
        RefreshTokenRequest rotateRequest = new()
        {
            ClientId = fixture.Registration.ClientId.Value,
            RefreshToken = originalRefreshToken
        };
        AuthCodeFlowEndpointResult rotation = await fixture.Client.AuthCode.RefreshAsync(
            fixture.Registration, rotateRequest, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, rotation.Outcome,
            $"The DPoP-proved rotation must succeed. ErrorCode={rotation.ErrorCode}");
        string successorRefreshToken = (string)rotation.Body![OAuthRequestParameterNames.RefreshToken];

        string segment = material.Registration.TenantId.Value;
        string nonceEndpoint = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment).GetLeftPart(UriPartial.Path);
        string proof = await DpopProofConstruction.BuildAsync(
            new DpopProofClaims
            {
                Htm = WellKnownHttpMethods.Post,
                Htu = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment).OriginalString,
                Iat = TimeProvider.GetUtcNow(),
                Jti = Guid.NewGuid().ToString("N"),
                Nonce = fixture.NonceCache.Lookup(nonceEndpoint)
                    ?? throw new AssertFailedException("The legitimate rotation must cache a valid nonce.")
            },
            fixture.DpopKey,
            TestHostShell.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);
        var originalResolver = host.Server.OAuth().ResolveIssuerAsync;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveIssuerAsync = (registration, ctx, ct) =>
                ValueTask.FromResult<Uri?>(null);
        }).ConfigureAwait(false);

        (int StatusCode, string Body) reuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, originalRefreshToken),
            OutgoingHeaders.Empty.WithDpop(proof), TestContext.CancellationToken).ConfigureAwait(false);
        (int StatusCode, string Body) unknown = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, "unknown-refresh-token"),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, reuse.StatusCode, "A null resolved issuer during reuse must preserve invalid_grant.");
        Assert.AreEqual(unknown, reuse, "A null resolved issuer during reuse must preserve the constant response bytes.");
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveIssuerAsync = originalResolver;
        }).ConfigureAwait(false);
        AuthCodeFlowEndpointResult next = await fixture.Client.AuthCode.RefreshAsync(
            fixture.Registration, new RefreshTokenRequest
            {
                ClientId = ClientId,
                RefreshToken = successorRefreshToken
            }, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, next.Outcome,
            "A null resolved issuer during reuse must leave the successor usable.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 §5</see>, lines
    /// 558-561: "If the DPoP proof is invalid, the authorization server issues an error response
    /// ... with invalid_dpop_proof". A public (non-DPoP-required) refresh token presented with a
    /// structurally well-formed proof whose SIGNATURE is invalid is refused
    /// <c>invalid_dpop_proof</c> — identically for an unknown handle and a live one, since the
    /// refresh endpoint's pre-correlation step decides the whole request-only half of DPoP
    /// validation once, before the presented <c>refresh_token</c> is ever looked up. A signature
    /// failure is caught before the <c>jti</c> replay guard ever runs, so the refusal — shape 7 of
    /// <see cref="HostedAuthorizationServer.AssertNoFlowStateStoreOperationTouched"/>'s covered set
    /// — touches no flow-state store operation of any kind, unknown and live alike; a subsequent
    /// well-signed presentation shows storage activity again and leaves the live token usable.
    /// </summary>
    [TestMethod]
    public async Task PublicRefreshWithInvalidDpopSignatureAnswersTheSameBodyForAnUnknownAndALiveTokenAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

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
        string liveRefreshToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.RefreshToken];
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer,
            (string)drive.TokenResult.Body![OAuthRequestParameterNames.TokenType]!,
            "This test needs an unbound Bearer issuance to prove the public-refresh shape.");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> proofKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey proofKey = new(proofKeys, WellKnownJwaValues.Es256);
            string wellFormedProof = await DpopProofConstruction.BuildAsync(
                new DpopProofClaims
                {
                    Htm = WellKnownHttpMethods.Post,
                    Htu = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment).OriginalString,
                    Iat = TimeProvider.GetUtcNow(),
                    Jti = Guid.NewGuid().ToString("N"),
                    Nonce = null
                },
                proofKey,
                TestHostShell.Base64UrlEncoder,
                DpopTestSupport.Serializer,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async,
                TestHostShell.MemoryPool,
                TestContext.CancellationToken).ConfigureAwait(false);

            //Corrupt a DATA-BEARING character in the middle of the SIGNATURE segment — never its
            //final character, whose top bits alone survive decoding (an ES256 signature is 64 bytes
            //encoded as 86 unpadded base64url characters, so the last character's low four bits are
            //discarded; a change confined to those bits can decode to the SAME signature bytes,
            //leaving the proof's signature valid and the test flaky). A middle character contributes
            //its full six bits to the decoded byte stream, so any change to it changes at least one
            //decoded signature byte, and the failure is a signature-verification failure, never a
            //structural ("Malformed") one — the header and payload stay well-formed.
            string[] segments = wellFormedProof.Split('.');
            Assert.HasCount(3, segments, "A compact JWS has three segments.");
            char[] signatureChars = segments[2].ToCharArray();
            int mutateIndex = signatureChars.Length / 2;
            signatureChars[mutateIndex] = signatureChars[mutateIndex] == 'A' ? 'B' : 'A';
            string mutatedSignatureSegment = new(signatureChars);
            Assert.AreNotEqual(segments[2], mutatedSignatureSegment,
                "The mutated signature segment must differ from the original, or the corruption proves nothing.");
            string invalidSignatureProof = $"{segments[0]}.{segments[1]}.{mutatedSignatureSegment}";

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                hosted.InstallObservedStorage(candidateIntegration, hosted);
            }).ConfigureAwait(false);

            int beforeLive = hosted.StorageObservations.Count;
            (int LiveStatusCode, string LiveBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, liveRefreshToken),
                OutgoingHeaders.Empty.WithDpop(invalidSignatureProof), TestContext.CancellationToken).ConfigureAwait(false);
            hosted.AssertNoFlowStateStoreOperationTouched(beforeLive, "shape 7 (an invalid DPoP signature) at a live refresh token");

            int beforeUnknown = hosted.StorageObservations.Count;
            (int UnknownStatusCode, string UnknownBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, "unknown-refresh-token-value"),
                OutgoingHeaders.Empty.WithDpop(invalidSignatureProof), TestContext.CancellationToken).ConfigureAwait(false);
            hosted.AssertNoFlowStateStoreOperationTouched(beforeUnknown, "shape 7 (an invalid DPoP signature) at an unknown refresh token");

            Assert.AreEqual(400, LiveStatusCode, LiveBody);
            Assert.Contains(OAuthErrors.InvalidDpopProof, LiveBody, StringComparison.Ordinal);
            Assert.Contains(nameof(DpopProofValidationFailureReason.SignatureFailed), LiveBody, StringComparison.Ordinal,
                "The failure must be a signature-verification failure specifically, never merely invalid_dpop_proof for any reason.");
            Assert.AreEqual(UnknownStatusCode, LiveStatusCode);
            Assert.AreEqual(UnknownBody, LiveBody,
                "An unknown refresh token and a live one must answer byte-identically for an invalid DPoP signature.");

            //The live token is unconsumed — it still refreshes normally afterward with no proof at
            //all (this profile does not require DPoP), and that SUCCESSFUL control shows the
            //storage instrumentation is actually connected (unlike the two refusals above).
            int beforeSuccess = hosted.StorageObservations.Count;
            RefreshTokenRequest refreshRequest = new()
            {
                ClientId = registration.ClientId.Value,
                RefreshToken = liveRefreshToken
            };
            AuthCodeFlowEndpointResult stillWorks = await AuthCodeFlowDriver.DriveRefreshAsync(
                client, registration, refreshRequest, clientAssertionOptions: null, TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, stillWorks.Outcome,
                $"An invalid-signature presentation must not consume the live refresh token. ErrorCode={stillWorks.ErrorCode}");
            var successOps = hosted.StorageObservations.Skip(beforeSuccess).Select(entry => entry.Operation).ToList();
            _ = Assert.ContainsSingle(op => op == "correlate", successOps,
                "A correct presentation must correlate the grant store exactly once.");
            _ = Assert.ContainsSingle(op => op == "load", successOps,
                "A correct presentation must load the grant store exactly once.");
        }
        finally
        {
            proofKeys.PublicKey.Dispose();
            proofKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// A DPoP-bound refresh token presented with no proof at all, under a profile that does not
    /// itself require DPoP: <see cref="Verifiable.OAuth.AuthCode.Server.DpopTokenEndpointValidation.BindValidatedProofAsync"/>'s
    /// bound-record, no-carried-proof branch answers the refresh endpoint's own not-found constant
    /// directly, consulting NONE of the five DPoP delegates
    /// <see cref="Verifiable.OAuth.AuthCode.Server.DpopTokenEndpointValidation.ValidateAsync"/>
    /// checks before issuing a nonce challenge. A partially wired DPoP configuration
    /// (<see cref="AuthorizationServerIntegration.IssueDpopNonceAsync"/> present,
    /// <see cref="AuthorizationServerIntegration.ValidateDpopProofAsync"/> and
    /// <see cref="AuthorizationServerCodecs.DpopProofParser"/> absent) therefore never
    /// surfaces here: the collapse onto the endpoint's constant
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 §8</see>: the
    /// nonce requirement is the server's, and this exit issues none) makes the wiring gap
    /// irrelevant to this exit rather than something it must fail loud about.
    /// </summary>
    [TestMethod]
    public async Task BoundRefreshWithoutAProofAndPartiallyWiredDpopFailsClosedAsync()
    {
        await using TestHostShell host = new(TimeProvider);

        //A profile that does NOT mandate DPoP server-side; the refresh token below is bound
        //anyway because the manual code redemption presents a proof voluntarily.
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration, RedirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId,
            browserClient, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        AuthorizationCodeReceivedState callbackState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        //Redeem the code manually, presenting a DPoP proof this client would never attach on its
        //own — the registration's profile does not mandate one — to establish a BOUND refresh
        //token under a non-mandating profile.
        Uri tokenUri = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> proofKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey redemptionProofKey = new(proofKeys, WellKnownJwaValues.Es256);
        try
        {
            async Task<string> BuildProofAsync(string? nonce) =>
                await DpopProofConstruction.BuildAsync(
                    new DpopProofClaims
                    {
                        Htm = WellKnownHttpMethods.Post,
                        Htu = tokenUri.OriginalString,
                        Iat = TimeProvider.GetUtcNow(),
                        Jti = Guid.NewGuid().ToString("N"),
                        Nonce = nonce
                    },
                    redemptionProofKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
                    MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
                    TestContext.CancellationToken).ConfigureAwait(false);

            Dictionary<string, string> tokenFields = RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, callbackState.Code, callbackState.Pkce.EncodedVerifier, callbackState.RedirectUri.OriginalString);

            string firstProof = await BuildProofAsync(nonce: null).ConfigureAwait(false);
            HttpResponseData challenge = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, tokenFields,
                OutgoingHeaders.Empty.WithDpop(firstProof), TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, challenge.StatusCode, challenge.Body);
            Assert.Contains(OAuthErrors.UseDpopNonce, challenge.Body, StringComparison.Ordinal,
                "A nonce-less proof at code redemption is always challenged (the single server nonce policy).");
            string serverNonce = challenge.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce)
                ?? throw new AssertFailedException("The use_dpop_nonce challenge must carry a DPoP-Nonce header.");

            string retryProof = await BuildProofAsync(serverNonce).ConfigureAwait(false);
            HttpResponseData redemption = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, tokenFields,
                OutgoingHeaders.Empty.WithDpop(retryProof), TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, redemption.StatusCode, redemption.Body);

            using JsonDocument doc = JsonDocument.Parse(redemption.Body);
            Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP,
                doc.RootElement.GetProperty(OAuthRequestParameterNames.TokenType).GetString(),
                "The voluntary proof at redemption must bind the issuance even though the profile does not mandate it.");
            string boundRefreshToken = doc.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!;

            //Unwire ONLY proof validation (the slot unassigned and no parser for the library default), after
            //the bound token was minted: a proof-absent presentation never reaches this or any other DPoP
            //delegate, so the wiring gap has no way to surface for THIS exit, proving the collapse, not
            //merely that some delegate happens to still be wired.
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateDpopProofAsync = null;
                candidateIntegration.Codecs.DpopProofParser = null;
            }).ConfigureAwait(false);

            (int NoProofStatusCode, string NoProofBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, boundRefreshToken),
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(400, NoProofStatusCode, NoProofBody);
            Assert.Contains(OAuthErrors.InvalidGrant, NoProofBody, StringComparison.Ordinal);
            Assert.Contains("The refresh token is unknown, expired, or has been revoked.", NoProofBody, StringComparison.Ordinal);
        }
        finally
        {
            proofKeys.PublicKey.Dispose();
            proofKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// A DPoP-required profile (HAIP 1.0, <see cref="TestHostShell.RegisterDpopClientAsync"/>'s
    /// default) presenting NO proof at all at CODE REDEMPTION: the pre-correlation step answers the
    /// fresh-nonce challenge before the presented <c>code</c> is ever looked up, so an unknown code
    /// and a live one answer byte-identically, each carrying a non-empty <c>DPoP-Nonce</c>. The live
    /// code is unconsumed: the real client's own DPoP-aware exchange, presenting a proof carrying
    /// the supplied nonce, still succeeds.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 §8</see>.
    /// </summary>
    [TestMethod]
    public async Task RequiredDpopProofAbsentAtCodeRedemptionAnswersTheSameBodyForAnUnknownAndALiveCodeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult parResult = await fixture.Client.AuthCode.StartParAsync(
            fixture.Registration, RedirectUri, OAuthFormEncodedFieldsFixtures.OpenIdScope, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"Expected PAR to yield a redirect. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        string flowId = fixture.ClientFlowStore.Keys.Single();
        ParCompletedState parCompleted = (ParCompletedState)fixture.ClientFlowStore[flowId];

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = parCompleted.Par.RequestUri.ToString()
        };
        ExchangeContext authorizeContext = [];
        authorizeContext.SetSubjectId(SubjectId);

        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value, WellKnownEndpointNames.AuthCodeAuthorize,
            WellKnownHttpMethods.Get, authorizeFields, authorizeContext, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, $"Expected redirect from authorize. Body: {authorizeResponse.Body}");

        string code = TestBrowser.ExtractQueryParam(authorizeResponse.Location!, OAuthRequestParameterNames.Code)
            ?? throw new AssertFailedException("Authorize redirect missing code.");
        string? iss = TestBrowser.ExtractQueryParam(authorizeResponse.Location!, OAuthRequestParameterNames.Iss);

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

        AuthorizationCodeReceivedState callbackState = (AuthorizationCodeReceivedState)fixture.ClientFlowStore[flowId];
        string segment = material.Registration.TenantId.Value;
        Uri tokenUri = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);
        HostedAuthorizationServer hosted = host.Host("default");

        Dictionary<string, string> liveFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, callbackState.Code, callbackState.Pkce.EncodedVerifier, callbackState.RedirectUri.OriginalString);
        HttpResponseData liveResponse = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri, liveFields, OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, string> unknownFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, "unknown-authorization-code-value", callbackState.Pkce.EncodedVerifier, callbackState.RedirectUri.OriginalString);
        HttpResponseData unknownResponse = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri, unknownFields, OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, liveResponse.StatusCode, liveResponse.Body);
        Assert.Contains(OAuthErrors.UseDpopNonce, liveResponse.Body, StringComparison.Ordinal);
        string? liveNonce = liveResponse.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce);
        Assert.IsFalse(string.IsNullOrEmpty(liveNonce), "The challenge must carry a non-empty DPoP-Nonce header.");
        Assert.AreEqual(liveResponse.StatusCode, unknownResponse.StatusCode);
        Assert.AreEqual(liveResponse.Body, unknownResponse.Body,
            "An unknown code and a live one must answer byte-identically when a required DPoP proof is absent.");
        string? unknownNonce = unknownResponse.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce);
        Assert.IsFalse(string.IsNullOrEmpty(unknownNonce),
            "The challenge must carry a non-empty DPoP-Nonce header for an unknown code too.");

        //The live code is unconsumed: a proof built explicitly FROM THE CAPTURED liveNonce
        //succeeds — not merely a proof obtained through the client's own independent retry/cache,
        //which could pass even if the specific captured challenge nonce were itself unusable.
        string retryProof = await DpopProofConstruction.BuildAsync(
            new DpopProofClaims
            {
                Htm = WellKnownHttpMethods.Post,
                Htu = tokenUri.OriginalString,
                Iat = TimeProvider.GetUtcNow(),
                Jti = Guid.NewGuid().ToString("N"),
                Nonce = liveNonce
            },
            fixture.DpopKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData retryResponse = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri, liveFields,
            OutgoingHeaders.Empty.WithDpop(retryProof), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, retryResponse.StatusCode, retryResponse.Body,
            "The live code must still redeem once a proof carrying the EXACT captured nonce is presented.");
    }


    /// <summary>
    /// A DPoP-required profile presenting NO proof at all at REFRESH: the pre-correlation step
    /// answers the fresh-nonce challenge before the presented <c>refresh_token</c> is ever looked
    /// up, so an unknown token and a live one answer byte-identically, each carrying a non-empty
    /// <c>DPoP-Nonce</c>. The live token is unconsumed: the real client's own DPoP-aware refresh,
    /// presenting a proof carrying the supplied nonce, still succeeds.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 §8</see>.
    /// </summary>
    [TestMethod]
    public async Task RequiredDpopProofAbsentAtRefreshAnswersTheSameBodyForAnUnknownAndALiveTokenAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult parResult = await fixture.Client.AuthCode.StartParAsync(
            fixture.Registration, RedirectUri, OAuthFormEncodedFieldsFixtures.OpenIdScope, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"Expected PAR to yield a redirect. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        string flowId = fixture.ClientFlowStore.Keys.Single();
        ParCompletedState parCompleted = (ParCompletedState)fixture.ClientFlowStore[flowId];

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = parCompleted.Par.RequestUri.ToString()
        };
        ExchangeContext authorizeContext = [];
        authorizeContext.SetSubjectId(SubjectId);

        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value, WellKnownEndpointNames.AuthCodeAuthorize,
            WellKnownHttpMethods.Get, authorizeFields, authorizeContext, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, $"Expected redirect from authorize. Body: {authorizeResponse.Body}");

        string code = TestBrowser.ExtractQueryParam(authorizeResponse.Location!, OAuthRequestParameterNames.Code)
            ?? throw new AssertFailedException("Authorize redirect missing code.");
        string? iss = TestBrowser.ExtractQueryParam(authorizeResponse.Location!, OAuthRequestParameterNames.Iss);

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

        AuthCodeFlowEndpointResult tokenResult = await fixture.Client.AuthCode.ExchangeTokenAsync(
            fixture.Registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Expected token issuance success. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
        string originalRefreshToken = (string)tokenResult.Body![OAuthRequestParameterNames.RefreshToken];

        string segment = material.Registration.TenantId.Value;
        Uri tokenUri = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);
        HostedAuthorizationServer hosted = host.Host("default");

        HttpResponseData liveResponse = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, originalRefreshToken),
            OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData unknownResponse = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, "unknown-refresh-token-value"),
            OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, liveResponse.StatusCode, liveResponse.Body);
        Assert.Contains(OAuthErrors.UseDpopNonce, liveResponse.Body, StringComparison.Ordinal);
        string? liveNonce = liveResponse.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce);
        Assert.IsFalse(string.IsNullOrEmpty(liveNonce), "The challenge must carry a non-empty DPoP-Nonce header.");
        Assert.AreEqual(liveResponse.StatusCode, unknownResponse.StatusCode);
        Assert.AreEqual(liveResponse.Body, unknownResponse.Body,
            "An unknown refresh token and a live one must answer byte-identically when a required DPoP proof is absent.");
        string? unknownNonce = unknownResponse.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce);
        Assert.IsFalse(string.IsNullOrEmpty(unknownNonce),
            "The challenge must carry a non-empty DPoP-Nonce header for an unknown token too.");

        //The live refresh token is unconsumed: a proof built explicitly FROM THE CAPTURED
        //liveNonce succeeds — not merely a proof obtained through the client's own independent
        //retry/cache, which could pass even if the specific captured challenge nonce were itself
        //unusable.
        string retryProof = await DpopProofConstruction.BuildAsync(
            new DpopProofClaims
            {
                Htm = WellKnownHttpMethods.Post,
                Htu = tokenUri.OriginalString,
                Iat = TimeProvider.GetUtcNow(),
                Jti = Guid.NewGuid().ToString("N"),
                Nonce = liveNonce
            },
            fixture.DpopKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData retryResponse = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, originalRefreshToken),
            OutgoingHeaders.Empty.WithDpop(retryProof), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, retryResponse.StatusCode, retryResponse.Body,
            "The live refresh token must still work once a proof carrying the EXACT captured nonce is presented.");
    }


    /// <summary>
    /// A registration under a DPoP-mandating profile (<see cref="PolicyProfile.Haip10"/>) holding a
    /// refresh record OBTAINED BEFORE the profile mandated DPoP — issued Bearer, with no stored
    /// <c>cnf.jkt</c> binding — then altered live to the mandating profile through
    /// <see cref="HostedAuthorizationServer.UpdateClientAsync"/>, the way the live-alteration tests
    /// change a registration mid-lifetime: the refresh grant's request-only DPoP half derives from
    /// the REGISTRATION's profile, decided in the endpoint's pre-correlation step, not from the
    /// record's own (empty) binding, so presenting the unbound token with no proof is still
    /// CHALLENGED, byte-identically for an unknown token and this live one. The live token is
    /// unconsumed: a proof carrying the supplied nonce then succeeds, and the client being a public
    /// client, the issuance is bound to the proof's public key and answered <c>token_type</c>
    /// <c>DPoP</c>. <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>;
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 Section 5</see>: "When an
    /// authorization server supporting DPoP issues a refresh token to a public client that presents a
    /// valid DPoP proof at the token endpoint, the refresh token MUST be bound to the respective public
    /// key." and "To sender-constrain the access token after checking the validity of the DPoP proof,
    /// the authorization server associates the issued access token with the public key from the DPoP
    /// proof".
    /// </summary>
    [TestMethod]
    public async Task DpopMandatingProfileChallengesAnUnboundRefreshRecordObtainedBeforeTheProfileMandatedItAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration, RedirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId,
            browserClient, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        AuthorizationCodeReceivedState callbackState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        Uri tokenUri = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);

        //Redeemed with NO DPoP header at all: a Bearer refresh token, no cnf.jkt binding — the
        //shape the record-level reading (the base commit's, before this fix) would have decided
        //the challenge from.
        Dictionary<string, string> tokenFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, callbackState.Code, callbackState.Pkce.EncodedVerifier, callbackState.RedirectUri.OriginalString);
        HttpResponseData redemption = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri, tokenFields,
            OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, redemption.StatusCode, redemption.Body);
        using JsonDocument redemptionDoc = JsonDocument.Parse(redemption.Body);
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer,
            redemptionDoc.RootElement.GetProperty(OAuthRequestParameterNames.TokenType).GetString(),
            "No proof was presented at redemption, under a profile that does not mandate DPoP: the token issues as Bearer.");
        string unboundRefreshToken = redemptionDoc.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!;

        //Altered live to a DPoP-mandating profile, AFTER the Bearer issuance above.
        ClientRecord beforeAlteration = hosted.Registrations[segment];
        ClientRecord mandatingRegistration = beforeAlteration with { Profile = PolicyProfile.Haip10 };
        _ = await hosted.UpdateClientAsync(beforeAlteration, mandatingRegistration, [], TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> proofKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey refreshProofKey = new(proofKeys, WellKnownJwaValues.Es256);
            async Task<string> BuildProofAsync(string? nonce) =>
                await DpopProofConstruction.BuildAsync(
                    new DpopProofClaims
                    {
                        Htm = WellKnownHttpMethods.Post,
                        Htu = tokenUri.OriginalString,
                        Iat = TimeProvider.GetUtcNow(),
                        Jti = Guid.NewGuid().ToString("N"),
                        Nonce = nonce
                    },
                    refreshProofKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
                    MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
                    TestContext.CancellationToken).ConfigureAwait(false);

            //The shape under test: the unbound Bearer refresh token, presented with NO proof, once
            //its registration's profile mandates DPoP. RED on the base (commit da5a2478): the
            //refresh grant derived `dpopRequired` from `boundConfirmation is { IsEmpty: false }`
            //(the record's own binding) rather than the registration's profile, so an unbound
            //record answered 200 Bearer here instead of challenging — the production line that
            //flips this test is AuthCodeEndpoints.cs's BeforeRefreshCorrelationAsync computing
            //`proofRequiredByRegistration = ClientPolicyProfiles.RequiresDpop(registration.Profile)`
            //ahead of DpopTokenEndpointValidation.ValidatePresentedProofAsync.
            HttpResponseData liveResponse = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, unboundRefreshToken),
                OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);
            HttpResponseData unknownResponse = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, "unknown-refresh-token-value"),
                OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(400, liveResponse.StatusCode, liveResponse.Body);
            Assert.Contains(OAuthErrors.UseDpopNonce, liveResponse.Body, StringComparison.Ordinal);
            string? liveNonce = liveResponse.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce);
            Assert.IsFalse(string.IsNullOrEmpty(liveNonce), "The challenge must carry a non-empty DPoP-Nonce header.");
            Assert.AreEqual(liveResponse.StatusCode, unknownResponse.StatusCode);
            Assert.AreEqual(liveResponse.Body, unknownResponse.Body,
                "An unknown refresh token and a live, previously-Bearer one must answer byte-identically once the registration's profile mandates DPoP.");
            string? unknownNonce = unknownResponse.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce);
            Assert.IsFalse(string.IsNullOrEmpty(unknownNonce),
                "The challenge must carry a non-empty DPoP-Nonce header for an unknown token too.");

            //The live refresh token is unconsumed: a proof carrying the supplied nonce satisfies
            //the registration's mandate and succeeds. The client is a public client, so the valid
            //proof binds the issuance: the refreshed access token answers DPoP.
            string retryProof = await BuildProofAsync(liveNonce).ConfigureAwait(false);
            HttpResponseData retryResponse = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, unboundRefreshToken),
                OutgoingHeaders.Empty.WithDpop(retryProof), TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, retryResponse.StatusCode, retryResponse.Body);
            using JsonDocument retryDoc = JsonDocument.Parse(retryResponse.Body);
            Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP,
                retryDoc.RootElement.GetProperty(OAuthRequestParameterNames.TokenType).GetString(),
                "The valid proof a public client presents binds the refreshed access token to its public key.");
        }
        finally
        {
            proofKeys.PublicKey.Dispose();
            proofKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5.2">RFC 9449 Section 5.2</see>: "If the value is
    /// true, the authorization server MUST reject token requests from the client that do not contain the DPoP header.",
    /// which <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">Section 5</see> makes "applicable for all
    /// access token requests regardless of grant type (e.g., the common authorization_code and refresh_token grant
    /// types". A public client issued an unbound refresh token under a profile that leaves DPoP optional, whose
    /// registration then declares <c>dpop_bound_access_tokens</c> <c>true</c>, presents that refresh token over the wire
    /// with no <c>DPoP</c> field: the refresh is refused 400 <c>use_dpop_nonce</c> "DPoP proof required." with exactly
    /// one <c>DPoP-Nonce</c> field line and no access token.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ClientDeclaringDpopBoundAccessTokensWithoutAProofIsRefusedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        (HostedAuthorizationServer hosted, Uri tokenUri, string unboundRefreshToken) =
            await ObtainUnboundRefreshTokenAsync(host, material).ConfigureAwait(false);
        _ = await host.UpdateAsync(material, static previous => previous with { DpopBoundAccessTokens = true },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        HttpResponseData response = await PostRefreshAsync(hosted, tokenUri, unboundRefreshToken, proof: null).ConfigureAwait(false);

        DpopCodeBindingWire.AssertProofRequired(response);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 Section 5</see>: "When an authorization
    /// server supporting DPoP issues a refresh token to a public client that presents a valid DPoP proof at the token
    /// endpoint, the refresh token MUST be bound to the respective public key.", and "To sender-constrain the access
    /// token after checking the validity of the DPoP proof, the authorization server associates the issued access token
    /// with the public key from the DPoP proof". A public client issued an unbound refresh token, under a profile that
    /// leaves DPoP optional, presents it over the wire with a valid proof carrying the supplied nonce: it is answered 200
    /// with <c>token_type</c> <c>DPoP</c> and the access token's <c>cnf.jkt</c> the JWK SHA-256 Thumbprint of the proof's
    /// DPoP key; the rotated refresh token is bound to that DPoP key, refused 400 <c>invalid_grant</c> "The refresh token is
    /// unknown, expired, or has been revoked." under a proof by another DPoP key and served under a proof by the bound
    /// one.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task PublicClientRefreshOfAnUnboundTokenWithAValidProofBindsTheIssuanceAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        (HostedAuthorizationServer hosted, Uri tokenUri, string unboundRefreshToken) =
            await ObtainUnboundRefreshTokenAsync(host, material).ConfigureAwait(false);
        using FreshDpopKey bound = new();
        using FreshDpopKey other = new();
        string boundThumbprint = bound.Key.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);

        (string successor, string nonce) =
            await RefreshUnderAProofAsync(hosted, tokenUri, unboundRefreshToken, bound.Key).ConfigureAwait(false);

        HttpResponseData underOther = await PostRefreshAsync(
            hosted, tokenUri, successor, await BuildRefreshProofAsync(other.Key, tokenUri, nonce).ConfigureAwait(false)).ConfigureAwait(false);
        DpopCodeBindingWire.AssertError(underOther.StatusCode, underOther.Body, 400, "invalid_grant", "The refresh token is unknown, expired, or has been revoked.");

        HttpResponseData underBound = await PostRefreshAsync(
            hosted, tokenUri, successor, await BuildRefreshProofAsync(bound.Key, tokenUri, nonce).ConfigureAwait(false)).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(underBound.StatusCode, underBound.Body, "DPoP", boundThumbprint);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 Section 5</see>: "When an authorization
    /// server supporting DPoP issues a refresh token to a public client that presents a valid DPoP proof at the token
    /// endpoint, the refresh token MUST be bound to the respective public key. The binding MUST be validated when the
    /// refresh token is later presented to get new access tokens. As a result, such a client MUST present a DPoP proof for
    /// the same key that was used to obtain the refresh token each time that refresh token is used to obtain a new access
    /// token." A public client (<c>token_endpoint_auth_method</c> <c>none</c>), under a profile that leaves DPoP optional,
    /// is issued over the wire a refresh token bound to one DPoP key; an update of its client configuration with its
    /// registration access token then declares <c>private_key_jwt</c> and a JWK Set holding a client assertion key. The
    /// refresh token, presented with a valid client assertion and no <c>DPoP</c> field, or with a proof by another DPoP
    /// key, is refused 400 <c>invalid_grant</c> "The refresh token is unknown, expired, or has been revoked.";
    /// presented with a proof by the DPoP key it was issued under, it is answered 200 with <c>token_type</c>
    /// <c>DPoP</c> and the access token's <c>cnf.jkt</c> the JWK SHA-256 Thumbprint of that DPoP key.
    /// </summary>
    /// <param name="presentation">The DPoP field the refresh carries: <c>no proof</c>, <c>another DPoP key</c> or <c>the bound DPoP key</c>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("no proof")]
    [DataRow("another DPoP key")]
    [DataRow("the bound DPoP key")]
    public async Task PublicClientTurnedConfidentialIsHeldToItsRefreshTokensBindingAsync(string presentation)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        using FreshDpopKey bound = new();
        using FreshDpopKey other = new();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> assertionKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory assertionPublicKey = assertionKeys.PublicKey;
        using PrivateKeyMemory assertionPrivateKey = assertionKeys.PrivateKey;
        (HostedAuthorizationServer hosted, Uri tokenUri, string refreshToken, string nonce) =
            await IssueBoundRefreshTokenAndTurnTheClientConfidentialAsync(host, material, bound.Key, assertionPublicKey).ConfigureAwait(false);

        string? proof = presentation switch
        {
            "no proof" => null,
            "another DPoP key" => await BuildRefreshProofAsync(other.Key, tokenUri, nonce).ConfigureAwait(false),
            "the bound DPoP key" => await BuildRefreshProofAsync(bound.Key, tokenUri, nonce).ConfigureAwait(false),
            _ => throw new ArgumentOutOfRangeException(nameof(presentation), presentation, "No such presentation row.")
        };
        HttpResponseData response = await PostAssertedRefreshAsync(
            host, hosted, tokenUri, refreshToken, assertionPrivateKey, proof).ConfigureAwait(false);

        if(presentation == "the bound DPoP key")
        {
            DpopCodeBindingWire.AssertIssued(response.StatusCode, response.Body, "DPoP",
                bound.Key.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool));

            return;
        }

        DpopCodeBindingWire.AssertError(response.StatusCode, response.Body, 400, "invalid_grant", "The refresh token is unknown, expired, or has been revoked.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 Section 5</see>: "The binding MUST be
    /// validated when the refresh token is later presented to get new access tokens.", with
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1 draft-16 Section 7.5.3</see>:
    /// "The authorization server SHOULD NOT revoke any issued tokens when receiving a replayed authorization code that
    /// contains invalid parameters", the reasoning a presentation of a rotated-out refresh token without the DPoP key it is
    /// bound to follows. A public client, under a profile that leaves DPoP optional, is issued over the wire a refresh
    /// token bound to one DPoP key; an update of its client configuration with its registration access token then
    /// declares <c>private_key_jwt</c>; the client rotates the refresh token with a valid client assertion and a proof by
    /// that DPoP key. The rotated-out refresh token, presented again with a valid client assertion and no <c>DPoP</c>
    /// field, is refused 400 <c>invalid_grant</c> "The refresh token is unknown, expired, or has been revoked." and
    /// revokes nothing: the successor is then answered 200 under a proof by that DPoP key.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task PublicClientTurnedConfidentialReusingARetiredRefreshTokenAnswersAsABoundReuseAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        using FreshDpopKey bound = new();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> assertionKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory assertionPublicKey = assertionKeys.PublicKey;
        using PrivateKeyMemory assertionPrivateKey = assertionKeys.PrivateKey;
        (HostedAuthorizationServer hosted, Uri tokenUri, string original, string nonce) =
            await IssueBoundRefreshTokenAndTurnTheClientConfidentialAsync(host, material, bound.Key, assertionPublicKey).ConfigureAwait(false);
        string boundThumbprint = bound.Key.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);

        HttpResponseData rotation = await PostAssertedRefreshAsync(
            host, hosted, tokenUri, original, assertionPrivateKey,
            await BuildRefreshProofAsync(bound.Key, tokenUri, nonce).ConfigureAwait(false)).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(rotation.StatusCode, rotation.Body, "DPoP", boundThumbprint);
        using JsonDocument rotationDocument = JsonDocument.Parse(rotation.Body);
        string successor = rotationDocument.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!;

        HttpResponseData reuse = await PostAssertedRefreshAsync(
            host, hosted, tokenUri, original, assertionPrivateKey, proof: null).ConfigureAwait(false);
        DpopCodeBindingWire.AssertError(reuse.StatusCode, reuse.Body, 400, "invalid_grant", "The refresh token is unknown, expired, or has been revoked.");

        HttpResponseData afterReuse = await PostAssertedRefreshAsync(
            host, hosted, tokenUri, successor, assertionPrivateKey,
            await BuildRefreshProofAsync(bound.Key, tokenUri, nonce).ConfigureAwait(false)).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(afterReuse.StatusCode, afterReuse.Body, "DPoP", boundThumbprint);
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1 draft-16 Section 4.3.1</see>:
    /// "Authorization servers MUST utilize one of these methods to detect refresh token replay by malicious actors for
    /// public clients: ... Refresh token rotation: ... If a refresh token is compromised and subsequently used by both the
    /// attacker and the legitimate client, one of them will present an invalidated refresh token, which will inform the
    /// authorization server of the breach. The authorization server cannot determine which party submitted the invalid
    /// refresh token, but it will revoke the active refresh token as well as the access authorization grant associated
    /// with it.", with <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 Section 5</see>: "When an
    /// authorization server supporting DPoP issues a refresh token to a public client that presents a valid DPoP proof at
    /// the token endpoint, the refresh token MUST be bound to the respective public key. The binding MUST be validated
    /// when the refresh token is later presented to get new access tokens." A public client, under a profile that leaves
    /// DPoP optional, redeems its code over the wire with no <c>DPoP</c> field and is issued an unbound refresh token
    /// (<c>token_type</c> <c>Bearer</c>, no <c>cnf</c>). That refresh token, presented with a valid proof by one DPoP key
    /// carrying the supplied nonce, is answered 200 with <c>token_type</c> <c>DPoP</c>, the access token's
    /// <c>cnf.jkt</c> the JWK SHA-256 Thumbprint of that DPoP key; that the successor is bound to it is held by
    /// <see cref="PublicClientRefreshOfAnUnboundTokenWithAValidProofBindsTheIssuanceAsync"/>. The rotated-out refresh
    /// token is held to the binding it was issued under, none: presented again with no <c>DPoP</c> field, with a
    /// valid proof by another DPoP key, or with a valid proof by the DPoP key of the rotation, it is a valid reuse,
    /// refused 400 <c>invalid_grant</c> "The refresh token is unknown, expired, or has been revoked.", and the grant is
    /// revoked: the successor, presented under a proof by the DPoP key it is bound to, is refused with the same answer.
    /// The server cannot tell which party rotated the refresh token and which reused it, so the one exchange is both
    /// readings: an attacker rotating a stolen unbound refresh token first under its own DPoP key and the legitimate
    /// client reusing it, or the legitimate client rotating it and an attacker reusing it.
    /// </summary>
    /// <param name="presentation">The DPoP field the reuse carries: <c>no proof</c>, <c>another DPoP key</c> or
    /// <c>the rotation's DPoP key</c>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("no proof")]
    [DataRow("another DPoP key")]
    [DataRow("the rotation's DPoP key")]
    public async Task PublicClientsUnboundRefreshTokenRotatedUnderAProofIsRevokedByItsReuseAsync(string presentation)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        (HostedAuthorizationServer hosted, Uri tokenUri, string unboundRefreshToken) =
            await ObtainUnboundRefreshTokenAsync(host, material).ConfigureAwait(false);
        using FreshDpopKey rotating = new();
        using FreshDpopKey other = new();

        (string successor, string nonce) =
            await RefreshUnderAProofAsync(hosted, tokenUri, unboundRefreshToken, rotating.Key).ConfigureAwait(false);

        string? reuseProof = presentation switch
        {
            "no proof" => null,
            "another DPoP key" => await BuildRefreshProofAsync(other.Key, tokenUri, nonce).ConfigureAwait(false),
            "the rotation's DPoP key" => await BuildRefreshProofAsync(rotating.Key, tokenUri, nonce).ConfigureAwait(false),
            _ => throw new ArgumentOutOfRangeException(nameof(presentation), presentation, "No such presentation row.")
        };
        HttpResponseData reuse = await PostRefreshAsync(hosted, tokenUri, unboundRefreshToken, reuseProof).ConfigureAwait(false);
        DpopCodeBindingWire.AssertError(reuse.StatusCode, reuse.Body, 400, "invalid_grant", "The refresh token is unknown, expired, or has been revoked.");

        HttpResponseData afterReuse = await PostRefreshAsync(
            hosted, tokenUri, successor, await BuildRefreshProofAsync(rotating.Key, tokenUri, nonce).ConfigureAwait(false)).ConfigureAwait(false);
        DpopCodeBindingWire.AssertError(afterReuse.StatusCode, afterReuse.Body, 400, "invalid_grant", "The refresh token is unknown, expired, or has been revoked.");
    }


    /// <summary>
    /// Presents <paramref name="refreshToken"/> at the token endpoint over the wire with a proof by <paramref name="key"/>:
    /// first without a nonce, answered 400 with the nonce challenge, then with the supplied nonce, asserting an issuance
    /// with <c>token_type</c> <c>DPoP</c> bound to <paramref name="key"/>.
    /// </summary>
    /// <param name="hosted">The hosted server whose client sends the requests.</param>
    /// <param name="tokenUri">The token endpoint URL.</param>
    /// <param name="refreshToken">The refresh token presented.</param>
    /// <param name="key">The DPoP key that signs both proofs.</param>
    /// <returns>The successor refresh token issued and the nonce the endpoint supplied.</returns>
    private async Task<(string Successor, string Nonce)> RefreshUnderAProofAsync(
        HostedAuthorizationServer hosted, Uri tokenUri, string refreshToken, DpopKey key)
    {
        HttpResponseData challenge = await PostRefreshAsync(
            hosted, tokenUri, refreshToken, await BuildRefreshProofAsync(key, tokenUri, nonce: null).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.AreEqual(400, challenge.StatusCode, challenge.Body);
        string nonce = challenge.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce)
            ?? throw new AssertFailedException("The nonce challenge carries a DPoP-Nonce field.");

        HttpResponseData refreshed = await PostRefreshAsync(
            hosted, tokenUri, refreshToken, await BuildRefreshProofAsync(key, tokenUri, nonce).ConfigureAwait(false)).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(refreshed.StatusCode, refreshed.Body, "DPoP",
            key.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool));
        using JsonDocument refreshedDocument = JsonDocument.Parse(refreshed.Body);

        return (refreshedDocument.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!, nonce);
    }


    /// <summary>
    /// Declares <paramref name="material"/>'s client public (<c>token_endpoint_auth_method</c> <c>none</c>) at a server
    /// that verifies DPoP proofs and authenticates <c>private_key_jwt</c> client assertions addressed to its token
    /// endpoint, gives it its client configuration endpoint, issues it over the wire a refresh token bound to
    /// <paramref name="key"/>, and sends an RFC 7592 update of its client configuration with its registration access
    /// token declaring <c>private_key_jwt</c> and a JWK Set holding <paramref name="assertionPublicKey"/> under
    /// <see cref="AssertionKeyId"/>, asserting the update is answered 200.
    /// </summary>
    /// <param name="host">The fixture whose listener serves the flow.</param>
    /// <param name="material">The client, registered under <see cref="PolicyProfile.Rfc6749WithPkce"/>.</param>
    /// <param name="key">The DPoP key the refresh token is bound to.</param>
    /// <param name="assertionPublicKey">The P-256 public key the client's assertions are verified with.</param>
    /// <returns>The hosted server, its token endpoint URL, the bound refresh token and the nonce the endpoint supplied.</returns>
    private async Task<(HostedAuthorizationServer Hosted, Uri TokenUri, string RefreshToken, string Nonce)> IssueBoundRefreshTokenAndTurnTheClientConfidentialAsync(
        TestHostShell host, VerifierKeyMaterial material, DpopKey key, PublicKeyMemory assertionPublicKey)
    {
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        _ = await host.SetTokenEndpointAuthMethodAsync(material, ClientAuthenticationMethod.None,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        (Uri managementUri, string registrationAccessToken) =
            await host.EnableClientConfigurationAsync(material, TestContext.CancellationToken).ConfigureAwait(false);
        Uri tokenUri = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, material.Registration.TenantId.Value);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ClientAuthenticationMethodsSupported =
                [ClientAuthenticationMethod.None, ClientAuthenticationMethod.PrivateKeyJwt];
            candidateIntegration.ClientAssertionSigningAlgorithmsSupported = [WellKnownJwaValues.Es256];
            candidateIntegration.ValidateClientCredentialsAsync =
                PrivateKeyJwtClientAuthentication.BuildValidator(additionalAcceptedAudiences: [tokenUri.OriginalString]);
        }).ConfigureAwait(false);

        (HostedAuthorizationServer hosted, _, string refreshToken, string nonce) =
            await ObtainBoundRefreshTokenAsync(host, material, key).ConfigureAwait(false);

        Dictionary<string, string> assertionJwk = new(
            DpopJwkUtilities.ToJwk(assertionPublicKey, WellKnownJwaValues.Es256, TestSetup.Base64UrlEncoder), StringComparer.Ordinal)
        {
            [WellKnownJwkMemberNames.Kid] = AssertionKeyId
        };
        string confidentialMetadata = JsonSerializer.Serialize(new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["client_id"] = ClientId,
            ["redirect_uris"] = new[] { RedirectUri.OriginalString },
            ["scope"] = WellKnownScopes.OpenId,
            ["token_endpoint_auth_method"] = "private_key_jwt",
            ["jwks"] = new Dictionary<string, object>(StringComparer.Ordinal) { [WellKnownJwkMemberNames.Keys] = new[] { assertionJwk } }
        });
        using HttpResponseMessage update = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(
            host, HttpMethod.Put, managementUri, registrationAccessToken, confidentialMetadata, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)update.StatusCode, await update.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false));
        Assert.AreEqual(ClientAuthenticationMethod.PrivateKeyJwt, hosted.Registrations[ClientId].TokenEndpointAuthMethod,
            "The update declared the client confidential.");

        return (hosted, tokenUri, refreshToken, nonce);
    }


    /// <summary>The <c>kid</c> of the client assertion key the confidential client's JWK Set publishes.</summary>
    private static string AssertionKeyId { get; } = "refresh-client-assertion-key-1";


    /// <summary>
    /// Presents <paramref name="refreshToken"/> at the token endpoint over the wire with a <c>private_key_jwt</c> client
    /// assertion (<see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.2">RFC 7523 Section 2.2</see>) signed ES256
    /// by <paramref name="assertionPrivateKey"/> under <see cref="AssertionKeyId"/>, its <c>iss</c> and <c>sub</c> the
    /// client identifier, its <c>aud</c> <paramref name="tokenUri"/>, a fresh <c>jti</c> and a lifetime of one minute,
    /// carrying <paramref name="proof"/> in its one <c>DPoP</c> field or no such field when it is <see langword="null"/>.
    /// </summary>
    /// <param name="host">The fixture whose codecs serialize the assertion.</param>
    /// <param name="hosted">The hosted server whose client sends the request.</param>
    /// <param name="tokenUri">The token endpoint URL.</param>
    /// <param name="refreshToken">The refresh token presented.</param>
    /// <param name="assertionPrivateKey">The P-256 private key the assertion is signed with.</param>
    /// <param name="proof">The DPoP proof, or <see langword="null"/> for none.</param>
    /// <returns>The whole response.</returns>
    private async Task<HttpResponseData> PostAssertedRefreshAsync(
        TestHostShell host, HostedAuthorizationServer hosted, Uri tokenUri, string refreshToken,
        PrivateKeyMemory assertionPrivateKey, string? proof)
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        JwtHeader header = new(capacity: 3)
        {
            [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256,
            [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt,
            [WellKnownJwkMemberNames.Kid] = AssertionKeyId
        };
        JwtPayload payload = new(capacity: 6)
        {
            [WellKnownJwtClaimNames.Iss] = ClientId,
            [WellKnownJwtClaimNames.Sub] = ClientId,
            [WellKnownJwtClaimNames.Aud] = tokenUri.OriginalString,
            [WellKnownJwtClaimNames.Jti] = $"assertion-{Guid.NewGuid():N}",
            [WellKnownJwtClaimNames.Iat] = now.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = now.AddMinutes(1).ToUnixTimeSeconds()
        };
        using JwsMessage jws = await new UnsignedJwt(header, payload).SignAsync(
            assertionPrivateKey, host.Server.OAuth().Codecs.JwtHeaderSerializer!, host.Server.OAuth().Codecs.JwtPayloadSerializer!,
            TestSetup.Base64UrlEncoder, MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, string> fields = RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, refreshToken);
        fields[OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer;
        fields[OAuthRequestParameterNames.ClientAssertion] = JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
        OutgoingHeaders headers = proof switch
        {
            null => OutgoingHeaders.Empty,
            _ => OutgoingHeaders.Empty.WithDpop(proof)
        };

        return await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri, fields, headers, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Drives PAR, authorize and callback over the real wire for <paramref name="material"/>'s public client and redeems
    /// the code with no <c>DPoP</c> field, asserting a Bearer issuance.
    /// </summary>
    /// <param name="host">The fixture whose listener serves the flow.</param>
    /// <param name="material">The registration the flow runs under.</param>
    /// <returns>The hosted server, its token endpoint URL and the unbound refresh token issued.</returns>
    private async Task<(HostedAuthorizationServer Hosted, Uri TokenUri, string RefreshToken)> ObtainUnboundRefreshTokenAsync(
        TestHostShell host, VerifierKeyMaterial material)
    {
        (HostedAuthorizationServer hosted, Uri tokenUri, Dictionary<string, string> redemptionFields) =
            await DriveToTheCodeRedemptionAsync(host, material).ConfigureAwait(false);

        HttpResponseData redemption = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri, redemptionFields, OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(redemption.StatusCode, redemption.Body, "Bearer", expectedJwkThumbprint: null);
        using JsonDocument redemptionDocument = JsonDocument.Parse(redemption.Body);

        return (hosted, tokenUri, redemptionDocument.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!);
    }


    /// <summary>
    /// Drives PAR, authorize and callback over the real wire for <paramref name="material"/>'s public client and redeems
    /// the code with a proof by <paramref name="key"/>: first without a nonce, answered with the nonce challenge, then
    /// with the supplied nonce, asserting an issuance bound to <paramref name="key"/>.
    /// </summary>
    /// <param name="host">The fixture whose listener serves the flow.</param>
    /// <param name="material">The registration the flow runs under.</param>
    /// <param name="key">The DPoP key the issuance is bound to.</param>
    /// <returns>The hosted server, its token endpoint URL, the bound refresh token issued and the nonce the endpoint supplied.</returns>
    private async Task<(HostedAuthorizationServer Hosted, Uri TokenUri, string RefreshToken, string Nonce)> ObtainBoundRefreshTokenAsync(
        TestHostShell host, VerifierKeyMaterial material, DpopKey key)
    {
        (HostedAuthorizationServer hosted, Uri tokenUri, Dictionary<string, string> redemptionFields) =
            await DriveToTheCodeRedemptionAsync(host, material).ConfigureAwait(false);

        HttpResponseData challenge = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri, redemptionFields,
            OutgoingHeaders.Empty.WithDpop(await BuildRefreshProofAsync(key, tokenUri, nonce: null).ConfigureAwait(false)),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, challenge.StatusCode, challenge.Body);
        string nonce = challenge.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce)
            ?? throw new AssertFailedException("The nonce challenge carries a DPoP-Nonce field.");

        HttpResponseData redemption = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri, redemptionFields,
            OutgoingHeaders.Empty.WithDpop(await BuildRefreshProofAsync(key, tokenUri, nonce).ConfigureAwait(false)),
            TestContext.CancellationToken).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(redemption.StatusCode, redemption.Body, "DPoP",
            key.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool));
        using JsonDocument redemptionDocument = JsonDocument.Parse(redemption.Body);

        return (hosted, tokenUri, redemptionDocument.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!, nonce);
    }


    /// <summary>
    /// Drives PAR, authorize and callback over the real wire for <paramref name="material"/>'s public client, up to the
    /// form fields of the code redemption.
    /// </summary>
    /// <param name="host">The fixture whose listener serves the flow.</param>
    /// <param name="material">The registration the flow runs under.</param>
    /// <returns>The hosted server, its token endpoint URL and the form fields that redeem the code.</returns>
    private async Task<(HostedAuthorizationServer Hosted, Uri TokenUri, Dictionary<string, string> RedemptionFields)> DriveToTheCodeRedemptionAsync(
        TestHostShell host, VerifierKeyMaterial material)
    {
        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration, RedirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);
        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId,
            browserClient, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        AuthorizationCodeReceivedState callbackState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        return (hosted, RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment),
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, callbackState.Code, callbackState.Pkce.EncodedVerifier, callbackState.RedirectUri.OriginalString));
    }


    /// <summary>
    /// Builds a refresh request proof by <paramref name="key"/>: <c>htm</c> <c>POST</c>, <c>htu</c>
    /// <paramref name="tokenUri"/>, a fresh <c>jti</c>, the current instant and <paramref name="nonce"/>.
    /// </summary>
    /// <param name="key">The DPoP key that signs the proof.</param>
    /// <param name="tokenUri">The token endpoint URL.</param>
    /// <param name="nonce">The <c>nonce</c>, or <see langword="null"/> for none.</param>
    /// <returns>The compact proof.</returns>
    private Task<string> BuildRefreshProofAsync(DpopKey key, Uri tokenUri, string? nonce) =>
        ResourceDpopProofs.BuildAsync(
            key, WellKnownHttpMethods.Post, tokenUri.OriginalString, accessToken: null, nonce, TimeProvider.GetUtcNow(),
            TestContext.CancellationToken);


    /// <summary>
    /// Presents <paramref name="refreshToken"/> at the token endpoint over the wire, carrying <paramref name="proof"/> in
    /// its one <c>DPoP</c> field or no such field when it is <see langword="null"/>.
    /// </summary>
    /// <param name="hosted">The hosted server whose client sends the request.</param>
    /// <param name="tokenUri">The token endpoint URL.</param>
    /// <param name="refreshToken">The refresh token presented.</param>
    /// <param name="proof">The DPoP proof, or <see langword="null"/> for none.</param>
    /// <returns>The whole response.</returns>
    private async Task<HttpResponseData> PostRefreshAsync(
        HostedAuthorizationServer hosted, Uri tokenUri, string refreshToken, string? proof)
    {
        OutgoingHeaders headers = proof switch
        {
            null => OutgoingHeaders.Empty,
            _ => OutgoingHeaders.Empty.WithDpop(proof)
        };

        return await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, refreshToken),
            headers, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// A profile that does NOT require DPoP (<see cref="PolicyProfile.Rfc6749WithPkce"/>), holding a
    /// DPoP-BOUND refresh token established by voluntarily presenting a proof at code redemption: a
    /// valid proof WITHOUT the server's nonce, at REFRESH, is CHALLENGED identically for the bound
    /// live token and an unknown one — the single server nonce policy applies whatever the profile
    /// or the record says. The live token is unconsumed: a proof carrying the supplied nonce
    /// succeeds.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 §8</see>.
    /// </summary>
    [TestMethod]
    public async Task OptionalProfileBoundRefreshWithProofWithoutNonceAnswersTheSameChallengeForAnUnknownAndALiveTokenAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration, RedirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId,
            browserClient, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        AuthorizationCodeReceivedState callbackState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        Uri tokenUri = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> proofKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey redemptionProofKey = new(proofKeys, WellKnownJwaValues.Es256);
        try
        {
            async Task<string> BuildProofAsync(string? nonce) =>
                await DpopProofConstruction.BuildAsync(
                    new DpopProofClaims
                    {
                        Htm = WellKnownHttpMethods.Post,
                        Htu = tokenUri.OriginalString,
                        Iat = TimeProvider.GetUtcNow(),
                        Jti = Guid.NewGuid().ToString("N"),
                        Nonce = nonce
                    },
                    redemptionProofKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
                    MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
                    TestContext.CancellationToken).ConfigureAwait(false);

            Dictionary<string, string> tokenFields = RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, callbackState.Code, callbackState.Pkce.EncodedVerifier, callbackState.RedirectUri.OriginalString);

            //Establish the bound refresh token: a voluntary proof at redemption, challenged once
            //(the single server nonce policy) then retried with the supplied nonce.
            string firstProof = await BuildProofAsync(nonce: null).ConfigureAwait(false);
            HttpResponseData challenge = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, tokenFields,
                OutgoingHeaders.Empty.WithDpop(firstProof), TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, challenge.StatusCode, challenge.Body);
            Assert.Contains(OAuthErrors.UseDpopNonce, challenge.Body, StringComparison.Ordinal);
            string codeNonce = challenge.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce)
                ?? throw new AssertFailedException("The use_dpop_nonce challenge must carry a DPoP-Nonce header.");

            string retryProof = await BuildProofAsync(codeNonce).ConfigureAwait(false);
            HttpResponseData redemption = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, tokenFields,
                OutgoingHeaders.Empty.WithDpop(retryProof), TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, redemption.StatusCode, redemption.Body);

            using JsonDocument doc = JsonDocument.Parse(redemption.Body);
            Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP,
                doc.RootElement.GetProperty(OAuthRequestParameterNames.TokenType).GetString(),
                "The voluntary proof at redemption must bind the issuance even though the profile does not mandate it.");
            string boundRefreshToken = doc.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!;

            //Installed only after the bound refresh token above is established, so the storage
            //activity under observation is exactly the nonce challenge under test, never the code
            //redemption that preceded it.
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                hosted.InstallObservedStorage(candidateIntegration, hosted);
            }).ConfigureAwait(false);

            //The shape under test: a valid proof at REFRESH carrying NO nonce, for the bound live
            //token and for an unknown one — the single server nonce policy challenges both alike.
            int beforeLive = hosted.StorageObservations.Count;
            string liveNoNonceProof = await BuildProofAsync(nonce: null).ConfigureAwait(false);
            HttpResponseData liveResponse = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, boundRefreshToken),
                OutgoingHeaders.Empty.WithDpop(liveNoNonceProof), TestContext.CancellationToken).ConfigureAwait(false);
            hosted.AssertNoFlowStateStoreOperationTouched(beforeLive, "shape 6 (the optional-profile nonce challenge) at a bound live refresh token");

            int beforeUnknown = hosted.StorageObservations.Count;
            string unknownNoNonceProof = await BuildProofAsync(nonce: null).ConfigureAwait(false);
            HttpResponseData unknownResponse = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, "unknown-refresh-token-value"),
                OutgoingHeaders.Empty.WithDpop(unknownNoNonceProof), TestContext.CancellationToken).ConfigureAwait(false);
            hosted.AssertNoFlowStateStoreOperationTouched(beforeUnknown, "shape 6 (the optional-profile nonce challenge) at an unknown refresh token");

            Assert.AreEqual(400, liveResponse.StatusCode, liveResponse.Body);
            Assert.Contains(OAuthErrors.UseDpopNonce, liveResponse.Body, StringComparison.Ordinal);
            string? liveRefreshNonce = liveResponse.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce);
            Assert.IsFalse(string.IsNullOrEmpty(liveRefreshNonce), "The challenge must carry a non-empty DPoP-Nonce header.");
            Assert.AreEqual(liveResponse.StatusCode, unknownResponse.StatusCode);
            Assert.AreEqual(liveResponse.Body, unknownResponse.Body,
                "A DPoP-bound refresh token and an unknown one must answer byte-identically to a nonce-less proof.");
            string? unknownRefreshNonce = unknownResponse.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce);
            Assert.IsFalse(string.IsNullOrEmpty(unknownRefreshNonce),
                "The challenge must carry a non-empty DPoP-Nonce header for an unknown token too.");

            //The live token is unconsumed: a proof carrying the supplied nonce succeeds — the
            //SUCCESSFUL control proving the storage instrumentation above is actually connected.
            int beforeSuccess = hosted.StorageObservations.Count;
            string retryRefreshProof = await BuildProofAsync(liveRefreshNonce).ConfigureAwait(false);
            HttpResponseData refreshSuccess = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, boundRefreshToken),
                OutgoingHeaders.Empty.WithDpop(retryRefreshProof), TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, refreshSuccess.StatusCode, refreshSuccess.Body);
            //A correct, DPoP-BOUND presentation touches storage at least once for the grant AND at
            //least once (in fact twice — the read plus the post-save self-check) for the retried
            //proof's own jti replay guard, which shares the SAME "correlate"/"load"-labelled
            //delegates as the grant store (see AssertNoFlowStateStoreOperationTouched's remarks) —
            //so a bare non-zero check, not an exact count, is what this control can honestly prove.
            var successOps = hosted.StorageObservations.Skip(beforeSuccess).Select(entry => entry.Operation).ToList();
            Assert.Contains("correlate", successOps,
                "A correct presentation must correlate storage at least once (the grant, and the retried proof's own jti).");
            Assert.Contains("load", successOps,
                "A correct presentation must load storage at least once (the grant record).");
        }
        finally
        {
            proofKeys.PublicKey.Dispose();
            proofKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449, Section 11.1</see>: "In order to
    /// guard against memory exhaustion attacks, a server that is tracking jti values should reject DPoP proof JWTs
    /// with unnecessarily large jti values or store only a hash thereof." Beside that length rule, this library
    /// refuses a <c>jti</c> holding a character of the Unicode general category Cc before the replay store is read
    /// or written, since the application's store may not hold such a character; the character rule is this
    /// library's policy, not a rule of the text. At REFRESH, whose DPoP proof the token endpoint validates before it
    /// correlates the stored refresh token, a valid proof carrying the server's nonce and a <c>jti</c> holding U+0000
    /// is answered 400 with <c>invalid_dpop_proof</c> and the one description every DPoP endpoint of the library
    /// gives that refusal (naming the empty, the over-long and the unstorable <c>jti</c>), and the store
    /// observation records no flow-state store call. The refresh token is unconsumed: a proof with an ordinary
    /// <c>jti</c> then refreshes it with 200, and the observation sees the replay guard read, save, read back and
    /// claim its record.
    /// </summary>
    [TestMethod]
    public async Task ADpopProofAtRefreshWhoseJtiCarriesAControlCharacterIsRefusedBeforeAnyStoreCallAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration, RedirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId,
            browserClient, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        AuthorizationCodeReceivedState callbackState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        Uri tokenUri = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> proofKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey proofKey = new(proofKeys, WellKnownJwaValues.Es256);
        try
        {
            async Task<HttpResponseData> PostWithProofAsync(Dictionary<string, string> fields, string? nonce, string jti)
            {
                string proof = await DpopProofConstruction.BuildAsync(
                    new DpopProofClaims
                    {
                        Htm = WellKnownHttpMethods.Post,
                        Htu = tokenUri.OriginalString,
                        Iat = TimeProvider.GetUtcNow(),
                        Jti = jti,
                        Nonce = nonce
                    },
                    proofKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
                    MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
                    TestContext.CancellationToken).ConfigureAwait(false);

                return await HttpClientTransport.SendFormPostAsync(
                    hosted.SharedHttpClient!, tokenUri, fields,
                    OutgoingHeaders.Empty.WithDpop(proof), TestContext.CancellationToken).ConfigureAwait(false);
            }

            //Establish the bound refresh token: a voluntary proof at redemption, challenged once for the server's
            //nonce, then retried with it.
            Dictionary<string, string> tokenFields = RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, callbackState.Code, callbackState.Pkce.EncodedVerifier, callbackState.RedirectUri.OriginalString);
            HttpResponseData challenge = await PostWithProofAsync(tokenFields, nonce: null, "jti-redemption-challenge").ConfigureAwait(false);
            Assert.AreEqual(400, challenge.StatusCode, challenge.Body);
            Assert.Contains(OAuthErrors.UseDpopNonce, challenge.Body, StringComparison.Ordinal);
            string serverNonce = challenge.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce)
                ?? throw new AssertFailedException("The use_dpop_nonce challenge must carry a DPoP-Nonce header.");

            HttpResponseData redemption = await PostWithProofAsync(tokenFields, serverNonce, "jti-redemption").ConfigureAwait(false);
            Assert.AreEqual(200, redemption.StatusCode, redemption.Body);
            using JsonDocument redemptionDocument = JsonDocument.Parse(redemption.Body);
            string boundRefreshToken = redemptionDocument.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!;

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                hosted.InstallObservedStorage(candidateIntegration, hosted);
            }).ConfigureAwait(false);
            Dictionary<string, string> refreshFields = RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, boundRefreshToken);

            int beforeRefusal = hosted.StorageObservations.Count;
            HttpResponseData refused = await PostWithProofAsync(
                refreshFields, serverNonce, string.Concat("jti-", ((char)0x0000).ToString(), "-value")).ConfigureAwait(false);
            List<string> refusalOperations = [.. hosted.StorageObservations.Skip(beforeRefusal).Select(static entry => entry.Operation)];

            Assert.AreEqual(400, refused.StatusCode, refused.Body);
            using JsonDocument refusedDocument = JsonDocument.Parse(refused.Body);
            Assert.AreEqual("invalid_dpop_proof", refusedDocument.RootElement.GetProperty("error").GetString());
            Assert.AreEqual(
                "DPoP proof jti is empty, too long or carries a character the replay guard cannot store.",
                refusedDocument.RootElement.GetProperty("error_description").GetString());
            Assert.IsEmpty(refusalOperations,
                $"The refused jti must never reach the store; it observed: {string.Join(", ", refusalOperations)}.");

            int beforeAcceptance = hosted.StorageObservations.Count;
            HttpResponseData refreshed = await PostWithProofAsync(refreshFields, serverNonce, "jti-refresh").ConfigureAwait(false);
            List<string> acceptanceOperations = [.. hosted.StorageObservations.Skip(beforeAcceptance).Select(static entry => entry.Operation)];

            Assert.AreEqual(200, refreshed.StatusCode, refreshed.Body);
            Assert.IsTrue(HostedAuthorizationServer.IsReplayGuardFirstUseObserved(acceptanceOperations),
                $"The store observation must see the replay guard's read, save, read-back and claim; it observed: {string.Join(", ", acceptanceOperations)}.");
        }
        finally
        {
            proofKeys.PublicKey.Dispose();
            proofKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// A profile that does NOT require DPoP (<see cref="PolicyProfile.Rfc6749WithPkce"/>), holding a
    /// DPoP-BOUND refresh token established by voluntarily presenting a proof at code redemption,
    /// presented at REFRESH with NO proof at all: <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC
    /// 9449 §5</see> names no error for a missing proof — its binding-MUST-be-validated sentence
    /// governs a proof that IS presented — and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 §8</see> governs a
    /// proof presented WITHOUT the server's nonce, not a request presenting no proof at all. The
    /// grant presented without its key answers the same body an unknown refresh token does, never
    /// a nonce challenge that would itself prove the binding exists.
    /// </summary>
    [TestMethod]
    public async Task OptionalProfileBoundRefreshWithNoProofAtAllAnswersTheEndpointConstantForAnUnknownAndALiveTokenAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration, RedirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId,
            browserClient, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        AuthorizationCodeReceivedState callbackState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        Uri tokenUri = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> proofKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey redemptionProofKey = new(proofKeys, WellKnownJwaValues.Es256);
        try
        {
            async Task<string> BuildProofAsync(string? nonce) =>
                await DpopProofConstruction.BuildAsync(
                    new DpopProofClaims
                    {
                        Htm = WellKnownHttpMethods.Post,
                        Htu = tokenUri.OriginalString,
                        Iat = TimeProvider.GetUtcNow(),
                        Jti = Guid.NewGuid().ToString("N"),
                        Nonce = nonce
                    },
                    redemptionProofKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
                    MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
                    TestContext.CancellationToken).ConfigureAwait(false);

            Dictionary<string, string> tokenFields = RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, callbackState.Code, callbackState.Pkce.EncodedVerifier, callbackState.RedirectUri.OriginalString);

            //Establish the bound refresh token: a voluntary proof at redemption, challenged once
            //(the single server nonce policy) then retried with the supplied nonce.
            string firstProof = await BuildProofAsync(nonce: null).ConfigureAwait(false);
            HttpResponseData challenge = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, tokenFields,
                OutgoingHeaders.Empty.WithDpop(firstProof), TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, challenge.StatusCode, challenge.Body);
            Assert.Contains(OAuthErrors.UseDpopNonce, challenge.Body, StringComparison.Ordinal);
            string codeNonce = challenge.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce)
                ?? throw new AssertFailedException("The use_dpop_nonce challenge must carry a DPoP-Nonce header.");

            string retryProof = await BuildProofAsync(codeNonce).ConfigureAwait(false);
            HttpResponseData redemption = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, tokenFields,
                OutgoingHeaders.Empty.WithDpop(retryProof), TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, redemption.StatusCode, redemption.Body);

            using JsonDocument doc = JsonDocument.Parse(redemption.Body);
            Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP,
                doc.RootElement.GetProperty(OAuthRequestParameterNames.TokenType).GetString(),
                "The voluntary proof at redemption must bind the issuance even though the profile does not mandate it.");
            string boundRefreshToken = doc.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!;

            //The shape under test: NO DPoP header at all, for the bound live token and for an
            //unknown one. The record's own binding requirement must not turn into a distinguishable
            //answer for a request the registration's profile does not itself require DPoP on.
            HttpResponseData liveResponse = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, boundRefreshToken),
                OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);
            HttpResponseData unknownResponse = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, "unknown-refresh-token-value"),
                OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(400, liveResponse.StatusCode, liveResponse.Body);
            Assert.Contains(OAuthErrors.InvalidGrant, liveResponse.Body, StringComparison.Ordinal);
            Assert.AreEqual(liveResponse.StatusCode, unknownResponse.StatusCode);
            Assert.AreEqual(liveResponse.Body, unknownResponse.Body,
                "A DPoP-bound refresh token presented with no proof at all, under a profile that does not "
                + "require DPoP, must answer identically to a refresh_token that was never issued.");
            Assert.IsNull(liveResponse.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce),
                "The collapsed refusal must not issue a nonce challenge — doing so would itself prove the "
                + "record's binding.");
        }
        finally
        {
            proofKeys.PublicKey.Dispose();
            proofKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// A valid DPoP proof — well-formed, correctly signed, carrying the server's own nonce — for a
    /// key OTHER than the one a LIVE (unrotated) refresh token is bound to answers the same body an
    /// unknown refresh token does, never <c>invalid_dpop_proof</c> text of its own:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 §5</see> prescribes
    /// <c>invalid_dpop_proof</c> for an INVALID proof — already answered before correlation, in
    /// the pre-correlation step — and prescribes nothing for a valid proof bound to the wrong key.
    /// </summary>
    [TestMethod]
    public async Task LiveBoundRefreshWithAValidProofForAnUnrelatedKeyAnswersTheEndpointConstantForAnUnknownAndALiveTokenAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult parResult = await fixture.Client.AuthCode.StartParAsync(
            fixture.Registration, RedirectUri, OAuthFormEncodedFieldsFixtures.OpenIdScope, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"Expected PAR to yield a redirect. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        string flowId = fixture.ClientFlowStore.Keys.Single();
        ParCompletedState parCompleted = (ParCompletedState)fixture.ClientFlowStore[flowId];

        HostedAuthorizationServer hosted = host.Host("default");
        Uri authorizeUri = new(hosted.HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, material.Registration.TenantId.Value)
            + "?client_id=" + Uri.EscapeDataString(ClientId)
            + "&request_uri=" + Uri.EscapeDataString(parCompleted.Par.RequestUri.ToString()));
        using HttpResponseMessage authorizeResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, authorizeUri, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, (int)authorizeResponse.StatusCode);
        string location = authorizeResponse.Headers.Location!.OriginalString;
        string code = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Code)
            ?? throw new AssertFailedException("Authorize redirect missing code.");
        string? iss = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Iss);

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

        AuthCodeFlowEndpointResult tokenResult = await fixture.Client.AuthCode.ExchangeTokenAsync(
            fixture.Registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Expected token issuance success. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
        string liveRefreshToken = (string)tokenResult.Body![OAuthRequestParameterNames.RefreshToken];

        string segment = material.Registration.TenantId.Value;
        Uri tokenUri = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);

        var attackerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey attackerKey = new(attackerKeys, WellKnownJwaValues.Es256);

            async Task<string> BuildAttackerProofAsync(string? refreshTokenValue, string? nonce) =>
                await DpopProofConstruction.BuildAsync(
                    new DpopProofClaims
                    {
                        Htm = WellKnownHttpMethods.Post,
                        Htu = tokenUri.OriginalString,
                        Iat = TimeProvider.GetUtcNow(),
                        Jti = Guid.NewGuid().ToString("N"),
                        Nonce = nonce
                    },
                    attackerKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
                    MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
                    TestContext.CancellationToken).ConfigureAwait(false);

            //A currently-valid nonce isolates the thumbprint compare: without one, a missing nonce
            //alone would refuse this request for an unrelated reason and the test would not notice
            //the thumbprint check being gone. DpopTokenEndpointValidation checks the bound
            //thumbprint AFTER the nonce, so a real nonce must be obtained first for each token.
            string livePreNonceProof = await BuildAttackerProofAsync(liveRefreshToken, nonce: null).ConfigureAwait(false);
            HttpResponseData liveChallenge = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, liveRefreshToken),
                OutgoingHeaders.Empty.WithDpop(livePreNonceProof), TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, liveChallenge.StatusCode, liveChallenge.Body);
            Assert.Contains(OAuthErrors.UseDpopNonce, liveChallenge.Body, StringComparison.Ordinal);
            string liveNonce = liveChallenge.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce)
                ?? throw new AssertFailedException("The use_dpop_nonce challenge must carry a DPoP-Nonce header.");

            string liveAttackerProof = await BuildAttackerProofAsync(liveRefreshToken, liveNonce).ConfigureAwait(false);
            HttpResponseData liveResponse = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, liveRefreshToken),
                OutgoingHeaders.Empty.WithDpop(liveAttackerProof), TestContext.CancellationToken).ConfigureAwait(false);

            const string UnknownRefreshToken = "unknown-refresh-token-value";
            string unknownPreNonceProof = await BuildAttackerProofAsync(UnknownRefreshToken, nonce: null).ConfigureAwait(false);
            HttpResponseData unknownChallenge = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, UnknownRefreshToken),
                OutgoingHeaders.Empty.WithDpop(unknownPreNonceProof), TestContext.CancellationToken).ConfigureAwait(false);
            string unknownNonce = unknownChallenge.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce)
                ?? throw new AssertFailedException("Expected a use_dpop_nonce challenge for the unknown token too.");
            string unknownAttackerProof = await BuildAttackerProofAsync(UnknownRefreshToken, unknownNonce).ConfigureAwait(false);
            HttpResponseData unknownResponse = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, UnknownRefreshToken),
                OutgoingHeaders.Empty.WithDpop(unknownAttackerProof), TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(400, liveResponse.StatusCode, liveResponse.Body);
            Assert.Contains(OAuthErrors.InvalidGrant, liveResponse.Body, StringComparison.Ordinal);
            Assert.AreEqual(liveResponse.StatusCode, unknownResponse.StatusCode);
            Assert.AreEqual(liveResponse.Body, unknownResponse.Body,
                "A valid DPoP proof for a key other than the one a live refresh token is bound to must "
                + "answer identically to a refresh_token that was never issued.");

            //The live refresh token is unconsumed: it still rotates with its own bound key's proof.
            string liveRetryProof = await DpopProofConstruction.BuildAsync(
                new DpopProofClaims
                {
                    Htm = WellKnownHttpMethods.Post,
                    Htu = tokenUri.OriginalString,
                    Iat = TimeProvider.GetUtcNow(),
                    Jti = Guid.NewGuid().ToString("N"),
                    Nonce = liveNonce
                },
                fixture.DpopKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
                TestContext.CancellationToken).ConfigureAwait(false);
            HttpResponseData liveRetryResponse = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, liveRefreshToken),
                OutgoingHeaders.Empty.WithDpop(liveRetryProof), TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, liveRetryResponse.StatusCode, liveRetryResponse.Body,
                "The wrong-key presentation must not have consumed or revoked the live refresh token.");
        }
        finally
        {
            attackerKeys.PublicKey.Dispose();
            attackerKeys.PrivateKey.Dispose();
        }
    }
}
