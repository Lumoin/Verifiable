using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Time.Testing;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Real-wire capstone for the Authorization Code + PAR + PKCE family (contract decision 5): every
/// leg — PAR, the browser's authorize GET, the callback, token exchange, refresh, and revocation —
/// crosses a real loopback socket, composed via <see cref="TestHostShell.CreateOAuthClientAndRegistrationAsync"/>
/// and <see cref="AuthCodeClient.StartParAsync"/> / <see cref="AuthCodeClient.HandleCallbackAsync"/> /
/// <see cref="AuthCodeClient.ExchangeTokenAsync"/> exactly as <see cref="IdJagGrantTests"/> and
/// <see cref="HttpWireFidelityTests"/> compose the HTTP-backed factory. <see cref="AuthCodeFlowTests"/>
/// keeps the hand-mocked delegate as unit coverage; this class never calls it.
/// </summary>
[TestClass]
internal sealed class AuthCodeParPkceRealWireFlowTests
{
    /// <summary>
    /// MSTest's per-test context, supplying the <see cref="System.Threading.CancellationToken"/> every
    /// socket call in this capstone runs under.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The clock the host and the client share, so PAR/token lifetime checks and the client's own
    /// timestamps agree on the current instant.
    /// </summary>
    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    /// <summary>
    /// The client identifier registered with the host and carried on every leg of the journey — PAR,
    /// authorize, callback, token, refresh, and revocation.
    /// </summary>
    private const string ClientId = "https://client.example.com";

    /// <summary>
    /// The authenticated end-user identifier the authorize step asserts, read off the wire via
    /// <see cref="AuthorizationServerHttpApplication.TestSubjectHeaderName"/>.
    /// </summary>
    private const string SubjectId = "subject-real-wire-authcode-01";

    /// <summary>
    /// <see cref="ClientId"/> as a <see cref="Uri"/>, the shape
    /// <see cref="TestHostShell.RegisterDpopClient"/> requires for client registration.
    /// </summary>
    private static Uri ClientBaseUri { get; } = new(ClientId);

    /// <summary>
    /// The client's registered redirect URI. The callback step reads the authorization code and
    /// <c>state</c> off this exact origin's query string.
    /// </summary>
    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

    /// <summary>
    /// The capabilities the client registration needs to exercise every leg of the journey: the
    /// authorization code grant, pushed authorization requests, refresh tokens, and revocation.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> Capabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OAuthRefreshToken,
            WellKnownCapabilityIdentifiers.OAuthTokenRevocation);


    /// <summary>
    /// The full PAR -> authorize -> callback -> token -> refresh -> revocation journey. PAR, token
    /// exchange, refresh, and revocation POST through <see cref="HttpClientTransport"/> against the
    /// Kestrel-bound <see cref="HostedAuthorizationServer.SharedHttpClient"/>; the authorize step is a
    /// genuine <see cref="HttpClient"/> GET with auto-redirect disabled so the 302 <c>Location</c> is
    /// read off the wire instead of being followed toward the (unreachable) client callback origin.
    /// The only configured client transport is the socket-backed one, so stopping the Kestrel listener
    /// would fail every leg with a connection error rather than a protocol error.
    /// </summary>
    [TestMethod]
    public async Task FullJourneyReachesTokenRefreshAndRevocation()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);

        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);
        host.Server.OAuth().RevokeTokenAsync = static (_, _, _, _, _) =>
            ValueTask.CompletedTask;

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        string flowId = await DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, host.ServerCertificate, TestContext.CancellationToken)
            .ConfigureAwait(false);

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Token exchange must succeed over the real wire. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
        string accessToken = (string)tokenResult.Body![OAuthRequestParameterNames.AccessToken];
        string refreshToken = (string)tokenResult.Body[OAuthRequestParameterNames.RefreshToken];
        Assert.IsFalse(string.IsNullOrEmpty(accessToken));
        Assert.IsFalse(string.IsNullOrEmpty(refreshToken));

        AuthCodeFlowEndpointResult refreshResult = await client.AuthCode.RefreshAsync(
            registration,
            new RefreshTokenRequest { ClientId = ClientId, RefreshToken = refreshToken },
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, refreshResult.Outcome,
            $"Refresh must succeed over the real wire. ErrorCode={refreshResult.ErrorCode} ErrorDescription={refreshResult.ErrorDescription}");
        string refreshedAccessToken = (string)refreshResult.Body![OAuthRequestParameterNames.AccessToken];
        Assert.IsFalse(string.IsNullOrEmpty(refreshedAccessToken));
        Assert.AreNotEqual(accessToken, refreshedAccessToken,
            "The refresh grant must mint a fresh access token, not echo the original.");

        AuthCodeFlowEndpointResult revokeResult = await client.AuthCode.RevokeAsync(
            registration,
            new OAuthFormEncodedFields(new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.Token] = refreshedAccessToken
            }),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, revokeResult.Outcome,
            $"Revocation must succeed over the real wire. ErrorCode={revokeResult.ErrorCode} ErrorDescription={revokeResult.ErrorDescription}");
    }


    /// <summary>
    /// RFC 9700 §2.1 PKCE downgrade defense negative: the client presents a wrong <c>code_verifier</c>
    /// at token exchange. The Authorization Server recomputes <c>SHA256(code_verifier)</c> and compares
    /// it to the challenge captured at PAR time; the mismatch fails the real-wire token POST with the
    /// exact <c>invalid_grant</c> error — never a weaker or generic failure.
    /// </summary>
    [TestMethod]
    public async Task WrongPkceVerifierAtTokenExchangeIsInvalidGrant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        string flowId = await DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, host.ServerCertificate, TestContext.CancellationToken)
            .ConfigureAwait(false);

        //Tamper the persisted verifier so token exchange presents a code_verifier that does not hash
        //to the challenge sent at PAR time — the flow record is client-side state, not wire bytes, so
        //rewriting it here models an implementation bug or a stolen-code replay by a party that never
        //held the true verifier.
        AuthorizationCodeReceivedState receivedState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];
        clientFlowStore[flowId] = receivedState with
        {
            Pkce = receivedState.Pkce with
            {
                EncodedVerifier = "wrong0000000000000000000000000000000000000"
            }
        };

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, tokenResult.Outcome,
            $"A wrong code_verifier must fail token exchange. Body={tokenResult.Body}");
        Assert.AreEqual(OAuthErrors.InvalidGrant, tokenResult.ErrorCode);
    }


    /// <summary>
    /// Drives PAR (a real wire POST), the browser's authorize GET (a real wire GET with auto-redirect
    /// disabled and the test subject header standing in for an authenticated session), and the
    /// callback (a client-local state transition over the extracted <c>code</c>/<c>state</c>/<c>iss</c>).
    /// Returns the flow identifier ready for token exchange.
    /// </summary>
    private static async Task<string> DriveParAuthorizeAndCallbackAsync(
        HostedAuthorizationServer hosted,
        OAuthClient client,
        ClientRegistration registration,
        Dictionary<string, FlowState> clientFlowStore,
        string segment,
        X509Certificate2 pinnedCertificate,
        CancellationToken cancellationToken)
    {
        AuthCodeFlowEndpointResult parResult = await client.AuthCode.StartParAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, cancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"PAR must redirect over the real wire. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        string flowId = clientFlowStore.Keys.Single();
        ParCompletedState parState = (ParCompletedState)clientFlowStore[flowId];

        Uri authorizeUrl = new(
            hosted.HttpBaseAddress!,
            $"{TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment)}" +
            $"?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(ClientId)}" +
            $"&{OAuthRequestParameterNames.RequestUri}={Uri.EscapeDataString(parState.Par.RequestUri.ToString())}");

        //A fresh pinned, no-redirect client for the browser leg: the same certificate the shell's
        //SharedHttpClient pins, so this genuine HTTPS GET succeeds without trusting a CA, and with
        //auto-redirect disabled so the 302 Location is read off the wire instead of being followed.
        using HttpClientHandler noRedirectHandler = LoopbackTls.CreatePinnedHandler(pinnedCertificate);
        noRedirectHandler.AllowAutoRedirect = false;
        using HttpClient browserClient = new(noRedirectHandler) { BaseAddress = hosted.HttpBaseAddress };
        using HttpRequestMessage authorizeRequest = new(HttpMethod.Get, authorizeUrl);
        authorizeRequest.Headers.Add(AuthorizationServerHttpApplication.TestSubjectHeaderName, SubjectId);

        using HttpResponseMessage authorizeResponse = await browserClient
            .SendAsync(authorizeRequest, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, (int)authorizeResponse.StatusCode,
            "The authorize endpoint must redirect with the authorization code.");

        string location = authorizeResponse.Headers.Location!.ToString();
        string code = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Code)
            ?? throw new InvalidOperationException("Authorize redirect Location missing code.");
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

        AuthCodeFlowEndpointResult callbackResult = await client.AuthCode.HandleCallbackAsync(
            registration, new OAuthFormEncodedFields(callbackFields), cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, callbackResult.Outcome,
            $"Callback must succeed. ErrorCode={callbackResult.ErrorCode} ErrorDescription={callbackResult.ErrorDescription}");

        return flowId;
    }
}
