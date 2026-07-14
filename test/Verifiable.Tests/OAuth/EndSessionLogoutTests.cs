using System.Collections.Immutable;
using System.Linq;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Metadata;
using Verifiable.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// OIDC RP-Initiated Logout 1.0 — the <c>end_session_endpoint</c> end-to-end. A real
/// auth-code flow issues an ID Token (carrying the Slice-3 <c>sid</c>); the RP then
/// redirects the User Agent to the end-session endpoint with that token as
/// <c>id_token_hint</c>. The OP verifies the hint (signature + issuer, <em>not</em>
/// <c>exp</c>), validates <c>post_logout_redirect_uri</c> against the client's registered
/// set, terminates the session via <see cref="TerminateSessionDelegate"/>, and redirects
/// with <c>state</c> echoed. Firewalled: the hint is the actual wire token.
/// </summary>
[TestClass]
internal sealed class EndSessionLogoutTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so issued artefacts are reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://client.example.com";
    private const string SubjectId = "subject-logout-1";
    private static readonly Uri ClientBaseUri = new("https://client.example.com");
    private static readonly Uri RedirectUri = new("https://client.example.com/callback");

    /// <summary>The post-logout URI TestHostShell registers for DPoP clients.</summary>
    private const string RegisteredPostLogout = "https://client.example.com/post-logout";

    /// <summary>DPoP-client defaults plus the RP-Initiated Logout capability.</summary>
    private static readonly ImmutableHashSet<CapabilityIdentifier> LogoutCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OidcRpInitiatedLogout,
            WellKnownCapabilityIdentifiers.OidcBackChannelLogout);


    /// <summary>
    /// Happy path: valid <c>id_token_hint</c> + registered <c>post_logout_redirect_uri</c>
    /// → session terminated with the right sub/sid + 302 redirect with <c>state</c> echoed.
    /// </summary>
    [TestMethod]
    public async Task EndSessionTerminatesAndRedirectsWithState()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities);

        List<(string Subject, string? SessionId)> terminated = [];
        host.Server.OAuth().TerminateSessionAsync = (sub, sid, _, _, _) =>
        {
            terminated.Add((sub, sid));
            return ValueTask.CompletedTask;
        };

        string idToken = await IssueIdTokenAsync(host, material, "session-A").ConfigureAwait(false);

        ServerHttpResponse response = await EndSessionAsync(host, material, new RequestFields
        {
            [OAuthRequestParameterNames.IdTokenHint] = idToken,
            [OAuthRequestParameterNames.PostLogoutRedirectUri] = RegisteredPostLogout,
            [OAuthRequestParameterNames.State] = "xyz"
        }).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode, response.Body);
        Assert.AreEqual($"{RegisteredPostLogout}?state=xyz", response.Location);
        Assert.HasCount(1, terminated, "The session must be terminated exactly once.");
        Assert.AreEqual(SubjectId, terminated[0].Subject);
        Assert.AreEqual("session-A", terminated[0].SessionId,
            "The sid extracted from the id_token_hint must reach the terminate seam.");
    }


    /// <summary>No <c>post_logout_redirect_uri</c> → 200 logged-out, session still terminated.</summary>
    [TestMethod]
    public async Task EndSessionWithoutRedirectUriReturns200AndTerminates()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities);

        bool terminated = false;
        host.Server.OAuth().TerminateSessionAsync = (_, _, _, _, _) =>
        {
            terminated = true;
            return ValueTask.CompletedTask;
        };

        string idToken = await IssueIdTokenAsync(host, material, "session-A").ConfigureAwait(false);

        ServerHttpResponse response = await EndSessionAsync(host, material, new RequestFields
        {
            [OAuthRequestParameterNames.IdTokenHint] = idToken
        }).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.IsTrue(terminated, "Logout must happen even without a redirect URI.");
    }


    /// <summary>
    /// An unregistered <c>post_logout_redirect_uri</c> → 400, no redirect, and the
    /// session is NOT terminated (validation precedes the terminate drop-out).
    /// </summary>
    [TestMethod]
    public async Task EndSessionRejectsUnregisteredPostLogoutRedirectUri()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities);

        bool terminated = false;
        host.Server.OAuth().TerminateSessionAsync = (_, _, _, _, _) =>
        {
            terminated = true;
            return ValueTask.CompletedTask;
        };

        string idToken = await IssueIdTokenAsync(host, material, "session-A").ConfigureAwait(false);

        ServerHttpResponse response = await EndSessionAsync(host, material, new RequestFields
        {
            [OAuthRequestParameterNames.IdTokenHint] = idToken,
            [OAuthRequestParameterNames.PostLogoutRedirectUri] = "https://evil.example/cb"
        }).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.IsNull(response.Location);
        Assert.IsFalse(terminated, "An unregistered redirect URI must be rejected before terminating.");
    }


    /// <summary>
    /// A tampered <c>id_token_hint</c> (not validly signed by this AS) → 400, no
    /// termination — the OP only acts on a hint it can verify it issued.
    /// </summary>
    [TestMethod]
    public async Task EndSessionRejectsTamperedHint()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities);

        bool terminated = false;
        host.Server.OAuth().TerminateSessionAsync = (_, _, _, _, _) =>
        {
            terminated = true;
            return ValueTask.CompletedTask;
        };

        string idToken = await IssueIdTokenAsync(host, material, "session-A").ConfigureAwait(false);

        //Flip a middle character of the signature segment — it stays base64url-valid, so the id_token
        //decodes cleanly and the signature simply fails to verify (a deterministic rejection, not an
        //incidental decode failure on a non-canonical final character).
        int signatureStart = idToken.LastIndexOf('.') + 1;
        int tamperIndex = signatureStart + (idToken.Length - signatureStart) / 2;
        char flipped = idToken[tamperIndex] == 'A' ? 'B' : 'A';
        string tampered = string.Concat(idToken.AsSpan(0, tamperIndex), flipped.ToString(), idToken.AsSpan(tamperIndex + 1));

        ServerHttpResponse response = await EndSessionAsync(host, material, new RequestFields
        {
            [OAuthRequestParameterNames.IdTokenHint] = tampered,
            [OAuthRequestParameterNames.PostLogoutRedirectUri] = RegisteredPostLogout
        }).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.IsFalse(terminated, "A hint that does not verify must not terminate a session.");
    }


    /// <summary>
    /// RP-Initiated Logout §3: an EXPIRED <c>id_token_hint</c> is still accepted —
    /// logging out a session whose ID Token has expired is valid. The clock is advanced
    /// well past the token's <c>exp</c> before the logout call.
    /// </summary>
    [TestMethod]
    public async Task EndSessionAcceptsExpiredHint()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities);

        bool terminated = false;
        host.Server.OAuth().TerminateSessionAsync = (_, _, _, _, _) =>
        {
            terminated = true;
            return ValueTask.CompletedTask;
        };

        string idToken = await IssueIdTokenAsync(host, material, "session-A").ConfigureAwait(false);

        //Advance far beyond any plausible ID Token lifetime.
        TimeProvider.Advance(TimeSpan.FromDays(2));

        ServerHttpResponse response = await EndSessionAsync(host, material, new RequestFields
        {
            [OAuthRequestParameterNames.IdTokenHint] = idToken,
            [OAuthRequestParameterNames.PostLogoutRedirectUri] = RegisteredPostLogout,
            [OAuthRequestParameterNames.State] = "s2"
        }).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode, response.Body);
        Assert.AreEqual($"{RegisteredPostLogout}?state=s2", response.Location);
        Assert.IsTrue(terminated, "An expired id_token_hint must still log the session out (§3).");
    }


    /// <summary>
    /// The "complicated case": an <c>id_token_hint</c> minted through the full
    /// HAIP/DPoP-bound issuance path (PAR → authorize → DPoP-proofed token with the
    /// nonce-challenge retry) still verifies and logs out at the (DPoP-agnostic)
    /// end-session endpoint. Proves the logout path is independent of how the hint was
    /// issued.
    /// </summary>
    [TestMethod]
    public async Task EndSessionAcceptsDpopIssuedHint()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);

        //No explicit profile → HAIP 1.0 default → DPoP enforced at the token endpoint.
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, capabilities: LogoutCapabilities);
        host.EnableDpop();

        List<(string Subject, string? SessionId)> terminated = [];
        host.Server.OAuth().TerminateSessionAsync = (sub, sid, _, _, _) =>
        {
            terminated.Add((sub, sid));
            return ValueTask.CompletedTask;
        };

        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        //PAR with openid scope so the issued response carries an id_token.
        AuthCodeFlowEndpointResult parResult = await fixture.Client.AuthCode.StartParAsync(
            fixture.Registration,
            RedirectUri,
            new OAuthFormEncodedFields(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
            }),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome, parResult.ErrorDescription);

        string flowId = fixture.ClientFlowStore.Keys.Single();
        ParCompletedState parCompleted = (ParCompletedState)fixture.ClientFlowStore[flowId];

        //Authorize (in-process), stamping subject + the per-session sid.
        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);
        authorizeContext.SetSessionId("session-D");
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            new RequestFields
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.RequestUri] = parCompleted.Par.RequestUri.ToString()
            },
            authorizeContext, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        (string code, string? iss) = ParseAuthorizeRedirect(authorizeResponse.Location!);

        //Callback + DPoP-bound token exchange (proof + single nonce-challenge retry).
        AuthCodeFlowEndpointResult callbackResult = await fixture.Client.AuthCode.HandleCallbackAsync(
            fixture.Registration,
            new OAuthFormEncodedFields(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [OAuthRequestParameterNames.Code] = code,
                [OAuthRequestParameterNames.State] = flowId,
                [OAuthRequestParameterNames.Iss] = iss!
            }),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, callbackResult.Outcome, callbackResult.ErrorDescription);

        AuthCodeFlowEndpointResult tokenResult = await fixture.Client.AuthCode.ExchangeTokenAsync(
            fixture.Registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome, tokenResult.ErrorDescription);
        Assert.IsTrue(tokenResult.Body!.TryGetValue("id_token", out object? idTokenObj),
            "DPoP-bound issuance with openid scope must emit an id_token.");
        string idToken = (string)idTokenObj!;

        //Log out with the DPoP-issued ID token as the hint — end_session itself is
        //DPoP-agnostic (no token is presented at logout).
        ServerHttpResponse response = await EndSessionAsync(host, material, new RequestFields
        {
            [OAuthRequestParameterNames.IdTokenHint] = idToken,
            [OAuthRequestParameterNames.PostLogoutRedirectUri] = RegisteredPostLogout,
            [OAuthRequestParameterNames.State] = "d1"
        }).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode, response.Body);
        Assert.AreEqual($"{RegisteredPostLogout}?state=d1", response.Location);
        Assert.HasCount(1, terminated);
        Assert.AreEqual(SubjectId, terminated[0].Subject);
        Assert.AreEqual("session-D", terminated[0].SessionId,
            "The sid from a DPoP-issued id_token_hint must reach the terminate seam.");
    }


    /// <summary>Dispatches a GET to the end-session endpoint with the given query fields.</summary>
    /// <summary>
    /// <c>ui_locales</c> is a current (non-legacy) RP-Initiated Logout request parameter,
    /// but the library renders no logout UI, so the only library-supportable surface is the
    /// <c>ui_locales_supported</c> discovery advertisement — contributed by the deployment.
    /// Assert that a contributed <c>ui_locales_supported</c> appears in the served discovery
    /// document alongside the library-emitted <c>end_session_endpoint</c>.
    /// </summary>
    [TestMethod]
    public async Task DiscoveryAdvertisesContributedUiLocalesAndEndSession()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities);

        //Wiring the terminate seam activates the end_session_endpoint candidate (and thus its
        //discovery field); the ui_locales_supported field is app-contributed.
        host.Server.OAuth().TerminateSessionAsync = (_, _, _, _, _) => ValueTask.CompletedTask;
        host.Server.OAuth().ContributeDiscoveryFieldsAsync = static (_, _, _) =>
            ValueTask.FromResult(new DiscoveryDocumentContribution(
                [new DiscoveryStringArrayField(
                    AuthorizationServerMetadataParameterNames.UiLocalesSupported,
                    ["en-US", "fi-FI"])]));

        ServerHttpResponse discovery = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataDiscovery, WellKnownHttpMethods.Get,
            new RequestFields(), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, discovery.StatusCode, discovery.Body);

        using JsonDocument doc = JsonDocument.Parse(discovery.Body!);
        JsonElement uiLocales = doc.RootElement.GetProperty(
            AuthorizationServerMetadataParameterNames.UiLocalesSupported);
        Assert.AreEqual(JsonValueKind.Array, uiLocales.ValueKind);
        Assert.AreEqual("en-US", uiLocales[0].GetString());
        Assert.AreEqual("fi-FI", uiLocales[1].GetString());

        Assert.IsTrue(doc.RootElement.TryGetProperty(
            AuthorizationServerMetadataParameterNames.EndSessionEndpoint, out _),
            "end_session_endpoint is library-emitted when the RP-Initiated Logout capability is active.");
    }


    /// <summary>
    /// §3 sessionless logout: a request carrying an opaque <c>logout_hint</c> (no
    /// <c>id_token_hint</c>) terminates via the by-hint seam when the application wired it.
    /// The library does not interpret the hint — it passes it verbatim to
    /// <see cref="TerminateSessionByHintDelegate"/>. <c>post_logout_redirect_uri</c>
    /// validation and the 302+state response are identical to the id_token_hint path.
    /// </summary>
    [TestMethod]
    public async Task EndSessionTerminatesByLogoutHintWhenSeamWired()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities);

        //The endpoint gate still requires the id_token_hint terminate seam; wire it (unused here).
        host.Server.OAuth().TerminateSessionAsync = (_, _, _, _, _) => ValueTask.CompletedTask;

        List<string> hints = [];
        host.Server.OAuth().TerminateSessionByHintAsync = (hint, _, _, _) =>
        {
            hints.Add(hint);
            return ValueTask.CompletedTask;
        };

        ServerHttpResponse response = await EndSessionAsync(host, material, new RequestFields
        {
            [OAuthRequestParameterNames.LogoutHint] = "user@example.com",
            [OAuthRequestParameterNames.PostLogoutRedirectUri] = RegisteredPostLogout,
            [OAuthRequestParameterNames.State] = "lh1"
        }).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode, response.Body);
        Assert.AreEqual($"{RegisteredPostLogout}?state=lh1", response.Location);
        Assert.HasCount(1, hints, "The logout_hint must reach the by-hint terminate seam exactly once.");
        Assert.AreEqual("user@example.com", hints[0], "The opaque logout_hint is passed through verbatim.");
    }


    /// <summary>
    /// Fail-closed: when only a <c>logout_hint</c> is supplied but the deployment did not
    /// wire the by-hint terminate seam, sessionless logout is unavailable, so an
    /// <c>id_token_hint</c> remains required — the request is rejected (400, no redirect).
    /// </summary>
    [TestMethod]
    public async Task EndSessionRejectsLogoutHintWhenByHintSeamNotWired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities);

        host.Server.OAuth().TerminateSessionAsync = (_, _, _, _, _) => ValueTask.CompletedTask;
        //TerminateSessionByHintAsync intentionally left unwired.

        ServerHttpResponse response = await EndSessionAsync(host, material, new RequestFields
        {
            [OAuthRequestParameterNames.LogoutHint] = "user@example.com"
        }).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.IsNull(response.Location, "A rejected sessionless logout must not redirect.");
    }


    /// <summary>
    /// Back-Channel composition: after the local session is terminated, the end-session
    /// endpoint drops out to the back-channel fan-out seam with the same verified sub/sid, so
    /// a deployment can deliver Logout Tokens to its registered RPs. Asserts ordering
    /// (terminate then deliver) and that the verified identifiers reach the seam.
    /// </summary>
    [TestMethod]
    public async Task EndSessionFansOutBackChannelLogoutAfterTerminate()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities);

        List<string> order = [];
        (string Subject, string? SessionId) delivered = default;
        host.Server.OAuth().TerminateSessionAsync = (_, _, _, _, _) =>
        {
            order.Add("terminate");
            return ValueTask.CompletedTask;
        };
        host.Server.OAuth().DeliverBackChannelLogoutAsync = (sub, sid, _, _, _) =>
        {
            order.Add("deliver");
            delivered = (sub, sid);
            return ValueTask.CompletedTask;
        };

        string idToken = await IssueIdTokenAsync(host, material, "session-BC").ConfigureAwait(false);

        ServerHttpResponse response = await EndSessionAsync(host, material, new RequestFields
        {
            [OAuthRequestParameterNames.IdTokenHint] = idToken
        }).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.HasCount(2, order, "Both the terminate and the deliver seam must run.");
        Assert.AreEqual("terminate", order[0]);
        Assert.AreEqual("deliver", order[1],
            "Back-channel fan-out must run after the local session is terminated.");
        Assert.AreEqual(SubjectId, delivered.Subject);
        Assert.AreEqual("session-BC", delivered.SessionId,
            "The verified sub/sid must reach the back-channel deliver seam.");
    }


    private async Task<ServerHttpResponse> EndSessionAsync(
        TestHostShell host, VerifierKeyMaterial material, RequestFields fields) =>
        await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.EndSession,
            "GET",
            fields,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// Drives PAR → Authorize (stamping subject + session id) → Token and returns the
    /// issued ID Token — the value an RP later presents as <c>id_token_hint</c>.
    /// </summary>
    private async Task<string> IssueIdTokenAsync(
        TestHostShell host, VerifierKeyMaterial material, string sessionId)
    {
        PkceParameters pkce = PkceGeneration.Generate(
            TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        using JsonDocument parDoc = JsonDocument.Parse(parResponse.Body);
        string requestUri = parDoc.RootElement.GetProperty("request_uri").GetString()!;

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);
        authorizeContext.SetSessionId(sessionId);
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
        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken, "POST",
            tokenFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument tokenDoc = JsonDocument.Parse(tokenResponse.Body);

        return tokenDoc.RootElement.GetProperty("id_token").GetString()!;
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


    /// <summary>Parses the <c>code</c> and (RFC 9207) <c>iss</c> from an authorize redirect Location.</summary>
    private static (string Code, string? Iss) ParseAuthorizeRedirect(string location)
    {
        string? code = null;
        string? iss = null;
        int q = location.IndexOf('?', StringComparison.Ordinal);
        foreach(string pair in location[(q + 1)..].Split('&'))
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            if(eq <= 0)
            {
                continue;
            }

            string key = pair[..eq];
            string value = Uri.UnescapeDataString(pair[(eq + 1)..]);
            if(string.Equals(key, OAuthRequestParameterNames.Code, StringComparison.Ordinal))
            {
                code = value;
            }
            else if(string.Equals(key, OAuthRequestParameterNames.Iss, StringComparison.Ordinal))
            {
                iss = value;
            }
        }

        return (code ?? throw new InvalidOperationException(
            $"Authorize redirect did not carry a code parameter: {location}"), iss);
    }
}
