using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Net;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Metadata;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// OIDC RP-Initiated Logout 1.0 — the <c>end_session_endpoint</c> end-to-end. A real
/// auth-code flow issues an ID Token (carrying the Slice-3 <c>sid</c>); the RP then
/// redirects the User Agent to the end-session endpoint with that token as
/// <c>id_token_hint</c>. The OP verifies the hint as an ID Token it issued: its kind (a
/// <c>typ</c> that is absent or <c>JWT</c>), a <c>kid</c> the registration lists for ID Token
/// issuance, the signature under that key and the issuer, <em>not</em> <c>exp</c>; it validates
/// <c>post_logout_redirect_uri</c> against the client's registered set, terminates the session
/// via <see cref="TerminateSessionDelegate"/>, and redirects with <c>state</c> echoed.
/// Firewalled: the hint is the actual wire token.
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
    private static Uri ClientBaseUri { get; } = new("https://client.example.com");
    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

    /// <summary>The post-logout URI TestHostShell registers for DPoP clients.</summary>
    private const string RegisteredPostLogout = "https://client.example.com/post-logout";

    /// <summary>DPoP-client defaults plus the RP-Initiated Logout capability.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> LogoutCapabilities { get; } =
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
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities).ConfigureAwait(false);

        List<(string Subject, string? SessionId)> terminated = [];
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.TerminateSessionAsync = (sub, sid, _, _, _) =>
            {
                terminated.Add((sub, sid));

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

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
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities).ConfigureAwait(false);

        bool terminated = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.TerminateSessionAsync = (_, _, _, _, _) =>
            {
                terminated = true;

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

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
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities).ConfigureAwait(false);

        bool terminated = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.TerminateSessionAsync = (_, _, _, _, _) =>
            {
                terminated = true;

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

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
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities).ConfigureAwait(false);

        bool terminated = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.TerminateSessionAsync = (_, _, _, _, _) =>
            {
                terminated = true;

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        string idToken = await IssueIdTokenAsync(host, material, "session-A").ConfigureAwait(false);

        //Flip a middle character of the signature segment — it stays base64url-valid, so the id_token
        //decodes cleanly and the signature simply fails to verify (a deterministic rejection, not an
        //incidental decode failure on a non-canonical final character).
        int signatureStart = idToken.LastIndexOf('.', StringComparison.Ordinal) + 1;
        int tamperIndex = signatureStart + ((idToken.Length - signatureStart) / 2);
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
    /// RFC 7519 §4: "The JWT Claim Names within a Claims Set MUST be unique." An
    /// <c>id_token_hint</c> whose Claims Set repeats <c>sub</c> — the attacker's value first, the
    /// honest value last, the shape a last-value-wins deserializer resolves to the honest subject
    /// while a first-match reader elsewhere disagrees — is refused with the same malformed-hint
    /// outcome as an unverifiable hint, never a server error. Only the payload segment is rebuilt
    /// by hand (never through this repository's serializers) and re-signed with the AS's own
    /// signing key for that <c>kid</c>; the header is untouched, so only the payload's
    /// well-formedness gate — not an invalid signature — can be responsible for the refusal.
    /// </summary>
    [TestMethod]
    public async Task EndSessionRejectsIdTokenHintWithDuplicateSubClaim()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities).ConfigureAwait(false);

        bool terminated = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.TerminateSessionAsync = (_, _, _, _, _) =>
            {
                terminated = true;

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        string idToken = await IssueIdTokenAsync(host, material, "session-A").ConfigureAwait(false);

        string[] parts = idToken.Split('.');
        using IMemoryOwner<byte> headerOwner = TestSetup.Base64UrlDecoder(parts[0], BaseMemoryPool.Shared);
        using JsonDocument headerDoc = JsonDocument.Parse(headerOwner.Memory);
        string kid = headerDoc.RootElement.GetProperty("kid").GetString()!;

        using IMemoryOwner<byte> payloadOwner = TestSetup.Base64UrlDecoder(parts[1], BaseMemoryPool.Shared);
        string payloadJson = Encoding.UTF8.GetString(payloadOwner.Memory.Span);

        //Splice an attacker-controlled "sub" ahead of the honest one already in the serialized
        //payload — raw string surgery, not a Dictionary<string,object> round trip, since a
        //dictionary cannot itself carry two entries under the same key.
        string tamperedPayloadJson = payloadJson.Insert(1, "\"sub\":\"attacker-subject\",");
        string tamperedPayloadB64 = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(tamperedPayloadJson));

        PrivateKeyMemory signingKey = host.Host("default").SigningKeys[new KeyId(kid)];
        byte[] signingInput = Encoding.ASCII.GetBytes($"{parts[0]}.{tamperedPayloadB64}");
        using Signature signature = await signingKey.SignAsync(signingInput, BaseMemoryPool.Shared).ConfigureAwait(false);
        string signatureB64 = TestSetup.Base64UrlEncoder(signature.AsReadOnlySpan());
        string tamperedIdToken = $"{parts[0]}.{tamperedPayloadB64}.{signatureB64}";

        ServerHttpResponse response = await EndSessionAsync(host, material, new RequestFields
        {
            [OAuthRequestParameterNames.IdTokenHint] = tamperedIdToken,
            [OAuthRequestParameterNames.PostLogoutRedirectUri] = RegisteredPostLogout
        }).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.IsLessThan(500, response.StatusCode, "A duplicate claim must never surface as a server error.");
        Assert.IsFalse(terminated, "A hint carrying a duplicate claim must not terminate a session.");
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
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities).ConfigureAwait(false);

        bool terminated = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.TerminateSessionAsync = (_, _, _, _, _) =>
            {
                terminated = true;

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

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
        _ = host.SeedTestSubject(subject: SubjectId);

        //No explicit profile → HAIP 1.0 default → DPoP enforced at the token endpoint.
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, capabilities: LogoutCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        List<(string Subject, string? SessionId)> terminated = [];
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.TerminateSessionAsync = (sub, sid, _, _, _) =>
            {
                terminated.Add((sub, sid));

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

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
        ExchangeContext authorizeContext = [];
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities).ConfigureAwait(false);

        //Wiring the terminate seam activates the end_session_endpoint candidate (and thus its
        //discovery field); the ui_locales_supported field is app-contributed.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.TerminateSessionAsync = (_, _, _, _, _) => ValueTask.CompletedTask;

            candidateIntegration.ContributeDiscoveryFieldsAsync = static (_, _, _) =>
                ValueTask.FromResult(new DiscoveryDocumentContribution(
                    [new DiscoveryStringArrayField(
                        AuthorizationServerMetadataParameterNames.UiLocalesSupported,
                        ["en-US", "fi-FI"])]));
        }).ConfigureAwait(false);

        ServerHttpResponse discovery = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataDiscovery, WellKnownHttpMethods.Get,
            new RequestFields(), [],
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, discovery.StatusCode, discovery.Body);

        using JsonDocument doc = JsonDocument.Parse(discovery.Body);
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
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities).ConfigureAwait(false);

        //The endpoint gate still requires the id_token_hint terminate seam; wire it (unused here).
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.TerminateSessionAsync = (_, _, _, _, _) => ValueTask.CompletedTask;
        }).ConfigureAwait(false);

        List<string> hints = [];
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.TerminateSessionByHintAsync = (hint, _, _, _) =>
            {
                hints.Add(hint);

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.TerminateSessionAsync = (_, _, _, _, _) => ValueTask.CompletedTask;
        }).ConfigureAwait(false);
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
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities).ConfigureAwait(false);

        List<string> order = [];
        (string Subject, string? SessionId) delivered = default;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.TerminateSessionAsync = (_, _, _, _, _) =>
            {
                order.Add("terminate");

                return ValueTask.CompletedTask;
            };

            candidateIntegration.DeliverBackChannelLogoutAsync = (sub, sid, _, _, _) =>
            {
                order.Add("deliver");
                delivered = (sub, sid);

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

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


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout">RP-Initiated
    /// Logout 1.0 §2</see>: "When an id_token_hint parameter is present, the OP MUST validate that it
    /// was the issuer of the ID Token." and
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.12">RFC 8725 §3.12</see>: "If more
    /// than one kind of JWT can be issued by the same issuer, the validation rules for those JWTs MUST
    /// be written such that they are mutually exclusive, rejecting JWTs of the wrong kind." A hint
    /// carrying an ID Token's claims and signed under the very key the registration lists for ID
    /// Tokens, but explicitly typed as another kind of JWT this issuer produces, is not an ID Token, and
    /// <see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling">RP-Initiated
    /// Logout 1.0 §4</see> fixes what follows: "If any of the validation procedures defined in this
    /// specification fail, any operations requiring the information that failed to correctly validate
    /// MUST be aborted and the information that failed to validate MUST NOT be used." and "when the OP
    /// detects errors in the RP-Initiated Logout request, the OP MUST not perform post-logout
    /// redirection to an RP." The end-session request over the wire is not redirected and the session
    /// stays live. The 400 <c>invalid_request</c> body and its description are the library's own refusal
    /// shape; the specification names no error code or status. The rows are an access token's, a
    /// logout token's and an ID-JAG's <c>typ</c>.
    /// </summary>
    /// <param name="type">The explicit <c>typ</c> the hint's protected header carries.</param>
    [TestMethod]
    [DataRow("at+jwt")]
    [DataRow("logout+jwt")]
    [DataRow("oauth-id-jag+jwt")]
    public async Task EndSessionRefusesAHintThatIsNotAnIdTokenAsync(string type)
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities).ConfigureAwait(false);

        List<string> terminated = await WireTerminateSeamAsync(host).ConfigureAwait(false);

        string idToken = await IssueIdTokenAsync(host, material, "session-T").ConfigureAwait(false);
        string hint = await CompactJwsResigning.ResignWithHeaderAsync(host, idToken, material.SigningKeyId, type).ConfigureAwait(false);

        using HttpResponseMessage response = await EndSessionOverWireAsync(host, material, hint, "t1").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertHintRefused(response, body);
        Assert.IsEmpty(terminated, "A hint that is not an ID Token must not end the session.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout">RP-Initiated
    /// Logout 1.0 §2</see>: "id_token_hint RECOMMENDED. ID Token previously issued by the OP to the RP
    /// passed to the Logout Endpoint as a hint about the End-User's current authenticated session with
    /// the Client." An ID Token this server issued, signed under the registration's ID Token key, whose
    /// header carries no <c>typ</c> or one naming the JWT media type, is accepted over the wire: the
    /// end-session request redirects to the registered post-logout URI with the <c>state</c> and ends
    /// the session. The <c>typ</c> is compared as the media type
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515 §4.1.9</see> makes it:
    /// "Per RFC 2045 [RFC2045], all media type values, subtype values, and parameter names are case
    /// insensitive." and "A recipient using the media type value MUST treat it as if "application/"
    /// were prepended to any "typ" value not containing a '/'." The rows: no <c>typ</c> at all
    /// (<see langword="null"/>); <c>JWT</c>, the header the server's own ID Token carries; <c>jwt</c>,
    /// the same media type in lower case; <c>application/jwt</c>, the same media type with the prefix
    /// written out.
    /// </summary>
    /// <param name="typ">The hint's <c>typ</c> header value, or <see langword="null"/> for none.</param>
    [TestMethod]
    [DataRow(null)]
    [DataRow("JWT")]
    [DataRow("jwt")]
    [DataRow("application/jwt")]
    public async Task EndSessionAcceptsAnUntypedOrJwtTypedHintAsync(string? typ)
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities).ConfigureAwait(false);

        List<string> terminated = await WireTerminateSeamAsync(host).ConfigureAwait(false);

        string idToken = await IssueIdTokenAsync(host, material, "session-U").ConfigureAwait(false);
        string hint = await CompactJwsResigning.ResignWithHeaderAsync(host, idToken, material.SigningKeyId, typ).ConfigureAwait(false);

        using HttpResponseMessage response = await EndSessionOverWireAsync(host, material, hint, "u1").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Found, response.StatusCode, body);
        Assert.AreEqual("https://client.example.com/post-logout?state=u1", response.Headers.Location?.OriginalString);
        Assert.HasCount(1, terminated, "An ID Token hint ends the session exactly once.");
        Assert.AreEqual(SubjectId, terminated[0]);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout">RP-Initiated
    /// Logout 1.0 §2</see>: "When an id_token_hint parameter is present, the OP MUST validate that it
    /// was the issuer of the ID Token." and
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.12">RFC 8725 §3.12</see>: "Use
    /// different keys for different kinds of JWTs. Then the keys used to validate one kind of JWT will
    /// fail to validate other kinds of JWTs." A hint carrying this registration's ID Token claims and
    /// typed <c>JWT</c>, but signed under a key the registration does not list for ID Tokens (another
    /// registration's signing key on the same server, which the server can resolve by its <c>kid</c>),
    /// fails that validation, and
    /// <see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling">RP-Initiated
    /// Logout 1.0 §4</see> fixes what follows: "If any of the validation procedures defined in this
    /// specification fail, any operations requiring the information that failed to correctly validate
    /// MUST be aborted and the information that failed to validate MUST NOT be used." and "when the OP
    /// detects errors in the RP-Initiated Logout request, the OP MUST not perform post-logout
    /// redirection to an RP." The end-session request over the wire is not redirected and the session
    /// stays live. The 400 <c>invalid_request</c> body and its description are the library's own refusal
    /// shape; the specification names no error code or status.
    /// </summary>
    [TestMethod]
    public async Task EndSessionRefusesAHintSignedUnderAKeyNotListedForIdTokensAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities).ConfigureAwait(false);
        using VerifierKeyMaterial otherMaterial = await host.RegisterDpopClientAsync(
            OtherClientId, OtherClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities).ConfigureAwait(false);

        List<string> terminated = await WireTerminateSeamAsync(host).ConfigureAwait(false);

        string idToken = await IssueIdTokenAsync(host, material, "session-K").ConfigureAwait(false);
        string hint = await CompactJwsResigning.ResignWithHeaderAsync(host, idToken, otherMaterial.SigningKeyId, "JWT").ConfigureAwait(false);

        using HttpResponseMessage response = await EndSessionOverWireAsync(host, material, hint, "k1").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertHintRefused(response, body);
        Assert.IsEmpty(terminated, "A hint signed under a key not listed for ID Tokens must not end the session.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout">RP-Initiated
    /// Logout 1.0 §2</see>: "When an id_token_hint parameter is present, the OP MUST validate that it
    /// was the issuer of the ID Token." A hint whose protected header's <c>kid</c> is a single space
    /// names no key, so the OP cannot validate that it issued it, and
    /// <see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling">RP-Initiated
    /// Logout 1.0 §4</see> fixes what follows: "If any of the validation procedures defined in this
    /// specification fail, any operations requiring the information that failed to correctly validate
    /// MUST be aborted and the information that failed to validate MUST NOT be used." and "when the OP
    /// detects errors in the RP-Initiated Logout request, the OP MUST not perform post-logout
    /// redirection to an RP." The end-session request over the wire is not redirected, never answered
    /// with a server error, and the session stays live. The 400 <c>invalid_request</c> body with the
    /// description "id_token_hint header is missing kid." is the library's own refusal shape; the
    /// specification names no error code or status.
    /// </summary>
    [TestMethod]
    public async Task EndSessionRefusesAHintWhoseKidIsWhitespaceAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities).ConfigureAwait(false);

        List<string> terminated = await WireTerminateSeamAsync(host).ConfigureAwait(false);

        string idToken = await IssueIdTokenAsync(host, material, "session-W").ConfigureAwait(false);
        string hint = await CompactJwsResigning.ResignWithHeaderAsync(host, idToken, material.SigningKeyId, " ", "JWT").ConfigureAwait(false);

        using HttpResponseMessage response = await EndSessionOverWireAsync(host, material, hint, "w1").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode, body);
        Assert.IsNull(response.Headers.Location, "A refused hint must not redirect.");
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_request", document.RootElement.GetProperty("error").GetString());
        Assert.AreEqual("id_token_hint header is missing kid.", document.RootElement.GetProperty("error_description").GetString());
        Assert.IsEmpty(terminated, "A hint whose kid names no key must not end the session.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling">RP-Initiated
    /// Logout 1.0 §4</see>: "If any of the validation procedures defined in this specification fail,
    /// any operations requiring the information that failed to correctly validate MUST be aborted and
    /// the information that failed to validate MUST NOT be used." and "when the OP detects errors in the
    /// RP-Initiated Logout request, the OP MUST not perform post-logout redirection to an RP." A hint
    /// whose protected header is a JSON array (<c>W10.e30.AA</c>, the header <c>[]</c>) fails
    /// validation: the end-session request over the wire is not redirected, never answered with a
    /// server error, and the session stays live. The 400 <c>invalid_request</c> body is the library's
    /// own refusal shape; the specification names no error code or status.
    /// </summary>
    [TestMethod]
    public async Task EndSessionRefusesAHintWhoseHeaderIsNotAJsonObjectAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities).ConfigureAwait(false);

        List<string> terminated = await WireTerminateSeamAsync(host).ConfigureAwait(false);

        using HttpResponseMessage response = await EndSessionOverWireAsync(host, material, "W10.e30.AA", "m1").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode, body);
        Assert.IsNull(response.Headers.Location, "A refused hint must not redirect.");
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_request", document.RootElement.GetProperty("error").GetString());
        Assert.IsEmpty(terminated, "A malformed hint must not end the session.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling">RP-Initiated
    /// Logout 1.0 §4</see>: "If any of the validation procedures defined in this specification fail,
    /// any operations requiring the information that failed to correctly validate MUST be aborted". A
    /// hint that is an ID Token this server issued with its signature segment lengthened past
    /// <see cref="Verifiable.JCose.Jws.DefaultMaxJwsLength"/>, the longest compact JWS the library
    /// verifies, cannot be validated: the end-session request sent over the wire is answered 400
    /// <c>invalid_request</c>, never redirected and never a server fault, and the session stays live.
    /// </summary>
    [TestMethod]
    public async Task EndSessionRefusesAHintLongerThanTheVerifiedMaximumAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities).ConfigureAwait(false);

        List<string> terminated = await WireTerminateSeamAsync(host).ConfigureAwait(false);

        string idToken = await IssueIdTokenAsync(host, material, "session-A").ConfigureAwait(false);
        string oversizedHint = idToken + new string('A', Verifiable.JCose.Jws.DefaultMaxJwsLength);

        using HttpResponseMessage response = await EndSessionOverWireAsync(host, material, oversizedHint, "o1").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode, body);
        Assert.IsNull(response.Headers.Location, "A refused hint must not redirect.");
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_request", document.RootElement.GetProperty("error").GetString());
        Assert.AreEqual(
            "id_token_hint exceeds the longest compact JWS this server verifies.",
            document.RootElement.GetProperty("error_description").GetString());
        Assert.IsEmpty(terminated, "An oversized hint must not end the session.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.12">RFC 8725 §3.12</see>: "Use
    /// different keys for different kinds of JWTs. Then the keys used to validate one kind of JWT will
    /// fail to validate other kinds of JWTs." A registration whose access tokens and ID Tokens are
    /// issued under two distinct keys: a hint carrying the registration's ID Token claims, typed
    /// <c>JWT</c>, but signed under the registration's own access-token key, fails the validation
    /// <see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout">RP-Initiated
    /// Logout 1.0 §2</see> requires ("When an id_token_hint parameter is present, the OP MUST validate
    /// that it was the issuer of the ID Token."), and
    /// <see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling">§4</see>
    /// "when the OP detects errors in the RP-Initiated Logout request, the OP MUST not perform
    /// post-logout redirection to an RP.": the end-session request over the wire is not redirected and
    /// the session stays live. The 400 <c>invalid_request</c> body is the library's own refusal shape.
    /// </summary>
    [TestMethod]
    public async Task EndSessionRefusesAHintSignedUnderTheRegistrationsAccessTokenKeyAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities).ConfigureAwait(false);
        _ = await IssuanceKeySeparation.ListFreshKeyAsync(host, material, KeyUsageContext.IdTokenIssuance).ConfigureAwait(false);

        List<string> terminated = await WireTerminateSeamAsync(host).ConfigureAwait(false);

        string idToken = await IssueIdTokenAsync(host, material, "session-A").ConfigureAwait(false);
        string hint = await CompactJwsResigning.ResignWithHeaderAsync(host, idToken, material.SigningKeyId, "JWT").ConfigureAwait(false);

        using HttpResponseMessage response = await EndSessionOverWireAsync(host, material, hint, "a1").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertHintRefused(response, body);
        Assert.IsEmpty(terminated, "A hint signed under the access-token key must not end the session.");
    }


    /// <summary>
    /// The verification-key resolver's documented contract, a contract of this library: every
    /// resolution states the <see cref="KeyUsageContext"/> the key is expected under. The design follows
    /// <see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout">RP-Initiated
    /// Logout 1.0 §2</see>: "When an id_token_hint parameter is present, the OP MUST validate that it was
    /// the issuer of the ID Token." and
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.12">RFC 8725 §3.12</see>: "If more
    /// than one kind of JWT can be issued by the same issuer, the validation rules for those JWTs MUST be
    /// written such that they are mutually exclusive, rejecting JWTs of the wrong kind." An ID Token this
    /// server issued, presented as <c>id_token_hint</c> at the end-session endpoint over the wire with
    /// the registered <c>post_logout_redirect_uri</c> and a <c>state</c>, redirects 302 to
    /// "https://client.example.com/post-logout" with the <c>state</c>, and the resolver is asked for the
    /// hint's key under <see cref="KeyUsageContext.IdTokenIssuance"/>.
    /// </summary>
    [TestMethod]
    public async Task EndSessionResolvesTheHintKeyUnderIdTokenIssuanceAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: LogoutCapabilities).ConfigureAwait(false);

        List<string> terminated = await WireTerminateSeamAsync(host).ConfigureAwait(false);

        string idToken = await IssueIdTokenAsync(host, material, "session-R").ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        hosted.VerificationKeyResolutions.Clear();

        using HttpResponseMessage response = await EndSessionOverWireAsync(host, material, idToken, "r1").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Found, response.StatusCode, body);
        Assert.AreEqual("https://client.example.com/post-logout?state=r1", response.Headers.Location?.OriginalString);
        Assert.HasCount(1, terminated, "An ID Token hint ends the session exactly once.");

        VerificationKeyResolution resolution = Assert.ContainsSingle(hosted.ResolutionsOf(material.SigningKeyId));
        Assert.AreEqual(KeyUsageContext.IdTokenIssuance, resolution.Usage);
    }


    /// <summary>The client identifier of the second registration whose signing key the foreign-key hint borrows.</summary>
    private const string OtherClientId = "https://other.client.example.com";

    /// <summary>The base URI of the second registration.</summary>
    private static Uri OtherClientBaseUri { get; } = new("https://other.client.example.com");


    /// <summary>
    /// Wires the application's terminate seam to record each ended session's subject, so a test can
    /// tell a live session (nothing recorded) from an ended one.
    /// </summary>
    /// <param name="host">The host whose integration is altered.</param>
    /// <returns>The list the seam appends each ended session's subject to.</returns>
    private static async Task<List<string>> WireTerminateSeamAsync(TestHostShell host)
    {
        List<string> terminated = [];
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.TerminateSessionAsync = (sub, _, _, _, _) =>
            {
                terminated.Add(sub);

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        return terminated;
    }


    /// <summary>
    /// Asserts the end-session refusal of a hint that is not an ID Token this server issued: 400, no
    /// redirect, and the fixed <c>invalid_request</c> body.
    /// </summary>
    /// <param name="response">The wire response.</param>
    /// <param name="body">The response body text.</param>
    private static void AssertHintRefused(HttpResponseMessage response, string body)
    {
        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode, body);
        Assert.IsNull(response.Headers.Location, "A refused hint must not redirect.");

        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_request", document.RootElement.GetProperty("error").GetString());
        Assert.AreEqual(
            "id_token_hint is not an ID Token issued by this server.",
            document.RootElement.GetProperty("error_description").GetString());
    }


    /// <summary>
    /// Sends the end-session GET over the host's loopback HTTPS listener with the hint, the registered
    /// post-logout URI and <paramref name="state"/> in the query, through a client that does not follow
    /// redirects, so the 302 and its <c>Location</c> are read as the server wrote them.
    /// </summary>
    /// <param name="host">The host whose listener serves the request.</param>
    /// <param name="material">The registration whose end-session path is addressed.</param>
    /// <param name="idTokenHint">The <c>id_token_hint</c> value.</param>
    /// <param name="state">The <c>state</c> value.</param>
    /// <returns>The wire response; the caller disposes it.</returns>
    private async Task<HttpResponseMessage> EndSessionOverWireAsync(
        TestHostShell host, VerifierKeyMaterial material, string idTokenHint, string state)
    {
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        string query =
            $"?{OAuthRequestParameterNames.IdTokenHint}={Uri.EscapeDataString(idTokenHint)}" +
            $"&{OAuthRequestParameterNames.PostLogoutRedirectUri}={Uri.EscapeDataString(RegisteredPostLogout)}" +
            $"&{OAuthRequestParameterNames.State}={Uri.EscapeDataString(state)}";
        Uri endSessionUrl = new(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.EndSession, material.Registration.TenantId.Value) + query);

        using HttpClient client = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        using HttpRequestMessage request = new(HttpMethod.Get, endSessionUrl);

        return await client.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
    }


    private async Task<ServerHttpResponse> EndSessionAsync(
        TestHostShell host, VerifierKeyMaterial material, RequestFields fields) =>
        await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.EndSession,
            "GET",
            fields,
            [],
            TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// Drives PAR → Authorize (stamping subject + session id) → Token and returns the
    /// issued ID Token — the value an RP later presents as <c>id_token_hint</c>.
    /// </summary>
    private async Task<string> IssueIdTokenAsync(
        TestHostShell host, VerifierKeyMaterial material, string sessionId)
    {
        InProcessAuthCodeDriveResult result = await InProcessAuthCodeDriver.DriveAsync(
            host, material, SubjectId, RedirectUri,
            new InProcessAuthCodeDriveOptions { Scope = WellKnownScopes.OpenId, SessionId = sessionId },
            TestContext.CancellationToken).ConfigureAwait(false);

        using JsonDocument tokenDoc = JsonDocument.Parse(result.TokenResponse.Body);

        return tokenDoc.RootElement.GetProperty("id_token").GetString()!;
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
