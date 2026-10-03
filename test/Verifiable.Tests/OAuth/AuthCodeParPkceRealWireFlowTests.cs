using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Diagnostics;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Introspection;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Server.Pipeline;
using Verifiable.Server.Routing;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Real-wire capstone for the Authorization Code + PAR + PKCE family: PAR, the browser's authorize
/// GET, token exchange, refresh, and revocation cross a real loopback socket, and the callback is a
/// client-local transition on the <c>code</c>/<c>state</c>/<c>iss</c> parameters read from the HTTP
/// redirect the authorize GET answers, composed via <see cref="TestHostShell.CreateOAuthClientAndRegistrationAsync"/>
/// and <see cref="AuthCodeClient.StartParAsync(ClientRegistration, Uri, OAuthFormEncodedFields, ExchangeContext, IReadOnlyList{string}?, CancellationToken)"/> / <see cref="AuthCodeClient.HandleCallbackAsync(ClientRegistration, OAuthFormEncodedFields, CancellationToken)"/> /
/// <see cref="AuthCodeClient.ExchangeTokenAsync(ClientRegistration, string, CancellationToken)"/> exactly as <see cref="IdJagGrantTests"/> and
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
    /// <see cref="TestHostShell.RegisterDpopClientAsync"/> requires for client registration.
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
    /// <see cref="Capabilities"/> plus RFC 7662 introspection, for the replay tests that prove a
    /// revoked access token is refused afterwards at a path the suite already has.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> CapabilitiesWithIntrospection { get; } =
        Capabilities.Add(WellKnownCapabilityIdentifiers.OAuthTokenIntrospection);

    /// <summary>
    /// <see cref="Capabilities"/> plus the direct authorization request, signed request objects and
    /// OpenID Connect, so that one registration takes every start the client offers and its token
    /// responses carry an ID Token beside the access token.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> CapabilitiesWithOpenIdConnect { get; } =
        Capabilities
            .Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization)
            .Add(WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest)
            .Add(WellKnownCapabilityIdentifiers.OidcOpenIdConnect);


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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(true);

            candidateIntegration.RevokeTokenAsync = static (_, _, _, _, _) =>
                ValueTask.CompletedTask;
        }).ConfigureAwait(false);

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
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0
    /// section 2</see> defines <c>auth_time</c> as "Time when the End-User authentication occurred." and
    /// states "When a max_age request is made or when auth_time is requested as an Essential Claim, then
    /// this Claim is REQUIRED; otherwise, its inclusion is OPTIONAL." The instant is a fact of the host's
    /// own authentication: a session whose browser leg carries the authenticated subject and no
    /// authentication instant yields a code whose redemption and whose refresh carry no <c>auth_time</c>
    /// on either ID Token or on either access token, never the instant the authorize leg ran, whichever
    /// start carries the authorization request.
    /// </summary>
    /// <param name="start">
    /// Which start carries the authorization request: <see cref="PushedStart"/>,
    /// <see cref="DirectStart"/>, <see cref="RequestObjectByValueStart"/> or
    /// <see cref="PushedRequestObjectStart"/>.
    /// </param>
    [TestMethod]
    [DataRow(PushedStart, DisplayName = "PushedRequest")]
    [DataRow(DirectStart, DisplayName = "DirectRequest")]
    [DataRow(RequestObjectByValueStart, DisplayName = "SignedRequestByValue")]
    [DataRow(PushedRequestObjectStart, DisplayName = "PushedSignedRequest")]
    public async Task ASessionStampedWithoutAnAuthenticationInstantIssuesNoAuthTime(string start)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: CapabilitiesWithOpenIdConnect)
            .ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await ComposeResourceJourneyClientAsync(host, material).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        string flowId = start switch
        {
            PushedStart => await DriveParAuthorizeAndCallbackAsync(
                hosted, client, registration, clientFlowStore, material.Registration.TenantId.Value,
                host.ServerCertificate, TestContext.CancellationToken).ConfigureAwait(false),
            DirectStart => await DriveDirectStartAuthorizeAndCallbackAsync(
                hosted, client, registration, clientFlowStore, host.ServerCertificate,
                OAuthFormEncodedFieldsFixtures.OpenIdScope, TestContext.CancellationToken).ConfigureAwait(false),
            PushedRequestObjectStart or RequestObjectByValueStart => await DriveRequestObjectStartAuthorizeAndCallbackAsync(
                start, host, client, registration, clientFlowStore, material, WellKnownScopes.OpenId, resource: null).ConfigureAwait(false),
            _ => throw new ArgumentOutOfRangeException(nameof(start), start, "Unknown authorization request start.")
        };

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Token exchange must succeed over the real wire. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
        AssertNoAuthTime(tokenResult.Body!, OAuthRequestParameterNames.IdToken, "the ID Token of the code redemption");
        AssertNoAuthTime(tokenResult.Body!, OAuthRequestParameterNames.AccessToken, "the access token of the code redemption");

        //The refresh runs at a later instant, so a refresh that dated the grant by its own clock would show.
        TimeProvider.Advance(TimeSpan.FromMinutes(10));

        AuthCodeFlowEndpointResult refreshResult = await client.AuthCode.RefreshAsync(
            registration,
            new RefreshTokenRequest
            {
                ClientId = ClientId,
                RefreshToken = (string)tokenResult.Body![OAuthRequestParameterNames.RefreshToken]
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, refreshResult.Outcome,
            $"Refresh must succeed over the real wire. ErrorCode={refreshResult.ErrorCode} ErrorDescription={refreshResult.ErrorDescription}");
        AssertNoAuthTime(refreshResult.Body!, OAuthRequestParameterNames.IdToken, "the ID Token of the refresh");
        AssertNoAuthTime(refreshResult.Body!, OAuthRequestParameterNames.AccessToken, "the access token of the refresh");
    }


    /// <summary>
    /// Asserts that the token response <paramref name="body"/> carries the JWT named
    /// <paramref name="tokenParameterName"/> and that its payload has no <c>auth_time</c> member, the
    /// shape of a token issued for an authentication whose instant the host did not state.
    /// </summary>
    /// <param name="body">The token endpoint's response members as the client decoded them off the wire.</param>
    /// <param name="tokenParameterName">The response member that holds the compact JWT.</param>
    /// <param name="tokenDescription">The token's name in the assertion messages.</param>
    private static void AssertNoAuthTime(
        IReadOnlyDictionary<string, object> body, string tokenParameterName, string tokenDescription)
    {
        Assert.IsTrue(body.TryGetValue(tokenParameterName, out object? token) && token is string { Length: > 0 },
            $"The response must carry {tokenDescription}.");
        using JsonDocument payload = JwtPayloadReader.ParsePayloadJson((string)token);
        Assert.IsFalse(payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.AuthTime, out JsonElement authTime),
            $"No authentication instant was stamped, so {tokenDescription} must carry no auth_time; it carried {authTime}.");
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

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
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.1">RFC 7636 §4.1</see>:
    /// "code-verifier = 43*128unreserved" — a 42-character verifier is refused even when its S256
    /// digest would match, and answers identically whether the presented <c>code</c> names a live
    /// grant or one that was never issued: this grammar check runs at the token endpoint's
    /// pre-correlation step, before any stored code is looked up.
    /// </summary>
    [TestMethod]
    public async Task TooShortCodeVerifierAtTokenExchangeIsInvalidGrant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);

        string tooShortVerifier = new('a', 42);

        (int LiveStatusCode, string LiveBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, code, tooShortVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        (int UnknownStatusCode, string UnknownBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, "code-never-issued-by-this-host", tooShortVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, LiveStatusCode, LiveBody);
        Assert.Contains(OAuthErrors.InvalidGrant, LiveBody, StringComparison.Ordinal);
        Assert.AreEqual(UnknownStatusCode, LiveStatusCode);
        Assert.AreEqual(UnknownBody, LiveBody,
            "A code_verifier outside RFC 7636 §4.1's grammar must answer identically whether or "
            + "not the named code exists.");

        //The malformed presentation left the live code unconsumed: it still redeems with the
        //correctly-shaped verifier the challenge was actually computed from.
        (int RedeemedStatusCode, string RedeemedBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, RedeemedStatusCode, RedeemedBody);

        //The matching-digest leg: the stored challenge is computed FROM the too-short verifier
        //itself, so a direct comparison would match — proving the refusal is the grammar check
        //alone, independent of the digest, and that it runs before any digest is ever compared.
        string matchingChallenge = await RawAuthCodeWirePushers.ComputeAuthorizationCodeHashAsync(tooShortVerifier)
            .ConfigureAwait(false);
        string matchingDigestCode = await DriveRawParAndAuthorizeAsync(
            host, segment, matchingChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);
        (int MatchingDigestStatusCode, string MatchingDigestBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, matchingDigestCode, tooShortVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, MatchingDigestStatusCode, MatchingDigestBody);
        Assert.Contains(OAuthErrors.InvalidGrant, MatchingDigestBody, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.1">RFC 7636 §4.1</see>:
    /// "unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"" — a plus sign is refused even when the S256 digest matches.
    /// </summary>
    [TestMethod]
    public async Task CodeVerifierWithDisallowedCharacterAtTokenExchangeIsInvalidGrant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        string verifierWithDisallowedCharacter = new string('a', 42) + "+";
        string challenge = await RawAuthCodeWirePushers.ComputeAuthorizationCodeHashAsync(verifierWithDisallowedCharacter).ConfigureAwait(false);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, challenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);

        (int TokenStatusCode, string TokenBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, code, verifierWithDisallowedCharacter, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, TokenStatusCode, TokenBody);
        Assert.Contains(OAuthErrors.InvalidGrant, TokenBody, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-7.5.2">OAuth 2.1 §7.5.2</see>
    /// forbids plain. A storage-corrupted method must fail the persisted-method verification of
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.6">RFC 7636 §4.6</see>, even
    /// when comparing the verifier directly would succeed — answering the same body a code that
    /// was never issued does, per <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC
    /// 6749 §5.2</see>'s <c>invalid_grant</c>, never text of its own.
    /// </summary>
    [TestMethod]
    public async Task PersistedPlainPkceMethodAtTokenExchangeIsInvalidGrant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string flowId = hosted.FlowStates.Single(pair => pair.Value.State is ServerCodeIssuedState).Key;
        (FlowState state, int stepCount) = hosted.FlowStates[flowId];
        ServerCodeIssuedState issued = Assert.IsInstanceOfType<ServerCodeIssuedState>(state);
        hosted.FlowStates[flowId] = (issued with
        {
            CodeChallengeMethod = WellKnownCodeChallengeMethods.Plain,
            CodeChallenge = pkce.EncodedVerifier
        }, stepCount);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidGrant, Body, StringComparison.Ordinal);
        Assert.Contains("The authorization code is unknown, expired, or already used.", Body, StringComparison.Ordinal);

        //Discriminators: the seeded record's StepCount is unchanged by the refusal, and a record
        //whose persisted method is S256 still redeems — so this test can still fail on the wrong
        //code, not merely on any 400.
        Assert.AreEqual(stepCount, hosted.FlowStates[flowId].StepCount,
            "The collapsed refusal must not consume the seeded record.");
        hosted.FlowStates[flowId] = (issued, stepCount);
        (int RedeemedStatusCode, string RedeemedBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, RedeemedStatusCode, RedeemedBody);
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-7.5.2">OAuth 2.1 §7.5.2</see>
    /// forbids plain. An unknown storage-corrupted method must fail the persisted-method verification of
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.6">RFC 7636 §4.6</see>, even
    /// when S256 hashing the verifier would succeed — answering the same body a code that was
    /// never issued does, per <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC
    /// 6749 §5.2</see>'s <c>invalid_grant</c>, never text of its own.
    /// </summary>
    [TestMethod]
    public async Task PersistedUnknownPkceMethodAtTokenExchangeIsInvalidGrant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string flowId = hosted.FlowStates.Single(pair => pair.Value.State is ServerCodeIssuedState).Key;
        (FlowState state, int stepCount) = hosted.FlowStates[flowId];
        ServerCodeIssuedState issued = Assert.IsInstanceOfType<ServerCodeIssuedState>(state);
        hosted.FlowStates[flowId] = (issued with
        {
            CodeChallengeMethod = "unknown"
        }, stepCount);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidGrant, Body, StringComparison.Ordinal);
        Assert.Contains("The authorization code is unknown, expired, or already used.", Body, StringComparison.Ordinal);

        //Discriminators: the seeded record's StepCount is unchanged by the refusal, and a record
        //whose persisted method is S256 still redeems — so this test can still fail on the wrong
        //code, not merely on any 400.
        Assert.AreEqual(stepCount, hosted.FlowStates[flowId].StepCount,
            "The collapsed refusal must not consume the seeded record.");
        hosted.FlowStates[flowId] = (issued, stepCount);
        (int RedeemedStatusCode, string RedeemedBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, RedeemedStatusCode, RedeemedBody);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.6">RFC 7636 §4.6</see>: the
    /// authorization server recomputes the digest of the presented <c>code_verifier</c> and
    /// compares it to the persisted <c>code_challenge</c>. A well-formed verifier whose digest does
    /// NOT match answers the SAME body as a code that was never issued —
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>'s
    /// <c>invalid_grant</c> — because a caller who could tell the two apart would have proven the
    /// code exists from the digest compare alone, with no verifier at all.
    /// </summary>
    [TestMethod]
    public async Task WrongButWellFormedCodeVerifierAnswersTheSameBodyForAnUnknownAndALiveCodeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string flowId = hosted.FlowStates.Single(pair => pair.Value.State is ServerCodeIssuedState state
            && state.CodeChallenge == pkce.EncodedChallenge).Key;
        int stepCountBefore = hosted.FlowStates[flowId].StepCount;

        string wrongButWellFormedVerifier = new('a', 64);

        (int LiveStatusCode, string LiveBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, wrongButWellFormedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        (int UnknownStatusCode, string UnknownBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, "code-never-issued-by-this-host", wrongButWellFormedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, LiveStatusCode, LiveBody);
        Assert.Contains(OAuthErrors.InvalidGrant, LiveBody, StringComparison.Ordinal);
        Assert.AreEqual(UnknownStatusCode, LiveStatusCode);
        Assert.AreEqual(UnknownBody, LiveBody,
            "A well-formed but wrong code_verifier must answer identically whether or not the named code exists.");
        Assert.AreEqual(stepCountBefore, hosted.FlowStates[flowId].StepCount,
            "A failed PKCE digest compare must not consume the live code.");

        //Discriminator: the live code is unconsumed and still redeems with the correct verifier.
        (int RedeemedStatusCode, string RedeemedBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, RedeemedStatusCode, RedeemedBody);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 §2.2</see>: a
    /// token-request <c>resource</c> outside the code's own granted set is a refusal reachable
    /// only once the caller has already proven possession of the code's own secret — the matching
    /// <c>code_verifier</c> digest
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.6">RFC 7636 §4.6</see>) — so it
    /// keeps its own <c>invalid_target</c> body instead of the endpoint's not-found constant; an
    /// UNKNOWN code, which no caller has proven possession of, answers that constant instead. The
    /// two bodies are DIFFERENT by design: a caller reaching the granted-set refusal already knows
    /// the code exists, so the endpoint's own text tells it nothing an oracle would leak.
    /// </summary>
    [TestMethod]
    public async Task ResourceOutsideTheGrantedSetKeepsItsOwnBodyForAPossessionProvenCallerAtCodeRedemptionAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        const string GrantedResource = "https://rs.example.com/";
        const string UngrantedResource = "https://other-rs.example.com/";

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken, resource: GrantedResource).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string flowId = hosted.FlowStates.Single(pair => pair.Value.State is ServerCodeIssuedState state
            && state.CodeChallenge == pkce.EncodedChallenge).Key;
        int stepCountBefore = hosted.FlowStates[flowId].StepCount;

        Dictionary<string, string> liveFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString);
        liveFields[OAuthRequestParameterNames.Resource] = UngrantedResource;
        (int LiveStatusCode, string LiveBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, liveFields, TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, string> unknownFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, "code-never-issued-by-this-host", pkce.EncodedVerifier, RedirectUri.OriginalString);
        unknownFields[OAuthRequestParameterNames.Resource] = UngrantedResource;
        (int UnknownStatusCode, string UnknownBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, unknownFields, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, LiveStatusCode, LiveBody);
        Assert.Contains(OAuthErrors.InvalidTarget, LiveBody, StringComparison.Ordinal);
        Assert.AreEqual(400, UnknownStatusCode, UnknownBody);
        Assert.Contains(OAuthErrors.InvalidGrant, UnknownBody, StringComparison.Ordinal);
        Assert.AreNotEqual(UnknownBody, LiveBody,
            "A possession-proven caller's granted-set refusal must keep its own body, distinct from the not-found constant an unknown code answers.");
        Assert.AreEqual(stepCountBefore, hosted.FlowStates[flowId].StepCount,
            "A resource outside the granted set must not consume the live code.");

        //Discriminator: the live code is unconsumed and still redeems with a resource inside the set.
        Dictionary<string, string> redeemFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString);
        redeemFields[OAuthRequestParameterNames.Resource] = GrantedResource;
        (int RedeemedResourceStatusCode, string RedeemedResourceBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, redeemFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, RedeemedResourceStatusCode, RedeemedResourceBody);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-6">RFC 9396 §6</see>: a
    /// token-request <c>authorization_details</c> narrowed to a <c>credential_configuration_id</c>
    /// the code's own grant never authorized is a refusal reachable only once the caller has
    /// already proven possession of the code's own secret — the matching <c>code_verifier</c>
    /// digest (<see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.6">RFC 7636 §4.6</see>)
    /// — so it keeps its own <c>invalid_authorization_details</c> body instead of the endpoint's
    /// not-found constant; an UNKNOWN code, which no caller has proven possession of, answers that
    /// constant instead. The two bodies are DIFFERENT by design: a caller reaching the narrowing
    /// refusal already knows the code exists, so the endpoint's own text tells it nothing an
    /// oracle would leak.
    /// </summary>
    [TestMethod]
    public async Task NarrowedAuthorizationDetailsBeyondTheGrantKeepsItsOwnBodyForAPossessionProvenCallerAtCodeRedemptionAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) => ValueTask.FromResult(GrantAllRequestedCredentials(details));
        }).ConfigureAwait(false);

        const string GrantedConfigurationId = "UniversityDegree_dc_sd_jwt";
        const string UnauthorizedConfigurationId = "org.iso.18013.5.1.mDL";

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken,
            authorizationDetails: SingleAuthorizationDetail(GrantedConfigurationId)).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string flowId = hosted.FlowStates.Single(pair => pair.Value.State is ServerCodeIssuedState state
            && state.CodeChallenge == pkce.EncodedChallenge).Key;
        int stepCountBefore = hosted.FlowStates[flowId].StepCount;

        Dictionary<string, string> liveFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString);
        liveFields[OAuthRequestParameterNames.AuthorizationDetails] = SingleAuthorizationDetail(UnauthorizedConfigurationId);
        (int LiveStatusCode, string LiveBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, liveFields, TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, string> unknownFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, "code-never-issued-by-this-host", pkce.EncodedVerifier, RedirectUri.OriginalString);
        unknownFields[OAuthRequestParameterNames.AuthorizationDetails] = SingleAuthorizationDetail(UnauthorizedConfigurationId);
        (int UnknownStatusCode, string UnknownBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, unknownFields, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, LiveStatusCode, LiveBody);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, LiveBody, StringComparison.Ordinal);
        Assert.AreEqual(400, UnknownStatusCode, UnknownBody);
        Assert.Contains(OAuthErrors.InvalidGrant, UnknownBody, StringComparison.Ordinal);
        Assert.AreNotEqual(UnknownBody, LiveBody,
            "A possession-proven caller's narrowing refusal must keep its own body, distinct from the not-found constant an unknown code answers.");
        Assert.AreEqual(stepCountBefore, hosted.FlowStates[flowId].StepCount,
            "The narrowing refusal must not consume the live code.");

        //Discriminator: the live code is unconsumed and still redeems with the granted configuration.
        Dictionary<string, string> redeemFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString);
        redeemFields[OAuthRequestParameterNames.AuthorizationDetails] = SingleAuthorizationDetail(GrantedConfigurationId);
        (int RedeemedDetailsStatusCode, string RedeemedDetailsBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, redeemFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, RedeemedDetailsStatusCode, RedeemedDetailsBody);
    }


    /// <summary>
    /// The refresh-grant twin of
    /// <see cref="ResourceOutsideTheGrantedSetKeepsItsOwnBodyForAPossessionProvenCallerAtCodeRedemptionAsync"/>
    /// — <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 §2.2</see>'s
    /// granted-set compare at REFRESH is a refusal reachable only once the caller has already
    /// proven possession by presenting the bound client's own identity
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see>), so it
    /// keeps its own <c>invalid_target</c> body instead of the endpoint's not-found constant; an
    /// UNKNOWN refresh token, which no caller has proven possession of, answers that constant
    /// instead. The two bodies are DIFFERENT by design.
    /// </summary>
    [TestMethod]
    public async Task ResourceOutsideTheGrantedSetKeepsItsOwnBodyForAPossessionProvenCallerAtRefreshAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        const string GrantedResource = "https://rs.example.com/";
        const string UngrantedResource = "https://other-rs.example.com/";

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken, resource: GrantedResource).ConfigureAwait(false);
        (int TokenStatusCode, string TokenBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, TokenStatusCode, TokenBody);
        using JsonDocument tokenDoc = JsonDocument.Parse(TokenBody);
        string refreshToken = tokenDoc.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!;

        HostedAuthorizationServer hosted = host.Host("default");
        string flowId = hosted.FlowStates.Single(pair => pair.Value.State is ServerRefreshTokenIssuedState).Key;
        int stepCountBefore = hosted.FlowStates[flowId].StepCount;

        Dictionary<string, string> liveFields = RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, refreshToken);
        liveFields[OAuthRequestParameterNames.Resource] = UngrantedResource;
        (int LiveStatusCode, string LiveBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, liveFields, TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, string> unknownFields = RawAuthCodeWirePushers.BuildRefreshTokenFields(
            ClientId, "refresh-token-never-issued-by-this-host");
        unknownFields[OAuthRequestParameterNames.Resource] = UngrantedResource;
        (int UnknownStatusCode, string UnknownBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, unknownFields, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, LiveStatusCode, LiveBody);
        Assert.Contains(OAuthErrors.InvalidTarget, LiveBody, StringComparison.Ordinal);
        Assert.AreEqual(400, UnknownStatusCode, UnknownBody);
        Assert.Contains(OAuthErrors.InvalidGrant, UnknownBody, StringComparison.Ordinal);
        Assert.AreNotEqual(UnknownBody, LiveBody,
            "A possession-proven caller's granted-set refusal must keep its own body, distinct from the not-found constant an unknown refresh token answers.");
        Assert.AreEqual(stepCountBefore, hosted.FlowStates[flowId].StepCount,
            "A resource outside the granted set must not consume the live refresh token.");

        //Discriminator: the live refresh token is unconsumed and still refreshes with a resource
        //inside the set.
        Dictionary<string, string> redeemFields = RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, refreshToken);
        redeemFields[OAuthRequestParameterNames.Resource] = GrantedResource;
        (int RefreshedResourceStatusCode, string RefreshedResourceBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, redeemFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, RefreshedResourceStatusCode, RefreshedResourceBody);
    }


    /// <summary>
    /// The refresh-grant twin of
    /// <see cref="NarrowedAuthorizationDetailsBeyondTheGrantKeepsItsOwnBodyForAPossessionProvenCallerAtCodeRedemptionAsync"/>
    /// — <see href="https://www.rfc-editor.org/rfc/rfc9396#section-6">RFC 9396 §6</see>'s
    /// narrowing-against-grant compare at REFRESH is a refusal reachable only once the caller has
    /// already proven possession by presenting the bound client's own identity
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see>), so it
    /// keeps its own <c>invalid_authorization_details</c> body instead of the endpoint's not-found
    /// constant; an UNKNOWN refresh token, which no caller has proven possession of, answers that
    /// constant instead. The two bodies are DIFFERENT by design.
    /// </summary>
    [TestMethod]
    public async Task NarrowedAuthorizationDetailsBeyondTheGrantKeepsItsOwnBodyForAPossessionProvenCallerAtRefreshAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) => ValueTask.FromResult(GrantAllRequestedCredentials(details));
        }).ConfigureAwait(false);

        const string GrantedConfigurationId = "UniversityDegree_dc_sd_jwt";
        const string UnauthorizedConfigurationId = "org.iso.18013.5.1.mDL";

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken,
            authorizationDetails: SingleAuthorizationDetail(GrantedConfigurationId)).ConfigureAwait(false);
        (int TokenStatusCode, string TokenBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, TokenStatusCode, TokenBody);
        using JsonDocument tokenDoc = JsonDocument.Parse(TokenBody);
        string refreshToken = tokenDoc.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!;

        HostedAuthorizationServer hosted = host.Host("default");
        string flowId = hosted.FlowStates.Single(pair => pair.Value.State is ServerRefreshTokenIssuedState).Key;
        int stepCountBefore = hosted.FlowStates[flowId].StepCount;

        Dictionary<string, string> liveFields = RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, refreshToken);
        liveFields[OAuthRequestParameterNames.AuthorizationDetails] = SingleAuthorizationDetail(UnauthorizedConfigurationId);
        (int LiveStatusCode, string LiveBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, liveFields, TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, string> unknownFields = RawAuthCodeWirePushers.BuildRefreshTokenFields(
            ClientId, "refresh-token-never-issued-by-this-host");
        unknownFields[OAuthRequestParameterNames.AuthorizationDetails] = SingleAuthorizationDetail(UnauthorizedConfigurationId);
        (int UnknownStatusCode, string UnknownBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, unknownFields, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, LiveStatusCode, LiveBody);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, LiveBody, StringComparison.Ordinal);
        Assert.AreEqual(400, UnknownStatusCode, UnknownBody);
        Assert.Contains(OAuthErrors.InvalidGrant, UnknownBody, StringComparison.Ordinal);
        Assert.AreNotEqual(UnknownBody, LiveBody,
            "A possession-proven caller's narrowing refusal must keep its own body, distinct from the not-found constant an unknown refresh token answers.");
        Assert.AreEqual(stepCountBefore, hosted.FlowStates[flowId].StepCount,
            "The narrowing refusal must not consume the live refresh token.");

        //Discriminator: the live refresh token is unconsumed and still refreshes with the granted
        //configuration.
        Dictionary<string, string> redeemFields = RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, refreshToken);
        redeemFields[OAuthRequestParameterNames.AuthorizationDetails] = SingleAuthorizationDetail(GrantedConfigurationId);
        (int RefreshedDetailsStatusCode, string RefreshedDetailsBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, redeemFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, RefreshedDetailsStatusCode, RefreshedDetailsBody);
    }


    /// <summary>
    /// A grant covering every requested configuration, with a deterministic per-configuration
    /// dataset identifier — the decision seam
    /// <see cref="NarrowedAuthorizationDetailsBeyondTheGrantKeepsItsOwnBodyForAPossessionProvenCallerAtCodeRedemptionAsync"/>
    /// and its refresh twin wire so a correctly-scoped request still mints
    /// <c>credential_identifiers</c>.
    /// </summary>
    private static CredentialAuthorizationDecision GrantAllRequestedCredentials(
        IReadOnlyList<CredentialAuthorizationDetail> details)
    {
        List<GrantedCredentialAuthorization> granted = [];
        foreach(CredentialAuthorizationDetail detail in details)
        {
            granted.Add(new GrantedCredentialAuthorization
            {
                CredentialConfigurationId = detail.CredentialConfigurationId!,
                CredentialIdentifiers = [$"{detail.CredentialConfigurationId}-dataset-1"]
            });
        }

        return CredentialAuthorizationDecision.Grant(granted);
    }


    /// <summary>
    /// A single <c>openid_credential</c> <c>authorization_details</c> entry naming
    /// <paramref name="configurationId"/> — the minimal RFC 9396 §5.1.1 shape the narrowing tests
    /// push and present at the token/refresh endpoint.
    /// </summary>
    private static string SingleAuthorizationDetail(string configurationId) =>
        "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + configurationId + "\"}]";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see> "issued
    /// to another client" and <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC
    /// 6749 §4.1.3</see>'s <c>redirect_uri</c> comparison: a code record whose stored client or
    /// redirect differs from what a legitimate first presentation would ever produce — the shape a
    /// store fault or a legacy record could produce — answers the SAME body as a code that was
    /// never issued, never a distinct text of its own: a caller who reaches a distinguishable
    /// answer has already proven the code exists.
    /// </summary>
    [TestMethod]
    public async Task CodeSeededWithAnotherClientOrRedirectAnswersTheSameBodyForAnUnknownAndALiveCodeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        const string HostileStoredClientId = "https://attacker.example.com";

        //Leg 1: the stored record names a client the registration never was.
        {
            PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
            string code = await DriveRawParAndAuthorizeAsync(
                host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
                TestContext.CancellationToken).ConfigureAwait(false);
            string flowId = hosted.FlowStates.Single(pair => pair.Value.State is ServerCodeIssuedState state
                && state.CodeChallenge == pkce.EncodedChallenge).Key;
            (FlowState state, int stepCount) = hosted.FlowStates[flowId];
            ServerCodeIssuedState issued = Assert.IsInstanceOfType<ServerCodeIssuedState>(state);
            hosted.FlowStates[flowId] = (issued with { ClientId = HostileStoredClientId }, stepCount);

            (int LiveStatusCode, string LiveBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment,
                RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
                TestContext.CancellationToken).ConfigureAwait(false);
            (int UnknownStatusCode, string UnknownBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment,
                RawAuthCodeWirePushers.BuildTokenFields(
                    ClientId, "code-never-issued-by-this-host-1", pkce.EncodedVerifier, RedirectUri.OriginalString),
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(400, LiveStatusCode, LiveBody);
            Assert.AreEqual(UnknownStatusCode, LiveStatusCode);
            Assert.AreEqual(UnknownBody, LiveBody,
                "A code stored bound to another client must answer identically to a code that was never issued.");
            Assert.AreEqual(stepCount, hosted.FlowStates[flowId].StepCount,
                "The refusal must not consume the seeded record.");
        }

        //Leg 2: the stored record names a redirect_uri the client never presented at PAR time.
        {
            PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
            string code = await DriveRawParAndAuthorizeAsync(
                host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
                TestContext.CancellationToken).ConfigureAwait(false);
            string flowId = hosted.FlowStates.Single(pair => pair.Value.State is ServerCodeIssuedState state
                && state.CodeChallenge == pkce.EncodedChallenge).Key;
            (FlowState state, int stepCount) = hosted.FlowStates[flowId];
            ServerCodeIssuedState issued = Assert.IsInstanceOfType<ServerCodeIssuedState>(state);
            hosted.FlowStates[flowId] = (issued with { RedirectUri = new Uri("https://stale.example.com/callback") }, stepCount);

            (int LiveStatusCode, string LiveBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment,
                RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
                TestContext.CancellationToken).ConfigureAwait(false);
            (int UnknownStatusCode, string UnknownBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment,
                RawAuthCodeWirePushers.BuildTokenFields(
                    ClientId, "code-never-issued-by-this-host-2", pkce.EncodedVerifier, RedirectUri.OriginalString),
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(400, LiveStatusCode, LiveBody);
            Assert.AreEqual(UnknownStatusCode, LiveStatusCode);
            Assert.AreEqual(UnknownBody, LiveBody,
                "A code stored bound to a stale redirect_uri must answer identically to a code that was never issued.");
            Assert.AreEqual(stepCount, hosted.FlowStates[flowId].StepCount,
                "The refusal must not consume the seeded record.");
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>'s
    /// <c>invalid_grant</c> covers a code that has "already been redeemed": a SECOND valid replay
    /// of a code the FIRST valid replay already revoked reaches the same early exit an unknown code
    /// answers with, never text of its own.
    /// </summary>
    [TestMethod]
    public async Task SecondValidReplayAfterRevocationAnswersTheSameBodyForAnUnknownAndTheRevokedCodeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);

        (int FirstStatusCode, string FirstBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, FirstStatusCode, FirstBody);

        //FIRST replay: a valid presentation of the redeemed code — revokes the grant and
        //persists RevokedAt.
        (int FirstReplayStatusCode, string FirstReplayBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, FirstReplayStatusCode, FirstReplayBody);

        //SECOND replay: with RevokedAt set — the site under test — compared against a code that
        //was never issued, presented with the same well-formed verifier.
        (int SecondReplayStatusCode, string SecondReplayBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        (int UnknownStatusCode, string UnknownBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, "code-never-issued-by-this-host", pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, SecondReplayStatusCode, SecondReplayBody);
        Assert.AreEqual(UnknownStatusCode, SecondReplayStatusCode);
        Assert.AreEqual(UnknownBody, SecondReplayBody,
            "A code already revoked by an earlier valid replay must answer identically to a code that was never issued.");
    }


    /// <summary>
    /// A code correlation key resolving to a <see cref="ServerTokenIssuedState"/> missing its
    /// binding fields (the refresh-rotation shape of that record type, which a code correlation
    /// key never legitimately resolves to — the code and refresh-token index spaces are disjoint)
    /// answers the same body a code that was never issued does, never distinct text of its own.
    /// </summary>
    [TestMethod]
    public async Task ReplayResolvingToATerminalStateMissingItsBindingFieldsAnswersTheSameBodyForAnUnknownAndALiveCodeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);

        (int FirstStatusCode, string FirstBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, FirstStatusCode, FirstBody);

        string flowId = hosted.FlowStates.Single(pair => pair.Value.State is ServerTokenIssuedState).Key;
        (FlowState state, int stepCount) = hosted.FlowStates[flowId];
        ServerTokenIssuedState issued = Assert.IsInstanceOfType<ServerTokenIssuedState>(state);
        hosted.FlowStates[flowId] = (issued with
        {
            ClientId = null,
            RedirectUri = null,
            CodeChallenge = null,
            CodeChallengeMethod = null
        }, stepCount);

        (int LiveStatusCode, string LiveBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        (int UnknownStatusCode, string UnknownBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, "code-never-issued-by-this-host", pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, LiveStatusCode, LiveBody);
        Assert.AreEqual(UnknownStatusCode, LiveStatusCode);
        Assert.AreEqual(UnknownBody, LiveBody,
            "A replay resolving to a terminal state missing its binding fields must answer identically to a code that was never issued.");
    }


    /// <summary>
    /// A code correlation key resolving to a record of a type the token endpoint never produces or
    /// consumes for a code grant (the shape a store fault could produce) answers the same body a
    /// code that was never issued does, never distinct text of its own.
    /// </summary>
    [TestMethod]
    public async Task TokenEndpointHandleResolvingToAWronglyTypedRecordAnswersTheSameBodyForAnUnknownAndALiveCodeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);
        string flowId = hosted.FlowStates.Single(pair => pair.Value.State is ServerCodeIssuedState state
            && state.CodeChallenge == pkce.EncodedChallenge).Key;
        int stepCount = hosted.FlowStates[flowId].StepCount;

        //A separately pushed PAR gives a genuine ParRequestReceivedState — a record type the code
        //correlation key could never legitimately resolve to. Seeded directly, the shape a
        //corrupted store could produce.
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        (int ParStatusCode, string ParBody) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, parFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, ParStatusCode, ParBody);
        using JsonDocument parDoc = JsonDocument.Parse(ParBody);
        string requestUri = parDoc.RootElement.GetProperty("request_uri").GetString()!;
        string parFlowId = hosted.RequestUriTokenIndex[TestHostShell.ExtractRequestUriToken(new Uri(requestUri))];
        FlowState wronglyTypedState = hosted.FlowStates[parFlowId].State;

        hosted.FlowStates[flowId] = (wronglyTypedState, stepCount);

        (int LiveStatusCode, string LiveBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        (int UnknownStatusCode, string UnknownBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, "code-never-issued-by-this-host", pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, LiveStatusCode, LiveBody);
        Assert.AreEqual(UnknownStatusCode, LiveStatusCode);
        Assert.AreEqual(UnknownBody, LiveBody,
            "A code correlation key resolving to a wrongly-typed record must answer identically to a code that was never issued.");
    }


    /// <summary>
    /// A plain request receives an error redirect after client and destination validation per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>:
    /// "the authorization server informs the client by adding the following parameters to the
    /// query component of the redirection URI using the "application/x-www-form-urlencoded" format".
    /// The state is "The exact value received from the client."
    /// </summary>
    [TestMethod]
    public async Task PlainPkceRefusedAtDirectAuthorizeUnderRfc6749WithPkce()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities.Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization)).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.Plain,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.State] = "pkce state + & = ?"
        };

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string query = string.Join("&", parFields.Select(pair =>
            $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));
        Uri uri = new(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment) + "?" + query);
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, uri, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, (int)response.StatusCode, body);
        Uri location = response.Headers.Location!;
        Assert.IsNotNull(location, "A validated redirect URI receives the authorization error.");
        Dictionary<string, string> parameters = location.Query.TrimStart('?').Split('&')
            .Select(part => part.Split('=', 2))
            .ToDictionary(parts => Uri.UnescapeDataString(parts[0]),
                parts => Uri.UnescapeDataString(parts[1].Replace('+', ' ')), StringComparer.Ordinal);
        Assert.AreEqual(OAuthErrors.InvalidRequest, parameters["error"], "The unsupported method error is invalid_request.");
        Assert.AreEqual("pkce state + & = ?", parameters["state"], "The authorization error echoes the exact state.");
        Assert.AreEqual("only the S256 code challenge method is supported", parameters["error_description"],
            "The error describes the supported transformation.");
    }


    /// <summary>
    /// A plain request receives an error redirect after client and destination validation per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>:
    /// "the authorization server informs the client by adding the following parameters to the
    /// query component of the redirection URI using the "application/x-www-form-urlencoded" format".
    /// The state is "The exact value received from the client."
    /// </summary>
    [TestMethod]
    public async Task PlainPkceRefusedAtDirectAuthorizeBeforeParPolicy()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Fapi20, capabilities: Capabilities.Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization)).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.Plain,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.State] = "pkce state + & = ?"
        };

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string query = string.Join("&", parFields.Select(pair =>
            $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));
        Uri uri = new(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment) + "?" + query);
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, uri, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, (int)response.StatusCode, body);
        Uri location = response.Headers.Location!;
        Assert.IsNotNull(location, "A validated redirect URI receives the authorization error.");
        Dictionary<string, string> parameters = location.Query.TrimStart('?').Split('&')
            .Select(part => part.Split('=', 2))
            .ToDictionary(parts => Uri.UnescapeDataString(parts[0]),
                parts => Uri.UnescapeDataString(parts[1].Replace('+', ' ')), StringComparer.Ordinal);
        Assert.AreEqual(OAuthErrors.InvalidRequest, parameters["error"], "The unsupported method error is invalid_request.");
        Assert.AreEqual("pkce state + & = ?", parameters["state"], "The authorization error echoes the exact state.");
        Assert.AreEqual("only the S256 code challenge method is supported", parameters["error_description"],
            "The error describes the supported transformation.");
    }


    /// <summary>
    /// An absent method requests the refused plain transformation per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>:
    /// "OPTIONAL, defaults to "plain" if not present in the request".
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.4.1">§4.4.1</see> requires
    /// "authorization error response with "error" value set to "invalid_request"."
    /// </summary>
    [TestMethod]
    public async Task AbsentPkceMethodRefusedAtDirectAuthorizeUnderRfc6749WithPkce()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities.Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization)).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.State] = "pkce state + & = ?"
        };

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string query = string.Join("&", parFields.Select(pair =>
            $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));
        Uri uri = new(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment) + "?" + query);
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, uri, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, (int)response.StatusCode, body);
        Uri location = response.Headers.Location!;
        Assert.IsNotNull(location, "A validated redirect URI receives the authorization error.");
        Dictionary<string, string> parameters = location.Query.TrimStart('?').Split('&')
            .Select(part => part.Split('=', 2))
            .ToDictionary(parts => Uri.UnescapeDataString(parts[0]),
                parts => Uri.UnescapeDataString(parts[1].Replace('+', ' ')), StringComparer.Ordinal);
        Assert.AreEqual(OAuthErrors.InvalidRequest, parameters["error"], "The unsupported method error is invalid_request.");
        Assert.AreEqual("pkce state + & = ?", parameters["state"], "The authorization error echoes the exact state.");
        Assert.AreEqual("only the S256 code challenge method is supported", parameters["error_description"],
            "The error describes the supported transformation.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see>:
    /// "response_type: REQUIRED." <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.1">§3.1.1</see>:
    /// "If an authorization request is missing the "response_type" parameter... the
    /// authorization server MUST return an error response as described in Section 4.1.2.1."
    /// A validated destination receives the error redirect rather than an implicit
    /// <c>code</c> grant.
    /// </summary>
    [TestMethod]
    public async Task AbsentResponseTypeRefusedAtDirectAuthorizeUnderRfc6749WithPkce()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities.Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization)).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.State] = "response_type state + & = ?"
        };

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string query = string.Join("&", parFields.Select(pair =>
            $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));
        Uri uri = new(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment) + "?" + query);
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, uri, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, (int)response.StatusCode, body);
        Uri location = response.Headers.Location!;
        Assert.IsNotNull(location, "A validated redirect URI receives the authorization error.");
        Dictionary<string, string> parameters = location.Query.TrimStart('?').Split('&')
            .Select(part => part.Split('=', 2))
            .ToDictionary(parts => Uri.UnescapeDataString(parts[0]),
                parts => Uri.UnescapeDataString(parts[1].Replace('+', ' ')), StringComparer.Ordinal);
        Assert.AreEqual(OAuthErrors.InvalidRequest, parameters["error"], "A missing response_type is invalid_request.");
        Assert.AreEqual("response_type state + & = ?", parameters["state"], "The authorization error echoes the exact state.");
        Assert.AreEqual("Missing response_type.", parameters["error_description"],
            "The error names the missing required parameter.");
    }


    /// <summary>
    /// An invalid client or destination receives a direct refusal per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>:
    /// "MUST NOT automatically redirect the user-agent to the invalid redirection URI".
    /// </summary>
    [TestMethod]
    public async Task PlainPkceWithInvalidRedirectUriDoesNotRedirect()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities.Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization)).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.Plain,
            [OAuthRequestParameterNames.RedirectUri] = "https://unregistered.example/cb",
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.State] = "pkce state + & = ?"
        };

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string query = string.Join("&", parFields.Select(pair =>
            $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));
        Uri uri = new(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment) + "?" + query);
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, uri, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.IsNull(response.Headers.Location, "An invalid client or redirect URI must not receive a redirect.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-7.5.2">OAuth 2.1 §7.5.2</see>:
    /// "The plain code challenge method, defined in [RFC7636], is explicitly forbidden in OAuth 2.1."
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.4.1">RFC 7636 §4.4.1</see>
    /// requires <c>invalid_request</c> for this unsupported transformation.
    /// </summary>
    [TestMethod]
    public async Task PlainPkceRefusedAtParUnderRfc6749WithPkce()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.Plain,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, parFields, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidRequest}\"", Body, StringComparison.Ordinal);
        Assert.Contains("only the S256 code challenge method is supported", Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.1">RFC 9126 §2.1</see>: "the
    /// "request_uri" authorization request parameter defined in Section 4 of [RFC9101] ... MUST NOT be
    /// provided" on a pushed authorization request. A PAR body otherwise carrying a complete,
    /// well-formed authorization request is refused for presenting one.
    /// </summary>
    [TestMethod]
    public async Task RequestUriIsRefusedWhenPresentedToThePushedAuthorizationEndpoint()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.RequestUri] = "urn:ietf:params:oauth:request_uri:arbitrary"
        };

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, parFields, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        using JsonDocument error = JsonDocument.Parse(Body);
        Assert.AreEqual(OAuthErrors.InvalidRequest, error.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 §3.1</see>: "Parameters
    /// sent without a value MUST be treated as if they were omitted from the request." A pushed
    /// authorization request carrying an empty <c>request</c> alongside an otherwise-complete PKCE
    /// body is therefore the SAME request as one naming no <c>request</c> at all
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.1">RFC 9126 §2.1</see> carries
    /// "any of the parameters applicable for use at the authorization endpoint"), accepted and pushed.
    /// </summary>
    [TestMethod]
    public async Task EmptyRequestIsTreatedAsOmittedAtPushedAuthorization()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.Request] = string.Empty
        };

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, parFields, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, StatusCode, Body);
        using JsonDocument response = JsonDocument.Parse(Body);
        Assert.IsFalse(string.IsNullOrEmpty(response.RootElement.GetProperty("request_uri").GetString()));
    }


    /// <summary>
    /// An absent method requests the refused plain transformation per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>:
    /// "OPTIONAL, defaults to "plain" if not present in the request".
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.4.1">§4.4.1</see> requires
    /// "authorization error response with "error" value set to "invalid_request"."
    /// </summary>
    [TestMethod]
    public async Task AbsentPkceMethodRefusedAtParUnderRfc6749WithPkce()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, parFields, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidRequest}\"", Body, StringComparison.Ordinal);
        Assert.Contains("only the S256 code challenge method is supported", Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.1">RFC 9126 §2.1</see>: the PAR
    /// body carries the same authorization request parameters, so
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see>'s
    /// "response_type: REQUIRED" applies. A missing parameter is answered directly per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.3">RFC 9126 §2.3</see> — PAR has
    /// no redirect leg of its own.
    /// </summary>
    [TestMethod]
    public async Task AbsentResponseTypeRefusedAtParUnderRfc6749WithPkce()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, parFields, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidRequest}\"", Body, StringComparison.Ordinal);
        Assert.Contains("Missing response_type.", Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-7.5.2">OAuth 2.1 §7.5.2</see>:
    /// "The plain code challenge method, defined in [RFC7636], is explicitly forbidden in OAuth 2.1."
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.4.1">RFC 7636 §4.4.1</see>
    /// requires <c>invalid_request</c> for this unsupported transformation.
    /// </summary>
    [TestMethod]
    public async Task PlainPkceRefusedAtParUnderS256OnlyDefault()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Fapi20, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.Plain,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, parFields, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidRequest}\"", Body, StringComparison.Ordinal);
        Assert.Contains("only the S256 code challenge method is supported", Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.6">RFC 7636 §4.6</see>: PKCE
    /// verification dispatches on the <c>code_challenge_method</c> PERSISTED at authorization time,
    /// never on one a client could assert at the token request (which carries no such parameter at
    /// all). An S256-issued code presented with the CHALLENGE STRING itself as <c>code_verifier</c>
    /// — which a naive "plain" comparison would accept, since challenge == challenge — still fails
    /// <c>invalid_grant</c>, because the persisted method makes the endpoint hash it instead.
    /// </summary>
    [TestMethod]
    public async Task S256IssuedCodeVerifiedAgainstPersistedMethodNotRequest()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);

        (int TokenStatusCode, string TokenBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedChallenge, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, TokenStatusCode, TokenBody);
        Assert.Contains(OAuthErrors.InvalidGrant, TokenBody, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>:
    /// <c>invalid_grant</c> covers a "provided authorization grant ... invalid, expired, revoked."
    /// A token request naming a <c>code</c> the store never issued fails <c>invalid_grant</c>, not
    /// the host-generic <c>invalid_request</c> a correlation-handle miss would otherwise produce.
    /// </summary>
    [TestMethod]
    public async Task UnknownAuthorizationCodeAtTokenEndpointIsInvalidGrant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, material.Registration.TenantId.Value,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, "code-never-issued-by-this-host", "verifier-does-not-matter", RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidGrant, Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §7.5.2</see> reads together with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see>'s
    /// "the authorization server MUST enforce the correct usage of code_verifier at the token
    /// endpoint": an unauthenticated party holding only a candidate <c>code</c> string must not be
    /// able to learn whether that code was ever issued by omitting <c>code_verifier</c> — a live,
    /// genuinely-issued code presented with no verifier at all answers with the exact same
    /// <c>error</c> and <c>error_description</c> as a <c>code</c> the store never issued.
    /// </summary>
    [TestMethod]
    public async Task MissingCodeVerifierOnALiveCodeMatchesTheUnknownCodeResponse()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

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
        AuthorizationCodeReceivedState codeState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, codeState.Code, codeVerifier: null, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        (int StatusCode, string Body) unknownCode = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, "code-never-issued-by-this-host", codeVerifier: null, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.AreEqual(unknownCode.StatusCode, StatusCode);
        Assert.AreEqual(unknownCode.Body, Body,
            "A candidate code's existence must not be discoverable from whether code_verifier was sent.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.11">RFC 6749 Appendix A.11</see>:
    /// "code = 1*VSCHAR" — a <c>code</c> containing a byte outside <c>VSCHAR</c> (<c>%x20-7E</c>)
    /// was never issued by this server, so it answers with the exact same <c>error</c> and
    /// <c>error_description</c> as a well-formed but never-issued code, never a response that
    /// could let a caller distinguish "malformed" from "unknown."
    /// </summary>
    [TestMethod]
    public async Task NonAsciiCodeMatchesTheUnknownCodeResponse()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, "código-que-no-fue-emitido", codeVerifier: "verifier-does-not-matter",
                RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        (int StatusCode, string Body) unknownCode = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, "code-never-issued-by-this-host", codeVerifier: "verifier-does-not-matter",
                RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.AreEqual(unknownCode.StatusCode, StatusCode);
        Assert.AreEqual(unknownCode.Body, Body,
            "A non-ASCII code must not be distinguishable from a well-formed but unknown code.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>:
    /// <c>invalid_grant</c> covers "expired." A genuinely issued code presented after its
    /// persisted <c>ExpiresAt</c> has passed (the injected <see cref="FakeTimeProvider"/> advanced
    /// past it) fails <c>invalid_grant</c> AT THE SERVER — driven with
    /// <see cref="RawAuthCodeWirePushers"/> rather than <see cref="AuthCodeClient.ExchangeTokenAsync(ClientRegistration, string, CancellationToken)"/>
    /// so the assertion exercises the server's own refusal, not the client SDK's own separate
    /// local-expiry guard. The policy that governs a PAR-issued code's <c>ExpiresAt</c> is the
    /// 600-second authorization-code lifetime
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>:
    /// "A maximum authorization code lifetime of 10 minutes is RECOMMENDED.") — never the
    /// 60-second <c>request_uri</c> lifetime (RFC 9126 §4); see
    /// <see cref="ParIssuedCodeRedeemsAfterRequestUriLifetimeElapses"/> for the positive case that
    /// isolates the two.
    /// </summary>
    [TestMethod]
    public async Task ExpiredAuthorizationCodeAtTokenExchangeIsInvalidGrant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

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
        AuthorizationCodeReceivedState codeState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        //700s clears the 600-second authorization-code lifetime (RFC 6749 §4.1.2) that governs
        //this code's ExpiresAt, so RFC 6749 §5.2's "expired" fires regardless of the shorter
        //60-second request_uri lifetime (RFC 9126 §4) having elapsed too.
        TimeProvider.Advance(TimeSpan.FromSeconds(700));

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, codeState.Code, codeState.Pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidGrant, Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>:
    /// "A maximum authorization code lifetime of 10 minutes is RECOMMENDED." A PAR-issued code's
    /// persisted <c>ExpiresAt</c> is governed by the 600-second authorization-code lifetime, not
    /// by the shorter 60-second <c>request_uri</c> lifetime
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9126#section-4">RFC 9126 §4</see>) — presenting
    /// the code after the <c>request_uri</c>'s own lifetime has elapsed, but still within the
    /// code lifetime, redeems.
    /// </summary>
    [TestMethod]
    public async Task ParIssuedCodeRedeemsAfterRequestUriLifetimeElapses()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

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
        AuthorizationCodeReceivedState codeState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        //61s: one second past the 60-second default request_uri lifetime (RFC 9126 §4), but well
        //inside the 600-second default authorization-code lifetime (RFC 6749 §4.1.2) that governs
        //this issued code's own ExpiresAt.
        TimeProvider.Advance(TimeSpan.FromSeconds(61));

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, codeState.Code, codeState.Pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, StatusCode,
            $"A PAR-issued code must redeem within its own authorization-code lifetime even after "
            + $"the shorter request_uri lifetime has elapsed. Body={Body}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>:
    /// "invalid_request ... The request is missing a required parameter." A code-grant token
    /// request that omits <c>code</c> entirely is refused <c>invalid_request</c> with an OAuth
    /// error JSON body — never the host's bare, bodiless 404 a request no endpoint recognizes
    /// would otherwise produce.
    /// </summary>
    [TestMethod]
    public async Task MissingCodeParameterAtTokenEndpointIsInvalidRequestWithOAuthBody()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, material.Registration.TenantId.Value,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, code: null, codeVerifier: "verifier-does-not-matter", redirectUri: RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidRequest, Body, StringComparison.Ordinal);

        using JsonDocument doc = JsonDocument.Parse(Body);
        Assert.AreEqual("Missing code.", doc.RootElement.GetProperty("error_description").GetString(),
            "RFC 6749 §5.2's invalid_request names the missing required parameter, in the style of "
            + "this endpoint's own 'Missing grant_type.' refusal, rather than the host-generic "
            + "'Cannot determine correlation key.'");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 §4.1.3</see>:
    /// "redirect_uri: REQUIRED, if the "redirect_uri" parameter was included in the authorization
    /// request as described in Section 4.1.1, and their values MUST be identical." A
    /// <c>redirect_uri</c> that IS sent at redemption must therefore be the single value bound to
    /// the code. A PRESENT value naming anything other than the bound one answers the same
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>
    /// <c>invalid_grant</c> body as a redemption whose code is unknown, so a credential-less
    /// presenter cannot distinguish which check failed. A REPEATED <c>redirect_uri</c> — bound
    /// alongside a foreign value, or the bound value sent twice — is a malformed request under
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>, which
    /// answers <c>invalid_request</c> for a request that "repeats a parameter", refused before the
    /// code record is ever loaded, naming the repetition. An OMITTED or EMPTY <c>redirect_uri</c> —
    /// RFC 6749 §3.1 treats the two alike — is accepted on the code's PKCE binding, the posture
    /// <see cref="RedirectUriMatchingTests.RealWireTokenRedirectUriAbsentWithPkceBoundCodeIsAccepted"/>
    /// pins under <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §10.2</see>'s "the authorization server MUST allow clients to send the
    /// redirect_uri parameter in the token request ... and MUST enforce the parameter as described
    /// in [RFC6749]".
    /// </summary>
    [TestMethod]
    [DataRow("omitted")]
    [DataRow("empty")]
    [DataRow("repeated bound+foreign")]
    [DataRow("repeated bound+bound")]
    [DataRow("mismatch")]
    [DataRow("correct")]
    public async Task PresentRedirectUriMustBeTheBoundValueAtCodeRedemption(string shape)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: Capabilities.Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization)).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> authorizeFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        using HttpResponseMessage authorizeResponse = await SendAuthorizeGetAsync(host, hosted, segment, authorizeFields)
            .ConfigureAwait(false);
        Assert.AreEqual(302, (int)authorizeResponse.StatusCode,
            await authorizeResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false));
        string code = TestBrowser.ExtractQueryParam(
            authorizeResponse.Headers.Location!.ToString(), OAuthRequestParameterNames.Code)!;

        Dictionary<string, string> baseTokenFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, code, pkce.EncodedVerifier, redirectUri: null);
        List<KeyValuePair<string, string>> wireFields = new(baseTokenFields);
        switch(shape)
        {
            case "empty":
                wireFields.Add(KeyValuePair.Create(OAuthRequestParameterNames.RedirectUri, string.Empty));
                break;
            case "repeated bound+foreign":
                //A code bound to a leaky redirect_uri, repeated alongside a second, foreign value:
                //the shape an attacker who steals a code sent to a registered-but-leaky URI would
                //present while injecting their own callback.
                wireFields.Add(KeyValuePair.Create(OAuthRequestParameterNames.RedirectUri, RedirectUri.OriginalString));
                wireFields.Add(KeyValuePair.Create(OAuthRequestParameterNames.RedirectUri, "https://attacker.example/cb"));
                break;
            case "repeated bound+bound":
                //The SAME bound value sent twice is still a repetition RFC 6749 §5.2 refuses —
                //value-equality among the occurrences does not make the parameter singular.
                wireFields.Add(KeyValuePair.Create(OAuthRequestParameterNames.RedirectUri, RedirectUri.OriginalString));
                wireFields.Add(KeyValuePair.Create(OAuthRequestParameterNames.RedirectUri, RedirectUri.OriginalString));
                break;
            case "mismatch":
                wireFields.Add(KeyValuePair.Create(OAuthRequestParameterNames.RedirectUri, "https://attacker.example/cb"));
                break;
            case "correct":
                wireFields.Add(KeyValuePair.Create(OAuthRequestParameterNames.RedirectUri, RedirectUri.OriginalString));
                break;
            case "omitted":
                break;
        }

        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, wireFields, TestContext.CancellationToken).ConfigureAwait(false);

        if(shape is "correct" or "omitted" or "empty")
        {
            Assert.AreEqual(200, statusCode, body);

            return;
        }

        using JsonDocument error = JsonDocument.Parse(body);
        if(shape is "repeated bound+foreign" or "repeated bound+bound")
        {
            Assert.AreEqual(400, statusCode, body);
            Assert.AreEqual(OAuthErrors.InvalidRequest, error.RootElement.GetProperty("error").GetString());
            Assert.AreEqual(
                "redirect_uri must not be repeated.",
                error.RootElement.GetProperty("error_description").GetString(),
                "A repeated redirect_uri names the repetition rather than answering the same body as an unknown code.");

            return;
        }

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(OAuthErrors.InvalidGrant, error.RootElement.GetProperty("error").GetString());
        Assert.AreEqual(
            "The authorization code is unknown, expired, or already used.",
            error.RootElement.GetProperty("error_description").GetString(),
            "A mismatched redirect_uri must answer the SAME body as an unknown code.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 §3.2</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// applied at the token endpoint to <c>authorization_details</c>: an empty occurrence reads as
    /// no narrowing request, exactly as an omitted occurrence would, both before and after this
    /// read moved onto the endpoint's shared <c>ReadAuthorizationDetails</c> helper — so
    /// this assertion holds regardless of which of those two equivalent implementations answers it,
    /// and exists to keep that equivalence from silently drifting.
    /// </summary>
    [TestMethod]
    public async Task EmptyAuthorizationDetailsAtCodeRedemptionMatchesOmittedBehavior()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: Capabilities.Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization)).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        async Task<(int StatusCode, string Body)> RedeemAsync(bool includeEmptyAuthorizationDetails)
        {
            PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
            Dictionary<string, string> authorizeFields = new(StringComparer.Ordinal)
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
                [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
                [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
                [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
                [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
            };
            using HttpResponseMessage authorizeResponse = await SendAuthorizeGetAsync(host, hosted, segment, authorizeFields)
                .ConfigureAwait(false);
            Assert.AreEqual(302, (int)authorizeResponse.StatusCode,
                await authorizeResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false));
            string code = TestBrowser.ExtractQueryParam(
                authorizeResponse.Headers.Location!.ToString(), OAuthRequestParameterNames.Code)!;

            Dictionary<string, string> tokenFields = RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString);
            if(includeEmptyAuthorizationDetails)
            {
                tokenFields[OAuthRequestParameterNames.AuthorizationDetails] = string.Empty;
            }

            return await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, tokenFields, TestContext.CancellationToken).ConfigureAwait(false);
        }

        (int omittedStatusCode, string omittedBody) = await RedeemAsync(includeEmptyAuthorizationDetails: false).ConfigureAwait(false);
        (int emptyStatusCode, string emptyBody) = await RedeemAsync(includeEmptyAuthorizationDetails: true).ConfigureAwait(false);

        Assert.AreEqual(200, omittedStatusCode, omittedBody);
        Assert.AreEqual(200, emptyStatusCode, emptyBody);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 §3.1</see>: "Parameters
    /// sent without a value MUST be treated as if they were omitted from the request." Applied to the
    /// OPTIONAL <c>response_mode</c> parameter at direct authorization: a GET naming
    /// <c>response_mode=</c> produces the same RFC 6749 §4.1.2 redirect shape as one that omits the
    /// parameter entirely — both read as no request for a JWT-secured response, so both take the
    /// plain-redirect branch to the SAME registered <c>redirect_uri</c> with the SAME set of query
    /// parameter names, the one-time <c>code</c> value aside.
    /// </summary>
    [TestMethod]
    public async Task EmptyResponseModeAtDirectAuthorizationMatchesOmittedBehavior()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: Capabilities.Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization)).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        static IEnumerable<string> QueryParamNames(Uri location) =>
            location.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Select(part => Uri.UnescapeDataString(part[..part.IndexOf('=', StringComparison.Ordinal)]))
                .OrderBy(name => name, StringComparer.Ordinal);

        async Task<HttpResponseMessage> AuthorizeAsync(bool includeEmptyResponseMode)
        {
            PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
            Dictionary<string, string> fields = new(StringComparer.Ordinal)
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
                [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
                [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
                [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
                [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
            };
            if(includeEmptyResponseMode)
            {
                fields[OAuthRequestParameterNames.ResponseMode] = string.Empty;
            }

            return await SendAuthorizeGetAsync(host, hosted, segment, fields).ConfigureAwait(false);
        }

        using HttpResponseMessage omittedResponse = await AuthorizeAsync(includeEmptyResponseMode: false).ConfigureAwait(false);
        using HttpResponseMessage emptyResponse = await AuthorizeAsync(includeEmptyResponseMode: true).ConfigureAwait(false);

        Assert.AreEqual(302, (int)omittedResponse.StatusCode,
            await omittedResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false));
        Assert.AreEqual((int)omittedResponse.StatusCode, (int)emptyResponse.StatusCode);

        Uri omittedLocation = omittedResponse.Headers.Location!;
        Uri emptyLocation = emptyResponse.Headers.Location!;
        Assert.AreEqual(omittedLocation.GetLeftPart(UriPartial.Path), emptyLocation.GetLeftPart(UriPartial.Path),
            "An omitted response_mode and an empty one must redirect to the same registered redirect_uri.");
        Assert.AreSequenceEqual(QueryParamNames(omittedLocation).ToList(), QueryParamNames(emptyLocation).ToList(),
            "An omitted response_mode and an empty one must redirect with the same set of query parameters.");
        Assert.IsNotNull(TestBrowser.ExtractQueryParam(omittedLocation.ToString(), OAuthRequestParameterNames.Code));
        Assert.IsNotNull(TestBrowser.ExtractQueryParam(emptyLocation.ToString(), OAuthRequestParameterNames.Code));
    }


    /// <summary>
    /// Real-wire RFC 8707 threading capstone: PAR carries a genuinely REPEATED <c>resource</c>
    /// parameter over the wire (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC
    /// 8707 §2</see>'s actual multi-resource wire form), CODE REDEMPTION narrows the issued access
    /// token to a subset — proving
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">§2.2</see> Figure 3's
    /// example over the real wire, not merely the refresh leg — and the issued access token's
    /// <c>aud</c> claim, decoded off the real wire byte-for-byte, is asserted to be the RFC 7519
    /// §4.1.3 JSON ARRAY shape throughout. A no-resource refresh then proves the refresh token
    /// itself stayed bound to the FULL original grant despite the narrowed code redemption, before
    /// a second, refresh-leg narrowing round (§2.2's central example) and a final no-resource
    /// refresh confirm the rotated refresh token is likewise still bound to the full grant.
    /// </summary>
    [TestMethod]
    public async Task FullJourneyThreadsResourceIndicatorToArrayAudience()
    {
        const string ResourceA = "https://cal.example.com/";
        const string ResourceB = "https://contacts.example.com/";

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(true);
        }).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        //PAR carries the multi-resource request through the CLIENT abstraction
        //(AuthCodeClient.StartParAsync's resource-bearing overload), which threads each entry to the
        //wire as its OWN repeated resource occurrence — never a raw hand-built POST.
        string flowId = await DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, host.ServerCertificate,
            TestContext.CancellationToken, resource: [ResourceA, ResourceB])
            .ConfigureAwait(false);

        //§2.2 Figure 3: a resource named AT CODE REDEMPTION narrows the minted access token to that
        //subset.
        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration,
            flowId,
            [],
            clientAssertionOptions: null,
            resource: [ResourceA],
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Token exchange must succeed over the real wire. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
        string accessToken = (string)tokenResult.Body![OAuthRequestParameterNames.AccessToken];
        string refreshToken = (string)tokenResult.Body[OAuthRequestParameterNames.RefreshToken];

        using JsonDocument accessPayload = DecodePayload(accessToken);
        JsonElement aud = accessPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Aud);
        Assert.AreEqual(JsonValueKind.Array, aud.ValueKind,
            $"aud must be a JSON array byte-honestly — RFC 7519 §4.1.3, this producer's always-array rule. Payload: {accessPayload.RootElement}");
        Assert.AreEqual(1, aud.GetArrayLength(),
            $"§2.2 Figure 3: the code-redemption resource must narrow the access token to that subset alone. Payload: {accessPayload.RootElement}");
        Assert.AreEqual(ResourceA, aud[0].GetString());

        //A no-resource refresh proves the refresh token stayed bound to the FULL original two-resource
        //grant (§2.2: "any refresh token that is returned is bound to the full original grant")
        //despite the code-redemption access token above having been narrowed to one.
        AuthCodeFlowEndpointResult fullRefresh = await client.AuthCode.RefreshAsync(
            registration,
            new RefreshTokenRequest { ClientId = ClientId, RefreshToken = refreshToken },
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, fullRefresh.Outcome,
            $"The unnarrowed refresh must succeed over the real wire. ErrorCode={fullRefresh.ErrorCode} ErrorDescription={fullRefresh.ErrorDescription}");
        string fullAccessToken = (string)fullRefresh.Body![OAuthRequestParameterNames.AccessToken];
        string rotatedRefreshToken = (string)fullRefresh.Body[OAuthRequestParameterNames.RefreshToken];

        using JsonDocument fullPayload = DecodePayload(fullAccessToken);
        JsonElement fullAud = fullPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Aud);
        Assert.AreEqual(JsonValueKind.Array, fullAud.ValueKind);
        Assert.AreEqual(2, fullAud.GetArrayLength(),
            "The refresh token must be bound to the FULL original grant even though the code-redemption access token was narrowed.");
        List<string> fullAudValues = fullAud.EnumerateArray().Select(e => e.GetString()!).ToList();
        Assert.Contains(ResourceA, fullAudValues);
        Assert.Contains(ResourceB, fullAudValues);

        //Refresh-narrowing round (RFC 8707 §2.2's central example): a refresh-request resource
        //narrows the ACCESS token to a subset, while the ROTATED refresh token stays bound to the
        //full grant.
        AuthCodeFlowEndpointResult narrowedRefresh = await client.AuthCode.RefreshAsync(
            registration,
            new RefreshTokenRequest { ClientId = ClientId, RefreshToken = rotatedRefreshToken, Resource = [ResourceB] },
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, narrowedRefresh.Outcome,
            $"Narrowed refresh must succeed over the real wire. ErrorCode={narrowedRefresh.ErrorCode} ErrorDescription={narrowedRefresh.ErrorDescription}");
        string narrowedAccessToken = (string)narrowedRefresh.Body![OAuthRequestParameterNames.AccessToken];
        string twiceRotatedRefreshToken = (string)narrowedRefresh.Body[OAuthRequestParameterNames.RefreshToken];

        using JsonDocument narrowedPayload = DecodePayload(narrowedAccessToken);
        JsonElement narrowedAud = narrowedPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Aud);
        Assert.AreEqual(JsonValueKind.Array, narrowedAud.ValueKind);
        Assert.HasCount(1, narrowedAud.EnumerateArray().ToList(),
            $"A refresh-request resource must narrow the access token to that subset alone. Payload: {narrowedPayload.RootElement}");
        Assert.AreEqual(ResourceB, narrowedAud[0].GetString());

        //A THIRD, no-resource refresh proves the TWICE-rotated refresh token itself was never
        //narrowed — it is still bound to the full original two-resource grant.
        AuthCodeFlowEndpointResult fullRefreshAgain = await client.AuthCode.RefreshAsync(
            registration,
            new RefreshTokenRequest { ClientId = ClientId, RefreshToken = twiceRotatedRefreshToken },
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, fullRefreshAgain.Outcome,
            $"The unnarrowed refresh must still succeed. ErrorCode={fullRefreshAgain.ErrorCode} ErrorDescription={fullRefreshAgain.ErrorDescription}");
        string fullAccessTokenAgain = (string)fullRefreshAgain.Body![OAuthRequestParameterNames.AccessToken];

        using JsonDocument fullPayloadAgain = DecodePayload(fullAccessTokenAgain);
        JsonElement fullAudAgain = fullPayloadAgain.RootElement.GetProperty(WellKnownJwtClaimNames.Aud);
        Assert.AreEqual(JsonValueKind.Array, fullAudAgain.ValueKind);
        Assert.AreEqual(2, fullAudAgain.GetArrayLength(),
            "The refresh token must still be bound to the FULL original grant (RFC 8707 §2.2) even after two prior narrowed exchanges.");
    }


    /// <summary>
    /// Concurrent authorization requests for one pushed reference issue exactly one code, enforcing
    /// the one-time-use recommendation in
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-4">RFC 9126 §4</see>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see>
    /// defines the single-use reference. Every losing claim receives a redirect carrying
    /// <c>invalid_request_uri</c>, the reference-error code that
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-7">RFC 9101 §7</see> defines
    /// for a reference returning an error or invalid data. All contenders load the same pending
    /// request before a barrier releases them, ensuring the single-use claim is contested.
    /// </summary>
    [TestMethod]
    public async Task ConcurrentAuthorizeRequestsForTheSameRequestUriYieldExactlyOneIssuedCode()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        (int ParStatusCode, string ParBody) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, parFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, ParStatusCode, ParBody);

        using JsonDocument parBody = JsonDocument.Parse(ParBody);
        string requestUri = parBody.RootElement.GetProperty("request_uri").GetString()!;

        HostedAuthorizationServer hosted = host.Host("default");
        Uri authorizeUrl = new(
            hosted.HttpBaseAddress!,
            $"{TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment)}" +
            $"?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(ClientId)}" +
            $"&{OAuthRequestParameterNames.RequestUri}={Uri.EscapeDataString(requestUri)}");

        const int ConcurrentRequests = 8;
        hosted.IsOrderingRequestsPerGrant = false;
        await using CancellableTestBarrier authorizeBarrier = new(
            "authorize pending request", ConcurrentRequests, TestContext.CancellationToken);
        LoadServerFlowStateDelegate originalLoad = host.Server.OAuth().LoadFlowStateAsync!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.LoadFlowStateAsync = async (tenantId, key, ctx, ct) =>
            {
                try
                {
                    (FlowState? state, int stepCount) = await originalLoad(tenantId, key, ctx, ct).ConfigureAwait(false);
                    if(state is ParRequestReceivedState)
                    {
                        await authorizeBarrier.SignalAndWaitAsync().ConfigureAwait(false);
                    }

                    return (state, stepCount);
                }
                catch(Exception exception) when(!TestContext.CancellationToken.IsCancellationRequested)
                {
                    authorizeBarrier.ReportFault(exception);
                    throw;
                }

            };
        }).ConfigureAwait(false);

        Task<HttpResponseMessage>[] authorizeCalls = [.. Enumerable.Range(0, ConcurrentRequests)
            .Select(_ => authorizeBarrier.ObserveParticipantAsync(() => RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
                host, authorizeUrl, SubjectId, TestContext.CancellationToken)))];

        await authorizeBarrier.WaitForReleaseAsync().ConfigureAwait(false);
        HttpResponseMessage[] responses = await Task.WhenAll(authorizeCalls).ConfigureAwait(false);
        List<Dictionary<string, string>> redirects = [];
        foreach(HttpResponseMessage response in responses)
        {
            string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(302, (int)response.StatusCode,
                $"Every authorization outcome must redirect to the registered callback. Body: {body}");
            Assert.IsNotNull(response.Headers.Location);
            redirects.Add(ParseQuery(response.Headers.Location));
        }

        _ = Assert.ContainsSingle(r => r.ContainsKey(OAuthRequestParameterNames.Code), redirects,
            "RFC 9126 §4: request_uri is single-use — exactly one concurrent authorize GET may consume it.");
        foreach(Dictionary<string, string> refusal in redirects.Where(r => !r.ContainsKey(OAuthRequestParameterNames.Code)))
        {
            Assert.AreEqual(OAuthErrors.InvalidRequestUri, refusal.GetValueOrDefault(OAuthRequestParameterNames.Error),
                "RFC 9126 §4 and RFC 9101 §7 require invalid_request_uri for each refused single-use reference.");

        }

    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.1.3</see>: "The authorization server MUST return an access token only once
    /// for a given authorization code." N concurrent token requests presenting the identical
    /// valid code and verifier race against the same claim; the invariant under test is exactly
    /// one 200 and every other response invalid_grant — never which request wins, and never that
    /// a particular code path fired. A gate on <see cref="ServerIntegration.LoadFlowStateAsync"/>
    /// holds every contender until all N have loaded the SAME live <see cref="ServerCodeIssuedState"/>
    /// before releasing them together, so the assertions below exercise the atomic
    /// <see cref="ServerIntegration.ClaimFlowStateAsync"/> race itself rather than merely a
    /// sequence of independent redemptions the async scheduler happened to interleave one at a
    /// time — a shape reuse-detection-shaped refusals alone could satisfy without the claim ever
    /// actually contending.
    /// </summary>
    [TestMethod]
    public async Task ConcurrentTokenRedemptionOfSameCodeYieldsExactlyOneSuccess()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");

        //This test forces same-version claim contention on the code's own live record: with the
        //per-grant ordering gate on, the second request would never enter the library while the
        //first is held at LoadFlowStateAsync below.
        hosted.IsOrderingRequestsPerGrant = false;
        string segment = material.Registration.TenantId.Value;

        string flowId = await DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, host.ServerCertificate, TestContext.CancellationToken)
            .ConfigureAwait(false);
        AuthorizationCodeReceivedState codeState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        Dictionary<string, string> tokenFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, codeState.Code, codeState.Pkce.EncodedVerifier, RedirectUri.OriginalString);

        const int ConcurrentRequests = 8;

        await using CancellableTestBarrier redemptionBarrier = new(
            "authorization code redemption", ConcurrentRequests, TestContext.CancellationToken);
        LoadServerFlowStateDelegate originalLoad = host.Server.OAuth().LoadFlowStateAsync!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.LoadFlowStateAsync = async (tenantId, key, ctx, ct) =>
            {
                try
                {
                    (FlowState? state, int stepCount) = await originalLoad(tenantId, key, ctx, ct).ConfigureAwait(false);
                    if(state is ServerCodeIssuedState)
                    {
                        await redemptionBarrier.SignalAndWaitAsync().ConfigureAwait(false);
                    }

                    return (state, stepCount);
                }
                catch(Exception exception) when(!TestContext.CancellationToken.IsCancellationRequested)
                {
                    redemptionBarrier.ReportFault(exception);
                    throw;
                }

            };
        }).ConfigureAwait(false);

        Task<(int StatusCode, string Body)>[] redemptions = [.. Enumerable.Range(0, ConcurrentRequests)
            .Select(_ => redemptionBarrier.ObserveParticipantAsync(() => RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, tokenFields, TestContext.CancellationToken)))];

        await redemptionBarrier.WaitForReleaseAsync().ConfigureAwait(false);
        (int StatusCode, string Body)[] responses = await Task.WhenAll(redemptions).ConfigureAwait(false);

        _ = Assert.ContainsSingle(r => r.StatusCode == 200, responses,
            $"Exactly one concurrent redemption of the same code must succeed. Bodies: {string.Join(" | ", responses.Select(r => r.Body))}");
        Assert.AreEqual(ConcurrentRequests - 1,
            responses.Count(r => r.StatusCode == 400
                && r.Body.Contains(OAuthErrors.InvalidGrant, StringComparison.Ordinal)),
            $"Every losing concurrent redemption must fail invalid_grant. Bodies: {string.Join(" | ", responses.Select(r => r.Body))}");
    }


    /// <summary>
    /// A rule of this library: no release follows a walk that completed. A redemption whose issuance walk completed,
    /// its first store write made and its tokens minted, and whose dispatcher's save of the resulting state then
    /// throws keeps its claim, since a persisted record of the step, the refresh token born of the code, may already
    /// be live: the redemption over the wire is answered 500 with the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> that the
    /// host writes for the fault, and the same code presented again with the store restored is answered 400 with the
    /// body
    /// <c>{"error":"invalid_grant","error_description":"The authorization code is unknown, expired, or already used."}</c>.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-4.1.3">OAuth 2.1 draft-16
    /// Section 4.1.3</see> requires the denial for "a previously successful token request"; this library keeps the code
    /// spent from the step's first store write on, whether or not the request that made it succeeded.
    /// </summary>
    [TestMethod]
    public async Task AFailureAfterPersistenceBeganLeavesTheCodeSpentAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);
        Dictionary<string, string> tokenFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString);

        //Every save the redemption makes is recorded by the type of the state saved; the second one throws.
        ConcurrentQueue<string> savedStates = new();
        int saveCount = 0;
        SaveServerFlowStateDelegate originalSave = host.Server.OAuth().SaveFlowStateAsync!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            candidateIntegration.SaveFlowStateAsync = (tenantId, key, state, stepCount, ctx, ct) =>
            {
                savedStates.Enqueue(state.GetType().Name);
                if(Interlocked.Increment(ref saveCount) == 2)
                {
                    throw new InvalidOperationException("The flow store is unavailable.");
                }

                return originalSave(tenantId, key, state, stepCount, ctx, ct);
            }).ConfigureAwait(false);

        (int failedStatus, string failedBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, tokenFields, TestContext.CancellationToken).ConfigureAwait(false);
        string savedRecord = string.Join(", ", savedStates);
        Assert.AreEqual(500, failedStatus, $"{failedBody} saves: {savedRecord}");
        Assert.AreEqual(
            "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            failedBody);
        Assert.AreEqual(nameof(ServerRefreshTokenIssuedState), savedStates.First(),
            $"The first store write of the redemption precedes the failure. Saves: {savedRecord}");
        Exception fault = Assert.ContainsSingle(host.Host("default").ConsumeHttpFaults());
        Assert.AreEqual("The flow store is unavailable.", fault.Message, failedBody);

        //The store is restored under traffic; the same code and verifier are presented again.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            candidateIntegration.SaveFlowStateAsync = originalSave).ConfigureAwait(false);
        (int status, string body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, tokenFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, status, body);
        Assert.AreEqual(
            "{\"error\":\"invalid_grant\",\"error_description\":\"The authorization code is unknown, expired, or already used.\"}",
            body);
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-4.1.3">OAuth 2.1 draft-16
    /// Section 4.1.3</see>: "If a second valid token request is made with the same authorization code as a previously
    /// successful token request, the authorization server MUST deny the request". A redemption whose issuance walk
    /// throws out of the application's identifier seam, at the draw of the refresh token's value and before the step's
    /// first store write, issued nothing and is not a successful token request: the redemption over the wire is answered
    /// 500 with the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> that the
    /// host writes for the fault, and the same code presented again with the seam restored is answered 200 with an
    /// <c>access_token</c> and a <c>refresh_token</c>. Releasing the claim of a walk that ended before the step's first
    /// store write is this library's rule.
    /// </summary>
    [TestMethod]
    public async Task ACodeSurvivesAWalkThatThrowsBeforePersistenceAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);
        Dictionary<string, string> tokenFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString);

        //The identifier seam throws when the walk draws the refresh token's value.
        GenerateIdentifierDelegate originalIdentifier = host.Server.OAuth().GenerateIdentifierAsync!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            candidateIntegration.GenerateIdentifierAsync = (purpose, ctx, ct) =>
                purpose.Equals(WellKnownIdentifierPurposes.OAuthRefreshToken)
                    ? throw new InvalidOperationException("The identifier source is unavailable.")
                    : originalIdentifier(purpose, ctx, ct)).ConfigureAwait(false);

        (int failedStatus, string failedBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, tokenFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(500, failedStatus, failedBody);
        Assert.AreEqual(
            "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            failedBody);
        Exception fault = Assert.ContainsSingle(host.Host("default").ConsumeHttpFaults());
        Assert.AreEqual("The identifier source is unavailable.", fault.Message, failedBody);

        //The seam is restored under traffic; the same code and verifier are presented again.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            candidateIntegration.GenerateIdentifierAsync = originalIdentifier).ConfigureAwait(false);
        (int status, string body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, tokenFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, status, body);

        using JsonDocument answer = JsonDocument.Parse(body);
        Assert.IsTrue(answer.RootElement.TryGetProperty(OAuthRequestParameterNames.AccessToken, out _), body);
        Assert.IsTrue(answer.RootElement.TryGetProperty(OAuthRequestParameterNames.RefreshToken, out _), body);
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-4.1.3">OAuth 2.1 draft-16
    /// Section 4.1.3</see>: "If a second valid token request is made with the same authorization code as a previously
    /// successful token request, the authorization server MUST deny the request". A redemption whose issuance walk is
    /// ended by the request's own cancellation, while the walk draws the refresh token's value and before the step's
    /// first store write, issued nothing and is not a successful token request: the client's cancelled redemption over
    /// the wire ends with a <see cref="TaskCanceledException"/>, its claim is released once under a cancellation token
    /// that cannot be cancelled, and the same code presented again is answered 200 with an <c>access_token</c> and a
    /// <c>refresh_token</c>. Releasing the claim of a walk that ended before the step's first store write, the
    /// request's own cancellation included, is this library's rule.
    /// </summary>
    [TestMethod]
    public async Task ACodeSurvivesAWalkThatTheRequestsCancellationEndsAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);
        Dictionary<string, string> tokenFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString);

        //The first draw of the refresh token's value cancels the client's side of the redemption and holds the walk
        //until the server observes that as the request's own cancellation, which then ends the walk.
        using CancellationTokenSource cancelledRedemptionSource =
            CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        int refreshValueDraws = 0;
        int releaseCalls = 0;
        int cancellableReleaseTokens = 0;
        GenerateIdentifierDelegate originalIdentifier = host.Server.OAuth().GenerateIdentifierAsync!;
        ReleaseServerFlowStateDelegate originalRelease = host.Server.OAuth().ReleaseFlowStateAsync!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.GenerateIdentifierAsync = async (purpose, ctx, ct) =>
            {
                if(purpose.Equals(WellKnownIdentifierPurposes.OAuthRefreshToken)
                    && Interlocked.Increment(ref refreshValueDraws) == 1)
                {
                    TaskCompletionSource requestCancelled = new(TaskCreationOptions.RunContinuationsAsynchronously);
                    using CancellationTokenRegistration onRequestCancelled = ct.Register(() => requestCancelled.TrySetResult());
                    await cancelledRedemptionSource.CancelAsync().ConfigureAwait(false);
                    await requestCancelled.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
                    ct.ThrowIfCancellationRequested();
                }

                return await originalIdentifier(purpose, ctx, ct).ConfigureAwait(false);
            };

            //The release records whether the token it receives can be cancelled, then forwards to the store.
            candidateIntegration.ReleaseFlowStateAsync = (tenantId, flowKey, stepCount, ctx, ct) =>
            {
                _ = Interlocked.Increment(ref releaseCalls);
                if(ct.CanBeCanceled)
                {
                    _ = Interlocked.Increment(ref cancellableReleaseTokens);
                }

                return originalRelease(tenantId, flowKey, stepCount, ctx, ct);
            };
        }).ConfigureAwait(false);

        Task<(int StatusCode, string Body)> cancelledRedemption = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, tokenFields, cancelledRedemptionSource.Token);
        _ = await Assert.ThrowsExactlyAsync<TaskCanceledException>(
            () => cancelledRedemption, "The redemption whose walk is cancelled ends on the client's side.").ConfigureAwait(false);

        //The host admits a second request of the same grant only after the first request has finished, its walk and
        //its release included (HostedAuthorizationServer.EnterGrantOrderGateAsync).
        (int status, string body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, tokenFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(1, Volatile.Read(ref releaseCalls), "The cancelled walk's claim is released once.");
        Assert.AreEqual(0, Volatile.Read(ref cancellableReleaseTokens), "The release receives a token that cannot be cancelled.");
        Assert.AreEqual(200, status, body);

        using JsonDocument answer = JsonDocument.Parse(body);
        Assert.IsTrue(answer.RootElement.TryGetProperty(OAuthRequestParameterNames.AccessToken, out _), body);
        Assert.IsTrue(answer.RootElement.TryGetProperty(OAuthRequestParameterNames.RefreshToken, out _), body);
    }


    /// <summary>
    /// A rule of this library, stated here because the specification sets no order between a failed redemption and
    /// the bookkeeping that follows it: when a redemption's issuance walk throws before the step's first store write
    /// and the release of its claim then throws as well, the walk's exception is the request's fault, the release's
    /// exception is recorded on the request's trace as an <c>exception</c> event, and the step stays claimed. The
    /// redemption over the wire is answered 500 with the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> that the
    /// host writes for the walk's fault, and the same code presented again with both seams restored is answered 400
    /// with the body
    /// <c>{"error":"invalid_grant","error_description":"The authorization code is unknown, expired, or already used."}</c>.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-4.1.3">OAuth 2.1 draft-16
    /// Section 4.1.3</see> requires the denial only for "a previously successful token request"; a code whose release
    /// failed stays spent by this library's fail-closed rule.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public async Task TheWalksExceptionStaysPrimaryWhenTheCodesReleaseThrowsAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);
        Dictionary<string, string> tokenFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString);

        //The identifier seam throws when the walk draws the refresh token's value, and the release throws its own.
        GenerateIdentifierDelegate originalIdentifier = host.Server.OAuth().GenerateIdentifierAsync!;
        ReleaseServerFlowStateDelegate originalRelease = host.Server.OAuth().ReleaseFlowStateAsync!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.GenerateIdentifierAsync = (purpose, ctx, ct) =>
                purpose.Equals(WellKnownIdentifierPurposes.OAuthRefreshToken)
                    ? throw new InvalidOperationException("The identifier source is unavailable.")
                    : originalIdentifier(purpose, ctx, ct);
            candidateIntegration.ReleaseFlowStateAsync =
                static (_, _, _, _, _) => throw new InvalidOperationException("The claim store is unavailable.");
        }).ConfigureAwait(false);

        using TraceTreeCapture capture = new();
        using Activity root = new(nameof(TheWalksExceptionStaysPrimaryWhenTheCodesReleaseThrowsAsync));
        _ = root.Start();
        (int failedStatus, string failedBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, tokenFields, TestContext.CancellationToken).ConfigureAwait(false);
        root.Stop();

        Assert.AreEqual(500, failedStatus, failedBody);
        Assert.AreEqual(
            "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            failedBody);
        Exception fault = Assert.ContainsSingle(host.Host("default").ConsumeHttpFaults());
        Assert.AreEqual(typeof(InvalidOperationException), fault.GetType(), fault.Message);
        Assert.AreEqual("The identifier source is unavailable.", fault.Message);

        //The release's exception is an event of this request's own trace.
        ActivityEvent[] exceptionEvents = [.. TraceTreeAssertions.FilterByTrace(capture.StoppedActivities, root.TraceId)
            .SelectMany(activity => activity.Events)
            .Where(activityEvent => string.Equals(activityEvent.Name, "exception", StringComparison.Ordinal))];
        _ = Assert.ContainsSingle(
            activityEvent => activityEvent.Tags.Any(tag => string.Equals(tag.Key, "exception.type", StringComparison.Ordinal)
                    && string.Equals(tag.Value as string, "System.InvalidOperationException", StringComparison.Ordinal))
                && activityEvent.Tags.Any(tag => string.Equals(tag.Key, "exception.message", StringComparison.Ordinal)
                    && string.Equals(tag.Value as string, "The claim store is unavailable.", StringComparison.Ordinal)),
            exceptionEvents,
            $"The release's exception must be recorded on the request's trace. Events: {exceptionEvents.Length}");

        //Both seams are restored under traffic; the same code and verifier are presented again.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.GenerateIdentifierAsync = originalIdentifier;
            candidateIntegration.ReleaseFlowStateAsync = originalRelease;
        }).ConfigureAwait(false);
        (int status, string body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, tokenFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, status, body);
        Assert.AreEqual(
            "{\"error\":\"invalid_grant\",\"error_description\":\"The authorization code is unknown, expired, or already used.\"}",
            body);
    }


    /// <summary>
    /// A rule of this library: the window in which a claim is released ends at the step's first store write, the
    /// write itself included. A redemption whose first store write, the save of the issued refresh token's record,
    /// takes effect and then throws may have left a live record of the step, so its claim is never released: the
    /// redemption over the wire is answered 500 with the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> that the
    /// host writes for the fault, the release is not called, and the same code presented again with the store
    /// restored is answered 400 with the body
    /// <c>{"error":"invalid_grant","error_description":"The authorization code is unknown, expired, or already used."}</c>.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-4.1.3">OAuth 2.1 draft-16
    /// Section 4.1.3</see> requires the denial for "a previously successful token request"; this library keeps the code
    /// spent from the step's first store write on, whether or not the request that made it succeeded.
    /// </summary>
    [TestMethod]
    public async Task AFirstStoreWriteThatTakesEffectAndThrowsLeavesTheCodeSpentAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);
        Dictionary<string, string> tokenFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString);

        //The first save of a refresh token's record is written and then throws; every release is counted.
        int refreshRecordSaves = 0;
        int releaseCalls = 0;
        SaveServerFlowStateDelegate originalSave = host.Server.OAuth().SaveFlowStateAsync!;
        ReleaseServerFlowStateDelegate originalRelease = host.Server.OAuth().ReleaseFlowStateAsync!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.SaveFlowStateAsync = async (tenantId, flowKey, state, stepCount, ctx, ct) =>
            {
                await originalSave(tenantId, flowKey, state, stepCount, ctx, ct).ConfigureAwait(false);
                if(state is ServerRefreshTokenIssuedState && Interlocked.Increment(ref refreshRecordSaves) == 1)
                {
                    throw new InvalidOperationException("The flow store failed after writing.");
                }
            };
            candidateIntegration.ReleaseFlowStateAsync = (tenantId, flowKey, stepCount, ctx, ct) =>
            {
                _ = Interlocked.Increment(ref releaseCalls);

                return originalRelease(tenantId, flowKey, stepCount, ctx, ct);
            };
        }).ConfigureAwait(false);

        (int failedStatus, string failedBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, tokenFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(500, failedStatus, failedBody);
        Assert.AreEqual(
            "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            failedBody);
        Exception fault = Assert.ContainsSingle(host.Host("default").ConsumeHttpFaults());
        Assert.AreEqual("The flow store failed after writing.", fault.Message, failedBody);
        Assert.AreEqual(0, Volatile.Read(ref releaseCalls), "A claim is never released once the step's first store write began.");

        //The store is restored under traffic; the same code and verifier are presented again.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            candidateIntegration.SaveFlowStateAsync = originalSave).ConfigureAwait(false);
        (int status, string body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, tokenFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, status, body);
        Assert.AreEqual(
            "{\"error\":\"invalid_grant\",\"error_description\":\"The authorization code is unknown, expired, or already used.\"}",
            body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>:
    /// "the authorization server MUST deny the request and SHOULD revoke (when possible)"
    /// when the code is presented more than once. A SEQUENTIAL second token request presenting the identical, still-valid parameters
    /// is refused <c>invalid_grant</c> and revokes the first access token — proven at the
    /// introspection endpoint the suite already has, per
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §7.5.3</see>'s "should only revoke issued tokens if the request containing the
    /// authorization code is also valid." The fixture's <see cref="AuthorizationServerIntegration.RevokeIssuedTokenAsync"/>
    /// is invoked with the audited token's <c>jti</c> on this path — distinct from
    /// <see cref="AuthorizationServerIntegration.RevokeTokenAsync"/>, the wire-string form the RFC
    /// 7009 client-driven revocation endpoint presents.
    /// </summary>
    [TestMethod]
    public async Task ValidReplayOfRedeemedCodeIsInvalidGrantAndRevokesTheIssuedAccessToken()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: CapabilitiesWithIntrospection).ConfigureAwait(false);

        HashSet<string> revokedJtis = new(StringComparer.Ordinal);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(true);

            candidateIntegration.RevokeIssuedTokenAsync = (tokenIdentifier, tokenType, _, _, _) =>
            {
                _ = revokedJtis.Add(tokenIdentifier);

                return ValueTask.CompletedTask;
            };

            candidateIntegration.IntrospectTokenAsync = (token, hint, _, _, _) =>
            {
                using JsonDocument payload = DecodePayload(token);
                string jti = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Jti).GetString()!;

                return ValueTask.FromResult(new TokenIntrospectionResult { IsActive = !revokedJtis.Contains(jti) });
            };
        }).ConfigureAwait(false);

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
        AuthorizationCodeReceivedState codeState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string firstAccessToken = (string)firstExchange.Body![OAuthRequestParameterNames.AccessToken];

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawIntrospectionFieldsAsync(
            host, segment,
            new Dictionary<string, string> { [OAuthRequestParameterNames.Token] = firstAccessToken },
            TestContext.CancellationToken).ConfigureAwait(false);
        using(JsonDocument beforeDoc = JsonDocument.Parse(Body))
        {
            Assert.IsTrue(beforeDoc.RootElement.GetProperty("active").GetBoolean(),
                "The first access token must still be active before any replay.");
        }

        //A VALID replay: the identical code, verifier, and redirect_uri a first presentation
        //would have used.
        (int StatusCode, string Body) replay = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, codeState.Code, codeState.Pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, replay.StatusCode, replay.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, replay.Body, StringComparison.Ordinal);

        (int StatusCode, string Body) activeAfterReplay = await RawAuthCodeWirePushers.PushRawIntrospectionFieldsAsync(
            host, segment,
            new Dictionary<string, string> { [OAuthRequestParameterNames.Token] = firstAccessToken },
            TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument afterDoc = JsonDocument.Parse(activeAfterReplay.Body);
        Assert.IsFalse(afterDoc.RootElement.GetProperty("active").GetBoolean(),
            "A VALID replay must revoke the first redemption's access token (RFC 6749 §4.1.2 SHOULD).");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>'s
    /// SHOULD-revoke on a code replay reaches the grant's CURRENT refresh token even when that
    /// token has already rotated at least once since the code was redeemed: the code-issued
    /// refresh record has itself already retired into a <see cref="ServerTokenIssuedState"/> by
    /// the time of the replay, and revocation must still reach the grant's live
    /// <see cref="ServerRefreshTokenIssuedState"/> rather than stopping at that immediate,
    /// already-dead record.
    /// </summary>
    [TestMethod]
    public async Task ValidReplayAfterTheRefreshTokenHasAlreadyRotatedRevokesTheCurrentSuccessorAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

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
        AuthorizationCodeReceivedState codeState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string codeIssuedRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        //A single legitimate rotation BEFORE the replay — the code's own refresh record is now an
        //already-retired record, not the family's live refresh token.
        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, codeIssuedRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, StatusCode, Body);
        string currentRefreshToken;
        string currentAccessToken;
        using(JsonDocument rotationDoc = JsonDocument.Parse(Body))
        {
            currentAccessToken = rotationDoc.RootElement.GetProperty(
                OAuthRequestParameterNames.AccessToken).GetString()!;
            currentRefreshToken = rotationDoc.RootElement.GetProperty(
                OAuthRequestParameterNames.RefreshToken).GetString()!;
        }

        HashSet<string> revokedJtis = [];
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.RevokeIssuedTokenAsync = (jti, _, _, _, _) =>
            {
                _ = revokedJtis.Add(jti);

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        //A VALID replay of the redeemed code.
        (int StatusCode, string Body) replay = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, codeState.Code, codeState.Pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, replay.StatusCode, replay.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, replay.Body, StringComparison.Ordinal);

        //The family's CURRENT refresh token — the one an attacker holding the replayed code could
        //otherwise still redeem against — must be refused afterward.
        (int StatusCode, string Body) currentAfterReplay = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, currentRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, currentAfterReplay.StatusCode,
            $"A code replay must revoke the family's CURRENT refresh token even after it has rotated. Body={currentAfterReplay.Body}");
        Assert.Contains(OAuthErrors.InvalidGrant, currentAfterReplay.Body, StringComparison.Ordinal);
        Assert.Contains(JwtPayloadReader.ReadJti(currentAccessToken)!, revokedJtis,
            "A valid code replay must revoke the access token issued by the rotated descendant.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>'s
    /// SHOULD-revoke shares <see cref="AuthCodeEndpoints"/>'s refresh-chain walk with refresh
    /// reuse: when that walk gives up on its bounded claim retry without reaching the family's
    /// live end, a code replay must not persist <see cref="ServerTokenIssuedState.RevokedAt"/>
    /// either, so the family survives and a later replay of the SAME code — once the claim seam
    /// recovers — re-runs the walk and this time reaches and revokes the current successor.
    /// </summary>
    [TestMethod]
    public async Task ValidReplayWithRepeatedLostClaimsDoesNotDeleteUnclaimedStateAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

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
        AuthorizationCodeReceivedState codeState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string codeIssuedRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, codeIssuedRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, StatusCode, Body);
        string currentRefreshToken;
        using(JsonDocument rotationDoc = JsonDocument.Parse(Body))
        {
            currentRefreshToken = rotationDoc.RootElement.GetProperty(
                OAuthRequestParameterNames.RefreshToken).GetString()!;
        }

        var originalClaim = host.Server.OAuth().ClaimFlowStateAsync;
        int claimCalls = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ClaimFlowStateAsync = (_, _, _, _, _) =>
            {
                if(++claimCalls > 2)
                {
                    throw new InvalidOperationException("A family walk must stop after its bounded claim retry.");
                }

                return ValueTask.FromResult(false);
            };
        }).ConfigureAwait(false);

        (int StatusCode, string Body) firstReplay = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, codeState.Code, codeState.Pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, firstReplay.StatusCode, firstReplay.Body);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ClaimFlowStateAsync = originalClaim;
        }).ConfigureAwait(false);

        (int StatusCode, string Body) currentAfterIncompleteWalk = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, currentRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, currentAfterIncompleteWalk.StatusCode,
            $"An incomplete walk must leave the current successor usable. Body={currentAfterIncompleteWalk.Body}");
        string nextRefreshToken;
        using(JsonDocument nextDoc = JsonDocument.Parse(currentAfterIncompleteWalk.Body))
        {
            nextRefreshToken = nextDoc.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!;
        }

        //The claim seam has recovered: replaying the SAME code again re-runs the walk, which this
        //time reaches and revokes the family's now-current successor.
        (int StatusCode, string Body) secondReplay = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, codeState.Code, codeState.Pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, secondReplay.StatusCode, secondReplay.Body);

        (int StatusCode, string Body) currentAfterCompletedWalk = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, nextRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, currentAfterCompletedWalk.StatusCode,
            "A completed walk must revoke the family's current successor.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>:
    /// "the authorization server MUST deny the request" for an already-used code — a THIRD valid
    /// presentation is still denied. The library's persisted revocation marker makes later valid
    /// replay idempotent: it does not repeat RevokeIssuedTokenAsync calls. This callback-count
    /// invariant is library behavior, separate from the protocol's replay denial.
    /// <see cref="ServerTokenIssuedState.RevokedAt"/> marker the first replay writes is directly
    /// observable on the test host's persisted state.
    /// </summary>
    [TestMethod]
    public async Task SecondAndThirdValidReplayDoNotReinvokeRevocationAndTheMarkerPersists()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: CapabilitiesWithIntrospection).ConfigureAwait(false);

        int revokeCallCount = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(true);

            candidateIntegration.RevokeIssuedTokenAsync = (_, _, _, _, _) =>
            {
                _ = Interlocked.Increment(ref revokeCallCount);

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

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
        AuthorizationCodeReceivedState codeState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");

        Dictionary<string, string> replayFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, codeState.Code, codeState.Pkce.EncodedVerifier, RedirectUri.OriginalString);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, replayFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidGrant, Body, StringComparison.Ordinal);

        int countAfterFirstReplay = revokeCallCount;
        Assert.IsGreaterThanOrEqualTo(1, countAfterFirstReplay,
            "The first (second-presentation) valid replay must revoke at least the audited access token.");

        //The persistence key is the internal flowId the PAR/authorize step generated, not the
        //code's own hash (a separate secondary index resolves one to the other) — searched by
        //shape instead of reconstructing that internal identifier.
        ServerTokenIssuedState persisted = hosted.FlowStates.Values
            .Select(entry => entry.State)
            .OfType<ServerTokenIssuedState>()
            .Single(s => s.RevokedAt is not null);
        Assert.IsNotNull(persisted.RevokedAt,
            "The RevokedAt marker must be observable on the persisted state after the first replay.");

        (int StatusCode, string Body) thirdPresentation = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, replayFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, thirdPresentation.StatusCode, thirdPresentation.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, thirdPresentation.Body, StringComparison.Ordinal);

        Assert.AreEqual(countAfterFirstReplay, revokeCallCount,
            "A THIRD valid replay must not re-invoke revocation — the marker already answers invalid_grant.");
    }


    /// <summary>
    /// <see cref="AuthorizationServerIntegration.RevokeIssuedTokenAsync"/> is optional per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>'s
    /// "SHOULD revoke (when possible)" — a deployment that leaves it unwired still denies a valid
    /// replay and still revokes the sibling refresh token (an unconditional
    /// <c>DeleteFlowStateAsync</c>), but the audited access token itself remains valid until it
    /// expires on its own. This is the documented degradation
    /// <see cref="RevokeIssuedTokenDelegate"/>'s remarks pin, not a defect.
    /// </summary>
    [TestMethod]
    public async Task UnwiredRevokeIssuedTokenStillDeniesReplayButLeavesTheAccessTokenValid()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: CapabilitiesWithIntrospection).ConfigureAwait(false);

        //RevokeIssuedTokenAsync deliberately left unwired.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(true);

            candidateIntegration.IntrospectTokenAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(new TokenIntrospectionResult { IsActive = true });
        }).ConfigureAwait(false);

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
        AuthorizationCodeReceivedState codeState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string firstAccessToken = (string)firstExchange.Body![OAuthRequestParameterNames.AccessToken];
        string firstRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, codeState.Code, codeState.Pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidGrant, Body, StringComparison.Ordinal);

        (int StatusCode, string Body) stillActive = await RawAuthCodeWirePushers.PushRawIntrospectionFieldsAsync(
            host, segment,
            new Dictionary<string, string> { [OAuthRequestParameterNames.Token] = firstAccessToken },
            TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument stillActiveDoc = JsonDocument.Parse(stillActive.Body);
        Assert.IsTrue(stillActiveDoc.RootElement.GetProperty("active").GetBoolean(),
            "With RevokeIssuedTokenAsync unwired, the audited access token remains valid — the documented degradation.");

        //The sibling refresh record IS still gone — RevokeIssuedTokenAsync being unwired only
        //degrades the access-token leg, never the unconditional DeleteFlowStateAsync the replay
        //handler runs on the refresh record.
        (int StatusCode, string Body) refreshAfterReplay = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, firstRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, refreshAfterReplay.StatusCode, refreshAfterReplay.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, refreshAfterReplay.Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>:
    /// <c>invalid_grant</c> covers "the provided authorization grant ... or refresh token is
    /// invalid, expired, revoked." A refresh token deleted by a VALID authorization-code replay's
    /// revocation (RFC 6749 §4.1.2 SHOULD) is refused <c>invalid_grant</c> at its next
    /// presentation, not the host-generic <c>invalid_request</c> a correlation-handle miss would
    /// otherwise produce.
    /// </summary>
    [TestMethod]
    public async Task RefreshTokenRevokedByValidCodeReplayIsRefusedInvalidGrant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

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
        AuthorizationCodeReceivedState codeState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string firstRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        //A VALID replay: the identical code, verifier, and redirect_uri a first presentation
        //would have used. Deletes the sibling refresh token's backing flow state.
        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, codeState.Code, codeState.Pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidGrant, Body, StringComparison.Ordinal);

        (int StatusCode, string Body) refreshAfterReplay = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.RefreshToken] = firstRefreshToken
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, refreshAfterReplay.StatusCode, refreshAfterReplay.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, refreshAfterReplay.Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>: "Authorization servers MUST utilize one of these methods to detect
    /// refresh token replay by malicious actors for public clients" — refresh token rotation, per
    /// the same paragraph's "The previous refresh token is invalidated," is the method this
    /// library uses (<see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.2.2">RFC 9700
    /// §2.2.2</see> names it as an accepted alternative to sender-constraining), which only holds
    /// as a replay-detection mechanism if rotation itself is exactly-once under concurrency: N
    /// concurrent presentations of the SAME refresh token must yield exactly one 200 and every
    /// other <c>invalid_grant</c> — proven as an invariant on the outcome counts, not on which
    /// request happened to win. A gate on <see cref="ServerIntegration.LoadFlowStateAsync"/> holds
    /// every contender until all N have loaded the SAME live <see cref="ServerRefreshTokenIssuedState"/>
    /// before releasing them together, so the assertions below exercise the atomic
    /// <see cref="ServerIntegration.ClaimFlowStateAsync"/> race itself — without the gate, a
    /// scheduler that happens to run the requests one at a time would satisfy the SAME assertions
    /// through reuse-detection alone, never exercising a genuine claim race.
    /// </summary>
    [TestMethod]
    public async Task ConcurrentRefreshOfSameTokenYieldsExactlyOneSuccess()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");

        //This test forces same-version claim contention on the refresh token's own live record:
        //with the per-grant ordering gate on, the second request would never enter the library
        //while the first is held at LoadFlowStateAsync below.
        hosted.IsOrderingRequestsPerGrant = false;
        string segment = material.Registration.TenantId.Value;

        string flowId = await DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, host.ServerCertificate, TestContext.CancellationToken)
            .ConfigureAwait(false);

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string firstRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        Dictionary<string, string> refreshFields = RawAuthCodeWirePushers.BuildRefreshTokenFields(
            ClientId, firstRefreshToken);

        const int ConcurrentRequests = 8;

        string refreshFlowId = hosted.RefreshTokenIndex[firstRefreshToken];
        string grantFlowId = hosted.ResolveGrantKey(refreshFlowId);
        int revokeCalls = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.RevokeIssuedTokenAsync = (_, _, _, _, _) =>
            {
                _ = Interlocked.Increment(ref revokeCalls);

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);
        int initialLiveRecords = hosted.FlowStates.Values.Count(entry => entry.State is ServerRefreshTokenIssuedState);
        int arrivedAtLiveState = 0;
        TaskCompletionSource releaseGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        LoadServerFlowStateDelegate originalLoad = host.Server.OAuth().LoadFlowStateAsync!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.LoadFlowStateAsync = async (tenantId, key, ctx, ct) =>
            {
                (FlowState? state, int stepCount) = await originalLoad(tenantId, key, ctx, ct).ConfigureAwait(false);
                if(key == refreshFlowId && state is ServerRefreshTokenIssuedState)
                {
                    if(Interlocked.Increment(ref arrivedAtLiveState) == ConcurrentRequests)
                    {
                        _ = releaseGate.TrySetResult();
                    }

                    await releaseGate.Task.WaitAsync(ct).ConfigureAwait(false);
                }

                return (state, stepCount);
            };
        }).ConfigureAwait(false);

        Task<(int StatusCode, string Body)>[] rotations = [.. Enumerable.Range(0, ConcurrentRequests)
            .Select(_ => RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, refreshFields, TestContext.CancellationToken))];

        (int StatusCode, string Body)[] responses = await Task.WhenAll(rotations).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.LoadFlowStateAsync = originalLoad;
        }).ConfigureAwait(false);

        (int StatusCode, string Body) = Assert.ContainsSingle(r => r.StatusCode == 200, responses,
            $"Exactly one concurrent rotation of the same refresh token must succeed. Bodies: {string.Join(" | ", responses.Select(r => r.Body))}");
        Assert.AreEqual(ConcurrentRequests - 1,
            responses.Count(r => r.StatusCode == 400
                && r.Body.Contains(OAuthErrors.InvalidGrant, StringComparison.Ordinal)),
            $"Every losing concurrent rotation must fail invalid_grant. Bodies: {string.Join(" | ", responses.Select(r => r.Body))}");
        Assert.AreEqual(0, revokeCalls, "Losing claims must not revoke any issued token.");
        Assert.AreEqual(initialLiveRecords,
            hosted.FlowStates.Values.Count(entry => entry.State is ServerRefreshTokenIssuedState),
            "One consumed live record must be replaced by exactly one live successor.");

        //LOST CLAIM state assertion (directly after both the race and its released, joined
        //LoadFlowStateAsync gate — before the "successor is still usable" presentation below):
        //a lost claim on the SAME live token neither revokes anything nor leaves the grant with
        //more or fewer than the one live successor the winner published.
        GrantStateSnapshot grantState = GrantStateOracle.SnapshotGrant(hosted, grantFlowId, ClientId);
        Assert.AreEqual(1, grantState.RedeemableRecordCount,
            $"LOST CLAIM: exactly one live successor of the grant must remain redeemable after the race. " +
            $"Live refresh flow ids: {string.Join(", ", grantState.RedeemableRefreshFlowIds)}; " +
            $"live code flow ids: {string.Join(", ", grantState.RedeemableCodeFlowIds)}.");
        Assert.IsEmpty(grantState.LiveRecordsMissingFromGrantIndex,
            "Every live record the oracle finds directly in FlowStates must also be indexed under the grant key.");

        using JsonDocument successfulDocument = JsonDocument.Parse(Body);
        string successor = successfulDocument.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!;
        (int StatusCode, string Body) next = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, successor),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, next.StatusCode, "Losing claims must leave the issued successor usable.");
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>: "The authorization server cannot determine which party submitted the
    /// invalid refresh token, but it will revoke the active refresh token as well as the access
    /// authorization grant associated with it." That sentence draws no distinction between an
    /// attacker's replay and a legitimate client's own second, merely late, presentation: whichever
    /// presentation of a refresh token loads its flow record AFTER the other has already saved that
    /// record's rotation observes it retired, which this library treats as a reuse under the same
    /// strict rule — refused, and taking the newly rotated successor down with it.
    /// </summary>
    [TestMethod]
    public async Task LateConcurrentPresentationLoadingAfterRotationSaveIsRefusedAsReuse()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");

        //This test forces a presentation loading after the rotation's own save: with the per-grant
        //ordering gate on, the second presentation below would never enter the library while the
        //first holds the gate.
        hosted.IsOrderingRequestsPerGrant = false;
        string segment = material.Registration.TenantId.Value;

        string flowId = await DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, host.ServerCertificate, TestContext.CancellationToken)
            .ConfigureAwait(false);

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string presentedRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        string refreshFlowId = hosted.RefreshTokenIndex[presentedRefreshToken];
        string grantFlowId = hosted.ResolveGrantKey(refreshFlowId);

        //The full expected access-token jti set, collected INDEPENDENTLY of the revocation seam,
        //from every successful token response of the test so far — the code redemption's own.
        //The winner's rotation response adds its own jti once it is known, below.
        HashSet<string> expectedAccessTokenJtis = new(StringComparer.Ordinal)
        {
            JwtPayloadReader.ReadJti((string)firstExchange.Body![OAuthRequestParameterNames.AccessToken])!
        };
        ConcurrentBag<(string Jti, string TokenType)> revocationNotifications = [];
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.RevokeIssuedTokenAsync = (jti, tokenType, _, _, _) =>
            {
                revocationNotifications.Add((jti, tokenType));

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        int loadOrder = 0;
        TaskCompletionSource lateLoadGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        LoadServerFlowStateDelegate originalLoad = host.Server.OAuth().LoadFlowStateAsync!;
        SaveServerFlowStateDelegate originalSave = host.Server.OAuth().SaveFlowStateAsync!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.LoadFlowStateAsync = async (tenantId, key, ctx, ct) =>
            {
                if(key == refreshFlowId && Interlocked.Increment(ref loadOrder) == 2)
                {
                    await lateLoadGate.Task.WaitAsync(ct).ConfigureAwait(false);
                }

                return await originalLoad(tenantId, key, ctx, ct).ConfigureAwait(false);
            };

            candidateIntegration.SaveFlowStateAsync = async (tenantId, key, state, stepCount, ctx, ct) =>
            {
                await originalSave(tenantId, key, state, stepCount, ctx, ct).ConfigureAwait(false);
                if(key == refreshFlowId && state is ServerTokenIssuedState)
                {
                    _ = lateLoadGate.TrySetResult();
                }
            };
        }).ConfigureAwait(false);

        Dictionary<string, string> refreshFields = RawAuthCodeWirePushers.BuildRefreshTokenFields(
            ClientId, presentedRefreshToken);

        Task<(int StatusCode, string Body)> firstTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, refreshFields, TestContext.CancellationToken);
        Task<(int StatusCode, string Body)> lateTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, refreshFields, TestContext.CancellationToken);

        (int StatusCode, string Body)[] responses = await Task.WhenAll(firstTask, lateTask).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.LoadFlowStateAsync = originalLoad;

            candidateIntegration.SaveFlowStateAsync = originalSave;
        }).ConfigureAwait(false);

        (_, string WinnerBody) = Assert.ContainsSingle(r => r.StatusCode == 200, responses,
            $"The presentation that loads first must complete its rotation. Bodies: {string.Join(" | ", responses.Select(r => r.Body))}");
        (_, string LateBody) = Assert.ContainsSingle(r => r.StatusCode == 400, responses,
            $"The presentation that loads after the rotation has saved must be refused. Bodies: {string.Join(" | ", responses.Select(r => r.Body))}");
        Assert.Contains(OAuthErrors.InvalidGrant, LateBody, StringComparison.Ordinal);

        using JsonDocument winnerDocument = JsonDocument.Parse(WinnerBody);
        string successor = winnerDocument.RootElement.GetProperty(
            OAuthRequestParameterNames.RefreshToken).GetString()!;
        _ = expectedAccessTokenJtis.Add(JwtPayloadReader.ReadJti(
            winnerDocument.RootElement.GetProperty(OAuthRequestParameterNames.AccessToken).GetString()!)!);

        //REUSE state assertion (directly after both responses are awaited and the paused
        //Load/SaveFlowStateAsync delegates have been released and joined — before the "successor
        //is refused" presentation below): the late load resolved a just-retired record, which is a
        //fresh, valid reuse — it must have notified every access token minted in the grant so far
        //by IDENTITY, and left no record of the grant redeemable.
        HashSet<string> notifiedAccessTokenJtis = revocationNotifications
            .Where(notification => string.Equals(notification.TokenType, WellKnownTokenTypes.AccessToken, StringComparison.Ordinal))
            .Select(notification => notification.Jti)
            .ToHashSet(StringComparer.Ordinal);
        Assert.IsTrue(expectedAccessTokenJtis.SetEquals(notifiedAccessTokenJtis),
            "REUSE must notify the application of exactly the access tokens minted in the grant so " +
            "far (this proves the application was notified, not that a resource server enforces it). " +
            $"Expected: {string.Join(", ", expectedAccessTokenJtis)}; notified: {string.Join(", ", notifiedAccessTokenJtis)}.");

        GrantStateSnapshot grantState = GrantStateOracle.SnapshotGrant(hosted, grantFlowId, ClientId);
        Assert.AreEqual(0, grantState.RedeemableRecordCount,
            $"REUSE: no record of the grant may remain redeemable after the late presentation resolved " +
            $"as reuse. Live refresh flow ids: {string.Join(", ", grantState.RedeemableRefreshFlowIds)}.");

        (int SurvivorStatusCode, _) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, successor),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, SurvivorStatusCode,
            "The family's active refresh token must not survive a reuse the late presentation triggered.");
    }


    /// <summary>
    /// <see cref="ServerIntegration.ClaimFlowStateAsync"/>'s exactly-once contract is a marker
    /// independent of the record it guards: a concurrent second presentation of the SAME,
    /// already-claimed refresh token that runs to completion entirely inside the window between
    /// the winning presentation's claim and its successor's publish observes the unpublished
    /// marker alone and is refused without ever seeing the retired shape the winner has not yet
    /// saved. <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>'s "it will revoke the active refresh token" still reaches the
    /// published successor once the retired token is presented again afterward — the race narrows
    /// the window but does not leave the successor reachable outside reuse detection.
    /// A successful concurrent claim is observed directly so a blocked publication cannot conceal it.
    /// </summary>
    [TestMethod]
    public async Task RotationHeldBetweenClaimAndPublishRefusesAConcurrentPresentationOfTheSameToken()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");

        //The first successor is held before publication so another request can contest the live token.
        hosted.IsOrderingRequestsPerGrant = false;
        string segment = material.Registration.TenantId.Value;

        string flowId = await DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, host.ServerCertificate, TestContext.CancellationToken)
            .ConfigureAwait(false);

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string presentedRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        string refreshFlowId = hosted.RefreshTokenIndex[presentedRefreshToken];
        string grantFlowId = hosted.ResolveGrantKey(refreshFlowId);
        int revokeCalls = 0;
        int successorPublications = 0;
        int presentationClaims = 0;
        await using CancellableTestBarrier publicationBarrier = new(
            "refresh successor publication", 1, TestContext.CancellationToken);
        TaskCompletionSource releaseGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource concurrentClaimSucceeded = new(TaskCreationOptions.RunContinuationsAsynchronously);
        ClaimServerFlowStateDelegate originalClaim = host.Server.OAuth().ClaimFlowStateAsync!;
        SaveServerFlowStateDelegate originalSave = host.Server.OAuth().SaveFlowStateAsync!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.RevokeIssuedTokenAsync = (_, _, _, _, _) =>
            {
                _ = Interlocked.Increment(ref revokeCalls);

                return ValueTask.CompletedTask;
            };

            candidateIntegration.ClaimFlowStateAsync = async (tenantId, key, expectedStepCount, ctx, ct) =>
            {
                try
                {
                    bool isConcurrentPresentation = key == refreshFlowId && ctx.FlowId == key
                        && Interlocked.Increment(ref presentationClaims) > 1;
                    bool isClaimed = await originalClaim(tenantId, key, expectedStepCount, ctx, ct).ConfigureAwait(false);
                    if(isConcurrentPresentation && isClaimed)
                    {
                        _ = concurrentClaimSucceeded.TrySetResult();
                    }

                    return isClaimed;
                }
                catch(Exception exception) when(!TestContext.CancellationToken.IsCancellationRequested)
                {
                    publicationBarrier.ReportFault(exception);
                    throw;
                }

            };

            candidateIntegration.SaveFlowStateAsync = async (tenantId, key, state, stepCount, ctx, ct) =>
            {
                try
                {
                    if(state is ServerRefreshTokenIssuedState successorState
                        && successorState.GrantFlowId == grantFlowId
                        && Interlocked.Increment(ref successorPublications) == 1)
                    {
                        await publicationBarrier.SignalAndWaitAsync().ConfigureAwait(false);
                        await releaseGate.Task.WaitAsync(ct).WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
                    }

                    await originalSave(tenantId, key, state, stepCount, ctx, ct).ConfigureAwait(false);
                }
                catch(Exception exception) when(!TestContext.CancellationToken.IsCancellationRequested)
                {
                    publicationBarrier.ReportFault(exception);
                    throw;
                }

            };
        }).ConfigureAwait(false);

        Dictionary<string, string> refreshFields = RawAuthCodeWirePushers.BuildRefreshTokenFields(
            ClientId, presentedRefreshToken);

        Task<(int StatusCode, string Body)> rotationTask = publicationBarrier.ObserveParticipantAsync(
            () => RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, refreshFields, TestContext.CancellationToken));
        Task<(int StatusCode, string Body)>? concurrentTask = null;
        (int StatusCode, string Body, Exception? Failure)[] outcomes;
        bool isConcurrentClaimSuccessful = false;
        bool isConcurrentCompletedBeforePublication = false;
        try
        {
            await publicationBarrier.WaitForReleaseAsync().ConfigureAwait(false);
            concurrentTask = publicationBarrier.ObserveParticipantAsync(() => RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, refreshFields, TestContext.CancellationToken));
            _ = await Task.WhenAny(concurrentClaimSucceeded.Task, concurrentTask)
                .WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
            isConcurrentClaimSuccessful = concurrentClaimSucceeded.Task.IsCompleted;
            isConcurrentCompletedBeforePublication = concurrentTask.IsCompleted;
        }
        finally
        {
            _ = releaseGate.TrySetResult();
            try
            {
                (int StatusCode, string Body, Exception? Failure) rotationOutcome =
                    await ObserveWireOutcomeAsync(rotationTask, TestContext.CancellationToken).ConfigureAwait(false);
                outcomes = concurrentTask switch
                {
                    null => [rotationOutcome],
                    _ =>
                    [
                        rotationOutcome,
                        await ObserveWireOutcomeAsync(concurrentTask, TestContext.CancellationToken).ConfigureAwait(false)
                    ]
                };
            }
            finally
            {
                await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
                {
                    candidateIntegration.SaveFlowStateAsync = originalSave;
                    candidateIntegration.ClaimFlowStateAsync = originalClaim;
                }).ConfigureAwait(false);
            }

        }

        string outcomeDiagnostic = string.Join(" | ", outcomes.Select((outcome, index) =>
            $"{(index == 0 ? "Rotation" : "Concurrent")}: status={outcome.StatusCode}, body={outcome.Body}, failure={outcome.Failure}"));
        Assert.IsFalse(isConcurrentClaimSuccessful,
            $"The concurrent presentation must never claim the same refresh token while successor publication is held. {outcomeDiagnostic}");
        Assert.IsTrue(isConcurrentCompletedBeforePublication,
            $"The concurrent presentation must finish while successor publication is held. {outcomeDiagnostic}");
        Assert.IsTrue(outcomes.All(outcome => outcome.Failure is null), outcomeDiagnostic);
        (int StatusCode, string Body) rotation = (outcomes[0].StatusCode, outcomes[0].Body);
        (int StatusCode, string Body) concurrent = (outcomes[1].StatusCode, outcomes[1].Body);
        Assert.AreEqual(400, concurrent.StatusCode,
            $"A concurrent presentation of the claimed refresh token must be refused before publication. {outcomeDiagnostic}");
        Assert.Contains(OAuthErrors.InvalidGrant, concurrent.Body, StringComparison.Ordinal, outcomeDiagnostic);


        //A refusal while the token is still live leaves issued tokens unrevoked and exactly one
        //successor redeemable after publication completes.
        Assert.AreEqual(0, revokeCalls,
            "A lost claim on a still-live token must not revoke any issued token.");
        GrantStateSnapshot grantStateAfterRace = GrantStateOracle.SnapshotGrant(hosted, grantFlowId, ClientId);
        Assert.AreEqual(1, grantStateAfterRace.RedeemableRecordCount,
            $"LOST CLAIM: exactly one live successor of the grant must remain redeemable after the race. " +
            $"Live refresh flow ids: {string.Join(", ", grantStateAfterRace.RedeemableRefreshFlowIds)}.");

        (int StatusCode, string Body)[] responses = [rotation, concurrent];
        Assert.DoesNotContain(r => r.StatusCode >= 500, responses,
            $"Neither presentation may fail with a server error. Bodies: {string.Join(" | ", responses.Select(r => r.Body))}");
        (_, string WinnerBody) = Assert.ContainsSingle(r => r.StatusCode == 200, responses,
            $"Exactly one presentation must be answered with tokens. Bodies: {string.Join(" | ", responses.Select(r => r.Body))}");

        using JsonDocument winnerDocument = JsonDocument.Parse(WinnerBody);
        string successor = winnerDocument.RootElement.GetProperty(
            OAuthRequestParameterNames.RefreshToken).GetString()!;

        (int ReuseStatusCode, string ReuseBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, refreshFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, ReuseStatusCode, ReuseBody);
        Assert.Contains(OAuthErrors.InvalidGrant, ReuseBody, StringComparison.Ordinal);

        (int SurvivorStatusCode, _) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, successor),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, SurvivorStatusCode,
            "Once the retired token is presented again, its published successor must be refused.");
    }


    /// <summary>
    /// <see cref="ClaimServerFlowStateDelegate"/>'s own contract: "Deletion must not permit a
    /// stale caller to claim the same consumed step again: implementations retain the claim or
    /// atomically reject absent and obsolete flow versions." A presentation that observed the live
    /// refresh record before a concurrent family walk (a reuse of an earlier retired sibling in the
    /// same grant) claimed and deleted that exact record must still be refused when its own,
    /// delayed claim call finally runs — the deletion evicting the walk's claim marker must not
    /// reopen the consumed step for a stale caller arriving after it.
    /// </summary>
    [TestMethod]
    public async Task ClaimAgainstARecordDeletedByAConcurrentFamilyWalkIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");

        //This test forces the claim against a record a concurrent family walk already deleted:
        //with the per-grant ordering gate on, the stale presentation below would never enter the
        //library while the reuse presentation it races is held at ClaimFlowStateAsync.
        hosted.IsOrderingRequestsPerGrant = false;
        string segment = material.Registration.TenantId.Value;

        string flowId = await DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, host.ServerCertificate, TestContext.CancellationToken)
            .ConfigureAwait(false);

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string retiredRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        (int RotationStatusCode, string RotationBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, retiredRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, RotationStatusCode, RotationBody);
        string liveRefreshToken;
        using(JsonDocument rotationDocument = JsonDocument.Parse(RotationBody))
        {
            liveRefreshToken = rotationDocument.RootElement.GetProperty(
                OAuthRequestParameterNames.RefreshToken).GetString()!;
        }

        string liveFlowId = hosted.RefreshTokenIndex[liveRefreshToken];
        TaskCompletionSource stalePresentationAtClaim = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releaseStalePresentation = new(TaskCreationOptions.RunContinuationsAsynchronously);
        ClaimServerFlowStateDelegate originalClaim = host.Server.OAuth().ClaimFlowStateAsync!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ClaimFlowStateAsync = async (tenantId, key, expectedStepCount, ctx, ct) =>
            {
                //ctx.FlowId names THIS request's own top-level flow. It equals the claimed key
                //only for a presentation of liveRefreshToken itself, never for the family walk's
                //nested claim on the SAME key while resolving a DIFFERENT presented token.
                if(key == liveFlowId && ctx.FlowId == key)
                {
                    _ = stalePresentationAtClaim.TrySetResult();
                    await releaseStalePresentation.Task.WaitAsync(ct).ConfigureAwait(false);
                }

                return await originalClaim(tenantId, key, expectedStepCount, ctx, ct).ConfigureAwait(false);
            };
        }).ConfigureAwait(false);

        Task<(int StatusCode, string Body)> staleTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, liveRefreshToken),
            TestContext.CancellationToken);
        await stalePresentationAtClaim.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

        (int ReuseStatusCode, string ReuseBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, retiredRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, ReuseStatusCode, ReuseBody);
        Assert.Contains(OAuthErrors.InvalidGrant, ReuseBody, StringComparison.Ordinal);

        _ = releaseStalePresentation.TrySetResult();
        (int StaleStatusCode, string StaleBody) = await staleTask.ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ClaimFlowStateAsync = originalClaim;
        }).ConfigureAwait(false);

        Assert.AreEqual(400, StaleStatusCode, StaleBody);
        Assert.Contains(OAuthErrors.InvalidGrant, StaleBody, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2">RFC 9700 §4.14.2</see>
    /// treats reuse of a rotated-out refresh token as a signal of possible token theft, and
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see> states the consequence: "it will revoke the active refresh token as
    /// well as the access authorization grant associated with it." A VALID reuse presentation
    /// (the token's own bound <c>client_id</c>) is refused <c>invalid_grant</c> exactly as an
    /// unknown token would be, AND revokes the CURRENT successor of the same grant family even
    /// after TWO rotations — the immediate successor pointer on the reused token's own retired
    /// record names only the FIRST rotation's output, itself already retired by the time this
    /// reuse fires, so revocation must walk the family link rather than deleting that one record.
    /// Every access token minted along the walked chain is revoked too, through
    /// <see cref="AuthorizationServerIntegration.RevokeIssuedTokenAsync"/> when wired.
    /// </summary>
    [TestMethod]
    public async Task DoubleRotatedReuseOfOldestRefreshTokenRevokesTheCurrentSuccessor()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        HashSet<string> revokedJtis = [];
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.RevokeIssuedTokenAsync = (jti, _, _, _, _) =>
            {
                _ = revokedJtis.Add(jti);

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

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

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string originalAccessTokenJti = JwtPayloadReader.ReadJti(
            (string)firstExchange.Body![OAuthRequestParameterNames.AccessToken])!;
        string oldestRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        //Rotation 1: oldestRefreshToken -> middleRefreshToken. The access token minted here
        //(middleAccessTokenJti) is the token a live client is now holding.
        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, oldestRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, StatusCode, Body);
        string middleRefreshToken;
        string middleAccessTokenJti;
        using(JsonDocument rotation1Doc = JsonDocument.Parse(Body))
        {
            middleRefreshToken = rotation1Doc.RootElement.GetProperty(
                OAuthRequestParameterNames.RefreshToken).GetString()!;
            middleAccessTokenJti = JwtPayloadReader.ReadJti(
                rotation1Doc.RootElement.GetProperty(OAuthRequestParameterNames.AccessToken).GetString()!)!;
        }

        //Rotation 2: middleRefreshToken -> currentRefreshToken. currentAccessTokenJti is the
        //access token the legitimate client holds at the moment of the reuse below.
        (int StatusCode, string Body) rotation2 = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, middleRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, rotation2.StatusCode, rotation2.Body);
        string currentRefreshToken;
        string currentAccessTokenJti;
        using(JsonDocument rotation2Doc = JsonDocument.Parse(rotation2.Body))
        {
            currentRefreshToken = rotation2Doc.RootElement.GetProperty(
                OAuthRequestParameterNames.RefreshToken).GetString()!;
            currentAccessTokenJti = JwtPayloadReader.ReadJti(
                rotation2Doc.RootElement.GetProperty(OAuthRequestParameterNames.AccessToken).GetString()!)!;
        }

        //A VALID reuse of the OLDEST (twice-rotated-out) token — its own SuccessorRefreshFlowId
        //names only the rotation-1 output, which is itself already retired.
        (int StatusCode, string Body) reuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, oldestRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, reuse.StatusCode, reuse.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, reuse.Body, StringComparison.Ordinal);

        //The family's CURRENT (third) refresh token must now be refused too — the walk reached
        //the live end of the chain, not merely the immediate (already-retired) successor.
        (int StatusCode, string Body) currentAfterReuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, currentRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, currentAfterReuse.StatusCode, currentAfterReuse.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, currentAfterReuse.Body, StringComparison.Ordinal);

        //The access tokens minted at both intermediate hops are revoked along the walked chain.
        Assert.Contains(originalAccessTokenJti, revokedJtis,
            "Reuse must revoke the access token minted alongside the presented refresh token.");
        Assert.Contains(middleAccessTokenJti, revokedJtis);
        Assert.Contains(currentAccessTokenJti, revokedJtis);
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>'s "it will revoke the active refresh token" holds regardless of how
    /// many rotations separate the reused token from the family's live end — the walk carries no
    /// fixed hop limit, only a cycle guard against corrupted storage, so a legitimate, merely
    /// long-lived refresh session rotating far more than any earlier fixed bound could never
    /// exceed still has its family fully revoked on a reuse of its oldest member.
    /// </summary>
    [TestMethod]
    public async Task ManyRotationsThenReuseOfTheOldestStillRevokesTheCurrentSuccessorAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

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

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string oldestRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        //65 further rotations — one MORE than a fixed 64-hop bound would tolerate — proving the
        //walk that reaches the live end has no such ceiling.
        const int RotationsPastAFormerFixedBound = 65;
        string currentRefreshToken = oldestRefreshToken;
        for(int rotationIndex = 0; rotationIndex < RotationsPastAFormerFixedBound; rotationIndex++)
        {
            (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, currentRefreshToken),
                TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, StatusCode, $"Rotation {rotationIndex} must succeed. Body={Body}");

            using JsonDocument rotationDoc = JsonDocument.Parse(Body);
            currentRefreshToken = rotationDoc.RootElement.GetProperty(
                OAuthRequestParameterNames.RefreshToken).GetString()!;
        }

        //A VALID reuse of the ORIGINAL token, rotated out 65 generations ago.
        (int StatusCode, string Body) reuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, oldestRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, reuse.StatusCode, reuse.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, reuse.Body, StringComparison.Ordinal);

        //The family's CURRENT (66th-generation) refresh token must be refused too.
        (int StatusCode, string Body) currentAfterReuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, currentRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, currentAfterReuse.StatusCode,
            $"A walk with no arbitrary hop limit must still reach and revoke the current successor after 65 rotations. Body={currentAfterReuse.Body}");
        Assert.Contains(OAuthErrors.InvalidGrant, currentAfterReuse.Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>'s family revocation must not create a permanently unreachable live
    /// token when a reuse presentation races a LEGITIMATE rotation touching the SAME live record
    /// the reuse walk passes through: whichever side observes the record as live first must claim
    /// it before mutating it, so a walk that loses that claim resumes from the rotation's own
    /// successor link instead of deleting a record the rotation has already superseded — which
    /// would sever the chain and leave the newly rotated token live forever. Proven as an
    /// invariant on the FINAL state only, never on which request wins the race: if the racing
    /// rotation returned a fresh refresh token, that token must be refused afterward.
    /// </summary>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task ReuseRacingALegitimateRotationOfTheSameRecordNeverLeavesAnHonourableSurvivorAsync(bool isReuseClaimFirst)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");

        //Both racing presentations resolve to the SAME grant key (the reuse's retired record
        //carries the same GrantFlowId as the rotation's live one), and each side's own release
        //depends on the OTHER having already entered the library — with the per-grant ordering
        //gate on, whichever side the gate admits first would hold it while waiting on a signal only
        //the still-queued side can raise, which never arrives. This is not one of the four forced
        //claim paths the per-grant ordering feature names; it stays a library-only, unordered race.
        hosted.IsOrderingRequestsPerGrant = false;
        string segment = material.Registration.TenantId.Value;

        string flowId = await DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, host.ServerCertificate, TestContext.CancellationToken)
            .ConfigureAwait(false);

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string oldestRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, oldestRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, StatusCode, Body);
        string currentRefreshToken;
        string rotation1AccessTokenJti;
        using(JsonDocument rotation1Doc = JsonDocument.Parse(Body))
        {
            currentRefreshToken = rotation1Doc.RootElement.GetProperty(
                OAuthRequestParameterNames.RefreshToken).GetString()!;
            rotation1AccessTokenJti = JwtPayloadReader.ReadJti(
                rotation1Doc.RootElement.GetProperty(OAuthRequestParameterNames.AccessToken).GetString()!)!;
        }

        //The full expected access-token jti set, collected INDEPENDENTLY of the revocation seam,
        //from every successful token response so far. Whatever the race itself mints is added once
        //its own outcome is known, below.
        HashSet<string> expectedAccessTokenJtis = new(StringComparer.Ordinal)
        {
            JwtPayloadReader.ReadJti((string)firstExchange.Body![OAuthRequestParameterNames.AccessToken])!,
            rotation1AccessTokenJti
        };
        ConcurrentBag<(string Jti, string TokenType)> revocationNotifications = [];

        //A VALID reuse of the ORIGINAL (once-rotated-out) token races a LEGITIMATE rotation of the
        //family's current successor — both requests reach the same live flow record.
        Dictionary<string, string> reuseFields =
            RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, oldestRefreshToken);
        Dictionary<string, string> rotateFields =
            RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, currentRefreshToken);

        string currentFlowId = hosted.RefreshTokenIndex[currentRefreshToken];
        string grantFlowId = hosted.ResolveGrantKey(currentFlowId);
        TaskCompletionSource walkObservedLive = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource rotationRetiredLive = new(TaskCreationOptions.RunContinuationsAsynchronously);
        LoadServerFlowStateDelegate originalLoad = host.Server.OAuth().LoadFlowStateAsync!;
        LoadGrantFlowStatesDelegate originalLoadGrant = host.Server.OAuth().LoadGrantFlowStatesAsync!;
        SaveServerFlowStateDelegate originalSave = host.Server.OAuth().SaveFlowStateAsync!;
        DeleteServerFlowStateDelegate originalDelete = host.Server.OAuth().DeleteFlowStateAsync!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.RevokeIssuedTokenAsync = (jti, tokenType, _, _, _) =>
            {
                revocationNotifications.Add((jti, tokenType));

                return ValueTask.CompletedTask;
            };

            //isReuseClaimFirst pauses the ROTATION request on its OWN direct dispatcher load of
            //the live record it presents, unaffected by how the revoker reaches the same record.
            candidateIntegration.LoadFlowStateAsync = async (tenantId, key, ctx, ct) =>
            {
                (FlowState? state, int stepCount) = await originalLoad(tenantId, key, ctx, ct).ConfigureAwait(false);
                if(isReuseClaimFirst && key == currentFlowId && ctx.FlowId == key && state is ServerRefreshTokenIssuedState)
                {
                    _ = walkObservedLive.TrySetResult();
                    await rotationRetiredLive.Task.WaitAsync(ct).ConfigureAwait(false);
                }

                return (state, stepCount);
            };

            //The other race shape pauses the REVOKING request the moment its own grant read has
            //returned the live record — it has observed the live record and has not yet claimed it.
            candidateIntegration.LoadGrantFlowStatesAsync = async (tenantId, grantFlowId, ctx, ct) =>
            {
                IReadOnlyList<(string FlowId, FlowState State, int StepCount)> records =
                    await originalLoadGrant(tenantId, grantFlowId, ctx, ct).ConfigureAwait(false);
                bool hasObservedTheLiveRecord = false;
                foreach((string recordFlowId, FlowState recordState, int _) in records)
                {
                    if(recordFlowId == currentFlowId && recordState is ServerRefreshTokenIssuedState)
                    {
                        hasObservedTheLiveRecord = true;

                        break;
                    }
                }

                if(!isReuseClaimFirst && hasObservedTheLiveRecord)
                {
                    _ = walkObservedLive.TrySetResult();
                    await rotationRetiredLive.Task.WaitAsync(ct).ConfigureAwait(false);
                }

                return records;
            };

            candidateIntegration.SaveFlowStateAsync = async (tenantId, key, state, stepCount, ctx, ct) =>
            {
                await originalSave(tenantId, key, state, stepCount, ctx, ct).ConfigureAwait(false);
                if(key == currentFlowId && state is ServerTokenIssuedState)
                {
                    _ = rotationRetiredLive.TrySetResult();
                }
            };


            candidateIntegration.DeleteFlowStateAsync = async (tenantId, key, ctx, ct) =>
            {
                await originalDelete(tenantId, key, ctx, ct).ConfigureAwait(false);
                if(isReuseClaimFirst && key == currentFlowId)
                {
                    _ = rotationRetiredLive.TrySetResult();
                }
            };
        }).ConfigureAwait(false);

        Task<(int StatusCode, string Body)> reuseTask;
        Task<(int StatusCode, string Body)> rotateTask;
        if(isReuseClaimFirst)
        {
            rotateTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, rotateFields, TestContext.CancellationToken);
            await walkObservedLive.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
            reuseTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, reuseFields, TestContext.CancellationToken);
        }
        else
        {
            reuseTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, reuseFields, TestContext.CancellationToken);
            await walkObservedLive.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
            rotateTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, rotateFields, TestContext.CancellationToken);
        }

        (int StatusCode, string Body)[] results = await Task.WhenAll(reuseTask, rotateTask).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.LoadFlowStateAsync = originalLoad;

            candidateIntegration.LoadGrantFlowStatesAsync = originalLoadGrant;

            candidateIntegration.SaveFlowStateAsync = originalSave;

            candidateIntegration.DeleteFlowStateAsync = originalDelete;
        }).ConfigureAwait(false);
        (int StatusCode, string Body) reuseResult = results[0];
        (int StatusCode, string Body) rotateResult = results[1];

        Assert.AreEqual(400, reuseResult.StatusCode, reuseResult.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, reuseResult.Body, StringComparison.Ordinal);

        //REUSE state assertion (directly after both responses are awaited and every paused
        //Load/LoadGrant/Save/DeleteFlowStateAsync delegate has been released and joined — BEFORE
        //the probes below, which could themselves repair a missed revocation and so must never be
        //what proves this): whatever the race left behind, by IDENTITY every access token minted
        //in the grant so far must already have been notified, and no record of the grant may
        //remain redeemable — the legitimate rotation's own freshly minted successor included.
        if(rotateResult.StatusCode == 200)
        {
            using JsonDocument rotateRaceDoc = JsonDocument.Parse(rotateResult.Body);
            _ = expectedAccessTokenJtis.Add(JwtPayloadReader.ReadJti(
                rotateRaceDoc.RootElement.GetProperty(OAuthRequestParameterNames.AccessToken).GetString()!)!);
        }

        HashSet<string> notifiedAccessTokenJtis = revocationNotifications
            .Where(notification => string.Equals(notification.TokenType, WellKnownTokenTypes.AccessToken, StringComparison.Ordinal))
            .Select(notification => notification.Jti)
            .ToHashSet(StringComparer.Ordinal);
        Assert.IsTrue(expectedAccessTokenJtis.SetEquals(notifiedAccessTokenJtis),
            "REUSE must notify the application of exactly the access tokens minted in the grant so " +
            "far (this proves the application was notified, not that a resource server enforces it). " +
            $"Expected: {string.Join(", ", expectedAccessTokenJtis)}; notified: {string.Join(", ", notifiedAccessTokenJtis)}.");

        GrantStateSnapshot grantStateAfterRace = GrantStateOracle.SnapshotGrant(hosted, grantFlowId, ClientId);
        Assert.AreEqual(0, grantStateAfterRace.RedeemableRecordCount,
            $"REUSE: no record of the grant may remain redeemable directly after the race, before any " +
            $"further presentation. Live refresh flow ids: {string.Join(", ", grantStateAfterRace.RedeemableRefreshFlowIds)}.");

        foreach(string token in new[] { oldestRefreshToken, currentRefreshToken })
        {
            (int StatusCode, string Body) probe = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, token),
                TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, probe.StatusCode, "Every presented family member must be refused after reuse.");
        }

        if(rotateResult.StatusCode == 200)
        {
            //The race let the legitimate rotation through — the freshly minted token it returned
            //must still end up revoked; winning that race must never let a family member survive
            //as an honourable, unreachable orphan.
            string racedSuccessorToken;
            using(JsonDocument rotateDoc = JsonDocument.Parse(rotateResult.Body))
            {
                racedSuccessorToken = rotateDoc.RootElement.GetProperty(
                    OAuthRequestParameterNames.RefreshToken).GetString()!;
            }

            (int StatusCode, string Body) afterRace = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, racedSuccessorToken),
                TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, afterRace.StatusCode,
                $"A refresh token minted by a rotation racing a valid reuse of its own predecessor must not survive as a usable orphan. Body={afterRace.Body}");
        }
        else
        {
            Assert.AreEqual(400, rotateResult.StatusCode, rotateResult.Body);
            Assert.Contains(OAuthErrors.InvalidGrant, rotateResult.Body, StringComparison.Ordinal);
        }
    }


    /// <summary>
    /// <see cref="LoadGrantFlowStatesDelegate"/>'s own remarks: the application sees every request
    /// before the library is called and every response after it, and it alone can order two
    /// requests presented for the same grant; the library runs no ordering protocol of its own
    /// beyond the claim it makes, through <see cref="ClaimServerFlowStateDelegate"/>, on a record
    /// it is about to delete. A rotation of the grant's live end is held AFTER its own
    /// dispatcher-level claim has already succeeded and BEFORE it saves its successor; a VALID
    /// reuse of an OLDER retired token of the same grant runs to completion entirely inside that
    /// window, which the library's own one-retry bound on a grant's revocation walk may still lose
    /// on the record the rotation already holds — this test asserts only what that contract promises an
    /// application presenting the two requests with no ordering of its own: the reuse is refused;
    /// the rotation's own already-successful claim is unaffected; and once the application gives
    /// the grant one further presentation of a retired token — its own turn to retry, exactly as
    /// the delegate's remarks describe — nothing of the grant remains redeemable. Whether the
    /// racing rotation's own successor survived the race itself is recorded, never asserted: that
    /// is the fact an application ordering its own requests per grant would be built on.
    /// </summary>
    [TestMethod]
    public async Task RotationHeldBeforeSuccessorPublicationStillConvergesAfterOneFurtherPresentationAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");

        //This test's own reuse presentation is awaited synchronously WHILE the rotation is held —
        //the rotation's own release runs only after that await returns. Both presentations resolve
        //to the SAME grant key, so with the per-grant ordering gate on the reuse would never reach
        //the library while the rotation holds the gate, and the rotation would never be released:
        //a deadlock this test's own synchronization does not exist to survive. This is the library-
        //only baseline the ordered counterpart (HostedAuthorizationServerOrderingTests) demonstrates
        //the gate closing; it is not one of the four forced claim paths named for this feature.
        hosted.IsOrderingRequestsPerGrant = false;
        string segment = material.Registration.TenantId.Value;

        string flowId = await DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, host.ServerCertificate, TestContext.CancellationToken)
            .ConfigureAwait(false);

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string oldestRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        //A normal, unraced rotation: oldestRefreshToken becomes the OLDER retired token the reuse
        //below presents; currentRefreshToken becomes the grant's live end the held rotation consumes.
        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, oldestRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, StatusCode, Body);
        string currentRefreshToken;
        using(JsonDocument rotation1Doc = JsonDocument.Parse(Body))
        {
            currentRefreshToken = rotation1Doc.RootElement.GetProperty(
                OAuthRequestParameterNames.RefreshToken).GetString()!;
        }

        string currentFlowId = hosted.RefreshTokenIndex[currentRefreshToken];
        string grantFlowId = hosted.ResolveGrantKey(currentFlowId);

        TaskCompletionSource rotationReachedSuccessorSave = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releaseRotation = new(TaskCreationOptions.RunContinuationsAsynchronously);
        SaveServerFlowStateDelegate originalSave = host.Server.OAuth().SaveFlowStateAsync!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            //The rotation's own dispatcher-level claim on currentFlowId has already succeeded by
            //the time its handler saves anything at all; the FIRST save of a brand-new live
            //refresh record (never currentFlowId's own key — the DISPATCHER retires that key only
            //after the handler returns) is the successor's publication, held here both after the
            //claim and before that publication.
            candidateIntegration.SaveFlowStateAsync = async (tenantId, key, state, stepCount, ctx, ct) =>
            {
                if(key != currentFlowId && state is ServerRefreshTokenIssuedState)
                {
                    _ = rotationReachedSuccessorSave.TrySetResult();
                    await releaseRotation.Task.WaitAsync(ct).ConfigureAwait(false);
                }

                await originalSave(tenantId, key, state, stepCount, ctx, ct).ConfigureAwait(false);
            };
        }).ConfigureAwait(false);

        Task<(int StatusCode, string Body)> rotationTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, currentRefreshToken),
            TestContext.CancellationToken);
        await rotationReachedSuccessorSave.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //A VALID reuse of the OLDER retired token runs to completion while the rotation is held —
        //its own bounded retry may still lose both claim attempts on currentFlowId, since the
        //rotation's OWN dispatcher-level claim on it already succeeded before the pause.
        (int StatusCode, string Body) reuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, oldestRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, reuse.StatusCode, reuse.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, reuse.Body, StringComparison.Ordinal);

        _ = releaseRotation.TrySetResult();
        (int StatusCode, string Body) rotation = await rotationTask.ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.SaveFlowStateAsync = originalSave;
        }).ConfigureAwait(false);

        //Recorded, never asserted — this library promises no ordering protocol of its own beyond
        //the claim it makes on a record it is about to delete.
        GrantStateSnapshot grantStateAfterRace = GrantStateOracle.SnapshotGrant(hosted, grantFlowId, ClientId);
        TestContext.WriteLine(
            $"RotationHeldBeforeSuccessorPublication: the rotation answered {rotation.StatusCode} " +
            $"(Body={rotation.Body}); directly after the race, before any further presentation, the " +
            $"grant's redeemable record count is {grantStateAfterRace.RedeemableRecordCount} " +
            $"(live refresh flow ids: {string.Join(", ", grantStateAfterRace.RedeemableRefreshFlowIds)}).");

        //ONE FURTHER presentation of a retired token of the grant — the application, not the
        //library, giving the two requests another turn, exactly as the delegate's remarks describe.
        (int StatusCode, string Body) further = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, oldestRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, further.StatusCode, further.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, further.Body, StringComparison.Ordinal);

        GrantStateSnapshot grantStateAfterFurtherPresentation = GrantStateOracle.SnapshotGrant(hosted, grantFlowId, ClientId);
        Assert.AreEqual(0, grantStateAfterFurtherPresentation.RedeemableRecordCount,
            $"After one further presentation of a retired token of the grant, nothing of the grant " +
            $"may remain redeemable. Live refresh flow ids: " +
            $"{string.Join(", ", grantStateAfterFurtherPresentation.RedeemableRefreshFlowIds)}.");
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see> requires refresh replay detection: "Authorization servers MUST utilize
    /// one of these methods to detect refresh token replay by malicious actors for public clients".
    /// The retired <see cref="ServerTokenIssuedState"/> a rotation leaves behind must outlive the
    /// access token it was minted alongside, per
    /// <see cref="Verifiable.OAuth.AuthCode.Server.ServerTokenExchangeSucceeded.ExpiresAt"/>'s remarks: it
    /// carries at least the freshly-minted successor refresh token's own expiry, never merely the
    /// one-hour default access-token lifetime. The clock advances past that access-token lifetime
    /// but stays well inside the 30-day default refresh-token lifetime, then a reuse of the
    /// rotated-out token still reaches reuse detection instead of a stale-record miss.
    /// </summary>
    [TestMethod]
    public async Task ReuseAfterAccessTokenExpiryStillRevokesTheSuccessor()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

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

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string retiredRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, retiredRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, StatusCode, Body);
        string successorRefreshToken;
        using(JsonDocument rotationDoc = JsonDocument.Parse(Body))
        {
            successorRefreshToken = rotationDoc.RootElement.GetProperty(
                OAuthRequestParameterNames.RefreshToken).GetString()!;
        }

        //Two hours: past the one-hour default access-token lifetime that would otherwise let
        //EndpointServer.HandleCoreAsync's expiry gate treat the retired record as gone, but far
        //short of the 30-day default refresh-token lifetime protecting the successor.
        TimeProvider.Advance(TimeSpan.FromHours(2));

        (int StatusCode, string Body) reuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, retiredRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, reuse.StatusCode, reuse.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, reuse.Body, StringComparison.Ordinal);

        (int StatusCode, string Body) successorAfterReuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, successorRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, successorAfterReuse.StatusCode,
            $"Reuse detection must still fire past the access token's own expiry and revoke the successor. Body={successorAfterReuse.Body}");
    }


    /// <summary>
    /// The mirror of
    /// <see cref="DoubleRotatedReuseOfOldestRefreshTokenRevokesTheCurrentSuccessor"/>: an INVALID
    /// reuse presentation (a <c>client_id</c> that is not the registration's own) of a rotated-out
    /// refresh token answers the SAME constant <c>invalid_grant</c> body an unknown, expired, or
    /// already-revoked refresh token receives — an unauthenticated observer must not be able to
    /// tell a wrong-identity reuse of a genuinely retired token apart from a reuse of one that
    /// never existed — and revokes nothing, under the denial-of-service reasoning
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §7.5.3</see> applies to a code replay applies identically here: an attacker who
    /// merely observed the spent token must not be able to deny the legitimate holder service by
    /// presenting it with an unidentified client. The successor remains usable afterward.
    /// </summary>
    [TestMethod]
    public async Task InvalidReuseOfRotatedOutRefreshTokenLeavesTheSuccessorUsable()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

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

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string retiredRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, retiredRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, StatusCode, Body);
        string successorRefreshToken;
        using(JsonDocument rotationDoc = JsonDocument.Parse(Body))
        {
            successorRefreshToken = rotationDoc.RootElement.GetProperty(
                OAuthRequestParameterNames.RefreshToken).GetString()!;
        }

        //An INVALID reuse of the just-retired token: a client_id that is not the registration's own.
        (int StatusCode, string Body) reuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields("not-the-bound-client", retiredRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, reuse.StatusCode, reuse.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, reuse.Body, StringComparison.Ordinal);

        //The successor must remain usable — the INVALID reuse presentation revoked nothing.
        (int StatusCode, string Body) successorAfterReuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, successorRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, successorAfterReuse.StatusCode,
            $"An INVALID reuse presentation must revoke nothing; the successor must stay usable. Body={successorAfterReuse.Body}");
    }


    /// <summary>
    /// The oracle closed here: a presenter with no credentials must not be able to tell an
    /// UNKNOWN refresh token apart from a LIVE or RETIRED (rotated-out) one by sending each the
    /// SAME wrong <c>client_id</c>. <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC
    /// 6749 §5.2</see> names <c>invalid_grant</c> for a grant "issued to another client", which is
    /// exactly what a foreign <c>client_id</c> is told here — the SAME status, error and body bytes
    /// the dispatcher's own unknown-token answer carries, for every one of the three presentations.
    /// </summary>
    [TestMethod]
    public async Task WrongClientIdAgainstUnknownLiveAndRetiredRefreshTokensAnswersByteIdenticalRefusals()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

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

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string retiredRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        (int RotationStatusCode, string RotationBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, retiredRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, RotationStatusCode, RotationBody);
        string liveRefreshToken;
        using(JsonDocument rotationDoc = JsonDocument.Parse(RotationBody))
        {
            liveRefreshToken = rotationDoc.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!;
        }

        const string ForeignClientId = "https://not-the-registration.example.com";
        const string UnknownRefreshToken = "an-entirely-unknown-refresh-token-value-0123456789";

        (int UnknownStatusCode, string UnknownBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ForeignClientId, UnknownRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        (int LiveStatusCode, string LiveBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ForeignClientId, liveRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        (int RetiredStatusCode, string RetiredBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ForeignClientId, retiredRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, UnknownStatusCode, UnknownBody);
        Assert.Contains(OAuthErrors.InvalidGrant, UnknownBody, StringComparison.Ordinal);
        Assert.AreEqual(UnknownStatusCode, LiveStatusCode,
            "A wrong client_id against a LIVE refresh token must answer with the same status as one against an UNKNOWN token.");
        Assert.AreEqual(UnknownBody, LiveBody,
            "A wrong client_id against a LIVE refresh token must answer with byte-identical bytes to one against an UNKNOWN token.");
        Assert.AreEqual(UnknownStatusCode, RetiredStatusCode,
            "A wrong client_id against a RETIRED (rotated-out) refresh token must answer with the same status as one against an UNKNOWN token.");
        Assert.AreEqual(UnknownBody, RetiredBody,
            "A wrong client_id against a RETIRED (rotated-out) refresh token must answer with byte-identical bytes to one against an UNKNOWN token.");

        //Nothing was consumed, rotated or revoked by any of the three wrong-client_id presentations:
        //the live refresh token still redeems correctly afterward.
        (int LiveStillWorksStatusCode, string LiveStillWorksBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, liveRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, LiveStillWorksStatusCode,
            $"The oracle probes above must not have consumed, rotated or revoked the live refresh token. Body={LiveStillWorksBody}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2.1">RFC 6749 §3.2.1</see>
    /// client identification on a reuse presentation is held to the SAME bar
    /// <c>AuthCodeEndpoints.BuildRefreshToken</c>'s live rotation path holds a live presentation to: a form
    /// omitting <c>client_id</c> entirely is an INVALID presentation — exactly as it is against a
    /// still-live refresh token — never a fallback to the tenant's resolved registration. The refresh
    /// endpoint's pre-correlation step decides this request-only fact (no <c>client_id</c> field and
    /// no declared credentials) before the retired token is ever looked up, so the answer is the
    /// SAME <c>invalid_request</c> "client_id is required for a client that is not authenticating."
    /// a still-live presentation with no identity would also receive — never the record-dependent
    /// <c>invalid_grant</c> binding body the stored-grant comparison answers once a record is
    /// loaded. A bare <c>grant_type=refresh_token&amp;refresh_token=&lt;retired&gt;</c> revokes
    /// nothing and the successor remains usable.
    /// </summary>
    [TestMethod]
    public async Task ReuseOfRotatedOutRefreshTokenWithNoFormClientIdLeavesTheSuccessorUsableAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

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

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string retiredRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, retiredRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, StatusCode, Body);
        string successorRefreshToken;
        using(JsonDocument rotationDoc = JsonDocument.Parse(Body))
        {
            successorRefreshToken = rotationDoc.RootElement.GetProperty(
                OAuthRequestParameterNames.RefreshToken).GetString()!;
        }

        //The reuse presentation omits client_id from the form entirely — a raw wire push, since a
        //real client entry point always attaches its own client_id.
        Dictionary<string, string> reuseFieldsWithoutClientId = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
            [OAuthRequestParameterNames.RefreshToken] = retiredRefreshToken
        };
        (int StatusCode, string Body) reuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, reuseFieldsWithoutClientId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, reuse.StatusCode, reuse.Body);
        //A reuse presentation with no client_id and no credentials is refused by the refresh
        //endpoint's request-only rule (RFC 6749 §3.2.1) before the token is looked up, with the
        //SAME invalid_request a live presentation without any identity receives.
        Assert.Contains(OAuthErrors.InvalidRequest, reuse.Body, StringComparison.Ordinal);
        Assert.Contains("client_id is required for a client that is not authenticating.", reuse.Body, StringComparison.Ordinal);

        //The successor must remain usable — a client_id-less reuse presentation revoked nothing.
        (int StatusCode, string Body) successorAfterReuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, successorRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, successorAfterReuse.StatusCode,
            $"A reuse presentation omitting client_id must not revoke the successor. Body={successorAfterReuse.Body}");
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see> requires refresh replay detection: "Authorization servers MUST utilize
    /// one of these methods to detect refresh token replay by malicious actors for public clients".
    /// The refresh endpoint's pre-correlation step runs the request-only half of DPoP validation
    /// once, before the presented <c>refresh_token</c> is looked up, so a structurally malformed
    /// proof answers <c>invalid_dpop_proof</c> identically whether the handle is unknown, live, or
    /// a retired (reused) token — <see
    /// href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 §5</see>: "If the DPoP
    /// proof is invalid, the authorization server issues an error response ... with
    /// invalid_dpop_proof". Revokes nothing; the successor remains usable.
    /// </summary>
    [TestMethod]
    public async Task ReuseOfRotatedOutBearerRefreshTokenWithMalformedDpopProofIsRefusedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        //DPoP delegates must be wired for DpopTokenEndpointValidation to evaluate the attached
        //proof at all — this test's client itself never binds a token to a key (Bearer issuance),
        //so wiring here proves the unconditional call, not a policy requiring DPoP.
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

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

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer,
            (string)firstExchange.Body![OAuthRequestParameterNames.TokenType]!,
            "This test needs an unbound Bearer issuance to prove anything about the unconditional DPoP check.");
        string retiredRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, retiredRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, StatusCode, Body);
        string successorRefreshToken;
        using(JsonDocument rotationDoc = JsonDocument.Parse(Body))
        {
            successorRefreshToken = rotationDoc.RootElement.GetProperty(
                OAuthRequestParameterNames.RefreshToken).GetString()!;
        }

        //A structurally malformed DPoP proof attached to the reuse of a retired BEARER token — a
        //raw wire push, since no real client entry point attaches a DPoP proof for an unbound
        //grant.
        (int StatusCode, string Body) reuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, retiredRefreshToken),
            OutgoingHeaders.Empty.WithDpop("not-a-well-formed-dpop-proof"), TestContext.CancellationToken)
            .ConfigureAwait(false);

        //The pre-correlation step decides a malformed proof before this presentation is even
        //known to be retired — so an UNKNOWN handle with the same malformed proof answers
        //byte-identically.
        (int UnknownStatusCode, string UnknownBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, "unknown-refresh-token-value"),
            OutgoingHeaders.Empty.WithDpop("not-a-well-formed-dpop-proof"), TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, reuse.StatusCode, reuse.Body);
        Assert.Contains(OAuthErrors.InvalidDpopProof, reuse.Body, StringComparison.Ordinal);
        Assert.AreEqual(UnknownStatusCode, reuse.StatusCode,
            "An unknown handle and a retired one must answer byte-identically once the request-only DPoP decision runs first.");
        Assert.AreEqual(UnknownBody, reuse.Body,
            "An unknown handle and a retired one must answer byte-identically once the request-only DPoP decision runs first.");

        //Revoked nothing — the successor remains usable.
        (int StatusCode, string Body) successorAfterReuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, successorRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, successorAfterReuse.StatusCode,
            $"A malformed-DPoP-proof reuse presentation must not revoke the successor. Body={successorAfterReuse.Body}");
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §7.5.3</see>: "The authorization server SHOULD NOT revoke any issued tokens when
    /// receiving a replayed authorization code that contains invalid parameters" — otherwise
    /// merely observing a spent code and presenting it with the wrong verifier would deny service
    /// to its legitimate holder. An INVALID replay (wrong <c>code_verifier</c>) is refused
    /// <c>invalid_grant</c> without touching the first redemption's access token.
    /// </summary>
    [TestMethod]
    public async Task InvalidReplayOfRedeemedCodeIsInvalidGrantAndDoesNotRevokeTheIssuedAccessToken()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: CapabilitiesWithIntrospection).ConfigureAwait(false);

        bool revokeInvoked = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(true);

            candidateIntegration.RevokeIssuedTokenAsync = (_, _, _, _, _) =>
            {
                revokeInvoked = true;

                return ValueTask.CompletedTask;
            };

            candidateIntegration.IntrospectTokenAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(new TokenIntrospectionResult { IsActive = true });
        }).ConfigureAwait(false);

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
        AuthorizationCodeReceivedState codeState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string firstAccessToken = (string)firstExchange.Body![OAuthRequestParameterNames.AccessToken];

        //An INVALID replay: the right code, the WRONG verifier.
        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, codeState.Code, "wrong0000000000000000000000000000000000000", RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidGrant, Body, StringComparison.Ordinal);
        Assert.IsFalse(revokeInvoked, "An invalid replay must never revoke anything (OAuth 2.1 §7.5.3).");

        (int StatusCode, string Body) stillActive = await RawAuthCodeWirePushers.PushRawIntrospectionFieldsAsync(
            host, segment,
            new Dictionary<string, string> { [OAuthRequestParameterNames.Token] = firstAccessToken },
            TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument stillActiveDoc = JsonDocument.Parse(stillActive.Body);
        Assert.IsTrue(stillActiveDoc.RootElement.GetProperty("active").GetBoolean(),
            "The first redemption's access token must remain untouched after an invalid replay.");
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §7.5.3</see>'s denial-of-service reasoning applies to the code itself, not only to
    /// its tokens: a refused FIRST presentation (wrong <c>code_verifier</c>) must never burn the
    /// code, because the exactly-once claim runs only after every verification — including PKCE —
    /// succeeds. The same code, presented next with the RIGHT verifier, still completes.
    /// </summary>
    [TestMethod]
    public async Task WrongPkceVerifierThenCorrectVerifierStillRedeemsTheCode()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, code, "wrong0000000000000000000000000000000000000", RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidGrant, Body, StringComparison.Ordinal);

        (int StatusCode, string Body) correctVerifierResponse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, correctVerifierResponse.StatusCode,
            $"A refused first presentation must leave the code redeemable. Body={correctVerifierResponse.Body}");
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §7.5.3</see>'s "SHOULD NOT revoke ... when receiving a replayed authorization code
    /// that contains invalid parameters" reasoning applies to the code itself, not only its
    /// tokens — the same rule <see cref="WrongPkceVerifierThenCorrectVerifierStillRedeemsTheCode"/>
    /// pins for a wrong verifier, here for a mismatched <c>redirect_uri</c> instead: a refused
    /// first presentation leaves the code redeemable at the next, correctly-formed presentation.
    /// </summary>
    [TestMethod]
    public async Task MismatchedRedirectUriThenCorrectRedirectUriStillRedeemsTheCode()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, code, pkce.EncodedVerifier, "https://not-the-registered-redirect.example.com/callback"),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidGrant, Body, StringComparison.Ordinal);

        (int StatusCode, string Body) correctRedirectResponse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, correctRedirectResponse.StatusCode,
            $"A refused first presentation must leave the code redeemable. Body={correctRedirectResponse.Body}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.5">RFC 6749 §10.5</see>:
    /// "Authorization codes MUST be short lived and single-use." The value on the wire is the raw
    /// code, kept only transiently; the persisted index key is its SHA-256 base64url hash, so the
    /// two values must differ from each other, and the wire value must hash to the stored one.
    /// </summary>
    [TestMethod]
    public async Task AuthorizationCodeOnWireIsNotTheStoredHashButHashesToIt()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);

        string expectedHash = await RawAuthCodeWirePushers.ComputeAuthorizationCodeHashAsync(code)
            .ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        Assert.IsFalse(hosted.CodeIndex.ContainsKey(code),
            "RFC 6749 §10.5: the wire code must not itself be the stored index key.");
        Assert.IsTrue(hosted.CodeIndex.ContainsKey(expectedHash),
            "The code on the wire must hash (SHA-256, base64url) to the stored CodeHash index key.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.5">RFC 6749 §10.5</see>:
    /// "Authorization codes MUST be short lived and single-use." Presenting the STORED hash value
    /// as <c>code</c> — what a party who compromised only the backing store, never the wire, would
    /// have — is refused: hashing it a second time never matches the index key hashing the true
    /// raw code produced.
    /// </summary>
    [TestMethod]
    public async Task PresentingTheStoredCodeHashAsCodeIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);
        string storedHash = await RawAuthCodeWirePushers.ComputeAuthorizationCodeHashAsync(code)
            .ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, storedHash, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidGrant, Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// The plain (non-PAR) authorization start's whole journey over the real wire — start,
    /// authorize, callback, token — against a registration whose profile permits a direct
    /// authorization request. The redirect
    /// <see cref="AuthCodeClient.StartAsync(ClientRegistration, Uri, OAuthFormEncodedFields, ExchangeContext, IReadOnlyList{string}?, TimeSpan, CancellationToken)"/>
    /// returns carries the parameters
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see> lists —
    /// "response_type: REQUIRED. Value MUST be set to 'code'.", "client_id: REQUIRED.",
    /// "redirect_uri: OPTIONAL.", "state: RECOMMENDED." — plus the PKCE pair per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>. The caller
    /// names no scope and the policy requires none, so "scope: OPTIONAL." is not sent and the journey
    /// still reaches the token.
    /// </summary>
    [TestMethod]
    public async Task PlainStartReachesTokenOverRealWire()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: Capabilities.Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization)).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(true);
        }).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");

        AuthCodeFlowEndpointResult startResult = await client.AuthCode.StartAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, [], resource: null,
            requestLifetime: TimeSpan.FromMinutes(5), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, startResult.Outcome,
            $"A plain start must redirect over the real wire. ErrorCode={startResult.ErrorCode} ErrorDescription={startResult.ErrorDescription}");

        string flowId = clientFlowStore.Keys.Single();
        ParCompletedState parState = (ParCompletedState)clientFlowStore[flowId];
        Dictionary<string, string> queryParams = ParseQuery(startResult.RedirectUri!);

        Assert.AreEqual(WellKnownResponseTypes.Code, queryParams[OAuthRequestParameterNames.ResponseType],
            "RFC 6749 §4.1.1: response_type REQUIRED, value MUST be 'code'.");
        Assert.AreEqual(ClientId, queryParams[OAuthRequestParameterNames.ClientId],
            "RFC 6749 §4.1.1: client_id REQUIRED.");
        Assert.AreEqual(RedirectUri.OriginalString, queryParams[OAuthRequestParameterNames.RedirectUri],
            "RFC 6749 §4.1.1: redirect_uri.");
        Assert.IsFalse(queryParams.ContainsKey(OAuthRequestParameterNames.Scope),
            "RFC 6749 §4.1.1: scope OPTIONAL; a start whose caller names no scope sends none.");
        Assert.AreEqual(flowId, queryParams[OAuthRequestParameterNames.State],
            "RFC 6749 §4.1.1: state.");
        Assert.AreEqual(parState.Pkce.EncodedChallenge, queryParams[OAuthRequestParameterNames.CodeChallenge],
            "RFC 7636 §4.3: code_challenge.");
        Assert.AreEqual("S256", queryParams[OAuthRequestParameterNames.CodeChallengeMethod],
            "RFC 7636 §4.3: code_challenge_method.");

        _ = await GetAuthorizeRedirectAndCallbackAsync(
            hosted, client, registration, host.ServerCertificate, startResult.RedirectUri!, flowId,
            TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Token exchange must succeed over the real wire. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
        string accessToken = (string)tokenResult.Body![OAuthRequestParameterNames.AccessToken];
        Assert.IsFalse(string.IsNullOrEmpty(accessToken));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-5">RFC 9126 §5</see>:
    /// "require_pushed_authorization_requests: Boolean parameter indicating whether the
    /// authorization server accepts authorization request data only via PAR." A registration whose
    /// resolved metadata sets it is refused before anything is dialed — every delegate other than
    /// metadata resolution throws if invoked, proving neither a PAR/authorize/token POST nor state
    /// persistence nor PKCE minting happens.
    /// </summary>
    [TestMethod]
    public async Task StartAsyncRefusedBeforeAnyDialWhenMetadataRequiresPar()
    {
        Uri issuer = new("https://as.example.com");
        AuthorizationServerMetadata parRequiredMetadata = new()
        {
            Issuer = issuer,
            AuthorizationEndpoint = new Uri("https://as.example.com/authorize"),
            TokenEndpoint = new Uri("https://as.example.com/token"),
            PushedAuthorizationRequestEndpoint = new Uri("https://as.example.com/par"),
            RequirePushedAuthorizationRequests = true
        };

        OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
            sendFormPostAsync: (_, _, _, _, _) =>
                throw new InvalidOperationException("Must not dial any endpoint when the metadata requires PAR."),
            saveStateAsync: (_, _, _) =>
                throw new InvalidOperationException("Must not persist state before the PAR-required refusal."),
            loadStateAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
            loadStateByRequestUriAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            parseRegistrationResponseAsync: (body, ct) =>
                throw new NotImplementedException("Test does not exercise dynamic registration."),
            resolveAuthorizationServerMetadataAsync: (_, _, _) =>
                ValueTask.FromResult<AuthorizationServerMetadataResolution>(new AuthorizationServerMetadataResolved
                {
                    MetadataLocation = WellKnownPaths.OAuthAuthorizationServer.ComputeUri(parRequiredMetadata.Issuer.OriginalString),
                    Metadata = parRequiredMetadata
                }),
            resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            memoryPool: BaseMemoryPool.Shared,
            timeProvider: TimeProvider,
            fillEntropy: _ =>
                throw new InvalidOperationException("Must not mint entropy before the PAR-required refusal."),
            generateIdentifierAsync: (_, _, _) =>
                throw new InvalidOperationException("Must not mint an identifier before the PAR-required refusal."));

        ClientRegistration registration = new()
        {
            ClientId = new ClientId(ClientId),
            AuthorizationServerIssuer = issuer,
            RedirectUris = [RedirectUri],
            AuthenticationMethod = ClientAuthenticationMethod.None,
            Profile = PolicyProfile.Fapi20
        };

        OAuthClient client = new(infrastructure);

        AuthCodeFlowEndpointResult result = await client.AuthCode.StartAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, [], resource: null,
            requestLifetime: TimeSpan.FromMinutes(5), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome,
            $"A PAR-required authorization server must refuse a plain start. Body={result.Body}");
        Assert.AreEqual(OAuthErrors.InvalidRequest, result.ErrorCode);
    }


    /// <summary>
    /// The additional fields a caller supplies to
    /// <see cref="AuthCodeClient.StartAsync(ClientRegistration, Uri, OAuthFormEncodedFields, ExchangeContext, IReadOnlyList{string}?, TimeSpan, CancellationToken)"/>
    /// ride the front channel, which any party observing the redirect can also construct — so a
    /// field named <c>state</c> or <c>code_challenge</c> must not be able to override the value this
    /// call minted for RFC 6749 §4.1.1's CSRF-protection <c>state</c> or RFC 7636 §4.3's PKCE
    /// <c>code_challenge</c>; either would let an attacker fix the flow to a value of their choosing.
    /// </summary>
    [TestMethod]
    public async Task AdditionalFieldsCannotOverrideStateOrCodeChallengeAtPlainStart()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: Capabilities.Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization)).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, string> attackerFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.State] = "attacker-supplied-state",
            [OAuthRequestParameterNames.CodeChallenge] = "attacker-supplied-challenge"
        };

        AuthCodeFlowEndpointResult startResult = await client.AuthCode.StartAsync(
            registration, RedirectUri, new OAuthFormEncodedFields(attackerFields), [], resource: null,
            requestLifetime: TimeSpan.FromMinutes(5), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, startResult.Outcome,
            $"ErrorCode={startResult.ErrorCode} ErrorDescription={startResult.ErrorDescription}");

        string flowId = clientFlowStore.Keys.Single();
        ParCompletedState parState = (ParCompletedState)clientFlowStore[flowId];
        Dictionary<string, string> queryParams = ParseQuery(startResult.RedirectUri!);

        Assert.AreEqual(flowId, queryParams[OAuthRequestParameterNames.State],
            "An additional field named state must not override the state this call minted.");
        Assert.AreNotEqual("attacker-supplied-state", queryParams[OAuthRequestParameterNames.State]);
        Assert.AreEqual(parState.Pkce.EncodedChallenge, queryParams[OAuthRequestParameterNames.CodeChallenge],
            "An additional field named code_challenge must not override the PKCE challenge this call minted.");
        Assert.AreNotEqual("attacker-supplied-challenge", queryParams[OAuthRequestParameterNames.CodeChallenge]);
    }


    /// <summary>
    /// The row value naming the pushed start
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.1">RFC 9126 §2.1</see>), whose
    /// authorization request parameters travel in the body of the pushed authorization request.
    /// </summary>
    private const string PushedStart = "pushed";


    /// <summary>
    /// The row value naming the direct start
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see>), whose
    /// authorization request parameters travel on the authorization endpoint's query.
    /// </summary>
    private const string DirectStart = "direct";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see> makes
    /// the parameter "scope OPTIONAL", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see> gives the
    /// default to the authorization server: "If the client omits the scope parameter when requesting
    /// authorization, the authorization server MUST either process the request using a pre-defined
    /// default value or fail the request indicating an invalid scope." A client whose caller names no
    /// scope sends no <c>scope</c> parameter; an OpenID Connect request names <c>openid</c> itself
    /// (<see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OpenID Connect
    /// Core 1.0 §3.1.2.1</see>: "OpenID Connect requests MUST contain the openid scope value."). Under a
    /// policy that requires no scope, the request the server receives carries no <c>scope</c> and the
    /// flow reaches an authorization code.
    /// </summary>
    /// <param name="start">Which start carries the request: <see cref="PushedStart"/> or <see cref="DirectStart"/>.</param>
    [TestMethod]
    [DataRow(PushedStart)]
    [DataRow(DirectStart)]
    public async Task ARequestWithoutAScopeFieldSendsNoScopeAsync(string start)
    {
        RequestFields received = await DriveStartToCallbackAndReadReceivedRequestAsync(
            start, OAuthFormEncodedFields.Empty).ConfigureAwait(false);

        Assert.IsFalse(received.ContainsKey(OAuthRequestParameterNames.Scope),
            $"A start whose caller names no scope must send no scope parameter; the server received scope " +
            $"[{string.Join(", ", received.GetValues(OAuthRequestParameterNames.Scope))}].");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 §3.1</see>: "Parameters
    /// sent without a value MUST be treated as if they were omitted from the request.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see> defines the
    /// value as "scope = scope-token *( SP scope-token )" with "scope-token = 1*( %x21 / %x23-5B /
    /// %x5D-7E )", so a value made only of white space names no scope token. A caller whose
    /// <c>scope</c> field is empty or white space only names no scope, and the request carries no
    /// <c>scope</c> parameter at all rather than a <c>scope</c> holding no token.
    /// </summary>
    /// <param name="start">Which start carries the request: <see cref="PushedStart"/> or <see cref="DirectStart"/>.</param>
    /// <param name="scope">The blank value the caller gives as its <c>scope</c> field: empty, or a tab alone.</param>
    [TestMethod]
    [DataRow(PushedStart, "")]
    [DataRow(DirectStart, "")]
    [DataRow(PushedStart, "\t")]
    [DataRow(DirectStart, "\t")]
    public async Task ABlankScopeFieldSendsNoScopeParameterAsync(string start, string scope)
    {
        OAuthFormEncodedFields blankScope = new(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.Scope] = scope
        });

        RequestFields received = await DriveStartToCallbackAndReadReceivedRequestAsync(start, blankScope)
            .ConfigureAwait(false);

        Assert.IsFalse(received.ContainsKey(OAuthRequestParameterNames.Scope),
            $"A blank scope field must send no scope parameter, never scope=; the server received scope " +
            $"[{string.Join(", ", received.GetValues(OAuthRequestParameterNames.Scope).Select(value => $"'{value}'"))}].");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OpenID Connect
    /// Core 1.0 §3.1.2.1</see>: "OpenID Connect requests MUST contain the openid scope value. ...
    /// Other scope values MAY be present." The scope the caller names travels as given, as the one
    /// space-delimited <c>scope</c> value of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see>.
    /// </summary>
    [TestMethod]
    public async Task AnExplicitScopeIsSentAsGivenAsync()
    {
        OAuthFormEncodedFields namedScope = new(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.Scope] = "openid profile"
        });

        RequestFields received = await DriveStartToCallbackAndReadReceivedRequestAsync(PushedStart, namedScope)
            .ConfigureAwait(false);

        Assert.IsTrue(received.TryGetValue(OAuthRequestParameterNames.Scope, out string? scope),
            "The scope the caller names must be sent exactly once.");
        Assert.AreEqual("openid profile", scope);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see>: "If the client
    /// omits the scope parameter when requesting authorization, the authorization server MUST either
    /// process the request using a pre-defined default value or fail the request indicating an invalid
    /// scope." Under the FAPI 2.0 policy a pushed request whose caller names no scope is refused: the
    /// client reports the refusal, is given no <c>request_uri</c>, keeps no flow, and the server's
    /// flow-state count stays unchanged.
    /// </summary>
    [TestMethod]
    public async Task AFapiRegistrationRefusesAPushedRequestWithoutScopeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Fapi20, capabilities: Capabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Fapi20,
                TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        int flowCountBefore = hosted.FlowStates.Count;

        AuthCodeFlowEndpointResult parResult = await client.AuthCode.StartParAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, [], resource: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, parResult.Outcome,
            $"A pushed request without scope must be refused under a policy with no default scope. " +
            $"ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");
        Assert.IsNull(parResult.RedirectUri,
            "A refused pushed request issues no request_uri, so the client has no authorization redirect.");
        Assert.IsEmpty(clientFlowStore, "A refused pushed request must leave the client no flow to continue.");
        Assert.HasCount(flowCountBefore, hosted.FlowStates,
            "A refused pushed request must issue no request_uri and record no pushed request.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 §3.1</see>: "Parameters
    /// sent without a value MUST be treated as if they were omitted from the request." A refresh whose
    /// caller gives a blank scope sends no <c>scope</c> parameter, never <c>scope=</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see>: an omitted
    /// refresh scope "is treated as equal to the scope originally granted by the resource owner" — the
    /// scope this test itself requested and was granted at authorization, <c>openid</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>: the
    /// response's <c>scope</c> is "OPTIONAL, if identical to the scope requested by the client;
    /// otherwise, REQUIRED", so the server may omit it; when it names one, it must name that same
    /// scope.
    /// </summary>
    [TestMethod]
    public async Task ABlankRefreshScopeSendsNoScopeParameterAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(true);
        }).ConfigureAwait(false);
        ConcurrentQueue<RequestFields> accepted = await RecordAcceptedRequestFieldsAsync(host).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        string flowId = await DriveParAuthorizeAndCallbackAsync(
            host.Host("default"), client, registration, clientFlowStore, material.Registration.TenantId.Value,
            host.ServerCertificate, TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Token exchange must succeed. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
        string refreshToken = (string)tokenResult.Body![OAuthRequestParameterNames.RefreshToken];

        AuthCodeFlowEndpointResult refreshResult = await client.AuthCode.RefreshAsync(
            registration,
            new RefreshTokenRequest { ClientId = ClientId, RefreshToken = refreshToken, Scope = string.Empty },
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, refreshResult.Outcome,
            $"The refresh must succeed. ErrorCode={refreshResult.ErrorCode} ErrorDescription={refreshResult.ErrorDescription}");

        RequestFields refreshRequest = accepted.Single(received =>
            received.TryGetValue(OAuthRequestParameterNames.GrantType, out string? grantType)
            && string.Equals(grantType, "refresh_token", StringComparison.Ordinal));
        Assert.IsFalse(refreshRequest.ContainsKey(OAuthRequestParameterNames.Scope),
            $"A blank refresh scope must send no scope parameter, never scope=; the server received scope " +
            $"[{string.Join(", ", refreshRequest.GetValues(OAuthRequestParameterNames.Scope).Select(value => $"'{value}'"))}].");
        Assert.IsTrue(
            !refreshResult.Body!.ContainsKey(OAuthRequestParameterNames.Scope)
            || string.Equals((string)refreshResult.Body[OAuthRequestParameterNames.Scope], "openid", StringComparison.Ordinal),
            "A refresh response, when it names a scope, must name the scope this test itself requested " +
            "and was granted at authorization.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-4">RFC 9101 §4</see>: a Request Object
    /// carries the authorization request parameters, and "The parameters are represented as the JWT
    /// Claims of the object."; <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749
    /// §3.1</see>: "Parameters sent without a value MUST be treated as if they were omitted from the
    /// request." A signed request object whose caller gives a blank scope carries no <c>scope</c> claim
    /// rather than an empty one, and the server accepts it and issues an authorization code.
    /// </summary>
    /// <param name="start">
    /// Which start carries the request object: <see cref="PushedRequestObjectStart"/> pushes it
    /// (RFC 9126 §3), and <see cref="RequestObjectByValueStart"/> passes it by value on the
    /// authorization endpoint's query (RFC 9101 §5.1).
    /// </param>
    [TestMethod]
    [DataRow(PushedRequestObjectStart)]
    [DataRow(RequestObjectByValueStart)]
    public async Task ABlankRequestObjectScopeSignsNoScopeClaimAsync(string start)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri,
            Capabilities
                .Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization)
                .Add(WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest),
            profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        ConcurrentQueue<RequestFields> accepted = await RecordAcceptedRequestFieldsAsync(host).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        _ = await DriveRequestObjectStartAuthorizeAndCallbackAsync(
            start, host, client, registration, clientFlowStore, material, scope: string.Empty, resource: null).ConfigureAwait(false);

        using JsonDocument claims = DecodeReceivedRequestObject(accepted);
        Assert.IsFalse(claims.RootElement.TryGetProperty(OAuthRequestParameterNames.Scope, out JsonElement scopeClaim),
            $"A blank scope must sign no scope claim; the request object carried scope {scopeClaim.GetRawText()}. " +
            $"Claims: {claims.RootElement}");
    }


    /// <summary>
    /// Decodes the claims of the one signed request object the server accepted: the <c>request</c>
    /// parameter of the pushed body of a pushed start, or of the authorization request of a start
    /// that passes the object by value. The request that completes a pushed start carries only
    /// <c>client_id</c> and <c>request_uri</c>, so exactly one accepted request carries
    /// <c>request</c>.
    /// </summary>
    /// <param name="accepted">The parameters of every request the server accepted, in arrival order.</param>
    /// <returns>The claims of the request object as the server received it.</returns>
    private static JsonDocument DecodeReceivedRequestObject(ConcurrentQueue<RequestFields> accepted)
    {
        RequestFields carrying = accepted.Single(received => received.ContainsKey(OAuthRequestParameterNames.Request));

        return DecodePayload(carrying[OAuthRequestParameterNames.Request]);
    }


    /// <summary>
    /// The row value naming the start that pushes a signed request object
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9126#section-3">RFC 9126 §3</see>), whose
    /// authorization request parameters travel as the claims of the object in the pushed body.
    /// </summary>
    private const string PushedRequestObjectStart = "pushed request object";


    /// <summary>
    /// The row value naming the start that passes a signed request object by value
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9101#section-5.1">RFC 9101 §5.1</see>), whose
    /// authorization request parameters travel as the claims of the object on the authorization
    /// endpoint's query.
    /// </summary>
    private const string RequestObjectByValueStart = "request object by value";


    /// <summary>
    /// The row value naming the path through the client's authorization code flow automaton
    /// (<see cref="AuthCodeFlowAutomaton"/>), whose caller composes and sends the pushed request
    /// itself and hands the automaton's code-received state to the client's code redemption.
    /// </summary>
    private const string AutomatonPath = "automaton";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 §2.2</see>: "In the
    /// "authorization_code" case where the requested resources are a subset of the set of resources
    /// originally granted, the authorization server will issue an access token based on that subset
    /// of requested resources". The resource parameter "MUST be included in both authorization
    /// requests and token requests"
    /// (<see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#resource-parameter-implementation">MCP
    /// authorization, Resource Parameter Implementation</see>). A code redemption whose caller names
    /// one of the two resources the authorization request named receives an access token whose
    /// audience is that one resource.
    /// </summary>
    [TestMethod]
    public async Task CodeExchangeNamesTheResourceTheCallerGivesAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: ResourceJourneyCapabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await ComposeResourceJourneyClientAsync(host, material).ConfigureAwait(false);

        string flowId = await DriveParAuthorizeAndCallbackAsync(
            host.Host("default"), client, registration, clientFlowStore, material.Registration.TenantId.Value,
            host.ServerCertificate, TestContext.CancellationToken,
            resource: ["https://cal.example.com/", "https://contacts.example.com/"]).ConfigureAwait(false);

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, [], clientAssertionOptions: null, resource: ["https://cal.example.com/"],
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"The code redemption must succeed. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");

        using JsonDocument accessPayload = DecodePayload((string)tokenResult.Body![OAuthRequestParameterNames.AccessToken]);
        List<string?> audience = [.. accessPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Aud).EnumerateArray()
            .Select(static member => member.GetString())];
        Assert.HasCount(1, audience,
            $"The access token of a code redemption naming one resource must be audienced to that resource alone. " +
            $"Payload: {accessPayload.RootElement}");
        Assert.AreEqual("https://cal.example.com/", audience[0]);
    }


    /// <summary>
    /// The resource parameter "MUST be included in both authorization requests and token requests",
    /// and "MCP clients MUST send this parameter regardless of whether authorization servers support
    /// it"
    /// (<see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#resource-parameter-implementation">MCP
    /// authorization, Resource Parameter Implementation</see>);
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 §2.2</see>: "When the
    /// "resource" parameter is used on an access token request made to the token endpoint, for all
    /// grant types, it indicates the target service or protected resource where the client intends to
    /// use the requested access token." A flow whose authorization request names a resource, redeemed
    /// by a caller that names none, sends that resource on the token request, and the token endpoint
    /// answers it.
    /// </summary>
    /// <param name="start">
    /// Which start carries the authorization request: <see cref="PushedStart"/>,
    /// <see cref="DirectStart"/>, <see cref="PushedRequestObjectStart"/>,
    /// <see cref="RequestObjectByValueStart"/>, or the <see cref="AutomatonPath"/>.
    /// </param>
    [TestMethod]
    [DataRow(PushedStart)]
    [DataRow(DirectStart)]
    [DataRow(PushedRequestObjectStart)]
    [DataRow(RequestObjectByValueStart)]
    [DataRow(AutomatonPath)]
    public async Task CodeExchangeNamesTheRequestedResourceByDefaultAsync(string start)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: ResourceJourneyCapabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await ComposeResourceJourneyClientAsync(host, material).ConfigureAwait(false);
        ConcurrentQueue<RequestFields> accepted = await RecordAcceptedRequestFieldsAsync(host).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;
        IReadOnlyList<string> requested = ["https://cal.example.com/"];

        string flowId = start switch
        {
            PushedStart => await DriveParAuthorizeAndCallbackAsync(
                hosted, client, registration, clientFlowStore, segment, host.ServerCertificate,
                TestContext.CancellationToken, resource: requested).ConfigureAwait(false),
            DirectStart => await DriveDirectStartAuthorizeAndCallbackAsync(
                hosted, client, registration, clientFlowStore, host.ServerCertificate,
                OAuthFormEncodedFieldsFixtures.OpenIdScope, TestContext.CancellationToken, requested).ConfigureAwait(false),
            PushedRequestObjectStart or RequestObjectByValueStart => await DriveRequestObjectStartAuthorizeAndCallbackAsync(
                start, host, client, registration, clientFlowStore, material, WellKnownScopes.OpenId, requested).ConfigureAwait(false),
            AutomatonPath => await DriveAutomatonToCodeReceivedAsync(
                host, client, registration, segment, requested).ConfigureAwait(false),
            _ => throw new ArgumentOutOfRangeException(nameof(start), start, "Unknown authorization request start.")
        };

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);

        RequestFields tokenRequest = accepted.Single(received =>
            received.TryGetValue(OAuthRequestParameterNames.GrantType, out string? grantType)
            && string.Equals(grantType, "authorization_code", StringComparison.Ordinal));
        List<string> sentResource = [.. tokenRequest.GetValues(OAuthRequestParameterNames.Resource)];
        Assert.HasCount(1, sentResource,
            $"A code redemption whose caller names no resource must name the resource the authorization request named; " +
            $"the server received resource [{string.Join(", ", sentResource)}].");
        Assert.AreEqual("https://cal.example.com/", sentResource[0]);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"The code redemption must succeed. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>: "Multiple
    /// "resource" parameters MAY be used to indicate that the requested token is intended to be used
    /// at multiple resources."; <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC
    /// 8707 §2.1</see>: "For an authorization request sent as a JSON Web Token (JWT), such as when
    /// using the JWT Secured Authorization Request [JWT-SAR], a single "resource" parameter value is
    /// represented as a JSON string while multiple values are represented as an array of strings.";
    /// and the resource parameter "MUST be included in both authorization requests and token
    /// requests"
    /// (<see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#resource-parameter-implementation">MCP
    /// authorization, Resource Parameter Implementation</see>). A flow whose caller names two
    /// resources sends both, in the caller's order, on its authorization request (two
    /// <c>resource</c> parameters, or a request object whose <c>resource</c> claim is the array of
    /// the two) and, when the code redemption's caller names none, on its token request as two
    /// <c>resource</c> parameters in the same order, and the token endpoint answers it.
    /// </summary>
    /// <param name="start">
    /// Which start carries the authorization request: <see cref="PushedStart"/>,
    /// <see cref="DirectStart"/>, <see cref="PushedRequestObjectStart"/>,
    /// <see cref="RequestObjectByValueStart"/>, or the <see cref="AutomatonPath"/>, whose caller
    /// composes the pushed request itself, so the <see cref="AutomatonPath"/> row's
    /// authorization-request assertions pin that composition rather than exercising the library;
    /// its token-request assertions exercise the library the same as every other row.
    /// </param>
    [TestMethod]
    [DataRow(PushedStart)]
    [DataRow(DirectStart)]
    [DataRow(PushedRequestObjectStart)]
    [DataRow(RequestObjectByValueStart)]
    [DataRow(AutomatonPath)]
    public async Task EveryRequestedResourceTravelsInOrderOnTheAuthorizationAndTokenRequestsAsync(string start)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: ResourceJourneyCapabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await ComposeResourceJourneyClientAsync(host, material).ConfigureAwait(false);
        ConcurrentQueue<RequestFields> accepted = await RecordAcceptedRequestFieldsAsync(host).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;
        IReadOnlyList<string> requested = ["https://cal.example.com/", "https://contacts.example.com/"];

        string flowId = start switch
        {
            PushedStart => await DriveParAuthorizeAndCallbackAsync(
                hosted, client, registration, clientFlowStore, segment, host.ServerCertificate,
                TestContext.CancellationToken, resource: requested).ConfigureAwait(false),
            DirectStart => await DriveDirectStartAuthorizeAndCallbackAsync(
                hosted, client, registration, clientFlowStore, host.ServerCertificate,
                OAuthFormEncodedFieldsFixtures.OpenIdScope, TestContext.CancellationToken, requested).ConfigureAwait(false),
            PushedRequestObjectStart or RequestObjectByValueStart => await DriveRequestObjectStartAuthorizeAndCallbackAsync(
                start, host, client, registration, clientFlowStore, material, WellKnownScopes.OpenId, requested).ConfigureAwait(false),
            AutomatonPath => await DriveAutomatonToCodeReceivedAsync(
                host, client, registration, segment, requested).ConfigureAwait(false),
            _ => throw new ArgumentOutOfRangeException(nameof(start), start, "Unknown authorization request start.")
        };

        List<string?> authorizationResource = start switch
        {
            PushedRequestObjectStart or RequestObjectByValueStart => ReadReceivedRequestObjectResourceArray(accepted),
            _ => [.. accepted
                .Single(received => received.ContainsKey(OAuthRequestParameterNames.CodeChallenge))
                .GetValues(OAuthRequestParameterNames.Resource)]
        };

        Assert.HasCount(2, authorizationResource,
            $"The authorization request must name both resources the caller named; the server received resource " +
            $"[{string.Join(", ", authorizationResource)}].");
        Assert.AreEqual("https://cal.example.com/", authorizationResource[0]);
        Assert.AreEqual("https://contacts.example.com/", authorizationResource[1]);

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);

        RequestFields tokenRequest = accepted.Single(received =>
            received.TryGetValue(OAuthRequestParameterNames.GrantType, out string? grantType)
            && string.Equals(grantType, "authorization_code", StringComparison.Ordinal));
        List<string> sentResource = [.. tokenRequest.GetValues(OAuthRequestParameterNames.Resource)];
        Assert.HasCount(2, sentResource,
            $"A code redemption whose caller names no resource must name every resource the authorization request named; " +
            $"the server received resource [{string.Join(", ", sentResource)}].");
        Assert.AreEqual("https://cal.example.com/", sentResource[0]);
        Assert.AreEqual("https://contacts.example.com/", sentResource[1]);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"The code redemption must succeed. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 §2.1</see>: "For an
    /// authorization request sent as a JSON Web Token (JWT), such as when using the JWT Secured
    /// Authorization Request [JWT-SAR], a single "resource" parameter value is represented as a JSON
    /// string while multiple values are represented as an array of strings." A request object whose
    /// caller names one resource carries the <c>resource</c> claim as that one JSON string, as the
    /// server receives it.
    /// </summary>
    /// <param name="start"><see cref="PushedRequestObjectStart"/> or <see cref="RequestObjectByValueStart"/>.</param>
    [TestMethod]
    [DataRow(PushedRequestObjectStart)]
    [DataRow(RequestObjectByValueStart)]
    public async Task ARequestObjectNamingOneResourceSignsItAsAJsonStringAsync(string start)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: ResourceJourneyCapabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await ComposeResourceJourneyClientAsync(host, material).ConfigureAwait(false);
        ConcurrentQueue<RequestFields> accepted = await RecordAcceptedRequestFieldsAsync(host).ConfigureAwait(false);

        _ = await DriveRequestObjectStartAuthorizeAndCallbackAsync(
            start, host, client, registration, clientFlowStore, material, WellKnownScopes.OpenId,
            ["https://cal.example.com/"]).ConfigureAwait(false);

        using JsonDocument claims = DecodeReceivedRequestObject(accepted);
        Assert.IsTrue(claims.RootElement.TryGetProperty(OAuthRequestParameterNames.Resource, out JsonElement resourceClaim),
            $"The request object must carry the resource claim. Claims: {claims.RootElement}");
        Assert.AreEqual(JsonValueKind.String, resourceClaim.ValueKind,
            $"One resource must be signed as a JSON string. Claims: {claims.RootElement}");
        Assert.AreEqual("https://cal.example.com/", resourceClaim.GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>: the resource
    /// value "MUST be an absolute URI, as specified by Section 4.3 of [RFC3986]", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-2">RFC 3986 §2</see>: "A URI is
    /// composed from a limited set of characters consisting of digits, letters, and a few graphic
    /// symbols.", so no resource indicator holds a white-space character. The entries a request
    /// object signs are the entries the flow keeps and the code redemption sends, so a request object
    /// start whose resource list holds an entry with white space in it, inside or around the URI, is
    /// refused by the client before anything is signed or sent: the start answers
    /// <c>invalid_request</c>, the server observes no arriving request, and the client keeps no flow.
    /// </summary>
    /// <param name="start"><see cref="PushedRequestObjectStart"/> or <see cref="RequestObjectByValueStart"/>.</param>
    /// <param name="entry">The one resource entry the caller names: two URIs with a space between them, or one URI padded with spaces.</param>
    [TestMethod]
    [DataRow(PushedRequestObjectStart, "https://cal.example.com/ https://contacts.example.com/")]
    [DataRow(RequestObjectByValueStart, "https://cal.example.com/ https://contacts.example.com/")]
    [DataRow(PushedRequestObjectStart, " https://cal.example.com/ ")]
    [DataRow(RequestObjectByValueStart, " https://cal.example.com/ ")]
    public async Task ARequestObjectStartRefusesAResourceEntryHoldingWhiteSpaceBeforeSendingAsync(string start, string entry)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: ResourceJourneyCapabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await ComposeResourceJourneyClientAsync(host, material).ConfigureAwait(false);
        ConcurrentQueue<RequestFields> accepted = await RecordAcceptedRequestFieldsAsync(host).ConfigureAwait(false);

        int arrivals = 0;
        host.Host("default").RequestArriving = () =>
        {
            _ = Interlocked.Increment(ref arrivals);

            return Task.CompletedTask;
        };

        AuthCodeFlowEndpointResult startResult = await StartRequestObjectAsync(
            start, host, client, registration, material, WellKnownScopes.OpenId, [entry]).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, startResult.Outcome,
            $"A request object start naming a resource entry that holds white space must be refused before anything is sent. " +
            $"ErrorCode={startResult.ErrorCode} ErrorDescription={startResult.ErrorDescription} RedirectUri={startResult.RedirectUri}");
        Assert.AreEqual("invalid_request", startResult.ErrorCode);
        Assert.IsNull(startResult.RedirectUri, "A refused start composes no authorization redirect.");
        Assert.AreEqual(0, Volatile.Read(ref arrivals),
            $"A refused start must reach the server with no request; the server observed {Volatile.Read(ref arrivals)} arrival(s).");
        Assert.IsEmpty(accepted, $"A refused start must send nothing; the server received {accepted.Count} request(s).");
        Assert.IsEmpty(clientFlowStore, "A refused start must store no flow.");
    }


    /// <summary>
    /// Reads the <c>resource</c> claim of the one signed request object the server accepted
    /// (<see cref="DecodeReceivedRequestObject"/>) and returns its members, asserting that the claim
    /// is a JSON array, the form <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC
    /// 8707 §2.1</see> gives several indicators.
    /// </summary>
    /// <param name="accepted">The parameters of every request the server accepted, in arrival order.</param>
    /// <returns>The members of the <c>resource</c> array, in order.</returns>
    private static List<string?> ReadReceivedRequestObjectResourceArray(ConcurrentQueue<RequestFields> accepted)
    {
        using JsonDocument claims = DecodeReceivedRequestObject(accepted);
        Assert.IsTrue(claims.RootElement.TryGetProperty(OAuthRequestParameterNames.Resource, out JsonElement resourceClaim),
            $"The request object must carry the resource claim. Claims: {claims.RootElement}");
        Assert.AreEqual(JsonValueKind.Array, resourceClaim.ValueKind,
            $"Several resources must be signed as a JSON array. Claims: {claims.RootElement}");

        return [.. resourceClaim.EnumerateArray().Select(static member => member.GetString())];
    }


    /// <summary>
    /// <see cref="Capabilities"/> plus the direct authorization request and signed request objects,
    /// so that one registration can take every start the client offers.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> ResourceJourneyCapabilities { get; } =
        Capabilities
            .Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization)
            .Add(WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest);


    /// <summary>
    /// Composes the client for a registration made with <see cref="ResourceJourneyCapabilities"/>
    /// (or <see cref="CapabilitiesWithOpenIdConnect"/>, which holds them)
    /// and lists the registration's own key as its request-object signing key, so the same
    /// registration verifies a signed request object and issues the tokens a code redemption
    /// returns. The client-credential check answers true, as for the other journeys of this class
    /// that redeem a code.
    /// </summary>
    /// <param name="host">The host serving the registration over the real wire.</param>
    /// <param name="material">The registration and its key material.</param>
    /// <returns>The client, its registration of the authorization server, and its flow store.</returns>
    private async Task<(OAuthClient Client, ClientRegistration Registration, Dictionary<string, FlowState> ClientFlowStore)>
        ComposeResourceJourneyClientAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(true);
        }).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        string segment = material.Registration.TenantId.Value;
        await host.UpdateSigningKeysAsync(
            segment,
            host.RegistrationStore[segment].SigningKeys.ToImmutableDictionary()
                .Add(KeyUsageContext.JarSigning, new SigningKeySet { Current = [material.SigningKeyId] })).ConfigureAwait(false);

        return (client, registration, clientFlowStore);
    }


    /// <summary>
    /// Starts an authorization request carrying a signed request object that names
    /// <paramref name="scope"/> and <paramref name="resource"/>, pushed or by value as
    /// <paramref name="start"/> names, and drives it over the real wire through the authorize leg to
    /// an authorization code accepted at the callback (<see cref="GetAuthorizeRedirectAndCallbackAsync"/>).
    /// Returns the flow identifier ready for the code redemption.
    /// </summary>
    /// <param name="start"><see cref="PushedRequestObjectStart"/> or <see cref="RequestObjectByValueStart"/>.</param>
    /// <param name="host">The host serving the registration over the real wire.</param>
    /// <param name="client">The client SDK instance the start and callback are issued through.</param>
    /// <param name="registration">The registration identifying the authorization server to the client.</param>
    /// <param name="clientFlowStore">The client-local flow-state store the start writes the flow into.</param>
    /// <param name="material">The registration's request-object signing key material.</param>
    /// <param name="scope">The scope the request object names; blank names none.</param>
    /// <param name="resource">The RFC 8707 resource indicators the request object names, or <see langword="null"/> for none.</param>
    /// <returns>The flow identifier ready for the code redemption.</returns>
    private async Task<string> DriveRequestObjectStartAuthorizeAndCallbackAsync(
        string start,
        TestHostShell host,
        OAuthClient client,
        ClientRegistration registration,
        Dictionary<string, FlowState> clientFlowStore,
        VerifierKeyMaterial material,
        string scope,
        IReadOnlyList<string>? resource)
    {
        AuthCodeFlowEndpointResult startResult = await StartRequestObjectAsync(
            start, host, client, registration, material, scope, resource).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, startResult.Outcome,
            $"The request object start must redirect. ErrorCode={startResult.ErrorCode} ErrorDescription={startResult.ErrorDescription}");

        string flowId = clientFlowStore.Keys.Single();

        return await GetAuthorizeRedirectAndCallbackAsync(
            host.Host("default"), client, registration, host.ServerCertificate, startResult.RedirectUri!, flowId,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Starts an authorization request carrying a signed request object that names
    /// <paramref name="scope"/> and <paramref name="resource"/>, through
    /// <see cref="AuthCodeClient.StartJarParAsync(ClientRegistration, AuthCodeStartJarParOptions, CancellationToken)"/>
    /// for <see cref="PushedRequestObjectStart"/> or
    /// <see cref="AuthCodeClient.StartJarAuthorizeAsync(ClientRegistration, AuthCodeStartJarAuthorizeOptions, CancellationToken)"/>
    /// for <see cref="RequestObjectByValueStart"/>, signed with the registration's key and the host's
    /// own serializers, and returns the client's answer unasserted.
    /// </summary>
    /// <param name="start"><see cref="PushedRequestObjectStart"/> or <see cref="RequestObjectByValueStart"/>.</param>
    /// <param name="host">The host whose serializers encode the request object.</param>
    /// <param name="client">The client SDK instance the start is issued through.</param>
    /// <param name="registration">The registration identifying the authorization server to the client.</param>
    /// <param name="material">The registration's request-object signing key material.</param>
    /// <param name="scope">The scope the request object names; blank names none.</param>
    /// <param name="resource">The RFC 8707 resource indicators the request object names, or <see langword="null"/> for none.</param>
    /// <returns>The client's answer to the start.</returns>
    private async Task<AuthCodeFlowEndpointResult> StartRequestObjectAsync(
        string start,
        TestHostShell host,
        OAuthClient client,
        ClientRegistration registration,
        VerifierKeyMaterial material,
        string scope,
        IReadOnlyList<string>? resource)
    {
        JwtHeaderSerializer headerSerializer = host.Server.OAuth().Codecs.JwtHeaderSerializer!;
        JwtPayloadSerializer payloadSerializer = host.Server.OAuth().Codecs.JwtPayloadSerializer!;

        return start switch
        {
            PushedRequestObjectStart => await client.AuthCode.StartJarParAsync(
                registration,
                new AuthCodeStartJarParOptions
                {
                    Scope = scope,
                    Resource = resource,
                    SigningKey = material.SigningPrivateKey,
                    SigningKeyId = material.SigningKeyId.Value,
                    RedirectUri = RedirectUri,
                    HeaderSerializer = headerSerializer,
                    PayloadSerializer = payloadSerializer,
                    MemoryPool = BaseMemoryPool.Shared
                },
                TestContext.CancellationToken).ConfigureAwait(false),
            RequestObjectByValueStart => await client.AuthCode.StartJarAuthorizeAsync(
                registration,
                new AuthCodeStartJarAuthorizeOptions
                {
                    Scope = scope,
                    Resource = resource,
                    SigningKey = material.SigningPrivateKey,
                    SigningKeyId = material.SigningKeyId.Value,
                    RedirectUri = RedirectUri,
                    HeaderSerializer = headerSerializer,
                    PayloadSerializer = payloadSerializer,
                    MemoryPool = BaseMemoryPool.Shared
                },
                TestContext.CancellationToken).ConfigureAwait(false),
            _ => throw new ArgumentOutOfRangeException(nameof(start), start, "Unknown request object start.")
        };
    }


    /// <summary>
    /// Drives the client's authorization code flow automaton (<see cref="AuthCodeFlowAutomaton"/>)
    /// the way its caller does: the caller initiates the flow naming <paramref name="resource"/>,
    /// composes the pushed request and sends it over the real wire itself, feeds the automaton the
    /// pushed request's answer, drives the authorize leg over the real wire, feeds the automaton the
    /// code, and saves the resulting code-received state to the client's flow store. Returns the
    /// flow identifier ready for the client's code redemption.
    /// </summary>
    /// <param name="host">The host serving the registration over the real wire.</param>
    /// <param name="client">The client SDK instance whose flow store receives the code-received state.</param>
    /// <param name="registration">The registration identifying the authorization server to the client.</param>
    /// <param name="segment">The tenant path segment addressing this authorization server's endpoints.</param>
    /// <param name="resource">The RFC 8707 resource indicators the flow requests.</param>
    /// <returns>The flow identifier ready for the code redemption.</returns>
    private async Task<string> DriveAutomatonToCodeReceivedAsync(
        TestHostShell host,
        OAuthClient client,
        ClientRegistration registration,
        string segment,
        IReadOnlyList<string> resource)
    {
        CancellationToken cancellationToken = TestContext.CancellationToken;
        HostedAuthorizationServer hosted = host.Host("default");
        DateTimeOffset now = TimeProvider.GetUtcNow();
        string flowId = Guid.NewGuid().ToString("N");
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        Verifiable.Foundation.Automata.PushdownAutomaton<FlowState, FlowInput, AuthCodeStackSymbol> automaton =
            AuthCodeFlowAutomaton.Create(flowId, TimeProvider);
        Assert.IsTrue(await automaton.StepAsync(
            new Initiate(
                pkce,
                RedirectUri,
                [WellKnownScopes.OpenId],
                flowId,
                registration.AuthorizationServerIssuer.OriginalString,
                now,
                now.AddMinutes(5))
            {
                Resource = [.. resource]
            },
            cancellationToken).ConfigureAwait(false), "The automaton must accept the initiation.");

        List<KeyValuePair<string, string>> parFields =
        [
            new(OAuthRequestParameterNames.ClientId, ClientId),
            new(OAuthRequestParameterNames.ResponseType, WellKnownResponseTypes.Code),
            new(OAuthRequestParameterNames.RedirectUri, RedirectUri.OriginalString),
            new(OAuthRequestParameterNames.Scope, WellKnownScopes.OpenId),
            new(OAuthRequestParameterNames.State, flowId),
            new(OAuthRequestParameterNames.CodeChallenge, pkce.EncodedChallenge),
            new(OAuthRequestParameterNames.CodeChallengeMethod, WellKnownCodeChallengeMethods.S256),
            .. resource.Select(static indicator => new KeyValuePair<string, string>(OAuthRequestParameterNames.Resource, indicator))
        ];
        string encodedBody = string.Join('&', parFields.Select(static field =>
            $"{Uri.EscapeDataString(field.Key)}={Uri.EscapeDataString(field.Value)}"));
        Assert.IsTrue(await automaton.StepAsync(new ParBodyComposed(encodedBody, now), cancellationToken).ConfigureAwait(false),
            "The automaton must accept the composed pushed request.");

        HttpResponseData parResponse = await RawAuthCodeWirePushers.PushRawParRequestAsync(
            hosted, segment, parFields, OutgoingHeaders.Empty, cancellationToken).ConfigureAwait(false);
        Result<ParResponse, OAuthParseError> parResult = client.Infrastructure.ParseParResponseAsync(parResponse);
        Assert.IsTrue(parResult.IsSuccess,
            $"The pushed request must succeed over the real wire. Status={parResponse.StatusCode} Body={parResponse.Body}");
        Assert.IsTrue(await automaton.StepAsync(new ParSucceeded(parResult.Value, now), cancellationToken).ConfigureAwait(false),
            "The automaton must accept the pushed request's answer.");

        Uri authorizeUrl = new(
            hosted.HttpBaseAddress!,
            $"{TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment)}" +
            $"?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(ClientId)}" +
            $"&{OAuthRequestParameterNames.RequestUri}={Uri.EscapeDataString(parResult.Value.RequestUri.ToString())}");
        using HttpResponseMessage authorizeResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, authorizeUrl, SubjectId, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, (int)authorizeResponse.StatusCode,
            "The authorize endpoint must redirect with the authorization code.");

        string location = authorizeResponse.Headers.Location!.ToString();
        string code = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Code)
            ?? throw new InvalidOperationException("Authorize redirect Location missing code.");
        string returnedState = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.State)
            ?? throw new InvalidOperationException("Authorize redirect Location missing state.");
        //Under this policy the authorization response carries no iss; the input carries the value
        //received, empty when there is none.
        string issuer = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Iss) ?? string.Empty;
        Assert.IsTrue(await automaton.StepAsync(new CodeReceived(code, returnedState, issuer, now), cancellationToken).ConfigureAwait(false),
            "The automaton must accept the authorization code.");

        AuthorizationCodeReceivedState codeState = Assert.IsInstanceOfType<AuthorizationCodeReceivedState>(automaton.CurrentState);
        await client.Infrastructure.SaveStateAsync(codeState, [], cancellationToken).ConfigureAwait(false);

        return flowId;
    }


    /// <summary>
    /// Decodes the payload segment of a compact JWS off the real wire, byte-for-byte — no
    /// production deserializer in the loop, so the assertion reflects exactly what was sent.
    /// </summary>
    private static JsonDocument DecodePayload(string compactJws)
    {
        string[] segments = compactJws.Split('.');
        Assert.HasCount(3, segments);
        byte[] payloadBytes = SecurityEventTestJson.DecodeSegment(segments[1], BaseMemoryPool.Shared);

        return JsonDocument.Parse(payloadBytes);
    }


    /// <summary>
    /// Drives a raw-wire PAR carrying <paramref name="codeChallenge"/> /
    /// <paramref name="codeChallengeMethod"/> and the browser's authorize GET, returning the
    /// extracted authorization code — the wire shape <see cref="AuthCodeFlowDriver"/> and
    /// <see cref="OAuthClient"/> cannot produce since the client abstraction always generates an
    /// S256 challenge of its own. An optional <paramref name="resource"/>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 §2.1</see>) or
    /// <paramref name="authorizationDetails"/>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9396#section-5">RFC 9396 §5</see>) rides the
    /// pushed request, establishing the granted set a later token-request value is compared
    /// against.
    /// </summary>
    private static async Task<string> DriveRawParAndAuthorizeAsync(
        TestHostShell host, string segment, string codeChallenge, string codeChallengeMethod,
        CancellationToken cancellationToken, string? resource = null, string? authorizationDetails = null)
    {
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = codeChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = codeChallengeMethod,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        if(resource is not null)
        {
            parFields[OAuthRequestParameterNames.Resource] = resource;
        }

        if(authorizationDetails is not null)
        {
            parFields[OAuthRequestParameterNames.AuthorizationDetails] = authorizationDetails;
        }

        (int parStatusCode, string parBody, Uri? authorizeLocation, int authorizeStatusCode) =
            await RawAuthCodeWirePushers.PushParAndAuthorizeAsync(
                host, segment, ClientId, SubjectId, parFields, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parStatusCode, parBody);
        Assert.AreEqual(302, authorizeStatusCode,
            "The authorize endpoint must redirect with the authorization code.");

        string location = authorizeLocation!.ToString();

        return TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Code)
            ?? throw new InvalidOperationException("Authorize redirect Location missing code.");
    }


    /// <summary>
    /// Issues a bearer access/refresh pair through the shared PAR, authorize and token pushers.
    /// Keeps adversarial refresh tests on the listener while using a fresh S256 authorization.
    /// </summary>
    private async Task<(string RefreshToken, string AccessToken)> IssueBearerPairAsync(TestHostShell host, string segment)
    {
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);
        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, StatusCode, Body);
        using JsonDocument document = JsonDocument.Parse(Body);

        return (document.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!,
            document.RootElement.GetProperty(OAuthRequestParameterNames.AccessToken).GetString()!);
    }


    /// <summary>
    /// Rotates one refresh token over the listener and returns the new access/refresh pair.
    /// An unsuccessful setup fails immediately so later assertions measure the reuse scenario.
    /// </summary>
    private async Task<(string RefreshToken, string AccessToken)> RotateBearerPairAsync(
        TestHostShell host, string segment, string refreshToken)
    {
        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, refreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, StatusCode, Body);
        using JsonDocument document = JsonDocument.Parse(Body);

        return (document.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!,
            document.RootElement.GetProperty(OAuthRequestParameterNames.AccessToken).GetString()!);
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>: "it will revoke the active refresh token as well as the access
    /// authorization grant associated with it." Reusing a rotated successor also revokes the
    /// access token paired with that successor, whose audit is on its predecessor's record.
    /// </summary>
    [TestMethod]
    public async Task ReuseRevokesTheAccessTokenPairedWithARotatedRefreshToken()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        (string original, _) = await IssueBearerPairAsync(host, segment).ConfigureAwait(false);
        (string reused, string pairedAccessToken) = await RotateBearerPairAsync(host, segment, original).ConfigureAwait(false);
        _ = await RotateBearerPairAsync(host, segment, reused).ConfigureAwait(false);
        HashSet<string> revokedJtis = [];
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.RevokeIssuedTokenAsync = (jti, _, _, _, _) =>
            {
                _ = revokedJtis.Add(jti);

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, reused),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains(JwtPayloadReader.ReadJti(pairedAccessToken), revokedJtis,
            "The predecessor audit must revoke the access token paired with the reused refresh token.");
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>: "it will revoke the active refresh token as well as the access
    /// authorization grant associated with it." A reuse of the family's THIRD generation refresh
    /// token — not its oldest — must still reach and revoke every access token of the grant,
    /// including the one issued alongside the authorization code itself.
    /// </summary>
    [TestMethod]
    public async Task ReuseOfAThirdGenerationRefreshTokenRevokesTheWholeGrantAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        (string firstGenerationRefreshToken, string codeGrantAccessToken) =
            await IssueBearerPairAsync(host, segment).ConfigureAwait(false);
        (string secondGenerationRefreshToken, string firstRotationAccessToken) =
            await RotateBearerPairAsync(host, segment, firstGenerationRefreshToken).ConfigureAwait(false);
        (string thirdGenerationRefreshToken, string secondRotationAccessToken) =
            await RotateBearerPairAsync(host, segment, secondGenerationRefreshToken).ConfigureAwait(false);
        (string fourthGenerationRefreshToken, string thirdRotationAccessToken) =
            await RotateBearerPairAsync(host, segment, thirdGenerationRefreshToken).ConfigureAwait(false);

        HashSet<string> revokedJtis = [];
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.RevokeIssuedTokenAsync = (jti, _, _, _, _) =>
            {
                _ = revokedJtis.Add(jti);

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        (int ReuseStatusCode, string ReuseBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, thirdGenerationRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, ReuseStatusCode, ReuseBody);
        Assert.Contains(OAuthErrors.InvalidGrant, ReuseBody, StringComparison.Ordinal);

        HashSet<string?> expectedRevokedJtis =
        [
            JwtPayloadReader.ReadJti(codeGrantAccessToken),
            JwtPayloadReader.ReadJti(firstRotationAccessToken),
            JwtPayloadReader.ReadJti(secondRotationAccessToken),
            JwtPayloadReader.ReadJti(thirdRotationAccessToken)
        ];
        Assert.IsTrue(expectedRevokedJtis.SetEquals(revokedJtis),
            $"Expected exactly {{{string.Join(",", expectedRevokedJtis)}}} revoked; got {{{string.Join(",", revokedJtis)}}}.");

        (int NewestAfterReuseStatusCode, _) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, fourthGenerationRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, NewestAfterReuseStatusCode,
            "The grant's newest refresh token must be refused once an earlier generation is reused.");
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>'s revocation of "the access authorization grant" does not depend on
    /// every intermediate retired record still being retained: a reuse must still reach and
    /// revoke the grant's live refresh token and its paired access token even when one retired
    /// record between the presented token and the live one is missing.
    /// </summary>
    [TestMethod]
    public async Task ReuseWithAMissingIntermediateRetiredRecordStillRevokesTheLiveSuccessorAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        (string firstGenerationRefreshToken, _) =
            await IssueBearerPairAsync(host, segment).ConfigureAwait(false);
        (string secondGenerationRefreshToken, _) =
            await RotateBearerPairAsync(host, segment, firstGenerationRefreshToken).ConfigureAwait(false);
        (string thirdGenerationRefreshToken, _) =
            await RotateBearerPairAsync(host, segment, secondGenerationRefreshToken).ConfigureAwait(false);
        (string liveRefreshToken, string accessTokenPairedWithLiveRefreshToken) =
            await RotateBearerPairAsync(host, segment, thirdGenerationRefreshToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        string missingIntermediateFlowId = hosted.RefreshTokenIndex[secondGenerationRefreshToken];
        Assert.IsTrue(hosted.FlowStates.TryRemove(missingIntermediateFlowId, out _),
            "The intermediate record between the presented token and the live one must exist before removal.");

        HashSet<string> revokedJtis = [];
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.RevokeIssuedTokenAsync = (jti, _, _, _, _) =>
            {
                _ = revokedJtis.Add(jti);

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        (int ReuseStatusCode, string ReuseBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, firstGenerationRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, ReuseStatusCode, ReuseBody);
        Assert.Contains(OAuthErrors.InvalidGrant, ReuseBody, StringComparison.Ordinal);

        Assert.Contains(JwtPayloadReader.ReadJti(accessTokenPairedWithLiveRefreshToken), revokedJtis,
            "The access token paired with the grant's live refresh token must be revoked even when a retired record between the presented token and the live one is missing.");

        (int LiveAfterReuseStatusCode, _) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, liveRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, LiveAfterReuseStatusCode,
            "The grant's live refresh token must be refused once an earlier generation is reused, even with a missing intermediate record.");
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>'s grant revocation is scoped to the presented grant's own client: a
    /// foreign record the grant read returns under the same grant key but a DIFFERENT
    /// <c>ClientId</c> is neither claimed nor deleted, while the grant's own records still are.
    /// </summary>
    [TestMethod]
    public async Task ForeignRecordUnderTheSameGrantKeyIsNeitherClaimedNorDeletedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        (string firstGenerationRefreshToken, string codeGrantAccessToken) =
            await IssueBearerPairAsync(host, segment).ConfigureAwait(false);
        (string liveRefreshToken, _) =
            await RotateBearerPairAsync(host, segment, firstGenerationRefreshToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        string retiredFlowId = hosted.RefreshTokenIndex[firstGenerationRefreshToken];
        string grantFlowId = ((ServerTokenIssuedState)hosted.FlowStates[retiredFlowId].State).GrantFlowId!;

        string foreignFlowId = $"foreign-{Guid.NewGuid():N}";
        ServerRefreshTokenIssuedState foreignRecord = new()
        {
            FlowId = foreignFlowId,
            GrantFlowId = grantFlowId,
            ExpectedIssuer = "https://foreign.example",
            EnteredAt = TimeProvider.GetUtcNow(),
            ExpiresAt = TimeProvider.GetUtcNow().AddHours(1),
            Kind = FlowKind.AuthCodeServer,
            ClientId = "foreign-client-under-the-same-grant-key",
            RefreshToken = $"foreign-refresh-{Guid.NewGuid():N}",
            OriginatingGrantType = WellKnownGrantTypes.AuthorizationCode,
            IssuedAt = TimeProvider.GetUtcNow(),
            SubjectId = "foreign-subject",
            Scope = WellKnownScopes.OpenId
        };
        hosted.InjectForeignGrantRecord(grantFlowId, foreignFlowId, foreignRecord, stepCount: 0);

        HashSet<string> revokedJtis = [];
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.RevokeIssuedTokenAsync = (jti, _, _, _, _) =>
            {
                _ = revokedJtis.Add(jti);

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        (int ReuseStatusCode, string ReuseBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, firstGenerationRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, ReuseStatusCode, ReuseBody);
        Assert.Contains(OAuthErrors.InvalidGrant, ReuseBody, StringComparison.Ordinal);

        Assert.Contains(JwtPayloadReader.ReadJti(codeGrantAccessToken), revokedJtis,
            "The grant's own access token must still be revoked.");
        Assert.IsTrue(hosted.FlowStates.TryGetValue(foreignFlowId, out var foreignEntry),
            "A foreign record under the same grant key must never be deleted.");
        Assert.AreEqual(foreignRecord, foreignEntry.State,
            "A foreign record under the same grant key must be left byte-for-byte untouched.");
        Assert.IsFalse(hosted.ClaimedFlowSteps.ContainsKey((foreignFlowId, 0)),
            "A foreign record under the same grant key must never be claimed.");

        (int LiveAfterReuseStatusCode, _) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, liveRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, LiveAfterReuseStatusCode,
            "The grant's own live refresh token must still be refused once an earlier generation is reused.");
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>'s
    /// revocation reads every record of a grant once, regardless of how many times it has
    /// rotated: a reuse after two rotations, a reuse after five, and a replay of the code after
    /// five rotations each cost exactly one grant read and one plain flow-state load.
    /// </summary>
    [TestMethod]
    public async Task GrantRevocationCostsExactlyOneGrantReadPerPresentationRegardlessOfRotationCountAsync()
    {
        async Task<(int GrantReads, int PlainLoads)> MeasureReuseCostsAsync(int rotationCount)
        {
            await using TestHostShell reuseHost = new(TimeProvider);
            using VerifierKeyMaterial reuseMaterial = await reuseHost.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
            string reuseSegment = reuseMaterial.Registration.TenantId.Value;

            (string presentedRefreshToken, _) = await IssueBearerPairAsync(reuseHost, reuseSegment).ConfigureAwait(false);
            string nextRefreshToken = presentedRefreshToken;
            for(int rotation = 0; rotation < rotationCount; rotation++)
            {
                (nextRefreshToken, _) = await RotateBearerPairAsync(reuseHost, reuseSegment, nextRefreshToken).ConfigureAwait(false);
            }

            int grantReads = 0;
            int plainLoads = 0;
            LoadGrantFlowStatesDelegate originalGrantRead = reuseHost.Server.OAuth().LoadGrantFlowStatesAsync!;
            LoadServerFlowStateDelegate originalLoad = reuseHost.Server.OAuth().LoadFlowStateAsync!;
            await TestHostShell.AlterAsync(reuseHost.Server, candidateIntegration =>
            {
                candidateIntegration.LoadGrantFlowStatesAsync = (tenantId, grantFlowId, ctx, ct) =>
                {
                    ++grantReads;

                    return originalGrantRead(tenantId, grantFlowId, ctx, ct);
                };
                candidateIntegration.LoadFlowStateAsync = (tenantId, key, ctx, ct) =>
                {
                    ++plainLoads;

                    return originalLoad(tenantId, key, ctx, ct);
                };
            }).ConfigureAwait(false);

            (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                reuseHost, reuseSegment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, presentedRefreshToken),
                TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, StatusCode, Body);

            return (grantReads, plainLoads);
        }

        (int GrantReadsAfterTwo, int PlainLoadsAfterTwo) = await MeasureReuseCostsAsync(2).ConfigureAwait(false);
        Assert.AreEqual(1, GrantReadsAfterTwo, "A reuse after two rotations must read the grant exactly once.");
        Assert.AreEqual(1, PlainLoadsAfterTwo,
            "A reuse after two rotations must plain-load a flow state exactly once (the dispatcher's own).");

        (int GrantReadsAfterFive, int PlainLoadsAfterFive) = await MeasureReuseCostsAsync(5).ConfigureAwait(false);
        Assert.AreEqual(1, GrantReadsAfterFive, "A reuse after five rotations must still read the grant exactly once.");
        Assert.AreEqual(1, PlainLoadsAfterFive,
            "A reuse after five rotations must still plain-load a flow state exactly once.");

        await using TestHostShell replayHost = new(TimeProvider);
        using VerifierKeyMaterial replayMaterial = await replayHost.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string replaySegment = replayMaterial.Registration.TenantId.Value;

        PkceParameters replayPkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string replayCode = await DriveRawParAndAuthorizeAsync(
            replayHost, replaySegment, replayPkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);
        Dictionary<string, string> replayTokenFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, replayCode, replayPkce.EncodedVerifier, RedirectUri.OriginalString);
        (int FirstStatusCode, string FirstBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            replayHost, replaySegment, replayTokenFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, FirstStatusCode, FirstBody);
        using(JsonDocument firstDocument = JsonDocument.Parse(FirstBody))
        {
            string replayNextRefreshToken = firstDocument.RootElement.GetProperty(
                OAuthRequestParameterNames.RefreshToken).GetString()!;
            for(int rotation = 0; rotation < 5; rotation++)
            {
                (replayNextRefreshToken, _) = await RotateBearerPairAsync(
                    replayHost, replaySegment, replayNextRefreshToken).ConfigureAwait(false);
            }
        }

        int replayGrantReads = 0;
        int replayPlainLoads = 0;
        LoadGrantFlowStatesDelegate originalReplayGrantRead = replayHost.Server.OAuth().LoadGrantFlowStatesAsync!;
        LoadServerFlowStateDelegate originalReplayLoad = replayHost.Server.OAuth().LoadFlowStateAsync!;
        await TestHostShell.AlterAsync(replayHost.Server, candidateIntegration =>
        {
            candidateIntegration.LoadGrantFlowStatesAsync = (tenantId, grantFlowId, ctx, ct) =>
            {
                ++replayGrantReads;

                return originalReplayGrantRead(tenantId, grantFlowId, ctx, ct);
            };
            candidateIntegration.LoadFlowStateAsync = (tenantId, key, ctx, ct) =>
            {
                ++replayPlainLoads;

                return originalReplayLoad(tenantId, key, ctx, ct);
            };
        }).ConfigureAwait(false);

        (int ReplayStatusCode, string ReplayBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            replayHost, replaySegment, replayTokenFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, ReplayStatusCode, ReplayBody);
        Assert.AreEqual(1, replayGrantReads, "A code replay after five rotations must read the grant exactly once.");
        Assert.AreEqual(1, replayPlainLoads,
            "A code replay after five rotations must still plain-load a flow state exactly once.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-4.3.1">OAuth 2.1 §4.3.1</see>
    /// describes refresh-token replay detection. The library's persisted marker makes a second
    /// sequential valid refresh reuse refuse without repeating family loads or audit revocations.
    /// </summary>
    [TestMethod]
    public async Task SecondValidRefreshReuseDoesNotRepeatRevocationAndTheMarkerPersists()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        (string original, _) = await IssueBearerPairAsync(host, segment).ConfigureAwait(false);
        _ = await RotateBearerPairAsync(host, segment, original).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string retiredFlowId = hosted.RefreshTokenIndex[original];
        int revocationCalls = 0;
        int grantReads = 0;
        LoadGrantFlowStatesDelegate originalLoadGrant = host.Server.OAuth().LoadGrantFlowStatesAsync!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.LoadGrantFlowStatesAsync = (tenantId, grantFlowId, ctx, ct) =>
            {
                ++grantReads;

                return originalLoadGrant(tenantId, grantFlowId, ctx, ct);
            };

            candidateIntegration.RevokeIssuedTokenAsync = (_, _, _, _, _) =>
            {
                ++revocationCalls;

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);
        Dictionary<string, string> fields = RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, original);
        (int StatusCode, string Body) first = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, fields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, first.StatusCode, first.Body);
        ServerTokenIssuedState retired = (ServerTokenIssuedState)hosted.FlowStates[retiredFlowId].State;
        Assert.IsNotNull(retired.RevokedAt, "A valid refresh reuse must persist RevokedAt.");
        int callsAfterFirst = revocationCalls;
        int grantReadsAfterFirst = grantReads;
        Assert.IsGreaterThan(0, callsAfterFirst);
        Assert.IsGreaterThan(0, grantReadsAfterFirst);

        (int StatusCode, string Body) second = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, fields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(first, second, "Sequential reuse must keep the same refusal response.");
        Assert.AreEqual(callsAfterFirst, revocationCalls, "Sequential reuse must not repeat audit revocation.");
        Assert.AreEqual(grantReadsAfterFirst, grantReads, "Sequential reuse must not repeat the grant read.");
        Assert.AreEqual(retired.RevokedAt,
            ((ServerTokenIssuedState)hosted.FlowStates[retiredFlowId].State).RevokedAt);
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>'s client-identification rule requires a matching client_id when
    /// credentials are absent. A public client's unidentified live refresh is refused without
    /// consuming the token.
    /// </summary>
    [TestMethod]
    public async Task LiveRefreshWithoutCredentialsOrClientIdIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        (string original, _) = await IssueBearerPairAsync(host, segment).ConfigureAwait(false);
        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(null, original),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, StatusCode, "A public refresh must identify its bound client.");
        _ = await RotateBearerPairAsync(host, segment, original).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>'s active-token revocation requires ownership of the loaded live
    /// record. Repeated lost claims terminate without deleting any unclaimed refresh state, and
    /// — because that walk did NOT reach a terminal outcome — without persisting
    /// <see cref="ServerTokenIssuedState.RevokedAt"/> on the presented token either: a second
    /// presentation of the SAME retired token, once the claim seam recovers, re-runs the walk and
    /// this time reaches and revokes the family's current successor.
    /// </summary>
    [TestMethod]
    public async Task ReuseWithRepeatedLostClaimsDoesNotDeleteUnclaimedState()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        (string original, _) = await IssueBearerPairAsync(host, segment).ConfigureAwait(false);
        (string successor, _) = await RotateBearerPairAsync(host, segment, original).ConfigureAwait(false);
        var originalClaim = host.Server.OAuth().ClaimFlowStateAsync;
        int claimCalls = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ClaimFlowStateAsync = (_, _, _, _, _) =>
            {
                if(++claimCalls > 2)
                {
                    throw new InvalidOperationException("A family walk must stop after its bounded claim retry.");
                }

                return ValueTask.FromResult(false);
            };
        }).ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, original),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, StatusCode, "Lost claims must produce a bounded refusal without deleting state.");
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ClaimFlowStateAsync = originalClaim;
        }).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        string originalFlowId = hosted.RefreshTokenIndex[original];
        Assert.IsNull(((ServerTokenIssuedState)hosted.FlowStates[originalFlowId].State).RevokedAt,
            "An incomplete walk must not persist RevokedAt on the presented token.");

        //The claim seam has recovered: presenting the SAME retired token again re-runs the walk,
        //which this time reaches and revokes the family's current successor — proving the earlier
        //400 did not silently and permanently spare the family.
        (int StatusCode, string Body) retryReuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, original),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, retryReuse.StatusCode, "The re-run reuse must still refuse the retired token.");
        Assert.IsNotNull(((ServerTokenIssuedState)hosted.FlowStates[originalFlowId].State).RevokedAt,
            "A completed walk must persist RevokedAt on the presented token.");

        (int StatusCode, string Body) successorAfterCompletedWalk = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, successor),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, successorAfterCompletedWalk.StatusCode,
            "The family's current successor must be refused once the walk completes.");
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>: "it will revoke the active refresh token as well as the access
    /// authorization grant associated with it." A corrupted <see cref="ServerTokenIssuedState.SuccessorRefreshFlowId"/>
    /// on a retired record of the grant — one pointing at itself — has no effect on revoking the
    /// grant, because the one grant read returns every retained record sharing the grant's key
    /// and the library never follows a link from one record to another.
    /// </summary>
    [TestMethod]
    public async Task CorruptedSuccessorRefreshFlowIdHasNoEffectOnGrantRevocationAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        (string original, string codeGrantAccessToken) = await IssueBearerPairAsync(host, segment).ConfigureAwait(false);
        (string middle, string middleAccessToken) = await RotateBearerPairAsync(host, segment, original).ConfigureAwait(false);
        (string current, string currentAccessToken) = await RotateBearerPairAsync(host, segment, middle).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string middleFlowId = hosted.RefreshTokenIndex[middle];
        (FlowState state, int stepCount) = hosted.FlowStates[middleFlowId];
        hosted.FlowStates[middleFlowId] = (((ServerTokenIssuedState)state) with
        {
            SuccessorRefreshFlowId = middleFlowId
        }, stepCount);
        HashSet<string> revokedJtis = [];
        int revocationCalls = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.RevokeIssuedTokenAsync = (jti, _, _, _, _) =>
            {
                if(++revocationCalls > 20)
                {
                    throw new InvalidOperationException("A self-referencing link must not cause repeated audit revocations.");
                }

                _ = revokedJtis.Add(jti);

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, original),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, StatusCode, "The self-referencing link must not prevent the reuse refusal.");
        Assert.Contains(JwtPayloadReader.ReadJti(codeGrantAccessToken), revokedJtis,
            "Every access token of the grant must be handed to the revocation seam.");
        Assert.Contains(JwtPayloadReader.ReadJti(middleAccessToken), revokedJtis,
            "Every access token of the grant must be handed to the revocation seam.");
        Assert.Contains(JwtPayloadReader.ReadJti(currentAccessToken), revokedJtis,
            "Every access token of the grant must be handed to the revocation seam.");

        (int NewestAfterReuseStatusCode, _) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, current),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, NewestAfterReuseStatusCode,
            "The grant's newest refresh token must be refused once an earlier generation is reused.");
    }


    /// <summary>
    /// Drives PAR (a real wire POST), the browser's authorize GET (a real wire GET with auto-redirect
    /// disabled and the test subject header standing in for an authenticated session), and the
    /// callback (a client-local state transition over the extracted <c>code</c>/<c>state</c>/<c>iss</c>).
    /// Returns the flow identifier ready for token exchange.
    /// </summary>
    /// <param name="hosted">The hosted authorization server the real wire calls reach.</param>
    /// <param name="client">The client SDK instance the PAR and callback calls are issued through.</param>
    /// <param name="registration">The registration identifying the authorization server to the client.</param>
    /// <param name="clientFlowStore">The client-local flow-state store PAR writes the started flow into.</param>
    /// <param name="segment">The tenant path segment addressing this authorization server's endpoints.</param>
    /// <param name="pinnedCertificate">The server's certificate the real wire calls pin against.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="resource">
    /// The RFC 8707 §2 <c>resource</c> indicator(s) to request through the CLIENT abstraction
    /// (<see cref="AuthCodeClient.StartParAsync(ClientRegistration, Uri, OAuthFormEncodedFields, ExchangeContext, IReadOnlyList{string}?, CancellationToken)"/>),
    /// which threads each entry to the wire as its OWN repeated <c>resource</c> occurrence — the
    /// genuine RFC 8707 §2 multi-resource wire form, never several indicators joined by a space
    /// into one occurrence. <see langword="null"/> omits the parameter entirely.
    /// </param>
    /// <param name="fields">
    /// The fields the caller hands the pushed start, among them the <c>scope</c> it names;
    /// <see langword="null"/> names <c>openid</c> through
    /// <see cref="OAuthFormEncodedFieldsFixtures.OpenIdScope"/>, the scope the journeys driven through
    /// this helper request.
    /// </param>
    private static async Task<string> DriveParAuthorizeAndCallbackAsync(
        HostedAuthorizationServer hosted,
        OAuthClient client,
        ClientRegistration registration,
        Dictionary<string, FlowState> clientFlowStore,
        string segment,
        X509Certificate2 pinnedCertificate,
        CancellationToken cancellationToken,
        IReadOnlyList<string>? resource = null,
        OAuthFormEncodedFields? fields = null)
    {
        AuthCodeFlowEndpointResult parResult = await client.AuthCode.StartParAsync(
            registration, RedirectUri, fields ?? OAuthFormEncodedFieldsFixtures.OpenIdScope,
            [], resource, cancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"PAR must redirect over the real wire. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        string flowId = clientFlowStore.Keys.Single();
        ParCompletedState parState = (ParCompletedState)clientFlowStore[flowId];

        return await AuthorizeAndCallbackAsync(
            hosted, client, registration, segment, pinnedCertificate, flowId, parState, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Drives the browser's authorize GET (a real wire GET with auto-redirect disabled and the test
    /// subject header standing in for an authenticated session) and the callback (a client-local
    /// state transition over the extracted <c>code</c>/<c>state</c>/<c>iss</c>) for an
    /// already-completed PAR. Called by <see cref="DriveParAuthorizeAndCallbackAsync"/> after PAR
    /// completes, single- and multi-resource alike. Returns the flow identifier ready for token
    /// exchange.
    /// </summary>
    private static async Task<string> AuthorizeAndCallbackAsync(
        HostedAuthorizationServer hosted,
        OAuthClient client,
        ClientRegistration registration,
        string segment,
        X509Certificate2 pinnedCertificate,
        string flowId,
        ParCompletedState parState,
        CancellationToken cancellationToken)
    {
        await client.Infrastructure.SaveStateAsync(parState, [], cancellationToken)
            .ConfigureAwait(false);

        Uri authorizeUrl = new(
            hosted.HttpBaseAddress!,
            $"{TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment)}" +
            $"?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(ClientId)}" +
            $"&{OAuthRequestParameterNames.RequestUri}={Uri.EscapeDataString(parState.Par.RequestUri.ToString())}");

        return await GetAuthorizeRedirectAndCallbackAsync(
            hosted, client, registration, pinnedCertificate, authorizeUrl, flowId, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Drives the browser's authorize GET against <paramref name="authorizeUrl"/> (a real wire GET
    /// with auto-redirect disabled and the test subject header standing in for an authenticated
    /// session) and the callback (a client-local state transition over the extracted
    /// <c>code</c>/<c>state</c>/<c>iss</c>). Shared by <see cref="AuthorizeAndCallbackAsync"/>'s
    /// PAR-style <c>request_uri</c> redirect and a plain start's fully composed redirect
    /// alike — both land here once the URL to GET is known. Returns the flow identifier ready for
    /// token exchange.
    /// </summary>
    private static async Task<string> GetAuthorizeRedirectAndCallbackAsync(
        HostedAuthorizationServer hosted,
        OAuthClient client,
        ClientRegistration registration,
        X509Certificate2 pinnedCertificate,
        Uri authorizeUrl,
        string flowId,
        CancellationToken cancellationToken)
    {
        //A fresh pinned, no-redirect client for the browser leg: the same certificate the shell's
        //SharedHttpClient pins, so this genuine HTTPS GET succeeds without trusting a CA, and with
        //auto-redirect disabled so the 302 Location is read off the wire instead of being followed.
        using SocketsHttpHandler noRedirectHandler = LoopbackTls.CreatePinnedHandler(pinnedCertificate);
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


    /// <summary>
    /// Drives a plain authorization start through
    /// <see cref="AuthCodeClient.StartAsync(ClientRegistration, Uri, OAuthFormEncodedFields, ExchangeContext, IReadOnlyList{string}?, TimeSpan, CancellationToken)"/>
    /// with <paramref name="fields"/>, then the browser's authorize GET of the redirect the client
    /// composes and the callback (<see cref="GetAuthorizeRedirectAndCallbackAsync"/>). Returns the
    /// flow identifier ready for token exchange.
    /// </summary>
    /// <param name="hosted">The hosted authorization server the real wire calls reach.</param>
    /// <param name="client">The client SDK instance the start and callback calls are issued through.</param>
    /// <param name="registration">The registration identifying the authorization server to the client.</param>
    /// <param name="clientFlowStore">The client-local flow-state store the start writes the flow into.</param>
    /// <param name="pinnedCertificate">The server's certificate the real wire calls pin against.</param>
    /// <param name="fields">The fields the caller hands the start, among them any <c>scope</c> it names.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="resource">
    /// The RFC 8707 §2 <c>resource</c> indicator(s) the start requests, each its own occurrence on the
    /// authorization redirect's query; <see langword="null"/> requests none.
    /// </param>
    private static async Task<string> DriveDirectStartAuthorizeAndCallbackAsync(
        HostedAuthorizationServer hosted,
        OAuthClient client,
        ClientRegistration registration,
        Dictionary<string, FlowState> clientFlowStore,
        X509Certificate2 pinnedCertificate,
        OAuthFormEncodedFields fields,
        CancellationToken cancellationToken,
        IReadOnlyList<string>? resource = null)
    {
        AuthCodeFlowEndpointResult startResult = await client.AuthCode.StartAsync(
            registration, RedirectUri, fields, [], resource,
            requestLifetime: TimeSpan.FromMinutes(5), cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, startResult.Outcome,
            $"A plain start must redirect. ErrorCode={startResult.ErrorCode} ErrorDescription={startResult.ErrorDescription}");

        string flowId = clientFlowStore.Keys.Single();

        return await GetAuthorizeRedirectAndCallbackAsync(
            hosted, client, registration, pinnedCertificate, startResult.RedirectUri!, flowId, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Wires the host's issuer resolution, which the authorization-code endpoints consult for every
    /// request they accept, to record that request's parameters exactly as the HTTP skin decoded them
    /// off the real wire, and then to answer the registration's own
    /// <see cref="ClientRecord.IssuerUri"/>, the value the default resolver answers. A request whose
    /// handling resolves the issuer more than once is recorded once, by the identity of its decoded
    /// parameters. An assertion over the recorded parameters therefore observes what the client's
    /// request carried on the wire.
    /// </summary>
    /// <param name="host">The host whose authorization server records the requests it accepts.</param>
    /// <returns>The parameters of every accepted request, each once, in arrival order.</returns>
    private static async Task<ConcurrentQueue<RequestFields>> RecordAcceptedRequestFieldsAsync(TestHostShell host)
    {
        ConcurrentQueue<RequestFields> accepted = new();
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveIssuerAsync = (registration, context, _) =>
            {
                if(context.IncomingRequest is { } request
                    && !accepted.Any(recorded => ReferenceEquals(recorded, request.Fields)))
                {
                    accepted.Enqueue(request.Fields);
                }

                return ValueTask.FromResult<Uri?>(((ClientRecord)registration).IssuerUri);
            };
        }).ConfigureAwait(false);

        return accepted;
    }


    /// <summary>
    /// Registers a client under <see cref="PolicyProfile.Rfc6749WithPkce"/>, a policy that requires no
    /// <c>scope</c> on the request, starts an authorization request through the client with
    /// <paramref name="fields"/> by the start <paramref name="start"/> names (<see cref="PushedStart"/>
    /// or <see cref="DirectStart"/>), and drives it over the real wire through the authorize leg to an
    /// authorization code accepted at the callback. Returns the authorization request's parameters as
    /// the server received them: the pushed body, or the authorize query of a direct start.
    /// </summary>
    /// <param name="start">Which start carries the request: <see cref="PushedStart"/> or <see cref="DirectStart"/>.</param>
    /// <param name="fields">The fields the caller hands the start, among them any <c>scope</c> it names.</param>
    /// <returns>The authorization request's parameters as the server received them.</returns>
    private async Task<RequestFields> DriveStartToCallbackAndReadReceivedRequestAsync(string start, OAuthFormEncodedFields fields)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: Capabilities.Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization)).ConfigureAwait(false);
        ConcurrentQueue<RequestFields> accepted = await RecordAcceptedRequestFieldsAsync(host).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        _ = start switch
        {
            PushedStart => await DriveParAuthorizeAndCallbackAsync(
                hosted, client, registration, clientFlowStore, segment, host.ServerCertificate,
                TestContext.CancellationToken, fields: fields).ConfigureAwait(false),
            DirectStart => await DriveDirectStartAuthorizeAndCallbackAsync(
                hosted, client, registration, clientFlowStore, host.ServerCertificate, fields,
                TestContext.CancellationToken).ConfigureAwait(false),
            _ => throw new ArgumentOutOfRangeException(nameof(start), start, "Unknown authorization request start.")
        };

        //The authorization request is the one accepted request that carries the PKCE challenge:
        //the pushed body of a pushed start, the authorize query of a direct start. The request_uri
        //completion of a pushed start carries only client_id and request_uri.
        return accepted.Single(received => received.ContainsKey(OAuthRequestParameterNames.CodeChallenge));
    }


    /// <summary>
    /// Observes a wire request's response or exception under runner cancellation so racing requests
    /// can both finish before an assertion reports their complete outcomes.
    /// </summary>
    private static async Task<(int StatusCode, string Body, Exception? Failure)> ObserveWireOutcomeAsync(
        Task<(int StatusCode, string Body)> request, CancellationToken cancellationToken)
    {
        try
        {
            (int statusCode, string body) = await request.WaitAsync(cancellationToken).ConfigureAwait(false);

            return (statusCode, body, null);
        }
        catch(Exception exception) when(!cancellationToken.IsCancellationRequested)
        {

            return (0, string.Empty, exception);
        }

    }


    /// <summary>
    /// Parses a redirect URI's query string into a single-valued map, unescaping both keys and
    /// values so authorization request parameters and callback outcomes can be asserted individually.
    /// </summary>
    private static Dictionary<string, string> ParseQuery(Uri uri) =>
        uri.Query.TrimStart('?').Split('&')
            .Select(part => part.Split('=', 2))
            .ToDictionary(
                parts => Uri.UnescapeDataString(parts[0]),
                parts => Uri.UnescapeDataString(parts[1]),
                StringComparer.Ordinal);


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.2">RFC 6749 §2.2</see>: a
    /// <c>client_id</c> the caller presents on a pushed authorization request must be the
    /// identifier of the registration ALREADY SELECTED for the tenant's route — an unregistered
    /// name, a path-traversal string, or another tenant's own registered identifier are each
    /// refused <c>invalid_client</c>, with no <c>request_uri</c> minted and no flow record created
    /// for the attempt.
    /// </summary>
    [TestMethod]
    [DataRow("an-unregistered-client-id", DisplayName = "UnregisteredClientId")]
    [DataRow("../../etc/passwd", DisplayName = "PathTraversalClientId")]
    public async Task PushedAuthorizationRequestWithUnidentifiedClientIdIsRefusedInvalidClient(string presentedClientId)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        int flowCountBefore = hosted.FlowStates.Count;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = presentedClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, parFields, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidClient, Body, StringComparison.Ordinal);
        Assert.DoesNotContain("request_uri", Body, StringComparison.Ordinal);
        Assert.HasCount(flowCountBefore, hosted.FlowStates,
            "An identification failure must create no flow record.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.2">RFC 6749 §2.2</see>: naming
    /// ANOTHER TENANT'S registered <c>client_id</c> on tenant A's own pushed-authorization route is
    /// refused exactly as an unregistered name is — the route resolves tenant A's registration
    /// regardless of the string presented, so identification compares against THAT registration,
    /// never against whatever registration the presented string would name elsewhere.
    /// </summary>
    [TestMethod]
    public async Task PushedAuthorizationRequestNamingAnotherTenantsClientIdIsRefusedInvalidClient()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial tenantA = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        const string TenantBClientId = "https://tenant-b.example.com";
        using VerifierKeyMaterial tenantB = await host.RegisterDpopClientAsync(
            TenantBClientId, new Uri(TenantBClientId), profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities)
            .ConfigureAwait(false);
        Assert.AreNotEqual(tenantA.Registration.TenantId, tenantB.Registration.TenantId,
            "The two registrations must sit under distinct tenants for this to be a cross-tenant presentation.");

        string segmentA = tenantA.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        int flowCountBefore = hosted.FlowStates.Count;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = TenantBClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };

        //Naming tenant A's route: the dispatcher loads tenant A's own registration regardless of
        //the presented client_id (asserted above by distinct TenantId values), so this proves
        //identification runs against the ROUTE's registration, never a lookup by the presented id.
        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segmentA, parFields, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidClient, Body, StringComparison.Ordinal);
        Assert.HasCount(flowCountBefore, hosted.FlowStates,
            "An identification failure must create no flow record.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>:
    /// an invalid client identifier at the direct authorization endpoint is a DIRECT refusal — no
    /// redirect, nothing stored — never the redirect-carried error a validated destination would
    /// receive. The matching-identifier request that follows is the success control proving the
    /// profile and fixture are otherwise capable of completing this leg.
    /// </summary>
    [TestMethod]
    public async Task DirectAuthorizationWithUnidentifiedClientIdIsRefusedDirectlyWithNoLocation()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: Capabilities.Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization))
            .ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");

        //The mismatching request: refused directly.
        PkceParameters mismatchPkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Uri mismatchUrl = BuildDirectAuthorizeUrl(hosted, segment, "not-the-registration", mismatchPkce);
        using HttpResponseMessage mismatchResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, mismatchUrl, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        string mismatchBody = await mismatchResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)mismatchResponse.StatusCode, mismatchBody);
        Assert.IsNull(mismatchResponse.Headers.Location);

        //The success control: the SAME request with the registration's own identifier redirects
        //with a code, proving the profile and fixture are otherwise capable of this leg.
        PkceParameters successPkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Uri successUrl = BuildDirectAuthorizeUrl(hosted, segment, ClientId, successPkce);
        using HttpResponseMessage successResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, successUrl, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, (int)successResponse.StatusCode);
        Assert.IsNotNull(TestBrowser.ExtractQueryParam(successResponse.Headers.Location!.ToString(), OAuthRequestParameterNames.Code));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see>
    /// binds a pushed reference to its client, with validation required by
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-4">RFC 9126 §4</see>.
    /// A wrong client receives <c>invalid_request_uri</c> under
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-7">RFC 9101 §7</see>.
    /// An omitted client receives <c>invalid_request</c> for the missing required parameter under
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>.
    /// Neither direct refusal consumes the reference; its bound client can still authorize it.
    /// </summary>
    [TestMethod]
    public async Task RequestUriCompletionWithWrongOrMissingClientIdIsRefusedWithoutConsumingThePushedRequest()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        (int ParStatusCode, string ParBody) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, parFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, ParStatusCode, ParBody);
        using JsonDocument parDoc = JsonDocument.Parse(ParBody);
        string requestUri = parDoc.RootElement.GetProperty("request_uri").GetString()!;

        //A DIFFERENT client_id: refused directly, no code, the pushed request left unconsumed.
        using HttpResponseMessage wrongIdResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, BuildRequestUriAuthorizationUrl(hosted, segment, requestUri, "not-the-registration"),
            SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        string wrongIdBody = await wrongIdResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)wrongIdResponse.StatusCode, wrongIdBody);
        using JsonDocument wrongIdError = JsonDocument.Parse(wrongIdBody);
        Assert.AreEqual(OAuthErrors.InvalidRequestUri, wrongIdError.RootElement.GetProperty("error").GetString());
        Assert.IsNull(wrongIdResponse.Headers.Location);

        //NO client_id at all: also refused directly.
        using HttpResponseMessage missingIdResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, BuildRequestUriAuthorizationUrl(hosted, segment, requestUri, null),
            SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        string missingIdBody = await missingIdResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)missingIdResponse.StatusCode, missingIdBody);
        using JsonDocument missingIdError = JsonDocument.Parse(missingIdBody);
        Assert.AreEqual(OAuthErrors.InvalidRequest, missingIdError.RootElement.GetProperty("error").GetString());
        Assert.IsNull(missingIdResponse.Headers.Location);

        //The pushed request still works afterward with the RIGHT identifier — neither refusal
        //consumed it.
        using HttpResponseMessage successResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, BuildRequestUriAuthorizationUrl(hosted, segment, requestUri, ClientId),
            SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, (int)successResponse.StatusCode);
        Assert.IsNotNull(TestBrowser.ExtractQueryParam(successResponse.Headers.Location!.ToString(), OAuthRequestParameterNames.Code));
    }


    /// <summary>
    /// The <c>request_uri</c> completion's two comparisons are independent, and run in different
    /// places. Identification against the ALREADY SELECTED registration rests on
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.1">RFC 9126 §2.1</see>: "The
    /// 'client_id' parameter is defined with the same semantics for both authorization requests and
    /// requests to the token endpoint; as a required authorization request parameter, it is
    /// similarly required in a pushed authorization request." It runs in the endpoint's own
    /// pre-correlation step, before the pushed record is ever loaded. Agreement with the STORED
    /// pushed request's own <c>client_id</c> rests on
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-4">RFC 9126 §4</see>: "The
    /// authorization server MUST validate authorization requests arising from a pushed request as
    /// it would any other authorization request." It runs in the handler, once the record is
    /// loaded — the only place it CAN run. A pushed record whose stored <c>client_id</c> is
    /// not the registration's is seeded directly into the host's store. Presenting the
    /// registration's own identifier fails the binding comparison alone; presenting the stored
    /// hostile identifier fails the identification (step) comparison alone. Both answer the SAME
    /// body. Either presentation is refused, and neither consumes, advances, or repairs the record.
    /// An UNKNOWN <c>request_uri</c> presenting the same hostile <c>client_id</c> answers the
    /// identical body too, and never touches the seeded record's own step count — proof that
    /// identification runs before any record, existing or not, is ever loaded.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see>
    /// requires the reference's client binding. Either binding mismatch makes the reference invalid
    /// for this presentation and receives <c>invalid_request_uri</c>, as defined by
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-7">RFC 9101 §7</see>.
    /// </summary>
    [TestMethod]
    public async Task RequestUriCompletionOfASeededMismatchedRecordFailsEachComparisonIndependently()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        (int ParStatusCode, string ParBody) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, parFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, ParStatusCode, ParBody);
        using JsonDocument parDoc = JsonDocument.Parse(ParBody);
        string requestUri = parDoc.RootElement.GetProperty("request_uri").GetString()!;

        //Seed the mismatch directly in the store: the stored record names a client the
        //registration never was, exactly the shape a store fault or a legacy record could produce.
        const string HostileStoredClientId = "https://attacker.example.com";
        string flowId = hosted.RequestUriTokenIndex[TestHostShell.ExtractRequestUriToken(new Uri(requestUri))];
        (FlowState State, int StepCount) = hosted.FlowStates[flowId];
        ParRequestReceivedState parState = (ParRequestReceivedState)State;
        hosted.FlowStates[flowId] = (parState with { ClientId = HostileStoredClientId }, StepCount);
        int stepCountBefore = StepCount;

        //The registration's own (correctly identified) identifier: refused by the binding
        //comparison alone (it agrees with the registration but not with the stored record).
        using HttpResponseMessage boundResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, BuildRequestUriAuthorizationUrl(hosted, segment, requestUri, ClientId),
            SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        string boundBody = await boundResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)boundResponse.StatusCode, boundBody);
        using JsonDocument boundError = JsonDocument.Parse(boundBody);
        Assert.AreEqual(OAuthErrors.InvalidRequestUri, boundError.RootElement.GetProperty("error").GetString());
        Assert.Contains("client_id does not match the pushed authorization request.", boundBody, StringComparison.Ordinal);
        Assert.IsNull(boundResponse.Headers.Location, "A request_uri completion refusal is direct, never a redirect.");
        Assert.AreEqual(stepCountBefore, hosted.FlowStates[flowId].StepCount,
            "A grant-binding refusal must not consume the pushed request.");
        Assert.AreEqual(HostileStoredClientId, ((ParRequestReceivedState)hosted.FlowStates[flowId].State).ClientId,
            "A grant-binding refusal must never repair the stored record to the registration's identifier.");

        //The STORED hostile identifier: refused by identification instead — in the pre-correlation
        //step, before this pushed record is even loaded (it agrees with the stored record but not
        //with the registration).
        using HttpResponseMessage hostileResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, BuildRequestUriAuthorizationUrl(hosted, segment, requestUri, HostileStoredClientId),
            SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        string hostileBody = await hostileResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)hostileResponse.StatusCode, hostileBody);
        Assert.IsNull(hostileResponse.Headers.Location, "A request_uri completion refusal is direct, never a redirect.");
        Assert.AreEqual(stepCountBefore, hosted.FlowStates[flowId].StepCount,
            "An identification refusal must not consume the pushed request either.");

        //Both comparisons answer the SAME body byte-for-byte, even though one runs in the step and
        //the other in the handler — a presenter with no credentials cannot tell which one fired.
        Assert.AreEqual(boundBody, hostileBody,
            "The binding comparison (handler) and the identification comparison (step) must answer byte-identically.");

        //An UNKNOWN request_uri presented with the SAME hostile client_id: the identification
        //comparison runs in the step, before any record — this seeded one included — is ever
        //loaded, so an unknown handle and this existing (but mismatched) one answer byte-identically.
        string unknownRequestUri = requestUri + "-does-not-exist";
        using HttpResponseMessage unknownHostileResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, BuildRequestUriAuthorizationUrl(hosted, segment, unknownRequestUri, HostileStoredClientId),
            SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        string unknownHostileBody = await unknownHostileResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)unknownHostileResponse.StatusCode, unknownHostileBody);
        Assert.IsNull(unknownHostileResponse.Headers.Location, "A request_uri completion refusal is direct, never a redirect.");
        Assert.AreEqual(hostileBody, unknownHostileBody,
            "An unknown request_uri and this existing, mismatched one must answer byte-identically for the same "
            + "hostile client_id — the identification comparison runs before either record would be loaded.");
        Assert.AreEqual(stepCountBefore, hosted.FlowStates[flowId].StepCount,
            "The unknown-handle presentation must not touch the seeded record's own step count.");
    }


    /// <summary>
    /// A whitespace-only <c>request_uri</c> is refused before any correlation-resolver or flow-state-store
    /// call, with or without a resolver wired. <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">
    /// RFC 6749 §3.1</see>: "Parameters sent without a value MUST be treated as if they were omitted from the
    /// request" — only the empty value is omitted, so a whitespace-only value is present. The registration's
    /// policy does not require pushed authorization requests, so
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-7">RFC 9101 §7</see> answers such an
    /// unresolvable reference with <c>invalid_request_uri</c>: "The "request_uri" in the authorization request
    /// returns an error or contains invalid data."
    /// </summary>
    /// <param name="configuration">
    /// "resolver null" runs with no correlation resolver wired at all; "observed store" keeps the resolver
    /// wired but observes it. Both configurations observe the flow-state store and assert it is never
    /// touched for this reference.
    /// </param>
    [TestMethod]
    [DataRow("resolver null")]
    [DataRow("observed store")]
    public async Task BlankRequestUriIsRefusedBeforeAnyCorrelation(string configuration)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        bool isObservedStore = string.Equals(configuration, "observed store", StringComparison.Ordinal);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            hosted.InstallObservedStorage(candidateIntegration, hosted);
            if(!isObservedStore)
            {
                candidateIntegration.ResolveCorrelationKeyAsync = null;
            }
        }).ConfigureAwait(false);
        int before = hosted.StorageObservations.Count;

        Uri authorizeUrl = BuildRequestUriAuthorizationUrl(hosted, segment, "  ", ClientId);
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, authorizeUrl, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.IsNull(response.Headers.Location, "A blank request_uri is refused directly, never a redirect.");
        using JsonDocument error = JsonDocument.Parse(body);
        Assert.AreEqual(OAuthErrors.InvalidRequestUri, error.RootElement.GetProperty("error").GetString());
        Assert.AreEqual("Flow not found or expired.", error.RootElement.GetProperty("error_description").GetString());

        //Both configurations prove the same zero-store-call guarantee: with the resolver cleared, the
        //blank value must never reach a load either.
        AssertNoGrantStorageTouched(hosted, before, "a blank request_uri refusal");
    }


    /// <summary>
    /// A reference that is unknown, foreign, has no token, or is stored answers according to the pushed
    /// authorization request policy: one that never identified a pending pushed request answers
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-4">RFC 9126 §4</see>: "...will refuse, using
    /// the "invalid_request" error code, to process any request to the authorization endpoint that does not
    /// have a "request_uri" parameter with a value obtained from the PAR endpoint" — a reference that never
    /// identified a pending pushed request was never obtained from it, so it answers this
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>
    /// <c>invalid_request</c> when the policy requires pushed authorization requests, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-7">RFC 9101 §7</see>'s
    /// <c>invalid_request_uri</c> — "The "request_uri" in the authorization request returns an error or
    /// contains invalid data" — otherwise. One that resolved but is now missing its record or has reached its
    /// expiry always answers <c>invalid_request_uri</c>, under
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see> (the reference and its
    /// lifetime) and RFC 9126 §4 ("An expired "request_uri" MUST be rejected as invalid"), regardless of
    /// policy.
    /// </summary>
    /// <param name="referenceCondition">
    /// The unavailable-reference condition presented at authorization. "missing record, no resolver" and
    /// "blank resolver answer" run only under the PAR-optional policy: the PAR-required profile in this
    /// fixture also needs the correlation resolver for its own JWT-replay store, so altering the resolver
    /// seam is confined to the policy that does not depend on it.
    /// </param>
    /// <param name="requiresPushedAuthorizationRequests">
    /// <see langword="true"/> runs the registration under a profile requiring pushed authorization requests.
    /// </param>
    [TestMethod]
    [DataRow("unknown", false)]
    [DataRow("empty token", false)]
    [DataRow("blank token", false)]
    [DataRow("never issued", false)]
    [DataRow("missing record", false)]
    [DataRow("missing record, no resolver", false)]
    [DataRow("expired", false)]
    [DataRow("blank resolver answer", false)]
    [DataRow("unknown", true)]
    [DataRow("empty token", true)]
    [DataRow("blank token", true)]
    [DataRow("never issued", true)]
    [DataRow("missing record", true)]
    [DataRow("expired", true)]
    public async Task UnavailableRequestUriIsRefusedByReferenceStateAndParPolicy(
        string referenceCondition, bool requiresPushedAuthorizationRequests)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri,
            profile: requiresPushedAuthorizationRequests ? PolicyProfile.Fapi20 : PolicyProfile.Rfc6749WithPkce,
            capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        string requestUri = await PushRequestUriAsync(host, segment).ConfigureAwait(false);
        string flowId = hosted.RequestUriTokenIndex[TestHostShell.ExtractRequestUriToken(new Uri(requestUri))];
        (FlowState state, int stepCount) = hosted.FlowStates[flowId];
        ParRequestReceivedState parState = (ParRequestReceivedState)state;

        //"missing record, no resolver" and "blank resolver answer" need the resolver seam itself
        //altered, not just the stored record, so they are applied before the switch picks the
        //presented reference (both reuse the issued requestUri).
        if(string.Equals(referenceCondition, "missing record, no resolver", StringComparison.Ordinal))
        {
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ResolveCorrelationKeyAsync = null;
            }).ConfigureAwait(false);
        }
        else if(string.Equals(referenceCondition, "blank resolver answer", StringComparison.Ordinal))
        {
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ResolveCorrelationKeyAsync = (_, _, _, _, _) => ValueTask.FromResult<string?>(" ");
            }).ConfigureAwait(false);
        }

        (string presentedReference, ParRequestReceivedState? storedRequest) = referenceCondition switch
        {
            "unknown" => (requestUri + "-unknown", parState),
            //A syntactically well-formed reference naming a token this server never issued to any
            //registration — distinct from "unknown" (a live token with a garbage suffix) — still
            //never identifies a pending pushed request.
            "never issued" => ("urn:ietf:params:oauth:request_uri:never-issued-" + Guid.NewGuid().ToString("N"), parState),
            "empty token" => ("urn:ietf:params:oauth:request_uri:", parState),
            "blank token" => (" ", parState),
            "missing record" or "missing record, no resolver" => (requestUri, null),
            "expired" => (requestUri, parState with { ExpiresAt = TimeProvider.GetUtcNow() }),
            "blank resolver answer" => (requestUri, parState),
            _ => throw new ArgumentOutOfRangeException(nameof(referenceCondition))
        };
        if(storedRequest is null)
        {
            Assert.IsTrue(hosted.FlowStates.TryRemove(flowId, out _));
        }
        else
        {
            hosted.FlowStates[flowId] = (storedRequest, stepCount);
        }

        Uri authorizeUrl = BuildRequestUriAuthorizationUrl(hosted, segment, presentedReference, ClientId);
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, authorizeUrl, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.IsNull(response.Headers.Location);
        using JsonDocument error = JsonDocument.Parse(body);

        //"missing record" and "expired" resolved to a real reference whose stored state is now
        //unusable: RFC 9126 §4 and §2.2 answer invalid_request_uri regardless of policy.
        //"missing record, no resolver" never resolved at all (no resolver is wired), so it joins the
        //never-resolved group governed by policy. Every other condition never resolved at all, so the
        //policy in force at the PAR-optional/PAR-required split decides between invalid_request_uri and
        //invalid_request.
        bool isKnownButUnusable = referenceCondition is "missing record" or "expired";
        string expectedError = isKnownButUnusable
            ? OAuthErrors.InvalidRequestUri
            : requiresPushedAuthorizationRequests ? OAuthErrors.InvalidRequest : OAuthErrors.InvalidRequestUri;
        Assert.AreEqual(expectedError, error.RootElement.GetProperty("error").GetString());

        //Neither the never-resolved nor the resolved-but-unusable refusal names its own description on
        //this endpoint, so both fall back to the same host-generic literal: every condition in this
        //test answers the identical description regardless of policy or reference state.
        Assert.AreEqual("Flow not found or expired.", error.RootElement.GetProperty("error_description").GetString());
        Assert.DoesNotContain(entry => entry.State is ServerCodeIssuedState, hosted.FlowStates.Values,
            "An unavailable reference must issue no authorization code.");
    }


    /// <summary>
    /// An already-authorized reference cannot issue another code after the successful state is saved, under
    /// either pushed authorization request policy. <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">
    /// RFC 9126 §2.2</see> defines the single-use reference, and this server enforces the one-time-use
    /// recommendation in <see href="https://www.rfc-editor.org/rfc/rfc9126#section-4">RFC 9126 §4</see> with
    /// <c>invalid_request_uri</c>, the reference-error code in
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-7">RFC 9101 §7</see>. This resolves to a real,
    /// already-consumed reference — a reference state, not an unresolved handle — so the pushed authorization
    /// request policy never changes the answer.
    /// </summary>
    /// <param name="requiresPushedAuthorizationRequests">
    /// <see langword="true"/> runs the registration under a profile requiring pushed authorization requests.
    /// </param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task ConsumedRequestUriIsRefusedInvalidRequestUriAfterAuthorizationIsSaved(
        bool requiresPushedAuthorizationRequests)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri,
            profile: requiresPushedAuthorizationRequests ? PolicyProfile.Fapi20 : PolicyProfile.Rfc6749WithPkce,
            capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        string requestUri = await PushRequestUriAsync(host, segment).ConfigureAwait(false);
        Uri authorizeUrl = BuildRequestUriAuthorizationUrl(hosted, segment, requestUri, ClientId);
        using HttpResponseMessage success = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, authorizeUrl, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, (int)success.StatusCode);
        Assert.IsNotNull(success.Headers.Location);
        Assert.IsNotNull(TestBrowser.ExtractQueryParam(success.Headers.Location.ToString(), OAuthRequestParameterNames.Code));
        string flowId = hosted.RequestUriTokenIndex[TestHostShell.ExtractRequestUriToken(new Uri(requestUri))];
        (FlowState state, int stepCount) = hosted.FlowStates[flowId];
        _ = Assert.IsInstanceOfType<ServerCodeIssuedState>(state);

        using HttpResponseMessage refusal = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, authorizeUrl, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await refusal.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)refusal.StatusCode, body);
        Assert.IsNull(refusal.Headers.Location);
        using JsonDocument error = JsonDocument.Parse(body);
        Assert.AreEqual(OAuthErrors.InvalidRequestUri, error.RootElement.GetProperty("error").GetString());
        Assert.AreEqual((state, stepCount), hosted.FlowStates[flowId],
            "Reusing the reference must leave the issued authorization code unchanged.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-4">RFC 9126 §4</see>'s server "will
    /// refuse, using the "invalid_request" error code, to process any request to the authorization
    /// endpoint that does not have a "request_uri" parameter with a value obtained from the PAR
    /// endpoint." A GET carrying no usable <c>request_uri</c> under a policy requiring pushed
    /// authorization requests answers this
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>
    /// <c>invalid_request</c>, since the registration owns neither the JAR-by-value nor the
    /// direct-authorization endpoint the request's shape would otherwise route to. An omitted
    /// <c>request_uri</c> and an empty one answer byte-identically for both shapes —
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 §3.1</see>: "Parameters
    /// sent without a value MUST be treated as if they were omitted from the request" — because that
    /// same rule governs both the routing matchers and the both-present guard (RFC 9101 §5) equally: an
    /// empty <c>request_uri</c> alongside a present <c>request</c> is one present parameter, not two,
    /// so it is not claimed by the both-present guard either.
    /// </summary>
    /// <param name="shape">
    /// "PKCE" sends no <c>request</c> parameter (the direct-authorization shape); "request object" sends one
    /// (the JAR-by-value shape). Neither owning endpoint is registered, so both fall to this refusal.
    /// </param>
    [TestMethod]
    [DataRow("PKCE")]
    [DataRow("request object")]
    public async Task MissingRequestUriIsRefusedInvalidRequestWhenParIsRequired(string shape)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Fapi20, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        bool isRequestObjectShape = string.Equals(shape, "request object", StringComparison.Ordinal);
        Dictionary<string, string> baseFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientId] = ClientId
        };
        if(isRequestObjectShape)
        {
            baseFields[OAuthRequestParameterNames.Request] = "not-a-real-request-object-jwt";
        }

        using HttpResponseMessage omittedResponse = await SendAuthorizeGetAsync(host, hosted, segment, baseFields)
            .ConfigureAwait(false);
        string omittedBody = await omittedResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)omittedResponse.StatusCode, omittedBody);
        Assert.IsNull(omittedResponse.Headers.Location);
        using JsonDocument omittedError = JsonDocument.Parse(omittedBody);
        Assert.AreEqual(OAuthErrors.InvalidRequest, omittedError.RootElement.GetProperty("error").GetString());
        Assert.AreEqual("Missing request_uri.", omittedError.RootElement.GetProperty("error_description").GetString());

        Dictionary<string, string> emptyFields = new(baseFields, StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.RequestUri] = string.Empty
        };
        using HttpResponseMessage emptyResponse = await SendAuthorizeGetAsync(host, hosted, segment, emptyFields)
            .ConfigureAwait(false);
        string emptyBody = await emptyResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual((int)omittedResponse.StatusCode, (int)emptyResponse.StatusCode);
        Assert.AreEqual(omittedBody, emptyBody,
            "An omitted request_uri and an empty one must answer byte-identically.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-4">RFC 9126 §4</see>'s PAR-required
    /// refusal ("will refuse ... to process any request to the authorization endpoint that does not
    /// have a "request_uri" parameter") applies only when no OTHER endpoint already owns the exact
    /// request — this library's own routing design, not a rule RFC 6749 §3.1 states: a GET naming
    /// neither <c>request_uri</c> nor <c>request</c> is direct authorization's exact shape whenever
    /// the registration carries that capability, so the direct-authorization endpoint owns and
    /// answers it under its own acceptance test, never the authorize endpoint's
    /// missing-<c>request_uri</c> fallback. The direct endpoint's handler runs its request-shape
    /// checks before its PAR-required policy check
    /// (<see cref="PlainPkceRefusedAtDirectAuthorizeBeforeParPolicy"/> pins the same order), so a
    /// request missing <c>code_challenge</c> is refused by that check first, answering that
    /// endpoint's own "Missing code_challenge." — this test does not exercise RFC 7636 §4.4.1's
    /// redirect-shaped answer, since this handler's check order answers directly instead.
    /// </summary>
    [TestMethod]
    public async Task MissingRequestUriIsRefusedInvalidRequestEvenWithDirectAuthorizationRegistered()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Fapi20,
            capabilities: Capabilities.Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization))
            .ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //A well-formed GET for direct authorization EXCEPT for code_challenge, so the registered
        //direct-authorization endpoint's own matcher accepts this exact request and its handler
        //answers with its own "Missing code_challenge." refusal.
        Dictionary<string, string> fields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };

        using HttpResponseMessage response = await SendAuthorizeGetAsync(host, hosted, segment, fields)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.IsNull(response.Headers.Location);
        using JsonDocument error = JsonDocument.Parse(body);
        Assert.AreEqual(OAuthErrors.InvalidRequest, error.RootElement.GetProperty("error").GetString());
        Assert.AreEqual("Missing code_challenge.", error.RootElement.GetProperty("error_description").GetString());
    }


    /// <summary>
    /// The authorize endpoint's fallback matcher decides its own claim on a reference-less GET by
    /// invoking every other chained endpoint's own matcher
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9126#section-4">RFC 9126 §4</see>: the server
    /// answers <c>invalid_request</c> only when no other endpoint already owns the exact request — a
    /// rule this library's own routing design applies through a probe, not text §4 itself states). A
    /// sibling matcher from a composed builder set could decide its own claim the same way, and a
    /// probe that in turn probes back into this one would recurse without bound. This test composes a
    /// sibling that DOES probe back into the real production matcher — the exact mutual-recursion
    /// shape the mark on <see cref="ExchangeContext"/> defends against — capped at a small depth so a
    /// broken guard fails an assertion here instead of overflowing the process stack. With the guard
    /// present, the authorize matcher sets the mark before probing, the sibling observes it set and
    /// declines immediately, and the whole exchange runs to a nesting depth of exactly one.
    /// </summary>
    [TestMethod]
    public async Task OwnershipProbeBoundedReentrantSiblingIsConsultedExactlyOnce()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Fapi20, capabilities: Capabilities)
            .ConfigureAwait(false);

        ExchangeContext context = new();
        context.SetServer(host.Server);
        context.SetRequestServer(host.Server);
        context.SetRequirePushedAuthorizationRequests(true);

        IReadOnlyList<EndpointCandidate> candidates = await AuthCodeEndpoints.Builder(
            material.Registration, context, TestContext.CancellationToken).ConfigureAwait(false);
        EndpointCandidate authorizeCandidate = candidates.Single(
            candidate => candidate.Name == WellKnownEndpointNames.AuthCodeAuthorize);
        Uri resolvedUri = new("https://issuer.test.example/connect/x/authorize");
        ServerEndpoint authorizeEndpoint = new()
        {
            Name = authorizeCandidate.Name,
            Capability = authorizeCandidate.Capability,
            HttpMethod = authorizeCandidate.HttpMethod,
            Kind = authorizeCandidate.Kind,
            StartsNewFlow = authorizeCandidate.StartsNewFlow,
            MatchesRequest = authorizeCandidate.MatchesRequest,
            BuildInputAsync = authorizeCandidate.BuildInputAsync,
            BuildResponse = authorizeCandidate.BuildResponse,
            ResolvedUri = resolvedUri
        };

        int siblingProbeCount = 0;
        const int siblingProbeDepthCap = 4;
        ServerEndpoint siblingEndpoint = new()
        {
            Name = "test.probing-sibling-authorize",
            Capability = WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            HttpMethod = WellKnownHttpMethods.Get,
            Kind = FlowKind.AuthCodeServer,
            StartsNewFlow = true,
            //Stands in for a sibling endpoint from a composed builder set that decides its own claim
            //by probing every other chained matcher too, INCLUDING one already probing it — the
            //shape that recurses without bound unless the authorize matcher's own guard breaks the
            //cycle. The depth cap is this test's own safety valve, not a stand-in for the guard: it
            //keeps an unguarded run from overflowing the stack so the assertions below can observe
            //the difference instead.
            MatchesRequest = async (siblingFields, siblingContext, _, ct) =>
            {
                int depth = ++siblingProbeCount;
                if(depth > siblingProbeDepthCap)
                {

                    return null;
                }

                if(siblingContext.IsOwnershipProbeInProgress)
                {

                    return null;
                }

                return await authorizeEndpoint.MatchesRequest(siblingFields, siblingContext, authorizeEndpoint, ct)
                    .ConfigureAwait(false);
            },
            BuildInputAsync = static (_, _, _, _) =>
                throw new InvalidOperationException("Never invoked: this synthetic endpoint never matches."),
            BuildResponse = static (_, _, _) =>
                throw new InvalidOperationException("Never invoked: this synthetic endpoint never matches."),
            ResolvedUri = resolvedUri
        };

        context.SetEndpointChain(new EndpointChain([authorizeEndpoint, siblingEndpoint]));
        context.SetIncomingRequest(new IncomingRequest(
            Path: resolvedUri.AbsolutePath,
            Method: WellKnownHttpMethods.Get,
            Fields: new RequestFields(),
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty));
        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId
        };

        MatchPayload? result = await authorizeEndpoint.MatchesRequest(
            fields, context, authorizeEndpoint, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result,
            "With the sibling declining once probed, the authorize endpoint's own fallback claims the reference-less GET.");
        Assert.AreEqual(1, siblingProbeCount,
            "A sibling that cooperates with the mark is consulted exactly once, never probed back into.");
        Assert.IsFalse(context.IsOwnershipProbeInProgress,
            "The mark is restored once the authorize matcher's own probe completes.");
    }


    /// <summary>
    /// The mark <see cref="OwnershipProbeBoundedReentrantSiblingIsConsultedExactlyOnce"/> proves
    /// is set and cleared around a completed probe is cleared the same way when a probed sibling
    /// FAULTS instead of returning: the authorize matcher's own <c>try</c>/<c>finally</c> around the
    /// chain walk restores <c>ExchangeContext.IsOwnershipProbeInProgress</c> to
    /// <see langword="false"/> even though the exception propagates past it uncaught, so the next
    /// request on this context never inherits a mark a failed probe left behind.
    /// </summary>
    [TestMethod]
    public async Task OwnershipProbeMarkIsClearedWhenAProbedSiblingFaults()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Fapi20, capabilities: Capabilities)
            .ConfigureAwait(false);

        ExchangeContext context = new();
        context.SetServer(host.Server);
        context.SetRequestServer(host.Server);
        context.SetRequirePushedAuthorizationRequests(true);

        IReadOnlyList<EndpointCandidate> candidates = await AuthCodeEndpoints.Builder(
            material.Registration, context, TestContext.CancellationToken).ConfigureAwait(false);
        EndpointCandidate authorizeCandidate = candidates.Single(
            candidate => candidate.Name == WellKnownEndpointNames.AuthCodeAuthorize);
        Uri resolvedUri = new("https://issuer.test.example/connect/x/authorize");
        ServerEndpoint authorizeEndpoint = new()
        {
            Name = authorizeCandidate.Name,
            Capability = authorizeCandidate.Capability,
            HttpMethod = authorizeCandidate.HttpMethod,
            Kind = authorizeCandidate.Kind,
            StartsNewFlow = authorizeCandidate.StartsNewFlow,
            MatchesRequest = authorizeCandidate.MatchesRequest,
            BuildInputAsync = authorizeCandidate.BuildInputAsync,
            BuildResponse = authorizeCandidate.BuildResponse,
            ResolvedUri = resolvedUri
        };

        ServerEndpoint faultingSibling = new()
        {
            Name = "test.faulting-sibling-authorize",
            Capability = WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            HttpMethod = WellKnownHttpMethods.Get,
            Kind = FlowKind.AuthCodeServer,
            StartsNewFlow = true,
            MatchesRequest = static (_, _, _, _) =>
                throw new InvalidOperationException("A composed sibling's own matcher fails during the probe."),
            BuildInputAsync = static (_, _, _, _) =>
                throw new InvalidOperationException("Never invoked: this synthetic endpoint never matches."),
            BuildResponse = static (_, _, _) =>
                throw new InvalidOperationException("Never invoked: this synthetic endpoint never matches."),
            ResolvedUri = resolvedUri
        };

        context.SetEndpointChain(new EndpointChain([authorizeEndpoint, faultingSibling]));
        context.SetIncomingRequest(new IncomingRequest(
            Path: resolvedUri.AbsolutePath,
            Method: WellKnownHttpMethods.Get,
            Fields: new RequestFields(),
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty));
        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId
        };

        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => authorizeEndpoint.MatchesRequest(fields, context, authorizeEndpoint, TestContext.CancellationToken).AsTask())
            .ConfigureAwait(false);

        Assert.IsFalse(context.IsOwnershipProbeInProgress,
            "A probed sibling that faults must not leave the mark set for the next request on this context.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-4">RFC 9126 §4</see>'s server "will
    /// refuse, using the "invalid_request" error code, to process any request to the authorization
    /// endpoint that does not have a "request_uri" parameter with a value obtained from the PAR
    /// endpoint." A GET carrying a JAR-by-value <c>request</c> object and no <c>request_uri</c> under a
    /// policy requiring pushed authorization requests is claimed by the JAR-by-value endpoint itself
    /// (RFC 9101 §6.1 governs its ownership of this request's shape) and refused by that endpoint's own
    /// PAR-mandating message, never by the authorize endpoint's missing-<c>request_uri</c> fallback.
    /// </summary>
    [TestMethod]
    public async Task JarByValueAuthorizeIsRefusedByItsOwnMessageWhenParIsRequired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Fapi20,
            capabilities: Capabilities
                .Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization)
                .Add(WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest))
            .ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //RegisterDpopClientAsync provisions AccessTokenIssuance/IdTokenIssuance signing keys only;
        //this row also signs a request object, so the registration's own signing key is extended
        //into the JarSigning slot the JAR-by-value endpoint verifies against.
        _ = await host.UpdateAsync(material, previous =>
        {
            Dictionary<KeyUsageContext, SigningKeySet> signingKeys = new(previous.SigningKeys)
            {
                [KeyUsageContext.JarSigning] = new SigningKeySet { Current = [material.SigningKeyId] }
            };

            return previous with { SigningKeys = signingKeys };
        }, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material,
            OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RedirectUri, "jar-owner-state", "jar-owner-nonce"),
            TestContext.CancellationToken)
            .ConfigureAwait(false);

        Dictionary<string, string> fields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.Request] = compactJar
        };

        using HttpResponseMessage response = await SendAuthorizeGetAsync(host, hosted, segment, fields)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.IsNull(response.Headers.Location);
        using JsonDocument error = JsonDocument.Parse(body);
        Assert.AreEqual(OAuthErrors.InvalidRequest, error.RootElement.GetProperty("error").GetString());
        Assert.Contains("a JAR-by-value authorization request is not accepted", body, StringComparison.Ordinal,
            $"The refusal must be JAR-by-value's own PAR-mandating message, not the missing-request_uri "
            + $"fallback's \"Missing request_uri.\" Got: {body}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-4">RFC 9126 §4</see>'s server "will
    /// refuse, using the "invalid_request" error code, to process any request to the authorization
    /// endpoint that does not have a "request_uri" parameter with a value obtained from the PAR
    /// endpoint." An otherwise well-formed direct-authorization (PKCE S256) GET under a policy
    /// requiring pushed authorization requests is claimed by the direct-authorization endpoint itself,
    /// which declines the request under its own PAR-mandating policy, never by the authorize endpoint's
    /// missing-<c>request_uri</c> fallback.
    /// </summary>
    [TestMethod]
    public async Task DirectAuthorizeIsRefusedByItsOwnMessageWhenParIsRequired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Fapi20,
            capabilities: Capabilities.Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization))
            .ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> fields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };

        using HttpResponseMessage response = await SendAuthorizeGetAsync(host, hosted, segment, fields)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.IsNull(response.Headers.Location);
        using JsonDocument error = JsonDocument.Parse(body);
        Assert.AreEqual(OAuthErrors.InvalidRequest, error.RootElement.GetProperty("error").GetString());
        Assert.Contains("a direct authorization request is not accepted", body, StringComparison.Ordinal,
            $"The refusal must be direct authorization's own PAR-mandating message, not the missing-request_uri "
            + $"fallback's \"Missing request_uri.\" Got: {body}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 §3.1</see>: "Parameters
    /// sent without a value MUST be treated as if they were omitted from the request." An empty
    /// <c>request_uri</c> alongside an otherwise-complete direct-authorization (PKCE) request is
    /// therefore not a reference to complete and not a missing-parameter refusal: it is the SAME
    /// request as one with no <c>request_uri</c> at all, routed to direct authorization and answered
    /// with a redirect carrying a redeemable authorization code, exactly like the omitted case.
    /// </summary>
    [TestMethod]
    public async Task EmptyRequestUriIsTreatedAsOmittedAtDirectAuthorization()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: Capabilities.Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization))
            .ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        async Task<string> AuthorizeAndRedeemAsync(bool includeEmptyRequestUri)
        {
            PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
            Dictionary<string, string> fields = new(StringComparer.Ordinal)
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
                [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
                [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
                [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
                [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
            };
            if(includeEmptyRequestUri)
            {
                fields[OAuthRequestParameterNames.RequestUri] = string.Empty;
            }

            using HttpResponseMessage response = await SendAuthorizeGetAsync(host, hosted, segment, fields)
                .ConfigureAwait(false);
            Assert.AreEqual(302, (int)response.StatusCode,
                await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false));
            string code = TestBrowser.ExtractQueryParam(
                response.Headers.Location!.ToString(), OAuthRequestParameterNames.Code)!;

            (int tokenStatusCode, string tokenBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment,
                RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
                TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, tokenStatusCode, tokenBody);

            return code;
        }

        string omittedCode = await AuthorizeAndRedeemAsync(includeEmptyRequestUri: false).ConfigureAwait(false);
        string emptyCode = await AuthorizeAndRedeemAsync(includeEmptyRequestUri: true).ConfigureAwait(false);
        Assert.AreNotEqual(omittedCode, emptyCode,
            "Each authorization redirects and redeems its own, independently issued code.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 §3.1</see> (PAR and
    /// direct authorization) and its restatement at the token endpoint,
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 §3.2</see> (the
    /// refresh grant): "Parameters sent without a value MUST be treated as if they were omitted from
    /// the request." Each endpoint below REQUIRES the named parameter — PAR's and direct
    /// authorization's <c>code_challenge</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.4.1">RFC 7636 §4.4.1</see>: a
    /// public client's absent <c>code_challenge</c> "MUST return the authorization error response
    /// with the "error" value set to "invalid_request"" — PAR answers this directly, having no
    /// front channel of its own; direct authorization's handler answers the same code and message
    /// as a bare 400 here rather than the redirect §4.4.1 names, an existing ordering this test does
    /// not itself prove conformant), the refresh grant's <c>refresh_token</c>,
    /// revocation's and introspection's <c>token</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7009#section-2.1">RFC 7009 §2.1</see> /
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.1">RFC 7662 §2.1</see>: both
    /// "REQUIRED") — an omitted occurrence and one present with an empty value answer
    /// byte-identically, each endpoint's own literal <c>error_description</c> included, so two
    /// endpoints that both answer <c>invalid_request</c> cannot be mistaken for one another.
    /// </summary>
    [TestMethod]
    [DataRow("PAR code_challenge", "Missing code_challenge.")]
    [DataRow("direct code_challenge", "Missing code_challenge.")]
    [DataRow("refresh_token", "Missing refresh_token.")]
    [DataRow("revoke token", "Missing token parameter.")]
    [DataRow("introspect token", "Missing token parameter.")]
    public async Task RequiredParameterSentWithoutAValueIsRefusedLikeAnOmittedOne(
        string parameter, string expectedDescription)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: CapabilitiesWithIntrospection.Add(WellKnownCapabilityIdentifiers.OAuthDirectAuthorization))
            .ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(true);
            candidateIntegration.RevokeTokenAsync = static (_, _, _, _, _) =>
                ValueTask.CompletedTask;
            candidateIntegration.IntrospectTokenAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(new TokenIntrospectionResult { IsActive = false });
        }).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        static Dictionary<string, string> WithOptionalEmptyValue(
            Dictionary<string, string> fields, string key, bool includeEmptyValue)
        {
            if(includeEmptyValue)
            {
                fields[key] = string.Empty;
            }
            else
            {
                _ = fields.Remove(key);
            }

            return fields;
        }

        async Task<(int StatusCode, string Body)> SendDirectAuthorizeAsync(Dictionary<string, string> fields)
        {
            using HttpResponseMessage response = await SendAuthorizeGetAsync(host, hosted, segment, fields)
                .ConfigureAwait(false);
            string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

            return ((int)response.StatusCode, body);
        }

        Task<(int StatusCode, string Body)> PushAsync(bool includeEmptyValue) => parameter switch
        {
            "PAR code_challenge" => RawAuthCodeWirePushers.PushRawParFieldsAsync(
                host, segment,
                WithOptionalEmptyValue(
                    new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
                        [OAuthRequestParameterNames.ClientId] = ClientId,
                        [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
                        [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
                        [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
                        [OAuthRequestParameterNames.CodeChallenge] = "unused"
                    },
                    OAuthRequestParameterNames.CodeChallenge, includeEmptyValue),
                TestContext.CancellationToken),
            "direct code_challenge" => SendDirectAuthorizeAsync(
                WithOptionalEmptyValue(
                    new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
                        [OAuthRequestParameterNames.ClientId] = ClientId,
                        [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
                        [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
                        [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
                        [OAuthRequestParameterNames.CodeChallenge] = "unused"
                    },
                    OAuthRequestParameterNames.CodeChallenge, includeEmptyValue)),
            "refresh_token" => RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment,
                WithOptionalEmptyValue(
                    RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, refreshToken: "unused"),
                    OAuthRequestParameterNames.RefreshToken, includeEmptyValue),
                TestContext.CancellationToken),
            "revoke token" => RawAuthCodeWirePushers.PushRawRevocationFieldsAsync(
                host, segment,
                WithOptionalEmptyValue(
                    new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        [OAuthRequestParameterNames.ClientId] = ClientId,
                        [OAuthRequestParameterNames.Token] = "unused"
                    },
                    OAuthRequestParameterNames.Token, includeEmptyValue),
                TestContext.CancellationToken),
            "introspect token" => RawAuthCodeWirePushers.PushRawIntrospectionFieldsAsync(
                host, segment,
                WithOptionalEmptyValue(
                    new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        [OAuthRequestParameterNames.ClientId] = ClientId,
                        [OAuthRequestParameterNames.Token] = "unused"
                    },
                    OAuthRequestParameterNames.Token, includeEmptyValue),
                TestContext.CancellationToken),
            _ => throw new ArgumentOutOfRangeException(nameof(parameter), parameter, "Unrecognized case name.")
        };

        (int omittedStatusCode, string omittedBody) = await PushAsync(includeEmptyValue: false).ConfigureAwait(false);
        (int emptyStatusCode, string emptyBody) = await PushAsync(includeEmptyValue: true).ConfigureAwait(false);

        Assert.AreEqual(400, omittedStatusCode, omittedBody);
        using JsonDocument omittedError = JsonDocument.Parse(omittedBody);
        Assert.AreEqual(OAuthErrors.InvalidRequest, omittedError.RootElement.GetProperty("error").GetString());
        Assert.AreEqual(expectedDescription, omittedError.RootElement.GetProperty("error_description").GetString(),
            "Each endpoint's own literal refusal, not merely a shared invalid_request code, must be the answer.");
        Assert.AreEqual(omittedStatusCode, emptyStatusCode);
        Assert.AreEqual(omittedBody, emptyBody,
            "An omitted required parameter and one sent with an empty value must answer byte-identically.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 §3.1</see>: "Parameters
    /// sent without a value MUST be treated as if they were omitted from the request." Driven over
    /// the real transport so the HTTP skin's own decoding of an empty-valued query key
    /// (<c>scope=</c>) is what this assertion observes, not a hand-built <c>RequestFields</c>
    /// standing in for it: a clean <c>request_uri</c> + <c>client_id</c> authorize GET carrying an
    /// empty <c>scope</c> alongside them emits no tampering signal
    /// (<c>oauth.authorize.extraneous_parameters_ignored</c>).
    /// </summary>
    [TestMethod]
    public async Task CleanReferencedAuthorizeWithEmptyScopeEmitsNoTamperingEventOverTheWire()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        (int parStatusCode, string parBody) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, parFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parStatusCode, parBody);
        using JsonDocument parJson = JsonDocument.Parse(parBody);
        string requestUri = parJson.RootElement.GetProperty("request_uri").GetString()!;

        Dictionary<string, string> authorizeFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri,
            [OAuthRequestParameterNames.Scope] = string.Empty
        };

        IReadOnlyList<Activity> activities = await ParRequestIntegrityTests.CaptureAuthorizeActivitiesAsync(
            material.Registration.TenantHandle!.Value.Value,
            async () =>
            {
                using HttpResponseMessage response = await SendAuthorizeGetAsync(host, hosted, segment, authorizeFields)
                    .ConfigureAwait(false);
                Assert.AreEqual(302, (int)response.StatusCode,
                    await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false));
            }).ConfigureAwait(false);

        List<string> eventNames = activities.SelectMany(a => a.Events).Select(e => e.Name).ToList();
        Assert.DoesNotContain(OAuthEventNames.ExtraneousAuthorizeParameters, eventNames,
            "A conformant request_uri + client_id authorize with an empty scope must emit no tampering "
            + "signal, with the empty value crossing a real HTTP query string.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-4">RFC 9126 §4</see>: "The
    /// authorization server MUST validate authorization requests arising from a pushed request as
    /// it would any other authorization request," and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.1">RFC 9126 §2.1</see> requires
    /// <c>client_id</c> on it. The check runs in the endpoint's own pre-correlation step, before
    /// the pushed request is ever looked up, so a request naming no <c>client_id</c> is refused
    /// identically whether its <c>request_uri</c> names a live pushed request or nothing at all.
    /// This missing-parameter refusal is <c>invalid_request</c> under
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task RequestUriCompletionWithNoClientIdAnswersTheSameBodyForAnUnknownAndAnExistingRequestUriAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        (int ParStatusCode, string ParBody) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, parFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, ParStatusCode, ParBody);
        using JsonDocument parDoc = JsonDocument.Parse(ParBody);
        string requestUri = parDoc.RootElement.GetProperty("request_uri").GetString()!;

        using HttpResponseMessage existingResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, BuildRequestUriAuthorizationUrl(hosted, segment, requestUri, null),
            SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        string existingBody = await existingResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using HttpResponseMessage unknownResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, BuildRequestUriAuthorizationUrl(hosted, segment, "urn:ietf:params:oauth:request_uri:unknown-value", null),
            SubjectId, TestContext.CancellationToken)
            .ConfigureAwait(false);
        string unknownBody = await unknownResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)existingResponse.StatusCode, existingBody);
        using JsonDocument existingError = JsonDocument.Parse(existingBody);
        Assert.AreEqual(OAuthErrors.InvalidRequest, existingError.RootElement.GetProperty("error").GetString());
        Assert.Contains("Missing client_id.", existingBody, StringComparison.Ordinal);
        Assert.AreEqual((int)unknownResponse.StatusCode, (int)existingResponse.StatusCode);
        Assert.AreEqual(unknownBody, existingBody,
            "An unknown request_uri and an existing one must answer byte-identically when client_id is missing.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>: a
    /// missing required parameter is <c>invalid_request</c>. A public client's code redemption
    /// that presents neither client authentication nor a <c>client_id</c> field is refused
    /// <c>invalid_request</c>, distinct from a confidential client's own declared-method
    /// authentication failure (<c>invalid_client</c>) and from a wrong or foreign <c>client_id</c>
    /// (the same <c>invalid_grant</c> constant an unknown code answers with); the same code
    /// redeems normally afterward with the field present. The check runs in the code-redemption
    /// endpoint's own pre-correlation step, before the presented <c>code</c> is ever looked up,
    /// so an UNKNOWN code with the same well-formed verifier and no <c>client_id</c> is refused
    /// byte-identically — RFC 6749 §3.2.1.
    /// </summary>
    [TestMethod]
    public async Task PublicClientCodeRedemptionWithNoClientIdIsInvalidRequest()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, string> fieldsWithoutClientId = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
        };
        (int MissingStatus, string MissingBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, fieldsWithoutClientId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, MissingStatus, MissingBody);
        Assert.Contains(OAuthErrors.InvalidRequest, MissingBody, StringComparison.Ordinal);

        //An UNKNOWN code, same well-formed verifier, no client_id: the pre-correlation step
        //answers this before the code is ever looked up, so the body is byte-identical.
        Dictionary<string, string> unknownCodeFieldsWithoutClientId = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
            [OAuthRequestParameterNames.Code] = "unknown-authorization-code-value",
            [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
        };
        (int UnknownStatus, string UnknownBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, unknownCodeFieldsWithoutClientId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(MissingStatus, UnknownStatus);
        Assert.AreEqual(MissingBody, UnknownBody,
            "An unknown code and a live one must answer byte-identically when client_id is missing.");

        //The code was not consumed: redeeming it correctly afterward still succeeds.
        (int OkStatus, string OkBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, OkStatus, OkBody);
    }


    /// <summary>
    /// The REFRESH twin of <see cref="PublicClientCodeRedemptionWithNoClientIdIsInvalidRequest"/>:
    /// this proves the library's own refresh identification policy —
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1 draft-16
    /// §4.3.1</see>'s stored-grant binding rule read fail-closed on neither identity — and the
    /// uniform answer it shares with code redemption, not an
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2.1">RFC 6749 §3.2.1</see>
    /// requirement (that MUST is scoped to the <c>authorization_code</c> grant's request, not
    /// refresh). A public client's refresh that presents neither client authentication nor a
    /// <c>client_id</c> field is refused <c>invalid_request</c>, hoisted into the refresh
    /// endpoint's pre-correlation step
    /// so an UNKNOWN refresh token answers byte-identically to a LIVE one — before this fix, the
    /// request-only condition was decided only once the stored record was already loaded, so a
    /// live token answered the record-dependent binding body while an unknown one answered the
    /// endpoint's own not-found constant. The live token is not consumed: refreshing correctly
    /// afterward still succeeds.
    /// </summary>
    [TestMethod]
    public async Task PublicRefreshWithNoClientIdIsInvalidRequestAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);

        (int TokenStatus, string TokenBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, TokenStatus, TokenBody);
        string refreshToken;
        using(JsonDocument tokenDoc = JsonDocument.Parse(TokenBody))
        {
            refreshToken = tokenDoc.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!;
        }

        Dictionary<string, string> fieldsWithoutClientId = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
            [OAuthRequestParameterNames.RefreshToken] = refreshToken
        };
        (int MissingStatus, string MissingBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, fieldsWithoutClientId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, MissingStatus, MissingBody);
        Assert.Contains(OAuthErrors.InvalidRequest, MissingBody, StringComparison.Ordinal);

        //An UNKNOWN refresh token, no client_id: the pre-correlation step answers this before the
        //token is ever looked up, so the body is byte-identical.
        Dictionary<string, string> unknownFieldsWithoutClientId = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
            [OAuthRequestParameterNames.RefreshToken] = "unknown-refresh-token-value"
        };
        (int UnknownStatus, string UnknownBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, unknownFieldsWithoutClientId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(MissingStatus, UnknownStatus);
        Assert.AreEqual(MissingBody, UnknownBody,
            "An unknown refresh token and a live one must answer byte-identically when client_id is missing.");

        //The refresh token was not consumed: refreshing correctly afterward still succeeds.
        (int OkStatus, string OkBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, refreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, OkStatus, OkBody);
    }


    /// <summary>
    /// The design document's
    /// <see href="../../../documents/AuthorizationServerDesign.md#5-operational-ordering-on-validation">ordering
    /// section</see>: a check that needs only the request and the registration must run before any
    /// stored record is correlated or loaded. A malformed <c>code_verifier</c> is refused by the
    /// code-redemption endpoint's pre-correlation step, for an UNKNOWN and a LIVE code alike, before
    /// <c>HostedAuthorizationServer.ResolveCorrelationKeyAsync</c> or
    /// <c>LoadFlowStateAsync</c> ever runs; a correct presentation shows exactly one of each.
    /// </summary>
    [TestMethod]
    public async Task MalformedVerifierRefusalTouchesNoGrantStorageAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            hosted.InstallObservedStorage(candidateIntegration, hosted);
        }).ConfigureAwait(false);

        const string MalformedVerifier = "too-short";

        int beforeLiveRefusal = hosted.StorageObservations.Count;
        (int LiveRefusalStatus, string LiveRefusalBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, code, MalformedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, LiveRefusalStatus, LiveRefusalBody);
        var liveRefusalOps = hosted.StorageObservations.Skip(beforeLiveRefusal).Select(entry => entry.Operation).ToList();
        Assert.DoesNotContain(op => op == "correlate", liveRefusalOps, "A pre-correlation refusal must not correlate the grant store.");
        Assert.DoesNotContain(op => op == "load", liveRefusalOps, "A pre-correlation refusal must not load the grant store.");

        int beforeUnknownRefusal = hosted.StorageObservations.Count;
        (int UnknownRefusalStatus, string UnknownRefusalBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, "unknown-authorization-code-value", MalformedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(LiveRefusalStatus, UnknownRefusalStatus);
        Assert.AreEqual(LiveRefusalBody, UnknownRefusalBody,
            "An unknown code and a live one must answer byte-identically for a malformed verifier.");
        var unknownRefusalOps = hosted.StorageObservations.Skip(beforeUnknownRefusal).Select(entry => entry.Operation).ToList();
        Assert.DoesNotContain(op => op == "correlate", unknownRefusalOps, "A pre-correlation refusal must not correlate the grant store.");
        Assert.DoesNotContain(op => op == "load", unknownRefusalOps, "A pre-correlation refusal must not load the grant store.");

        int beforeSuccess = hosted.StorageObservations.Count;
        (int OkStatus, string OkBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, OkStatus, OkBody);
        var successOps = hosted.StorageObservations.Skip(beforeSuccess).Select(entry => entry.Operation).ToList();
        _ = Assert.ContainsSingle(op => op == "correlate", successOps,
            "A correct presentation must correlate the grant store exactly once.");
        _ = Assert.ContainsSingle(op => op == "load", successOps,
            "A correct presentation must load the grant store exactly once.");
    }


    /// <summary>
    /// Extends <see cref="MalformedVerifierRefusalTouchesNoGrantStorageAsync"/>'s storage-observation
    /// proof to the request-only refusals a declared client authentication failure, a missing
    /// credential, and a required-but-absent DPoP proof answer: the grant store shows no
    /// <c>correlate</c> and no <c>load</c> for any of them, unknown and live alike, distinguishing
    /// those grant-store operations from the authentication stores (<c>jti</c>, nonce) the
    /// pre-correlation step legitimately touches for a well-formed presentation.
    /// <see href="../../../documents/AuthorizationServerDesign.md#5-operational-ordering-on-validation">ordering section</see>.
    /// </summary>
    [TestMethod]
    public async Task AuthenticationAndDpopRefusalsAlsoTouchNoGrantStorageAsync()
    {
        const string ClientSecret = "s3cret-of-the-storage-observation-client";
        const string WrongClientSecret = "wrong-not-the-registered-secret";

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        //The registration is still undeclared (public) for PAR and authorize — this helper's PAR
        //push attaches no credential — and is upgraded to a declared confidential method only once
        //the code is issued, so redemption (not PAR) is what is under test.
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedChallenge, WellKnownCodeChallengeMethods.S256,
            TestContext.CancellationToken).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                ValueTask.FromResult(AuthCodeFlowDriver.DecodeAndMatchBasicHeader(request, registration.ClientId, ClientSecret));
        }).ConfigureAwait(false);

        _ = await host.SetTokenEndpointAuthMethodAsync(
            material, ClientAuthenticationMethod.ClientSecretBasic, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        await TestHostShell.AlterAsync(hosted.Server, candidateIntegration =>
        {
            candidateIntegration.ClientAuthenticationMethodsSupported =
                [ClientAuthenticationMethod.None, ClientAuthenticationMethod.ClientSecretBasic];
        }).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            hosted.InstallObservedStorage(candidateIntegration, hosted);
        }).ConfigureAwait(false);

        Uri tokenUri = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);
        OutgoingHeaders wrongSecretHeaders = OutgoingHeaders.Empty.WithClientSecretBasic(
            ClientId, Encoding.UTF8.GetBytes(WrongClientSecret));

        //Shape 3: a wrong client_secret_basic secret.
        int beforeLiveAuthRefusal = hosted.StorageObservations.Count;
        HttpResponseData liveAuthRefusal = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            wrongSecretHeaders, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(401, liveAuthRefusal.StatusCode, liveAuthRefusal.Body);
        AssertNoGrantStorageTouched(hosted, beforeLiveAuthRefusal, "a wrong Basic secret refusal");

        int beforeUnknownAuthRefusal = hosted.StorageObservations.Count;
        HttpResponseData unknownAuthRefusal = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, "unknown-authorization-code-value", pkce.EncodedVerifier, RedirectUri.OriginalString),
            wrongSecretHeaders, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(liveAuthRefusal.StatusCode, unknownAuthRefusal.StatusCode);
        Assert.AreEqual(liveAuthRefusal.Body, unknownAuthRefusal.Body,
            "An unknown code and a live one must answer byte-identically for a wrong Basic secret.");
        AssertNoGrantStorageTouched(hosted, beforeUnknownAuthRefusal, "a wrong Basic secret refusal");

        //Shape 4: no credentials at all.
        int beforeLiveNoCredentialRefusal = hosted.StorageObservations.Count;
        HttpResponseData liveNoCredentialRefusal = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(401, liveNoCredentialRefusal.StatusCode, liveNoCredentialRefusal.Body);
        AssertNoGrantStorageTouched(hosted, beforeLiveNoCredentialRefusal, "a no-credentials refusal");

        int beforeUnknownNoCredentialRefusal = hosted.StorageObservations.Count;
        HttpResponseData unknownNoCredentialRefusal = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, "unknown-authorization-code-value", pkce.EncodedVerifier, RedirectUri.OriginalString),
            OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(liveNoCredentialRefusal.StatusCode, unknownNoCredentialRefusal.StatusCode);
        Assert.AreEqual(liveNoCredentialRefusal.Body, unknownNoCredentialRefusal.Body,
            "An unknown code and a live one must answer byte-identically when no credentials are presented.");
        AssertNoGrantStorageTouched(hosted, beforeUnknownNoCredentialRefusal, "a no-credentials refusal");

        //Shape 5: a DPoP-required registration presenting no proof at all. A DPoP-enabled client
        //drives PAR and authorize (DPoP is not checked there, only at redemption), so the manual
        //raw pushes below are the only presentations under test.
        using VerifierKeyMaterial dpopMaterial = await host.RegisterDpopClientAsync(
            "https://dpop-required.storage-observation.test",
            new Uri("https://dpop-required.storage-observation.test"),
            capabilities: Capabilities).ConfigureAwait(false);
        string dpopSegment = dpopMaterial.Registration.TenantId.Value;

        using DpopClientFixture dpopFixture = await host.CreateDpopEnabledOAuthClientAsync(
            dpopMaterial.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient dpopBrowserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        (string dpopFlowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
            hosted, dpopFixture.Client, dpopFixture.Registration, dpopFixture.ClientFlowStore, dpopSegment, RedirectUri,
            SubjectId, dpopBrowserClient, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        AuthorizationCodeReceivedState dpopCallbackState = (AuthorizationCodeReceivedState)dpopFixture.ClientFlowStore[dpopFlowId];

        Uri dpopTokenUri = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, dpopSegment);

        int beforeLiveDpopRefusal = hosted.StorageObservations.Count;
        HttpResponseData liveDpopRefusal = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, dpopTokenUri,
            RawAuthCodeWirePushers.BuildTokenFields(
                dpopMaterial.Registration.ClientId, dpopCallbackState.Code,
                dpopCallbackState.Pkce.EncodedVerifier, dpopCallbackState.RedirectUri.OriginalString),
            OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, liveDpopRefusal.StatusCode, liveDpopRefusal.Body);
        Assert.Contains(OAuthErrors.UseDpopNonce, liveDpopRefusal.Body, StringComparison.Ordinal);
        AssertNoGrantStorageTouched(hosted, beforeLiveDpopRefusal, "a required-DPoP-proof-absent refusal");

        int beforeUnknownDpopRefusal = hosted.StorageObservations.Count;
        HttpResponseData unknownDpopRefusal = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, dpopTokenUri,
            RawAuthCodeWirePushers.BuildTokenFields(
                dpopMaterial.Registration.ClientId, "unknown-authorization-code-value",
                dpopCallbackState.Pkce.EncodedVerifier, dpopCallbackState.RedirectUri.OriginalString),
            OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(liveDpopRefusal.StatusCode, unknownDpopRefusal.StatusCode);
        Assert.AreEqual(liveDpopRefusal.Body, unknownDpopRefusal.Body,
            "An unknown code and a live one must answer byte-identically when a required DPoP proof is absent.");
        AssertNoGrantStorageTouched(hosted, beforeUnknownDpopRefusal, "a required-DPoP-proof-absent refusal");

        //A correct presentation shows one correlate and one load — the live code from shapes 3 and
        //4 is unconsumed.
        int beforeSuccess = hosted.StorageObservations.Count;
        OutgoingHeaders rightSecretHeaders = OutgoingHeaders.Empty.WithClientSecretBasic(
            ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        HttpResponseData success = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            rightSecretHeaders, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, success.StatusCode, success.Body);
        var successOps2 = hosted.StorageObservations.Skip(beforeSuccess).Select(entry => entry.Operation).ToList();
        _ = Assert.ContainsSingle(op => op == "correlate", successOps2,
            "A correct presentation must correlate the grant store exactly once.");
        _ = Assert.ContainsSingle(op => op == "load", successOps2,
            "A correct presentation must load the grant store exactly once.");
    }


    /// <summary>Pushes a valid PKCE request through the existing wire fixture to obtain a reference for authorization checks.</summary>
    private async Task<string> PushRequestUriAsync(TestHostShell host, string segment)
    {
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> fields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, fields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, statusCode, body);
        using JsonDocument response = JsonDocument.Parse(body);

        return response.RootElement.GetProperty("request_uri").GetString()!;
    }


    /// <summary>Builds a direct-authorization URL so the PKCE-shaped requests in this class share one route and parameter encoding.</summary>
    private static Uri BuildDirectAuthorizeUrl(HostedAuthorizationServer hosted, string segment, string clientId, PkceParameters pkce) =>
        new(hosted.HttpBaseAddress!,
            $"{TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeDirectAuthorize, segment)}" +
            $"?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(clientId)}" +
            $"&{OAuthRequestParameterNames.CodeChallenge}={Uri.EscapeDataString(pkce.EncodedChallenge)}" +
            $"&{OAuthRequestParameterNames.CodeChallengeMethod}={WellKnownCodeChallengeMethods.S256}" +
            $"&{OAuthRequestParameterNames.RedirectUri}={Uri.EscapeDataString(RedirectUri.OriginalString)}" +
            $"&{OAuthRequestParameterNames.Scope}={Uri.EscapeDataString(WellKnownScopes.OpenId)}" +
            $"&{OAuthRequestParameterNames.ResponseType}={WellKnownResponseTypes.Code}");


    /// <summary>
    /// Sends a pinned, non-redirecting GET to the authorization endpoint carrying exactly
    /// <paramref name="fields"/> — the general-field-map form for requests <see cref="BuildRequestUriAuthorizationUrl"/>
    /// cannot express, such as an empty <c>request_uri</c> or a bare <c>request</c> parameter.
    /// </summary>
    private Task<HttpResponseMessage> SendAuthorizeGetAsync(
        TestHostShell host, HostedAuthorizationServer hosted, string segment, IReadOnlyDictionary<string, string> fields)
    {
        string query = string.Join("&", fields.Select(pair =>
            $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));
        Uri uri = new(hosted.HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment) + "?" + query);

        return RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, uri, SubjectId, TestContext.CancellationToken);
    }


    /// <summary>Builds a reference-based authorization URL so refusal tests use the same route and parameter encoding.</summary>
    private static Uri BuildRequestUriAuthorizationUrl(
        HostedAuthorizationServer hosted, string segment, string requestUri, string? clientId)
    {
        string clientQuery = clientId switch
        {
            null => string.Empty,
            _ => $"&{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(clientId)}"
        };

        return new Uri(hosted.HttpBaseAddress!,
            $"{TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment)}" +
            $"?{OAuthRequestParameterNames.RequestUri}={Uri.EscapeDataString(requestUri)}{clientQuery}");
    }


    /// <summary>
    /// Asserts that <see cref="HostedAuthorizationServer.StorageObservations"/> recorded NO flow-state
    /// store operation of ANY kind since <paramref name="before"/>. Delegates to
    /// <see cref="HostedAuthorizationServer.AssertNoFlowStateStoreOperationTouched"/>, whose remarks
    /// explain why every operation (not only <c>correlate</c>/<c>load</c>) is checked and why zero
    /// is the exact expected count for the shapes this helper covers.
    /// </summary>
    private static void AssertNoGrantStorageTouched(HostedAuthorizationServer hosted, int before, string context) =>
        hosted.AssertNoFlowStateStoreOperationTouched(before, context);


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7">RFC 7519 section 4.1.7</see>: "The "jti"
    /// (JWT ID) claim provides a unique identifier for the JWT." and "The identifier value MUST be assigned in a
    /// manner that ensures that there is a negligible probability that the same value will be accidentally
    /// assigned to a different data object; if the application uses multiple issuers, collisions MUST be
    /// prevented among values produced by different issuers as well." Every ID Token the authorization server
    /// issues carries its own identifier: two code redemptions for one subject and one client and a refresh of
    /// the first, all at one instant over the real wire, return three ID Tokens whose <c>jti</c> values are
    /// non-empty strings that differ from one another.
    /// </summary>
    [TestMethod]
    public async Task EveryIdTokenCarriesADistinctJti()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: CapabilitiesWithOpenIdConnect)
            .ConfigureAwait(false);

        (OAuthClient firstClient, ClientRegistration firstRegistration, Dictionary<string, FlowState> firstFlowStore) =
            await ComposeResourceJourneyClientAsync(host, material).ConfigureAwait(false);

        //A second client instance of the same registration keeps its own flow store, so each store holds one flow.
        (OAuthClient secondClient, ClientRegistration secondRegistration, Dictionary<string, FlowState> secondFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        string firstFlowId = await DriveParAuthorizeAndCallbackAsync(
            hosted, firstClient, firstRegistration, firstFlowStore, segment, host.ServerCertificate,
            TestContext.CancellationToken).ConfigureAwait(false);
        string secondFlowId = await DriveParAuthorizeAndCallbackAsync(
            hosted, secondClient, secondRegistration, secondFlowStore, segment, host.ServerCertificate,
            TestContext.CancellationToken).ConfigureAwait(false);

        //The clock is not advanced: both redemptions and the refresh run at one instant.
        AuthCodeFlowEndpointResult firstResult = await firstClient.AuthCode.ExchangeTokenAsync(
            firstRegistration, firstFlowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstResult.Outcome,
            $"The first code redemption must succeed over the real wire. ErrorCode={firstResult.ErrorCode} ErrorDescription={firstResult.ErrorDescription}");

        AuthCodeFlowEndpointResult secondResult = await secondClient.AuthCode.ExchangeTokenAsync(
            secondRegistration, secondFlowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, secondResult.Outcome,
            $"The second code redemption must succeed over the real wire. ErrorCode={secondResult.ErrorCode} ErrorDescription={secondResult.ErrorDescription}");

        AuthCodeFlowEndpointResult refreshResult = await firstClient.AuthCode.RefreshAsync(
            firstRegistration,
            new RefreshTokenRequest
            {
                ClientId = ClientId,
                RefreshToken = (string)firstResult.Body![OAuthRequestParameterNames.RefreshToken]
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, refreshResult.Outcome,
            $"The refresh must succeed over the real wire. ErrorCode={refreshResult.ErrorCode} ErrorDescription={refreshResult.ErrorDescription}");

        string firstJti = ReadIdTokenJti(firstResult.Body!, "the ID Token of the first code redemption");
        string secondJti = ReadIdTokenJti(secondResult.Body!, "the ID Token of the second code redemption");
        string refreshedJti = ReadIdTokenJti(refreshResult.Body!, "the ID Token of the refresh");

        Assert.AreNotEqual(firstJti, secondJti,
            "The ID Tokens of two code redemptions at one instant must carry different jti values.");
        Assert.AreNotEqual(firstJti, refreshedJti,
            "The ID Token of a refresh must carry a jti other than the one of the ID Token it follows.");
        Assert.AreNotEqual(secondJti, refreshedJti,
            "The ID Token of a refresh must carry a jti other than the one of another code redemption's ID Token.");
    }


    /// <summary>
    /// Reads the <c>jti</c> of the ID Token the token response <paramref name="body"/> carries, asserting that the
    /// response carries an ID Token and that its <c>jti</c> member is a JSON string that is not empty, the shape
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7">RFC 7519 section 4.1.7</see> gives the claim:
    /// "The "jti" value is a case-sensitive string."
    /// </summary>
    /// <param name="body">The token endpoint's response members as the client decoded them off the wire.</param>
    /// <param name="tokenDescription">The ID Token's name in the assertion messages.</param>
    /// <returns>The ID Token's <c>jti</c> value.</returns>
    private static string ReadIdTokenJti(IReadOnlyDictionary<string, object> body, string tokenDescription)
    {
        Assert.IsTrue(body.TryGetValue(OAuthRequestParameterNames.IdToken, out object? token) && token is string { Length: > 0 },
            $"The response must carry {tokenDescription}.");
        using JsonDocument payload = JwtPayloadReader.ParsePayloadJson((string)token);
        Assert.IsTrue(payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.Jti, out JsonElement jti),
            $"The payload of {tokenDescription} must carry a jti member.");
        Assert.AreEqual(JsonValueKind.String, jti.ValueKind,
            $"The jti of {tokenDescription} must be a JSON string.");
        string value = jti.GetString()!;
        Assert.IsFalse(string.IsNullOrEmpty(value),
            $"The jti of {tokenDescription} must not be empty.");

        return value;
    }
}
