using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Introspection;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Real-wire capstone for the Authorization Code + PAR + PKCE family: every
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
    /// <see cref="Capabilities"/> plus RFC 7662 introspection, for the replay tests that prove a
    /// revoked access token is refused afterwards at a path the suite already has.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> CapabilitiesWithIntrospection { get; } =
        Capabilities.Add(WellKnownCapabilityIdentifiers.OAuthTokenIntrospection);


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
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.6">RFC 7636 §4.6</see>: "If the
    /// 'code_challenge_method' from Section 4.3 was 'plain' ... code_verifier == code_challenge."
    /// A <c>plain</c>-method journey under <see cref="PolicyProfile.Rfc6749WithPkce"/> (which
    /// resolves <see cref="PkceMethodSet.S256AndPlain"/>) completes PAR -> authorize -> token over
    /// the real wire — the client SDK is S256-only, so <see cref="RawAuthCodeWirePushers"/> drives
    /// this wire shape directly.
    /// </summary>
    [TestMethod]
    public async Task PlainPkceJourneyCompletesUnderRfc6749WithPkce()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        string segment = material.Registration.TenantId.Value;

        //RFC 7636 §4.6: under "plain", code_verifier == code_challenge — no hashing.
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedVerifier, WellKnownCodeChallengeMethods.Plain,
            TestContext.CancellationToken).ConfigureAwait(false);

        (int TokenStatusCode, string TokenBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, TokenStatusCode,
            $"A plain PKCE journey under the RFC 6749 + RFC 7636 baseline policy must complete. Body={TokenBody}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.6">RFC 7636 §4.6</see>'s plain
    /// comparison is exact: a plain-issued code presented with a verifier that does not equal the
    /// challenge captured at PAR time fails <c>invalid_grant</c>, exactly as the S256 branch fails
    /// on a digest mismatch.
    /// </summary>
    [TestMethod]
    public async Task PlainPkceWrongVerifierAtTokenExchangeIsInvalidGrant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, pkce.EncodedVerifier, WellKnownCodeChallengeMethods.Plain,
            TestContext.CancellationToken).ConfigureAwait(false);

        (int TokenStatusCode, string TokenBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, code, "wrong0000000000000000000000000000000000000", RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, TokenStatusCode, TokenBody);
        Assert.Contains(OAuthErrors.InvalidGrant, TokenBody, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.1">RFC 7636 §4.1</see>:
    /// "code-verifier = 43*128unreserved" — a verifier under 43 characters is refused
    /// <c>invalid_grant</c> even when it is byte-identical to the persisted <c>plain</c>
    /// challenge. A literal comparison alone would accept it (<c>plain</c> compares the
    /// presented verifier to the challenge with no hashing), so this proves the length check
    /// runs and rejects before that comparison, not merely that a mismatched verifier fails.
    /// </summary>
    [TestMethod]
    public async Task TooShortCodeVerifierAtTokenExchangeIsInvalidGrant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        string segment = material.Registration.TenantId.Value;

        //A 42-character value: one short of RFC 7636 §4.1's 43-character minimum. Used as BOTH
        //the plain code_challenge and, at redemption, the presented code_verifier — under a bare
        //literal comparison the two are identical and PKCE would incorrectly verify.
        string tooShortVerifier = new('a', 42);
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, tooShortVerifier, WellKnownCodeChallengeMethods.Plain,
            TestContext.CancellationToken).ConfigureAwait(false);

        (int TokenStatusCode, string TokenBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, code, tooShortVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, TokenStatusCode, TokenBody);
        Assert.Contains(OAuthErrors.InvalidGrant, TokenBody, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.1">RFC 7636 §4.1</see>:
    /// "unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"" — a verifier of the correct length
    /// but containing a character outside this set is refused <c>invalid_grant</c> even though
    /// it is byte-identical to the persisted <c>plain</c> challenge, proving the character-set
    /// check runs independently of the length check and of the literal comparison.
    /// </summary>
    [TestMethod]
    public async Task CodeVerifierWithDisallowedCharacterAtTokenExchangeIsInvalidGrant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        string segment = material.Registration.TenantId.Value;

        //43 characters — RFC 7636 §4.1's minimum length — but the trailing '+' is outside
        //"unreserved". Used as BOTH the plain code_challenge and, at redemption, the presented
        //code_verifier, so a bare literal comparison would accept it.
        string verifierWithDisallowedCharacter = new string('a', 42) + "+";
        string code = await DriveRawParAndAuthorizeAsync(
            host, segment, verifierWithDisallowedCharacter, WellKnownCodeChallengeMethods.Plain,
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
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §7.5.2</see>: "The plain code challenge method, defined in [RFC7636], is
    /// explicitly forbidden in OAuth 2.1." Under the strict <see cref="PolicyProfile.Fapi20"/>
    /// default (<see cref="PkceMethodSet.S256Only"/>), a PAR request naming <c>plain</c> is
    /// refused over the real wire before any code is ever issued.
    /// </summary>
    [TestMethod]
    public async Task PlainPkceRefusedAtParUnderS256OnlyDefault()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Fapi20, capabilities: Capabilities);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.Plain,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, parFields, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidRequest, Body, StringComparison.Ordinal);
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
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
    /// <see cref="RawAuthCodeWirePushers"/> rather than <see cref="AuthCodeClient.ExchangeTokenAsync"/>
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, material.Registration.TenantId.Value,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, code: null, codeVerifier: "verifier-does-not-matter", redirectUri: RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains(OAuthErrors.InvalidRequest, Body, StringComparison.Ordinal);
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);

        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);

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
        //subset — the client SDK's ExchangeTokenAsync carries no resource parameter of its own, so
        //this drives AuthCodeFlowHandlers.HandleTokenAsync's resource-bearing overload directly,
        //exactly as AuthCodeClient.ExchangeTokenAsync does internally for every other field.
        AuthCodeFlowEndpointResult tokenResult = await AuthCodeFlowHandlers.HandleTokenAsync(
            new Dictionary<string, string>
            {
                [AuthCodeFlowRoutes.FlowIdField] = flowId
            },
            client.Infrastructure,
            registration,
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
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-4">RFC 9126 §4</see>: "the client
    /// MUST only use a <c>request_uri</c> value once. Authorization servers SHOULD treat
    /// <c>request_uri</c> values as one-time use but MAY allow for duplicate requests due to a
    /// user reloading/refreshing their user agent." This library elects the SHOULD unconditionally
    /// and does not offer the reload/refresh MAY. N concurrent authorize GETs against the identical
    /// <c>request_uri</c> race against the same claim as the token endpoint's code redemption; the
    /// invariants under test — never which request wins — are that exactly one response carries an
    /// issued <c>code</c>, and that a losing claim on the request_uri is reported via the RFC 6749
    /// §4.1.2.1 redirect rather than a bare response body.
    /// </summary>
    [TestMethod]
    public async Task ConcurrentAuthorizeRequestsForTheSameRequestUriYieldExactlyOneIssuedCode()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
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
        Task<HttpResponseMessage>[] authorizeCalls = [.. Enumerable.Range(0, ConcurrentRequests)
            .Select(_ => RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
                host, authorizeUrl, SubjectId, TestContext.CancellationToken))];

        HttpResponseMessage[] responses = await Task.WhenAll(authorizeCalls).ConfigureAwait(false);
        try
        {
            int issuedCodeCount = responses.Count(r =>
                (int)r.StatusCode == 302
                && r.Headers.Location!.Query.Contains($"{OAuthRequestParameterNames.Code}=", StringComparison.Ordinal));
            Assert.AreEqual(1, issuedCodeCount,
                "RFC 9126 §4: request_uri is single-use — exactly one concurrent authorize GET may consume it.");

            //A losing claim on the request_uri is reported via the RFC 6749 §4.1.2.1 redirect
            //(never a bare response body — see conformance fix at the claim site); a request whose
            //load raced past the winner's save onto a state that is not a pending pushed request
            //takes a separate, unrelated refusal shape. The invariant that belongs to THIS clause is
            //narrower than "every loser is a redirect": no response — of either shape — ever
            //carries the request_uri-already-used refusal in a bare body.
            foreach(HttpResponseMessage response in responses)
            {
                if((int)response.StatusCode == 400)
                {
                    string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken)
                        .ConfigureAwait(false);
                    Assert.DoesNotContain("already been used", body, StringComparison.Ordinal,
                        "The request_uri-already-used refusal must ride the RFC 6749 §4.1.2.1 redirect, never a bare response body.");
                }
            }
        }
        finally
        {
            foreach(HttpResponseMessage response in responses)
            {
                response.Dispose();
            }
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
        AuthorizationCodeReceivedState codeState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        Dictionary<string, string> tokenFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, codeState.Code, codeState.Pkce.EncodedVerifier, RedirectUri.OriginalString);

        const int ConcurrentRequests = 8;

        int arrivedAtLiveState = 0;
        TaskCompletionSource releaseGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        LoadServerFlowStateDelegate originalLoad = host.Server.OAuth().LoadFlowStateAsync!;
        host.Server.OAuth().LoadFlowStateAsync = async (tenantId, key, ctx, ct) =>
        {
            (FlowState? state, int stepCount) = await originalLoad(tenantId, key, ctx, ct).ConfigureAwait(false);
            if(state is ServerCodeIssuedState)
            {
                if(Interlocked.Increment(ref arrivedAtLiveState) == ConcurrentRequests)
                {
                    _ = releaseGate.TrySetResult();
                }
                await releaseGate.Task.ConfigureAwait(false);
            }

            return (state, stepCount);
        };

        Task<(int StatusCode, string Body)>[] redemptions = [.. Enumerable.Range(0, ConcurrentRequests)
            .Select(_ => RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, tokenFields, TestContext.CancellationToken))];

        (int StatusCode, string Body)[] responses = await Task.WhenAll(redemptions).ConfigureAwait(false);

        _ = Assert.ContainsSingle(r => r.StatusCode == 200, responses,
            $"Exactly one concurrent redemption of the same code must succeed. Bodies: {string.Join(" | ", responses.Select(r => r.Body))}");
        Assert.AreEqual(ConcurrentRequests - 1,
            responses.Count(r => r.StatusCode == 400
                && r.Body.Contains(OAuthErrors.InvalidGrant, StringComparison.Ordinal)),
            $"Every losing concurrent redemption must fail invalid_grant. Bodies: {string.Join(" | ", responses.Select(r => r.Body))}");
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: CapabilitiesWithIntrospection);

        HashSet<string> revokedJtis = new(StringComparer.Ordinal);
        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);
        host.Server.OAuth().RevokeIssuedTokenAsync = (tokenIdentifier, tokenType, _, _, _) =>
        {
            _ = revokedJtis.Add(tokenIdentifier);

            return ValueTask.CompletedTask;
        };
        host.Server.OAuth().IntrospectTokenAsync = (token, hint, _, _, _) =>
        {
            using JsonDocument payload = DecodePayload(token);
            string jti = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Jti).GetString()!;

            return ValueTask.FromResult(new TokenIntrospectionResult { IsActive = !revokedJtis.Contains(jti) });
        };

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
    /// token has already rotated at least once since the code was redeemed:
    /// <see cref="ServerTokenIssuedState.RefreshFlowId"/> names the code-issued refresh record,
    /// which by the time of the replay is itself already retired (carrying a
    /// <see cref="ServerTokenIssuedState.SuccessorRefreshFlowId"/> link) rather than a live
    /// <see cref="ServerRefreshTokenIssuedState"/> — the replay handler must walk that link to the
    /// family's live end rather than deleting only that immediate, already-dead record.
    /// </summary>
    [TestMethod]
    public async Task ValidReplayAfterTheRefreshTokenHasAlreadyRotatedRevokesTheCurrentSuccessorAsync()
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
        AuthorizationCodeReceivedState codeState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string codeIssuedRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        //A single legitimate rotation BEFORE the replay — the code's own RefreshFlowId now names
        //an already-retired record, not the family's live refresh token.
        (int StatusCode, string Body) rotation = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, codeIssuedRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, rotation.StatusCode, rotation.Body);
        string currentRefreshToken;
        string currentAccessToken;
        using(JsonDocument rotationDoc = JsonDocument.Parse(rotation.Body))
        {
            currentAccessToken = rotationDoc.RootElement.GetProperty(
                OAuthRequestParameterNames.AccessToken).GetString()!;
            currentRefreshToken = rotationDoc.RootElement.GetProperty(
                OAuthRequestParameterNames.RefreshToken).GetString()!;
        }

        HashSet<string> revokedJtis = [];
        host.Server.OAuth().RevokeIssuedTokenAsync = (jti, _, _, _, _) =>
        {
            _ = revokedJtis.Add(jti);

            return ValueTask.CompletedTask;
        };

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
        AuthorizationCodeReceivedState codeState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string codeIssuedRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        (int StatusCode, string Body) rotation = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, codeIssuedRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, rotation.StatusCode, rotation.Body);
        string currentRefreshToken;
        using(JsonDocument rotationDoc = JsonDocument.Parse(rotation.Body))
        {
            currentRefreshToken = rotationDoc.RootElement.GetProperty(
                OAuthRequestParameterNames.RefreshToken).GetString()!;
        }

        var originalClaim = host.Server.OAuth().ClaimFlowStateAsync;
        int claimCalls = 0;
        host.Server.OAuth().ClaimFlowStateAsync = (_, _, _, _, _) =>
        {
            if(++claimCalls > 2)
            {
                throw new InvalidOperationException("A family walk must stop after its bounded claim retry.");
            }

            return ValueTask.FromResult(false);
        };

        (int StatusCode, string Body) firstReplay = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, codeState.Code, codeState.Pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, firstReplay.StatusCode, firstReplay.Body);
        host.Server.OAuth().ClaimFlowStateAsync = originalClaim;

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
    /// presentation is still denied, but per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009#section-2.2">RFC 7009 §2.2</see> "the
    /// purpose of the revocation request ... is already achieved" once the first replay revoked
    /// the tokens, so a second and third valid replay must not re-invoke
    /// <see cref="AuthorizationServerIntegration.RevokeIssuedTokenAsync"/> — proven as an
    /// invariant on the call count, not on which path fired. The
    /// <see cref="ServerTokenIssuedState.RevokedAt"/> marker the first replay writes is directly
    /// observable on the test host's persisted state.
    /// </summary>
    [TestMethod]
    public async Task SecondAndThirdValidReplayDoNotReinvokeRevocationAndTheMarkerPersists()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: CapabilitiesWithIntrospection);

        int revokeCallCount = 0;
        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);
        host.Server.OAuth().RevokeIssuedTokenAsync = (_, _, _, _, _) =>
        {
            _ = Interlocked.Increment(ref revokeCallCount);

            return ValueTask.CompletedTask;
        };

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

        (int StatusCode, string Body) secondPresentation = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, replayFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, secondPresentation.StatusCode, secondPresentation.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, secondPresentation.Body, StringComparison.Ordinal);

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: CapabilitiesWithIntrospection);

        //RevokeIssuedTokenAsync deliberately left unwired.
        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);
        host.Server.OAuth().IntrospectTokenAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(new TokenIntrospectionResult { IsActive = true });

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

        (int StatusCode, string Body) replay = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment,
            RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, codeState.Code, codeState.Pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, replay.StatusCode, replay.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, replay.Body, StringComparison.Ordinal);

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

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string firstRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        Dictionary<string, string> refreshFields = RawAuthCodeWirePushers.BuildRefreshTokenFields(
            ClientId, firstRefreshToken);

        const int ConcurrentRequests = 8;

        string refreshFlowId = hosted.RefreshTokenIndex[firstRefreshToken];
        int revokeCalls = 0;
        host.Server.OAuth().RevokeIssuedTokenAsync = (_, _, _, _, _) =>
        {
            _ = Interlocked.Increment(ref revokeCalls);

            return ValueTask.CompletedTask;
        };
        int initialLiveRecords = hosted.FlowStates.Values.Count(entry => entry.State is ServerRefreshTokenIssuedState);
        int arrivedAtLiveState = 0;
        TaskCompletionSource releaseGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        LoadServerFlowStateDelegate originalLoad = host.Server.OAuth().LoadFlowStateAsync!;
        host.Server.OAuth().LoadFlowStateAsync = async (tenantId, key, ctx, ct) =>
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

        Task<(int StatusCode, string Body)>[] rotations = [.. Enumerable.Range(0, ConcurrentRequests)
            .Select(_ => RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, refreshFields, TestContext.CancellationToken))];

        (int StatusCode, string Body)[] responses = await Task.WhenAll(rotations).ConfigureAwait(false);

        host.Server.OAuth().LoadFlowStateAsync = originalLoad;

        (int StatusCode, string Body) successful = Assert.ContainsSingle(r => r.StatusCode == 200, responses,
            $"Exactly one concurrent rotation of the same refresh token must succeed. Bodies: {string.Join(" | ", responses.Select(r => r.Body))}");
        Assert.AreEqual(ConcurrentRequests - 1,
            responses.Count(r => r.StatusCode == 400
                && r.Body.Contains(OAuthErrors.InvalidGrant, StringComparison.Ordinal)),
            $"Every losing concurrent rotation must fail invalid_grant. Bodies: {string.Join(" | ", responses.Select(r => r.Body))}");
        Assert.AreEqual(0, revokeCalls, "Losing claims must not revoke any issued token.");
        Assert.AreEqual(initialLiveRecords,
            hosted.FlowStates.Values.Count(entry => entry.State is ServerRefreshTokenIssuedState),
            "One consumed live record must be replaced by exactly one live successor.");
        using JsonDocument successfulDocument = JsonDocument.Parse(successful.Body);
        string successor = successfulDocument.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!;
        (int StatusCode, string Body) next = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, successor),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, next.StatusCode, "Losing claims must leave the issued successor usable.");
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);

        HashSet<string> revokedJtis = [];
        host.Server.OAuth().RevokeIssuedTokenAsync = (jti, _, _, _, _) =>
        {
            _ = revokedJtis.Add(jti);

            return ValueTask.CompletedTask;
        };

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
        (int StatusCode, string Body) rotation1 = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, oldestRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, rotation1.StatusCode, rotation1.Body);
        string middleRefreshToken;
        string middleAccessTokenJti;
        using(JsonDocument rotation1Doc = JsonDocument.Parse(rotation1.Body))
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
            (int StatusCode, string Body) rotation = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, currentRefreshToken),
                TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, rotation.StatusCode, $"Rotation {rotationIndex} must succeed. Body={rotation.Body}");

            using JsonDocument rotationDoc = JsonDocument.Parse(rotation.Body);
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

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string oldestRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        (int StatusCode, string Body) rotation1 = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, oldestRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, rotation1.StatusCode, rotation1.Body);
        string currentRefreshToken;
        using(JsonDocument rotation1Doc = JsonDocument.Parse(rotation1.Body))
        {
            currentRefreshToken = rotation1Doc.RootElement.GetProperty(
                OAuthRequestParameterNames.RefreshToken).GetString()!;
        }

        //A VALID reuse of the ORIGINAL (once-rotated-out) token races a LEGITIMATE rotation of the
        //family's current successor — both requests reach the same live flow record.
        Dictionary<string, string> reuseFields =
            RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, oldestRefreshToken);
        Dictionary<string, string> rotateFields =
            RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, currentRefreshToken);

        string currentFlowId = hosted.RefreshTokenIndex[currentRefreshToken];
        TaskCompletionSource walkObservedLive = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource rotationRetiredLive = new(TaskCreationOptions.RunContinuationsAsynchronously);
        LoadServerFlowStateDelegate originalLoad = host.Server.OAuth().LoadFlowStateAsync!;
        SaveServerFlowStateDelegate originalSave = host.Server.OAuth().SaveFlowStateAsync!;
        DeleteServerFlowStateDelegate originalDelete = host.Server.OAuth().DeleteFlowStateAsync!;
        host.Server.OAuth().LoadFlowStateAsync = async (tenantId, key, ctx, ct) =>
        {
            (FlowState? state, int stepCount) = await originalLoad(tenantId, key, ctx, ct).ConfigureAwait(false);
            bool isPausedReader = isReuseClaimFirst ? ctx.FlowId == key : ctx.FlowId != key;
            if(key == currentFlowId && isPausedReader && state is ServerRefreshTokenIssuedState)
            {
                _ = walkObservedLive.TrySetResult();
                await rotationRetiredLive.Task.WaitAsync(ct).ConfigureAwait(false);
            }

            return (state, stepCount);
        };
        host.Server.OAuth().SaveFlowStateAsync = async (tenantId, key, state, stepCount, ctx, ct) =>
        {
            await originalSave(tenantId, key, state, stepCount, ctx, ct).ConfigureAwait(false);
            if(key == currentFlowId && state is ServerTokenIssuedState)
            {
                _ = rotationRetiredLive.TrySetResult();
            }
        };

        host.Server.OAuth().DeleteFlowStateAsync = async (tenantId, key, ctx, ct) =>
        {
            await originalDelete(tenantId, key, ctx, ct).ConfigureAwait(false);
            if(isReuseClaimFirst && key == currentFlowId)
            {
                _ = rotationRetiredLive.TrySetResult();
            }
        };

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
        host.Server.OAuth().LoadFlowStateAsync = originalLoad;
        host.Server.OAuth().SaveFlowStateAsync = originalSave;
        host.Server.OAuth().DeleteFlowStateAsync = originalDelete;
        (int StatusCode, string Body) reuseResult = results[0];
        (int StatusCode, string Body) rotateResult = results[1];

        Assert.AreEqual(400, reuseResult.StatusCode, reuseResult.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, reuseResult.Body, StringComparison.Ordinal);

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
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see> requires refresh replay detection: "Authorization servers MUST utilize
    /// one of these methods to detect refresh token replay by malicious actors for public clients".
    /// The retired <see cref="ServerTokenIssuedState"/> a rotation leaves behind must outlive the
    /// access token it was minted alongside, per
    /// <see cref="AuthCodeServerFlowInputs.ServerTokenExchangeSucceeded.ExpiresAt"/>'s remarks: it
    /// carries at least the freshly-minted successor refresh token's own expiry, never merely the
    /// one-hour default access-token lifetime. The clock advances past that access-token lifetime
    /// but stays well inside the 30-day default refresh-token lifetime, then a reuse of the
    /// rotated-out token still reaches reuse detection instead of a stale-record miss.
    /// </summary>
    [TestMethod]
    public async Task ReuseAfterAccessTokenExpiryStillRevokesTheSuccessor()
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

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string retiredRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        (int StatusCode, string Body) rotation = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, retiredRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, rotation.StatusCode, rotation.Body);
        string successorRefreshToken;
        using(JsonDocument rotationDoc = JsonDocument.Parse(rotation.Body))
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
    /// reuse presentation (the wrong <c>client_id</c>) of a rotated-out refresh token is refused
    /// <c>invalid_grant</c> exactly as a valid reuse would be, but revokes nothing — the
    /// denial-of-service reasoning
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §7.5.3</see> applies to a code replay applies identically here: an attacker who
    /// merely observed the spent token must not be able to deny the legitimate holder service by
    /// presenting it with the wrong client. The successor remains usable afterward.
    /// </summary>
    [TestMethod]
    public async Task InvalidReuseOfRotatedOutRefreshTokenLeavesTheSuccessorUsable()
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

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string retiredRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        (int StatusCode, string Body) rotation = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, retiredRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, rotation.StatusCode, rotation.Body);
        string successorRefreshToken;
        using(JsonDocument rotationDoc = JsonDocument.Parse(rotation.Body))
        {
            successorRefreshToken = rotationDoc.RootElement.GetProperty(
                OAuthRequestParameterNames.RefreshToken).GetString()!;
        }

        //An INVALID reuse of the just-retired token: the wrong client_id.
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
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see> client
    /// identification on a reuse presentation is held to the SAME bar
    /// <see cref="BuildRefreshToken"/>'s live rotation path holds a live presentation to: a form
    /// omitting <c>client_id</c> entirely is an INVALID presentation — exactly as it is against a
    /// still-live refresh token — never a fallback to the tenant's resolved registration. A bare
    /// <c>grant_type=refresh_token&amp;refresh_token=&lt;retired&gt;</c> revokes nothing and the
    /// successor remains usable.
    /// </summary>
    [TestMethod]
    public async Task ReuseOfRotatedOutRefreshTokenWithNoFormClientIdLeavesTheSuccessorUsableAsync()
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

        AuthCodeFlowEndpointResult firstExchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstExchange.Outcome,
            $"The first redemption must succeed. ErrorCode={firstExchange.ErrorCode}");
        string retiredRefreshToken = (string)firstExchange.Body![OAuthRequestParameterNames.RefreshToken];

        (int StatusCode, string Body) rotation = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, retiredRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, rotation.StatusCode, rotation.Body);
        string successorRefreshToken;
        using(JsonDocument rotationDoc = JsonDocument.Parse(rotation.Body))
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
        Assert.Contains(OAuthErrors.InvalidGrant, reuse.Body, StringComparison.Ordinal);

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
    /// <see cref="Verifiable.OAuth.AuthCode.Server.DpopTokenEndpointValidation.ValidateAsync"/>
    /// runs on every refresh-token reuse presentation, bound or not — mirroring
    /// <see cref="BuildRefreshToken"/>'s own unconditional call on a live rotation — so a
    /// structurally malformed DPoP proof attached to a reuse of a retired BEARER (unbound)
    /// refresh token is an INVALID presentation, exactly as the same malformed proof would refuse
    /// a live Bearer rotation, rather than being silently ignored because no thumbprint was ever
    /// bound to compare against. Revokes nothing; the successor remains usable.
    /// </summary>
    [TestMethod]
    public async Task ReuseOfRotatedOutBearerRefreshTokenWithMalformedDpopProofIsRefusedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);

        //DPoP delegates must be wired for DpopTokenEndpointValidation to evaluate the attached
        //proof at all — this test's client itself never binds a token to a key (Bearer issuance),
        //so wiring here proves the unconditional call, not a policy requiring DPoP.
        _ = host.EnableDpop();

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

        (int StatusCode, string Body) rotation = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, retiredRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, rotation.StatusCode, rotation.Body);
        string successorRefreshToken;
        using(JsonDocument rotationDoc = JsonDocument.Parse(rotation.Body))
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
        Assert.AreEqual(400, reuse.StatusCode, reuse.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, reuse.Body, StringComparison.Ordinal);

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: CapabilitiesWithIntrospection);

        bool revokeInvoked = false;
        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);
        host.Server.OAuth().RevokeIssuedTokenAsync = (_, _, _, _, _) =>
        {
            revokeInvoked = true;
            return ValueTask.CompletedTask;
        };
        host.Server.OAuth().IntrospectTokenAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(new TokenIntrospectionResult { IsActive = true });

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
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
    /// S256 challenge of its own.
    /// </summary>
    private static async Task<string> DriveRawParAndAuthorizeAsync(
        TestHostShell host, string segment, string codeChallenge, string codeChallengeMethod,
        CancellationToken cancellationToken)
    {
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = codeChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = codeChallengeMethod,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };

        (int ParStatusCode, string ParBody) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, parFields, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, ParStatusCode, ParBody);

        using JsonDocument parBody = JsonDocument.Parse(ParBody);
        string requestUri = parBody.RootElement.GetProperty("request_uri").GetString()!;

        HostedAuthorizationServer hosted = host.Host("default");
        Uri authorizeUrl = new(
            hosted.HttpBaseAddress!,
            $"{TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment)}" +
            $"?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(ClientId)}" +
            $"&{OAuthRequestParameterNames.RequestUri}={Uri.EscapeDataString(requestUri)}");

        using HttpResponseMessage authorizeResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, authorizeUrl, SubjectId, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, (int)authorizeResponse.StatusCode,
            "The authorize endpoint must redirect with the authorization code.");

        string location = authorizeResponse.Headers.Location!.ToString();

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
        (int StatusCode, string Body) response = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument document = JsonDocument.Parse(response.Body);

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
        (int StatusCode, string Body) response = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, refreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument document = JsonDocument.Parse(response.Body);

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        string segment = material.Registration.TenantId.Value;
        (string original, _) = await IssueBearerPairAsync(host, segment).ConfigureAwait(false);
        (string reused, string pairedAccessToken) = await RotateBearerPairAsync(host, segment, original).ConfigureAwait(false);
        _ = await RotateBearerPairAsync(host, segment, reused).ConfigureAwait(false);
        HashSet<string> revokedJtis = [];
        host.Server.OAuth().RevokeIssuedTokenAsync = (jti, _, _, _, _) =>
        {
            _ = revokedJtis.Add(jti);

            return ValueTask.CompletedTask;
        };

        (int StatusCode, string Body) response = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, reused),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(JwtPayloadReader.ReadJti(pairedAccessToken)!, revokedJtis,
            "The predecessor audit must revoke the access token paired with the reused refresh token.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009#section-2.2">RFC 7009 §2.2</see>:
    /// "the purpose of the revocation request, invalidating the particular token, is already
    /// achieved." A second sequential valid refresh reuse keeps the persisted revocation marker
    /// and refuses without repeating the family loads or audit revocations.
    /// </summary>
    [TestMethod]
    public async Task SecondValidRefreshReuseDoesNotRepeatRevocationAndTheMarkerPersists()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        string segment = material.Registration.TenantId.Value;
        (string original, _) = await IssueBearerPairAsync(host, segment).ConfigureAwait(false);
        _ = await RotateBearerPairAsync(host, segment, original).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string retiredFlowId = hosted.RefreshTokenIndex[original];
        int revocationCalls = 0;
        int familyLoads = 0;
        LoadServerFlowStateDelegate originalLoad = host.Server.OAuth().LoadFlowStateAsync!;
        host.Server.OAuth().LoadFlowStateAsync = (tenantId, key, ctx, ct) =>
        {
            if(key != retiredFlowId)
            {
                ++familyLoads;
            }

            return originalLoad(tenantId, key, ctx, ct);
        };
        host.Server.OAuth().RevokeIssuedTokenAsync = (_, _, _, _, _) =>
        {
            ++revocationCalls;

            return ValueTask.CompletedTask;
        };
        Dictionary<string, string> fields = RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, original);
        (int StatusCode, string Body) first = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, fields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, first.StatusCode, first.Body);
        ServerTokenIssuedState retired = (ServerTokenIssuedState)hosted.FlowStates[retiredFlowId].State;
        Assert.IsNotNull(retired.RevokedAt, "A valid refresh reuse must persist RevokedAt.");
        int callsAfterFirst = revocationCalls;
        int loadsAfterFirst = familyLoads;
        Assert.IsGreaterThan(0, callsAfterFirst);
        Assert.IsGreaterThan(0, loadsAfterFirst);

        (int StatusCode, string Body) second = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, fields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(first, second, "Sequential reuse must keep the same refusal response.");
        Assert.AreEqual(callsAfterFirst, revocationCalls, "Sequential reuse must not repeat audit revocation.");
        Assert.AreEqual(loadsAfterFirst, familyLoads, "Sequential reuse must not repeat the family walk.");
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        string segment = material.Registration.TenantId.Value;
        (string original, _) = await IssueBearerPairAsync(host, segment).ConfigureAwait(false);
        (int StatusCode, string Body) refusal = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(null, original),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, refusal.StatusCode, "A public refresh must identify its bound client.");
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        string segment = material.Registration.TenantId.Value;
        (string original, _) = await IssueBearerPairAsync(host, segment).ConfigureAwait(false);
        (string successor, _) = await RotateBearerPairAsync(host, segment, original).ConfigureAwait(false);
        var originalClaim = host.Server.OAuth().ClaimFlowStateAsync;
        int claimCalls = 0;
        host.Server.OAuth().ClaimFlowStateAsync = (_, _, _, _, _) =>
        {
            if(++claimCalls > 2)
            {
                throw new InvalidOperationException("A family walk must stop after its bounded claim retry.");
            }

            return ValueTask.FromResult(false);
        };

        (int StatusCode, string Body) reuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, original),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, reuse.StatusCode, "Lost claims must produce a bounded refusal without deleting state.");
        host.Server.OAuth().ClaimFlowStateAsync = originalClaim;

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
    /// draft-16 §4.3.1</see>'s reuse revocation keeps completed audit revocations when corrupt
    /// storage contains a successor cycle. Traversal terminates instead of repeatedly revoking
    /// that cycle; the corruption cannot authorize a fresh issuance.
    /// </summary>
    [TestMethod]
    public async Task RefreshReuseStopsAtACorruptedCycleAndKeepsCompletedRevocations()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        string segment = material.Registration.TenantId.Value;
        (string original, _) = await IssueBearerPairAsync(host, segment).ConfigureAwait(false);
        (string middle, _) = await RotateBearerPairAsync(host, segment, original).ConfigureAwait(false);
        (_, string currentAccessToken) = await RotateBearerPairAsync(host, segment, middle).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string middleFlowId = hosted.RefreshTokenIndex[middle];
        (FlowState state, int stepCount) = hosted.FlowStates[middleFlowId];
        hosted.FlowStates[middleFlowId] = (((ServerTokenIssuedState)state) with
        {
            SuccessorRefreshFlowId = middleFlowId
        }, stepCount);
        HashSet<string> revokedJtis = [];
        int revocationCalls = 0;
        host.Server.OAuth().RevokeIssuedTokenAsync = (jti, _, _, _, _) =>
        {
            if(++revocationCalls > 20)
            {
                throw new InvalidOperationException("A corrupted cycle must not repeat audit revocations indefinitely.");
            }

            _ = revokedJtis.Add(jti);

            return ValueTask.CompletedTask;
        };

        (int StatusCode, string Body) reuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, original),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, reuse.StatusCode, "A cycle must terminate with the refresh refusal.");
        Assert.Contains(JwtPayloadReader.ReadJti(currentAccessToken)!, revokedJtis,
            "Audits reached before the cycle must remain revoked.");
    }


    /// <summary>
    /// Drives PAR (a real wire POST), the browser's authorize GET (a real wire GET with auto-redirect
    /// disabled and the test subject header standing in for an authenticated session), and the
    /// callback (a client-local state transition over the extracted <c>code</c>/<c>state</c>/<c>iss</c>).
    /// Returns the flow identifier ready for token exchange.
    /// </summary>
    /// <param name="resource">
    /// The RFC 8707 §2 <c>resource</c> indicator(s) to request through the CLIENT abstraction
    /// (<see cref="AuthCodeClient.StartParAsync(ClientRegistration, Uri, OAuthFormEncodedFields, ExchangeContext, IReadOnlyList{string}?, CancellationToken)"/>),
    /// which threads each entry to the wire as its OWN repeated <c>resource</c> occurrence — the
    /// genuine RFC 8707 §2 multi-resource wire form, never several indicators joined by a space
    /// into one occurrence. <see langword="null"/> omits the parameter entirely.
    /// </param>
    private static async Task<string> DriveParAuthorizeAndCallbackAsync(
        HostedAuthorizationServer hosted,
        OAuthClient client,
        ClientRegistration registration,
        Dictionary<string, FlowState> clientFlowStore,
        string segment,
        X509Certificate2 pinnedCertificate,
        CancellationToken cancellationToken,
        IReadOnlyList<string>? resource = null)
    {
        AuthCodeFlowEndpointResult parResult = await client.AuthCode.StartParAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty,
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
