using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.TokenExchange;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Refresh-token grant. Drives PAR → Authorize → Token to
/// receive an initial refresh token, then exercises the refresh-grant
/// endpoint for rotation semantics (RFC 6749 §6 + RFC 9700 §2.2.2),
/// expiry, client-id binding, and the unknown-grant_type failure mode.
/// </summary>
/// <remarks>
/// Tests dispatch directly via <see cref="TestHostShell.DispatchAtEndpointAsync(string, string, string, RequestFields, ExchangeContext, CancellationToken)"/>
/// — the refresh endpoint is server-side. AS-touching tests use
/// <c>await using</c> with the async-disposable host.
/// </remarks>
[TestClass]
internal sealed class RefreshGrantTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 5, 15, 12, 0, 0, TimeSpan.Zero));

    private const string ClientId = "https://client.example.com";
    private static Uri ClientBaseUri { get; } = new("https://client.example.com");
    private static Uri RedirectUri { get; } =
        new("https://client.example.com/callback");


    [TestMethod]
    public async Task RefreshExchangeIssuesNewAccessAndRefreshTokens()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (string originalAccessToken, string originalRefreshToken) =
            await DriveInitialIssuance(host, material).ConfigureAwait(false);

        ServerHttpResponse refreshResponse = await DispatchRefreshAsync(
            host, material, originalRefreshToken).ConfigureAwait(false);

        Assert.AreEqual(200, refreshResponse.StatusCode,
            $"Refresh exchange must succeed. Body: {refreshResponse.Body}");

        using JsonDocument doc = JsonDocument.Parse(refreshResponse.Body);
        Assert.IsTrue(doc.RootElement.TryGetProperty("access_token", out JsonElement at));
        Assert.IsTrue(doc.RootElement.TryGetProperty("refresh_token", out JsonElement rt));

        string newAccessToken = at.GetString()!;
        string newRefreshToken = rt.GetString()!;

        Assert.IsFalse(string.IsNullOrEmpty(newAccessToken));
        Assert.IsFalse(string.IsNullOrEmpty(newRefreshToken));
        Assert.AreNotEqual(originalAccessToken, newAccessToken,
            "Refresh must issue a fresh access token, not return the original.");
        Assert.AreNotEqual(originalRefreshToken, newRefreshToken,
            "Refresh must rotate the refresh token (RFC 9700 §2.2.2).");
    }


    [TestMethod]
    public async Task UsingRotatedOutRefreshTokenReturnsInvalidGrant()
    {
        //RFC 9700 §2.2.2: presenting a refresh token that has already been
        //rotated out must be rejected. The library invalidates the old
        //state via DeleteFlowStateAsync; subsequent presentation of the
        //old refresh token resolves to a missing index entry and the
        //dispatcher returns invalid_request.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (_, string originalRefreshToken) =
            await DriveInitialIssuance(host, material).ConfigureAwait(false);

        //First refresh — succeeds, rotates the token.
        ServerHttpResponse firstResponse = await DispatchRefreshAsync(
            host, material, originalRefreshToken).ConfigureAwait(false);
        Assert.AreEqual(200, firstResponse.StatusCode);

        //Second refresh using the ORIGINAL token — must fail.
        ServerHttpResponse secondResponse = await DispatchRefreshAsync(
            host, material, originalRefreshToken).ConfigureAwait(false);
        Assert.AreEqual(400, secondResponse.StatusCode,
            $"Rotated-out refresh token must be rejected. Body: {secondResponse.Body}");
    }


    [TestMethod]
    public async Task ExpiredRefreshTokenReturnsInvalidGrant()
    {
        //Default RefreshTokenLifetime is 30 days. Advance time past it and
        //assert the refresh exchange fails.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (_, string refreshToken) =
            await DriveInitialIssuance(host, material).ConfigureAwait(false);

        TimeProvider.Advance(TimeSpan.FromDays(31));

        ServerHttpResponse response = await DispatchRefreshAsync(
            host, material, refreshToken).ConfigureAwait(false);
        Assert.AreEqual(400, response.StatusCode,
            $"Expired refresh token must be rejected. Body: {response.Body}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2.2">RFC 6749 §2.2</see>:
    /// a <c>client_id</c> the caller presents on a request the library handles for the
    /// selected registration must be that registration's own identifier. At the refresh
    /// grant — a CONTINUING grant — identification runs before the declared-authentication
    /// check and before grant binding, and a mismatch answers the SAME constant
    /// <c>invalid_grant</c> body an unknown, expired, retired, or revoked refresh token
    /// receives (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749
    /// §5.2</see>'s "issued to another client"): an unauthenticated presenter must not be able
    /// to tell a wrong <c>client_id</c> on a live token apart from one on a token that never
    /// existed. Nothing is rotated or revoked.
    /// </summary>
    [TestMethod]
    public async Task RefreshWithUnregisteredClientIdReturnsInvalidGrantOverHttpWire()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (_, string refreshToken) =
            await DriveInitialIssuance(host, material).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri tokenUrl = new(hosted.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
                [OAuthRequestParameterNames.RefreshToken] = refreshToken,
                [OAuthRequestParameterNames.ClientId] = "https://attacker.example.com"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidGrant, body, StringComparison.Ordinal);

        //Nothing was rotated or revoked: the same refresh token still redeems normally.
        using HttpResponseMessage validResponse = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
                [OAuthRequestParameterNames.RefreshToken] = refreshToken,
                [OAuthRequestParameterNames.ClientId] = ClientId
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        string validBody = await validResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)validResponse.StatusCode,
            $"An identification failure must not consume the refresh token. Body: {validBody}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>
    /// "issued to another client": grant binding is a check SEPARATE from identification.
    /// A refresh record whose STORED client differs from the registration's own identifier
    /// is refused <c>invalid_grant</c> when presented with the registration's own (correctly
    /// identified) <c>client_id</c>, and the record is neither rotated nor deleted; presenting
    /// the STORED hostile identifier instead answers the identification refusal instead —
    /// also <c>invalid_grant</c>, since a continuing grant never answers an identification
    /// mismatch with a different status than a grant-binding mismatch.
    /// </summary>
    [TestMethod]
    public async Task RefreshOfALegacyRecordBoundToAnotherClientReturnsInvalidGrantOverHttpWire()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (_, string refreshToken) =
            await DriveInitialIssuance(host, material).ConfigureAwait(false);

        const string HostileStoredClientId = "https://attacker.example.com";
        RebindRefreshTokenClientId(host.Host("default"), refreshToken, HostileStoredClientId);
        string flowId = host.Host("default").RefreshTokenIndex[refreshToken];
        int stepCountBefore = host.Host("default").FlowStates[flowId].StepCount;

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri tokenUrl = new(hosted.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        //The registration's own (correctly identified) client_id: refused by grant binding.
        using HttpResponseMessage boundResponse = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
                [OAuthRequestParameterNames.RefreshToken] = refreshToken,
                [OAuthRequestParameterNames.ClientId] = ClientId
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        string boundBody = await boundResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)boundResponse.StatusCode, boundBody);
        Assert.Contains(OAuthErrors.InvalidGrant, boundBody, StringComparison.Ordinal);
        Assert.AreEqual(stepCountBefore, hosted.FlowStates[flowId].StepCount,
            "A grant-binding refusal must not consume, rotate, or revoke the record.");
        Assert.AreEqual(HostileStoredClientId, ((ServerRefreshTokenIssuedState)hosted.FlowStates[flowId].State).ClientId,
            "A grant-binding refusal must never repair the stored record to the registration's identifier.");

        //The STORED hostile identifier: refused by identification instead.
        using HttpResponseMessage hostileResponse = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
                [OAuthRequestParameterNames.RefreshToken] = refreshToken,
                [OAuthRequestParameterNames.ClientId] = HostileStoredClientId
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        string hostileBody = await hostileResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)hostileResponse.StatusCode, hostileBody);
        Assert.Contains(OAuthErrors.InvalidGrant, hostileBody, StringComparison.Ordinal);
        Assert.AreEqual(stepCountBefore, hosted.FlowStates[flowId].StepCount,
            "An identification refusal must not consume, rotate, or revoke the record either.");

        //An UNKNOWN refresh_token, presented with the registration's own (correctly identified)
        //client_id: this comparison never reaches a record at all, so it must answer
        //byte-identically to the grant-binding refusal above — the discriminator that keeps this
        //test able to fail on the wrong body follows: restoring the record's stored client and
        //redeeming confirms the seeded record survives untouched by every refusal above.
        using HttpResponseMessage unknownResponse = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
                [OAuthRequestParameterNames.RefreshToken] = "unknown-refresh-token-value",
                [OAuthRequestParameterNames.ClientId] = ClientId
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        string unknownBody = await unknownResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)unknownResponse.StatusCode, unknownBody);
        Assert.AreEqual(boundBody, unknownBody,
            "The grant-binding refusal must answer byte-identically to a refresh_token that was never "
            + "issued — RFC 6749 §5.2's invalid_grant, never text of its own.");

        RebindRefreshTokenClientId(host.Host("default"), refreshToken, ClientId);
        using HttpResponseMessage restoredResponse = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
                [OAuthRequestParameterNames.RefreshToken] = refreshToken,
                [OAuthRequestParameterNames.ClientId] = ClientId
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        string restoredBody = await restoredResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)restoredResponse.StatusCode, restoredBody);
    }


    /// <summary>
    /// A <c>refresh_token</c> correlation key resolving to a record of a type the refresh endpoint
    /// never produces or consumes (the shape a store fault could produce) answers the same body a
    /// <c>refresh_token</c> that was never issued does, never distinct text of its own.
    /// </summary>
    [TestMethod]
    public async Task RefreshTokenResolvingToAWronglyTypedRecordAnswersTheSameBodyForAnUnknownAndALiveTokenOverHttpWire()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (_, string refreshToken) = await DriveInitialIssuance(host, material).ConfigureAwait(false);

        string segment = material.Registration.TenantId.Value;
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string flowId = hosted.RefreshTokenIndex[refreshToken];
        int stepCount = hosted.FlowStates[flowId].StepCount;

        //A separately pushed PAR gives a genuine ParRequestReceivedState — a record type the
        //refresh_token correlation key could never legitimately resolve to. Seeded directly, the
        //shape a corrupted store could produce.
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
        string parFlowId = hosted.RequestUriTokenIndex[TestHostShell.ExtractRequestUriToken(new Uri(requestUri))];
        FlowState wronglyTypedState = hosted.FlowStates[parFlowId].State;

        hosted.FlowStates[flowId] = (wronglyTypedState, stepCount);

        Uri tokenUrl = new(hosted.HttpBaseAddress!, $"/connect/{segment}/token");

        using HttpResponseMessage liveResponse = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
                [OAuthRequestParameterNames.RefreshToken] = refreshToken,
                [OAuthRequestParameterNames.ClientId] = ClientId
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        string liveBody = await liveResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using HttpResponseMessage unknownResponse = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
                [OAuthRequestParameterNames.RefreshToken] = "unknown-refresh-token-value",
                [OAuthRequestParameterNames.ClientId] = ClientId
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        string unknownBody = await unknownResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)liveResponse.StatusCode, liveBody);
        Assert.AreEqual((int)unknownResponse.StatusCode, (int)liveResponse.StatusCode);
        Assert.AreEqual(unknownBody, liveBody,
            "A refresh_token correlation key resolving to a wrongly-typed record must answer identically "
            + "to a refresh_token that was never issued.");
    }


    [TestMethod]
    public async Task UnsupportedGrantTypeReturnsBadRequestWithUnsupportedGrantTypeError()
    {
        //RFC 6749 §5.2: "unsupported_grant_type — The authorization grant type is not
        //supported by the authorization server." The token endpoint's residual grant_type
        //refusal arm answers this, not the host-generic 404 an unmatched chain would give.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.GrantType] = "password",
            [OAuthRequestParameterNames.ClientId] = ClientId
        };

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken, "POST",
            fields, [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            $"An unsupported grant_type must be refused with RFC 6749 §5.2 unsupported_grant_type, not 404. Body: {response.Body}");
        Assert.Contains(OAuthErrors.UnsupportedGrantType, response.Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// RFC 6749 §5.2: "invalid_request — The request is missing a required parameter ...".
    /// A token request with no <c>grant_type</c> at all is refused with <c>invalid_request</c>,
    /// over the real loopback socket <see cref="AuthCodeParPkceRealWireFlowTests"/> and the other
    /// token-endpoint real-wire tests drive.
    /// </summary>
    [TestMethod]
    public async Task MissingGrantTypeReturnsBadRequestWithInvalidRequestErrorOverHttpWire()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri tokenUrl = new(hosted.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string> { [OAuthRequestParameterNames.ClientId] = ClientId },
            TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(OAuthErrors.InvalidRequest, doc.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// RFC 6749 §5.2: "unsupported_grant_type — The authorization grant type is not supported
    /// by the authorization server." Same refusal as
    /// <see cref="UnsupportedGrantTypeReturnsBadRequestWithUnsupportedGrantTypeError"/>, driven
    /// over the real loopback socket instead of the in-process dispatcher.
    /// </summary>
    [TestMethod]
    public async Task UnsupportedGrantTypeReturnsBadRequestWithUnsupportedGrantTypeErrorOverHttpWire()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri tokenUrl = new(hosted.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = "password",
                [OAuthRequestParameterNames.ClientId] = ClientId
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(OAuthErrors.UnsupportedGrantType, doc.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// RFC 6749 §5.2: "unauthorized_client — The authenticated client is not authorized to use
    /// this authorization grant type." The server wires every token-exchange seam below, so THIS
    /// authorization server genuinely serves <see cref="WellKnownGrantTypes.TokenExchange"/>;
    /// <see cref="ClientBaseUri"/>'s default registration is still not allowed
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthTokenExchange"/>, isolating the client-registration
    /// gap from the server-wiring gap <see cref="TokenExchangeGrantTests.WellFormedExchangeWithoutTokenValidationSeamDoesNotActivateTheGrant"/>
    /// proves separately — a request naming a grant type the server serves but this client is not
    /// registered for is refused with <c>unauthorized_client</c> rather than the generic
    /// <c>unsupported_grant_type</c>.
    /// </summary>
    [TestMethod]
    public async Task GrantTypeNotRegisteredForClientReturnsBadRequestWithUnauthorizedClientErrorOverHttpWire()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        //Every token-exchange seam wired on the server; ClientBaseUri's registration is never
        //granted OAuthTokenExchange, so the server serves the grant type while this client remains
        //unregistered for it.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                ValueTask.FromResult(true);
            candidateIntegration.ValidateTokenExchangeTokenAsync = static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(new ValidatedSecurityToken { Subject = "https://subject.example.com" });
            candidateIntegration.AuthorizeTokenExchangeAsync = static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(new TokenExchangeAuthorization
                {
                    Subject = subject.Subject,
                    Scope = "read",
                    IssuedTokenType = TokenType.AccessToken
                });
        }).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri tokenUrl = new(hosted.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
                [OAuthRequestParameterNames.ClientId] = ClientId
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(OAuthErrors.UnauthorizedClient, doc.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// RFC 6749 §5.2: "unsupported_grant_type — The authorization grant type is not supported
    /// by the authorization server." <c>urn:ietf:params:oauth:grant-type:device_code</c> is a grant
    /// this library implements no candidate for on any host, so a server that never serves it must
    /// still answer the RFC 6749 refusal, not the host-generic 404.
    /// </summary>
    [TestMethod]
    public async Task DeviceCodeGrantTypeReturnsBadRequestWithUnsupportedGrantTypeErrorOverHttpWire()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri tokenUrl = new(hosted.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.DeviceCode,
                [OAuthRequestParameterNames.ClientId] = ClientId
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(OAuthErrors.UnsupportedGrantType, doc.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// RFC 6749 §5.2's refusal must reach every token-serving registration, not only one allowed
    /// authorization code, client credentials, or token exchange. A registration whose ONLY
    /// token-serving capability is <see cref="WellKnownCapabilityIdentifiers.OAuthJwtBearer"/> still
    /// gets the refusal for an unsupported <c>grant_type</c> — never the host-generic 404 a missing
    /// refusal candidate would otherwise leave behind.
    /// </summary>
    [TestMethod]
    public async Task JwtBearerOnlyRegistrationRejectsUnsupportedGrantTypeInsteadOf404OverHttpWire()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthJwtBearer,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri tokenUrl = new(hosted.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = "password",
                [OAuthRequestParameterNames.ClientId] = ClientId
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode,
            $"A JWT-bearer-only registration must still see the RFC 6749 §5.2 refusal, not a 404. Body: {body}");

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(OAuthErrors.UnsupportedGrantType, doc.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// The same coverage as
    /// <see cref="JwtBearerOnlyRegistrationRejectsUnsupportedGrantTypeInsteadOf404OverHttpWire"/> for
    /// the OID4VCI 1.0 §6 Pre-Authorized Code grant: a registration whose ONLY token-serving
    /// capability is <see cref="WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant"/> still
    /// gets the refusal for an unsupported <c>grant_type</c>, not the host-generic 404.
    /// </summary>
    [TestMethod]
    public async Task PreAuthorizedCodeOnlyRegistrationRejectsUnsupportedGrantTypeInsteadOf404OverHttpWire()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri tokenUrl = new(hosted.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = "password",
                [OAuthRequestParameterNames.ClientId] = ClientId
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode,
            $"A pre-authorized-code-only registration must still see the RFC 6749 §5.2 refusal, not a 404. Body: {body}");

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(OAuthErrors.UnsupportedGrantType, doc.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// RFC 6749 §5.2: "unauthorized_client — The authenticated client is not authorized to use
    /// this authorization grant type." A registration allowed only
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthClientCredentials"/> — never
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthAuthorizationCode"/> — still posts
    /// <c>grant_type=authorization_code</c>: the capability filter removes the code-grant
    /// candidate, and the token endpoint answers with this error rather than an empty 404.
    /// </summary>
    [TestMethod]
    public async Task AuthorizationCodeGrantFromClientCredentialsOnlyRegistrationReturnsUnauthorizedClientOverHttpWire()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri tokenUrl = new(hosted.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
                [OAuthRequestParameterNames.ClientId] = ClientId
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode,
            $"A client_credentials-only registration must see unauthorized_client for authorization_code, not a 404. Body: {body}");

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(OAuthErrors.UnauthorizedClient, doc.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// The same coverage as
    /// <see cref="AuthorizationCodeGrantFromClientCredentialsOnlyRegistrationReturnsUnauthorizedClientOverHttpWire"/>
    /// for <c>grant_type=refresh_token</c>: refresh is enabled only alongside
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthAuthorizationCode"/>, so a
    /// client_credentials-only registration must see <c>unauthorized_client</c>, not a 404.
    /// </summary>
    [TestMethod]
    public async Task RefreshTokenGrantFromClientCredentialsOnlyRegistrationReturnsUnauthorizedClientOverHttpWire()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri tokenUrl = new(hosted.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.RefreshToken] = "opaque-refresh-token-value"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode,
            $"A client_credentials-only registration must see unauthorized_client for refresh_token, not a 404. Body: {body}");

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(OAuthErrors.UnauthorizedClient, doc.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-6">RFC 6749 §6</see>: "The
    /// requested scope MUST NOT include any scope not originally granted by the resource owner".
    /// A refresh request naming a narrower <c>scope</c> than the stored grant narrows the access
    /// token to exactly the requested subset, and the response's own <c>scope</c> member —
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>: "REQUIRED"
    /// when different from what was requested — says so. A later refresh of the ROTATED refresh
    /// token with NO <c>scope</c> then proves the narrowing never touched the stored grant: "if
    /// omitted is treated as equal to the scope originally granted by the resource owner" (§6), so
    /// the FULL scope comes back.
    /// </summary>
    [TestMethod]
    public async Task NarrowerRefreshScopeGrantsExactlyTheRequestedSubsetAndALaterOmittedScopeRestoresTheFullGrantOverHttpWire()
    {
        string fullScope = $"{WellKnownScopes.OpenId} {WellKnownScopes.Profile} {WellKnownScopes.Email}";

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (_, string refreshToken) = await DriveInitialIssuance(host, material, scope: fullScope).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri tokenUrl = new(hosted.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage narrowedResponse = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
                [OAuthRequestParameterNames.RefreshToken] = refreshToken,
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.Scope] = WellKnownScopes.Profile
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        string narrowedBody = await narrowedResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)narrowedResponse.StatusCode, narrowedBody);

        using JsonDocument narrowedDoc = JsonDocument.Parse(narrowedBody);
        Assert.AreEqual(WellKnownScopes.Profile, narrowedDoc.RootElement.GetProperty(OAuthRequestParameterNames.Scope).GetString(),
            "RFC 6749 §5.1: the response's scope member must name the actual narrowed grant, not the full stored scope.");

        string narrowedAccessToken = narrowedDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument narrowedPayload = JwtPayloadDecoding.DecodePayload(narrowedAccessToken, BaseMemoryPool.Shared);
        Assert.AreEqual(WellKnownScopes.Profile, narrowedPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Scope).GetString(),
            "RFC 6749 §6: a narrower refresh-request scope must narrow the issued access token to exactly that subset.");

        string rotatedRefreshToken = narrowedDoc.RootElement.GetProperty(WellKnownTokenTypes.RefreshToken).GetString()!;

        using HttpResponseMessage fullResponse = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
                [OAuthRequestParameterNames.RefreshToken] = rotatedRefreshToken,
                [OAuthRequestParameterNames.ClientId] = ClientId
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        string fullBody = await fullResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)fullResponse.StatusCode, fullBody);

        using JsonDocument fullDoc = JsonDocument.Parse(fullBody);
        string fullAccessToken = fullDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument fullPayload = JwtPayloadDecoding.DecodePayload(fullAccessToken, BaseMemoryPool.Shared);
        Assert.AreEqual(fullScope, fullPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Scope).GetString(),
            "RFC 6749 §6: the rotated refresh token was never itself narrowed, so a later omitted-scope "
            + "refresh grants the full original scope again.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>:
    /// "invalid_scope — The requested scope is ... exceeds the scope granted by the resource
    /// owner." A refresh-request scope naming a value the stored grant never carried is refused
    /// BEFORE the rotation claim: nothing is minted, claimed, rotated, or revoked, so the presented
    /// refresh token still works afterward.
    /// </summary>
    [TestMethod]
    public async Task RefreshWithAnUngrantedScopeValueIsRefusedInvalidScopeWithoutConsumingTheTokenOverHttpWire()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (_, string refreshToken) = await DriveInitialIssuance(
            host, material, scope: $"{WellKnownScopes.OpenId} {WellKnownScopes.Profile}").ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri tokenUrl = new(hosted.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        string flowId = hosted.RefreshTokenIndex[refreshToken];
        int stepCountBefore = hosted.FlowStates[flowId].StepCount;
        int flowStateCountBefore = hosted.FlowStates.Count;

        using HttpResponseMessage refusedResponse = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
                [OAuthRequestParameterNames.RefreshToken] = refreshToken,
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.Scope] = WellKnownScopes.Address
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        string refusedBody = await refusedResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)refusedResponse.StatusCode, refusedBody);

        using JsonDocument refusedDoc = JsonDocument.Parse(refusedBody);
        Assert.AreEqual(OAuthErrors.InvalidScope, refusedDoc.RootElement.GetProperty("error").GetString());

        Assert.AreEqual(stepCountBefore, hosted.FlowStates[flowId].StepCount,
            "An invalid_scope refusal must not claim, rotate, or revoke the presented refresh record.");
        Assert.HasCount(flowStateCountBefore, hosted.FlowStates,
            "An invalid_scope refusal must mint no access token or successor refresh record.");

        using HttpResponseMessage validResponse = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
                [OAuthRequestParameterNames.RefreshToken] = refreshToken,
                [OAuthRequestParameterNames.ClientId] = ClientId
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        string validBody = await validResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)validResponse.StatusCode,
            $"An invalid_scope refusal must not consume the refresh token. Body: {validBody}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see>: scope is
    /// a list of space-delimited, case-sensitive strings whose "order does not matter". A
    /// refresh-request scope naming the SAME set as a subset of the stored grant, reordered and
    /// with one value repeated, is accepted as that same two-value set — never a three-value set
    /// (repetition does not "add an additional access range" beyond what the set already has) and
    /// never refused for its order or its repeat.
    /// </summary>
    [TestMethod]
    public async Task RefreshScopeInADifferentOrderWithARepeatedValueIsAcceptedAsTheSameSetOverHttpWire()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (_, string refreshToken) = await DriveInitialIssuance(
            host, material, scope: $"{WellKnownScopes.OpenId} {WellKnownScopes.Profile} {WellKnownScopes.Email}")
            .ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri tokenUrl = new(hosted.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        //Reordered relative to the granted scope AND with one value repeated — still names exactly
        //the two-value {email, profile} subset.
        string reorderedWithRepeat = $"{WellKnownScopes.Email} {WellKnownScopes.Profile} {WellKnownScopes.Profile}";

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
                [OAuthRequestParameterNames.RefreshToken] = refreshToken,
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.Scope] = reorderedWithRepeat
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument reorderedDoc = JsonDocument.Parse(body);
        string accessToken = reorderedDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument payload = JwtPayloadDecoding.DecodePayload(accessToken, BaseMemoryPool.Shared);
        string[] grantedTokens = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Scope).GetString()!
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);
        Assert.HasCount(2, grantedTokens,
            "A repeated scope token must not surface as a duplicate, and order must not add a third value — "
            + "RFC 6749 §3.3's scope is a SET.");
        Assert.Contains(WellKnownScopes.Profile, grantedTokens);
        Assert.Contains(WellKnownScopes.Email, grantedTokens);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequestValidation">OpenID
    /// Connect Core 1.0 §3.1.2.2</see>: "If no openid scope value is present, the request may still
    /// be a valid OAuth 2.0 request but is not an OpenID Connect request." A refresh request whose
    /// narrowed <c>scope</c> drops <c>openid</c> from an End-User-authenticating grant must yield a
    /// valid OAuth 2.0 refresh response with no <c>id_token</c>, per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse">§12.2</see>
    /// ("the response body is the Token Response ... except that it might not contain an id_token").
    /// </summary>
    [TestMethod]
    public async Task RefreshNarrowedToExcludeOpenIdYieldsNoIdTokenOverHttpWire()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (_, string refreshToken) = await DriveInitialIssuance(
            host, material, scope: $"{WellKnownScopes.OpenId} {WellKnownScopes.Profile}").ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri tokenUrl = new(hosted.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
                [OAuthRequestParameterNames.RefreshToken] = refreshToken,
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.Scope] = WellKnownScopes.Profile
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.IsFalse(doc.RootElement.TryGetProperty(WellKnownTokenTypes.IdToken, out _),
            "OpenID Connect Core §3.1.2.2: a scope with no openid value is not an OpenID Connect "
            + "request, so the refreshed response must carry no id_token.");

        string accessToken = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument payload = JwtPayloadDecoding.DecodePayload(accessToken, BaseMemoryPool.Shared);
        Assert.AreEqual(WellKnownScopes.Profile, payload.RootElement.GetProperty(WellKnownJwtClaimNames.Scope).GetString(),
            "The narrowed access token must still carry exactly the requested (openid-excluded) scope.");
    }


    /// <summary>
    /// Rebinds a saved <see cref="ServerRefreshTokenIssuedState"/>'s stored <c>ClientId</c> to
    /// <paramref name="clientId"/>, directly in the host's store, the way the host's own tests
    /// build a record whose stored client differs from the registration's own identifier —
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see> "issued
    /// to another client" grant binding, separate from identification of the presented
    /// <c>client_id</c> field against the registration.
    /// </summary>
    private static void RebindRefreshTokenClientId(
        HostedAuthorizationServer hosted, string refreshToken, string clientId)
    {
        string flowId = hosted.RefreshTokenIndex[refreshToken];
        (FlowState state, int stepCount) = hosted.FlowStates[flowId];
        ServerRefreshTokenIssuedState refresh = (ServerRefreshTokenIssuedState)state;
        hosted.FlowStates[flowId] = (refresh with { ClientId = clientId }, stepCount);
    }


    /// <summary>
    /// Drives PAR → Authorize → Token directly against the AS. Returns
    /// the issued access_token and refresh_token strings. <paramref name="scope"/> defaults to
    /// <see cref="WellKnownScopes.OpenId"/> alone, matching every pre-existing caller.
    /// </summary>
    private async Task<(string AccessToken, string RefreshToken)> DriveInitialIssuance(
        TestHostShell host, VerifierKeyMaterial material, string? scope = null)
    {
        PkceParameters pkce = PkceGeneration.Generate(
            TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = scope ?? WellKnownScopes.OpenId
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode);
        string requestUri = ExtractRequestUri(parResponse.Body);

        //Authorize.
        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = [];
        authorizeContext.SetSubjectId("subject-1");
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode);
        string code = ExtractCode(authorizeResponse.Location!);

        //Token exchange.
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
            tokenFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode,
            $"Token exchange must succeed. Body: {tokenResponse.Body}");

        using JsonDocument doc = JsonDocument.Parse(tokenResponse.Body);
        return (
            doc.RootElement.GetProperty("access_token").GetString()!,
            doc.RootElement.GetProperty("refresh_token").GetString()!);
    }


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
            refreshFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static string ExtractRequestUri(string body)
    {
        using JsonDocument doc = JsonDocument.Parse(body);
        return doc.RootElement.GetProperty("request_uri").GetString()!;
    }


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
            $"Authorize redirect did not carry a code parameter. Got: {location}");
    }
}
