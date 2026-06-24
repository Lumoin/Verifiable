using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Phase 9c — refresh-token grant. Drives PAR → Authorize → Token to
/// receive an initial refresh token, then exercises the refresh-grant
/// endpoint for rotation semantics (RFC 6749 §6 + RFC 9700 §2.2.2),
/// expiry, client-id binding, and the unknown-grant_type failure mode.
/// </summary>
/// <remarks>
/// Tests dispatch directly via <see cref="TestHostShell.DispatchAtEndpointAsync"/>
/// — the refresh endpoint is server-side. Per the phase 9b norm, AS-
/// touching tests use <c>await using</c> with the async-disposable host.
/// </remarks>
[TestClass]
internal sealed class RefreshGrantTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 5, 15, 12, 0, 0, TimeSpan.Zero));

    private const string ClientId = "https://client.example.com";
    private static readonly Uri ClientBaseUri = new("https://client.example.com");
    private static readonly Uri RedirectUri =
        new("https://client.example.com/callback");


    [TestMethod]
    public async Task RefreshExchangeIssuesNewAccessAndRefreshTokens()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        (_, string refreshToken) =
            await DriveInitialIssuance(host, material).ConfigureAwait(false);

        TimeProvider.Advance(TimeSpan.FromDays(31));

        ServerHttpResponse response = await DispatchRefreshAsync(
            host, material, refreshToken).ConfigureAwait(false);
        Assert.AreEqual(400, response.StatusCode,
            $"Expired refresh token must be rejected. Body: {response.Body}");
    }


    [TestMethod]
    public async Task RefreshWithWrongClientIdReturnsInvalidGrant()
    {
        //RFC 6749 §6 — the refresh request's client_id must match the
        //client the refresh token was originally issued to.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        (_, string refreshToken) =
            await DriveInitialIssuance(host, material).ConfigureAwait(false);

        RequestFields refreshFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
            [OAuthRequestParameterNames.RefreshToken] = refreshToken,
            [OAuthRequestParameterNames.ClientId] = "https://attacker.example.com"
        };

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken, "POST",
            refreshFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        Assert.Contains(OAuthErrors.InvalidGrant, response.Body, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task UnsupportedGrantTypeReturnsNotFound()
    {
        //The token endpoint matchers reject grant_type values they don't
        //recognise by simply not matching, which produces a 404 from the
        //dispatcher's unmatched-chain path. RFC 6749 §5.2 prefers
        //unsupported_grant_type but the matcher chain doesn't reach the
        //point of forming that error code.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.GrantType] = "password",
            [OAuthRequestParameterNames.ClientId] = ClientId
        };

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken, "POST",
            fields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            $"Unknown grant_type must not be matched by any token endpoint arm. Body: {response.Body}");
    }


    /// <summary>
    /// Drives PAR → Authorize → Token directly against the AS. Returns
    /// the issued access_token and refresh_token strings.
    /// </summary>
    private async Task<(string AccessToken, string RefreshToken)> DriveInitialIssuance(
        TestHostShell host, VerifierKeyMaterial material)
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
        Assert.AreEqual(201, parResponse.StatusCode);
        string requestUri = ExtractRequestUri(parResponse.Body);

        //Authorize.
        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = new();
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
            tokenFields, new ExchangeContext(),
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
            refreshFields, new ExchangeContext(),
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
