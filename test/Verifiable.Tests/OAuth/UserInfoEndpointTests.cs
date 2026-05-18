using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Routing;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// OIDC Phase A — UserInfo endpoint per
/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">OIDC Core §5.3</see>.
/// </summary>
/// <remarks>
/// <para>
/// Chunk 9 shipped the endpoint shell (registration, routing, bearer
/// header gate). Chunk 10 adds the bearer-token validation: signature,
/// <c>iss</c> match, <c>exp</c> check, and the OIDC Core §5.3.1 mandate
/// that the access token's scope include <c>openid</c>. The response body
/// at chunk 10 carries only the validated <c>sub</c>; chunk 11 will
/// expand the body via the contributor walk.
/// </para>
/// <para>
/// Tests dispatch directly against <see cref="AuthorizationServer.DispatchAsync"/>
/// rather than through <see cref="TestHostShell.DispatchAtEndpointAsync"/>
/// — the latter constructs <see cref="RequestHeaders.Empty"/>, and
/// UserInfo is the first library endpoint whose dispatch carries a
/// per-request header (the <c>Authorization</c> bearer).
/// </para>
/// </remarks>
[TestClass]
internal sealed class UserInfoEndpointTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 5, 17, 12, 0, 0, TimeSpan.Zero));

    private const string ClientId = "https://userinfo.client.test";
    private const string SubjectId = "subject-userinfo";
    private static readonly Uri ClientBaseUri = new("https://userinfo.client.test");
    private static readonly Uri RedirectUri =
        new("https://client.example.com/callback");


    //Header-gate tests — exercised before any token-content validation,
    //so the test does not need to issue a real access token.

    [TestMethod]
    public async Task PostWithoutAuthorizationHeaderReturnsUnauthorized()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterPlainUserInfoClient(host);

        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Post, authorizationHeader: null)
            .ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode,
            "Missing Authorization header must return 401 invalid_token per RFC 6750 §3.");
        Assert.Contains(OAuthErrors.InvalidToken, response.Body);
    }


    [TestMethod]
    public async Task GetWithoutAuthorizationHeaderReturnsUnauthorized()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterPlainUserInfoClient(host);

        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Get, authorizationHeader: null)
            .ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode,
            "GET is a spec-allowed method per OIDC Core §5.3; still requires bearer authentication.");
    }


    [TestMethod]
    public async Task PostWithMalformedAuthorizationHeaderReturnsUnauthorized()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterPlainUserInfoClient(host);

        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Post,
            authorizationHeader: "Basic dXNlcjpwYXNz")
            .ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode);
    }


    [TestMethod]
    public async Task PostWithMalformedBearerJwtReturnsUnauthorized()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterPlainUserInfoClient(host);

        //Bearer is present but the payload is not a well-formed JWS.
        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Post,
            authorizationHeader: "Bearer not.a.valid.jwt")
            .ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode);
        Assert.Contains(OAuthErrors.InvalidToken, response.Body);
    }


    [TestMethod]
    public async Task EndpointNotEmittedWhenUserInfoCapabilityAbsent()
    {
        //A registration without ServerCapabilityName.UserInfo must not have
        //a UserInfo endpoint in its chain — request resolves as 404 rather
        //than 401, confirming the builder's capability filter runs.
        await using TestHostShell host = new(TimeProvider);

        ImmutableHashSet<ServerCapabilityName> capabilitiesWithoutUserInfo =
            ImmutableHashSet.Create(
                ServerCapabilityName.AuthorizationCode,
                ServerCapabilityName.OpenIdConnect);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, capabilitiesWithoutUserInfo);

        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Post,
            authorizationHeader: "Bearer doesnt-matter")
            .ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            "Capability filter must remove UserInfo from the chain when not allowed.");
    }


    //Chunk-10 token-validation tests — drive a full PAR / Authorize / Token
    //exchange to mint a real access token, then present it to /userinfo.

    [TestMethod]
    public async Task ValidAccessTokenReturnsSubject()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId, name: "Alice");

        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId)
            .ConfigureAwait(false);

        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Post,
            authorizationHeader: "Bearer " + accessToken)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            $"Valid access token must reach 200. Body: {response.Body}");

        using JsonDocument body = JsonDocument.Parse(response.Body);
        Assert.AreEqual(SubjectId,
            body.RootElement.GetProperty(WellKnownJwtClaimNames.Sub).GetString(),
            "Chunk-10 response body must carry the validated sub.");
    }


    [TestMethod]
    public async Task ExpiredAccessTokenReturnsUnauthorized()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId)
            .ConfigureAwait(false);

        //Fast-forward beyond the access-token lifetime (default 1h per the
        //producer's lifetime fallback).
        TimeProvider.Advance(TimeSpan.FromHours(2));

        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Post,
            authorizationHeader: "Bearer " + accessToken)
            .ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode);
        Assert.Contains(OAuthErrors.InvalidToken, response.Body);
    }


    private static VerifierKeyMaterial RegisterPlainUserInfoClient(TestHostShell host)
    {
        ImmutableHashSet<ServerCapabilityName> capabilities = ImmutableHashSet.Create(
            ServerCapabilityName.AuthorizationCode,
            ServerCapabilityName.OpenIdConnect,
            ServerCapabilityName.UserInfo);
        return host.RegisterClient(ClientId, ClientBaseUri, capabilities);
    }


    private async ValueTask<string> IssueAccessTokenAsync(
        TestHostShell host, VerifierKeyMaterial material, string scope)
    {
        PkceParameters pkce = PkceGeneration.Generate(
            TestSetup.Base64UrlEncoder, SensitiveMemoryPool<byte>.Shared);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = OAuthRequestParameterValues.CodeChallengeMethodS256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = scope
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new RequestContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, parResponse.StatusCode, parResponse.Body);
        string requestUri = ExtractFromBody(parResponse.Body, "request_uri");

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        RequestContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode);
        string code = ExtractCode(authorizeResponse.Location!);

        RequestFields tokenFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypeAuthorizationCode,
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
        };
        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken, "POST",
            tokenFields, new RequestContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument body = JsonDocument.Parse(tokenResponse.Body);
        return body.RootElement.GetProperty("access_token").GetString()!;
    }


    private async ValueTask<ServerHttpResponse> DispatchUserInfoAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string httpMethod,
        string? authorizationHeader)
    {
        string segment = material.Registration.TenantId.Value;
        string path = TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.UserInfo, segment);

        RequestHeaders headers = authorizationHeader is null
            ? RequestHeaders.Empty
            : new RequestHeaders(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                [WellKnownHttpHeaderNames.Authorization] = [authorizationHeader]
            });

        IncomingRequest request = new(
            Path: path,
            Method: httpMethod,
            Fields: new RequestFields(),
            Headers: headers,
            RouteValues: RouteValues.Empty);

        RequestContext context = new();
        context.SetTenantId(segment);
        return await host.Server.DispatchAsync(request, context, TestContext.CancellationToken)
            .ConfigureAwait(false);
    }


    private static string ExtractFromBody(string body, string property)
    {
        using JsonDocument doc = JsonDocument.Parse(body);
        return doc.RootElement.GetProperty(property).GetString()!;
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
            $"Authorize redirect did not carry a code parameter: {location}");
    }
}
