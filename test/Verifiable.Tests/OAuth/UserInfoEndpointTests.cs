using System.Collections.Immutable;
using Microsoft.Extensions.Time.Testing;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Routing;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// OIDC Phase A — UserInfo endpoint per
/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">OIDC Core §5.3</see>.
/// Chunk 9 ships the endpoint shell: registration, routing, and bearer
/// header presence. Chunks 10 and 11 add token validation and the
/// contributor walk.
/// </summary>
/// <remarks>
/// Tests dispatch directly against <see cref="AuthorizationServer.DispatchAsync"/>
/// rather than through <see cref="TestHostShell.DispatchAtEndpointAsync"/>
/// — the latter constructs <see cref="RequestHeaders.Empty"/> and UserInfo
/// is the first library endpoint whose dispatch carries a per-request
/// header (the <c>Authorization</c> bearer).
/// </remarks>
[TestClass]
internal sealed class UserInfoEndpointTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 5, 17, 12, 0, 0, TimeSpan.Zero));

    private const string ClientId = "https://userinfo.client.test";
    private static readonly Uri ClientBaseUri = new("https://userinfo.client.test");


    [TestMethod]
    public async Task PostWithoutAuthorizationHeaderReturnsUnauthorized()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterUserInfoClient(host);

        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Post, authorizationHeader: null)
            .ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode,
            "Missing Authorization header must return 401 invalid_token per RFC 6750 §3.");
        Assert.Contains(OAuthErrors.InvalidToken, response.Body,
            "Error code must be invalid_token.");
    }


    [TestMethod]
    public async Task GetWithoutAuthorizationHeaderReturnsUnauthorized()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterUserInfoClient(host);

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
        using VerifierKeyMaterial material = RegisterUserInfoClient(host);

        //Non-Bearer scheme (Basic) must be rejected before any token-content
        //validation runs.
        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Post,
            authorizationHeader: "Basic dXNlcjpwYXNz")
            .ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode);
    }


    [TestMethod]
    public async Task PostWithBearerHeaderReturnsChunk9Placeholder()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterUserInfoClient(host);

        //Chunk 9 ship-state: bearer header is structurally present, so the
        //endpoint reaches the success path. The body is the chunk-9
        //placeholder; chunks 10/11 validate the token and emit subject +
        //scope-driven claims.
        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Post,
            authorizationHeader: "Bearer placeholder-token")
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            $"Bearer-present request must reach the chunk-9 placeholder path. Body: {response.Body}");
        Assert.AreEqual("{}", response.Body);
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


    private static VerifierKeyMaterial RegisterUserInfoClient(TestHostShell host)
    {
        ImmutableHashSet<ServerCapabilityName> capabilities = ImmutableHashSet.Create(
            ServerCapabilityName.AuthorizationCode,
            ServerCapabilityName.OpenIdConnect,
            ServerCapabilityName.UserInfo);
        return host.RegisterClient(ClientId, ClientBaseUri, capabilities);
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
}
