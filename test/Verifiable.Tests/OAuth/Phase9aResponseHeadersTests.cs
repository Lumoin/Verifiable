using System.Collections.Immutable;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Registration;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Phase 9a — verifies the two surgical gaps surfaced by the phase 7
/// audit:
/// </summary>
/// <list type="bullet">
///   <item><description>PKCE-PAR validates <c>redirect_uri</c> against
///   the registration's <c>AllowedRedirectUris</c> (RFC 9700 §2.1 /
///   OAuth 2.1 §2.3.1).</description></item>
///   <item><description>Token-bearing responses emit
///   <c>Cache-Control: no-store</c> (OAuth 2.1 §3.2.3).</description></item>
/// </list>
/// <remarks>
/// Tests dispatch directly against the AS via
/// <see cref="TestHostShell.DispatchAtPathAsync"/> and inspect
/// <see cref="ServerHttpResponse.Headers"/> rather than threading
/// through a client-side accessor. Both gaps are observable at the
/// server-side response shape; the wire-level fidelity test
/// (phase 9b) will promote a subset to HTTP-client-mediated assertions.
/// </remarks>
[TestClass]
internal sealed class Phase9aResponseHeadersTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private const string ClientId = "https://client.example.com";
    private static readonly Uri ClientBaseUri = new("https://client.example.com");
    private static readonly Uri RegisteredRedirectUri =
        new("https://client.example.com/callback");
    private static readonly Uri UnregisteredRedirectUri =
        new("https://attacker.example.com/callback");

    private static ImmutableHashSet<ServerCapabilityName> ParCapabilities { get; } =
        ImmutableHashSet.Create(
            ServerCapabilityName.AuthorizationCode,
            ServerCapabilityName.PushedAuthorization);


    [TestMethod]
    public async Task BuildParRejectsRedirectUriNotInAllowedSet()
    {
        //RFC 9700 §2.1 / OAuth 2.1 §2.3.1 — the PKCE-PAR matcher must reject
        //a redirect_uri that is not among the registration's
        //AllowedRedirectUris. Mirrors the JAR-PAR check that existed before
        //phase 9a; this regression-guards the new PKCE-PAR check.
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, ParCapabilities);

        RequestFields fields = new()
        {
            [OAuthRequestParameters.ClientId] = ClientId,
            [OAuthRequestParameters.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameters.CodeChallengeMethod] = OAuthRequestParameters.CodeChallengeMethodS256,
            [OAuthRequestParameters.RedirectUri] = UnregisteredRedirectUri.ToString(),
            [OAuthRequestParameters.Scope] = WellKnownScopes.OpenId
        };

        ServerHttpResponse response = await host.DispatchAtPathAsync(
            material.Registration.TenantId.Value,
            ServerEndpointPaths.Par,
            "POST",
            fields,
            new RequestContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            $"PAR must reject unregistered redirect_uri with 400. Body: {response.Body}");
        Assert.Contains(OAuthErrors.InvalidRequest, response.Body, StringComparison.Ordinal,
            $"Response must carry invalid_request error. Body: {response.Body}");
        Assert.Contains("not among the registered redirect URIs",
            response.Body, StringComparison.Ordinal,
            $"Response should mention the registered-redirect-URIs check. Body: {response.Body}");
    }


    [TestMethod]
    public async Task BuildParAcceptsRedirectUriInAllowedSet()
    {
        //Positive regression guard for the new PKCE-PAR redirect_uri check:
        //a request submitting the registered redirect_uri must still return
        //a 200 OK request_uri response.
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, ParCapabilities);

        RequestFields fields = new()
        {
            [OAuthRequestParameters.ClientId] = ClientId,
            [OAuthRequestParameters.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameters.CodeChallengeMethod] = OAuthRequestParameters.CodeChallengeMethodS256,
            [OAuthRequestParameters.RedirectUri] = RegisteredRedirectUri.ToString(),
            [OAuthRequestParameters.Scope] = WellKnownScopes.OpenId
        };

        ServerHttpResponse response = await host.DispatchAtPathAsync(
            material.Registration.TenantId.Value,
            ServerEndpointPaths.Par,
            "POST",
            fields,
            new RequestContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            $"PAR must succeed for a registered redirect_uri. Body: {response.Body}");
        Assert.Contains("\"request_uri\":", response.Body, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task PkceParSuccessResponseIncludesCacheControlNoStore()
    {
        //OAuth 2.1 §3.2.3 — PAR response carries a short-lived single-use
        //request_uri. Treated as sensitive and emitted with Cache-Control:
        //no-store. (Decision §3 in PHASE9A handoff.)
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, ParCapabilities);

        RequestFields fields = new()
        {
            [OAuthRequestParameters.ClientId] = ClientId,
            [OAuthRequestParameters.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameters.CodeChallengeMethod] = OAuthRequestParameters.CodeChallengeMethodS256,
            [OAuthRequestParameters.RedirectUri] = RegisteredRedirectUri.ToString(),
            [OAuthRequestParameters.Scope] = WellKnownScopes.OpenId
        };

        ServerHttpResponse response = await host.DispatchAtPathAsync(
            material.Registration.TenantId.Value,
            ServerEndpointPaths.Par,
            "POST",
            fields,
            new RequestContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode);
        Assert.IsTrue(response.Headers.TryGetValue(
            WellKnownHttpHeaderNames.CacheControl, out string? cacheControl));
        Assert.AreEqual(WellKnownCacheControlValues.NoStore, cacheControl);
    }


    [TestMethod]
    public async Task TokenResponseIncludesCacheControlNoStore()
    {
        //OAuth 2.1 §3.2.3 — the token endpoint's success response carries
        //the access token; Cache-Control: no-store mandated. Drive a full
        //PKCE flow end to end and inspect the token response headers.
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        PkceParameters pkce = PkceGeneration.Generate(
            TestSetup.Base64UrlEncoder, SensitiveMemoryPool<byte>.Shared);
        string verifier = pkce.EncodedVerifier;
        string challenge = pkce.EncodedChallenge;

        //PAR.
        RequestFields parFields = new()
        {
            [OAuthRequestParameters.ClientId] = ClientId,
            [OAuthRequestParameters.CodeChallenge] = challenge,
            [OAuthRequestParameters.CodeChallengeMethod] = OAuthRequestParameters.CodeChallengeMethodS256,
            [OAuthRequestParameters.RedirectUri] = RegisteredRedirectUri.ToString(),
            [OAuthRequestParameters.Scope] = WellKnownScopes.OpenId
        };
        ServerHttpResponse parResponse = await host.DispatchAtPathAsync(
            material.Registration.TenantId.Value,
            ServerEndpointPaths.Par,
            "POST", parFields, new RequestContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, parResponse.StatusCode);
        string requestUri = ExtractRequestUri(parResponse.Body);

        //Authorize.
        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameters.ClientId] = ClientId,
            [OAuthRequestParameters.RequestUri] = requestUri
        };
        RequestContext authorizeContext = new();
        authorizeContext.SetSubjectId("subject-1");
        ServerHttpResponse authorizeResponse = await host.DispatchAtPathAsync(
            material.Registration.TenantId.Value,
            ServerEndpointPaths.Authorize,
            WellKnownHttpMethods.Get, authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode);
        string code = ExtractCodeFromLocation(authorizeResponse.Location!);

        //Token exchange.
        RequestFields tokenFields = new()
        {
            [OAuthRequestParameters.GrantType] = OAuthRequestParameters.GrantTypeAuthorizationCode,
            [OAuthRequestParameters.Code] = code,
            [OAuthRequestParameters.CodeVerifier] = verifier,
            [OAuthRequestParameters.ClientId] = ClientId,
            [OAuthRequestParameters.RedirectUri] = RegisteredRedirectUri.ToString()
        };
        ServerHttpResponse tokenResponse = await host.DispatchAtPathAsync(
            material.Registration.TenantId.Value,
            ServerEndpointPaths.Token,
            "POST", tokenFields, new RequestContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode,
            $"Token exchange must succeed. Body: {tokenResponse.Body}");
        Assert.IsTrue(tokenResponse.Headers.TryGetValue(
            WellKnownHttpHeaderNames.CacheControl, out string? cacheControl),
            "Token response must emit Cache-Control header per OAuth 2.1 §3.2.3.");
        Assert.AreEqual(WellKnownCacheControlValues.NoStore, cacheControl);
    }


    [TestMethod]
    public async Task RegistrationCreateResponseIncludesCacheControlNoStore()
    {
        //OAuth 2.1 §3.2.3 — the RFC 7591 §3.2.1 response carries the
        //newly-issued registration_access_token and (when applicable)
        //client_secret. Cache-Control: no-store required.
        using TestHostShell host = new(TimeProvider);

        ImmutableHashSet<ServerCapabilityName> capabilities = ImmutableHashSet.Create(
            ServerCapabilityName.DynamicClientRegistration);

        TenantId tenantId = new("dynamic-clients");
        const string body = /*lang=json,strict*/ """
            {"redirect_uris":["https://client.example.com/callback"],"client_name":"phase9a"}
            """;

        RequestContext context = new();
        context.SetIssuer(host.IssuerUri);

        ServerHttpResponse response = await RegistrationEndpoints.HandleCreateAsync(
            tenantId, body, capabilities, context, host.Server,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode,
            $"Registration must succeed. Body: {response.Body}");
        Assert.IsTrue(response.Headers.TryGetValue(
            WellKnownHttpHeaderNames.CacheControl, out string? cacheControl),
            "Registration response must emit Cache-Control header per OAuth 2.1 §3.2.3.");
        Assert.AreEqual(WellKnownCacheControlValues.NoStore, cacheControl);
    }


    private static string ExtractRequestUri(string body)
    {
        //Minimal extraction — the response body is the JSON the PAR emits
        //directly. Find the request_uri value between quotes.
        const string marker = "\"request_uri\":\"";
        int start = body.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
        int end = body.IndexOf('"', start);
        return body.Substring(start, end - start);
    }


    private static string ExtractCodeFromLocation(string location)
    {
        int queryStart = location.IndexOf('?', StringComparison.Ordinal);
        string query = location[(queryStart + 1)..];
        foreach(string pair in query.Split('&'))
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            if(eq > 0 && string.Equals(pair[..eq], OAuthRequestParameters.Code, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(pair[(eq + 1)..]);
            }
        }
        throw new InvalidOperationException(
            $"Authorize redirect did not carry a code parameter. Got: {location}");
    }
}
