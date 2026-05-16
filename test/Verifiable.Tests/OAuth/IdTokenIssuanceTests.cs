using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Oidc;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// OIDC Phase A — end-to-end ID Token issuance through the token endpoint
/// per <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core §2</see>
/// and <see href="https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse">§3.1.3.3</see>.
/// </summary>
/// <remarks>
/// Drives PAR → Authorize → Token with <c>openid</c> in the requested scope
/// and asserts the wire-level shape of the issued <c>id_token</c>. Tests
/// dispatch directly via <see cref="TestHostShell.DispatchAtPathAsync"/>
/// rather than through the HTTP transport — same pattern as
/// <see cref="RefreshGrantTests"/>, sufficient for asserting the AS's
/// response body. DPoP-bound ID Token (RFC 9449 §6 cnf-on-ID-Token)
/// behaviour is exercised by the existing DPoP end-to-end tests once the
/// access-token cnf path proves the binding flows through; a dedicated
/// ID-Token-cnf test is deferred to a follow-up.
/// </remarks>
[TestClass]
internal sealed class IdTokenIssuanceTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 5, 16, 12, 0, 0, TimeSpan.Zero));

    private const string ClientId = "https://client.example.com";
    private const string SubjectId = "subject-oidc-1";
    private static readonly Uri ClientBaseUri = new("https://client.example.com");
    private static readonly Uri RedirectUri =
        new("https://client.example.com/callback");


    [TestMethod]
    public async Task TokenEndpointEmitsIdTokenWhenOpenIdScopeRequested()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(
            subject: SubjectId,
            name: "Alice",
            email: "alice@example.com",
            emailVerified: true);

        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        string scope = $"{WellKnownScopes.OpenId} {WellKnownScopes.Profile} {WellKnownScopes.Email}";
        ServerHttpResponse tokenResponse = await DriveCodeExchangeAsync(host, material, scope).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode,
            $"Token exchange must succeed. Body: {tokenResponse.Body}");

        using JsonDocument body = JsonDocument.Parse(tokenResponse.Body);
        Assert.IsTrue(body.RootElement.TryGetProperty("id_token", out JsonElement idTokenElement),
            $"Response must include id_token when openid scope was requested. Body: {tokenResponse.Body}");

        string idToken = idTokenElement.GetString()!;
        using JsonDocument payload = JwtPayloadReader.ParsePayloadJson(idToken);

        Assert.AreEqual(SubjectId, payload.RootElement.GetProperty(WellKnownJwtClaimNames.Sub).GetString());
        Assert.AreEqual(ClientId, payload.RootElement.GetProperty(WellKnownJwtClaimNames.Aud).GetString());
        Assert.AreEqual("Alice", payload.RootElement.GetProperty(WellKnownJwtClaimNames.Name).GetString());
        Assert.AreEqual("alice@example.com", payload.RootElement.GetProperty(WellKnownJwtClaimNames.Email).GetString());
        Assert.IsTrue(payload.RootElement.GetProperty(WellKnownJwtClaimNames.EmailVerified).GetBoolean());
    }


    [TestMethod]
    public async Task TokenEndpointOmitsIdTokenWhenOpenIdScopeAbsent()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        //Profile + email only, no openid — the ID Token producer's IsApplicable
        //gate skips it and the response body omits id_token.
        string scope = $"{WellKnownScopes.Profile} {WellKnownScopes.Email}";
        ServerHttpResponse tokenResponse = await DriveCodeExchangeAsync(host, material, scope).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument body = JsonDocument.Parse(tokenResponse.Body);
        Assert.IsFalse(body.RootElement.TryGetProperty("id_token", out _),
            "id_token must be omitted when openid scope is absent.");
    }


    [TestMethod]
    public async Task IdTokenOmitsProfileClaimsWhenProfileScopeAbsent()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(
            subject: SubjectId,
            name: "Alice",
            email: "alice@example.com");

        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        //openid only — emit ID Token but no profile/email claims.
        ServerHttpResponse tokenResponse = await DriveCodeExchangeAsync(
            host, material, WellKnownScopes.OpenId).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument body = JsonDocument.Parse(tokenResponse.Body);
        string idToken = body.RootElement.GetProperty("id_token").GetString()!;
        using JsonDocument payload = JwtPayloadReader.ParsePayloadJson(idToken);

        Assert.AreEqual(SubjectId, payload.RootElement.GetProperty(WellKnownJwtClaimNames.Sub).GetString());
        Assert.IsFalse(payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.Name, out _),
            "name must not be emitted without profile scope.");
        Assert.IsFalse(payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.Email, out _),
            "email must not be emitted without email scope.");
    }


    [TestMethod]
    public async Task IdTokenEmitsAddressClaimAsStructuredObjectWhenAddressScopeGranted()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SubjectClaims[SubjectId] = new OidcClaims
        {
            Subject = SubjectId,
            Address = new AddressClaims
            {
                Locality = "Helsinki",
                Country = "FI",
                PostalCode = "00100"
            }
        };

        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        string scope = $"{WellKnownScopes.OpenId} {WellKnownScopes.Address}";
        ServerHttpResponse tokenResponse = await DriveCodeExchangeAsync(host, material, scope).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument body = JsonDocument.Parse(tokenResponse.Body);
        string idToken = body.RootElement.GetProperty("id_token").GetString()!;
        using JsonDocument payload = JwtPayloadReader.ParsePayloadJson(idToken);

        JsonElement address = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Address);
        Assert.AreEqual(JsonValueKind.Object, address.ValueKind);
        Assert.AreEqual("Helsinki", address.GetProperty("locality").GetString());
        Assert.AreEqual("FI", address.GetProperty("country").GetString());
        Assert.AreEqual("00100", address.GetProperty("postal_code").GetString());
    }


    [TestMethod]
    public async Task IdTokenEmitsPhoneClaimsWhenPhoneScopeGranted()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SubjectClaims[SubjectId] = new OidcClaims
        {
            Subject = SubjectId,
            Phone = new PhoneClaims
            {
                PhoneNumber = "+358401234567",
                PhoneNumberVerified = true
            }
        };

        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        string scope = $"{WellKnownScopes.OpenId} {WellKnownScopes.Phone}";
        ServerHttpResponse tokenResponse = await DriveCodeExchangeAsync(host, material, scope).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument body = JsonDocument.Parse(tokenResponse.Body);
        string idToken = body.RootElement.GetProperty("id_token").GetString()!;
        using JsonDocument payload = JwtPayloadReader.ParsePayloadJson(idToken);

        Assert.AreEqual("+358401234567", payload.RootElement.GetProperty(WellKnownJwtClaimNames.PhoneNumber).GetString());
        Assert.IsTrue(payload.RootElement.GetProperty(WellKnownJwtClaimNames.PhoneNumberVerified).GetBoolean());
    }


    [TestMethod]
    public async Task IdTokenIssMatchesIssuerUriAndAudMatchesClientId()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse tokenResponse = await DriveCodeExchangeAsync(
            host, material, WellKnownScopes.OpenId).ConfigureAwait(false);

        using JsonDocument body = JsonDocument.Parse(tokenResponse.Body);
        string idToken = body.RootElement.GetProperty("id_token").GetString()!;
        using JsonDocument payload = JwtPayloadReader.ParsePayloadJson(idToken);

        string iss = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Iss).GetString()!;
        Assert.IsTrue(iss.Contains(material.Registration.TenantId.Value, StringComparison.Ordinal),
            $"iss must carry the tenant segment, got '{iss}'.");
        Assert.AreEqual(ClientId, payload.RootElement.GetProperty(WellKnownJwtClaimNames.Aud).GetString());
    }


    [TestMethod]
    public async Task IdTokenCarriesExpStrictlyAfterIatWithIatAtRequestTime()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse tokenResponse = await DriveCodeExchangeAsync(
            host, material, WellKnownScopes.OpenId).ConfigureAwait(false);

        using JsonDocument body = JsonDocument.Parse(tokenResponse.Body);
        string idToken = body.RootElement.GetProperty("id_token").GetString()!;
        using JsonDocument payload = JwtPayloadReader.ParsePayloadJson(idToken);

        long iat = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Iat).GetInt64();
        long exp = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Exp).GetInt64();

        Assert.IsGreaterThan(iat, exp,
            "exp must be strictly greater than iat.");
        Assert.AreEqual(TimeProvider.GetUtcNow().ToUnixTimeSeconds(), iat,
            "iat must reflect the request time captured at the start of token issuance.");
    }


    private async Task<ServerHttpResponse> DriveCodeExchangeAsync(
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
        ServerHttpResponse parResponse = await host.DispatchAtPathAsync(
            material.Registration.TenantId.Value,
            ServerEndpointPaths.Par, "POST",
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
        ServerHttpResponse authorizeResponse = await host.DispatchAtPathAsync(
            material.Registration.TenantId.Value,
            ServerEndpointPaths.Authorize, WellKnownHttpMethods.Get,
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
        return await host.DispatchAtPathAsync(
            material.Registration.TenantId.Value,
            ServerEndpointPaths.Token, "POST",
            tokenFields, new RequestContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
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
