using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Oidc;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// UserInfo endpoint per
/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">OIDC Core §5.3</see>.
/// </summary>
/// <remarks>
/// <para>
/// The endpoint shell (registration, routing, bearer header gate) pairs
/// with bearer-token validation: signature,
/// <c>iss</c> match, <c>exp</c> check, and the OIDC Core §5.3.1 mandate
/// that the access token's scope include <c>openid</c>. The response body
/// carries only the validated <c>sub</c>; a future contributor walk will
/// expand it.
/// </para>
/// <para>
/// Tests dispatch directly against <see cref="EndpointServer.DispatchAsync"/>
/// rather than through <see cref="TestHostShell.DispatchAtEndpointAsync(string, string, string, RequestFields, ExchangeContext, CancellationToken)"/>
/// — the latter constructs <see cref="RequestHeaders.Empty"/>, and
/// UserInfo is the first library endpoint whose dispatch carries a
/// per-request header (the <c>Authorization</c> bearer).
/// </para>
/// </remarks>
[TestClass]
internal sealed class UserInfoEndpointTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch.AddDays(-15));

    private const string ClientId = "https://userinfo.client.test";
    private const string SubjectId = "subject-userinfo";
    private static Uri ClientBaseUri { get; } = new("https://userinfo.client.test");
    private static Uri RedirectUri { get; } =
        new("https://client.example.com/callback");


    //Header-gate tests — exercised before any token-content validation,
    //so the test does not need to issue a real access token.

    [TestMethod]
    public async Task PostWithoutAuthorizationHeaderReturnsUnauthorized()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterPlainUserInfoClientAsync(host).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterPlainUserInfoClientAsync(host).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterPlainUserInfoClientAsync(host).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterPlainUserInfoClientAsync(host).ConfigureAwait(false);

        //Bearer is present but the payload is not a well-formed JWS.
        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Post,
            authorizationHeader: "Bearer not.a.valid.jwt")
            .ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode);
        Assert.Contains(OAuthErrors.InvalidToken, response.Body);
    }


    /// <summary>
    /// RFC 7519 §4: "The JWT Claim Names within a Claims Set MUST be unique." An access token
    /// whose Claims Set repeats <c>sub</c> — the attacker's value first, the honest value last —
    /// is refused with the same 401 <c>invalid_token</c> outcome as any other malformed bearer
    /// token, never a server error. Only the payload segment is rebuilt by hand (never through
    /// this repository's serializers) and re-signed with the AS's own signing key for that
    /// <c>kid</c>; the header is untouched, so only the payload's well-formedness gate — not an
    /// invalid signature — can be responsible for the refusal.
    /// </summary>
    [TestMethod]
    public async Task PostWithAccessTokenCarryingDuplicateSubClaimReturnsUnauthorized()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId, name: "Alice", email: "alice@example.com");

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId)
            .ConfigureAwait(false);

        string[] parts = accessToken.Split('.');
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
        string tamperedAccessToken = $"{parts[0]}.{tamperedPayloadB64}.{signatureB64}";

        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Post,
            authorizationHeader: "Bearer " + tamperedAccessToken)
            .ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.IsLessThan(500, response.StatusCode, "A duplicate claim must never surface as a server error.");
        Assert.Contains(OAuthErrors.InvalidToken, response.Body);
    }


    [TestMethod]
    public async Task EndpointNotEmittedWhenUserInfoCapabilityAbsent()
    {
        //A registration without WellKnownCapabilityIdentifiers.OidcUserInfo must not have
        //a UserInfo endpoint in its chain — request resolves as 404 rather
        //than 401, confirming the builder's capability filter runs.
        await using TestHostShell host = new(TimeProvider);

        ImmutableHashSet<CapabilityIdentifier> capabilitiesWithoutUserInfo =
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OidcOpenIdConnect);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, capabilitiesWithoutUserInfo).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Post,
            authorizationHeader: "Bearer doesnt-matter")
            .ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            "Capability filter must remove UserInfo from the chain when not allowed.");
    }


    //Token-validation + contributor-walk tests — drive a
    //full PAR / Authorize / Token exchange to mint a real access token, then
    //present it to /userinfo.

    [TestMethod]
    public async Task ValidAccessTokenWithOpenidOnlyReturnsOnlySubject()
    {
        await using TestHostShell host = new(TimeProvider);
        //Subject is seeded with profile + email, but the access token's
        //granted scope is openid only — UserInfo must emit just sub, no
        //scope-driven claims.
        _ = host.SeedTestSubject(subject: SubjectId, name: "Alice", email: "alice@example.com");

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId)
            .ConfigureAwait(false);

        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Post,
            authorizationHeader: "Bearer " + accessToken)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        Assert.AreEqual(SubjectId,
            body.RootElement.GetProperty(WellKnownJwtClaimNames.Sub).GetString());
        Assert.IsFalse(body.RootElement.TryGetProperty(WellKnownJwtClaimNames.Name, out _),
            "name must not appear without the profile scope.");
        Assert.IsFalse(body.RootElement.TryGetProperty(WellKnownJwtClaimNames.Email, out _),
            "email must not appear without the email scope.");
    }


    [TestMethod]
    public async Task ValidAccessTokenWithProfileScopeReturnsProfileClaims()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId, name: "Alice");

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string scope = $"{WellKnownScopes.OpenId} {WellKnownScopes.Profile}";
        string accessToken = await IssueAccessTokenAsync(host, material, scope)
            .ConfigureAwait(false);

        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Post,
            authorizationHeader: "Bearer " + accessToken)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        Assert.AreEqual(SubjectId,
            body.RootElement.GetProperty(WellKnownJwtClaimNames.Sub).GetString());
        Assert.AreEqual("Alice",
            body.RootElement.GetProperty(WellKnownJwtClaimNames.Name).GetString(),
            "profile scope must trigger the OidcStandardClaimsContributor profile rule.");
    }


    [TestMethod]
    public async Task ValidAccessTokenWithEmailScopeReturnsEmailClaims()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(
            subject: SubjectId,
            email: "alice@example.com",
            emailVerified: true);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string scope = $"{WellKnownScopes.OpenId} {WellKnownScopes.Email}";
        string accessToken = await IssueAccessTokenAsync(host, material, scope)
            .ConfigureAwait(false);

        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Post,
            authorizationHeader: "Bearer " + accessToken)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        Assert.AreEqual("alice@example.com",
            body.RootElement.GetProperty(WellKnownJwtClaimNames.Email).GetString());
        Assert.IsTrue(body.RootElement.GetProperty(WellKnownJwtClaimNames.EmailVerified).GetBoolean());
    }


    [TestMethod]
    public async Task ValidAccessTokenWithAddressScopeReturnsStructuredAddress()
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

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string scope = $"{WellKnownScopes.OpenId} {WellKnownScopes.Address}";
        string accessToken = await IssueAccessTokenAsync(host, material, scope)
            .ConfigureAwait(false);

        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Post,
            authorizationHeader: "Bearer " + accessToken)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        JsonElement address = body.RootElement.GetProperty(WellKnownJwtClaimNames.Address);
        Assert.AreEqual(JsonValueKind.Object, address.ValueKind,
            "address must serialise as a nested JSON object per OIDC Core §5.1.1.");
        Assert.AreEqual("Helsinki", address.GetProperty("locality").GetString());
        Assert.AreEqual("FI", address.GetProperty("country").GetString());
        Assert.AreEqual("00100", address.GetProperty("postal_code").GetString());
    }


    /// <summary>
    /// The UserInfo response places the application-resolved subject identifier in the required sub claim.
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">Core §5.3.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ResolveSubjectIdentifierIsConsultedOnUserInfo()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectIdentifierAsync =
                (endUserId, _, _, _) => ValueTask.FromResult($"hashed-{endUserId}");
        }).ConfigureAwait(false);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId)
            .ConfigureAwait(false);

        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Post,
            authorizationHeader: "Bearer " + accessToken)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        Assert.AreEqual($"hashed-{SubjectId}",
            body.RootElement.GetProperty(WellKnownJwtClaimNames.Sub).GetString(),
            "UserInfo response sub must reflect the AS-installed "
            + "ResolveSubjectIdentifierAsync delegate, not the validated "
            + "access token's raw sub claim.");
    }


    /// <summary>
    /// <see cref="UserInfoEndpoints"/>'s <c>openid</c>-in-token-scope check
    /// (OIDC Core §5.3.1) is correct only because the token endpoint's scope source guarantees a
    /// <c>client_credentials</c> token — whose <c>sub</c> is the client itself, a machine, not an
    /// End-User — never carries <c>openid</c>: <c>DropIdentityScopesForNonEndUserGrant</c> narrows it
    /// away at issuance (RFC 6749 §3.3) even though the request explicitly asked for it and the
    /// tenant has the <see cref="WellKnownCapabilityIdentifiers.OidcOpenIdConnect"/> feature granted.
    /// UserInfo therefore refuses the resulting token an identity body — proving the refusal follows
    /// from the source-side guarantee, not from UserInfo second-guessing the grant type itself.
    /// </summary>
    [TestMethod]
    public async Task ClientCredentialsAccessTokenIsRefusedIdentityBodyAtUserInfo()
    {
        await using TestHostShell host = new(TimeProvider);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId,
            ClientBaseUri,
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
                WellKnownCapabilityIdentifiers.OidcUserInfo,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);
        const string ClientSecret = "s3cret-of-the-machine";
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                ValueTask.FromResult(
                    fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                    && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
        }).ConfigureAwait(false);

        string accessToken = await IssueClientCredentialsAccessTokenAsync(
            host, material, ClientSecret, WellKnownScopes.OpenId).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Post,
            authorizationHeader: "Bearer " + accessToken)
            .ConfigureAwait(false);

        Assert.AreEqual(403, response.StatusCode,
            "OIDC Core §5.3.1 refuses UserInfo (insufficient_scope) to a token whose scope never "
            + "carries openid — guaranteed here because client_credentials narrows it away at issuance.");
        Assert.Contains(OAuthErrors.InsufficientScope, response.Body);
    }


    /// <summary>
    /// Dispatches a real <c>client_credentials</c> token request (RFC 6749 §4.4) and returns the
    /// issued access token — the machine-subject counterpart to <see cref="IssueAccessTokenAsync"/>'s
    /// authorization_code drive.
    /// </summary>
    private async ValueTask<string> IssueClientCredentialsAccessTokenAsync(
        TestHostShell host, VerifierKeyMaterial material, string clientSecret, string scope)
    {
        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.ClientCredentialsToken,
            WellKnownHttpMethods.Post,
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
                [OAuthRequestParameterNames.ClientId] = material.Registration.ClientId,
                [OAuthRequestParameterNames.ClientSecret] = clientSecret,
                [OAuthRequestParameterNames.Scope] = scope
            },
            [],
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument body = JsonDocument.Parse(tokenResponse.Body);

        return body.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
    }


    [TestMethod]
    public async Task ExpiredAccessTokenReturnsUnauthorized()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

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


    private static async Task<VerifierKeyMaterial> RegisterPlainUserInfoClientAsync(TestHostShell host)
    {
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
            WellKnownCapabilityIdentifiers.OidcUserInfo);
        return await host.RegisterClientAsync(ClientId, ClientBaseUri, capabilities).ConfigureAwait(false);
    }


    private async ValueTask<string> IssueAccessTokenAsync(
        TestHostShell host, VerifierKeyMaterial material, string scope)
    {
        InProcessAuthCodeDriveResult result = await InProcessAuthCodeDriver.DriveAsync(
            host, material, SubjectId, RedirectUri,
            new InProcessAuthCodeDriveOptions { Scope = scope },
            TestContext.CancellationToken).ConfigureAwait(false);

        using JsonDocument body = JsonDocument.Parse(result.TokenResponse.Body);
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

        ExchangeContext context = [];
        context.SetTenantId(segment);
        return await host.Server.DispatchAsync(request, context, TestContext.CancellationToken)
            .ConfigureAwait(false);
    }


}
