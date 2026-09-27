using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Net;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Oidc;
using Verifiable.OAuth.ProtectedResource;
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


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.12">RFC 8725 §3.12</see>: "If more
    /// than one kind of JWT can be issued by the same issuer, the validation rules for those JWTs MUST
    /// be written such that they are mutually exclusive, rejecting JWTs of the wrong kind", and among
    /// the strategies it names, "Use different keys for different kinds of JWTs. Then the keys used to
    /// validate one kind of JWT will fail to validate other kinds of JWTs." An access token presented
    /// at UserInfo over the wire whose header names a key the registration does not list for access
    /// tokens, and which verifies under that key, is refused with 401 <c>invalid_token</c> and the
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 §3</see> challenge. The
    /// rows are a key the registration lists for its client assertions and the access-token key of
    /// another registration on the same server; both verify the signature, neither signs access tokens
    /// for this registration.
    /// </summary>
    /// <param name="row">Which key the re-signed token names: <see cref="ClientAssertionKeyRow"/> or <see cref="OtherRegistrationKeyRow"/>.</param>
    [TestMethod]
    [DataRow(ClientAssertionKeyRow)]
    [DataRow(OtherRegistrationKeyRow)]
    public async Task UserInfoRefusesAnAccessTokenSignedUnderAKeyNotListedForAccessTokensAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        using VerifierKeyMaterial otherMaterial = await host.RegisterDpopClientAsync(
            OtherClientId, OtherClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId)
            .ConfigureAwait(false);

        KeyId foreignKeyId = row switch
        {
            ClientAssertionKeyRow => await ListClientAssertionKeyAsync(host, material).ConfigureAwait(false),
            _ => otherMaterial.SigningKeyId
        };

        string resignedAccessToken = await ResignUnderKeyAsync(host, accessToken, foreignKeyId).ConfigureAwait(false);

        using HttpResponseMessage response = await PostUserInfoOverWireAsync(host, material, resignedAccessToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues(WellKnownHttpHeaderNames.WwwAuthenticate, out IEnumerable<string>? challenges),
            "RFC 6750 §3: the refusal carries a WWW-Authenticate challenge.");
        string challenge = challenges.Single();
        Assert.IsTrue(challenge.StartsWith("Bearer ", StringComparison.Ordinal), challenge);
        Assert.IsTrue(BearerTokenChallenge.TryParse(challenge, out BearerTokenChallengeParameters parameters), challenge);
        Assert.AreEqual("invalid_token", parameters.Error, challenge);

        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_token", document.RootElement.GetProperty("error").GetString());
        Assert.AreEqual(
            "Access token is not signed by a key this server issues access tokens with.",
            document.RootElement.GetProperty("error_description").GetString());
        Assert.IsFalse(document.RootElement.TryGetProperty("sub", out _), "A refused token reveals no subject.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys">OpenID Connect
    /// Core 1.0 §10.1.1</see>: "The JWK Set document at the jwks_uri SHOULD retain recently
    /// decommissioned signing keys for a reasonable period of time to facilitate a smooth transition."
    /// An access token signed before its key was rotated out of signing, and still listed among the
    /// registration's access-token keys as retiring, is served at UserInfo over the wire: the keys a
    /// server issues access tokens with include those in rotation, not only the one currently signing.
    /// </summary>
    [TestMethod]
    public async Task UserInfoServesATokenSignedUnderARetiringAccessTokenKeyAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId)
            .ConfigureAwait(false);

        KeyId newCurrentKeyId = host.AllocateSigningKey();
        await host.UpdateSigningKeysAsync(material.Registration.TenantId.Value, new Dictionary<KeyUsageContext, SigningKeySet>
        {
            [KeyUsageContext.AccessTokenIssuance] = new SigningKeySet
            {
                Current = [newCurrentKeyId],
                Retiring = [material.SigningKeyId]
            },
            [KeyUsageContext.IdTokenIssuance] = material.Registration.SigningKeys[KeyUsageContext.IdTokenIssuance]
        }).ConfigureAwait(false);

        using HttpResponseMessage response = await PostUserInfoOverWireAsync(host, material, accessToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(SubjectId, document.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>The row of the key-listing test whose foreign key is one the registration lists for its client assertions.</summary>
    private const string ClientAssertionKeyRow = "client-assertion-key";

    /// <summary>The row of the key-listing test whose foreign key is another registration's access-token key.</summary>
    private const string OtherRegistrationKeyRow = "other-registration-key";

    /// <summary>The client identifier of the second registration whose signing key the foreign-key row borrows.</summary>
    private const string OtherClientId = "https://other.userinfo.client.test";

    /// <summary>The base URI of the second registration.</summary>
    private static Uri OtherClientBaseUri { get; } = new("https://other.userinfo.client.test");


    /// <summary>
    /// Allocates a fresh signing key and lists it under the registration's
    /// <see cref="KeyUsageContext.ClientAssertion"/> usage beside the access-token and ID Token sets
    /// the registration already holds, so the server can resolve the key by its <c>kid</c> while the
    /// registration does not list it for access tokens.
    /// </summary>
    /// <param name="host">The host holding the registration and its key stores.</param>
    /// <param name="material">The registration to extend.</param>
    /// <returns>The identifier of the key now listed for client assertions.</returns>
    private static async Task<KeyId> ListClientAssertionKeyAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        KeyId assertionKeyId = host.AllocateSigningKey();
        Dictionary<KeyUsageContext, SigningKeySet> signingKeys = new(material.Registration.SigningKeys)
        {
            [KeyUsageContext.ClientAssertion] = new SigningKeySet { Current = [assertionKeyId] }
        };
        await host.UpdateSigningKeysAsync(material.Registration.TenantId.Value, signingKeys).ConfigureAwait(false);

        return assertionKeyId;
    }


    /// <summary>
    /// Rebuilds <paramref name="accessToken"/> with a protected header naming <paramref name="keyId"/>
    /// and keeping the token's <c>alg</c> and <c>typ</c>, the payload segment unchanged, and signs it
    /// with the private half the host holds for that key, so the token verifies under the named key and
    /// differs from the issued one only in which key signed it.
    /// </summary>
    /// <param name="host">The host whose signing-key store holds the key's private half.</param>
    /// <param name="accessToken">The access token the server issued.</param>
    /// <param name="keyId">The key the rebuilt token names and is signed under.</param>
    /// <returns>The re-signed compact JWS.</returns>
    private static async Task<string> ResignUnderKeyAsync(TestHostShell host, string accessToken, KeyId keyId)
    {
        string[] parts = accessToken.Split('.');
        using IMemoryOwner<byte> headerOwner = TestSetup.Base64UrlDecoder(parts[0], BaseMemoryPool.Shared);
        using JsonDocument headerDocument = JsonDocument.Parse(headerOwner.Memory);
        string algorithm = headerDocument.RootElement.GetProperty("alg").GetString()!;
        string type = headerDocument.RootElement.GetProperty("typ").GetString()!;

        string headerJson = $"{{\"alg\":\"{algorithm}\",\"typ\":\"{type}\",\"kid\":\"{keyId.Value}\"}}";
        string headerSegment = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(headerJson));

        PrivateKeyMemory signingKey = host.Host("default").SigningKeys[keyId];
        byte[] signingInput = Encoding.ASCII.GetBytes($"{headerSegment}.{parts[1]}");
        using Signature signature = await signingKey.SignAsync(signingInput, BaseMemoryPool.Shared).ConfigureAwait(false);

        return $"{headerSegment}.{parts[1]}.{TestSetup.Base64UrlEncoder(signature.AsReadOnlySpan())}";
    }


    /// <summary>
    /// POSTs to the registration's UserInfo endpoint over the host's loopback HTTPS listener with
    /// <paramref name="accessToken"/> under the <c>Bearer</c> scheme, so the request, its
    /// <c>Authorization</c> header and the response's headers cross the real transport.
    /// </summary>
    /// <param name="host">The host whose listener serves the request.</param>
    /// <param name="material">The registration whose UserInfo path is addressed.</param>
    /// <param name="accessToken">The access token presented.</param>
    /// <returns>The wire response; the caller disposes it.</returns>
    private async Task<HttpResponseMessage> PostUserInfoOverWireAsync(
        TestHostShell host, VerifierKeyMaterial material, string accessToken)
    {
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        Uri userInfoUrl = new(hosted.HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.UserInfo, material.Registration.TenantId.Value));
        using HttpRequestMessage request = new(HttpMethod.Post, userInfoUrl);
        _ = request.Headers.TryAddWithoutValidation(
            WellKnownHttpHeaderNames.Authorization, $"{WellKnownAuthenticationSchemes.Bearer} {accessToken}");

        return await hosted.SharedHttpClient!.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
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
