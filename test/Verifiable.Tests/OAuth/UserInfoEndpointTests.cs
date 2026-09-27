using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Dpop;
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
/// The header-gate, claim-contribution and expiry tests dispatch in-process against
/// <see cref="EndpointServer.DispatchAsync"/> rather than through
/// <see cref="TestHostShell.DispatchAtEndpointAsync(string, string, string, RequestFields, ExchangeContext, CancellationToken)"/>,
/// which constructs <see cref="RequestHeaders.Empty"/> while UserInfo reads the <c>Authorization</c>
/// header. The key-admission, challenge and sender-constraint tests send their request over the
/// host's loopback HTTPS listener, so the <c>Authorization</c> and <c>DPoP</c> request headers and the
/// <c>WWW-Authenticate</c> response header cross the real transport.
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
    /// tokens, and which verifies under that key, is refused with 401 <c>invalid_token</c>, and the
    /// refusal carries the challenge
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 §3</see> requires: "If the
    /// protected resource request does not include authentication credentials or does not contain an
    /// access token that enables access to the protected resource, the resource server MUST include the
    /// HTTP "WWW-Authenticate" response header field", here <c>Bearer error="invalid_token"</c>. The
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

        string resignedAccessToken = await CompactJwsResigning.ResignWithHeaderAsync(
            host, accessToken, foreignKeyId, "at+jwt").ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, resignedAccessToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "RFC 6750 §3: the refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual("Bearer error=\"invalid_token\"", challenges.Single());

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
    /// registration's access-token keys as retiring, is served at UserInfo over the wire. The row is a
    /// pin of the library's own admission policy, which admits every rotation slot of the access-token
    /// key set; the §10.1.1 retention practice quoted above is what that policy mirrors, not a rule the
    /// row derives from.
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

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, accessToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(SubjectId, document.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>:
    /// "invalid_token The access token provided is expired, revoked, malformed, or invalid for other
    /// reasons. The resource SHOULD respond with the HTTP 401 (Unauthorized) status code." An access
    /// token whose protected header's <c>kid</c> is a single space names no key and is malformed: it is
    /// refused at UserInfo over the wire with 401 <c>invalid_token</c> and the challenge
    /// <c>Bearer error="invalid_token"</c>, never a server error.
    /// </summary>
    [TestMethod]
    public async Task UserInfoRefusesAnAccessTokenWhoseKidIsWhitespaceAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId)
            .ConfigureAwait(false);
        string whitespaceKidToken = await CompactJwsResigning.ResignWithHeaderAsync(
            host, accessToken, material.SigningKeyId, " ", "at+jwt").ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, whitespaceKidToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "RFC 6750 §3: the refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual("Bearer error=\"invalid_token\"", challenges.Single());

        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_token", document.RootElement.GetProperty("error").GetString());
        Assert.AreEqual("Access token header is missing kid.", document.RootElement.GetProperty("error_description").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 §3</see>: "If the
    /// protected resource request does not include authentication credentials or does not contain an
    /// access token that enables access to the protected resource, the resource server MUST include the
    /// HTTP "WWW-Authenticate" response header field". An access token that verifies under the
    /// registration's access-token key but carries no <c>sub</c> identifies no End-User, so UserInfo
    /// refuses it over the wire with 401 <c>invalid_token</c>, and the refusal carries the challenge
    /// <c>Bearer error="invalid_token"</c>.
    /// </summary>
    [TestMethod]
    public async Task UserInfoRefusalOfATokenWithoutSubjectCarriesABearerChallengeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId)
            .ConfigureAwait(false);

        string[] parts = accessToken.Split('.');
        using IMemoryOwner<byte> payloadOwner = TestSetup.Base64UrlDecoder(parts[1], BaseMemoryPool.Shared);
        JsonObject payload = JsonNode.Parse(payloadOwner.Memory.Span)!.AsObject();
        Assert.IsTrue(payload.Remove("sub"), "The issued access token carries a sub claim to remove.");
        string subjectlessToken = await CompactJwsResigning.ResignWithPayloadAsync(
            host, accessToken, material.SigningKeyId, payload.ToJsonString()).ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, subjectlessToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "RFC 6750 §3: the refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual("Bearer error=\"invalid_token\"", challenges.Single());

        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_token", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>:
    /// "insufficient_scope The request requires higher privileges than provided by the access token.
    /// The resource server SHOULD respond with the HTTP 403 (Forbidden) status code and MAY include the
    /// "scope" attribute with the scope necessary to access the protected resource." An access token
    /// granted <c>profile</c> but not <c>openid</c> is refused at UserInfo over the wire with 403
    /// <c>insufficient_scope</c>, and the refusal carries the
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 §3</see> challenge naming
    /// the scope UserInfo requires: <c>Bearer error="insufficient_scope", scope="openid"</c>.
    /// </summary>
    [TestMethod]
    public async Task UserInfoRefusalForAMissingOpenIdScopeCarriesAnInsufficientScopeChallengeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId, name: "Alice");

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.Profile)
            .ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, accessToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "RFC 6750 §3: the refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual("Bearer error=\"insufficient_scope\", scope=\"openid\"", challenges.Single());

        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("insufficient_scope", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 §7.2</see>: "such a
    /// protected resource MUST reject a DPoP-bound access token received as a bearer token per
    /// [RFC6750]." An access token the token endpoint bound to the client's DPoP key (<c>cnf.jkt</c>),
    /// presented at UserInfo over the wire under the <c>Bearer</c> scheme with no DPoP proof, is refused
    /// with 401 <c>invalid_token</c> and the challenge <c>Bearer error="invalid_token"</c>, and no claim
    /// of the End-User is returned.
    /// </summary>
    [TestMethod]
    public async Task UserInfoRefusesADpopBoundTokenPresentedUnderBearerAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        string boundAccessToken = await IssueDpopBoundAccessTokenAsync(host, material, fixture).ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, boundAccessToken, scheme: "Bearer")
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "RFC 6750 §3: the refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual("Bearer error=\"invalid_token\"", challenges.Single());

        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_token", document.RootElement.GetProperty("error").GetString());
        Assert.IsFalse(document.RootElement.TryGetProperty("sub", out _), "A refused token reveals no subject.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 §7.1</see>: "A
    /// DPoP-bound access token is sent using the Authorization request header field per Section 11.6.2
    /// of [RFC9110] with an authentication scheme of DPoP." and "For such an access token, a resource
    /// server MUST check that a DPoP proof was also received in the DPoP header field of the HTTP
    /// request, check the DPoP proof according to the rules in Section 4.3, and check that the public
    /// key of the DPoP proof matches the public key to which the access token is bound per Section 6."
    /// A DPoP-bound access token presented at UserInfo over the wire under the <c>DPoP</c> scheme with
    /// a proof signed by the bound key, naming the request's method and URL and hashing the token in
    /// <c>ath</c>, is served: 200 with the End-User's <c>sub</c>.
    /// </summary>
    [TestMethod]
    public async Task UserInfoServesADpopBoundTokenPresentedUnderDpopWithAValidProofAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        string boundAccessToken = await IssueDpopBoundAccessTokenAsync(host, material, fixture).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        string proof = await BuildUserInfoDpopProofAsync(fixture, "POST", userInfoUrl, boundAccessToken).ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, boundAccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(SubjectId, document.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see>, among the
    /// checks the receiving server makes of a DPoP proof: "The htm claim matches the HTTP method of the
    /// current request." and
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoRequest">OpenID Connect
    /// Core 1.0 §5.3.1</see>: "The Client sends the UserInfo Request using either HTTP GET or HTTP
    /// POST." A DPoP-bound access token presented at UserInfo over the wire in a GET under the
    /// <c>DPoP</c> scheme, with a proof signed by the bound key whose <c>htm</c> is <c>GET</c>, is
    /// served: 200 with the End-User's <c>sub</c>.
    /// </summary>
    [TestMethod]
    public async Task UserInfoServesADpopBoundTokenOnGetWithAProofNamingGetAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        string boundAccessToken = await IssueDpopBoundAccessTokenAsync(host, material, fixture).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        string proof = await BuildUserInfoDpopProofAsync(fixture, "GET", userInfoUrl, boundAccessToken).ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, boundAccessToken, scheme: "DPoP", dpopProof: proof, httpMethod: HttpMethod.Get).ConfigureAwait(false);
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
    /// Drives the full authorization-code flow over the real wire through a DPoP-wired client (PAR,
    /// authorize, callback, and the token request with its DPoP proof), so the access token the token
    /// endpoint issues is bound to the client's DPoP key by its <c>cnf.jkt</c> claim, and requests the
    /// <c>openid</c> scope so the token reaches UserInfo.
    /// </summary>
    /// <param name="host">The host whose registration and listener serve the flow.</param>
    /// <param name="material">The registration the flow runs under.</param>
    /// <param name="fixture">The DPoP-wired client and its key.</param>
    /// <returns>The DPoP-bound access token.</returns>
    private async Task<string> IssueDpopBoundAccessTokenAsync(
        TestHostShell host, VerifierKeyMaterial material, DpopClientFixture fixture)
    {
        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
            host.Host("default"), fixture.Client, fixture.Registration, fixture.ClientFlowStore,
            material.Registration.TenantId.Value, RedirectUri, SubjectId, browserClient,
            scope: WellKnownScopes.OpenId, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual("DPoP", (string)drive.TokenResult.Body![OAuthRequestParameterNames.TokenType]!,
            "The token endpoint must issue a DPoP-bound access token to the DPoP-wired client.");

        return (string)drive.TokenResult.Body![OAuthRequestParameterNames.AccessToken];
    }


    /// <summary>
    /// Builds a DPoP proof for a request with <paramref name="httpMethod"/> to
    /// <paramref name="userInfoUrl"/>, bound to <paramref name="accessToken"/> by its <c>ath</c> and
    /// signed with the client's DPoP key, the proof the resource checks per RFC 9449 §4.3 and §7.
    /// </summary>
    /// <param name="fixture">The DPoP-wired client whose key signs the proof.</param>
    /// <param name="httpMethod">The HTTP method the proof's <c>htm</c> names.</param>
    /// <param name="userInfoUrl">The UserInfo URL the proof's <c>htu</c> names.</param>
    /// <param name="accessToken">The access token the proof's <c>ath</c> hashes.</param>
    /// <returns>The DPoP proof JWT.</returns>
    private async Task<string> BuildUserInfoDpopProofAsync(
        DpopClientFixture fixture, string httpMethod, Uri userInfoUrl, string accessToken)
    {
        string ath = await DpopProofValidator.ComputeAthAsync(
            accessToken, TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool, TestContext.CancellationToken)
            .ConfigureAwait(false);

        DpopProofClaims claims = new()
        {
            Htm = httpMethod,
            Htu = userInfoUrl.ToString(),
            Iat = TimeProvider.GetUtcNow(),
            Jti = Guid.NewGuid().ToString("N"),
            Ath = ath
        };

        return await DpopProofConstruction.BuildAsync(
            claims, fixture.DpopKey, TestHostShell.Base64UrlEncoder,
            DpopTestSupport.Serializer, MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            TestHostShell.MemoryPool, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// The URL of the registration's UserInfo endpoint on the host's loopback HTTPS listener,
    /// starting the listener when it is not yet running.
    /// </summary>
    /// <param name="host">The host whose listener serves the request.</param>
    /// <param name="material">The registration whose UserInfo path is addressed.</param>
    /// <returns>The absolute UserInfo URL.</returns>
    private async Task<Uri> UserInfoUrlAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        return new Uri(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.UserInfo, material.Registration.TenantId.Value));
    }


    /// <summary>
    /// Sends a request to the registration's UserInfo endpoint over the host's loopback HTTPS listener
    /// with <paramref name="accessToken"/> under <paramref name="scheme"/> and, when given,
    /// <paramref name="dpopProof"/> in the <c>DPoP</c> header, so the request, its headers and the
    /// response's headers cross the real transport.
    /// </summary>
    /// <param name="host">The host whose listener serves the request.</param>
    /// <param name="material">The registration whose UserInfo path is addressed.</param>
    /// <param name="accessToken">The access token presented.</param>
    /// <param name="scheme">The <c>Authorization</c> scheme the token is presented under.</param>
    /// <param name="dpopProof">The DPoP proof, or <see langword="null"/> to send no <c>DPoP</c> header.</param>
    /// <param name="httpMethod">The request method, or <see langword="null"/> for POST.</param>
    /// <returns>The wire response; the caller disposes it.</returns>
    private async Task<HttpResponseMessage> SendUserInfoOverWireAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string accessToken,
        string scheme = "Bearer",
        string? dpopProof = null,
        HttpMethod? httpMethod = null)
    {
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        using HttpRequestMessage request = new(httpMethod ?? HttpMethod.Post, userInfoUrl);
        _ = request.Headers.TryAddWithoutValidation("Authorization", $"{scheme} {accessToken}");
        if(dpopProof is not null)
        {
            _ = request.Headers.TryAddWithoutValidation("DPoP", dpopProof);
        }

        return await host.Host("default").SharedHttpClient!.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
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
