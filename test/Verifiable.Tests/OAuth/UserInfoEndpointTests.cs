using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Oidc;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.States;
using Verifiable.Tests.TestDataProviders;
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
/// The tests declared before the key-admission rows dispatch in-process against
/// <see cref="EndpointServer.DispatchAsync"/> rather than through
/// <see cref="TestHostShell.DispatchAtEndpointAsync(string, string, string, RequestFields, ExchangeContext, CancellationToken)"/>,
/// which constructs <see cref="RequestHeaders.Empty"/> while UserInfo reads the <c>Authorization</c>
/// header. The key-admission rows and every test after them send their request over the host's
/// loopback HTTPS listener, so the <c>Authorization</c> and <c>DPoP</c> request headers and the
/// <c>WWW-Authenticate</c> and <c>DPoP-Nonce</c> response headers cross the real transport.
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

    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>: "If the
    /// request lacks any authentication information (e.g., the client was unaware that authentication
    /// is necessary or attempted using an unsupported authentication method), the resource server
    /// SHOULD NOT include an error code or other error information." A UserInfo POST dispatched with no
    /// <c>Authorization</c> header is answered 401 with an empty body and the one challenge
    /// <c>Bearer scope="openid", DPoP algs="…"</c>, which carries no error.
    /// </summary>
    [TestMethod]
    public async Task PostWithoutAuthorizationHeaderReturnsUnauthorized()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterPlainUserInfoClientAsync(host).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Post, authorizationHeader: null)
            .ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode);
        Assert.AreEqual(string.Empty, response.Body, "RFC 6750 §3.1: no error code or other error information.");
        AssertMissingCredentialsChallenge(response);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>: "If the
    /// request lacks any authentication information ... the resource server SHOULD NOT include an error
    /// code or other error information." UserInfo answers GET as well as POST
    /// (<see href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoRequest">OIDC Core
    /// §5.3.1</see>: "The Client sends the UserInfo Request using either HTTP GET or HTTP POST."); a GET dispatched
    /// with no <c>Authorization</c> header is answered 401 with an empty body and the one challenge
    /// <c>Bearer scope="openid", DPoP algs="…"</c>.
    /// </summary>
    [TestMethod]
    public async Task GetWithoutAuthorizationHeaderReturnsUnauthorized()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterPlainUserInfoClientAsync(host).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchUserInfoAsync(
            host, material, WellKnownHttpMethods.Get, authorizationHeader: null)
            .ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode);
        Assert.AreEqual(string.Empty, response.Body, "RFC 6750 §3.1: no error code or other error information.");
        AssertMissingCredentialsChallenge(response);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>: "If the
    /// request lacks any authentication information (e.g., the client was unaware that authentication
    /// is necessary or attempted using an unsupported authentication method), the resource server
    /// SHOULD NOT include an error code or other error information." A UserInfo POST dispatched with an
    /// <c>Authorization</c> header under the unsupported <c>Basic</c> scheme is answered 401 with an
    /// empty body and the one challenge <c>Bearer scope="openid", DPoP algs="…"</c>.
    /// </summary>
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
        Assert.AreEqual(string.Empty, response.Body, "RFC 6750 §3.1: no error code or other error information.");
        AssertMissingCredentialsChallenge(response);
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


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>:
    /// "invalid_token The access token provided is expired, revoked, malformed, or invalid for other
    /// reasons. The resource SHOULD respond with the HTTP 401 (Unauthorized) status code." An access
    /// token issued by this server with its signature segment lengthened past
    /// <see cref="Jws.DefaultMaxJwsLength"/>, the longest compact JWS the library verifies, is malformed:
    /// presented in the <c>Authorization</c> header over the wire, UserInfo answers it 401
    /// <c>invalid_token</c> with <c>Bearer error="invalid_token"</c>, never a server fault.
    /// </summary>
    [TestMethod]
    public async Task UserInfoRefusesAnAccessTokenLongerThanTheVerifiedMaximumAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);
        string oversizedToken = accessToken + new string('A', Jws.DefaultMaxJwsLength);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, oversizedToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, HttpStatusCode.Unauthorized, "Bearer error=\"invalid_token\"", "invalid_token");
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(
            "Access token exceeds the longest compact JWS this server verifies.",
            document.RootElement.GetProperty("error_description").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see> item 2: "The DPoP
    /// HTTP request header field value is a single and well-formed JWT." A DPoP proof whose signature
    /// segment makes it longer than <see cref="Jws.DefaultMaxJwsLength"/>, the longest compact JWS the
    /// library verifies, presented over the wire at UserInfo with the DPoP-bound access token it was built
    /// for, cannot be validated: UserInfo answers 401 with <c>DPoP error="invalid_dpop_proof"</c> and the
    /// description naming the proof malformed, never a server fault.
    /// </summary>
    [TestMethod]
    public async Task UserInfoRefusesADpopProofLongerThanTheVerifiedMaximumAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        string oversizedProof = proof + new string('A', Jws.DefaultMaxJwsLength);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, presentation.AccessToken, scheme: "DPoP", dpopProof: oversizedProof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, HttpStatusCode.Unauthorized, ResourceDpopProofs.DpopChallenge("invalid_dpop_proof"), "invalid_dpop_proof");
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(
            "DPoP proof validation failed: Malformed.",
            document.RootElement.GetProperty("error_description").GetString());
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
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">OpenID Connect Core 1.0
    /// Section 5.3.2</see>: "The sub (subject) Claim MUST always be returned in the UserInfo Response." A valid
    /// access token is presented at UserInfo over the wire while the subject resolver returns a value of white space
    /// only, which names no End-User, so no response without a subject is sent: the answer is 500 with the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> and no
    /// claim of the End-User. The value is the resolver's own defect; answering it <c>server_error</c> is this
    /// library's rule.
    /// </summary>
    [TestMethod]
    public async Task AResolverThatReturnsABlankSubjectSendsNoUserInfoResponseAsync()
    {
        await AssertNoUserInfoResponseIsSentAsync(candidateIntegration =>
            candidateIntegration.ResolveSubjectIdentifierAsync =
                static (_, _, _, _) => ValueTask.FromResult(" ")).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">OpenID Connect Core 1.0
    /// Section 5.3.2</see>: "The sub (subject) Claim MUST always be returned in the UserInfo Response." A valid
    /// access token is presented at UserInfo over the wire while the subject resolver throws, so the composed
    /// response carries no <c>sub</c> and is not sent: the answer is 500 with the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> and no
    /// claim of the End-User. Answering the resolver's fault <c>server_error</c> is this library's rule.
    /// </summary>
    [TestMethod]
    public async Task AResolverThatThrowsSendsNoUserInfoResponseAsync()
    {
        await AssertNoUserInfoResponseIsSentAsync(candidateIntegration =>
            candidateIntegration.ResolveSubjectIdentifierAsync =
                static (_, _, _, _) => throw new InvalidOperationException("The subject identifier store is unavailable."))
            .ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">OpenID Connect Core 1.0
    /// Section 5.3.2</see>: "The sub (subject) Claim MUST always be returned in the UserInfo Response." A valid
    /// access token is presented at UserInfo over the wire while the subject resolver returns null, which names no
    /// End-User, so no response whose <c>sub</c> is null is sent: the answer is 500 with the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> and no
    /// claim of the End-User. The value is the resolver's own defect; answering it <c>server_error</c> is this
    /// library's rule.
    /// </summary>
    [TestMethod]
    public async Task AResolverThatReturnsNullSendsNoUserInfoResponseAsync()
    {
        await AssertNoUserInfoResponseIsSentAsync(candidateIntegration =>
            candidateIntegration.ResolveSubjectIdentifierAsync =
                static (_, _, _, _) => ValueTask.FromResult<string>(null!)).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">OpenID Connect Core 1.0
    /// Section 5.3.2</see>: "The sub (subject) Claim MUST always be returned in the UserInfo Response." A valid
    /// access token is presented at UserInfo over the wire while the host's claim issuer carries the standard rules
    /// without the subject identifier rule, so the composed response carries no <c>sub</c> and is not sent: the
    /// answer is 500 with the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> and no
    /// claim of the End-User. Answering the composition's defect <c>server_error</c> is this library's rule.
    /// </summary>
    [TestMethod]
    public async Task AResponseComposedWithoutASubjectIsNotSentAsync()
    {
        List<ClaimDelegate<ClaimContributionTarget>> rules = ContributionProfiles.StandardRules();
        int removedRules = rules.RemoveAll(static rule =>
            rule.ExpectedClaimIds.Contains(WellKnownClaimIds.SubjectIdentifier));
        Assert.AreEqual(1, removedRules, "The standard rules carry one subject identifier rule.");

        await AssertNoUserInfoResponseIsSentAsync(candidateIntegration =>
            candidateIntegration.ClaimIssuer = new ClaimIssuer<ClaimContributionTarget>(
                WellKnownAssessorIds.ClaimContributors, rules, TimeProvider)).ConfigureAwait(false);
    }


    /// <summary>
    /// Issues an access token for <c>openid profile</c> to a subject named <c>Alice</c> under the host's standard
    /// wiring, applies <paramref name="alteration"/> to the host's integration, presents the token at UserInfo over
    /// the loopback listener, and asserts that no UserInfo response is sent: 500 with the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c>, which
    /// carries no claim of the End-User.
    /// </summary>
    /// <param name="alteration">The change to the host's integration made after the token is issued.</param>
    private async Task AssertNoUserInfoResponseIsSentAsync(Action<AuthorizationServerIntegration> alteration)
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId, name: "Alice");

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(
            host, material, $"{WellKnownScopes.OpenId} {WellKnownScopes.Profile}").ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, alteration).ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, accessToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string record = $"{(int)response.StatusCode} '{body}'";

        Assert.AreEqual(HttpStatusCode.InternalServerError, response.StatusCode, record);
        Assert.AreEqual(
            "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            body,
            record);
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
            candidateIntegration.ValidateClientCredentialsAsync = static (reading, registration, context, ct) =>
                ValueTask.FromResult(
                    reading.ClientSecret is string secret
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
            ClientAssertionKeyRow => await IssuanceKeySeparation.ListFreshKeyAsync(
                host, material, KeyUsageContext.ClientAssertion).ConfigureAwait(false),
            OtherRegistrationKeyRow => otherMaterial.SigningKeyId,
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown key row.")
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
    /// a proof signed by the bound key, naming the request's method and URL, hashing the token in
    /// <c>ath</c> and carrying the nonce UserInfo provided, is served: 200 with the End-User's
    /// <c>sub</c>.
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
        string nonce = await ObtainResourceNonceAsync(host, material, boundAccessToken).ConfigureAwait(false);
        string proof = await ResourceDpopProofs.BuildAsync(
            fixture.DpopKey, "POST", userInfoUrl.ToString(), boundAccessToken, nonce, TimeProvider.GetUtcNow(),
            TestContext.CancellationToken).ConfigureAwait(false);

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
    /// <c>DPoP</c> scheme, with a proof signed by the bound key whose <c>htm</c> is <c>GET</c> and which
    /// carries the nonce UserInfo provided, is served: 200 with the End-User's <c>sub</c>.
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
        string nonce = await ObtainResourceNonceAsync(host, material, boundAccessToken).ConfigureAwait(false);
        string proof = await ResourceDpopProofs.BuildAsync(
            fixture.DpopKey, "GET", userInfoUrl.ToString(), boundAccessToken, nonce, TimeProvider.GetUtcNow(),
            TestContext.CancellationToken).ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, boundAccessToken, scheme: "DPoP", dpopProof: proof, httpMethod: HttpMethod.Get).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(SubjectId, document.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 §3</see>: "If the
    /// protected resource request does not include authentication credentials or does not contain an
    /// access token that enables access to the protected resource, the resource server MUST include the
    /// HTTP "WWW-Authenticate" response header field", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>: "If the
    /// request lacks any authentication information (e.g., the client was unaware that authentication
    /// is necessary or attempted using an unsupported authentication method), the resource server
    /// SHOULD NOT include an error code or other error information." A UserInfo request over the wire
    /// with no <c>Authorization</c> header, with one under an unsupported scheme, or with a <c>Bearer</c> line
    /// whose credentials are an auth-param list and so carry no access token (the token is a <c>b64token</c>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 Section 2.1</see>,
    /// "credentials = "Bearer" 1*SP b64token"), is refused with 401, an empty body and exactly one challenge
    /// naming the two schemes UserInfo accepts and no error: <c>Bearer scope="openid", DPoP algs="..."</c>.
    /// </summary>
    /// <param name="authorization">The <c>Authorization</c> header sent, or <see langword="null"/> for none.</param>
    [TestMethod]
    [DataRow(null)]
    [DataRow("Basic dXNlcjpwYXNz")]
    [DataRow("Bearer a=b")]
    public async Task UserInfoChallengesARequestWithoutUsableCredentialsAsync(string? authorization)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        using HttpRequestMessage request = new(HttpMethod.Post, userInfoUrl);
        if(authorization is not null)
        {
            _ = request.Headers.TryAddWithoutValidation("Authorization", authorization);
        }

        using HttpResponseMessage response = await host.Host("default").SharedHttpClient!
            .SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //The header is read as sent: the client's typed view splits one field value into its challenges.
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.NonValidated.TryGetValues("WWW-Authenticate", out HeaderStringValues challenges),
            "RFC 6750 §3: the refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual($"Bearer scope=\"openid\", DPoP algs=\"{ResourceDpopProofs.AcceptedProofAlgorithms}\"", Assert.ContainsSingle(challenges));
        Assert.AreEqual(string.Empty, body, "RFC 6750 §3.1: no error code or other error information.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>:
    /// "invalid_request The request is missing a required parameter, includes an unsupported parameter or
    /// parameter value, repeats the same parameter, uses more than one method for including an access
    /// token, or is otherwise malformed.  The resource server SHOULD respond with the HTTP 400 (Bad
    /// Request) status code." A UserInfo POST sent over a raw TLS connection with two
    /// <c>Authorization: Bearer</c> field lines (<c>Authorization = credentials</c> is no list,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.2">RFC 9110 Section 11.6.2</see>) is
    /// refused with 400 <c>invalid_request</c> and one <c>WWW-Authenticate</c> field holding the <c>Bearer</c> and
    /// the <c>DPoP</c> challenge, each with <c>error="invalid_request"</c>,
    /// <c>Bearer realm="https://userinfo-realm.issuer.test/", error="invalid_request", DPoP error="invalid_request", algs="..."</c>:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>, "Otherwise, both
    /// Bearer and DPoP challenges MAY be used to deliver error information (Figure 19)." The reading of a repeated
    /// field keeps no scheme, so the section's "If the mechanism used to attempt authentication could be established
    /// unambiguously, then the corresponding challenge SHOULD be used to deliver error information (Figure 18)." is
    /// not applied to two lines of one scheme, a named deviation.
    /// </summary>
    [TestMethod]
    public async Task UserInfoRefusesTwoAuthorizationLinesWithBothChallengesAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        await TestHostShell.NameIssuerAsync(host.Server, new Uri("https://userinfo-realm.issuer.test/")).ConfigureAwait(false);

        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl,
            [
                new(WellKnownHttpHeaderNames.Authorization, "Bearer first-access-token"),
                new(WellKnownHttpHeaderNames.Authorization, "Bearer second-access-token")
            ],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(
            "Bearer realm=\"https://userinfo-realm.issuer.test/\", error=\"invalid_request\", "
            + $"DPoP error=\"invalid_request\", algs=\"{ResourceDpopProofs.AcceptedProofAlgorithms}\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual("invalid_request", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.1">RFC 9110 Section 11.1</see>: "It uses a
    /// case-insensitive token to identify the authentication scheme:", followed by "auth-scheme    = token". A
    /// valid access token presented at
    /// UserInfo over the wire under the scheme written <c>bearer</c> is read as a <c>Bearer</c>
    /// presentation and served: 200 with the token's subject.
    /// </summary>
    [TestMethod]
    public async Task UserInfoReadsALowerCaseBearerSchemeAsTheBearerSchemeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId, name: "Alice", email: "alice@example.com");
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);
        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, accessToken, scheme: "bearer").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(SubjectId, document.RootElement.GetProperty(WellKnownJwtClaimNames.Sub).GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.3">RFC 9449 §11.3</see>: "A server
    /// MUST NOT accept any DPoP proofs without the nonce claim when a DPoP nonce has been provided to
    /// the client." UserInfo answers a DPoP-bound token presented with no proof with 401, the challenge
    /// <c>DPoP error="use_dpop_nonce"</c> and a <c>DPoP-Nonce</c>; a proof the client then sends over the
    /// wire signed by the bound key and correct in every other claim but carrying no <c>nonce</c> is
    /// refused the same way, and no claim of the End-User is returned.
    /// </summary>
    [TestMethod]
    public async Task UserInfoRefusesAProofWithoutTheNonceItProvidedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        string boundAccessToken = await IssueDpopBoundAccessTokenAsync(host, material, fixture).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        _ = await ObtainResourceNonceAsync(host, material, boundAccessToken).ConfigureAwait(false);

        string proofWithoutNonce = await ResourceDpopProofs.BuildAsync(
            fixture.DpopKey, "POST", userInfoUrl.ToString(), boundAccessToken, nonce: null, TimeProvider.GetUtcNow(),
            TestContext.CancellationToken).ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, boundAccessToken, scheme: "DPoP", dpopProof: proofWithoutNonce).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, HttpStatusCode.Unauthorized, ResourceDpopProofs.DpopChallenge("use_dpop_nonce"), "use_dpop_nonce");
        Assert.IsNotNull(ResourceDpopProofs.ReadNonce(response), "The challenge provides a fresh nonce.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see> item 8: "The
    /// htm claim matches the HTTP method of the current request." and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-9.1">RFC 9110 §9.1</see>: "The method
    /// token is case-sensitive". A proof presented with its DPoP-bound token in a POST to UserInfo over
    /// the wire, correct in every other claim, whose <c>htm</c> names the other method UserInfo answers
    /// (<c>GET</c>) or the request's own method in lower case (<c>post</c>), is refused with 401,
    /// <c>invalid_dpop_proof</c> and the one challenge <c>DPoP error="invalid_dpop_proof", algs="…"</c>.
    /// </summary>
    /// <param name="htm">The proof's <c>htm</c>.</param>
    [TestMethod]
    [DataRow("GET")]
    [DataRow("post")]
    public async Task UserInfoRefusesAProofWhoseHtmIsNotTheRequestMethodAsync(string htm)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, htm, presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        await AssertProofRefusedAsync(presentation, proof, "invalid_dpop_proof").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see> item 9: "The
    /// htu claim matches the HTTP URI value for the HTTP request in which the JWT was received, ignoring
    /// any query and fragment parts." A proof presented with its DPoP-bound token at UserInfo over the
    /// wire, correct in every other claim, whose <c>htu</c> names another target is refused with 401 and
    /// the one challenge <c>DPoP error="invalid_dpop_proof", algs="…"</c>. The rows: a path below the
    /// UserInfo path; and the UserInfo path with its second <c>/</c> written as <c>%2F</c>, an encoded
    /// reserved character that syntax-based normalization keeps apart from the delimiter
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-2.2">RFC 3986 §2.2</see>: "URIs that
    /// differ in the replacement of a reserved character with its corresponding percent-encoded octet
    /// are not equivalent.").
    /// </summary>
    /// <param name="variant">How the proof's <c>htu</c> differs from the request URL.</param>
    [TestMethod]
    [DataRow(HtuOtherPathRow)]
    [DataRow(HtuEncodedDelimiterRow)]
    public async Task UserInfoRefusesAProofWhoseHtuNamesAnotherTargetAsync(string variant)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        Uri url = new(presentation.UserInfoUrl);
        string path = url.AbsolutePath;
        int innerDelimiter = path.AsSpan(1).IndexOf('/') + 1;
        string htu = variant switch
        {
            HtuOtherPathRow => presentation.UserInfoUrl + "/other",
            HtuEncodedDelimiterRow => $"{url.Scheme}://{url.Authority}{path[..innerDelimiter]}%2F{path[(innerDelimiter + 1)..]}",
            _ => throw new ArgumentOutOfRangeException(nameof(variant), variant, "Unknown htu row.")
        };
        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", htu, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        await AssertProofRefusedAsync(presentation, proof, "invalid_dpop_proof").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see> item 12: "If
    /// presented to a protected resource in conjunction with an access token, ensure that the value of the
    /// ath claim equals the hash of that access token". A proof presented with its DPoP-bound token at
    /// UserInfo over the wire, correct in every other claim, whose <c>ath</c> is the hash of another token
    /// is refused with 401 and the one challenge <c>DPoP error="invalid_dpop_proof", algs="…"</c>.
    /// </summary>
    [TestMethod]
    public async Task UserInfoRefusesAProofWhoseAthHashesAnotherTokenAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, "another-access-token", presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        await AssertProofRefusedAsync(presentation, proof, "invalid_dpop_proof").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see> item 11: "The
    /// creation time of the JWT, as determined by either the iat claim or a server managed timestamp via
    /// the nonce claim, is within an acceptable window (see Section 11.1)." A proof presented with its
    /// DPoP-bound token at UserInfo over the wire, correct in every other claim, whose <c>iat</c> is ten
    /// minutes old or ten minutes ahead is refused with 401 and the one challenge
    /// <c>DPoP error="invalid_dpop_proof", algs="…"</c>.
    /// </summary>
    /// <param name="offsetMinutes">How far the proof's <c>iat</c> lies from the server's clock.</param>
    [TestMethod]
    [DataRow(-10)]
    [DataRow(10)]
    public async Task UserInfoRefusesAProofCreatedOutsideTheAcceptableWindowAsync(int offsetMinutes)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow().AddMinutes(offsetMinutes), TestContext.CancellationToken).ConfigureAwait(false);

        await AssertProofRefusedAsync(presentation, proof, "invalid_dpop_proof").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see> item 4: "The
    /// typ JOSE Header Parameter has the value dpop+jwt." A proof presented with its DPoP-bound token at
    /// UserInfo over the wire, correct in every other respect, whose <c>typ</c> is <c>JWT</c> is refused
    /// with 401 and the one challenge <c>DPoP error="invalid_dpop_proof", algs="…"</c>.
    /// </summary>
    [TestMethod]
    public async Task UserInfoRefusesAProofWhoseTypIsNotDpopJwtAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken,
            alterHeader: header => header["typ"] = "JWT").ConfigureAwait(false);

        await AssertProofRefusedAsync(presentation, proof, "invalid_dpop_proof").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 §5.2</see> step 8:
    /// "Validate the JWS Signature against the JWS Signing Input ... in the manner defined for the
    /// algorithm being used, which MUST be accurately represented by the value of the "alg" (algorithm)
    /// Header Parameter". A proof signed with ES256 by the P-256 key its <c>jwk</c> carries, but declaring
    /// <c>RS256</c>, does not represent the algorithm its signature is validated under: presented with its
    /// DPoP-bound token at UserInfo over the wire it is refused with 401 and the one challenge
    /// <c>DPoP error="invalid_dpop_proof", algs="…"</c>.
    /// </summary>
    [TestMethod]
    public async Task UserInfoRefusesAProofWhoseAlgIsNotTheAlgorithmOfItsKeyAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken,
            alterHeader: header => header["alg"] = "RS256").ConfigureAwait(false);

        await AssertProofRefusedAsync(presentation, proof, "invalid_dpop_proof").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see>, <c>jti</c>:
    /// "The value MUST be assigned such that there is a negligible probability that the same value will
    /// be assigned to any other DPoP proof used in the same context during the time window of validity."
    /// An empty <c>jti</c> is a value any proof could carry. A proof presented with its DPoP-bound token
    /// at UserInfo over the wire, correct in every other claim, whose <c>jti</c> is empty is refused with
    /// 401 and the one challenge <c>DPoP error="invalid_dpop_proof", algs="…"</c>, never a server error.
    /// </summary>
    [TestMethod]
    public async Task UserInfoRefusesAProofWithAnEmptyJtiAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken, jti: string.Empty).ConfigureAwait(false);

        await AssertProofRefusedAsync(presentation, proof, "invalid_dpop_proof").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see> item 12:
    /// "confirm that the public key to which the access token is bound matches the public key from the
    /// DPoP proof." A structurally valid proof signed by a key other than the bound one, presented with
    /// the DPoP-bound token at UserInfo over the wire, is refused with 401 and the one challenge
    /// <c>DPoP error="invalid_token", algs="…"</c>, the error of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 §7.1</see>'s Figure 16
    /// ("Invalid DPoP key binding").
    /// </summary>
    [TestMethod]
    public async Task UserInfoRefusesAProofSignedByAKeyOtherThanTheBoundOneAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            new DpopKey(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256),
            "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        await AssertProofRefusedAsync(presentation, proof, "invalid_token").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see> item 10: "If the
    /// server provided a nonce value to the client, the nonce claim matches the server-provided nonce
    /// value." and <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">§9</see>: "Resource servers
    /// use an HTTP 401 (Unauthorized) error code with an accompanying WWW-Authenticate: DPoP value and
    /// DPoP-Nonce value to accomplish this." A proof presented with its DPoP-bound token at UserInfo over
    /// the wire, after UserInfo provided a nonce, whose <c>nonce</c> is not that nonce is refused with 401,
    /// the one challenge <c>DPoP error="use_dpop_nonce", algs="…"</c> and a fresh <c>DPoP-Nonce</c>, never
    /// a server error. The rows: an empty nonce (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-8.1">§8.1</see>:
    /// "nonce = 1*NQCHAR"); and a nonce in the server's packed shape whose timestamp names no
    /// representable instant.
    /// </summary>
    /// <param name="variant">Which nonce the proof carries.</param>
    [TestMethod]
    [DataRow(NonceEmptyRow)]
    [DataRow(NonceUnrepresentableTimestampRow)]
    public async Task UserInfoRefusesAProofWhoseNonceIsNotTheOneItProvidedAsync(string variant)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string presentedNonce = variant switch
        {
            NonceEmptyRow => string.Empty,
            NonceUnrepresentableTimestampRow => UnrepresentableTimestampNonce(),
            _ => throw new ArgumentOutOfRangeException(nameof(variant), variant, "Unknown nonce row.")
        };
        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentedNonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        await AssertProofRefusedAsync(presentation, proof, "use_dpop_nonce", isDpopNonceExpected: true).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 §11.1</see>: "servers can
    /// store the jti value of each DPoP proof for the time window in which the respective DPoP proof JWT
    /// would be accepted to prevent multiple uses of the same DPoP proof. HTTP requests to the same URI
    /// for which the jti value has been seen before would be declined." A proof UserInfo served once is
    /// presented again over the wire with the same token: the second request is refused with 401 and
    /// <c>DPoP error="invalid_dpop_proof"</c>.
    /// </summary>
    [TestMethod]
    public async Task UserInfoRefusesAReplayedDpopProofAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        string boundAccessToken = await IssueDpopBoundAccessTokenAsync(host, material, fixture).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        string nonce = await ObtainResourceNonceAsync(host, material, boundAccessToken).ConfigureAwait(false);
        string proof = await ResourceDpopProofs.BuildAsync(
            fixture.DpopKey, "POST", userInfoUrl.ToString(), boundAccessToken, nonce, TimeProvider.GetUtcNow(),
            TestContext.CancellationToken).ConfigureAwait(false);

        using HttpResponseMessage first = await SendUserInfoOverWireAsync(
            host, material, boundAccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, first.StatusCode,
            await first.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false));

        using HttpResponseMessage replay = await SendUserInfoOverWireAsync(
            host, material, boundAccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await replay.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(replay, body, HttpStatusCode.Unauthorized, ResourceDpopProofs.DpopChallenge("invalid_dpop_proof"), "invalid_dpop_proof");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 §11.1</see>: "In the
    /// context of the target URI, servers can store the jti value of each DPoP proof for the time window
    /// in which the respective DPoP proof JWT would be accepted to prevent multiple uses of the same DPoP
    /// proof. HTTP requests to the same URI for which the jti value has been seen before would be
    /// declined." The client's token request carries a DPoP proof to the token endpoint over the wire;
    /// a second, independently signed proof carrying the same <c>jti</c>, its <c>htu</c> naming UserInfo
    /// with the right <c>ath</c> and nonce, is presented at UserInfo over the wire and served 200 with the
    /// End-User's <c>sub</c>, since UserInfo is another target URI; the same UserInfo proof presented
    /// again is declined with 401 and <c>DPoP error="invalid_dpop_proof"</c>.
    /// </summary>
    [TestMethod]
    public async Task UserInfoServesAProofWhoseJtiATokenEndpointProofCarriedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        //Every DPoP proof jti the server records while the token is issued, in order; the token request
        //is the last request of the flow that carries a proof.
        SaveServerFlowStateDelegate save = host.Server.OAuth().SaveFlowStateAsync!;
        List<string> recordedProofJtis = [];
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.SaveFlowStateAsync = (tenantId, correlationKey, state, stepCount, ctx, ct) =>
            {
                if(state is JtiSeenState { Purpose: JtiReplayPurpose.DpopProof } proofRecord)
                {
                    lock(recordedProofJtis)
                    {
                        recordedProofJtis.Add(proofRecord.Jti);
                    }
                }

                return save(tenantId, correlationKey, state, stepCount, ctx, ct);
            };
        }).ConfigureAwait(false);

        string boundAccessToken = await IssueDpopBoundAccessTokenAsync(host, material, fixture).ConfigureAwait(false);
        string tokenEndpointProofJti;
        lock(recordedProofJtis)
        {
            Assert.IsNotEmpty(recordedProofJtis, "The token endpoint records the jti of the proof it accepted.");
            tokenEndpointProofJti = recordedProofJtis[^1];
        }

        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        string nonce = await ObtainResourceNonceAsync(host, material, boundAccessToken).ConfigureAwait(false);
        string proof = await ResourceDpopProofs.BuildAsync(
            fixture.DpopKey, "POST", userInfoUrl.ToString(), boundAccessToken, nonce, TimeProvider.GetUtcNow(),
            TestContext.CancellationToken, jti: tokenEndpointProofJti).ConfigureAwait(false);

        using HttpResponseMessage atUserInfo = await SendUserInfoOverWireAsync(
            host, material, boundAccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string servedBody = await atUserInfo.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, atUserInfo.StatusCode, servedBody);
        using JsonDocument served = JsonDocument.Parse(servedBody);
        Assert.AreEqual(SubjectId, served.RootElement.GetProperty("sub").GetString());

        using HttpResponseMessage atUserInfoAgain = await SendUserInfoOverWireAsync(
            host, material, boundAccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string replayBody = await atUserInfoAgain.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        AssertRefused(atUserInfoAgain, replayBody, HttpStatusCode.Unauthorized,
            ResourceDpopProofs.DpopChallenge("invalid_dpop_proof"), "invalid_dpop_proof");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 §11.1</see>: "servers can
    /// store the jti value of each DPoP proof for the time window in which the respective DPoP proof JWT
    /// would be accepted to prevent multiple uses of the same DPoP proof." One proof presented at
    /// UserInfo over the wire in two concurrent requests that both reach the replay store before either
    /// records the proof's <c>jti</c> is served at most once: exactly one request is answered 200 and
    /// the other is refused with 401 and <c>DPoP error="invalid_dpop_proof"</c>.
    /// </summary>
    [TestMethod]
    public async Task UserInfoServesOnlyOneOfConcurrentPresentationsOfOneDpopProofAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        string boundAccessToken = await IssueDpopBoundAccessTokenAsync(host, material, fixture).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        string nonce = await ObtainResourceNonceAsync(host, material, boundAccessToken).ConfigureAwait(false);
        string proofJti = Guid.NewGuid().ToString("N");
        string proof = await ResourceDpopProofs.BuildAsync(
            fixture.DpopKey, "POST", userInfoUrl.ToString(), boundAccessToken, nonce, TimeProvider.GetUtcNow(),
            TestContext.CancellationToken, jti: proofJti).ConfigureAwait(false);

        //Each request's first look-up of this proof's jti reads the store, then waits until the other
        //request has read it too, so both have read "not seen" before either records the jti: the
        //interleaving under which the store's read alone decides nothing.
        ResolveCorrelationKeyDelegate storeLookup = host.Server.OAuth().ResolveCorrelationKeyAsync!;
        int lookups = 0;
        TaskCompletionSource bothLooked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveCorrelationKeyAsync = async (tenantId, flowKind, handle, ctx, ct) =>
            {
                string? resolved = await storeLookup(tenantId, flowKind, handle, ctx, ct).ConfigureAwait(false);
                if(flowKind == FlowKind.JtiReplay && handle.EndsWith(":" + proofJti, StringComparison.Ordinal))
                {
                    int arrival = Interlocked.Increment(ref lookups);
                    if(arrival <= 2)
                    {
                        if(arrival == 2)
                        {
                            _ = bothLooked.TrySetResult();
                        }

                        await bothLooked.Task.WaitAsync(ct).ConfigureAwait(false);
                    }
                }

                return resolved;
            };
        }).ConfigureAwait(false);

        Task<HttpResponseMessage> firstPresentation = SendUserInfoOverWireAsync(
            host, material, boundAccessToken, scheme: "DPoP", dpopProof: proof);
        Task<HttpResponseMessage> secondPresentation = SendUserInfoOverWireAsync(
            host, material, boundAccessToken, scheme: "DPoP", dpopProof: proof);
        HttpResponseMessage[] responses = await Task.WhenAll(firstPresentation, secondPresentation).ConfigureAwait(false);

        try
        {
            HttpStatusCode[] statuses = [.. responses.Select(response => response.StatusCode)];
            _ = Assert.ContainsSingle(statuses.Where(status => status == HttpStatusCode.OK),
                $"Exactly one presentation of one proof is served; statuses: {string.Join(", ", statuses)}.");

            HttpResponseMessage refused = responses.Single(response => response.StatusCode != HttpStatusCode.OK);
            string body = await refused.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            AssertRefused(refused, body, HttpStatusCode.Unauthorized, ResourceDpopProofs.DpopChallenge("invalid_dpop_proof"), "invalid_dpop_proof");
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
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see>: "The htu claim
    /// matches the HTTP URI value for the HTTP request in which the JWT was received, ignoring any query
    /// and fragment parts." and "To reduce the likelihood of false negatives, servers SHOULD employ
    /// syntax-based normalization (Section 6.2.2 of [RFC3986]) and scheme-based normalization (Section
    /// 6.2.3 of [RFC3986]) before comparing the htu claim." A proof presented at UserInfo over the wire
    /// whose <c>htu</c> names the UserInfo URL with its scheme in upper case, with the last character of
    /// its path percent-encoded (an unreserved character, RFC 3986 §6.2.2.2), or with a query appended,
    /// names the same target and is served: 200 with the End-User's <c>sub</c>.
    /// </summary>
    /// <param name="variant">How the proof's <c>htu</c> differs from the request URL.</param>
    [TestMethod]
    [DataRow(HtuUpperCaseSchemeRow)]
    [DataRow(HtuPercentEncodedUnreservedRow)]
    [DataRow(HtuWithQueryRow)]
    public async Task UserInfoServesAProofWhoseHtuNamesTheSameTargetAsync(string variant)
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        string boundAccessToken = await IssueDpopBoundAccessTokenAsync(host, material, fixture).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        string nonce = await ObtainResourceNonceAsync(host, material, boundAccessToken).ConfigureAwait(false);
        string path = userInfoUrl.AbsolutePath;
        string htu = variant switch
        {
            HtuUpperCaseSchemeRow => $"{userInfoUrl.Scheme.ToUpperInvariant()}://{userInfoUrl.Authority}{path}",
            HtuPercentEncodedUnreservedRow =>
                $"{userInfoUrl.Scheme}://{userInfoUrl.Authority}{path[..^1]}%{(int)path[^1]:X2}",
            HtuWithQueryRow => $"{userInfoUrl}?display=page",
            _ => throw new ArgumentOutOfRangeException(nameof(variant), variant, "Unknown htu row.")
        };
        string proof = await ResourceDpopProofs.BuildAsync(
            fixture.DpopKey, "POST", htu, boundAccessToken, nonce, TimeProvider.GetUtcNow(),
            TestContext.CancellationToken).ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, boundAccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(SubjectId, document.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7638#section-3.2">RFC 7638 §3.2</see>: "Only the
    /// required members of a key's representation are used when computing its JWK Thumbprint value." and
    /// §3.2.2: "The benefit of including only the JWK required members is that the JWK Thumbprint of any
    /// JWK representing the key remains the same, regardless of any other attributes that are present."
    /// A proof presented at UserInfo over the wire whose embedded <c>jwk</c> is the bound key with
    /// <c>kid</c> and <c>alg</c> members added matches the token's <c>cnf.jkt</c> and is served: 200
    /// with the End-User's <c>sub</c>.
    /// </summary>
    [TestMethod]
    public async Task UserInfoServesAProofWhoseJwkCarriesOptionalMembersAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        string boundAccessToken = await IssueDpopBoundAccessTokenAsync(host, material, fixture).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        string nonce = await ObtainResourceNonceAsync(host, material, boundAccessToken).ConfigureAwait(false);
        string proof = await ResourceDpopProofs.BuildAsync(
            fixture.DpopKey, "POST", userInfoUrl.ToString(), boundAccessToken, nonce, TimeProvider.GetUtcNow(),
            TestContext.CancellationToken,
            alterHeader: header =>
            {
                Dictionary<string, object> jwk = new((Dictionary<string, object>)header["jwk"], StringComparer.Ordinal)
                {
                    ["kid"] = "client-dpop-key-1",
                    ["alg"] = "ES256"
                };
                header["jwk"] = jwk;
            }).ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, boundAccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(SubjectId, document.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 §7.1</see>: "A DPoP-bound
    /// access token is sent using the Authorization request header field per Section 11.6.2 of
    /// [RFC9110] with an authentication scheme of DPoP." An access token bound to no key, presented at
    /// UserInfo over the wire under the <c>DPoP</c> scheme, is not a DPoP-bound access token and is
    /// refused with 401 and <c>DPoP error="invalid_token"</c>; no claim of the End-User is returned.
    /// </summary>
    [TestMethod]
    public async Task UserInfoRefusesAnUnboundTokenPresentedUnderDpopAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, accessToken, scheme: "DPoP")
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, HttpStatusCode.Unauthorized, ResourceDpopProofs.DpopChallenge("invalid_token"), "invalid_token");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 §7.2</see>: "such a
    /// protected resource MUST reject a DPoP-bound access token received as a bearer token per
    /// [RFC6750]." An access token whose <c>cnf</c> claim binds it by a confirmation method UserInfo does
    /// not check (<c>x5t#S256</c>), presented over the wire under the <c>Bearer</c> scheme, is not served
    /// as a bearer token: it is refused with 401 and <c>Bearer error="invalid_token"</c>, and no claim of
    /// the End-User is returned.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoRefusesATokenBoundByAConfirmationMethodItCannotCheckAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);
        string certificateBoundToken = await CompactJwsResigning.ResignWithAlteredPayloadAsync(
            host, accessToken, material.SigningKeyId,
            payload => payload["cnf"] = new JsonObject { ["x5t#S256"] = "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2" })
            .ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, certificateBoundToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, HttpStatusCode.Unauthorized, "Bearer error=\"invalid_token\"", "invalid_token");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 §7.2</see>: "If the
    /// mechanism used to attempt authentication could be established unambiguously, then the
    /// corresponding challenge SHOULD be used to deliver error information". A request that presents
    /// its access token under the <c>DPoP</c> scheme and is refused at UserInfo over the wire carries the
    /// <c>DPoP</c> challenge, never a <c>Bearer</c> one. The rows: a bound token whose signature does not
    /// verify (401 <c>invalid_token</c>); a bound token whose <c>scope</c> names <c>profile</c> but not
    /// <c>openid</c>, with a valid proof (403 <c>insufficient_scope</c> naming <c>scope="openid"</c>); a bound token
    /// carrying no <c>sub</c>, with a valid proof (401 <c>invalid_token</c>; refusing a token without
    /// <c>sub</c> is this library's own rule, UserInfo having no subject to answer for).
    /// </summary>
    /// <param name="row">Which refusal the DPoP-scheme request meets.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(TamperedSignatureRow)]
    [DataRow(WithoutOpenIdScopeRow)]
    [DataRow(WithoutSubjectRow)]
    public async Task UserInfoAnswersARefusedDpopPresentationWithADpopChallengeAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);

        string boundAccessToken = await IssueDpopBoundAccessTokenAsync(host, material, fixture).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);

        (string presentedToken, HttpStatusCode status, string challenge, string error) = row switch
        {
            TamperedSignatureRow => (TamperSignature(boundAccessToken), HttpStatusCode.Unauthorized,
                ResourceDpopProofs.DpopChallenge("invalid_token"), "invalid_token"),
            WithoutOpenIdScopeRow => (await CompactJwsResigning.ResignWithAlteredPayloadAsync(host, boundAccessToken, material.SigningKeyId,
                    payload => payload["scope"] = WellKnownScopes.Profile).ConfigureAwait(false),
                HttpStatusCode.Forbidden,
                $"DPoP error=\"insufficient_scope\", scope=\"openid\", algs=\"{ResourceDpopProofs.AcceptedProofAlgorithms}\"", "insufficient_scope"),
            WithoutSubjectRow => (await CompactJwsResigning.ResignWithAlteredPayloadAsync(host, boundAccessToken, material.SigningKeyId,
                    payload => _ = payload.Remove("sub")).ConfigureAwait(false),
                HttpStatusCode.Unauthorized, ResourceDpopProofs.DpopChallenge("invalid_token"), "invalid_token"),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown refusal row.")
        };

        string? proof = null;
        if(row != TamperedSignatureRow)
        {
            string nonce = await ObtainResourceNonceAsync(host, material, presentedToken).ConfigureAwait(false);
            proof = await ResourceDpopProofs.BuildAsync(
                fixture.DpopKey, "POST", userInfoUrl.ToString(), presentedToken, nonce, TimeProvider.GetUtcNow(),
                TestContext.CancellationToken).ConfigureAwait(false);
        }

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, presentedToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, status, challenge, error);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.1">RFC 9449 Section 4.1</see>: "Note that per
    /// [RFC9110], header field names are case insensitive; thus, DPoP, DPOP, dpop, etc., are all valid and
    /// equivalent header field names." A DPoP-bound access token presented at UserInfo over a raw TLS connection
    /// under the <c>DPoP</c> scheme, with a valid proof sent in a field whose name is spelled <c>dpop</c> or
    /// <c>DPOP</c>, is served: 200 with the End-User's <c>sub</c>.
    /// </summary>
    /// <param name="fieldName">The spelling of the field name the proof is sent under.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("dpop")]
    [DataRow("DPOP")]
    public async Task UserInfoReadsTheProofUnderAnySpellingOfTheDpopFieldNameAsync(string fieldName)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, new Uri(presentation.UserInfoUrl),
            [
                new(WellKnownHttpHeaderNames.Authorization, $"DPoP {presentation.AccessToken}"),
                new(fieldName, proof)
            ],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual(SubjectId, document.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>: "To validate a DPoP
    /// proof, the receiving server MUST ensure the following: 1. There is not more than one DPoP HTTP request header
    /// field.", with <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">Section 7.1</see>: "invalid_dpop_proof
    /// is used to indicate that the DPoP proof itself was deemed invalid based on the criteria of Section 4.3." A
    /// DPoP-bound access token presented at UserInfo over a raw TLS connection under the <c>DPoP</c> scheme with two
    /// <c>DPoP</c> field lines, each a valid proof carrying the nonce UserInfo provided, is refused: 401 with the one
    /// challenge <c>DPoP error="invalid_dpop_proof", algs="..."</c> and <c>invalid_dpop_proof</c> in the body.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoRefusesTwoDpopFieldsAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string firstProof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        string secondProof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, new Uri(presentation.UserInfoUrl),
            [
                new(WellKnownHttpHeaderNames.Authorization, $"DPoP {presentation.AccessToken}"),
                new(WellKnownHttpHeaderNames.DPoP, firstProof),
                new(WellKnownHttpHeaderNames.DPoP, secondProof)
            ],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefusedOverARawConnection(response, ResourceDpopProofs.DpopChallenge("invalid_dpop_proof"), "invalid_dpop_proof");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 9: "The htu claim
    /// matches the HTTP URI value for the HTTP request in which the JWT was received, ignoring any query and fragment
    /// parts.", with <see href="https://www.rfc-editor.org/rfc/rfc9110#section-7.1">RFC 9110 Section 7.1</see>: "Upon
    /// receipt of a client's request, a server reconstructs the target URI from the received components in accordance
    /// with their local configuration and incoming connection context." A host whose configuration names its listener's
    /// authority <c>https://as-alias.test</c>, unlike its issuer's, judges a UserInfo proof against that authority: a
    /// DPoP-bound access token presented over the wire with a proof carrying the provided nonce whose <c>htu</c> is the
    /// UserInfo path at the listener's authority is served, 200 with the End-User's <c>sub</c>, and one whose <c>htu</c>
    /// is UserInfo at the issuer's authority is refused, 401 with the one challenge
    /// <c>DPoP error="invalid_dpop_proof", algs="..."</c> and "DPoP proof validation failed: HtuMismatch." in the body.
    /// </summary>
    /// <param name="isHtuAtTheListenerAuthority">Whether the proof's <c>htu</c> names the listener's authority rather than the issuer's.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(true, DisplayName = "htu at the listener authority")]
    [DataRow(false, DisplayName = "htu at the issuer authority")]
    public async Task UserInfoHoldsHtuToTheListenerAuthorityAsync(bool isHtuAtTheListenerAuthority)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        Uri listenerAuthority = new("https://as-alias.test");
        host.Host("default").TrustedListenerAuthority = listenerAuthority;
        string htu = isHtuAtTheListenerAuthority switch
        {
            true => new Uri(listenerAuthority, new Uri(presentation.UserInfoUrl).AbsolutePath).OriginalString,
            false => presentation.UserInfoUrl
        };
        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", htu, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, presentation.AccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        if(isHtuAtTheListenerAuthority)
        {
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
            using JsonDocument served = JsonDocument.Parse(body);
            Assert.AreEqual(SubjectId, served.RootElement.GetProperty("sub").GetString());

            return;
        }

        AssertRefused(response, body, HttpStatusCode.Unauthorized, ResourceDpopProofs.DpopChallenge("invalid_dpop_proof"), "invalid_dpop_proof");
        using JsonDocument refused = JsonDocument.Parse(body);
        Assert.AreEqual("DPoP proof validation failed: HtuMismatch.", refused.RootElement.GetProperty("error_description").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 9: "The htu claim
    /// matches the HTTP URI value for the HTTP request in which the JWT was received", the target the server reconstructs
    /// "in accordance with their local configuration and incoming connection context"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-7.1">RFC 9110 Section 7.1</see>). A host that
    /// configures no listener authority judges a UserInfo proof against its issuer's authority whatever <c>Host</c> the
    /// request names: a DPoP-bound access token presented over a raw TLS connection whose <c>Host</c> field names
    /// <c>attacker.example</c> is served, 200 with the End-User's <c>sub</c>, with a proof whose <c>htu</c> is the
    /// configured UserInfo URL, and is refused, 401 with the one challenge <c>DPoP error="invalid_dpop_proof",
    /// algs="..."</c>, with a proof whose <c>htu</c> is the UserInfo path at <c>https://attacker.example</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoJudgesTheProofAgainstTheConfiguredOriginWhateverHostTheRequestNamesAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);
        Uri userInfoUrl = new(presentation.UserInfoUrl);
        const string attackerHost = "attacker.example";

        string configuredProof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData configured = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl,
            [
                new(WellKnownHttpHeaderNames.Authorization, $"DPoP {presentation.AccessToken}"),
                new(WellKnownHttpHeaderNames.DPoP, configuredProof)
            ],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken, attackerHost).ConfigureAwait(false);
        Assert.AreEqual(200, configured.StatusCode, configured.Body);
        using JsonDocument served = JsonDocument.Parse(configured.Body);
        Assert.AreEqual(SubjectId, served.RootElement.GetProperty("sub").GetString());

        string namedHostProof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", new Uri(new Uri($"https://{attackerHost}"), userInfoUrl.AbsolutePath).OriginalString,
            presentation.AccessToken, presentation.Nonce, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData namedHost = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl,
            [
                new(WellKnownHttpHeaderNames.Authorization, $"DPoP {presentation.AccessToken}"),
                new(WellKnownHttpHeaderNames.DPoP, namedHostProof)
            ],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken, attackerHost).ConfigureAwait(false);
        AssertRefusedOverARawConnection(namedHost, ResourceDpopProofs.DpopChallenge("invalid_dpop_proof"), "invalid_dpop_proof");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "For such an access
    /// token, a resource server MUST check that a DPoP proof was also received in the DPoP header field of the HTTP
    /// request, check the DPoP proof according to the rules in Section 4.3 ... The resource server MUST NOT grant access
    /// to the resource unless all checks are successful.", the checks of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see> reading the proof's claims: "10.
    /// If the server provided a nonce value to the client, the nonce claim matches the server-provided nonce value." and
    /// "11. The creation time of the JWT ... is within an acceptable window (see Section 11.1)", where
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">Section 11.1</see> keeps "the jti value of each
    /// DPoP proof". A resource whose DPoP proof validation answers a valid proof with no claims has neither the nonce nor
    /// the <c>jti</c> to check: a DPoP-bound access token presented at UserInfo over the wire with a valid proof carrying
    /// the nonce UserInfo provided is answered 500 <c>server_error</c> "The DPoP proof validator answered no claims for a
    /// valid proof." in a JSON error body, with no <c>WWW-Authenticate</c> challenge and no subject.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoProofWhoseValidatorAnswersNoClaimsIsAServerErrorAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        await host.VerifyDpopProofsWithAsync(MicrosoftCryptographicFunctionsAdapter.VerifyP256Async).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        await host.AnswerValidatedDpopProofsWithoutClaimsAsync().ConfigureAwait(false);
        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        await AssertServerErrorAsync(presentation, proof, "The DPoP proof validator answered no claims for a valid proof.").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: a resource server MUST
    /// "check that the public key of the DPoP proof matches the public key to which the access token is bound per Section
    /// 6", and "The resource server MUST NOT grant access to the resource unless all checks are successful.", the binding
    /// being (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">Section 6.1</see>) a <c>jkt</c> whose value
    /// "MUST be the base64url encoding (as defined in [RFC7515]) of the JWK SHA-256 Thumbprint (according to [RFC7638])
    /// of the DPoP public key". A resource whose DPoP proof validation answers a valid proof with no such thumbprint has
    /// no public key to match: a DPoP-bound access token presented at UserInfo over the wire with a valid proof carrying
    /// the nonce UserInfo provided, validated with no thumbprint or with a 42-character value, is answered 500
    /// <c>server_error</c> "The DPoP proof validator answered no JWK SHA-256 Thumbprint for a valid proof." in a JSON
    /// error body, with no <c>WWW-Authenticate</c> challenge and no subject.
    /// </summary>
    /// <param name="answeredJwkThumbprint">The JWK thumbprint the validation answers for the valid proof.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(null, DisplayName = "no thumbprint")]
    [DataRow("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4", DisplayName = "a 42-character value")]
    public async Task UserInfoProofWhoseValidatorAnswersNoThumbprintIsAServerErrorAsync(string? answeredJwkThumbprint)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        await host.VerifyDpopProofsWithAsync(MicrosoftCryptographicFunctionsAdapter.VerifyP256Async).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        await host.AnswerValidatedDpopProofsWithJwkThumbprintAsync(answeredJwkThumbprint).ConfigureAwait(false);
        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        await AssertServerErrorAsync(presentation, proof, "The DPoP proof validator answered no JWK SHA-256 Thumbprint for a valid proof.").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.1">RFC 9449 Section 4.1</see>: "However, case
    /// is significant in the header field value." Two proofs for one UserInfo request are presented over the wire
    /// with the DPoP-bound token they were built for: the one whose first segment is sent with the case of every
    /// letter swapped is another field value and is refused with 401 and the one challenge
    /// <c>DPoP error="invalid_dpop_proof", algs="..."</c>; the one sent exactly as it was signed is served, 200 with
    /// the End-User's <c>sub</c>. The refusal half is held by the JWS integrity of the proof: a base64url segment with
    /// its letters in the other case decodes to other bytes, so the signature does not verify; no reading of the
    /// field value refuses it on its own. The half a reader of the field value can break is the acceptance: a resource
    /// that folds the value's case would refuse the proof sent exactly as it was signed.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoReadsTheDpopFieldValueWithItsCaseSignificantAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string caseSwappedProof = DpopWireReading.SwapLetterCaseOfFirstSegment(await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false));
        await AssertProofRefusedAsync(presentation, caseSwappedProof, "invalid_dpop_proof").ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, presentation.AccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(SubjectId, document.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.1">RFC 9449 Section 4.1</see>: "The DPoP HTTP
    /// header field value uses the token68 syntax defined in Section 11.2 of [RFC9110]", Figure 3:
    /// <c>token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="</c>. A proof signed for the
    /// request, sent with a <c>!</c> placed inside its first segment, is a field value outside that syntax:
    /// presented at UserInfo over the wire with the DPoP-bound token it was built for, it is refused with 401 and
    /// the one challenge <c>DPoP error="invalid_dpop_proof", algs="..."</c>, never served.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoRefusesAProofValueOutsideTheToken68SyntaxAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        int firstDot = proof.IndexOf('.', StringComparison.Ordinal);
        string outsideToken68 = proof.Insert(firstDot / 2, "!");
        Assert.IsFalse(DpopWireReading.IsToken68(outsideToken68), "The value sent is outside the token68 syntax.");

        await AssertProofRefusedAsync(presentation, outsideToken68, "invalid_dpop_proof").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>, of the
    /// <c>DPoP</c> challenge: "The authentication parameter realm MAY be included to indicate the scope of
    /// protection in the manner described in [RFC9110], Section 11.5." The resource takes the option not: a proof
    /// naming another target, presented with its DPoP-bound token at UserInfo over the wire, is refused with 401
    /// and a <c>DPoP</c> challenge whose auth-params are read from the field as sent and carry no <c>realm</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoDpopChallengeCarriesNoRealmParameterAsync()
    {
        IReadOnlyDictionary<string, string> parameters = await ReadRefusedDpopChallengeParametersAsync().ConfigureAwait(false);

        Assert.AreEqual("invalid_dpop_proof", parameters["error"]);
        Assert.IsFalse(parameters.ContainsKey("realm"), "The DPoP challenge carries no realm parameter.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>, of the
    /// <c>DPoP</c> challenge: "A scope authentication parameter MAY be included as defined in [RFC6750], Section
    /// 3.", where <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see> reads "The
    /// "scope" attribute is a space-delimited list of case-sensitive scope values indicating the required scope of
    /// the access token for accessing the requested resource." A DPoP-bound token whose <c>scope</c> names
    /// <c>profile</c> but not <c>openid</c>, presented at UserInfo over the wire with a valid proof, is refused with
    /// 403 and a <c>DPoP</c> challenge whose <c>error</c> is <c>insufficient_scope</c> and whose <c>scope</c> names
    /// the scope UserInfo requires, <c>openid</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoInsufficientScopeDpopChallengeNamesTheRequiredScopeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);

        string boundAccessToken = await IssueDpopBoundAccessTokenAsync(host, material, fixture).ConfigureAwait(false);
        string profileOnlyToken = await CompactJwsResigning.ResignWithAlteredPayloadAsync(
            host, boundAccessToken, material.SigningKeyId, payload => payload["scope"] = WellKnownScopes.Profile).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        string nonce = await ObtainResourceNonceAsync(host, material, profileOnlyToken).ConfigureAwait(false);
        string proof = await ResourceDpopProofs.BuildAsync(
            fixture.DpopKey, "POST", userInfoUrl.ToString(), profileOnlyToken, nonce, TimeProvider.GetUtcNow(),
            TestContext.CancellationToken).ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, profileOnlyToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode, body);
        IReadOnlyDictionary<string, string> parameters = DpopWireReading.ReadChallengeParameters(
            Assert.ContainsSingle(RawAuthCodeWirePushers.ChallengesOf(response)), "DPoP");
        Assert.AreEqual("insufficient_scope", parameters["error"]);
        Assert.IsTrue(parameters.TryGetValue("scope", out string? scope), "The insufficient_scope challenge names the required scope.");
        Assert.AreEqual("openid", scope);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>, of the
    /// <c>DPoP</c> challenge: "An error_description parameter ([RFC6750], Section 3) MAY be included along with
    /// the error parameter to provide developers a human-readable explanation that is not meant to be displayed to
    /// end-users." The resource takes the option in the response body, not in the challenge: a proof naming
    /// another target, presented with its DPoP-bound token at UserInfo over the wire, is refused with 401, a
    /// <c>DPoP</c> challenge carrying <c>error</c> and no <c>error_description</c>, and a body carrying both.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoDpopChallengeCarriesNoErrorDescriptionParameterAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        (HttpStatusCode status, string challenge, string body) = await PresentProofNamingAnotherTargetAsync(presentation).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, status, body);
        IReadOnlyDictionary<string, string> parameters = DpopWireReading.ReadChallengeParameters(challenge, "DPoP");
        Assert.AreEqual("invalid_dpop_proof", parameters["error"]);
        Assert.IsFalse(parameters.ContainsKey("error_description"), "The DPoP challenge carries no error_description parameter.");
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.IsFalse(string.IsNullOrEmpty(document.RootElement.GetProperty("error_description").GetString()),
            "The refusal's body carries the error_description.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "This
    /// authentication scheme is for origin-server authentication only. Therefore, this authentication scheme MUST
    /// NOT be used with the Proxy-Authenticate or Proxy-Authorization header fields." A DPoP-bound access token
    /// sent at UserInfo over a raw TLS connection in <c>Proxy-Authorization: DPoP</c>, with a valid proof in the
    /// <c>DPoP</c> field and no <c>Authorization</c> field, is no credential of the scheme: the request is refused
    /// with 401, an empty body and the challenge <c>Bearer scope="openid", DPoP algs="..."</c> a request without
    /// credentials is answered with, and the response carries no <c>Proxy-Authenticate</c> field.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoReadsNoDpopCredentialFromProxyAuthorizationAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, new Uri(presentation.UserInfoUrl),
            [
                new("Proxy-Authorization", $"DPoP {presentation.AccessToken}"),
                new(WellKnownHttpHeaderNames.DPoP, proof)
            ],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(string.Empty, response.Body, "A request without credentials is answered with no error information.");
        Assert.AreEqual(
            $"Bearer scope=\"openid\", DPoP algs=\"{ResourceDpopProofs.AcceptedProofAlgorithms}\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.IsEmpty(response.Headers.Headers.GetValues("Proxy-Authenticate"), "No Proxy-Authenticate field is sent.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: "Other HTTP headers
    /// and JSON fields MAY also be included in the error response, but there MUST NOT be more than one DPoP-Nonce
    /// header.", which <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">Section 9</see> applies to a
    /// resource server ("They provide the nonce using the DPoP-Nonce header in the same way that authorization
    /// servers do"). A DPoP-bound access token presented at UserInfo over a raw TLS connection under the
    /// <c>DPoP</c> scheme with no proof is answered with the 401 nonce challenge, whose head carries exactly one
    /// <c>DPoP-Nonce</c> field line, its value not empty.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoNonceChallengeCarriesOneDpopNonceFieldAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);

        string boundAccessToken = await IssueDpopBoundAccessTokenAsync(host, material, fixture).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl,
            [new(WellKnownHttpHeaderNames.Authorization, $"DPoP {boundAccessToken}")],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        string nonce = Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.DPoPNonce));
        Assert.IsFalse(string.IsNullOrEmpty(nonce), "The one DPoP-Nonce field carries a nonce.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8.2">RFC 9449 Section 8.2</see>: "Responses that
    /// include the DPoP-Nonce HTTP header should be uncacheable (e.g., using Cache-Control: no-store in response to
    /// a GET request) to prevent the response from being used to serve a subsequent request and a stale nonce
    /// value from being used as a result." A DPoP-bound access token presented at UserInfo in a GET over a raw TLS
    /// connection with no proof is answered with a 401 nonce challenge carrying a <c>DPoP-Nonce</c> that no cache
    /// may store (<see href="https://www.rfc-editor.org/rfc/rfc9111#section-3">RFC 9111 Section 3</see>): GET is a
    /// method whose caching is defined, 401 is no status code defined as heuristically cacheable, and the response
    /// carries no <c>public</c>, <c>private</c>, <c>max-age</c> or <c>s-maxage</c> directive and no <c>Expires</c>
    /// field.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoNonceChallengeToAGetIsNotStorableByACacheAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);

        string boundAccessToken = await IssueDpopBoundAccessTokenAsync(host, material, fixture).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get, userInfoUrl,
            [new(WellKnownHttpHeaderNames.Authorization, $"DPoP {boundAccessToken}")],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.IsNotEmpty(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.DPoPNonce), "The challenge carries a DPoP-Nonce.");
        Assert.IsFalse(DpopWireReading.IsStorableByACache(WellKnownHttpMethods.Get, userInfoUrl, response.StatusCode, response.Headers.Headers),
            "A response carrying a DPoP-Nonce is not storable by a cache.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "Unlike
    /// cryptographic nonces, it is acceptable for clients to use the same nonce multiple times and for the server
    /// to accept the same nonce multiple times." Two proofs with distinct <c>jti</c> values, both carrying the one
    /// nonce UserInfo provided, are presented one after the other with their DPoP-bound token at UserInfo over the
    /// wire: both are served, 200 with the End-User's <c>sub</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoAcceptsTheNonceItProvidedInSeveralProofsAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        foreach(string jti in (string[])["first-proof-of-the-nonce", "second-proof-of-the-nonce"])
        {
            string proof = await ResourceDpopProofs.BuildAsync(
                presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
                TimeProvider.GetUtcNow(), TestContext.CancellationToken, jti: jti).ConfigureAwait(false);
            using HttpResponseMessage response = await SendUserInfoOverWireAsync(
                host, material, presentation.AccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
            string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, $"The proof '{jti}' carrying the provided nonce is served: {body}");
            using JsonDocument document = JsonDocument.Parse(body);
            Assert.AreEqual(SubjectId, document.RootElement.GetProperty("sub").GetString());
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "a resource server MUST
    /// ... check the DPoP proof according to the rules in Section 4.3" and "The resource server MUST NOT grant access to
    /// the resource unless all checks are successful", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>, check 10: "If the server
    /// provided a nonce value to the client, the nonce claim matches the server-provided nonce value." A proof whose
    /// <c>nonce</c> decodes to the octets UserInfo provided, or begins with them, but is not the text it provided,
    /// presented with its DPoP-bound token at UserInfo over the wire, is refused: 401, the one challenge
    /// <c>DPoP error="use_dpop_nonce", algs="..."</c> and a <c>DPoP-Nonce</c> field, the signalling of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">Section 9</see> ("Resource servers use an HTTP 401
    /// (Unauthorized) error code with an accompanying WWW-Authenticate: DPoP value and DPoP-Nonce value"). The host's nonce key is
    /// <see cref="ResourceDpopProofs.PartialGroupNonceKeyId"/>, so its nonces end in a partial base64url group. The rows:
    /// the provided octets and one more octet, written canonically; the provided nonce with a space inside it; the
    /// provided nonce with its <c>=</c> padding; and the provided nonce with a pad bit of its last character set. The
    /// space and the <c>=</c> are characters outside the base64url alphabet
    /// (<see href="https://www.rfc-editor.org/rfc/rfc4648#section-5">RFC 4648 Section 5</see>, Table 2, written without
    /// padding by <see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see>), and
    /// <see href="https://www.rfc-editor.org/rfc/rfc4648#section-3.3">RFC 4648 Section 3.3</see> reads: "Implementations
    /// MUST reject the encoded data if it contains characters outside the base alphabet when interpreting base-encoded
    /// data, unless the specification referring to this document explicitly states otherwise".
    /// </summary>
    /// <param name="row">How the presented nonce spells or extends the provided one.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(NonceExtendedByAnOctetRow)]
    [DataRow(NonceWithASpaceInsideRow)]
    [DataRow(NoncePaddedRow)]
    [DataRow(NonceWithAPadBitSetRow)]
    public async Task UserInfoRefusesANonceThatIsNotTheTextItProvidedAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync(ResourceDpopProofs.PartialGroupNonceKeyId).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string provided = presentation.Nonce;
        string presented = row switch
        {
            NonceExtendedByAnOctetRow => ResourceDpopProofs.ExtendNonceByAnOctet(provided),
            NonceWithASpaceInsideRow => provided.Insert(provided.Length / 2, " "),
            NoncePaddedRow => ResourceDpopProofs.PadNonce(provided),
            NonceWithAPadBitSetRow => ResourceDpopProofs.SetUnusedBitsOfNonce(provided),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown nonce row.")
        };
        Assert.AreNotEqual(provided, presented);
        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presented,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        await AssertProofRefusedAsync(presentation, proof, "use_dpop_nonce", isDpopNonceExpected: true).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "a resource server MUST
    /// ... check the DPoP proof according to the rules in Section 4.3", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>, check 10: "If the server
    /// provided a nonce value to the client, the nonce claim matches the server-provided nonce value." The nonce is the
    /// one UserInfo provided by its <c>DPoP-Nonce</c> (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">Section
    /// 9</see>: "Resource servers can also choose to provide a nonce value to be included in DPoP proofs sent to them").
    /// The host's nonce key is <see cref="ResourceDpopProofs.PartialGroupNonceKeyId"/>, so the nonce UserInfo provides ends
    /// in a partial base64url group; a proof carrying that nonce exactly as provided, presented with its DPoP-bound token
    /// at UserInfo over the wire, is served: 200 with the End-User's <c>sub</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoAcceptsTheNonceItProvidedEndingInAPartialGroupAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync(ResourceDpopProofs.PartialGroupNonceKeyId).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        Assert.AreNotEqual(0, presentation.Nonce.Length % 4, $"The provided nonce ends in a partial group: '{presentation.Nonce}'.");
        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, presentation.AccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, $"The nonce as provided is accepted: {body}");
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(SubjectId, document.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "a resource server MUST
    /// ... check the DPoP proof according to the rules in Section 4.3" and "MUST NOT grant access to the resource unless
    /// all checks are successful", and <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>,
    /// check 10: "If the server provided a nonce value to the client, the nonce claim matches the server-provided nonce
    /// value." A decoder may read another spelling as the provided octets.
    /// <see href="https://www.rfc-editor.org/rfc/rfc4648#section-3.5">RFC 4648 Section 3.5</see>: "decoders MAY chose to
    /// reject an encoding if the pad bits have not been set to zero", so a conforming decoder may read a set pad bit.
    /// <see href="https://www.rfc-editor.org/rfc/rfc4648#section-3.3">RFC 4648 Section 3.3</see>: "Implementations MUST
    /// reject the encoded data if it contains characters outside the base alphabet when interpreting base-encoded data,
    /// unless the specification referring to this document explicitly states otherwise", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see> states no such exception
    /// for base64url, whose alphabet is <see href="https://www.rfc-editor.org/rfc/rfc4648#section-5">Section 5</see>'s
    /// Table 2: a decoder that reads the base64 characters <c>+</c> and <c>/</c> as the base64url <c>-</c> and <c>_</c>
    /// is outside Section 3.3, and for such a decoder the validator's own check of the base64url alphabet is what holds
    /// the match. The host's nonce validation is wired with
    /// <see cref="ResourceDpopProofs.PermissiveBase64UrlDecoder"/>, which reads both, and its issuance with
    /// <see cref="ResourceDpopProofs.RandomFieldOfOnes"/>, so the provided text holds a <c>_</c>. A proof whose
    /// <c>nonce</c> that decoder reads as the provided octets, but which is not the provided text, presented with its
    /// DPoP-bound token at UserInfo over the wire, is refused: 401, the one challenge
    /// <c>DPoP error="use_dpop_nonce", algs="..."</c> and a <c>DPoP-Nonce</c> field, the signalling of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">Section 9</see>. The rows: the provided text with
    /// the lowest pad bit of its last character set, with the highest pad bit of its last character set, and with its
    /// first <c>-</c> or <c>_</c> written <c>+</c> or <c>/</c>; each under a nonce HMAC key whose identifier is 12
    /// octets (an 85-octet nonce, four pad bits) and 13 octets (86 octets, two pad bits); and under the 12-octet
    /// identifier, the provided text with the second-lowest pad bit (value <c>0b0010</c>) and with the third-lowest pad
    /// bit (value <c>0b0100</c>) of its last character set alone, the two pad bits between the lowest and the highest.
    /// </summary>
    /// <param name="keyIdRow">The nonce HMAC key, by the length of its identifier.</param>
    /// <param name="spellingRow">How the presented nonce spells the provided octets.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(TwelveOctetKeyIdRow, PadBitSetSpellingRow)]
    [DataRow(TwelveOctetKeyIdRow, HighestPadBitSetSpellingRow)]
    [DataRow(TwelveOctetKeyIdRow, SecondLowestPadBitSetSpellingRow)]
    [DataRow(TwelveOctetKeyIdRow, ThirdLowestPadBitSetSpellingRow)]
    [DataRow(TwelveOctetKeyIdRow, Base64CharacterSpellingRow)]
    [DataRow(ThirteenOctetKeyIdRow, PadBitSetSpellingRow)]
    [DataRow(ThirteenOctetKeyIdRow, HighestPadBitSetSpellingRow)]
    [DataRow(ThirteenOctetKeyIdRow, Base64CharacterSpellingRow)]
    public async Task UserInfoRefusesAnotherSpellingOfTheProvidedNonceItsDecoderReadsAsync(string keyIdRow, string spellingRow)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        await EnableDpopUnderThePermissiveDecoderAsync(host, keyIdRow).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string provided = presentation.Nonce;
        string presented = spellingRow switch
        {
            PadBitSetSpellingRow => ResourceDpopProofs.SetUnusedBitsOfNonce(provided),
            HighestPadBitSetSpellingRow => ResourceDpopProofs.SetHighestUnusedBitOfNonce(provided),
            SecondLowestPadBitSetSpellingRow => ResourceDpopProofs.SetPadBitOfNonce(provided, 1),
            ThirdLowestPadBitSetSpellingRow => ResourceDpopProofs.SetPadBitOfNonce(provided, 2),
            Base64CharacterSpellingRow => ResourceDpopProofs.SpellNonceInTheBase64Alphabet(provided),
            _ => throw new ArgumentOutOfRangeException(nameof(spellingRow), spellingRow, "Unknown spelling row.")
        };
        Assert.AreNotEqual(provided, presented);
        Assert.IsTrue(ResourceDpopProofs.IsReadAsTheSuppliedOctetsByThePermissiveDecoder(presented, provided),
            "The wired decoder reads the presented spelling as the provided octets.");
        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presented,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        await AssertProofRefusedAsync(presentation, proof, "use_dpop_nonce", isDpopNonceExpected: true).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "a resource server MUST
    /// ... check the DPoP proof according to the rules in Section 4.3", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>, check 10: "the nonce claim
    /// matches the server-provided nonce value." Under the wiring of
    /// <see cref="UserInfoRefusesAnotherSpellingOfTheProvidedNonceItsDecoderReadsAsync"/> (the nonce validation reading
    /// through <see cref="ResourceDpopProofs.PermissiveBase64UrlDecoder"/>), a proof carrying the nonce exactly as
    /// provided, presented with its DPoP-bound token at UserInfo over the wire, is served, 200 with the End-User's
    /// <c>sub</c>, under a nonce key of 12 octets and of 13 octets: the decoder reads the provided text, so the refusals
    /// of the other spellings are the validator's.
    /// </summary>
    /// <param name="keyIdRow">The nonce key, by the length of its identifier.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(TwelveOctetKeyIdRow)]
    [DataRow(ThirteenOctetKeyIdRow)]
    public async Task UserInfoAcceptsTheProvidedNonceUnderAPermissiveDecoderAsync(string keyIdRow)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        await EnableDpopUnderThePermissiveDecoderAsync(host, keyIdRow).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, presentation.AccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, $"The nonce as provided is accepted: {body}");
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(SubjectId, document.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// Enables DPoP on the host under the nonce key <paramref name="keyIdRow"/> names, its nonce validation reading
    /// through <see cref="ResourceDpopProofs.PermissiveBase64UrlDecoder"/> and its issuance filling the random field from
    /// <see cref="ResourceDpopProofs.RandomFieldOfOnes"/>.
    /// </summary>
    /// <param name="host">The host.</param>
    /// <param name="keyIdRow">The nonce key, by the length of its identifier.</param>
    /// <returns>A task that completes when the host is wired.</returns>
    private static async Task EnableDpopUnderThePermissiveDecoderAsync(TestHostShell host, string keyIdRow)
    {
        string keyId = keyIdRow switch
        {
            TwelveOctetKeyIdRow => ResourceDpopProofs.PartialGroupNonceKeyId,
            ThirteenOctetKeyIdRow => ResourceDpopProofs.TwoOctetFinalQuantumNonceKeyId,
            _ => throw new ArgumentOutOfRangeException(nameof(keyIdRow), keyIdRow, "Unknown key identifier row.")
        };
        _ = await host.EnableDpopAsync(keyId).ConfigureAwait(false);
        await host.ValidateDpopNoncesWithDecoderAsync(ResourceDpopProofs.PermissiveBase64UrlDecoder).ConfigureAwait(false);
        await host.IssueDpopNoncesFromEntropyAsync(ResourceDpopProofs.RandomFieldOfOnes).ConfigureAwait(false);
    }


    /// <summary>The row of a permissive-decoder test whose nonce key identifier is 12 octets, its nonces 85 octets.</summary>
    private const string TwelveOctetKeyIdRow = "twelve-octet-key-identifier";

    /// <summary>The row of a permissive-decoder test whose nonce key identifier is 13 octets, its nonces 86 octets.</summary>
    private const string ThirteenOctetKeyIdRow = "thirteen-octet-key-identifier";

    /// <summary>The row of a permissive-decoder test whose presented nonce is the provided one with the lowest pad bit of its last character set.</summary>
    private const string PadBitSetSpellingRow = "pad-bit-set";

    /// <summary>The row of a permissive-decoder test whose presented nonce is the provided one with the highest pad bit of its last character set.</summary>
    private const string HighestPadBitSetSpellingRow = "highest-pad-bit-set";

    /// <summary>The row of a permissive-decoder test whose presented nonce is the provided one with the second-lowest pad bit of its last character set alone, of value <c>0b0010</c>.</summary>
    private const string SecondLowestPadBitSetSpellingRow = "second-lowest-pad-bit-set";

    /// <summary>The row of a permissive-decoder test whose presented nonce is the provided one with the third-lowest pad bit of its last character set alone, of value <c>0b0100</c>.</summary>
    private const string ThirdLowestPadBitSetSpellingRow = "third-lowest-pad-bit-set";

    /// <summary>The row of a permissive-decoder test whose presented nonce writes the provided one's first <c>-</c> or <c>_</c> as <c>+</c> or <c>/</c>.</summary>
    private const string Base64CharacterSpellingRow = "base64-character";


    /// <summary>The row of the exact-text test whose presented nonce is the provided octets and one more, written canonically.</summary>
    private const string NonceExtendedByAnOctetRow = "nonce-extended-by-an-octet";

    /// <summary>The row of the exact-text test whose presented nonce is the provided one with a space inside it.</summary>
    private const string NonceWithASpaceInsideRow = "nonce-with-a-space-inside";

    /// <summary>The row of the exact-text test whose presented nonce is the provided one with its padding.</summary>
    private const string NoncePaddedRow = "nonce-padded";

    /// <summary>The row of the exact-text test whose presented nonce is the provided one with a pad bit of its last character set.</summary>
    private const string NonceWithAPadBitSetRow = "nonce-with-a-pad-bit-set";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.6">RFC 9449 Section 11.6</see>: "In
    /// particular, the algorithm none MUST NOT be allowed." A proof whose protected header declares <c>alg</c>
    /// <c>none</c>, its signature made by the P-256 key its <c>jwk</c> carries so the signature itself verifies
    /// under that public key, presented with its DPoP-bound token at UserInfo over the wire, is refused with 401 and the
    /// one challenge <c>DPoP error="invalid_dpop_proof", algs="..."</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoRefusesAProofWhoseAlgIsNoneAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken,
            alterHeader: header => header["alg"] = "none").ConfigureAwait(false);

        await AssertProofRefusedAsync(presentation, proof, "invalid_dpop_proof").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-5.1">RFC 9728 Section 5.1</see>: "This parameter
    /// MAY also be used in WWW-Authenticate responses using authorization schemes other than "Bearer" [RFC6750],
    /// such as the DPoP scheme defined by [RFC9449]." The resource takes the option not for the <c>DPoP</c>
    /// scheme: a proof naming another target, presented with its DPoP-bound token at UserInfo over the wire, is
    /// refused with 401 and a <c>DPoP</c> challenge whose auth-params carry no <c>resource_metadata</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoDpopChallengeCarriesNoResourceMetadataParameterAsync()
    {
        IReadOnlyDictionary<string, string> parameters = await ReadRefusedDpopChallengeParametersAsync().ConfigureAwait(false);

        Assert.AreEqual("invalid_dpop_proof", parameters["error"]);
        Assert.IsFalse(parameters.ContainsKey("resource_metadata"), "The DPoP challenge carries no resource_metadata parameter.");
    }


    /// <summary>
    /// Issues a DPoP-bound token over the wire, presents it at UserInfo with a proof naming another target, asserts
    /// the 401 refusal, and reads the auth-params of the <c>DPoP</c> challenge of its one <c>WWW-Authenticate</c>
    /// field.
    /// </summary>
    /// <returns>The <c>DPoP</c> challenge's auth-params.</returns>
    private async Task<IReadOnlyDictionary<string, string>> ReadRefusedDpopChallengeParametersAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        (HttpStatusCode status, string challenge, string body) = await PresentProofNamingAnotherTargetAsync(presentation).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, status, body);

        return DpopWireReading.ReadChallengeParameters(challenge, "DPoP");
    }


    /// <summary>
    /// Presents the presentation's token at UserInfo over the wire with a proof whose <c>htu</c> names a path below
    /// the UserInfo path, correct in every other claim, and returns the answer.
    /// </summary>
    /// <param name="presentation">The presentation state.</param>
    /// <returns>The status, the one <c>WWW-Authenticate</c> field value and the body.</returns>
    private async Task<(HttpStatusCode Status, string Challenge, string Body)> PresentProofNamingAnotherTargetAsync(
        DpopPresentationContext presentation)
    {
        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl + "/other", presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            presentation.Host, presentation.Material, presentation.AccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        return (response.StatusCode, Assert.ContainsSingle(RawAuthCodeWirePushers.ChallengesOf(response)), body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>:
    /// "invalid_token The access token provided is expired, revoked, malformed, or invalid for other
    /// reasons. The resource SHOULD respond with the HTTP 401 (Unauthorized) status code." An access
    /// token whose protected header is a JSON array (<c>W10.e30.AA</c>, the header <c>[]</c>) is
    /// malformed: it is refused at UserInfo over the wire with 401 <c>invalid_token</c> and
    /// <c>Bearer error="invalid_token"</c>, never a server error.
    /// </summary>
    [TestMethod]
    public async Task UserInfoRefusesAnAccessTokenWhoseHeaderIsNotAJsonObjectAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, "W10.e30.AA")
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, HttpStatusCode.Unauthorized, "Bearer error=\"invalid_token\"", "invalid_token");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>:
    /// "invalid_token The access token provided is expired, revoked, malformed, or invalid for other
    /// reasons. The resource SHOULD respond with the HTTP 401 (Unauthorized) status code." An access
    /// token signed under the registration's access-token key whose <c>exp</c> is
    /// 9223372036854775807, a NumericDate no instant is represented for, is malformed: it is refused at
    /// UserInfo over the wire with 401 <c>invalid_token</c> and <c>Bearer error="invalid_token"</c>,
    /// never a server error.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoRefusesAnAccessTokenWhoseExpIsNotARepresentableInstantAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);
        string farExpiryToken = await CompactJwsResigning.ResignWithAlteredPayloadAsync(
            host, accessToken, material.SigningKeyId, payload => payload["exp"] = long.MaxValue).ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, farExpiryToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, HttpStatusCode.Unauthorized, "Bearer error=\"invalid_token\"", "invalid_token");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.12">RFC 8725 §3.12</see>: "Use
    /// different keys for different kinds of JWTs. Then the keys used to validate one kind of JWT will
    /// fail to validate other kinds of JWTs." A registration whose access tokens and ID Tokens are
    /// issued under two distinct keys: an access token re-signed under the registration's own ID Token
    /// key, presented at UserInfo over the wire, is refused with 401 <c>invalid_token</c> and
    /// <c>Bearer error="invalid_token"</c>, and no claim of the End-User is returned.
    /// </summary>
    [TestMethod]
    public async Task UserInfoRefusesAnAccessTokenSignedUnderTheRegistrationsIdTokenKeyAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        KeyId idTokenKeyId = await IssuanceKeySeparation.ListFreshKeyAsync(
            host, material, KeyUsageContext.IdTokenIssuance).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);
        string underIdTokenKey = await CompactJwsResigning.ResignWithHeaderAsync(host, accessToken, idTokenKeyId, "at+jwt")
            .ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, underIdTokenKey)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, HttpStatusCode.Unauthorized, "Bearer error=\"invalid_token\"", "invalid_token");
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(
            "Access token is not signed by a key this server issues access tokens with.",
            document.RootElement.GetProperty("error_description").GetString());
    }


    /// <summary>
    /// The verification-key resolver's documented contract, a contract of this library: every
    /// resolution states the <see cref="KeyUsageContext"/> the key is expected under, so a key store can
    /// keep keys apart per kind. The design follows
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.12">RFC 8725 §3.12</see>: "If more
    /// than one kind of JWT can be issued by the same issuer, the validation rules for those JWTs MUST be
    /// written such that they are mutually exclusive, rejecting JWTs of the wrong kind." and "Use
    /// different keys for different kinds of JWTs. Then the keys used to validate one kind of JWT will
    /// fail to validate other kinds of JWTs." An access token issued to the registration and presented at
    /// UserInfo over the wire as a Bearer token is served 200 with the End-User's <c>sub</c>, and the
    /// resolver is asked for the token's key exactly once, under
    /// <see cref="KeyUsageContext.AccessTokenIssuance"/>.
    /// </summary>
    [TestMethod]
    public async Task UserInfoResolvesTheAccessTokenKeyUnderAccessTokenIssuanceAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        hosted.VerificationKeyResolutions.Clear();

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, accessToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(SubjectId, document.RootElement.GetProperty("sub").GetString());

        VerificationKeyResolution resolution = Assert.ContainsSingle(hosted.ResolutionsOf(material.SigningKeyId));
        Assert.AreEqual(KeyUsageContext.AccessTokenIssuance, resolution.Usage);
    }


    /// <summary>
    /// The verification-key resolver's documented contract, a contract of this library: a resolver
    /// answers null for a key it does not hold for the usage it is asked under, and the refusal is the
    /// library's answer to that null. The design follows
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.12">RFC 8725 §3.12</see>: "Use
    /// different keys for different kinds of JWTs. Then the keys used to validate one kind of JWT will
    /// fail to validate other kinds of JWTs." In both rows the resolver is asked for the access token's
    /// key exactly once, under <see cref="KeyUsageContext.AccessTokenIssuance"/>. A resolver that holds
    /// the registration's key for access tokens serves the access token at UserInfo over the wire with
    /// 200 and the End-User's <c>sub</c>; a resolver that holds the same key only for ID Tokens answers
    /// nothing for an access token, and UserInfo refuses it with 401 <c>invalid_token</c>,
    /// <c>Bearer error="invalid_token"</c> and the fixed description "No verification key is available
    /// for the access token.", which names no key identifier.
    /// </summary>
    /// <param name="row">Which usage the row's resolver holds the key under: <see cref="HeldForAccessTokensRow"/> or <see cref="HeldForIdTokensRow"/>.</param>
    [TestMethod]
    [DataRow(HeldForAccessTokensRow)]
    [DataRow(HeldForIdTokensRow)]
    public async Task UserInfoAnswersOnlyWhenTheResolverHoldsTheKeyForAccessTokensAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);

        KeyUsageContext heldUsage = row switch
        {
            HeldForAccessTokensRow => KeyUsageContext.AccessTokenIssuance,
            HeldForIdTokensRow => KeyUsageContext.IdTokenIssuance,
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown usage row.")
        };

        HostedAuthorizationServer hosted = host.Host("default");
        ConcurrentQueue<KeyUsageContext> askedUsages = new();
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.Cryptography.VerificationKeyResolver = (keyId, usage, tenantId, ctx, ct) =>
            {
                if(keyId == material.SigningKeyId)
                {
                    askedUsages.Enqueue(usage);
                }

                return ValueTask.FromResult(
                    usage == heldUsage && hosted.VerificationKeys.TryGetValue(keyId, out PublicKeyMemory? key)
                        ? key : null);
            };
        }).ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, accessToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        if(row == HeldForAccessTokensRow)
        {
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
            using JsonDocument served = JsonDocument.Parse(body);
            Assert.AreEqual(SubjectId, served.RootElement.GetProperty("sub").GetString());
            Assert.AreEqual(KeyUsageContext.AccessTokenIssuance, Assert.ContainsSingle(askedUsages));

            return;
        }

        AssertRefused(response, body, HttpStatusCode.Unauthorized, "Bearer error=\"invalid_token\"", "invalid_token");
        Assert.AreEqual(KeyUsageContext.AccessTokenIssuance, Assert.ContainsSingle(askedUsages));
        using JsonDocument refused = JsonDocument.Parse(body);
        Assert.AreEqual(
            "No verification key is available for the access token.",
            refused.RootElement.GetProperty("error_description").GetString());
        Assert.DoesNotContain(material.SigningKeyId.Value, body, StringComparison.Ordinal, "The refusal names no key identifier.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 Section 4</see>: "The resource
    /// server MUST validate that the "aud" claim contains a resource indicator value corresponding to an
    /// identifier the resource server expects for itself.  The JWT access token MUST be rejected if "aud" does
    /// not contain a resource indicator of the current resource server as a valid audience." UserInfo is a
    /// resource of this Authorization Server, whose identifier is the issuer. A registration whose scope map
    /// names another resource for <c>openid</c> is issued an access token whose <c>aud</c> is that resource
    /// alone; presented at UserInfo over the wire under the <c>Bearer</c> scheme, it is refused with 401,
    /// <c>invalid_token</c> and the one challenge <c>Bearer error="invalid_token"</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoRefusesATokenAudiencedAtAnotherResourceAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        _ = await host.AddScopeWithAudienceAsync(
            material, WellKnownScopes.OpenId, OtherResourceAudience, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);
        Assert.AreEqual($"[\"{OtherResourceAudience}\"]", ReadAudienceClaim(accessToken),
            "The scope map audiences the token at the other resource alone.");

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, accessToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, HttpStatusCode.Unauthorized, "Bearer error=\"invalid_token\"", "invalid_token");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 Section 4</see>: "The JWT access
    /// token MUST be rejected if "aud" does not contain a resource indicator of the current resource server as a
    /// valid audience." and "Please note that this requirement does not prevent JWT access tokens from using
    /// authentication schemes other than "Bearer"." A DPoP-bound access token whose <c>aud</c> names another
    /// resource alone, signed under the registration's access-token key and presented at UserInfo over the wire
    /// under the <c>DPoP</c> scheme with a proof from the bound key carrying the nonce UserInfo provided, is
    /// refused with 401, <c>invalid_token</c> and the one challenge <c>DPoP error="invalid_token", algs="..."</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoRefusesADpopBoundTokenAudiencedAtAnotherResourceAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string otherAudienceToken = await CompactJwsResigning.ResignWithAlteredPayloadAsync(
            host, presentation.AccessToken, material.SigningKeyId,
            payload => payload["aud"] = new JsonArray(OtherResourceAudience)).ConfigureAwait(false);
        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, otherAudienceToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, otherAudienceToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, HttpStatusCode.Unauthorized, ResourceDpopProofs.DpopChallenge("invalid_token"), "invalid_token");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2">RFC 9068 Section 2.2</see>: "aud  REQUIRED -
    /// as defined in Section 4.1.3 of [RFC7519]." and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">Section 4</see>: "The JWT access token MUST be
    /// rejected if "aud" does not contain a resource indicator of the current resource server as a valid
    /// audience." An access token signed under the registration's access-token key whose claims carry no
    /// <c>aud</c> contains no audience at all; presented at UserInfo over the wire under the <c>Bearer</c>
    /// scheme, it is refused with 401, <c>invalid_token</c> and the one challenge <c>Bearer error="invalid_token"</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoRefusesATokenWithoutAnAudienceAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);
        string withoutAudience = await CompactJwsResigning.ResignWithAlteredPayloadAsync(
            host, accessToken, material.SigningKeyId, payload => payload.Remove("aud")).ConfigureAwait(false);
        Assert.IsNull(ReadAudienceClaim(withoutAudience), "The presented token carries no aud claim.");

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, withoutAudience).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, HttpStatusCode.Unauthorized, "Bearer error=\"invalid_token\"", "invalid_token");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 Section 4</see>: "The resource
    /// server MUST validate that the "aud" claim contains a resource indicator value corresponding to an
    /// identifier the resource server expects for itself." The rule is containment, not equality: an access
    /// token signed under the registration's access-token key whose <c>aud</c> is the array of another resource
    /// and the issuer, presented at UserInfo over the wire under the <c>Bearer</c> scheme, is served 200 with
    /// the End-User's <c>sub</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoServesATokenWhoseAudienceHoldsTheIssuerAmongOtherResourcesAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        string issuer = IssuerOf(host, material);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);
        string sharedAudienceToken = await CompactJwsResigning.ResignWithAlteredPayloadAsync(
            host, accessToken, material.SigningKeyId,
            payload => payload["aud"] = new JsonArray(OtherResourceAudience, issuer)).ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, sharedAudienceToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(SubjectId, document.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-3">RFC 9068 Section 3</see>: "If the request does
    /// not include a "resource" parameter, the authorization server MUST use a default resource indicator in the
    /// "aud" claim." The default resource indicator of this Authorization Server is its issuer. Under the FAPI 2.0
    /// and the HAIP 1.0 profile, a registration whose scopes map to no audience runs the pushed authorization-code
    /// flow of a DPoP-wired client over the wire for <c>openid</c> with no <c>resource</c>; the issued access
    /// token's <c>aud</c> is the one-element array <c>["&lt;issuer&gt;"]</c>, and the token, presented at UserInfo
    /// over the wire under the <c>DPoP</c> scheme with a proof from the bound key carrying the nonce UserInfo
    /// provided, is served 200 with the End-User's <c>sub</c>.
    /// </summary>
    /// <param name="profileRow">The registration's policy profile: <see cref="Fapi20ProfileRow"/> or <see cref="Haip10ProfileRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(Fapi20ProfileRow)]
    [DataRow(Haip10ProfileRow)]
    public async Task ATokenRequestedWithoutAResourceIsAudiencedAtTheIssuerAndServedAtUserInfoAsync(string profileRow)
    {
        PolicyProfile profile = profileRow switch
        {
            Fapi20ProfileRow => PolicyProfile.Fapi20,
            Haip10ProfileRow => PolicyProfile.Haip10,
            _ => throw new ArgumentOutOfRangeException(nameof(profileRow), profileRow, "Unknown profile row.")
        };

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, profile).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);

        //The token endpoint's answer is asserted first, with every fault the host captured for the request taken
        //into the assertion's message, so a token request the server fails is the row's own failure.
        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
            host.Host("default"), fixture.Client, fixture.Registration, fixture.ClientFlowStore,
            material.Registration.TenantId.Value, RedirectUri, SubjectId, browserClient,
            scope: WellKnownScopes.OpenId, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        AuthCodeFlowEndpointResult tokenResult = await fixture.Client.AuthCode.ExchangeTokenAsync(
            fixture.Registration, flowId, [], null, TestContext.CancellationToken).ConfigureAwait(false);
        Exception[] tokenFaults = host.Host("default").ConsumeHttpFaults();
        string tokenAnswer = $"Outcome={tokenResult.Outcome} ErrorCode={tokenResult.ErrorCode} "
            + $"ErrorDescription={tokenResult.ErrorDescription} Faults=[{string.Join(" | ", tokenFaults.Select(static fault => fault.Message))}]";
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome, tokenAnswer);
        Assert.IsEmpty(tokenFaults, tokenAnswer);
        Assert.AreEqual("DPoP", (string)tokenResult.Body![OAuthRequestParameterNames.TokenType], tokenAnswer);

        string accessToken = (string)tokenResult.Body![OAuthRequestParameterNames.AccessToken];
        string? audience = ReadAudienceClaim(accessToken);
        Assert.IsNotNull(audience, "The issued access token carries aud.");
        Assert.AreEqual($"[\"{IssuerOf(host, material)}\"]", audience,
            "The default audience is the issuer, written as the one-element array.");

        string userInfoUrl = (await UserInfoUrlAsync(host, material).ConfigureAwait(false)).ToString();
        string nonce = await ObtainResourceNonceAsync(host, material, accessToken).ConfigureAwait(false);
        string proof = await ResourceDpopProofs.BuildAsync(
            fixture.DpopKey, "POST", userInfoUrl, accessToken, nonce, TimeProvider.GetUtcNow(), TestContext.CancellationToken)
            .ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, accessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(SubjectId, document.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-3">RFC 9068 Section 3</see>: "If the request does
    /// not include a "resource" parameter, the authorization server MUST use a default resource indicator in the
    /// "aud" claim." The default resource indicator of this Authorization Server is its issuer. Under the RFC 6749
    /// with PKCE profile, a registration whose scopes map to no audience runs the authorization-code flow for
    /// <c>openid</c> with no <c>resource</c>, its pushed request and its token request over the wire; the issued
    /// access token's <c>aud</c> is the one-element array <c>["&lt;issuer&gt;"]</c>, and the token, presented at
    /// UserInfo over the wire under the <c>Bearer</c> scheme, is served 200 with the End-User's <c>sub</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ATokenRequestedWithoutAResourceUnderRfc6749WithPkceIsAudiencedAtTheIssuerAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        //The pushed request and the token request cross the loopback listener; the token endpoint's answer is asserted
        //first.
        InProcessAuthCodeDriveResult drive = await InProcessAuthCodeDriver.DriveAsync(
            host, material, SubjectId, RedirectUri,
            new InProcessAuthCodeDriveOptions { Scope = WellKnownScopes.OpenId, UsesRealWireTransport = true },
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, drive.TokenResponse.StatusCode, drive.TokenResponse.Body);

        using JsonDocument tokenBody = JsonDocument.Parse(drive.TokenResponse.Body);
        string accessToken = tokenBody.RootElement.GetProperty("access_token").GetString()!;
        string? audience = ReadAudienceClaim(accessToken);
        Assert.IsNotNull(audience, "The issued access token carries aud.");
        Assert.AreEqual($"[\"{IssuerOf(host, material)}\"]", audience,
            "The default audience is the issuer, written as the one-element array.");

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, accessToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(SubjectId, document.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 Section 4</see>: "The current time
    /// MUST be before the time represented by the "exp" claim." An access token issued to the registration is
    /// presented at UserInfo over the wire under the <c>Bearer</c> scheme with the injected clock set relative to
    /// the token's <c>exp</c>: one second before it the token is served 200 with the End-User's <c>sub</c>; at the
    /// instant of <c>exp</c> it is refused with 401, <c>invalid_token</c>, the one challenge
    /// <c>Bearer error="invalid_token"</c> and the description "Access token has expired.".
    /// </summary>
    /// <param name="secondsFromExp">The clock's offset from the token's <c>exp</c>, in seconds: -1 or 0.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(-1)]
    [DataRow(0)]
    public async Task UserInfoServesATokenOnlyBeforeTheInstantOfItsExpAsync(int secondsFromExp)
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);
        long exp = ReadExpirationSeconds(accessToken);
        TimeProvider.SetUtcNow(DateTimeOffset.FromUnixTimeSeconds(exp).AddSeconds(secondsFromExp));

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, accessToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        if(secondsFromExp < 0)
        {
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
            using JsonDocument served = JsonDocument.Parse(body);
            Assert.AreEqual(SubjectId, served.RootElement.GetProperty("sub").GetString());

            return;
        }

        AssertRefused(response, body, HttpStatusCode.Unauthorized, "Bearer error=\"invalid_token\"", "invalid_token");
        using JsonDocument refused = JsonDocument.Parse(body);
        Assert.AreEqual("Access token has expired.", refused.RootElement.GetProperty("error_description").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_token The
    /// access token provided is expired, revoked, malformed, or invalid for other reasons." A malformed access token
    /// presented at UserInfo over the wire under the <c>Bearer</c> scheme is refused with 401, <c>invalid_token</c>
    /// and the one challenge <c>Bearer error="invalid_token"</c>, and its description is a fixed text that carries
    /// nothing a parser said about the token. The rows: a protected header that is a JSON array
    /// (<c>W10.e30.AA</c>), answered "Access token is malformed."; a payload, signed under the registration's
    /// access-token key, that is the JSON array <c>[]</c>, answered "Access token payload could not be parsed.".
    /// </summary>
    /// <param name="row">Which part of the token is malformed: <see cref="HeaderNotAnObjectRow"/> or <see cref="PayloadNotAnObjectRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(HeaderNotAnObjectRow)]
    [DataRow(PayloadNotAnObjectRow)]
    public async Task UserInfoDescribesAMalformedTokenWithAFixedTextAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (string malformedToken, string expectedDescription) = row switch
        {
            HeaderNotAnObjectRow => ("W10.e30.AA", "Access token is malformed."),
            PayloadNotAnObjectRow => (await CompactJwsResigning.ResignWithPayloadAsync(
                host,
                await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false),
                material.SigningKeyId,
                "[]").ConfigureAwait(false), "Access token payload could not be parsed."),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown malformed-token row.")
        };

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, malformedToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, HttpStatusCode.Unauthorized, "Bearer error=\"invalid_token\"", "invalid_token");
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(expectedDescription, document.RootElement.GetProperty("error_description").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1">RFC 9110 Section 15.6.1</see>: "The 500
    /// (Internal Server Error) status code indicates that the server encountered an unexpected condition that
    /// prevented it from fulfilling the request." An access token issued to the registration is presented at
    /// UserInfo over the wire under the <c>Bearer</c> scheme after the server's own wiring is altered so that it cannot
    /// validate it; the answer is 500 with exactly the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> and no
    /// challenge, whatever the fault names. The rows: the registration's issuer replaced by one the default issuer
    /// resolver refuses (<c>http</c> scheme); an application issuer resolver that answers nothing.
    /// </summary>
    /// <param name="row">Which part of the wiring fails: <see cref="IssuerUnresolvableRow"/> or <see cref="IssuerResolverAnswersNothingRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(IssuerUnresolvableRow)]
    [DataRow(IssuerResolverAnswersNothingRow)]
    public async Task UserInfoAnswersAFaultOfTheServersWiringWithTheFixedDescriptionAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //The unresolvable row replaces the registration the host holds; the other row alters the integration.
        Action<AuthorizationServerIntegration>? alteration = row switch
        {
            IssuerResolverAnswersNothingRow => static candidateIntegration =>
                candidateIntegration.ResolveIssuerAsync = static (_, _, _) => ValueTask.FromResult<Uri?>(null),
            IssuerUnresolvableRow => null,
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown wiring row.")
        };
        if(alteration is not null)
        {
            await TestHostShell.AlterAsync(host.Server, alteration).ConfigureAwait(false);
        }
        else
        {
            ReplaceRegistrationIssuer(host, material, new Uri("http://issuer.test/" + material.Registration.TenantId.Value));
        }

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, accessToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.InternalServerError, response.StatusCode, body);
        Assert.AreEqual(
            /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}", body);
        Assert.IsFalse(response.Headers.Contains("WWW-Authenticate"), "A fault of the server carries no challenge.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_token The
    /// access token provided is expired, revoked, malformed, or invalid for other reasons." An access token issued to
    /// the registration is presented at UserInfo over the wire under the <c>Bearer</c> scheme while the verification
    /// registry raises an <see cref="InvalidOperationException"/> whose message is
    /// <see cref="VerificationRaisedMessage"/> as the function for the token's verification key is resolved; a
    /// signature whose verification cannot run is a signature that does
    /// not verify, so the token is refused with 401, <c>invalid_token</c>, the one challenge
    /// <c>Bearer error="invalid_token"</c> and exactly the description "Access token signature verification
    /// failed.", and the body carries nothing of the exception's message.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DoNotParallelize]
    public async Task UserInfoDescribesASignatureVerificationThatRaisesWithAFixedTextAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        string body;
        HttpResponseMessage response;
        try
        {
            //The registry the library resolves a verification function from is process-wide: the row runs
            //alone and restores the test setup's registry whatever happens.
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.Initialize(
                (_, _, _) => MicrosoftCryptographicFunctionsAdapter.SignP256Async,
                (_, _, _) => throw new InvalidOperationException(VerificationRaisedMessage));
            response = await SendUserInfoOverWireAsync(host, material, accessToken).ConfigureAwait(false);
            body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            TestSetup.Setup();
        }

        using(response)
        {
            AssertRefused(response, body, HttpStatusCode.Unauthorized, "Bearer error=\"invalid_token\"", "invalid_token");
            using JsonDocument document = JsonDocument.Parse(body);
            Assert.AreEqual(
                "Access token signature verification failed.",
                document.RootElement.GetProperty("error_description").GetString(),
                body);
            Assert.DoesNotContain(VerificationRaisedMessage, body, StringComparison.Ordinal);
        }
    }


    /// <summary>The message of the exception the replaced verification function raises.</summary>
    private static string VerificationRaisedMessage { get; } = "verification-function-raised-marker";


    /// <summary>The identifier of a resource other than this Authorization Server.</summary>
    private static string OtherResourceAudience { get; } = "https://rs.example.com";

    /// <summary>The profile row of the FAPI 2.0 registration.</summary>
    private const string Fapi20ProfileRow = "fapi20";

    /// <summary>The profile row of the HAIP 1.0 registration.</summary>
    private const string Haip10ProfileRow = "haip10";

    /// <summary>The malformed-token row whose protected header is a JSON array.</summary>
    private const string HeaderNotAnObjectRow = "header-not-an-object";

    /// <summary>The malformed-token row whose payload is a JSON array.</summary>
    private const string PayloadNotAnObjectRow = "payload-not-an-object";

    /// <summary>The wiring row whose registration names an issuer the default resolver refuses.</summary>
    private const string IssuerUnresolvableRow = "issuer-unresolvable";

    /// <summary>The wiring row whose application issuer resolver answers nothing.</summary>
    private const string IssuerResolverAnswersNothingRow = "issuer-resolver-answers-nothing";


    /// <summary>
    /// The issuer the host holds for <paramref name="material"/>'s registration, the value the issued tokens'
    /// <c>iss</c> carries.
    /// </summary>
    /// <param name="host">The host holding the registration.</param>
    /// <param name="material">The registration.</param>
    /// <returns>The issuer, as written.</returns>
    private static string IssuerOf(TestHostShell host, VerifierKeyMaterial material) =>
        host.Host("default").Registrations[material.Registration.TenantId.Value].IssuerUri!.OriginalString;


    /// <summary>
    /// Replaces the issuer the host holds for <paramref name="material"/>'s registration with
    /// <paramref name="issuer"/>, under both of the keys the host serves the registration by, without the
    /// checks a registration update runs.
    /// </summary>
    /// <param name="host">The host holding the registration.</param>
    /// <param name="material">The registration.</param>
    /// <param name="issuer">The issuer the registration names from then on.</param>
    private static void ReplaceRegistrationIssuer(TestHostShell host, VerifierKeyMaterial material, Uri issuer)
    {
        HostedAuthorizationServer served = host.Host("default");
        ClientRecord replaced = served.Registrations[material.Registration.TenantId.Value] with { IssuerUri = issuer };
        served.Registrations[replaced.TenantId.Value] = replaced;
        served.Registrations[replaced.ClientId] = replaced;
    }


    /// <summary>
    /// The <c>aud</c> claim of a compact JWS's payload exactly as written, or <see langword="null"/> when the
    /// payload carries none.
    /// </summary>
    /// <param name="compactJws">The access token.</param>
    /// <returns>The claim's raw JSON text, or <see langword="null"/>.</returns>
    private static string? ReadAudienceClaim(string compactJws)
    {
        string[] parts = compactJws.Split('.');
        using IMemoryOwner<byte> payloadOwner = TestSetup.Base64UrlDecoder(parts[1], BaseMemoryPool.Shared);
        using JsonDocument payload = JsonDocument.Parse(payloadOwner.Memory);

        return payload.RootElement.TryGetProperty("aud", out JsonElement audience) ? audience.GetRawText() : null;
    }


    /// <summary>The <c>exp</c> claim of a compact JWS's payload, in seconds since the epoch.</summary>
    /// <param name="compactJws">The access token.</param>
    /// <returns>The <c>exp</c> value.</returns>
    private static long ReadExpirationSeconds(string compactJws)
    {
        string[] parts = compactJws.Split('.');
        using IMemoryOwner<byte> payloadOwner = TestSetup.Base64UrlDecoder(parts[1], BaseMemoryPool.Shared);
        using JsonDocument payload = JsonDocument.Parse(payloadOwner.Memory);

        return payload.RootElement.GetProperty("exp").GetInt64();
    }


    /// <summary>The resolver row that holds the registration's key for access tokens only.</summary>
    private const string HeldForAccessTokensRow = "held-for-access-tokens";

    /// <summary>The resolver row that holds the registration's key for ID Tokens only.</summary>
    private const string HeldForIdTokensRow = "held-for-id-tokens";


    /// <summary>The <c>htu</c> row naming a path below the UserInfo path.</summary>
    private const string HtuOtherPathRow = "htu-other-path";

    /// <summary>The <c>htu</c> row naming the UserInfo path with its second <c>/</c> written as <c>%2F</c>.</summary>
    private const string HtuEncodedDelimiterRow = "htu-encoded-delimiter";

    /// <summary>The proof-check row whose <c>nonce</c> is empty.</summary>
    private const string NonceEmptyRow = "nonce-empty";

    /// <summary>The proof-check row whose <c>nonce</c> packs a timestamp no instant is represented for.</summary>
    private const string NonceUnrepresentableTimestampRow = "nonce-unrepresentable-timestamp";

    /// <summary>The <c>htu</c> row naming the UserInfo URL with its scheme in upper case.</summary>
    private const string HtuUpperCaseSchemeRow = "htu-upper-case-scheme";

    /// <summary>The <c>htu</c> row naming the UserInfo URL with the last path character percent-encoded.</summary>
    private const string HtuPercentEncodedUnreservedRow = "htu-percent-encoded-unreserved";

    /// <summary>The <c>htu</c> row naming the UserInfo URL with a query appended.</summary>
    private const string HtuWithQueryRow = "htu-with-query";

    /// <summary>The DPoP-scheme refusal row whose token signature does not verify.</summary>
    private const string TamperedSignatureRow = "tampered-signature";

    /// <summary>The DPoP-scheme refusal row whose token's <c>scope</c> names <c>profile</c> but not <c>openid</c>.</summary>
    private const string WithoutOpenIdScopeRow = "without-openid-scope";

    /// <summary>The DPoP-scheme refusal row whose token carries no <c>sub</c>.</summary>
    private const string WithoutSubjectRow = "without-subject";


    /// <summary>
    /// A nonce in the packed shape the server's nonce issuance writes (a one-byte key-id length, the
    /// key id <c>x</c>, a big-endian 64-bit timestamp, then 64 bytes where the audience hash, random part
    /// and HMAC tag sit) whose timestamp is <see cref="long.MaxValue"/>, a value no instant is represented
    /// for; its HMAC is never valid.
    /// </summary>
    /// <returns>The base64url-encoded nonce.</returns>
    private static string UnrepresentableTimestampNonce()
    {
        Span<byte> packed = stackalloc byte[1 + 1 + 8 + 64];
        packed.Clear();
        packed[0] = 1;
        packed[1] = (byte)'x';
        BinaryPrimitives.WriteInt64BigEndian(packed[2..], long.MaxValue);

        return TestHostShell.Base64UrlEncoder(packed);
    }


    /// <summary>
    /// Flips one character in the middle of a compact JWS's signature segment; it stays base64url, so
    /// the token parses and its signature deterministically fails to verify.
    /// </summary>
    /// <param name="compactJws">The token to tamper.</param>
    /// <returns>The token with a signature that does not verify.</returns>
    private static string TamperSignature(string compactJws)
    {
        int signatureStart = compactJws.LastIndexOf('.', StringComparison.Ordinal) + 1;
        int tamperIndex = signatureStart + ((compactJws.Length - signatureStart) / 2);
        char flipped = compactJws[tamperIndex] == 'A' ? 'B' : 'A';

        return string.Concat(compactJws.AsSpan(0, tamperIndex), flipped.ToString(), compactJws.AsSpan(tamperIndex + 1));
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
    /// A DPoP-bound access token issued over the wire, the UserInfo URL it is presented at, and the
    /// nonce UserInfo provided for it: the state every proof-check row starts from. The test owns and
    /// disposes the host, the registration's key material and the DPoP-wired client.
    /// </summary>
    /// <param name="Host">The host serving UserInfo.</param>
    /// <param name="Material">The registration the token was issued under.</param>
    /// <param name="Fixture">The DPoP-wired client whose key the token is bound to.</param>
    /// <param name="AccessToken">The DPoP-bound access token.</param>
    /// <param name="UserInfoUrl">The absolute UserInfo URL on the host's loopback listener.</param>
    /// <param name="Nonce">The nonce UserInfo provided for the token.</param>
    private sealed record DpopPresentationContext(
        TestHostShell Host, VerifierKeyMaterial Material, DpopClientFixture Fixture, string AccessToken, string UserInfoUrl, string Nonce)
    {
        /// <summary>The DPoP key the token is bound to.</summary>
        public DpopKey DpopKey => Fixture.DpopKey;
    }


    /// <summary>
    /// Seeds the End-User, enables DPoP on the host and creates the DPoP-wired client of
    /// <paramref name="material"/>'s registration.
    /// </summary>
    /// <param name="host">The host holding the registration.</param>
    /// <param name="material">The registration the client is wired to.</param>
    /// <returns>The client fixture; the caller disposes it.</returns>
    private async Task<DpopClientFixture> CreateDpopFixtureAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        _ = host.SeedTestSubject(subject: SubjectId);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        return await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Issues the DPoP-wired client a DPoP-bound access token over the wire and obtains the nonce
    /// UserInfo provides for it.
    /// </summary>
    /// <param name="host">The host whose registration and listener serve the flow.</param>
    /// <param name="material">The registration the token is issued under.</param>
    /// <param name="fixture">The DPoP-wired client.</param>
    /// <returns>The presentation state.</returns>
    private async Task<DpopPresentationContext> PrepareDpopPresentationAsync(
        TestHostShell host, VerifierKeyMaterial material, DpopClientFixture fixture)
    {
        string boundAccessToken = await IssueDpopBoundAccessTokenAsync(host, material, fixture).ConfigureAwait(false);
        string url = (await UserInfoUrlAsync(host, material).ConfigureAwait(false)).ToString();
        string nonce = await ObtainResourceNonceAsync(host, material, boundAccessToken).ConfigureAwait(false);

        return new DpopPresentationContext(host, material, fixture, boundAccessToken, url, nonce);
    }


    /// <summary>
    /// Presents <paramref name="proof"/> with the presentation's token under the <c>DPoP</c> scheme at
    /// UserInfo over the wire and asserts the refusal: 401, the one challenge
    /// <c>DPoP error="<paramref name="error"/>", algs="…"</c>, the error in the body, no subject, and,
    /// when <paramref name="isDpopNonceExpected"/>, a <c>DPoP-Nonce</c> header.
    /// </summary>
    /// <param name="presentation">The presentation state.</param>
    /// <param name="proof">The DPoP proof sent.</param>
    /// <param name="error">The expected error.</param>
    /// <param name="isDpopNonceExpected">Whether the refusal is answered with a <c>DPoP-Nonce</c> field.</param>
    private async Task AssertProofRefusedAsync(
        DpopPresentationContext presentation, string proof, string error, bool isDpopNonceExpected = false)
    {
        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            presentation.Host, presentation.Material, presentation.AccessToken, scheme: "DPoP", dpopProof: proof)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, HttpStatusCode.Unauthorized, ResourceDpopProofs.DpopChallenge(error), error);
        if(isDpopNonceExpected)
        {
            Assert.IsFalse(string.IsNullOrEmpty(ResourceDpopProofs.ReadNonce(response)), "The refusal is answered with a DPoP-Nonce field.");
        }
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
    /// Presents <paramref name="accessToken"/> at UserInfo over the wire under the <c>DPoP</c> scheme
    /// with no proof, asserts the RFC 9449 §9 nonce challenge it is answered with, and returns the
    /// nonce the challenge's <c>DPoP-Nonce</c> header provides.
    /// </summary>
    /// <param name="host">The host whose listener serves the request.</param>
    /// <param name="material">The registration whose UserInfo path is addressed.</param>
    /// <param name="accessToken">The DPoP-bound access token presented.</param>
    /// <returns>The nonce UserInfo provided.</returns>
    private async Task<string> ObtainResourceNonceAsync(TestHostShell host, VerifierKeyMaterial material, string accessToken)
    {
        using HttpResponseMessage challenge = await SendUserInfoOverWireAsync(host, material, accessToken, scheme: "DPoP")
            .ConfigureAwait(false);
        string body = await challenge.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        AssertRefused(challenge, body, HttpStatusCode.Unauthorized, ResourceDpopProofs.DpopChallenge("use_dpop_nonce"), "use_dpop_nonce");

        return ResourceDpopProofs.ReadNonce(challenge);
    }


    /// <summary>
    /// Asserts that an in-process UserInfo refusal of a request without usable credentials carries the
    /// one <c>WWW-Authenticate</c> value <c>Bearer scope="openid", DPoP algs="…"</c> (RFC 6750 §3 and
    /// §3.1, RFC 9449 §7.2).
    /// </summary>
    /// <param name="response">The dispatched response.</param>
    private static void AssertMissingCredentialsChallenge(ServerHttpResponse response)
    {
        Assert.IsTrue(response.Headers.TryGetValue("WWW-Authenticate", out string? challenge),
            "RFC 6750 §3: the refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual($"Bearer scope=\"openid\", DPoP algs=\"{ResourceDpopProofs.AcceptedProofAlgorithms}\"", challenge);
    }


    /// <summary>
    /// Asserts a UserInfo refusal over the wire: <paramref name="status"/>, exactly one
    /// <c>WWW-Authenticate</c> value equal to <paramref name="challenge"/>, <paramref name="error"/> in
    /// the body, and no subject revealed.
    /// </summary>
    /// <param name="response">The wire response.</param>
    /// <param name="body">The response body text.</param>
    /// <param name="status">The expected status.</param>
    /// <param name="challenge">The expected single challenge value.</param>
    /// <param name="error">The expected body <c>error</c>.</param>
    private static void AssertRefused(HttpResponseMessage response, string body, HttpStatusCode status, string challenge, string error)
    {
        Assert.AreEqual(status, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "The refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual(challenge, challenges.Single());

        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(error, document.RootElement.GetProperty("error").GetString());
        Assert.IsFalse(document.RootElement.TryGetProperty("sub", out _), "A refused request reveals no subject.");
    }


    /// <summary>
    /// Presents <paramref name="proof"/> with the presentation's token under the <c>DPoP</c> scheme at UserInfo over the
    /// wire and asserts the server-side failure: 500, a JSON error body whose <c>error</c> is <c>server_error</c> and
    /// whose <c>error_description</c> is <paramref name="expectedDescription"/>, no <c>WWW-Authenticate</c> challenge and
    /// no subject. The body is asserted to carry an <c>error</c> member before it is parsed, so an answer with no JSON
    /// error body fails at that assertion.
    /// </summary>
    /// <param name="presentation">The presentation state.</param>
    /// <param name="proof">The DPoP proof sent.</param>
    /// <param name="expectedDescription">The expected <c>error_description</c>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertServerErrorAsync(DpopPresentationContext presentation, string proof, string expectedDescription)
    {
        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            presentation.Host, presentation.Material, presentation.AccessToken, scheme: "DPoP", dpopProof: proof)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.InternalServerError, response.StatusCode, body);
        DpopCodeBindingWire.AssertCarriesJsonErrorBody(body);
        Assert.IsFalse(response.Headers.Contains("WWW-Authenticate"), "A server error carries no WWW-Authenticate challenge.");
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("server_error", document.RootElement.GetProperty("error").GetString(), body);
        Assert.AreEqual(expectedDescription, document.RootElement.GetProperty("error_description").GetString(), body);
        Assert.IsFalse(document.RootElement.TryGetProperty("sub", out _), "A server error reveals no subject.");
    }


    /// <summary>
    /// Asserts a UserInfo refusal received over a raw TLS connection: 401, exactly one <c>WWW-Authenticate</c> field
    /// line equal to <paramref name="challenge"/>, <paramref name="error"/> in the body, and no subject revealed.
    /// </summary>
    /// <param name="response">The wire response.</param>
    /// <param name="challenge">The expected single challenge value.</param>
    /// <param name="error">The expected body <c>error</c>.</param>
    private static void AssertRefusedOverARawConnection(HttpResponseData response, string challenge, string error)
    {
        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(challenge, Assert.ContainsSingle(response.Headers.Headers.GetValues("WWW-Authenticate")));

        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual(error, document.RootElement.GetProperty("error").GetString());
        Assert.IsFalse(document.RootElement.TryGetProperty("sub", out _), "A refused request reveals no subject.");
    }


    /// <summary>
    /// The URL of the registration's UserInfo endpoint on the host's loopback HTTPS listener,
    /// starting the listener when it is not yet running.
    /// </summary>
    /// <param name="host">The host whose listener serves the request.</param>
    /// <param name="material">The registration whose UserInfo path is addressed.</param>
    /// <returns>The absolute UserInfo URL.</returns>
    private Task<Uri> UserInfoUrlAsync(TestHostShell host, VerifierKeyMaterial material) =>
        RawAuthCodeWirePushers.ResolveUserInfoUriAsync(host, material, TestContext.CancellationToken);


    /// <summary>
    /// Sends a request to the registration's UserInfo endpoint over the host's loopback HTTPS listener
    /// with <paramref name="accessToken"/> under <paramref name="scheme"/> and, when given,
    /// <paramref name="dpopProof"/> in the <c>DPoP</c> header, through the shared
    /// <see cref="RawAuthCodeWirePushers.SendUserInfoRequestAsync"/> under this test's cancellation token.
    /// </summary>
    /// <param name="host">The host whose listener serves the request.</param>
    /// <param name="material">The registration whose UserInfo path is addressed.</param>
    /// <param name="accessToken">The access token presented.</param>
    /// <param name="scheme">The <c>Authorization</c> scheme the token is presented under.</param>
    /// <param name="dpopProof">The DPoP proof, or <see langword="null"/> to send no <c>DPoP</c> header.</param>
    /// <param name="httpMethod">The request method, or <see langword="null"/> for POST.</param>
    /// <returns>The wire response; the caller disposes it.</returns>
    private Task<HttpResponseMessage> SendUserInfoOverWireAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string accessToken,
        string scheme = "Bearer",
        string? dpopProof = null,
        HttpMethod? httpMethod = null) =>
        RawAuthCodeWirePushers.SendUserInfoRequestAsync(
            host, material, accessToken, scheme, dpopProof, httpMethod, TestContext.CancellationToken);


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
