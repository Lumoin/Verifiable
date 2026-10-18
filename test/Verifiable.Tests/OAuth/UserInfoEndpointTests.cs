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
        using var signature = await signingKey.SignAsync(signingInput, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
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
            ClientAssertionKeyRow => await IssuanceKeySeparation.ListFreshKeyAsync(
                host, material, KeyUsageContext.ClientAssertion).ConfigureAwait(false),
            OtherRegistrationKeyRow => otherMaterial.SigningKeyId,
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown key row.")
        };

        string resignedAccessToken = await CompactJwsResigning.ResignWithHeaderAsync(
            host, accessToken, foreignKeyId, "at+jwt", TestContext.CancellationToken).ConfigureAwait(false);

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
            host, accessToken, material.SigningKeyId, " ", "at+jwt", TestContext.CancellationToken).ConfigureAwait(false);

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
            host, accessToken, material.SigningKeyId, payload.ToJsonString(), TestContext.CancellationToken).ConfigureAwait(false);

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
    /// with no <c>Authorization</c> header, or with one under an unsupported scheme, is refused with 401,
    /// an empty body and exactly one challenge naming the two schemes UserInfo accepts and no error:
    /// <c>Bearer scope="openid", DPoP algs="…"</c>.
    /// </summary>
    /// <param name="authorization">The <c>Authorization</c> header sent, or <see langword="null"/> for none.</param>
    [TestMethod]
    [DataRow(null)]
    [DataRow("Basic dXNlcjpwYXNz")]
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

        await AssertProofRefusedAsync(presentation, proof, "use_dpop_nonce", isFreshNonceExpected: true).ConfigureAwait(false);
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
    [TestMethod]
    public async Task UserInfoRefusesATokenBoundByAConfirmationMethodItCannotCheckAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);
        string certificateBoundToken = await ResignAccessTokenPayloadAsync(
            host, accessToken, material.SigningKeyId,
            payload => payload["cnf"] = new JsonObject { ["x5t#S256"] = "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2" }, TestContext.CancellationToken)
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
            WithoutOpenIdScopeRow => (await ResignAccessTokenPayloadAsync(host, boundAccessToken, material.SigningKeyId,
                    payload => payload["scope"] = WellKnownScopes.Profile, TestContext.CancellationToken).ConfigureAwait(false),
                HttpStatusCode.Forbidden,
                $"DPoP error=\"insufficient_scope\", scope=\"openid\", algs=\"{ResourceDpopProofs.AcceptedProofAlgorithms}\"", "insufficient_scope"),
            WithoutSubjectRow => (await ResignAccessTokenPayloadAsync(host, boundAccessToken, material.SigningKeyId,
                    payload => _ = payload.Remove("sub"), TestContext.CancellationToken).ConfigureAwait(false),
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
    [TestMethod]
    public async Task UserInfoRefusesAnAccessTokenWhoseExpIsNotARepresentableInstantAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);
        string farExpiryToken = await ResignAccessTokenPayloadAsync(
            host, accessToken, material.SigningKeyId, payload => payload["exp"] = long.MaxValue, TestContext.CancellationToken).ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, farExpiryToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, HttpStatusCode.Unauthorized, "Bearer error=\"invalid_token\"", "invalid_token");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4">RFC 7519 §4.1.4</see>: "the current date/time MUST be
    /// before the expiration date/time listed in the "exp" claim". An access token whose <c>exp</c> is the present instant
    /// itself is refused at UserInfo over the wire with 401 <c>invalid_token</c>, where the expiry instant was once accepted, and
    /// one whose <c>exp</c> lies a tick after the present is served.
    /// </summary>
    [TestMethod]
    public async Task UserInfoRefusesAnAccessTokenAtItsExpiryInstantAsync()
    {
        await using var host = new TestHostShell(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using var material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);
        var now = TimeProvider.GetUtcNow();
        var atTheExpiry = await ResignAccessTokenPayloadAsync(
            host, accessToken, material.SigningKeyId, payload => payload["exp"] = SecondsSinceTheEpoch(now), TestContext.CancellationToken).ConfigureAwait(false);

        using var refused = await SendUserInfoOverWireAsync(host, material, atTheExpiry).ConfigureAwait(false);
        var refusedBody = await refused.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(refused, refusedBody, HttpStatusCode.Unauthorized, "Bearer error=\"invalid_token\"", "invalid_token");

        var aTickBeforeTheExpiry = await ResignAccessTokenPayloadAsync(
            host, accessToken, material.SigningKeyId, payload => payload["exp"] = SecondsSinceTheEpoch(now.AddTicks(1)), TestContext.CancellationToken).ConfigureAwait(false);

        using var served = await SendUserInfoOverWireAsync(host, material, aTickBeforeTheExpiry).ConfigureAwait(false);
        var servedBody = await served.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, served.StatusCode, servedBody);
    }


    /// <summary>The count of seconds since the epoch an instant names, to its tick.</summary>
    /// <param name="instant">The instant.</param>
    /// <returns>The count.</returns>
    private static decimal SecondsSinceTheEpoch(DateTimeOffset instant) =>
        (instant.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / (decimal)TimeSpan.TicksPerSecond;


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
        var underIdTokenKey = await CompactJwsResigning.ResignWithHeaderAsync(host, accessToken, idTokenKeyId, "at+jwt", TestContext.CancellationToken)
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


    /// <summary>
    /// Re-signs an issued access token under <paramref name="keyId"/> with its payload rewritten by
    /// <paramref name="alterPayload"/>, through <see cref="CompactJwsResigning.ResignWithPayloadAsync"/>.
    /// </summary>
    /// <param name="host">The host holding the key's private half.</param>
    /// <param name="accessToken">The issued access token.</param>
    /// <param name="keyId">The key the token's header names and the rebuilt token is signed under.</param>
    /// <param name="alterPayload">Rewrites the parsed payload.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The re-signed access token.</returns>
    private static async Task<string> ResignAccessTokenPayloadAsync(
        TestHostShell host, string accessToken, KeyId keyId, Action<JsonObject> alterPayload,
        CancellationToken cancellationToken)
    {
        string[] parts = accessToken.Split('.');
        using IMemoryOwner<byte> payloadOwner = TestSetup.Base64UrlDecoder(parts[1], BaseMemoryPool.Shared);
        JsonObject payload = JsonNode.Parse(payloadOwner.Memory.Span)!.AsObject();
        alterPayload(payload);

        return await CompactJwsResigning.ResignWithPayloadAsync(host, accessToken, keyId, payload.ToJsonString(), cancellationToken)
            .ConfigureAwait(false);
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
    /// when <paramref name="isFreshNonceExpected"/>, a <c>DPoP-Nonce</c> header.
    /// </summary>
    /// <param name="presentation">The presentation state.</param>
    /// <param name="proof">The DPoP proof sent.</param>
    /// <param name="error">The expected error.</param>
    /// <param name="isFreshNonceExpected">Whether the refusal provides a fresh nonce.</param>
    private async Task AssertProofRefusedAsync(
        DpopPresentationContext presentation, string proof, string error, bool isFreshNonceExpected = false)
    {
        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            presentation.Host, presentation.Material, presentation.AccessToken, scheme: "DPoP", dpopProof: proof)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, HttpStatusCode.Unauthorized, ResourceDpopProofs.DpopChallenge(error), error);
        if(isFreshNonceExpected)
        {
            Assert.IsFalse(string.IsNullOrEmpty(ResourceDpopProofs.ReadNonce(response)), "The challenge provides a fresh nonce.");
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
