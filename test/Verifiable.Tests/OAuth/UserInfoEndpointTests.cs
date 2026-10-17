using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
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
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Diagnostics;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Oidc;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Metadata;
using Verifiable.OAuth.Server.States;
using Verifiable.Server.Diagnostics;
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
    /// <c>Bearer realm="&lt;issuer&gt;", scope="openid", DPoP realm="&lt;issuer&gt;", scope="openid", algs="..."</c>, which carries no error.
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
        AssertMissingCredentialsChallenge(response, IssuerOf(host, material));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>: "If the
    /// request lacks any authentication information ... the resource server SHOULD NOT include an error
    /// code or other error information." UserInfo answers GET as well as POST
    /// (<see href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoRequest">OIDC Core
    /// §5.3.1</see>: "The Client sends the UserInfo Request using either HTTP GET or HTTP POST."); a GET dispatched
    /// with no <c>Authorization</c> header is answered 401 with an empty body and the one challenge
    /// <c>Bearer realm="&lt;issuer&gt;", scope="openid", DPoP realm="&lt;issuer&gt;", scope="openid", algs="..."</c>.
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
        AssertMissingCredentialsChallenge(response, IssuerOf(host, material));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>: "If the
    /// request lacks any authentication information (e.g., the client was unaware that authentication
    /// is necessary or attempted using an unsupported authentication method), the resource server
    /// SHOULD NOT include an error code or other error information." A UserInfo POST dispatched with an
    /// <c>Authorization</c> header under the unsupported <c>Basic</c> scheme is answered 401 with an
    /// empty body and the one challenge <c>Bearer realm="&lt;issuer&gt;", scope="openid", DPoP realm="&lt;issuer&gt;", scope="openid", algs="..."</c>.
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
        AssertMissingCredentialsChallenge(response, IssuerOf(host, material));
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
    /// <c>invalid_token</c> with <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c>, never a server fault.
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

        AssertRefused(response, body, HttpStatusCode.Unauthorized, UserInfoBearerChallenge(host, material, "invalid_token"), "invalid_token");
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

        AssertRefused(response, body, HttpStatusCode.Unauthorized, UserInfoDpopChallenge(host, material, "invalid_dpop_proof"), "invalid_dpop_proof");
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
    /// HTTP "WWW-Authenticate" response header field", here <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c>. The
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
        Assert.AreEqual(UserInfoBearerChallenge(host, material, "invalid_token"), challenges.Single());

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
    /// <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c>, never a server error.
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
        Assert.AreEqual(UserInfoBearerChallenge(host, material, "invalid_token"), challenges.Single());

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
    /// <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c>.
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
        Assert.AreEqual(UserInfoBearerChallenge(host, material, "invalid_token"), challenges.Single());

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
    /// the scope UserInfo requires and the realm, the issuer: <c>Bearer realm="&lt;issuer&gt;", error="insufficient_scope", scope="openid"</c>.
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
        Assert.AreEqual(UserInfoBearerChallenge(host, material, "insufficient_scope", "openid"), challenges.Single());

        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("insufficient_scope", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 §7.2</see>: "such a
    /// protected resource MUST reject a DPoP-bound access token received as a bearer token per
    /// [RFC6750]." An access token the token endpoint bound to the client's DPoP key (<c>cnf.jkt</c>),
    /// presented at UserInfo over the wire under the <c>Bearer</c> scheme with no DPoP proof, is refused
    /// with 401 <c>invalid_token</c> and the challenge <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c>, and no claim
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
        Assert.AreEqual(UserInfoBearerChallenge(host, material, "invalid_token"), challenges.Single());

        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_token", document.RootElement.GetProperty("error").GetString());
        Assert.IsFalse(document.RootElement.TryGetProperty("sub", out _), "A refused token reveals no subject.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>:
    /// "dpop_bound_access_tokens_required OPTIONAL. Boolean value specifying whether the protected resource always
    /// requires the use of DPoP-bound access tokens [RFC9449]."; <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC
    /// 9449 Section 7.1</see>: "Upon receipt of a request to a protected resource within the protection space requiring
    /// DPoP authentication, the server can respond with a challenge to the client to provide DPoP authentication
    /// information"; and <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "If
    /// the request lacks any authentication information (e.g., the client was unaware that authentication is necessary
    /// or attempted using an unsupported authentication method), the resource server SHOULD NOT include an error code or
    /// other error information." At a server whose resources require DPoP-bound access tokens, a UserInfo POST sent over
    /// a raw TLS connection with one <c>Authorization: Bearer</c> field line is refused whatever the credentials:
    /// 401, an empty body, the one challenge
    /// <c>DPoP realm="&lt;issuer&gt;", scope="openid", algs="ES256 ES384 ES512 ES256K RS256 RS384 RS512 PS256 PS384 PS512 EdDSA Ed25519"</c>
    /// with no <c>error</c> and no <c>Bearer</c> challenge, and the one field line
    /// <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>. The rows: an access token bound to no key; an
    /// access token bound to the client's DPoP key; the value <c>x</c>.
    /// </summary>
    /// <param name="row">The credentials presented: <see cref="UnboundTokenRow"/>, <see cref="DpopBoundTokenRow"/> or <see cref="NonTokenValueRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(UnboundTokenRow)]
    [DataRow(DpopBoundTokenRow)]
    [DataRow(NonTokenValueRow)]
    public async Task UserInfoRequiringDpopBoundAccessTokensRefusesEveryBearerPresentationAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        PolicyProfile? profile = row switch
        {
            DpopBoundTokenRow => null,
            _ => PolicyProfile.Rfc6749WithPkce
        };
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, profile).ConfigureAwait(false);
        string credentials = await ArrangeBearerPresentationAsync(host, material, row).ConfigureAwait(false);
        await RequireDpopBoundAccessTokensAtResourcesAsync(host).ConfigureAwait(false);

        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl,
            [new(WellKnownHttpHeaderNames.Authorization, $"Bearer {credentials}")],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The presentation is refused without a server fault.");
        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            ResourceDpopProofs.DpopChallenge(IssuerOf(host, material), error: null, scope: "openid"),
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        Assert.AreEqual(string.Empty, response.Body, "No error code or other error information.");
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
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "For such an access
    /// token, a resource server MUST check that a DPoP proof was also received in the DPoP header field of the HTTP
    /// request, check the DPoP proof according to the rules in Section 4.3, and check that the public key of the DPoP
    /// proof matches the public key to which the access token is bound per Section 6." and "The resource server MUST NOT
    /// grant access to the resource unless all checks are successful." A DPoP-bound access token and the nonce UserInfo
    /// provides are obtained; once the server's resources require DPoP-bound access tokens, the token presented at
    /// UserInfo over the wire under the <c>DPoP</c> scheme with a proof signed by the bound key and carrying that nonce
    /// passes every check and is served: 200 with the End-User's <c>sub</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoRequiringDpopBoundAccessTokensServesADpopPresentationAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);
        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The token and the nonce are obtained without a server fault.");

        await RequireDpopBoundAccessTokensAtResourcesAsync(host).ConfigureAwait(false);
        string proof = await ResourceDpopProofs.BuildAsync(
            fixture.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce, TimeProvider.GetUtcNow(),
            TestContext.CancellationToken).ConfigureAwait(false);
        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, presentation.AccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The presentation is answered without a server fault.");
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(SubjectId, document.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "For such an access
    /// token, a resource server MUST check that a DPoP proof was also received in the DPoP header field of the HTTP
    /// request, check the DPoP proof according to the rules in Section 4.3, and check that the public key of the DPoP proof
    /// matches the public key to which the access token is bound per Section 6." A DPoP-bound access token presented at
    /// UserInfo over the wire with the nonce UserInfo provided, the server's dispatch span unwired and so started on its
    /// own source: a proof signed by another key is answered 401 and the request's <c>server.handle</c> span carries one
    /// <c>oauth.dpop.resource.decided</c> event with <c>oauth.dpop.resource.decision</c> <c>Deny</c>,
    /// <c>oauth.dpop.resource.check</c> <c>key_binding</c> and <c>server.response.error_code</c> <c>invalid_token</c>; a
    /// proof signed by the bound key is answered 200 and the span carries one such event with <c>Permit</c>, no check and
    /// no error code.
    /// </summary>
    /// <param name="row">Whether the proof is signed by another key or by the bound key.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(ProofByAnotherKeyRow)]
    [DataRow(ProofByTheBoundKeyRow)]
    public async Task UserInfoDispatchSpanRecordsTheDpopDecisionAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);
        using FreshDpopKey otherKey = new();
        string proof = await ResourceDpopProofs.BuildAsync(
            row == ProofByAnotherKeyRow ? otherKey.Key : fixture.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken,
            presentation.Nonce, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        //The listener is process-wide and this class runs in parallel with others, so the dispatch span is found by the
        //registration's own tenant handle; it starts after the token and the nonce are obtained, so it sees the one request.
        ConcurrentQueue<Activity> captured = new();
        using ActivityListener listener = new()
        {
            ShouldListenTo = static source => string.Equals(source.Name, ServerActivitySource.SourceName, StringComparison.Ordinal),
            Sample = static (ref _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = captured.Enqueue
        };
        ActivitySource.AddActivityListener(listener);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, presentation.AccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The presentation is answered without a server fault.");
        Assert.AreEqual(row == ProofByAnotherKeyRow ? HttpStatusCode.Unauthorized : HttpStatusCode.OK, response.StatusCode, body);
        string handle = material.Registration.TenantHandle!.Value.Value;
        Activity dispatch = Assert.ContainsSingle(captured.Where(activity =>
            string.Equals(activity.OperationName, ServerActivityNames.Handle, StringComparison.Ordinal)
            && string.Equals(activity.GetTagItem(ServerTagNames.TenantHandle) as string, handle, StringComparison.Ordinal)),
            "The request is dispatched once under the registration's tenant handle.");
        ActivityEvent decided = Assert.ContainsSingle(
            dispatch.Events.Where(static activityEvent => string.Equals(activityEvent.Name, OAuthEventNames.DpopResourceDecided, StringComparison.Ordinal)),
            "The dispatch span carries one decision event.");
        Dictionary<string, object?> tags = decided.Tags.ToDictionary(static tag => tag.Key, static tag => tag.Value, StringComparer.Ordinal);
        Assert.AreEqual(
            row == ProofByAnotherKeyRow ? nameof(Verifiable.OAuth.ProtectedResource.DpopResourceDecisionKind.Deny) : nameof(Verifiable.OAuth.ProtectedResource.DpopResourceDecisionKind.Permit),
            tags.GetValueOrDefault(OAuthTagNames.DpopResourceDecision) as string);
        Assert.AreEqual(row == ProofByAnotherKeyRow ? "key_binding" : null, tags.GetValueOrDefault(OAuthTagNames.DpopResourceCheck) as string);
        Assert.AreEqual(row == ProofByAnotherKeyRow ? "invalid_token" : null, tags.GetValueOrDefault(ServerTagNames.ErrorCode) as string);
    }


    /// <summary>The row of a proof signed by the key the token is bound to. A constant, not a property, because a DataRow attribute argument must be a compile-time constant.</summary>
    private const string ProofByTheBoundKeyRow = "proof-by-the-bound-key";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 §3</see>: "If the
    /// protected resource request does not include authentication credentials or does not contain an
    /// access token that enables access to the protected resource, the resource server MUST include the
    /// HTTP "WWW-Authenticate" response header field", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>: "If the
    /// request lacks any authentication information (e.g., the client was unaware that authentication
    /// is necessary or attempted using an unsupported authentication method), the resource server
    /// SHOULD NOT include an error code or other error information." A UserInfo request over the wire
    /// with no <c>Authorization</c> header, with one under an unsupported scheme, or with a <c>Bearer</c> or a
    /// <c>DPoP</c> line naming its scheme alone and so carrying no credentials at all (the token is a
    /// <c>b64token</c>, <see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 Section 2.1</see>,
    /// "credentials = "Bearer" 1*SP b64token"), is refused with 401, an empty body and exactly one challenge
    /// naming the two schemes UserInfo accepts and no error: <c>Bearer realm="&lt;issuer&gt;", scope="openid", DPoP realm="&lt;issuer&gt;", scope="openid", algs="..."</c>.
    /// </summary>
    /// <param name="authorization">The <c>Authorization</c> header sent, or <see langword="null"/> for none.</param>
    [TestMethod]
    [DataRow(null)]
    [DataRow("Basic dXNlcjpwYXNz")]
    [DataRow("Bearer")]
    [DataRow("DPoP")]
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
        Assert.AreEqual(MissingCredentialsChallenge(IssuerOf(host, material)), Assert.ContainsSingle(challenges));
        Assert.AreEqual(string.Empty, body, "RFC 6750 §3.1: no error code or other error information.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "If no authentication
    /// information has been included with the request, then the challenges SHOULD NOT include an error code or other
    /// error information, as per Section 3.1 of [RFC6750] (Figure 17).", at a resource within
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">Section 7.1</see>'s "protection space requiring
    /// DPoP authentication". At a server whose resources require DPoP-bound access tokens, a UserInfo POST sent over a
    /// raw TLS connection with no <c>Authorization</c> field is answered 401 with an empty body, the one challenge
    /// <c>DPoP realm="&lt;issuer&gt;", scope="openid", algs="..."</c> alone, no <c>Bearer</c> challenge, and the one
    /// field line <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoRequiringDpopBoundAccessTokensChallengesARequestWithoutCredentialsWithTheDpopChallengeAloneAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        await RequireDpopBoundAccessTokensAtResourcesAsync(host).ConfigureAwait(false);

        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl, [], ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is challenged without a server fault.");
        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            ResourceDpopProofs.DpopChallenge(IssuerOf(host, material), error: null, scope: "openid"),
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        Assert.AreEqual(string.Empty, response.Body, "No error code or other error information.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>, Figure 12: "credentials
    /// = "DPoP" 1*SP token68", with <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section
    /// 11.2</see>: "token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=""; the credential outside that
    /// form is malformed, <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>:
    /// "invalid_request The request is missing a required parameter, includes an unsupported parameter or parameter
    /// value, repeats the same parameter, uses more than one method for including an access token, or is otherwise
    /// malformed. The resource server SHOULD respond with the HTTP 400 (Bad Request) status code.", and the mechanism it
    /// attempts is named, <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "If
    /// the mechanism used to attempt authentication could be established unambiguously, then the corresponding challenge
    /// SHOULD be used to deliver error information (Figure 18)." A UserInfo request sent over a raw TLS connection whose
    /// one <c>Authorization</c> field line names the <c>DPoP</c> scheme with credentials outside token68 is answered 400
    /// with the body
    /// <c>{"error":"invalid_request","error_description":"The Authorization header credentials are not a token68."}</c>,
    /// the one challenge <c>DPoP realm="&lt;issuer&gt;", error="invalid_request", scope="openid", algs="..."</c> and the
    /// one field line <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>. The rows: credentials holding a
    /// space; credentials holding <c>"</c>; credentials holding <c>,</c>.
    /// </summary>
    /// <param name="authorization">The <c>Authorization</c> field line sent.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("DPoP abc def", DisplayName = "credentials holding a space")]
    [DataRow("DPoP abc\"def", DisplayName = "credentials holding a double quote")]
    [DataRow("DPoP abc,def", DisplayName = "credentials holding a comma")]
    public async Task UserInfoRefusesADpopCredentialOutsideToken68Async(string authorization)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl,
            [new(WellKnownHttpHeaderNames.Authorization, authorization)],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(
            ResourceDpopProofs.DpopChallenge(IssuerOf(host, material), "invalid_request", scope: "openid"),
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        Assert.AreEqual(CredentialsOutsideToken68Body, response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 Section 2.1</see>: "b64token    = 1*(
    /// ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="" and "credentials = "Bearer" 1*SP b64token"; the
    /// credential outside that form is malformed, <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750
    /// Section 3.1</see>: "invalid_request The request is missing a required parameter, includes an unsupported parameter
    /// or parameter value, repeats the same parameter, uses more than one method for including an access token, or is
    /// otherwise malformed. The resource server SHOULD respond with the HTTP 400 (Bad Request) status code.", and the
    /// mechanism it attempts is named, <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section
    /// 7.2</see>: "If the mechanism used to attempt authentication could be established unambiguously, then the
    /// corresponding challenge SHOULD be used to deliver error information (Figure 18)." A UserInfo request sent over a
    /// raw TLS connection whose one <c>Authorization</c> field line names the <c>Bearer</c> scheme with credentials
    /// outside that form is answered 400 with the body
    /// <c>{"error":"invalid_request","error_description":"The Authorization header credentials are not a token68."}</c>,
    /// the one challenge <c>Bearer realm="&lt;issuer&gt;", error="invalid_request"</c>, no <c>DPoP</c> challenge and no
    /// <c>Access-Control-Expose-Headers</c> field. The rows: credentials holding a space; credentials holding <c>"</c>;
    /// credentials holding <c>,</c>; credentials that are an auth-param, <c>a=b</c>.
    /// </summary>
    /// <param name="authorization">The <c>Authorization</c> field line sent.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("Bearer abc def", DisplayName = "credentials holding a space")]
    [DataRow("Bearer abc\"def", DisplayName = "credentials holding a double quote")]
    [DataRow("Bearer abc,def", DisplayName = "credentials holding a comma")]
    [DataRow("Bearer a=b", DisplayName = "credentials that are an auth-param")]
    public async Task UserInfoRefusesABearerCredentialOutsideToken68Async(string authorization)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl,
            [new(WellKnownHttpHeaderNames.Authorization, authorization)],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(
            $"Bearer realm=\"{IssuerOf(host, material)}\", error=\"invalid_request\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.IsEmpty(response.Headers.Headers.GetValues("Access-Control-Expose-Headers"), "A Bearer challenge alone exposes no field.");
        Assert.AreEqual(CredentialsOutsideToken68Body, response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "Upon receipt of a
    /// request to a protected resource within the protection space requiring DPoP authentication, the server can respond
    /// with a challenge to the client to provide DPoP authentication information if the request does not include valid
    /// credentials or does not contain an access token sufficient for access.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_request The
    /// request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same
    /// parameter, uses more than one method for including an access token, or is otherwise malformed." and "If the request
    /// lacks any authentication information (e.g., the client was unaware that authentication is necessary or attempted
    /// using an unsupported authentication method), the resource server SHOULD NOT include an error code or other error
    /// information." At a server whose resources require DPoP-bound access tokens, a UserInfo POST sent over a raw TLS
    /// connection with one <c>Authorization</c> field line whose credentials are <c>abc def</c>, no token68, is answered by
    /// the scheme it names. The rows: the <c>DPoP</c> scheme, a malformed attempt of the one mechanism the resource
    /// accepts, answered 400 with the body
    /// <c>{"error":"invalid_request","error_description":"The Authorization header credentials are not a token68."}</c>
    /// and the one challenge <c>DPoP realm="&lt;issuer&gt;", error="invalid_request", scope="openid", algs="..."</c>; the
    /// <c>Bearer</c> scheme, a method the resource does not accept, answered 401 with an empty body and the one challenge
    /// <c>DPoP realm="&lt;issuer&gt;", scope="openid", algs="..."</c> with no <c>error</c>. Both carry the one field line
    /// <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>.
    /// </summary>
    /// <param name="authorization">The <c>Authorization</c> field line sent.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("DPoP abc def", DisplayName = "the DPoP scheme")]
    [DataRow("Bearer abc def", DisplayName = "the Bearer scheme")]
    public async Task UserInfoRequiringDpopBoundAccessTokensAnswersACredentialOutsideToken68ByItsSchemeAsync(string authorization)
    {
        bool isDpopScheme = authorization.StartsWith("DPoP ", StringComparison.Ordinal);
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        await RequireDpopBoundAccessTokensAtResourcesAsync(host).ConfigureAwait(false);

        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl,
            [new(WellKnownHttpHeaderNames.Authorization, authorization)],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
        Assert.AreEqual(isDpopScheme ? 400 : 401, response.StatusCode, response.Body);
        Assert.AreEqual(
            ResourceDpopProofs.DpopChallenge(IssuerOf(host, material), isDpopScheme ? "invalid_request" : null, scope: "openid"),
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        Assert.AreEqual(isDpopScheme ? CredentialsOutsideToken68Body : string.Empty, response.Body);
    }


    /// <summary>
    /// The body a library resource answers a credential outside token68 with: <c>invalid_request</c> and its one fixed
    /// description.
    /// </summary>
    private static string CredentialsOutsideToken68Body { get; } =
        "{\"error\":\"invalid_request\",\"error_description\":\"The Authorization header credentials are not a token68.\"}";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "If the mechanism used
    /// to attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be used to
    /// deliver error information (Figure 18).", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_request The
    /// request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same
    /// parameter, uses more than one method for including an access token, or is otherwise malformed.  The resource
    /// server SHOULD respond with the HTTP 400 (Bad Request) status code." A UserInfo POST sent over a raw TLS
    /// connection with two <c>Authorization: Bearer</c> field lines (<c>Authorization = credentials</c> is no list,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.2">RFC 9110 Section 11.6.2</see>) attempts the
    /// <c>Bearer</c> mechanism alone: it is refused with 400 <c>invalid_request</c> and the one challenge
    /// <c>Bearer realm="https://userinfo-realm.issuer.test/", error="invalid_request"</c>, no <c>DPoP</c> challenge.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoRefusesTwoBearerAuthorizationLinesWithTheBearerChallengeAloneAsync()
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
            "Bearer realm=\"https://userinfo-realm.issuer.test/\", error=\"invalid_request\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual("invalid_request", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "Upon receipt of a
    /// request to a protected resource within the protection space requiring DPoP authentication, the server can respond
    /// with a challenge to the client to provide DPoP authentication information if the request does not include valid
    /// credentials or does not contain an access token sufficient for access.", so the <c>DPoP</c> challenge is the one
    /// such a space answers with, and <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750
    /// Section 3.1</see>: "invalid_request The request is missing a required parameter, includes an unsupported parameter
    /// or parameter value, repeats the same parameter, uses more than one method for including an access token, or is
    /// otherwise malformed.  The resource server SHOULD respond with the HTTP 400 (Bad Request) status code." At a server
    /// whose resources require DPoP-bound access tokens the <c>DPoP</c> scheme is the one mechanism the resource accepts:
    /// a UserInfo POST sent over a raw TLS connection with two <c>Authorization: Bearer</c> field lines is refused with
    /// 400, <c>invalid_request</c> in the body, the one challenge
    /// <c>DPoP realm="&lt;issuer&gt;", error="invalid_request", scope="openid", algs="..."</c> alone and no <c>Bearer</c>
    /// challenge, and the one field line <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoRequiringDpopBoundAccessTokensAnswersTwoBearerLinesWithTheDpopChallengeAloneAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        await RequireDpopBoundAccessTokensAtResourcesAsync(host).ConfigureAwait(false);

        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl,
            [
                new(WellKnownHttpHeaderNames.Authorization, "Bearer first-access-token"),
                new(WellKnownHttpHeaderNames.Authorization, "Bearer second-access-token")
            ],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The repeated field is answered without a server fault.");
        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(
            UserInfoDpopChallenge(host, material, "invalid_request"),
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual("invalid_request", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "If the mechanism used
    /// to attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be used to
    /// deliver error information (Figure 18).", the scheme compared case-insensitively
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.1">RFC 9110 Section 11.1</see>: "It uses a
    /// case-insensitive token to identify the authentication scheme"). A UserInfo POST sent over a raw TLS connection
    /// with the field lines <c>Authorization: DPoP a</c> and <c>Authorization: dpop b</c> attempts the <c>DPoP</c>
    /// mechanism alone: it is refused with 400, <c>invalid_request</c> in the body, the one challenge
    /// <c>DPoP realm="&lt;issuer&gt;", error="invalid_request", scope="openid", algs="..."</c> and no <c>Bearer</c> one,
    /// and the one field line <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">Section 7.1</see>: "the server needs to make it
    /// available to the application by including WWW-Authenticate in the Access-Control-Expose-Headers response header
    /// list value").
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoAnswersTwoDpopAuthorizationLinesWithTheDpopChallengeAloneAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl,
            [
                new(WellKnownHttpHeaderNames.Authorization, "DPoP a"),
                new(WellKnownHttpHeaderNames.Authorization, "dpop b")
            ],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(
            UserInfoDpopChallenge(host, material, "invalid_request"),
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual("invalid_request", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "Otherwise, both Bearer
    /// and DPoP challenges MAY be used to deliver error information (Figure 19)." A UserInfo POST sent over a raw TLS
    /// connection with an <c>Authorization: Bearer</c> and an <c>Authorization: DPoP</c> field line, Figure 19's request,
    /// establishes no one mechanism: it is refused with 400, <c>invalid_request</c> in the body and one
    /// <c>WWW-Authenticate</c> field holding both challenges, each with the error,
    /// <c>Bearer realm="&lt;issuer&gt;", error="invalid_request", DPoP realm="&lt;issuer&gt;", error="invalid_request",
    /// scope="openid", algs="..."</c>, and the one field line
    /// <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoAnswersAuthorizationLinesOfTwoSchemesWithBothChallengesAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl,
            [
                new(WellKnownHttpHeaderNames.Authorization, "Bearer first-access-token"),
                new(WellKnownHttpHeaderNames.Authorization, "DPoP second-access-token")
            ],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        string issuer = IssuerOf(host, material);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(
            $"Bearer realm=\"{issuer}\", error=\"invalid_request\", {UserInfoDpopChallenge(host, material, "invalid_request")}",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
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

        AssertRefused(response, body, HttpStatusCode.Unauthorized, UserInfoDpopChallenge(host, material, "use_dpop_nonce"), "use_dpop_nonce");
        Assert.IsNotNull(ResourceDpopProofs.ReadNonce(response), "The challenge provides a fresh nonce.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see> item 8: "The
    /// htm claim matches the HTTP method of the current request." and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-9.1">RFC 9110 §9.1</see>: "The method
    /// token is case-sensitive". A proof presented with its DPoP-bound token in a POST to UserInfo over
    /// the wire, correct in every other claim, whose <c>htm</c> names the other method UserInfo answers
    /// (<c>GET</c>) or the request's own method in lower case (<c>post</c>), is refused with 401,
    /// <c>invalid_dpop_proof</c> and the one challenge <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid", algs="..."</c>.
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
    /// the one challenge <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid", algs="..."</c>. The rows: a path below the
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
    /// is refused with 401 and the one challenge <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid", algs="..."</c>.
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
    /// <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid", algs="..."</c>.
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
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "Note: To accommodate
    /// for clock offsets, the server MAY accept DPoP proofs that carry an iat time in the reasonably near future (on the
    /// order of seconds or minutes)." A proof presented with its DPoP-bound token at UserInfo over the wire, correct in
    /// every claim, whose <c>iat</c> lies twenty seconds after the server's clock, inside the thirty seconds the library's
    /// validator accepts (<see cref="WellKnownDpopValues.DefaultIatSkew"/>), is served: 200 with the End-User's
    /// <c>sub</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoServesAProofWhoseIatIsSecondsAheadAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow().AddSeconds(20), TestContext.CancellationToken).ConfigureAwait(false);
        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, presentation.AccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(SubjectId, document.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "servers MAY limit
    /// DPoP proof lifetimes by using server-provided nonce values containing the time at the server rather than comparing
    /// the client-supplied iat time to the time at the server.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">Section 8</see>: "This same error code is used when
    /// supplying a new nonce value when there was a nonce mismatch." A proof presented with its DPoP-bound token at
    /// UserInfo over the wire six minutes after UserInfo provided its nonce, its <c>iat</c> the server's clock then and
    /// every other claim correct, carries a nonce older than the five minutes the library accepts one for
    /// (<see cref="WellKnownDpopValues.DefaultNonceValidityWindow"/>): it is refused with 401, the one challenge
    /// <c>DPoP realm="&lt;issuer&gt;", error="use_dpop_nonce", scope="openid", algs="..."</c>, the description "DPoP
    /// nonce invalid: Expired." and a <c>DPoP-Nonce</c> field supplying a nonce other than the one presented.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoRefusesAProofCarryingANonceOlderThanItsValidityWindowAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        TimeProvider.Advance(TimeSpan.FromMinutes(6));
        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, presentation.AccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, HttpStatusCode.Unauthorized, UserInfoDpopChallenge(host, material, "use_dpop_nonce"), "use_dpop_nonce");
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("DPoP nonce invalid: Expired.", document.RootElement.GetProperty("error_description").GetString(), body);
        Assert.AreNotEqual(presentation.Nonce, ResourceDpopProofs.ReadNonce(response), "UserInfo supplies a fresh nonce.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "a server that is
    /// tracking jti values should reject DPoP proof JWTs with unnecessarily large jti values or store only a hash
    /// thereof". A proof presented with its DPoP-bound token at UserInfo over a raw TLS connection, carrying the nonce
    /// UserInfo provided and correct in every claim but its <c>jti</c>, 1025 printable characters, one more than the
    /// 1024 the library's replay guard stores (<see cref="JtiReplayGuard.MaxJtiLength"/>), is refused with 401, the one
    /// challenge <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid", algs="..."</c>, the one
    /// field line <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>, <c>invalid_dpop_proof</c> in the
    /// body and the description "DPoP proof jti is empty, too long or carries a character the replay guard cannot store.".
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoRefusesAProofWhoseJtiIsLongerThanTheReplayGuardStoresAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string jti = new('j', 1025);
        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken, jti: jti).ConfigureAwait(false);
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, new Uri(presentation.UserInfoUrl),
            [
                new(WellKnownHttpHeaderNames.Authorization, $"DPoP {presentation.AccessToken}"),
                new(WellKnownHttpHeaderNames.DPoP, proof)
            ],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The proof is refused without a server fault.");
        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            UserInfoDpopChallenge(host, material, "invalid_dpop_proof"),
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual("invalid_dpop_proof", document.RootElement.GetProperty("error").GetString(), response.Body);
        Assert.AreEqual(
            "DPoP proof jti is empty, too long or carries a character the replay guard cannot store.",
            document.RootElement.GetProperty("error_description").GetString(), response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see> item 4: "The
    /// typ JOSE Header Parameter has the value dpop+jwt." A proof presented with its DPoP-bound token at
    /// UserInfo over the wire, correct in every other respect, whose <c>typ</c> is <c>JWT</c> is refused
    /// with 401 and the one challenge <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid", algs="..."</c>.
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
    /// <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid", algs="..."</c>.
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
    /// 401 and the one challenge <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid", algs="..."</c>, never a server error.
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
    /// <c>DPoP realm="&lt;issuer&gt;", error="invalid_token", scope="openid", algs="..."</c>, the error of
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
    /// the one challenge <c>DPoP realm="&lt;issuer&gt;", error="use_dpop_nonce", scope="openid", algs="..."</c> and a fresh <c>DPoP-Nonce</c>, never
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

        AssertRefused(replay, body, HttpStatusCode.Unauthorized, UserInfoDpopChallenge(host, material, "invalid_dpop_proof"), "invalid_dpop_proof");
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
            UserInfoDpopChallenge(host, material, "invalid_dpop_proof"), "invalid_dpop_proof");
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
            AssertRefused(refused, body, HttpStatusCode.Unauthorized, UserInfoDpopChallenge(host, material, "invalid_dpop_proof"), "invalid_dpop_proof");
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

        AssertRefused(response, body, HttpStatusCode.Unauthorized, UserInfoDpopChallenge(host, material, "invalid_token"), "invalid_token");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 §7.2</see>: "such a
    /// protected resource MUST reject a DPoP-bound access token received as a bearer token per
    /// [RFC6750]." An access token whose <c>cnf</c> claim binds it by a confirmation method UserInfo does
    /// not check (<c>x5t#S256</c>), presented over the wire under the <c>Bearer</c> scheme, is not served
    /// as a bearer token: it is refused with 401 and <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c>, and no claim of
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

        AssertRefused(response, body, HttpStatusCode.Unauthorized, UserInfoBearerChallenge(host, material, "invalid_token"), "invalid_token");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">RFC 9449 Section 6.1</see>: the <c>jkt</c> value
    /// "MUST be the base64url encoding (as defined in [RFC7515]) of the JWK SHA-256 Thumbprint (according to [RFC7638])
    /// of the DPoP public key (in JWK format) to which the access token is bound.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_token The
    /// access token provided is expired, revoked, malformed, or invalid for other reasons." An access token of the
    /// authorization server whose <c>cnf</c> carries a blank <c>jkt</c> names no key and is malformed. Presented at
    /// UserInfo over the wire it is refused before any proof is judged, with 401, <c>invalid_token</c> and the description
    /// "Access token cnf claim carries a blank jkt." in the body and the challenge of the scheme it was presented under
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "the corresponding
    /// challenge SHOULD be used to deliver error information"), and no claim of the End-User is returned. The rows: under
    /// the <c>Bearer</c> scheme, the one challenge <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c>; under the <c>DPoP</c> scheme with
    /// a proof by a DPoP key of the client's, the one challenge
    /// <c>DPoP realm="&lt;issuer&gt;", error="invalid_token", scope="openid", algs="..."</c>.
    /// </summary>
    /// <param name="scheme">The scheme the token is presented under.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("Bearer")]
    [DataRow("DPoP")]
    public async Task UserInfoRefusesATokenWhoseCnfCarriesABlankJktAsync(string scheme)
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);
        string blankBoundToken = await CompactJwsResigning.ResignWithAlteredPayloadAsync(
            host, accessToken, material.SigningKeyId, payload => payload["cnf"] = new JsonObject { ["jkt"] = string.Empty })
            .ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        string? proof = scheme switch
        {
            "DPoP" => await ResourceDpopProofs.BuildAsync(
                new DpopKey(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256), "POST", userInfoUrl.ToString(),
                blankBoundToken, nonce: null, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false),
            _ => null
        };

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, blankBoundToken, scheme, proof)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The presentation is refused without a server fault.");
        AssertRefused(
            response, body, HttpStatusCode.Unauthorized,
            scheme == "DPoP" ? UserInfoDpopChallenge(host, material, "invalid_token") : UserInfoBearerChallenge(host, material, "invalid_token"),
            "invalid_token");
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("Access token cnf claim carries a blank jkt.", document.RootElement.GetProperty("error_description").GetString(), body);
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
                UserInfoDpopChallenge(host, material, "invalid_token"), "invalid_token"),
            WithoutOpenIdScopeRow => (await CompactJwsResigning.ResignWithAlteredPayloadAsync(host, boundAccessToken, material.SigningKeyId,
                    payload => payload["scope"] = WellKnownScopes.Profile).ConfigureAwait(false),
                HttpStatusCode.Forbidden,
                UserInfoDpopChallenge(host, material, "insufficient_scope"), "insufficient_scope"),
            WithoutSubjectRow => (await CompactJwsResigning.ResignWithAlteredPayloadAsync(host, boundAccessToken, material.SigningKeyId,
                    payload => _ = payload.Remove("sub")).ConfigureAwait(false),
                HttpStatusCode.Unauthorized, UserInfoDpopChallenge(host, material, "invalid_token"), "invalid_token"),
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
    /// challenge <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid", algs="..."</c> and <c>invalid_dpop_proof</c> in the body.
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

        AssertRefusedOverARawConnection(response, UserInfoDpopChallenge(host, material, "invalid_dpop_proof"), "invalid_dpop_proof");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 9: "The htu claim
    /// matches the HTTP URI value for the HTTP request in which the JWT was received, ignoring any query and fragment
    /// parts.", with <see href="https://www.rfc-editor.org/rfc/rfc9110#section-7.1">RFC 9110 Section 7.1</see>: "Upon
    /// receipt of a client's request, a server reconstructs the target URI from the received components in accordance
    /// with their local configuration and incoming connection context." A host whose configuration names its listener's
    /// authority <c>https://as-alias.test</c>, unlike its issuer's, judges a UserInfo proof against that authority: a
    /// DPoP-bound access token presented over the wire with a proof carrying the nonce UserInfo provides under that
    /// configuration (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see>: "nonces
    /// will be only accepted by the server that issued them") whose <c>htu</c> is the UserInfo path at the listener's
    /// authority is served, 200 with the End-User's <c>sub</c>, and one whose <c>htu</c> is UserInfo at the issuer's
    /// authority is refused, 401 with the one challenge <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid", algs="..."</c> and "DPoP
    /// proof validation failed: HtuMismatch." in the body.
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
        string configuredNonce = await ObtainResourceNonceAsync(host, material, presentation.AccessToken).ConfigureAwait(false);
        string htu = isHtuAtTheListenerAuthority switch
        {
            true => new Uri(listenerAuthority, new Uri(presentation.UserInfoUrl).AbsolutePath).OriginalString,
            false => presentation.UserInfoUrl
        };
        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", htu, presentation.AccessToken, configuredNonce,
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

        AssertRefused(response, body, HttpStatusCode.Unauthorized, UserInfoDpopChallenge(host, material, "invalid_dpop_proof"), "invalid_dpop_proof");
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
    /// configured UserInfo URL, and is refused, 401 with the one challenge <c>DPoP realm="&lt;issuer&gt;",
    /// error="invalid_dpop_proof", scope="openid", algs="..."</c>, with a proof whose <c>htu</c> is the UserInfo path at <c>https://attacker.example</c>.
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
        AssertRefusedOverARawConnection(namedHost, UserInfoDpopChallenge(host, material, "invalid_dpop_proof"), "invalid_dpop_proof");
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
    /// <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid", algs="..."</c>; the one sent exactly as it was signed is served, 200 with
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
    /// the one challenge <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid", algs="..."</c>, never served.
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
    /// protection in the manner described in [RFC9110], Section 11.5.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.5">RFC 9110 Section 11.5</see>: "A "protection
    /// space" is defined by the origin (see Section 4.3.1) of the server being accessed, in combination with the realm
    /// value if present." A proof naming another target, presented with its DPoP-bound token at UserInfo over the wire,
    /// is refused with 401 and a <c>DPoP</c> challenge whose auth-params, read from the field as sent, carry the
    /// <c>realm</c> of the protection space UserInfo serves, the issuer the registration is served under.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoDpopChallengeCarriesTheRealmOfItsProtectionSpaceAsync()
    {
        (IReadOnlyDictionary<string, string> parameters, string issuer) = await ReadRefusedDpopChallengeParametersAsync().ConfigureAwait(false);

        Assert.AreEqual("invalid_dpop_proof", parameters["error"]);
        Assert.IsTrue(parameters.TryGetValue("realm", out string? realm), "The DPoP challenge carries the realm parameter.");
        Assert.AreEqual(issuer, realm);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 Section 11.6.1</see>: "A server
    /// generating a 401 (Unauthorized) response MUST send a WWW-Authenticate header field containing at least one
    /// challenge." A UserInfo request sent over a raw TLS connection with no <c>Authorization</c> field, at a server whose
    /// issuer does not resolve, has no protection space realm to name: it is answered 401 with an empty body and the one
    /// challenge <c>Bearer scope="openid", DPoP scope="openid", algs="..."</c>, the <c>DPoP</c> challenge sent without
    /// <c>realm</c> and without <c>resource_metadata</c>. The rows: the registration's issuer replaced by one the default
    /// issuer resolver refuses (<c>http</c> scheme); an application issuer resolver that answers nothing.
    /// </summary>
    /// <param name="row">Which part of the wiring fails: <see cref="IssuerUnresolvableRow"/> or <see cref="IssuerResolverAnswersNothingRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(IssuerUnresolvableRow)]
    [DataRow(IssuerResolverAnswersNothingRow)]
    public async Task UserInfoDpopChallengeOmitsTheRealmWhereNoIssuerResolvesAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        await MakeTheIssuerUnresolvableAsync(host, material, row).ConfigureAwait(false);

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl, [], ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            $"Bearer scope=\"openid\", DPoP scope=\"openid\", algs=\"{ResourceDpopProofs.AcceptedProofAlgorithms}\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(string.Empty, response.Body, "No error code or other error information.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 Section 11.6.1</see>: "A server
    /// generating a 401 (Unauthorized) response MUST send a WWW-Authenticate header field containing at least one
    /// challenge." The <c>realm</c> is a quoted-string, and the library writes the issuer in it in visible US-ASCII, an
    /// internationalized issuer in its URI form as <see href="https://www.rfc-editor.org/rfc/rfc3987#section-3.1">RFC 3987
    /// Section 3.1</see> maps an IRI, its host "converted using the ToASCII operation specified in section 4.1 of
    /// [RFC3490]". An issuer the library cannot write in that form is left out of the challenge, the library's own
    /// reading, as an issuer that does not resolve is: a UserInfo request sent over a raw TLS connection with no
    /// <c>Authorization</c> field, at a server whose application issuer resolver answers such an issuer, is answered with
    /// no captured server fault, 401 with an empty body, the one challenge
    /// <c>Bearer scope="openid", DPoP scope="openid", algs="..."</c>, the <c>DPoP</c> challenge sent without
    /// <c>realm</c>, and the one field line <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>. The rows:
    /// an issuer whose host holds U+200D ZERO WIDTH JOINER, a character the ToASCII operation does not map; a relative
    /// URI, which names no host.
    /// </summary>
    /// <param name="row">Which issuer the resolver answers: <see cref="IssuerHostOutsideIdnaRow"/> or <see cref="IssuerRelativeRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(IssuerHostOutsideIdnaRow)]
    [DataRow(IssuerRelativeRow)]
    public async Task UserInfoDpopChallengeOmitsTheRealmWhereTheIssuerHasNoHeaderFormAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        Uri issuer = row switch
        {
            IssuerHostOutsideIdnaRow => new Uri("https://a\u200Db.example/"),
            IssuerRelativeRow => new Uri("issuer", UriKind.Relative),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown issuer row.")
        };
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            candidateIntegration.ResolveIssuerAsync = (_, _, _) => ValueTask.FromResult<Uri?>(issuer)).ConfigureAwait(false);

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl, [], ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            $"Bearer scope=\"openid\", DPoP scope=\"openid\", algs=\"{ResourceDpopProofs.AcceptedProofAlgorithms}\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        Assert.AreEqual(string.Empty, response.Body, "No error code or other error information.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 Section 11.6.1</see>: "A server MAY
    /// generate a WWW-Authenticate header field in other response messages to indicate that supplying credentials (or
    /// different credentials) might affect the response.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>:
    /// "invalid_request The request is missing a required parameter, includes an unsupported parameter or parameter value,
    /// repeats the same parameter, uses more than one method for including an access token, or is otherwise malformed.
    /// The resource server SHOULD respond with the HTTP 400 (Bad Request) status code.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "If the mechanism used
    /// to attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be used to
    /// deliver error information (Figure 18)." and "Otherwise, both Bearer and DPoP challenges MAY be used to deliver
    /// error information (Figure 19)." A UserInfo POST sent over a raw TLS connection with two <c>Authorization</c> field
    /// lines, at a server whose issuer does not resolve, has no protection space realm to name: it is answered 400 with
    /// <c>invalid_request</c> in the body, no captured server fault, and the challenge of the mechanism the lines attempt
    /// without <c>realm</c>. Two <c>Bearer</c> lines: exactly <c>Bearer error="invalid_request"</c> and no
    /// <c>Access-Control-Expose-Headers</c> field. Two <c>DPoP</c> lines: exactly
    /// <c>DPoP error="invalid_request", scope="openid", algs="..."</c> and one field line
    /// <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>. A <c>Bearer</c> and a <c>DPoP</c> line:
    /// exactly <c>Bearer error="invalid_request", DPoP error="invalid_request", scope="openid", algs="..."</c> and one
    /// such field line. Each under both wirings: the registration's issuer replaced by one the default issuer resolver
    /// refuses (<c>http</c> scheme); an application issuer resolver that answers nothing.
    /// </summary>
    /// <param name="lines">Which <c>Authorization</c> field lines are sent.</param>
    /// <param name="row">Which part of the wiring fails: <see cref="IssuerUnresolvableRow"/> or <see cref="IssuerResolverAnswersNothingRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(TwoBearerLinesRow, IssuerUnresolvableRow)]
    [DataRow(TwoBearerLinesRow, IssuerResolverAnswersNothingRow)]
    [DataRow(TwoDpopLinesRow, IssuerUnresolvableRow)]
    [DataRow(TwoDpopLinesRow, IssuerResolverAnswersNothingRow)]
    [DataRow(BearerAndDpopLinesRow, IssuerUnresolvableRow)]
    [DataRow(BearerAndDpopLinesRow, IssuerResolverAnswersNothingRow)]
    public async Task UserInfoAnswersARepeatedAuthorizationFieldWhereNoIssuerResolvesAsync(string lines, string row)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        await MakeTheIssuerUnresolvableAsync(host, material, row).ConfigureAwait(false);

        string dpopChallenge = $"DPoP error=\"invalid_request\", scope=\"openid\", algs=\"{ResourceDpopProofs.AcceptedProofAlgorithms}\"";
        (IReadOnlyList<KeyValuePair<string, string>> FieldLines, string Challenge, bool IsExposed) expected = lines switch
        {
            TwoBearerLinesRow => (
                [
                    new(WellKnownHttpHeaderNames.Authorization, "Bearer first-access-token"),
                    new(WellKnownHttpHeaderNames.Authorization, "Bearer second-access-token")],
                "Bearer error=\"invalid_request\"",
                false),
            TwoDpopLinesRow => (
                [
                    new(WellKnownHttpHeaderNames.Authorization, "DPoP first-access-token"),
                    new(WellKnownHttpHeaderNames.Authorization, "DPoP second-access-token")],
                dpopChallenge,
                true),
            BearerAndDpopLinesRow => (
                [
                    new(WellKnownHttpHeaderNames.Authorization, "Bearer first-access-token"),
                    new(WellKnownHttpHeaderNames.Authorization, "DPoP second-access-token")],
                $"Bearer error=\"invalid_request\", {dpopChallenge}",
                true),
            _ => throw new ArgumentOutOfRangeException(nameof(lines), lines, "Unknown field line row.")
        };
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl, expected.FieldLines, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The repeated field is answered without a server fault.");
        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(expected.Challenge, Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        IReadOnlyList<string> exposed = response.Headers.Headers.GetValues("Access-Control-Expose-Headers");
        if(expected.IsExposed)
        {
            Assert.AreEqual(ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(exposed));
        }
        else
        {
            Assert.IsEmpty(exposed, "An answer carrying no DPoP challenge carries no exposure field.");
        }

        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual("invalid_request", document.RootElement.GetProperty("error").GetString(), response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_request The
    /// request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same
    /// parameter, uses more than one method for including an access token, or is otherwise malformed. The resource
    /// server SHOULD respond with the HTTP 400 (Bad Request) status code.", for a credential outside the grammar of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">Section 2.1</see> ("credentials = "Bearer" 1*SP
    /// b64token") and of <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>
    /// ("credentials = "DPoP" 1*SP token68"), with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "If the mechanism used
    /// to attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be used to
    /// deliver error information (Figure 18)." A UserInfo POST sent over a raw TLS connection with one
    /// <c>Authorization</c> field line whose credentials are no token68, at a server whose issuer does not resolve, has no
    /// protection space realm to name: it is answered 400 with exactly the body
    /// <c>{"error":"invalid_request","error_description":"The Authorization header credentials are not a token68."}</c>,
    /// no captured server fault, and the challenge of the scheme the line names without <c>realm</c>. The line
    /// <c>Bearer abc def</c>: exactly <c>Bearer error="invalid_request"</c> and no <c>Access-Control-Expose-Headers</c>
    /// field. The line <c>DPoP abc def</c>: exactly <c>DPoP error="invalid_request", scope="openid", algs="..."</c> and
    /// one field line <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>. Each under both wirings: the
    /// registration's issuer replaced by one the default issuer resolver refuses (<c>http</c> scheme); an application
    /// issuer resolver that answers nothing.
    /// </summary>
    /// <param name="line">The <c>Authorization</c> field line.</param>
    /// <param name="row">Which part of the wiring fails: <see cref="IssuerUnresolvableRow"/> or <see cref="IssuerResolverAnswersNothingRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("Bearer abc def", IssuerUnresolvableRow)]
    [DataRow("Bearer abc def", IssuerResolverAnswersNothingRow)]
    [DataRow("DPoP abc def", IssuerUnresolvableRow)]
    [DataRow("DPoP abc def", IssuerResolverAnswersNothingRow)]
    public async Task UserInfoAnswersACredentialOutsideToken68WhereNoIssuerResolvesAsync(string line, string row)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        await MakeTheIssuerUnresolvableAsync(host, material, row).ConfigureAwait(false);
        bool isDpopLine = line.StartsWith("DPoP ", StringComparison.Ordinal);

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl, [new(WellKnownHttpHeaderNames.Authorization, line)],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The credential is answered without a server fault.");
        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(
            isDpopLine
                ? $"DPoP error=\"invalid_request\", scope=\"openid\", algs=\"{ResourceDpopProofs.AcceptedProofAlgorithms}\""
                : "Bearer error=\"invalid_request\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        IReadOnlyList<string> exposed = response.Headers.Headers.GetValues("Access-Control-Expose-Headers");
        if(isDpopLine)
        {
            Assert.AreEqual(ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(exposed));
        }
        else
        {
            Assert.IsEmpty(exposed, "An answer carrying no DPoP challenge carries no exposure field.");
        }

        Assert.AreEqual(
            "{\"error\":\"invalid_request\",\"error_description\":\"The Authorization header credentials are not a token68.\"}", response.Body);
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
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>, of the <c>DPoP</c>
    /// challenge: "A scope authentication parameter MAY be included as defined in [RFC6750], Section 3.", where
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see> reads "The "scope" attribute
    /// is a space-delimited list of case-sensitive scope values indicating the required scope of the access token for
    /// accessing the requested resource." UserInfo requires <c>openid</c> for every request, and every <c>DPoP</c>
    /// challenge it answers over a raw TLS connection names it, in the order <c>realm</c>, <c>error</c>, <c>scope</c>,
    /// <c>algs</c>: a proof naming another target, 401
    /// <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid", algs="..."</c> with the one field line
    /// <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>; a DPoP-bound token with no proof, 401
    /// <c>DPoP realm="&lt;issuer&gt;", error="use_dpop_nonce", scope="openid", algs="..."</c>; a proof signed by a DPoP key
    /// other than the bound one, 401 <c>DPoP realm="&lt;issuer&gt;", error="invalid_token", scope="openid", algs="..."</c>;
    /// and no <c>Authorization</c> field, 401 with an empty body and
    /// <c>Bearer realm="&lt;issuer&gt;", scope="openid", DPoP realm="&lt;issuer&gt;", scope="openid", algs="..."</c>.
    /// </summary>
    /// <param name="row">Which refusal the request meets.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(InvalidProofRow)]
    [DataRow(NonceChallengeRow)]
    [DataRow(ProofByAnotherKeyRow)]
    [DataRow(NoCredentialsRow)]
    public async Task UserInfoDpopChallengeNamesTheRequiredScopeInEveryRefusalAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);

        //A request without credentials needs no token; every other refusal starts from a presented token whose nonce
        //is read without asserting the challenge it arrives with, so the challenge under test is first seen below.
        DpopPresentationContext? presentation = row switch
        {
            NoCredentialsRow => null,
            _ => await PrepareDpopPresentationWithoutTheChallengeLiteralAsync(host, material, fixture).ConfigureAwait(false)
        };
        (IReadOnlyList<KeyValuePair<string, string>> FieldLines, string Challenge) expected = (row, presentation) switch
        {
            (InvalidProofRow, DpopPresentationContext presented) => (
                [
                    new(WellKnownHttpHeaderNames.Authorization, $"DPoP {presented.AccessToken}"),
                    new(WellKnownHttpHeaderNames.DPoP, await ResourceDpopProofs.BuildAsync(
                    presented.DpopKey, "POST", presented.UserInfoUrl + "/other", presented.AccessToken, presented.Nonce,
                    TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false))],
                UserInfoDpopChallenge(host, material, "invalid_dpop_proof")),
            (NonceChallengeRow, DpopPresentationContext presented) => (
                [new(WellKnownHttpHeaderNames.Authorization, $"DPoP {presented.AccessToken}")],
                UserInfoDpopChallenge(host, material, "use_dpop_nonce")),
            (ProofByAnotherKeyRow, DpopPresentationContext presented) => (
                [
                    new(WellKnownHttpHeaderNames.Authorization, $"DPoP {presented.AccessToken}"),
                    new(WellKnownHttpHeaderNames.DPoP, await ResourceDpopProofs.BuildAsync(
                    new DpopKey(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256),
                    "POST", presented.UserInfoUrl, presented.AccessToken, presented.Nonce,
                    TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false))],
                UserInfoDpopChallenge(host, material, "invalid_token")),
            (NoCredentialsRow, _) => ([], MissingCredentialsChallenge(IssuerOf(host, material))),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown refusal row.")
        };
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl, expected.FieldLines,
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(expected.Challenge, Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        if(row == NoCredentialsRow)
        {
            Assert.AreEqual(string.Empty, response.Body, "A request without credentials is answered with no error information.");

            return;
        }

        if(row == InvalidProofRow)
        {
            Assert.AreEqual(
                ResourceDpopProofs.ExposedDpopResponseFields,
                Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        }
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
    /// with 401, an empty body and the challenge <c>Bearer realm="&lt;issuer&gt;", scope="openid", DPoP realm="&lt;issuer&gt;", scope="openid", algs="..."</c> a request without
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
            MissingCredentialsChallenge(IssuerOf(host, material)),
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
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "In order for the
    /// application to obtain and use the WWW-Authenticate HTTP response header value, the server needs to make it available
    /// to the application by including WWW-Authenticate in the Access-Control-Expose-Headers response header list value.",
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">Section 8</see>: "In order for the application to
    /// obtain and use the DPoP-Nonce HTTP response header value, the server needs to make it available to the application
    /// by including DPoP-Nonce in the Access-Control-Expose-Headers response header list value.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">Section 9</see>: "They provide the nonce using the
    /// DPoP-Nonce header in the same way that authorization servers do as described in Sections 8 and 8.2." Every UserInfo
    /// answer carrying a <c>DPoP</c> challenge, received over a raw TLS connection whose request names no <c>Origin</c>,
    /// carries exactly one field line <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>. The rows: the
    /// nonce challenge to a DPoP-bound token with no proof; the <c>invalid_dpop_proof</c> refusal of a proof naming
    /// another target; the challenge to a request with no <c>Authorization</c> field.
    /// </summary>
    /// <param name="row">Which answer is read.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(NonceChallengeRow)]
    [DataRow(InvalidProofRow)]
    [DataRow(NoCredentialsRow)]
    public async Task UserInfoDpopAnswersExposeTheirFieldsToABrowserApplicationAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);
        KeyValuePair<string, string> authorization = new(WellKnownHttpHeaderNames.Authorization, $"DPoP {presentation.AccessToken}");

        IReadOnlyList<KeyValuePair<string, string>> fieldLines = row switch
        {
            NonceChallengeRow => [authorization],
            InvalidProofRow => [authorization, new(WellKnownHttpHeaderNames.DPoP, await ResourceDpopProofs.BuildAsync(
                presentation.DpopKey, "POST", presentation.UserInfoUrl + "/other", presentation.AccessToken, presentation.Nonce,
                TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false))],
            NoCredentialsRow => [],
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown answer row.")
        };
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, new Uri(presentation.UserInfoUrl), fieldLines,
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields,
            Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")),
            "The answer exposes WWW-Authenticate and DPoP-Nonce in one field line.");
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
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see>: "Note that the nonces
    /// provided by an authorization server and a resource server are different and should not be confused with one
    /// another since nonces will be only accepted by the server that issued them. Likewise, should a client use multiple
    /// authorization servers and/or resource servers, a nonce issued by any of them should be used only at the issuing
    /// server." The token endpoint's challenge to a token request whose proof carries no <c>nonce</c> supplies a nonce;
    /// a proof carrying that nonce is presented with its DPoP-bound token at UserInfo over the wire and is refused:
    /// 401, the one challenge <c>DPoP realm="&lt;issuer&gt;", error="use_dpop_nonce", scope="openid", algs="..."</c>, <c>use_dpop_nonce</c> in the body with
    /// the description that names the nonce's audience as another endpoint's, and a <c>DPoP-Nonce</c> field supplying
    /// a nonce other than the one presented.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoRefusesTheTokenEndpointNonceAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        string boundAccessToken = await IssueDpopBoundAccessTokenAsync(host, material, fixture).ConfigureAwait(false);
        string userInfoUrl = (await UserInfoUrlAsync(host, material).ConfigureAwait(false)).ToString();
        string tokenEndpointNonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, material.Registration.TenantId.Value, ClientId, fixture.DpopKey, TimeProvider.GetUtcNow(),
            TestContext.CancellationToken).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            fixture.DpopKey, "POST", userInfoUrl, boundAccessToken, tokenEndpointNonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, boundAccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, HttpStatusCode.Unauthorized, UserInfoDpopChallenge(host, material, "use_dpop_nonce"), "use_dpop_nonce");
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("DPoP nonce invalid: AudienceMismatch.", document.RootElement.GetProperty("error_description").GetString(), body);
        string resourceNonce = ResourceDpopProofs.ReadNonce(response);
        Assert.IsFalse(string.IsNullOrEmpty(resourceNonce), "The refusal supplies a nonce.");
        Assert.AreNotEqual(tokenEndpointNonce, resourceNonce, "UserInfo supplies a nonce of its own.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see>: "Note that the nonces
    /// provided by an authorization server and a resource server are different and should not be confused with one
    /// another since nonces will be only accepted by the server that issued them. Likewise, should a client use multiple
    /// authorization servers and/or resource servers, a nonce issued by any of them should be used only at the issuing
    /// server." and <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">Section 8</see>: "This same error code
    /// is used when supplying a new nonce value when there was a nonce mismatch." UserInfo's challenge to a DPoP-bound
    /// token presented with no proof supplies a nonce; a refresh request carrying the client's refresh token and a
    /// proof by the bound DPoP key carrying that nonce is sent to the token endpoint over the wire and is refused: 400,
    /// <c>use_dpop_nonce</c>, a <c>DPoP-Nonce</c> field supplying a nonce other than the one presented, and no access
    /// token.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task TokenEndpointRefusesTheNonceUserInfoProvidedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
            host.Host("default"), fixture.Client, fixture.Registration, fixture.ClientFlowStore,
            material.Registration.TenantId.Value, RedirectUri, SubjectId, browserClient,
            scope: WellKnownScopes.OpenId, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string boundAccessToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.AccessToken];
        Assert.IsTrue(drive.TokenResult.Body.TryGetValue(OAuthRequestParameterNames.RefreshToken, out object? refreshTokenValue),
            "The code redemption issues a refresh token.");
        string userInfoNonce = await ObtainResourceNonceAsync(host, material, boundAccessToken).ConfigureAwait(false);

        string segment = material.Registration.TenantId.Value;
        string proof = await DpopCodeBindingWire.BuildTokenProofAsync(
            host, segment, fixture.DpopKey, userInfoNonce, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData refresh = await HttpClientTransport.SendFormPostAsync(
            host.Host("default").SharedHttpClient!, RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment),
            RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, (string)refreshTokenValue!),
            OutgoingHeaders.Empty.WithDpop(proof), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, refresh.StatusCode, refresh.Body);
        using JsonDocument document = JsonDocument.Parse(refresh.Body);
        Assert.AreEqual(OAuthErrors.UseDpopNonce, document.RootElement.GetProperty("error").GetString(), refresh.Body);
        Assert.IsFalse(document.RootElement.TryGetProperty(OAuthRequestParameterNames.AccessToken, out _), "The refusal carries no access token.");
        string tokenEndpointNonce = Assert.ContainsSingle(refresh.Headers.Headers.GetValues(WellKnownHttpHeaderNames.DPoPNonce),
            "The refusal supplies one nonce.");
        Assert.AreNotEqual(userInfoNonce, tokenEndpointNonce, "The token endpoint supplies a nonce of its own.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "a resource server MUST
    /// ... check the DPoP proof according to the rules in Section 4.3" and "The resource server MUST NOT grant access to
    /// the resource unless all checks are successful", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>, check 10: "If the server
    /// provided a nonce value to the client, the nonce claim matches the server-provided nonce value." A proof whose
    /// <c>nonce</c> decodes to the octets UserInfo provided, or begins with them, but is not the text it provided,
    /// presented with its DPoP-bound token at UserInfo over the wire, is refused: 401, the one challenge
    /// <c>DPoP realm="&lt;issuer&gt;", error="use_dpop_nonce", scope="openid", algs="..."</c> and a <c>DPoP-Nonce</c> field, the signalling of
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
    /// <c>DPoP realm="&lt;issuer&gt;", error="use_dpop_nonce", scope="openid", algs="..."</c> and a <c>DPoP-Nonce</c> field, the signalling of
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
    /// one challenge <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid", algs="..."</c>.
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
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>: "The JOSE Header of a
    /// DPoP JWT MUST contain at least the following parameters: typ ... alg ... jwk", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">Section 7.1</see>: "invalid_dpop_proof is used to
    /// indicate that the DPoP proof itself was deemed invalid based on the criteria of Section 4.3." A proof presented
    /// with its DPoP-bound token at UserInfo over the wire, signed by the bound DPoP key and carrying the provided nonce,
    /// whose header leaves out one of the three, is refused with 401 and the one challenge
    /// <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid", algs="..."</c>.
    /// </summary>
    /// <param name="missingParameter">The header parameter the proof leaves out.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("typ")]
    [DataRow("alg")]
    [DataRow("jwk")]
    public async Task UserInfoRefusesAProofWhoseHeaderLacksARequiredParameterAsync(string missingParameter)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken,
            alterHeader: header => _ = header.Remove(missingParameter)).ConfigureAwait(false);

        await AssertProofRefusedAsync(presentation, proof, "invalid_dpop_proof").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>, <c>alg</c>: "It MUST
    /// NOT be none or an identifier for a symmetric algorithm (Message Authentication Code (MAC))." A proof presented with
    /// its DPoP-bound token at UserInfo over the wire, carrying the provided nonce, whose header declares <c>HS256</c>
    /// beside the bound DPoP key's <c>jwk</c> and whose signature is an HMAC with SHA-256 over the JWS Signing Input
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.2">RFC 7518 Section 3.2</see>), is refused with 401,
    /// the one challenge <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid", algs="..."</c> and the body's <c>error_description</c>
    /// "DPoP proof validation failed: InvalidAlg.", the refusal of its algorithm.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoRefusesAProofUnderAMacAlgorithmAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken,
            alterHeader: static header => header["alg"] = "HS256", sign: ResourceDpopProofs.SignHmacSha256Async).ConfigureAwait(false);

        await AssertProofRefusedAsync(
            presentation, proof, "invalid_dpop_proof", expectedDescription: "DPoP proof validation failed: InvalidAlg.").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.6">RFC 9449 Section 11.6</see>: "Implementers MUST
    /// ensure that only asymmetric digital signature algorithms (such as ES256) that are deemed secure can be used for
    /// signing DPoP proofs. In particular, the algorithm none MUST NOT be allowed." The rule holds whatever list of
    /// algorithms the host answers: a host whose signing-algorithm resolver answers <c>ES256</c> beside a further
    /// algorithm for DPoP proofs still has UserInfo refuse a proof under an algorithm that is no asymmetric signature, and
    /// its challenge signals only the acceptable one (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">Section
    /// 7.1</see>: "An algs parameter SHOULD be included to signal to the client the JWS algorithms that are acceptable for
    /// the DPoP proof JWT."). A proof carrying the nonce UserInfo provided, presented with its DPoP-bound access token over
    /// a raw TLS connection, is refused with 401, <c>invalid_dpop_proof</c> in the body, the one challenge
    /// <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid", algs="ES256"</c> and
    /// the one field line <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>. The rows: the host answering
    /// <c>["ES256","HS256"]</c>, a header declaring <c>HS256</c> over thirty-two arbitrary signature octets, refused on its
    /// algorithm before any signature is checked, the description "DPoP proof validation failed: InvalidAlg."; the host
    /// answering <c>["ES256","none"]</c>, a header declaring <c>none</c> over thirty-two arbitrary signature octets,
    /// refused on its algorithm, the description "DPoP proof validation failed: InvalidAlg."; the host answering
    /// <c>["ES256","HS256"]</c>, a header declaring <c>none</c> with an empty signature part, the form of an unsecured
    /// JWS, refused by the structural parse of a signed proof before its algorithm is read
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>, check 2: "The DPoP HTTP request
    /// header field value is a single and well-formed JWT."), the description "DPoP proof validation failed:
    /// Malformed.".
    /// </summary>
    /// <param name="row">
    /// The proof: <see cref="MacAlgorithmProofRow"/>, <see cref="NoneAlgorithmSignedProofRow"/> or
    /// <see cref="NoneAlgorithmProofRow"/>.
    /// </param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(MacAlgorithmProofRow)]
    [DataRow(NoneAlgorithmSignedProofRow)]
    [DataRow(NoneAlgorithmProofRow)]
    public async Task UserInfoRefusesAProofUnderNoAsymmetricSignatureAlgorithmTheHostListsAsync(string row)
    {
        (string algorithm, string listedAlgorithm, bool isSignaturePartKept, string expectedDescription) = row switch
        {
            MacAlgorithmProofRow => ("HS256", "HS256", true, "DPoP proof validation failed: InvalidAlg."),
            NoneAlgorithmSignedProofRow => ("none", "none", true, "DPoP proof validation failed: InvalidAlg."),
            NoneAlgorithmProofRow => ("none", "HS256", false, "DPoP proof validation failed: Malformed."),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown proof row.")
        };
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);
        await host.AcceptDpopProofsUnderAsync([WellKnownJwaValues.Es256, listedAlgorithm]).ConfigureAwait(false);

        string signedProof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken, alterHeader: header => header["alg"] = algorithm).ConfigureAwait(false);
        string proof = isSignaturePartKept
            ? ResourceDpopProofs.WithArbitrarySignature(signedProof)
            : ResourceDpopProofs.WithoutSignature(signedProof);
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, new Uri(presentation.UserInfoUrl),
            [
                new(WellKnownHttpHeaderNames.Authorization, $"DPoP {presentation.AccessToken}"),
                new(WellKnownHttpHeaderNames.DPoP, proof)
            ],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The proof is refused without a server fault.");
        AssertRefusedOverARawConnection(
            response,
            $"DPoP realm=\"{IssuerOf(host, material)}\", error=\"invalid_dpop_proof\", scope=\"openid\", algs=\"ES256\"",
            "invalid_dpop_proof");
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual(expectedDescription, document.RootElement.GetProperty("error_description").GetString(), response.Body);
    }


    /// <summary>
    /// The proof row whose header declares the MAC algorithm <c>HS256</c>. A constant, not a property, because a DataRow
    /// attribute argument must be a compile-time constant.
    /// </summary>
    private const string MacAlgorithmProofRow = "mac-algorithm-proof";

    /// <summary>
    /// The proof row whose header declares <c>none</c> over thirty-two arbitrary signature octets at a host listing
    /// <c>none</c>. A constant, not a property, because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string NoneAlgorithmSignedProofRow = "none-algorithm-proof-with-a-signature";

    /// <summary>
    /// The proof row whose header declares <c>none</c> with an empty signature part. A constant, not a property, because a
    /// DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string NoneAlgorithmProofRow = "none-algorithm-proof";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "An algs parameter
    /// SHOULD be included to signal to the client the JWS algorithms that are acceptable for the DPoP proof JWT.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.6">Section 11.6</see>: "In particular, the algorithm
    /// none MUST NOT be allowed." A host whose signing-algorithm resolver answers <c>none</c> alone for DPoP proofs leaves
    /// no algorithm acceptable, so its challenge signals none: an ES256 proof carrying the nonce UserInfo provided,
    /// presented with its DPoP-bound access token over a raw TLS connection, is refused with 401,
    /// <c>invalid_dpop_proof</c> and the description "DPoP proof validation failed: InvalidAlg." in the body, the one
    /// challenge <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid"</c> carrying no <c>algs</c>,
    /// and the one field line <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoChallengeSignalsNoAlgorithmWhereTheHostListsNoneAloneAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);
        await host.AcceptDpopProofsUnderAsync(["none"]).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, new Uri(presentation.UserInfoUrl),
            [
                new(WellKnownHttpHeaderNames.Authorization, $"DPoP {presentation.AccessToken}"),
                new(WellKnownHttpHeaderNames.DPoP, proof)
            ],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The proof is refused without a server fault.");
        AssertRefusedOverARawConnection(
            response,
            $"DPoP realm=\"{IssuerOf(host, material)}\", error=\"invalid_dpop_proof\", scope=\"openid\"",
            "invalid_dpop_proof");
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual("DPoP proof validation failed: InvalidAlg.", document.RootElement.GetProperty("error_description").GetString(), response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "The resource server
    /// MUST NOT grant access to the resource unless all checks are successful.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1">RFC 9110 Section 15.6.1</see>: "The 500
    /// (Internal Server Error) status code indicates that the server encountered an unexpected condition that prevented
    /// it from fulfilling the request." At a server whose replay store records a DPoP proof's <c>jti</c> but cannot
    /// resolve what it recorded, a proof carrying the nonce UserInfo provided, presented with its DPoP-bound access token
    /// over a raw TLS connection, is not served: 500, no <c>WWW-Authenticate</c> field and exactly the body
    /// <c>{"error":"server_error","error_description":"The DPoP proof jti replay defense could not record the proof."}</c>,
    /// which carries no claim.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoAnswersAReplayStoreThatCannotRecordTheProofWithAServerErrorAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);
        await DpopEndToEndTests.HalfWireJtiReplayStoreAsync(host.Server).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, new Uri(presentation.UserInfoUrl),
            [
                new(WellKnownHttpHeaderNames.Authorization, $"DPoP {presentation.AccessToken}"),
                new(WellKnownHttpHeaderNames.DPoP, proof)
            ],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.IsEmpty(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate), "A server error carries no challenge.");
        Assert.AreEqual(
            "{\"error\":\"server_error\",\"error_description\":\"The DPoP proof jti replay defense could not record the proof.\"}",
            response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 5: "The alg JOSE
    /// Header Parameter indicates a registered asymmetric digital signature algorithm [IANA.JOSE.ALGS], is not none, is
    /// supported by the application, and is acceptable per local policy.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">Section 7.1</see>: "An algs parameter SHOULD be
    /// included to signal to the client the JWS algorithms that are acceptable for the DPoP proof JWT." A host whose
    /// signing-algorithm resolver answers <c>["ES384"]</c> for DPoP proofs, after the token was issued, holds UserInfo to
    /// that list: an ES256 proof presented with its DPoP-bound token at UserInfo over the wire, carrying the nonce
    /// UserInfo provided and correct in every other claim, is refused with 401, the one challenge
    /// <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid", algs="ES384"</c> and the description
    /// "DPoP proof validation failed: InvalidAlg.".
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoRefusesAProofOutsideTheAcceptedAlgorithmsAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, static candidateIntegration =>
            candidateIntegration.Cryptography.ResolveSupportedSigningAlgorithmsAsync = static (registration, usage, context, cancellationToken) =>
                usage == KeyUsageContext.DpopProof
                    ? ValueTask.FromResult<IReadOnlyList<string>>([WellKnownJwaValues.Es384])
                    : DefaultSupportedSigningAlgorithms.ResolveAsync(
                        context.RequestServer!.OAuth(), registration, usage, context, cancellationToken)).ConfigureAwait(false);

        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, presentation.AccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, HttpStatusCode.Unauthorized,
            $"DPoP realm=\"{IssuerOf(host, material)}\", error=\"invalid_dpop_proof\", scope=\"openid\", algs=\"ES384\"", "invalid_dpop_proof");
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("DPoP proof validation failed: InvalidAlg.", document.RootElement.GetProperty("error_description").GetString(), body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 5: "The alg JOSE
    /// Header Parameter indicates a registered asymmetric digital signature algorithm [IANA.JOSE.ALGS], is not none, is
    /// supported by the application, and is acceptable per local policy." A host whose signing-algorithm resolver answers
    /// no list at all for DPoP proofs, after the token was issued, leaves UserInfo no local policy to hold a proof's
    /// <c>alg</c> to: a proof presented with its DPoP-bound token at UserInfo over a raw TLS connection, carrying the
    /// nonce UserInfo provided and correct in every claim, is answered 500 with <c>server_error</c> and the description
    /// "The signing-algorithm resolver answered no list for DPoP proofs.", no <c>WWW-Authenticate</c> field and no
    /// <c>Access-Control-Expose-Headers</c> field.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoAnswersAProofWhenTheAlgorithmResolverAnswersNoListAsServerErrorAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);
        await host.AnswerNoDpopProofAlgorithmListAsync().ConfigureAwait(false);

        HttpResponseData response = await SendProofOverRawWireAsync(presentation).ConfigureAwait(false);

        AssertServerErrorOverRawWire(host, response, "The signing-algorithm resolver answered no list for DPoP proofs.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 5: the alg "is
    /// supported by the application, and is acceptable per local policy.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">Section 7.1</see>: "An algs parameter SHOULD be
    /// included to signal to the client the JWS algorithms that are acceptable for the DPoP proof JWT." A host whose
    /// signing-algorithm resolver answers the empty list for DPoP proofs, after the token was issued, accepts no
    /// algorithm: an ES256 proof presented with its DPoP-bound token at UserInfo over a raw TLS connection, carrying the
    /// nonce UserInfo provided and correct in every other claim, is refused with 401, <c>invalid_dpop_proof</c> in the
    /// body, the description "DPoP proof validation failed: InvalidAlg.", the one challenge
    /// <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid"</c> with no <c>algs</c>, since no
    /// algorithm is acceptable, and the one field line <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoRefusesEveryProofUnderAnEmptyAcceptedListAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);
        await host.AcceptDpopProofsUnderAsync([]).ConfigureAwait(false);

        HttpResponseData response = await SendProofOverRawWireAsync(presentation).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The proof is refused without a server fault.");
        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            $"DPoP realm=\"{IssuerOf(host, material)}\", error=\"invalid_dpop_proof\", scope=\"openid\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual("invalid_dpop_proof", document.RootElement.GetProperty("error").GetString(), response.Body);
        Assert.AreEqual("DPoP proof validation failed: InvalidAlg.", document.RootElement.GetProperty("error_description").GetString(), response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "An algs parameter
    /// SHOULD be included to signal to the client the JWS algorithms that are acceptable for the DPoP proof JWT. The value
    /// of the parameter is a space-delimited list of JWS alg (Algorithm) header values", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 Section 11.6.1</see>: "A server
    /// generating a 401 (Unauthorized) response MUST send a WWW-Authenticate header field containing at least one
    /// challenge." A host whose signing-algorithm resolver answers <c>["ES 256"]</c> for DPoP proofs names an algorithm
    /// the space-delimited <c>algs</c> cannot carry: a UserInfo request sent over a raw TLS connection with no
    /// <c>Authorization</c> field is answered 401 with an empty body, the one challenge
    /// <c>Bearer realm="&lt;issuer&gt;", scope="openid", DPoP realm="&lt;issuer&gt;", scope="openid"</c>, the <c>DPoP</c>
    /// challenge sent without <c>algs</c>, and the one field line
    /// <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoAnswersANoCredentialRequestWithoutAlgsWhereTheAlgorithmListIsUnusableAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        await host.AcceptDpopProofsUnderAsync(["ES 256"]).ConfigureAwait(false);

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl, [], ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            $"Bearer realm=\"{IssuerOf(host, material)}\", scope=\"openid\", DPoP realm=\"{IssuerOf(host, material)}\", scope=\"openid\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        Assert.AreEqual(string.Empty, response.Body, "No error code or other error information.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 5: the alg "is
    /// supported by the application, and is acceptable per local policy." A host whose signing-algorithm resolver answers
    /// <c>["ES 256"]</c> for DPoP proofs, after the token was issued, answers a list no challenge can carry, which leaves
    /// UserInfo no usable local policy: a proof presented with its DPoP-bound token at UserInfo over a raw TLS connection,
    /// carrying the nonce UserInfo provided and correct in every claim, is answered 500 with <c>server_error</c> and the
    /// description "The signing-algorithm resolver answered a name for DPoP proofs that a challenge cannot carry.", no
    /// <c>WWW-Authenticate</c> field and no <c>Access-Control-Expose-Headers</c> field.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoAnswersAProofWhereTheAlgorithmListIsUnusableAsServerErrorAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationAsync(host, material, fixture).ConfigureAwait(false);
        await host.AcceptDpopProofsUnderAsync(["ES 256"]).ConfigureAwait(false);

        HttpResponseData response = await SendProofOverRawWireAsync(presentation).ConfigureAwait(false);

        AssertServerErrorOverRawWire(host, response, "The signing-algorithm resolver answered a name for DPoP proofs that a challenge cannot carry.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-5.1">RFC 9728 Section 5.1</see>: "This parameter
    /// MAY also be used in WWW-Authenticate responses using authorization schemes other than "Bearer" [RFC6750],
    /// such as the DPoP scheme defined by [RFC9449]." A registration that does not allow
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/> is served no protected resource
    /// metadata document, so there is no URL to name: a proof naming another target, presented with its DPoP-bound token
    /// at UserInfo over the wire, is refused with 401 and a <c>DPoP</c> challenge whose auth-params carry no
    /// <c>resource_metadata</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoDpopChallengeCarriesNoResourceMetadataParameterAsync()
    {
        (IReadOnlyDictionary<string, string> parameters, _) = await ReadRefusedDpopChallengeParametersAsync().ConfigureAwait(false);

        Assert.AreEqual("invalid_dpop_proof", parameters["error"]);
        Assert.IsFalse(parameters.ContainsKey("resource_metadata"), "The DPoP challenge carries no resource_metadata parameter.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-5.1">RFC 9728 Section 5.1</see>: "This parameter MAY
    /// also be used in WWW-Authenticate responses using authorization schemes other than "Bearer" [RFC6750], such as the
    /// DPoP scheme defined by [RFC9449]." and "The resource_metadata parameter MAY be combined with other parameters
    /// defined in other extensions", with <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section
    /// 7.1</see>: "Additional authentication parameters MAY be used, and unknown parameters MUST be ignored by
    /// recipients." Under a registration allowing
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, a proof naming another target,
    /// presented with its DPoP-bound token at UserInfo over the wire, is refused with 401, exactly the one challenge
    /// <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", scope="openid", algs="...", resource_metadata="&lt;document&gt;"</c>,
    /// the document's URL formed by inserting <c>/.well-known/oauth-protected-resource</c> between the host and the path
    /// of UserInfo's URL, and the one field line <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoDpopChallengeNamesUserInfosResourceMetadataAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, capabilities: DocumentServingCapabilities).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationWithoutTheChallengeLiteralAsync(
            host, material, fixture).ConfigureAwait(false);
        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl + "/other", presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            host, material, presentation.AccessToken, scheme: "DPoP", dpopProof: proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.AreEqual(
            ResourceDpopProofs.DpopChallenge(
                IssuerOf(host, material), "invalid_dpop_proof", scope: "openid",
                resourceMetadata: new Uri(InsertedDocumentUrl(AdvertisedUrlOf(host, material, WellKnownEndpointNames.UserInfo)))),
            Assert.ContainsSingle(RawAuthCodeWirePushers.ChallengesOf(response)));
        Assert.IsTrue(response.Headers.NonValidated.TryGetValues("Access-Control-Expose-Headers", out HeaderStringValues exposed),
            "The refusal exposes its fields to a browser application.");
        Assert.AreEqual(ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(exposed));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3">RFC 9728 Section 3</see>: "Protected resources
    /// supporting metadata MUST make a JSON document containing metadata as specified in Section 2 available at a URL
    /// formed by inserting a well-known URI string into the protected resource's resource identifier between the host
    /// component and the path and/or query components, if any."; <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">Section
    /// 3.2</see>: "A successful response MUST use the 200 OK HTTP status code and return a JSON object using the
    /// application/json content type"; and <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">Section
    /// 3.3</see>: "If the protected resource metadata was retrieved from a URL returned by the protected resource via the
    /// WWW-Authenticate resource_metadata parameter, then the resource value returned MUST be identical to the URL that
    /// the client used to make the request to the resource server." A UserInfo request without credentials sent over a
    /// raw TLS connection, under a registration allowing
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, is answered 401 with exactly the
    /// challenge naming UserInfo's document; a GET of that URL is answered 200 <c>application/json</c> with exactly the
    /// document whose <c>resource</c> is UserInfo's URL, whose <c>authorization_servers</c> is the issuer and whose
    /// <c>dpop_signing_alg_values_supported</c> names exactly the <c>algs</c> of the challenge
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">Section 2</see>: "JSON array containing a list of
    /// the JWS alg values ... supported by the resource server for validating Demonstrating Proof of Possession (DPoP)
    /// proof JWTs"). The rows: the server's resources not requiring DPoP-bound access tokens (the challenge
    /// <c>Bearer realm="&lt;issuer&gt;", scope="openid", resource_metadata="&lt;document&gt;", DPoP realm="&lt;issuer&gt;", scope="openid", algs="...", resource_metadata="&lt;document&gt;"</c>,
    /// the document's <c>bearer_methods_supported</c> <c>["header"]</c>); requiring them (the <c>DPoP</c> challenge
    /// alone, <c>"bearer_methods_supported":[]</c> and <c>"dpop_bound_access_tokens_required":true</c>, Section 2: "Boolean
    /// value specifying whether the protected resource always requires the use of DPoP-bound access tokens"); a host
    /// listing <c>ES256</c> and <c>HS256</c> for DPoP proofs, whose challenge and document both name <c>ES256</c> alone.
    /// </summary>
    /// <param name="row">The server's wiring: <see cref="RequirementUnsetRow"/>, <see cref="RequirementSetRow"/> or <see cref="SymmetricAlgorithmListedRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(RequirementUnsetRow)]
    [DataRow(RequirementSetRow)]
    [DataRow(SymmetricAlgorithmListedRow)]
    public async Task UserInfoProtectedResourceMetadataDocumentNamesUserInfoAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, capabilities: DocumentServingCapabilities).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        bool isRequired = string.Equals(row, RequirementSetRow, StringComparison.Ordinal);
        if(isRequired)
        {
            await RequireDpopBoundAccessTokensAtResourcesAsync(host).ConfigureAwait(false);
        }

        string algorithms = row switch
        {
            SymmetricAlgorithmListedRow => "ES256",
            _ => ResourceDpopProofs.AcceptedProofAlgorithms
        };
        if(string.Equals(row, SymmetricAlgorithmListedRow, StringComparison.Ordinal))
        {
            await host.AcceptDpopProofsUnderAsync(["ES256", "HS256"]).ConfigureAwait(false);
        }

        string issuer = IssuerOf(host, material);
        string identifier = AdvertisedUrlOf(host, material, WellKnownEndpointNames.UserInfo);
        string documentUrl = InsertedDocumentUrl(identifier);
        string dpopChallenge =
            $"DPoP realm=\"{issuer}\", scope=\"openid\", algs=\"{algorithms}\", resource_metadata=\"{documentUrl}\"";
        HttpResponseData challenged = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl, [], ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, challenged.StatusCode, challenged.Body);
        string challenge = Assert.ContainsSingle(challenged.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate));
        Assert.AreEqual(
            isRequired
                ? dpopChallenge
                : $"Bearer realm=\"{issuer}\", scope=\"openid\", resource_metadata=\"{documentUrl}\", {dpopChallenge}",
            challenge);

        HttpResponseData document = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get, new Uri(host.Host("default").HttpBaseAddress!, new Uri(documentUrl).AbsolutePath), [],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The document is served without a server fault.");
        Assert.AreEqual(200, document.StatusCode, document.Body);
        Assert.AreEqual(
            WellKnownMediaTypes.Application.Json,
            Assert.ContainsSingle(document.Headers.Headers.GetValues(WellKnownHttpHeaderNames.ContentType)).Split(';')[0].Trim());
        Assert.AreEqual(ExpectedLibraryResourceDocument(identifier, issuer, JwksUrlOf(host, material), "[\"openid\"]", algorithms, isRequired), document.Body);
        ProtectedResourceMetadata? metadata = ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata(document.Body);
        Assert.IsNotNull(metadata);
        Assert.IsTrue(ProtectedResourceMetadataValidation.IsResourceMatch(metadata, identifier), "The document's resource is the URL requested.");
        Assert.AreSequenceEqual(
            DpopWireReading.ReadChallengeParameters(challenge, "DPoP")["algs"].Split(' '),
            metadata.DpopSigningAlgValuesSupported!.ToArray(),
            "The document names exactly the algorithms the challenge names.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see>: "A "realm" attribute MAY be
    /// included to indicate the scope of protection in the manner described in HTTP/1.1 [RFC2617]. The "realm" attribute
    /// MUST NOT appear more than once." and "Other auth-param attributes MAY be used as well.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-5.1">RFC 9728 Section 5.1</see>'s example
    /// "WWW-Authenticate: Bearer resource_metadata=" and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "insufficient_scope ...
    /// The resource server SHOULD respond with the HTTP 403 (Forbidden) status code and MAY include the "scope" attribute
    /// with the scope necessary to access the protected resource." Under a registration allowing
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, every <c>Bearer</c> challenge UserInfo
    /// answers over the wire carries the realm, the issuer, and the URL of UserInfo's document. The rows: a token whose
    /// signature does not verify, 401 <c>Bearer realm="&lt;issuer&gt;", error="invalid_token", resource_metadata="&lt;document&gt;"</c>;
    /// a token granted <c>profile</c> without <c>openid</c>, 403
    /// <c>Bearer realm="&lt;issuer&gt;", error="insufficient_scope", scope="openid", resource_metadata="&lt;document&gt;"</c>;
    /// no credentials, 401 with an empty body and
    /// <c>Bearer realm="&lt;issuer&gt;", scope="openid", resource_metadata="&lt;document&gt;", DPoP realm="&lt;issuer&gt;", scope="openid", algs="...", resource_metadata="&lt;document&gt;"</c>;
    /// a DPoP-bound token presented under <c>Bearer</c>, 401
    /// <c>Bearer realm="&lt;issuer&gt;", error="invalid_token", resource_metadata="&lt;document&gt;"</c>.
    /// </summary>
    /// <param name="row">The presentation: <see cref="RefusedTokenRow"/>, <see cref="WithoutOpenIdScopeRow"/>, <see cref="NoCredentialsRow"/> or <see cref="DpopBoundTokenRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(RefusedTokenRow)]
    [DataRow(WithoutOpenIdScopeRow)]
    [DataRow(NoCredentialsRow)]
    [DataRow(DpopBoundTokenRow)]
    public async Task UserInfoBearerChallengesCarryTheRealmAndTheResourceMetadataAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        PolicyProfile? profile = row switch
        {
            DpopBoundTokenRow => null,
            _ => PolicyProfile.Rfc6749WithPkce
        };
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile, DocumentServingCapabilities).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);

        IReadOnlyList<KeyValuePair<string, string>> fieldLines = row switch
        {
            RefusedTokenRow => [new(WellKnownHttpHeaderNames.Authorization,
                "Bearer " + TamperSignature(await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false)))],
            WithoutOpenIdScopeRow => [new(WellKnownHttpHeaderNames.Authorization,
                "Bearer " + await IssueAccessTokenAsync(host, material, WellKnownScopes.Profile).ConfigureAwait(false))],
            NoCredentialsRow => [],
            DpopBoundTokenRow => [new(WellKnownHttpHeaderNames.Authorization,
                "Bearer " + await IssueDpopBoundTokenToAFreshClientAsync(host, material).ConfigureAwait(false))],
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown presentation row.")
        };
        string issuer = IssuerOf(host, material);
        string documentUrl = InsertedDocumentUrl(AdvertisedUrlOf(host, material, WellKnownEndpointNames.UserInfo));
        (int status, string challenge) = row switch
        {
            WithoutOpenIdScopeRow => (403,
                $"Bearer realm=\"{issuer}\", error=\"insufficient_scope\", scope=\"openid\", resource_metadata=\"{documentUrl}\""),
            NoCredentialsRow => (401,
                $"Bearer realm=\"{issuer}\", scope=\"openid\", resource_metadata=\"{documentUrl}\", "
                + ResourceDpopProofs.DpopChallenge(issuer, error: null, scope: "openid", resourceMetadata: new Uri(documentUrl))),
            _ => (401, $"Bearer realm=\"{issuer}\", error=\"invalid_token\", resource_metadata=\"{documentUrl}\"")
        };

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl, fieldLines, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
        Assert.AreEqual(status, response.StatusCode, response.Body);
        Assert.AreEqual(challenge, Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        if(string.Equals(row, NoCredentialsRow, StringComparison.Ordinal))
        {
            Assert.AreEqual(string.Empty, response.Body, "No error code or other error information.");
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see>: "If the protected
    /// resource metadata was retrieved from a URL returned by the protected resource via the WWW-Authenticate
    /// resource_metadata parameter, then the resource value returned MUST be identical to the URL that the client used to
    /// make the request to the resource server. If these values are not identical, the data contained in the response
    /// MUST NOT be used." A host whose configuration names its listener's authority <c>https://as-alias.test</c>, unlike
    /// UserInfo's URL, serves requests whose URL is not UserInfo's identifier, so a pointer to UserInfo's document is one
    /// a conforming client discards: under a registration allowing
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, a UserInfo request without credentials
    /// sent over a raw TLS connection is answered 401 with a challenge whose <c>DPoP</c> challenge carries its
    /// <c>realm</c>, the issuer, and no <c>resource_metadata</c>, and no <c>resource_metadata</c> in the field at all.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoChallengeNamesNoResourceMetadataUnderAListenerAliasAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, capabilities: DocumentServingCapabilities).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        host.Host("default").TrustedListenerAuthority = new Uri("https://as-alias.test");

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl, [], ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        string challenge = Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate));
        IReadOnlyDictionary<string, string> parameters = DpopWireReading.ReadChallengeParameters(challenge, "DPoP");
        Assert.AreEqual(IssuerOf(host, material), parameters["realm"], "The DPoP challenge carries the realm.");
        Assert.IsFalse(parameters.ContainsKey("resource_metadata"), "The DPoP challenge carries no resource_metadata parameter.");
        Assert.IsNull(ProtectedResourceChallenge.TryReadResourceMetadata(challenge), "No challenge names a document.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see>: "If the protected
    /// resource metadata was retrieved from a URL returned by the protected resource via the WWW-Authenticate
    /// resource_metadata parameter, then the resource value returned MUST be identical to the URL that the client used to
    /// make the request to the resource server. If these values are not identical, the data contained in the response
    /// MUST NOT be used.", with <see href="https://www.rfc-editor.org/rfc/rfc9728#section-6">Section 6</see>:
    /// "Comparisons between the two strings MUST be performed as a Unicode code-point-to-code-point equality
    /// comparison." The URL a client uses for <c>GET &lt;UserInfo&gt;?x=1</c> carries the query, and UserInfo's
    /// identifier carries none, so a pointer to UserInfo's document is one that client discards: under a registration
    /// allowing <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, that request without
    /// credentials, sent over a raw TLS connection, is answered 401 with a challenge naming no <c>resource_metadata</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoChallengeNamesNoResourceMetadataForARequestCarryingAQueryAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, capabilities: DocumentServingCapabilities).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get, new Uri(userInfoUrl + "?x=1"), [], ReadOnlyMemory<byte>.Empty,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.IsNull(
            ProtectedResourceChallenge.TryReadResourceMetadata(
                Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate))),
            "No challenge names a document.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-1.2">RFC 9728 Section 1.2</see>: "it is recognized that
    /// there are cases that make a query component a useful and necessary part of a resource identifier", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3">Section 3</see>: "available at a URL formed by
    /// inserting a well-known URI string into the protected resource's resource identifier between the host component
    /// and the path and/or query components, if any" and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">Section 3.3</see>: "the resource value returned
    /// MUST be identical to the URL that the client used to make the request to the resource server." A host whose
    /// endpoint resolver answers UserInfo at its URL with the query <c>?tenant=t1</c>, under a registration allowing
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>: a <c>GET</c> of exactly that URL
    /// without credentials, sent over a raw TLS connection, is answered 401 with exactly the challenge
    /// <c>Bearer realm="&lt;issuer&gt;", scope="openid", resource_metadata="&lt;document&gt;", DPoP realm="&lt;issuer&gt;", scope="openid", algs="...", resource_metadata="&lt;document&gt;"</c>,
    /// the document's URL <c>/.well-known/oauth-protected-resource</c> inserted before the path and the query kept after
    /// it; a <c>GET</c> of that URL is answered 200 with the document whose <c>resource</c> is the URL the client used.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoChallengeNamesTheDocumentOfAnIdentifierCarryingAQueryAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, capabilities: DocumentServingCapabilities).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        await AnswerUserInfoWithTheQueryAsync(host, IdentifierQuery).ConfigureAwait(false);
        string issuer = IssuerOf(host, material);
        string identifier = AdvertisedUrlOf(host, material, WellKnownEndpointNames.UserInfo) + IdentifierQuery;
        string documentUrl = InsertedDocumentUrl(identifier) + IdentifierQuery;

        HttpResponseData challenged = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get, new Uri(userInfoUrl + IdentifierQuery), [], ReadOnlyMemory<byte>.Empty,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
        Assert.AreEqual(401, challenged.StatusCode, challenged.Body);
        Assert.AreEqual(
            $"Bearer realm=\"{issuer}\", scope=\"openid\", resource_metadata=\"{documentUrl}\", "
                + ResourceDpopProofs.DpopChallenge(issuer, error: null, scope: "openid", resourceMetadata: new Uri(documentUrl)),
            Assert.ContainsSingle(challenged.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));

        HttpResponseData document = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get, new Uri(host.Host("default").HttpBaseAddress!, new Uri(documentUrl).PathAndQuery), [],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, document.StatusCode, document.Body);
        ProtectedResourceMetadata? metadata = ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata(document.Body);
        Assert.IsNotNull(metadata);
        Assert.IsTrue(ProtectedResourceMetadataValidation.IsResourceMatch(metadata, identifier), "The document's resource is the URL the client used.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see>: "The resource value
    /// returned MUST be identical to the protected resource's resource identifier value into which the well-known URI
    /// path suffix was inserted to create the URL used to retrieve the metadata." and "If the protected resource metadata
    /// was retrieved from a URL returned by the protected resource via the WWW-Authenticate resource_metadata parameter,
    /// then the resource value returned MUST be identical to the URL that the client used to make the request to the
    /// resource server.", with <see href="https://www.rfc-editor.org/rfc/rfc9728#section-6">Section 6</see>: "a Unicode
    /// code-point-to-code-point equality comparison". A host whose endpoint resolver answers UserInfo at its URL with the
    /// query <c>?tenant=t1</c>, under a registration allowing
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>: a UserInfo <c>GET</c> without
    /// credentials whose URL carries another query, or none, sent over a raw TLS connection, is answered 401 with a
    /// challenge naming no <c>resource_metadata</c>, and a <c>GET</c> of the document location with that query in place
    /// of <c>?tenant=t1</c> is answered 404, no document whose <c>resource</c> is a URL other than the one formed into
    /// that location. The rows: the query <c>?tenant=t2</c>; no query.
    /// </summary>
    /// <param name="row">The query the client sends: <see cref="OtherQueryRow"/> or <see cref="NoQueryRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(OtherQueryRow)]
    [DataRow(NoQueryRow)]
    public async Task UserInfoIdentifierCarryingAQueryIsNotNamedOrServedUnderAnotherQueryAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, capabilities: DocumentServingCapabilities).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        await AnswerUserInfoWithTheQueryAsync(host, IdentifierQuery).ConfigureAwait(false);
        string sentQuery = row switch
        {
            OtherQueryRow => "?tenant=t2",
            NoQueryRow => string.Empty,
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown query row.")
        };
        string documentPath = new Uri(InsertedDocumentUrl(AdvertisedUrlOf(host, material, WellKnownEndpointNames.UserInfo))).AbsolutePath;

        HttpResponseData challenged = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get, new Uri(userInfoUrl + sentQuery), [], ReadOnlyMemory<byte>.Empty,
            TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData document = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get, new Uri(host.Host("default").HttpBaseAddress!, documentPath + sentQuery), [],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The requests are answered without a server fault.");
        Assert.AreEqual(401, challenged.StatusCode, challenged.Body);
        Assert.IsNull(
            ProtectedResourceChallenge.TryReadResourceMetadata(
                Assert.ContainsSingle(challenged.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate))),
            "No challenge names a document.");
        Assert.AreEqual(404, document.StatusCode, document.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see>: "the resource value
    /// returned MUST be identical to the URL that the client used to make the request to the resource server. If these
    /// values are not identical, the data contained in the response MUST NOT be used.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-6">Section 6</see>: "Comparisons between the two strings
    /// MUST be performed as a Unicode code-point-to-code-point equality comparison." and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9112#section-3.2.1">RFC 9112 Section 3.2.1</see>: "origin-form =
    /// absolute-path [ "?" query ]". A UserInfo request whose request-target spells the path's <c>u</c> of
    /// <c>userinfo</c> as <c>%75</c> reaches UserInfo, but the URL that client used is not UserInfo's identifier code
    /// point for code point, so a pointer to UserInfo's document is one it discards: under a registration allowing
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, that <c>GET</c> without credentials,
    /// sent over a raw TLS connection, is answered 401 with a challenge naming no <c>resource_metadata</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoChallengeNamesNoResourceMetadataForAPercentEncodedSpellingOfItsPathAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, capabilities: DocumentServingCapabilities).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        string path = userInfoUrl.AbsolutePath;
        int lastSegment = path.LastIndexOf("/userinfo", StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, lastSegment, "UserInfo's path ends in the segment userinfo.");
        string encodedTarget = path[..lastSegment] + "/%75serinfo";

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get, userInfoUrl, [], ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken,
            requestTarget: encodedTarget).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.IsNull(
            ProtectedResourceChallenge.TryReadResourceMetadata(
                Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate))),
            "No challenge names a document.");
    }


    /// <summary>
    /// The query the endpoint resolver of the query rows appends to UserInfo's URL, the identifier's query component.
    /// </summary>
    private static string IdentifierQuery { get; } = "?tenant=t1";

    /// <summary>
    /// The row whose client sends a query other than the identifier's. A constant, not a property, because a DataRow
    /// attribute argument must be a compile-time constant.
    /// </summary>
    private const string OtherQueryRow = "other-query";

    /// <summary>
    /// The row whose client sends no query. A constant, not a property, because a DataRow attribute argument must be a
    /// compile-time constant.
    /// </summary>
    private const string NoQueryRow = "no-query";


    /// <summary>
    /// Wires the host's endpoint resolver to answer UserInfo at the URL it answers today with <paramref name="query"/>
    /// appended, so UserInfo's resource identifier carries that query component.
    /// </summary>
    /// <param name="host">The host whose integration is altered.</param>
    /// <param name="query">The query, its <c>?</c> included.</param>
    /// <returns>A task that completes when the alteration is published.</returns>
    private static Task AnswerUserInfoWithTheQueryAsync(TestHostShell host, string query) =>
        TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            ResolveEndpointUriDelegate resolve = candidateIntegration.ResolveEndpointUriAsync!;
            candidateIntegration.ResolveEndpointUriAsync = async (endpointKey, registration, context, cancellationToken) =>
            {
                Uri? resolved = await resolve(endpointKey, registration, context, cancellationToken).ConfigureAwait(false);

                return (endpointKey, resolved) switch
                {
                    (string key, Uri url) when string.Equals(key, WellKnownEndpointNames.UserInfo, StringComparison.Ordinal) =>
                        new Uri(url.GetLeftPart(UriPartial.Path) + query),
                    _ => resolved
                };
            };
        });


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">RFC 9728 Section 3.2</see>: "An error response
    /// uses the applicable HTTP status code value." UserInfo's document names the issuer as its
    /// <c>authorization_servers</c>; a server whose application issuer resolver answers nothing cannot compose it, a fault
    /// of the server's own wiring: under a registration allowing
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, a GET of UserInfo's document over a
    /// raw TLS connection is answered 500 with exactly the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c>, no captured
    /// server fault and no document.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoProtectedResourceMetadataDocumentWhereNoIssuerResolvesIsAServerErrorAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, capabilities: DocumentServingCapabilities).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        await MakeTheIssuerUnresolvableAsync(host, material, IssuerResolverAnswersNothingRow).ConfigureAwait(false);

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get, new Uri(InsertedDocumentUrl(userInfoUrl.ToString())), [],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.AreEqual(
            /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2.2">RFC 9728 Section 2.2</see>: "In addition to JSON
    /// elements, metadata values MAY also be provided as a signed_metadata value, which is a JSON Web Token (JWT) [JWT]
    /// that asserts metadata values about the protected resource as a bundle." and "A signed_metadata parameter SHOULD NOT
    /// appear as a claim in the JWT". Under a registration allowing
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/> and a signer answering
    /// <c>header.payload.signature</c>, UserInfo's document fetched over a raw TLS connection carries
    /// <c>"signed_metadata":"header.payload.signature"</c>, and the claims handed to the signer carry UserInfo's URL as
    /// <c>resource</c>, the issuer as <c>authorization_servers</c>, <c>openid</c> as <c>scopes_supported</c> and no
    /// <c>signed_metadata</c> claim.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoProtectedResourceMetadataDocumentCarriesTheSignedMetadataAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, capabilities: DocumentServingCapabilities).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        ConcurrentQueue<JwtPayload> signedClaims = new();
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            candidateIntegration.SignProtectedResourceMetadataAsync = (claims, _, _, _) =>
            {
                signedClaims.Enqueue(claims);

                return ValueTask.FromResult<string?>("header.payload.signature");
            }).ConfigureAwait(false);

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get, new Uri(InsertedDocumentUrl(userInfoUrl.ToString())), [],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.Contains("\"signed_metadata\":\"header.payload.signature\"", response.Body, StringComparison.Ordinal, response.Body);
        JwtPayload claims = Assert.ContainsSingle(signedClaims);
        Assert.AreEqual(AdvertisedUrlOf(host, material, WellKnownEndpointNames.UserInfo), claims[ProtectedResourceMetadataParameterNames.Resource]);
        Assert.AreSequenceEqual(
            [IssuerOf(host, material)],
            Assert.IsInstanceOfType<IReadOnlyList<string>>(claims[ProtectedResourceMetadataParameterNames.AuthorizationServers]).ToArray());
        Assert.AreSequenceEqual(
            ["openid"],
            Assert.IsInstanceOfType<IReadOnlyList<string>>(claims[ProtectedResourceMetadataParameterNames.ScopesSupported]).ToArray());
        Assert.IsFalse(claims.ContainsKey(ProtectedResourceMetadataParameterNames.SignedMetadata), "No signed_metadata claim.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>: "resource_name
    /// Human-readable name of the protected resource intended for display to the end user. It is RECOMMENDED that
    /// protected resource metadata include this field." and "resource_documentation OPTIONAL. URL of a page containing
    /// human-readable information that developers might want or need to know when using the protected resource.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2.1">Section 2.1</see>: "a resource could represent its
    /// name in English as "resource_name#en": "My Resource"". Under a registration allowing
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, an application contributing per
    /// resource names UserInfo <c>Example UserInfo</c>, its documentation <c>https://docs.example.com/userinfo</c> and its
    /// Finnish name <c>Esimerkki</c>, and names the issuer's resource <c>Example Signals Transmitter</c> with the scope
    /// <c>ssf.read</c>: UserInfo's document fetched over a raw TLS connection carries exactly
    /// <c>"resource_name":"Example UserInfo"</c>, <c>"resource_documentation":"https://docs.example.com/userinfo"</c> and
    /// <c>"resource_name#fi":"Esimerkki"</c> with its own <c>scopes_supported</c> <c>["openid"]</c>, and the issuer's
    /// document carries its own name and scope, neither document the other's.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoProtectedResourceMetadataDocumentCarriesTheNamesContributedForItAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, capabilities: DocumentServingCapabilities).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, static candidateIntegration =>
            candidateIntegration.ContributeProtectedResourceMetadataAsync = static (_, endpointName, _, _) =>
                ValueTask.FromResult(endpointName switch
                {
                    string name when string.Equals(name, WellKnownEndpointNames.UserInfo, StringComparison.Ordinal) =>
                        new ProtectedResourceMetadataContribution
                        {
                            ResourceName = "Example UserInfo",
                            ResourceDocumentation = "https://docs.example.com/userinfo",
                            LocalizedParameters = new Dictionary<string, string>(StringComparer.Ordinal) { ["resource_name#fi"] = "Esimerkki" }
                        },
                    _ => new ProtectedResourceMetadataContribution
                    {
                        ResourceName = "Example Signals Transmitter",
                        ScopesSupported = [WellKnownScopes.SsfRead]
                    }
                })).ConfigureAwait(false);

        HttpResponseData userInfoDocument = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get, new Uri(InsertedDocumentUrl(userInfoUrl.ToString())), [],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData issuerDocument = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get,
            new Uri(host.Host("default").HttpBaseAddress!,
                TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.ProtectedResourceMetadata, material.Registration.TenantId.Value)),
            [], ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, userInfoDocument.StatusCode, userInfoDocument.Body);
        Assert.Contains("\"scopes_supported\":[\"openid\"]", userInfoDocument.Body, StringComparison.Ordinal, userInfoDocument.Body);
        Assert.Contains("\"resource_name\":\"Example UserInfo\"", userInfoDocument.Body, StringComparison.Ordinal, userInfoDocument.Body);
        Assert.Contains("\"resource_documentation\":\"https://docs.example.com/userinfo\"", userInfoDocument.Body, StringComparison.Ordinal, userInfoDocument.Body);
        Assert.Contains("\"resource_name#fi\":\"Esimerkki\"", userInfoDocument.Body, StringComparison.Ordinal, userInfoDocument.Body);
        Assert.DoesNotContain("Example Signals Transmitter", userInfoDocument.Body, StringComparison.Ordinal, userInfoDocument.Body);
        Assert.AreEqual(200, issuerDocument.StatusCode, issuerDocument.Body);
        Assert.Contains("\"resource_name\":\"Example Signals Transmitter\"", issuerDocument.Body, StringComparison.Ordinal, issuerDocument.Body);
        Assert.Contains($"\"scopes_supported\":[\"{WellKnownScopes.SsfRead}\"]", issuerDocument.Body, StringComparison.Ordinal, issuerDocument.Body);
        Assert.DoesNotContain("Example UserInfo", issuerDocument.Body, StringComparison.Ordinal, issuerDocument.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">RFC 9728 Section 3.2</see>: "An error response uses
    /// the applicable HTTP status code value." UserInfo's document is composed by the library from what it knows; an
    /// application contribution asked for UserInfo that states a member the library composes contradicts the server's own
    /// resource, the server's wiring at fault: under a registration allowing
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, a GET of UserInfo's document over a
    /// raw TLS connection is answered 500 with exactly the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> and no
    /// document. The rows: a contribution naming the member <c>resource</c>; one naming <c>scopes_supported</c>.
    /// </summary>
    /// <param name="row">The contradicting contribution: <see cref="NamesTheResourceRow"/> or <see cref="NamesTheScopesRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(NamesTheResourceRow)]
    [DataRow(NamesTheScopesRow)]
    public async Task UserInfoProtectedResourceMetadataDocumentContributedAComposedMemberIsAServerErrorAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, capabilities: DocumentServingCapabilities).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        ProtectedResourceMetadataContribution contribution = row switch
        {
            NamesTheResourceRow => new ProtectedResourceMetadataContribution
            {
                LocalizedParameters = new Dictionary<string, string>(StringComparer.Ordinal) { ["resource"] = "https://attacker.example.com" }
            },
            NamesTheScopesRow => new ProtectedResourceMetadataContribution { ScopesSupported = [WellKnownScopes.SsfRead] },
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown contribution row.")
        };
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            candidateIntegration.ContributeProtectedResourceMetadataAsync = (_, endpointName, _, _) =>
                ValueTask.FromResult(string.Equals(endpointName, WellKnownEndpointNames.UserInfo, StringComparison.Ordinal)
                    ? contribution
                    : ProtectedResourceMetadataContribution.Empty)).ConfigureAwait(false);

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get, new Uri(InsertedDocumentUrl(userInfoUrl.ToString())), [],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.AreEqual(
            /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            response.Body);
    }


    /// <summary>
    /// The row whose contribution for UserInfo names the member <c>resource</c>. A constant, not a property, because a
    /// DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string NamesTheResourceRow = "names-the-resource";

    /// <summary>
    /// The row whose contribution for UserInfo names <c>scopes_supported</c>. A constant, not a property, because a
    /// DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string NamesTheScopesRow = "names-the-scopes";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2.1">RFC 9728 Section 2.1</see>: "language tags [BCP47]
    /// are added to resource metadata parameter names, delimited by a # character", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc5646#section-2.1">RFC 5646 Section 2.1</see>: "Subtags, in turn, are
    /// a sequence of alphanumeric characters (letters and digits), distinguished and separated from other subtags in a
    /// tag by a hyphen" and "All subtags have a maximum length of eight characters.  Whitespace is not permitted in a
    /// language tag." A
    /// contribution for UserInfo naming a human-readable member under a suffix that is no language tag states a member
    /// the document cannot carry, the server's wiring at fault: under a registration allowing
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, a GET of UserInfo's document over a
    /// raw TLS connection is answered 500 with exactly the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> and no
    /// document. The rows: <c>resource_name#en#x</c>; <c>resource_name#</c> followed by SP.
    /// </summary>
    /// <param name="localizedName">The member name the contribution names.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("resource_name#en#x")]
    [DataRow("resource_name# ")]
    public async Task UserInfoProtectedResourceMetadataDocumentContributedAMalformedLanguageTagIsAServerErrorAsync(string localizedName)
    {
        HttpResponseData response = await FetchUserInfoDocumentWithLocalizedNameAsync(localizedName).ConfigureAwait(false);

        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.AreEqual(
            /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2.1">RFC 9728 Section 2.1</see>: "language tags [BCP47]
    /// are added to resource metadata parameter names, delimited by a # character", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc5646#section-2.1">RFC 5646 Section 2.1</see>'s
    /// "language ["-" script] ["-" region]" form. Under a registration allowing
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, a contribution for UserInfo naming
    /// <c>resource_name#en-US</c> <c>Example UserInfo</c> is written into UserInfo's document fetched over a raw TLS
    /// connection, answered 200 with <c>"resource_name#en-US":"Example UserInfo"</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoProtectedResourceMetadataDocumentCarriesARegionTaggedNameAsync()
    {
        HttpResponseData response = await FetchUserInfoDocumentWithLocalizedNameAsync("resource_name#en-US").ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.Contains("\"resource_name#en-US\":\"Example UserInfo\"", response.Body, StringComparison.Ordinal, response.Body);
    }


    /// <summary>
    /// Registers a client allowing the protected resource metadata capability, wires a contribution naming
    /// <paramref name="localizedName"/> <c>Example UserInfo</c> for UserInfo alone, and fetches UserInfo's document over a
    /// raw TLS connection.
    /// </summary>
    /// <param name="localizedName">The member name the contribution names for UserInfo.</param>
    /// <returns>The wire response.</returns>
    private async Task<HttpResponseData> FetchUserInfoDocumentWithLocalizedNameAsync(string localizedName)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, capabilities: DocumentServingCapabilities).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        ProtectedResourceMetadataContribution contribution = new()
        {
            LocalizedParameters = new Dictionary<string, string>(StringComparer.Ordinal) { [localizedName] = "Example UserInfo" }
        };
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            candidateIntegration.ContributeProtectedResourceMetadataAsync = (_, endpointName, _, _) =>
                ValueTask.FromResult(string.Equals(endpointName, WellKnownEndpointNames.UserInfo, StringComparison.Ordinal)
                    ? contribution
                    : ProtectedResourceMetadataContribution.Empty)).ConfigureAwait(false);

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get, new Uri(InsertedDocumentUrl(userInfoUrl.ToString())), [],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");

        return response;
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-1.2">RFC 9728 Section 1.2</see>: "Resource Identifier:
    /// The protected resource's resource identifier, which is a URL that uses the https scheme and has no fragment
    /// component." A host whose endpoint resolver answers for UserInfo a URL that is no resource identifier names no
    /// resource UserInfo publishes metadata for: under a registration allowing
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, a UserInfo request without credentials
    /// sent over a raw TLS connection is answered 401 with a challenge naming no <c>resource_metadata</c>, and a GET of
    /// <c>/.well-known/oauth-protected-resource</c> inserted before UserInfo's path is not answered 200. The rows: the URL
    /// in the <c>http</c> scheme; the URL with the fragment <c>#part</c>.
    /// </summary>
    /// <param name="row">The URL the resolver answers: <see cref="HttpSchemeIdentifierRow"/> or <see cref="FragmentIdentifierRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(HttpSchemeIdentifierRow)]
    [DataRow(FragmentIdentifierRow)]
    public async Task UserInfoChallengeNamesNoResourceMetadataForAnIdentifierThatIsNotAResourceIdentifierAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, capabilities: DocumentServingCapabilities).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            ResolveEndpointUriDelegate resolve = candidateIntegration.ResolveEndpointUriAsync!;
            candidateIntegration.ResolveEndpointUriAsync = async (endpointKey, registration, context, cancellationToken) =>
            {
                Uri? resolved = await resolve(endpointKey, registration, context, cancellationToken).ConfigureAwait(false);
                bool isUserInfo = string.Equals(endpointKey, WellKnownEndpointNames.UserInfo, StringComparison.Ordinal);

                return (isUserInfo, resolved, row) switch
                {
                    (true, Uri url, HttpSchemeIdentifierRow) => new Uri("http://" + url.Authority + url.AbsolutePath),
                    (true, Uri url, FragmentIdentifierRow) => new Uri(url.ToString() + "#part"),
                    _ => resolved
                };
            };
        }).ConfigureAwait(false);

        HttpResponseData challenged = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl, [], ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData document = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get, new Uri(InsertedDocumentUrl(userInfoUrl.ToString())), [],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, challenged.StatusCode, challenged.Body);
        Assert.IsNull(
            ProtectedResourceChallenge.TryReadResourceMetadata(
                Assert.ContainsSingle(challenged.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate))),
            "No challenge names a document.");
        Assert.AreNotEqual(200, document.StatusCode, document.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 Section 4</see>: "The resource server MUST
    /// validate that the "aud" claim contains a resource indicator value corresponding to an identifier the resource
    /// server expects for itself." UserInfo expects for itself the issuer and its own URL, the identifier its protected
    /// resource metadata document names as <c>resource</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-7.4">RFC 9728 Section 7.4</see>: "the client SHOULD
    /// request audience-restricted access tokens using [RFC8707]"), with
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 Section 2</see>: "The authorization server
    /// SHOULD audience-restrict issued access tokens to the resource(s) indicated by the "resource" parameter." The
    /// authorization-code flow whose pushed authorization request and token request are sent over the wire, the pushed
    /// request naming UserInfo's URL as its <c>resource</c>, issues an access token whose <c>aud</c> is that URL alone;
    /// presented at UserInfo over the wire under the <c>Bearer</c> scheme, it is served 200 with the End-User's
    /// <c>sub</c>. The rows: the issuer the registration is configured with; the issuer <c>https://b</c> U+00FC
    /// <c>cher.example/tenant</c>, UserInfo's URL then requested in its URI form under the host
    /// <c>xn--bcher-kva.example</c> (<see href="https://www.rfc-editor.org/rfc/rfc3987#section-3.1">RFC 3987 Section
    /// 3.1</see>: "converted using the ToASCII operation").
    /// </summary>
    /// <param name="issuerRow">The issuer: <see cref="ConfiguredIssuerRow"/> or <see cref="InternationalizedIssuerRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(ConfiguredIssuerRow)]
    [DataRow(InternationalizedIssuerRow)]
    public async Task UserInfoServesATokenAudiencedAtItsOwnIdentifierAsync(string issuerRow)
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: DocumentServingCapabilities).ConfigureAwait(false);
        _ = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        string identifier = issuerRow switch
        {
            ConfiguredIssuerRow => AdvertisedUrlOf(host, material, WellKnownEndpointNames.UserInfo),
            InternationalizedIssuerRow => "https://xn--bcher-kva.example"
                + TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.UserInfo, material.Registration.TenantId.Value),
            _ => throw new ArgumentOutOfRangeException(nameof(issuerRow), issuerRow, "Unknown issuer row.")
        };

        if(string.Equals(issuerRow, InternationalizedIssuerRow, StringComparison.Ordinal))
        {
            ReplaceRegistrationIssuer(host, material, new Uri("https://b" + (char)0x00FC + "cher.example/tenant"));
        }

        string accessToken = await IssueAccessTokenOverTheWireAsync(host, material, WellKnownScopes.OpenId, identifier).ConfigureAwait(false);
        Assert.AreEqual($"[\"{identifier}\"]", ReadAudienceClaim(accessToken), "The token is audienced at UserInfo's URL alone.");

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, accessToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(SubjectId, document.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 Section 4</see>: "The JWT access token MUST
    /// be rejected if "aud" does not contain a resource indicator of the current resource server as a valid audience."
    /// The Credential Endpoint's URL identifies another resource of this server. An access token issued while the
    /// application's audience resolver grants the Credential Endpoint's URL alone as the audience, presented at UserInfo
    /// over the wire under the <c>Bearer</c> scheme, is refused with 401, <c>invalid_token</c> and the one challenge
    /// <c>Bearer realm="&lt;issuer&gt;", error="invalid_token", resource_metadata="&lt;document&gt;"</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UserInfoRefusesATokenAudiencedAtTheCredentialEndpointsIdentifierAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: DocumentServingCapabilities).ConfigureAwait(false);
        _ = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        string credentialEndpoint = AdvertisedUrlOf(host, material, WellKnownEndpointNames.Oid4VciCredential);
        await GrantTheAudienceAsync(host, credentialEndpoint).ConfigureAwait(false);

        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);
        Assert.AreEqual($"[\"{credentialEndpoint}\"]", ReadAudienceClaim(accessToken), "The token is audienced at the Credential Endpoint's URL alone.");

        using HttpResponseMessage response = await SendUserInfoOverWireAsync(host, material, accessToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(
            response, body, HttpStatusCode.Unauthorized,
            $"Bearer realm=\"{IssuerOf(host, material)}\", error=\"invalid_token\", resource_metadata=\"{InsertedDocumentUrl(AdvertisedUrlOf(host, material, WellKnownEndpointNames.UserInfo))}\"",
            "invalid_token");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-5.2">RFC 9728 Section 5.2</see>: "At any point, for any
    /// reason determined by the resource server, the protected resource MAY respond with a new WWW-Authenticate challenge
    /// that includes a value for the protected resource metadata URL to indicate that its metadata may have changed.",
    /// with <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_request
    /// The request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the
    /// same parameter, uses more than one method for including an access token, or is otherwise malformed." Under a
    /// registration allowing <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, a UserInfo POST
    /// sent over a raw TLS connection with two <c>Authorization</c> field lines is answered 400 with
    /// <c>invalid_request</c> in the body, no captured server fault, and a <c>Bearer</c> challenge carrying the realm and
    /// the URL of UserInfo's document. The rows: two <c>Bearer</c> lines, exactly
    /// <c>Bearer realm="&lt;issuer&gt;", error="invalid_request", resource_metadata="&lt;document&gt;"</c>; a
    /// <c>Bearer</c> and a <c>DPoP</c> line, exactly
    /// <c>Bearer realm="&lt;issuer&gt;", error="invalid_request", resource_metadata="&lt;document&gt;", DPoP realm="&lt;issuer&gt;", error="invalid_request", scope="openid", algs="...", resource_metadata="&lt;document&gt;"</c>.
    /// </summary>
    /// <param name="lines">Which <c>Authorization</c> field lines are sent: <see cref="TwoBearerLinesRow"/> or <see cref="BearerAndDpopLinesRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(TwoBearerLinesRow)]
    [DataRow(BearerAndDpopLinesRow)]
    public async Task UserInfoAnswersARepeatedAuthorizationFieldNamingUserInfosResourceMetadataAsync(string lines)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: DocumentServingCapabilities).ConfigureAwait(false);
        Uri userInfoUrl = await UserInfoUrlAsync(host, material).ConfigureAwait(false);
        string issuer = IssuerOf(host, material);
        string documentUrl = InsertedDocumentUrl(AdvertisedUrlOf(host, material, WellKnownEndpointNames.UserInfo));
        string bearerChallenge = $"Bearer realm=\"{issuer}\", error=\"invalid_request\", resource_metadata=\"{documentUrl}\"";
        (IReadOnlyList<KeyValuePair<string, string>> FieldLines, string Challenge) expected = lines switch
        {
            TwoBearerLinesRow => (
                [
                    new(WellKnownHttpHeaderNames.Authorization, "Bearer first-access-token"),
                    new(WellKnownHttpHeaderNames.Authorization, "Bearer second-access-token")],
                bearerChallenge),
            BearerAndDpopLinesRow => (
                [
                    new(WellKnownHttpHeaderNames.Authorization, "Bearer first-access-token"),
                    new(WellKnownHttpHeaderNames.Authorization, "DPoP second-access-token")],
                $"{bearerChallenge}, "
                    + ResourceDpopProofs.DpopChallenge(issuer, "invalid_request", scope: "openid", resourceMetadata: new Uri(documentUrl))),
            _ => throw new ArgumentOutOfRangeException(nameof(lines), lines, "Unknown field line row.")
        };

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl, expected.FieldLines, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The repeated field is answered without a server fault.");
        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(expected.Challenge, Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual("invalid_request", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// The capabilities of <see cref="DefaultDpopCapabilities"/> and
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, under which UserInfo's protected
    /// resource metadata document is served.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> DocumentServingCapabilities =>
        DefaultDpopCapabilities.Add(WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata);


    /// <summary>
    /// The row whose server's resources do not require DPoP-bound access tokens. A constant, not a property, because a
    /// DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string RequirementUnsetRow = "requirement-unset";

    /// <summary>
    /// The row whose server's resources require DPoP-bound access tokens. A constant, not a property, because a DataRow
    /// attribute argument must be a compile-time constant.
    /// </summary>
    private const string RequirementSetRow = "requirement-set";

    /// <summary>
    /// The row whose host lists <c>ES256</c> and <c>HS256</c> for DPoP proofs. A constant, not a property, because a
    /// DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string SymmetricAlgorithmListedRow = "symmetric-algorithm-listed";

    /// <summary>
    /// The row whose access token's signature does not verify. A constant, not a property, because a DataRow attribute
    /// argument must be a compile-time constant.
    /// </summary>
    private const string RefusedTokenRow = "refused-token";

    /// <summary>
    /// The row whose endpoint resolver answers UserInfo's URL in the <c>http</c> scheme. A constant, not a property,
    /// because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string HttpSchemeIdentifierRow = "http-scheme-identifier";

    /// <summary>
    /// The row whose endpoint resolver answers UserInfo's URL with a fragment. A constant, not a property, because a
    /// DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string FragmentIdentifierRow = "fragment-identifier";

    /// <summary>
    /// The row serving the registration under the issuer it is configured with. A constant, not a property, because a
    /// DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string ConfiguredIssuerRow = "configured-issuer";

    /// <summary>
    /// The row serving the registration under the issuer <c>https://b</c> U+00FC <c>cher.example/tenant</c>. A
    /// constant, not a property, because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string InternationalizedIssuerRow = "internationalized-issuer";


    /// <summary>
    /// The URL a protected resource metadata document is served at for <paramref name="identifier"/>, written out:
    /// <c>/.well-known/oauth-protected-resource</c> inserted between the host and the path
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.1">RFC 9728 Section 3.1</see>: "GET
    /// /.well-known/oauth-protected-resource/resource1 HTTP/1.1").
    /// </summary>
    /// <param name="identifier">The resource identifier, an https URL with a path and no query.</param>
    /// <returns>The document's URL.</returns>
    private static string InsertedDocumentUrl(string identifier)
    {
        Uri resource = new(identifier);

        return $"{resource.GetLeftPart(UriPartial.Authority)}/.well-known/oauth-protected-resource{resource.AbsolutePath}";
    }


    /// <summary>
    /// The URL the host advertises for <paramref name="endpointName"/> of the registration, the endpoint's path under the
    /// authority of the issuer the host holds for the registration, as the host's endpoint resolver composes it: for one
    /// of the server's own resources, its resource identifier.
    /// </summary>
    /// <param name="host">The host holding the registration.</param>
    /// <param name="material">The registration.</param>
    /// <param name="endpointName">The endpoint's name.</param>
    /// <returns>The URL's text.</returns>
    private static string AdvertisedUrlOf(TestHostShell host, VerifierKeyMaterial material, string endpointName) =>
        new Uri(new Uri(IssuerOf(host, material)),
            TestHostShell.ComposeEndpointPath(endpointName, material.Registration.TenantId.Value)).ToString();


    /// <summary>The URL of the registration's JWK Set the host advertises, the documents' <c>jwks_uri</c>.</summary>
    /// <param name="host">The host holding the registration.</param>
    /// <param name="material">The registration.</param>
    /// <returns>The JWK Set URL.</returns>
    private static string JwksUrlOf(TestHostShell host, VerifierKeyMaterial material) =>
        AdvertisedUrlOf(host, material, WellKnownEndpointNames.MetadataJwks);


    /// <summary>
    /// The protected resource metadata document of one of the server's own resources, written out member by member in
    /// the order the document is written: <c>resource</c>, <c>authorization_servers</c>, <c>jwks_uri</c>,
    /// <c>scopes_supported</c> when given, <c>bearer_methods_supported</c> (<c>["header"]</c>, or <c>[]</c> under the
    /// requirement), <c>dpop_signing_alg_values_supported</c>, then <c>dpop_bound_access_tokens_required</c> under the
    /// requirement.
    /// </summary>
    /// <param name="identifier">The resource identifier.</param>
    /// <param name="issuer">The issuer, the one authorization server named.</param>
    /// <param name="jwksUrl">The JWK Set URL.</param>
    /// <param name="scopes">The <c>scopes_supported</c> JSON array, or <see langword="null"/> for none.</param>
    /// <param name="algorithms">The space-delimited algorithm names.</param>
    /// <param name="isRequired">Whether the server's resources require DPoP-bound access tokens.</param>
    /// <returns>The document text.</returns>
    private static string ExpectedLibraryResourceDocument(
        string identifier, string issuer, string jwksUrl, string? scopes, string algorithms, bool isRequired)
    {
        string algorithmArray = "[" + string.Join(",", algorithms.Split(' ').Select(static name => $"\"{name}\"")) + "]";
        string scopesMember = scopes is null ? string.Empty : $",\"scopes_supported\":{scopes}";
        string bearerMethods = isRequired ? "[]" : "[\"header\"]";
        string requirement = isRequired ? ",\"dpop_bound_access_tokens_required\":true" : string.Empty;

        return $"{{\"resource\":\"{identifier}\",\"authorization_servers\":[\"{issuer}\"],\"jwks_uri\":\"{jwksUrl}\"{scopesMember}"
            + $",\"bearer_methods_supported\":{bearerMethods},\"dpop_signing_alg_values_supported\":{algorithmArray}{requirement}}}";
    }


    /// <summary>
    /// Wires the application's audience resolver to grant <paramref name="audience"/> alone as the <c>aud</c> of every
    /// access token the server issues.
    /// </summary>
    /// <param name="host">The host whose integration is altered.</param>
    /// <param name="audience">The audience granted.</param>
    /// <returns>A task that completes when the alteration is published.</returns>
    private static Task GrantTheAudienceAsync(TestHostShell host, string audience) =>
        TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            candidateIntegration.ResolveAccessTokenAudienceAsync = (_, _, _) =>
                ValueTask.FromResult<IReadOnlyList<string>?>([audience]));


    /// <summary>
    /// The capabilities a DPoP registration of these tests is allowed by default, the set
    /// <see cref="TestHostShell.RegisterDpopClientAsync"/> registers when it is given none.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> DefaultDpopCapabilities { get; } = ImmutableHashSet.Create(
        WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
        WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
        WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
        WellKnownCapabilityIdentifiers.OidcUserInfo,
        WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
        WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);


    /// <summary>
    /// Issues a DPoP-bound token over the wire, obtains UserInfo's nonce without asserting the challenge it arrives
    /// with (<see cref="PrepareDpopPresentationWithoutTheChallengeLiteralAsync"/>), presents the token at UserInfo with a
    /// proof naming another target, asserts the 401 refusal, and reads the auth-params of the <c>DPoP</c> challenge of
    /// its one <c>WWW-Authenticate</c> field.
    /// </summary>
    /// <param name="capabilities">The registration's capabilities, or <see langword="null"/> for the default set.</param>
    /// <returns>The <c>DPoP</c> challenge's auth-params and the issuer the registration is served under.</returns>
    private async Task<(IReadOnlyDictionary<string, string> Parameters, string Issuer)> ReadRefusedDpopChallengeParametersAsync(
        ImmutableHashSet<CapabilityIdentifier>? capabilities = null)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, capabilities: capabilities).ConfigureAwait(false);
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);
        DpopPresentationContext presentation = await PrepareDpopPresentationWithoutTheChallengeLiteralAsync(
            host, material, fixture).ConfigureAwait(false);

        (HttpStatusCode status, string challenge, string body) = await PresentProofNamingAnotherTargetAsync(presentation).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, status, body);

        return (DpopWireReading.ReadChallengeParameters(challenge, "DPoP"), IssuerOf(host, material));
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
    /// <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c>, never a server error.
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

        AssertRefused(response, body, HttpStatusCode.Unauthorized, UserInfoBearerChallenge(host, material, "invalid_token"), "invalid_token");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>:
    /// "invalid_token The access token provided is expired, revoked, malformed, or invalid for other
    /// reasons. The resource SHOULD respond with the HTTP 401 (Unauthorized) status code." An access
    /// token signed under the registration's access-token key whose <c>exp</c> is
    /// 9223372036854775807, a NumericDate no instant is represented for, is malformed: it is refused at
    /// UserInfo over the wire with 401 <c>invalid_token</c> and <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c>,
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

        AssertRefused(response, body, HttpStatusCode.Unauthorized, UserInfoBearerChallenge(host, material, "invalid_token"), "invalid_token");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.12">RFC 8725 §3.12</see>: "Use
    /// different keys for different kinds of JWTs. Then the keys used to validate one kind of JWT will
    /// fail to validate other kinds of JWTs." A registration whose access tokens and ID Tokens are
    /// issued under two distinct keys: an access token re-signed under the registration's own ID Token
    /// key, presented at UserInfo over the wire, is refused with 401 <c>invalid_token</c> and
    /// <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c>, and no claim of the End-User is returned.
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

        AssertRefused(response, body, HttpStatusCode.Unauthorized, UserInfoBearerChallenge(host, material, "invalid_token"), "invalid_token");
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
    /// <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c> and the fixed description "No verification key is available
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

        AssertRefused(response, body, HttpStatusCode.Unauthorized, UserInfoBearerChallenge(host, material, "invalid_token"), "invalid_token");
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
    /// <c>invalid_token</c> and the one challenge <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c>.
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

        AssertRefused(response, body, HttpStatusCode.Unauthorized, UserInfoBearerChallenge(host, material, "invalid_token"), "invalid_token");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 Section 4</see>: "The JWT access
    /// token MUST be rejected if "aud" does not contain a resource indicator of the current resource server as a
    /// valid audience." and "Please note that this requirement does not prevent JWT access tokens from using
    /// authentication schemes other than "Bearer"." A DPoP-bound access token whose <c>aud</c> names another
    /// resource alone, signed under the registration's access-token key and presented at UserInfo over the wire
    /// under the <c>DPoP</c> scheme with a proof from the bound key carrying the nonce UserInfo provided, is
    /// refused with 401, <c>invalid_token</c> and the one challenge <c>DPoP realm="&lt;issuer&gt;", error="invalid_token", scope="openid", algs="..."</c>.
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

        AssertRefused(response, body, HttpStatusCode.Unauthorized, UserInfoDpopChallenge(host, material, "invalid_token"), "invalid_token");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2">RFC 9068 Section 2.2</see>: "aud  REQUIRED -
    /// as defined in Section 4.1.3 of [RFC7519]." and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">Section 4</see>: "The JWT access token MUST be
    /// rejected if "aud" does not contain a resource indicator of the current resource server as a valid
    /// audience." An access token signed under the registration's access-token key whose claims carry no
    /// <c>aud</c> contains no audience at all; presented at UserInfo over the wire under the <c>Bearer</c>
    /// scheme, it is refused with 401, <c>invalid_token</c> and the one challenge <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c>.
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

        AssertRefused(response, body, HttpStatusCode.Unauthorized, UserInfoBearerChallenge(host, material, "invalid_token"), "invalid_token");
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
    /// <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c> and the description "Access token has expired.".
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

        AssertRefused(response, body, HttpStatusCode.Unauthorized, UserInfoBearerChallenge(host, material, "invalid_token"), "invalid_token");
        using JsonDocument refused = JsonDocument.Parse(body);
        Assert.AreEqual("Access token has expired.", refused.RootElement.GetProperty("error_description").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_token The
    /// access token provided is expired, revoked, malformed, or invalid for other reasons." A malformed access token
    /// presented at UserInfo over the wire under the <c>Bearer</c> scheme is refused with 401, <c>invalid_token</c>
    /// and the one challenge <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c>, and its description is a fixed text that carries
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

        AssertRefused(response, body, HttpStatusCode.Unauthorized, UserInfoBearerChallenge(host, material, "invalid_token"), "invalid_token");
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

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
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
    /// <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c> and exactly the description "Access token signature verification
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
            AssertRefused(response, body, HttpStatusCode.Unauthorized, UserInfoBearerChallenge(host, material, "invalid_token"), "invalid_token");
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

    /// <summary>The issuer row whose host holds a character the IDNA ToASCII operation does not map.</summary>
    private const string IssuerHostOutsideIdnaRow = "issuer-host-outside-idna";

    /// <summary>The issuer row naming a relative URI.</summary>
    private const string IssuerRelativeRow = "issuer-relative";


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
    /// Leaves the server with no issuer it resolves for <paramref name="material"/>'s registration: for
    /// <see cref="IssuerResolverAnswersNothingRow"/> an application issuer resolver that answers nothing, for
    /// <see cref="IssuerUnresolvableRow"/> the registration's issuer replaced by one the default issuer resolver refuses
    /// (<c>http</c> scheme).
    /// </summary>
    /// <param name="host">The host holding the registration.</param>
    /// <param name="material">The registration.</param>
    /// <param name="row">Which part of the wiring fails.</param>
    /// <returns>A task that completes when the wiring is altered.</returns>
    private static async Task MakeTheIssuerUnresolvableAsync(TestHostShell host, VerifierKeyMaterial material, string row)
    {
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

            return;
        }

        ReplaceRegistrationIssuer(host, material, new Uri("http://issuer.test/" + material.Registration.TenantId.Value));
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

    /// <summary>The refusal row whose proof names another target.</summary>
    private const string InvalidProofRow = "invalid-proof";

    /// <summary>The refusal row whose DPoP-bound token is presented with no proof.</summary>
    private const string NonceChallengeRow = "nonce-challenge";

    /// <summary>The refusal row whose proof is signed by a DPoP key other than the bound one.</summary>
    private const string ProofByAnotherKeyRow = "proof-by-another-key";

    /// <summary>The refusal row whose request carries no <c>Authorization</c> field.</summary>
    private const string NoCredentialsRow = "no-credentials";

    /// <summary>The field line row sending two <c>Authorization: Bearer</c> lines.</summary>
    private const string TwoBearerLinesRow = "two-bearer-lines";

    /// <summary>The field line row sending two <c>Authorization: DPoP</c> lines.</summary>
    private const string TwoDpopLinesRow = "two-dpop-lines";

    /// <summary>The field line row sending an <c>Authorization: Bearer</c> and an <c>Authorization: DPoP</c> line.</summary>
    private const string BearerAndDpopLinesRow = "bearer-and-dpop-lines";

    /// <summary>The DPoP-scheme refusal row whose token signature does not verify.</summary>
    private const string TamperedSignatureRow = "tampered-signature";

    /// <summary>The DPoP-scheme refusal row whose token's <c>scope</c> names <c>profile</c> but not <c>openid</c>.</summary>
    private const string WithoutOpenIdScopeRow = "without-openid-scope";

    /// <summary>The DPoP-scheme refusal row whose token carries no <c>sub</c>.</summary>
    private const string WithoutSubjectRow = "without-subject";

    /// <summary>
    /// The <c>Bearer</c> presentation row of an access token bound to no key. A constant, not a property, because a
    /// DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string UnboundTokenRow = "unbound-token";

    /// <summary>
    /// The <c>Bearer</c> presentation row of an access token bound to the client's DPoP key by its <c>cnf.jkt</c>. A
    /// constant, not a property, because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string DpopBoundTokenRow = "dpop-bound-token";

    /// <summary>
    /// The <c>Bearer</c> presentation row whose credentials are the value <c>x</c>, which is no access token. A constant,
    /// not a property, because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string NonTokenValueRow = "non-token-value";


    /// <summary>
    /// Sets <see cref="AuthorizationServerIntegration.IsDpopBoundAccessTokenRequiredAtResources"/> on the host, so UserInfo
    /// and the OID4VCI resources are a protection space requiring DPoP authentication. DPoP must be enabled first.
    /// </summary>
    /// <param name="host">The host whose integration is altered.</param>
    /// <returns>A task that completes when the alteration is published.</returns>
    private static Task RequireDpopBoundAccessTokensAtResourcesAsync(TestHostShell host) =>
        TestHostShell.AlterAsync(host.Server, static candidateIntegration =>
            candidateIntegration.IsDpopBoundAccessTokenRequiredAtResources = true);


    /// <summary>
    /// Arranges the value a <c>Bearer</c> presentation row sends and enables DPoP on the host: an unbound access token
    /// issued before DPoP is enabled, a DPoP-bound access token issued to a DPoP-wired client, or the value <c>x</c>.
    /// </summary>
    /// <param name="host">The host whose registration and listener serve the flow.</param>
    /// <param name="material">The registration the token is issued under.</param>
    /// <param name="row">The row: <see cref="UnboundTokenRow"/>, <see cref="DpopBoundTokenRow"/> or <see cref="NonTokenValueRow"/>.</param>
    /// <returns>The credentials the row presents under the <c>Bearer</c> scheme.</returns>
    private Task<string> ArrangeBearerPresentationAsync(TestHostShell host, VerifierKeyMaterial material, string row) => row switch
    {
        UnboundTokenRow => IssueUnboundTokenThenEnableDpopAsync(host, material),
        DpopBoundTokenRow => IssueDpopBoundTokenToAFreshClientAsync(host, material),
        NonTokenValueRow => EnableDpopAndAnswerAValueAsync(host, "x"),
        _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown presentation row.")
    };


    /// <summary>
    /// Seeds the End-User, issues an access token bound to no key through the authorization code flow, then enables DPoP
    /// on the host.
    /// </summary>
    /// <param name="host">The host.</param>
    /// <param name="material">The registration the token is issued under.</param>
    /// <returns>The unbound access token.</returns>
    private async Task<string> IssueUnboundTokenThenEnableDpopAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        _ = host.SeedTestSubject(subject: SubjectId);
        string accessToken = await IssueAccessTokenAsync(host, material, WellKnownScopes.OpenId).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        return accessToken;
    }


    /// <summary>Enables DPoP on the host and issues a DPoP-wired client a DPoP-bound access token over the wire.</summary>
    /// <param name="host">The host.</param>
    /// <param name="material">The registration the token is issued under.</param>
    /// <returns>The DPoP-bound access token.</returns>
    private async Task<string> IssueDpopBoundTokenToAFreshClientAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        using DpopClientFixture fixture = await CreateDpopFixtureAsync(host, material).ConfigureAwait(false);

        return await IssueDpopBoundAccessTokenAsync(host, material, fixture).ConfigureAwait(false);
    }


    /// <summary>Enables DPoP on the host and answers <paramref name="value"/>.</summary>
    /// <param name="host">The host.</param>
    /// <param name="value">The value answered.</param>
    /// <returns>The value.</returns>
    private static async Task<string> EnableDpopAndAnswerAValueAsync(TestHostShell host, string value)
    {
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        return value;
    }


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
    /// <c>DPoP realm="&lt;issuer&gt;", error="<paramref name="error"/>", scope="openid", algs="..."</c>, the error in the body, no subject, and,
    /// when <paramref name="isDpopNonceExpected"/>, a <c>DPoP-Nonce</c> header.
    /// </summary>
    /// <param name="presentation">The presentation state.</param>
    /// <param name="proof">The DPoP proof sent.</param>
    /// <param name="error">The expected error.</param>
    /// <param name="isDpopNonceExpected">Whether the refusal is answered with a <c>DPoP-Nonce</c> field.</param>
    /// <param name="expectedDescription">The <c>error_description</c> the body carries, or <see langword="null"/> when the row does not read it.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertProofRefusedAsync(
        DpopPresentationContext presentation, string proof, string error, bool isDpopNonceExpected = false, string? expectedDescription = null)
    {
        using HttpResponseMessage response = await SendUserInfoOverWireAsync(
            presentation.Host, presentation.Material, presentation.AccessToken, scheme: "DPoP", dpopProof: proof)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefused(response, body, HttpStatusCode.Unauthorized, UserInfoDpopChallenge(presentation.Host, presentation.Material, error), error);
        if(expectedDescription is not null)
        {
            using JsonDocument document = JsonDocument.Parse(body);
            Assert.AreEqual(expectedDescription, document.RootElement.GetProperty("error_description").GetString(), body);
        }

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
        AssertRefused(challenge, body, HttpStatusCode.Unauthorized, UserInfoDpopChallenge(host, material, "use_dpop_nonce"), "use_dpop_nonce");

        return ResourceDpopProofs.ReadNonce(challenge);
    }


    /// <summary>
    /// Issues the DPoP-wired client a DPoP-bound access token over the wire and obtains the nonce UserInfo provides for
    /// it through <see cref="ObtainResourceNonceWithoutTheChallengeLiteralAsync"/>, which reads the nonce without
    /// asserting the challenge it arrives with. A row that asserts one parameter of a later challenge, its
    /// <c>realm</c>, its <c>scope</c> or the absence of <c>resource_metadata</c>, starts here, so a server writing that
    /// parameter otherwise is first seen at the row's own assertion.
    /// </summary>
    /// <param name="host">The host whose registration and listener serve the flow.</param>
    /// <param name="material">The registration the token is issued under.</param>
    /// <param name="fixture">The DPoP-wired client.</param>
    /// <returns>The presentation state.</returns>
    private async Task<DpopPresentationContext> PrepareDpopPresentationWithoutTheChallengeLiteralAsync(
        TestHostShell host, VerifierKeyMaterial material, DpopClientFixture fixture)
    {
        string boundAccessToken = await IssueDpopBoundAccessTokenAsync(host, material, fixture).ConfigureAwait(false);
        string url = (await UserInfoUrlAsync(host, material).ConfigureAwait(false)).ToString();
        string nonce = await ObtainResourceNonceWithoutTheChallengeLiteralAsync(host, material, boundAccessToken).ConfigureAwait(false);

        return new DpopPresentationContext(host, material, fixture, boundAccessToken, url, nonce);
    }


    /// <summary>
    /// Presents <paramref name="accessToken"/> at UserInfo over the wire under the <c>DPoP</c> scheme with no proof,
    /// asserts the 401 it is answered with, and returns the nonce its <c>DPoP-Nonce</c> field provides, asserting
    /// nothing of its <c>WWW-Authenticate</c> field.
    /// </summary>
    /// <param name="host">The host whose listener serves the request.</param>
    /// <param name="material">The registration whose UserInfo path is addressed.</param>
    /// <param name="accessToken">The DPoP-bound access token presented.</param>
    /// <returns>The nonce UserInfo provided.</returns>
    private async Task<string> ObtainResourceNonceWithoutTheChallengeLiteralAsync(TestHostShell host, VerifierKeyMaterial material, string accessToken)
    {
        using HttpResponseMessage challenge = await SendUserInfoOverWireAsync(host, material, accessToken, scheme: "DPoP")
            .ConfigureAwait(false);
        string body = await challenge.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, challenge.StatusCode, body);

        return ResourceDpopProofs.ReadNonce(challenge);
    }


    /// <summary>
    /// The <c>DPoP</c> challenge UserInfo answers a refused DPoP presentation with, written out:
    /// <c>DPoP realm="&lt;issuer&gt;", error="&lt;error&gt;", scope="openid", algs="..."</c>, the realm the issuer the
    /// host serves the registration under and the scope the one UserInfo requires.
    /// </summary>
    /// <param name="host">The host holding the registration.</param>
    /// <param name="material">The registration.</param>
    /// <param name="error">The challenge's <c>error</c>.</param>
    /// <returns>The <c>WWW-Authenticate</c> value.</returns>
    private static string UserInfoDpopChallenge(TestHostShell host, VerifierKeyMaterial material, string error) =>
        ResourceDpopProofs.DpopChallenge(IssuerOf(host, material), error, scope: "openid");


    /// <summary>
    /// Asserts that an in-process UserInfo refusal of a request without usable credentials carries the
    /// one <c>WWW-Authenticate</c> value <c>Bearer realm="&lt;issuer&gt;", scope="openid", DPoP realm="&lt;issuer&gt;", scope="openid", algs="..."</c>
    /// (RFC 6750 Section 3 and Section 3.1, RFC 9449 Section 7.1 and Section 7.2).
    /// </summary>
    /// <param name="response">The dispatched response.</param>
    /// <param name="issuer">The issuer the registration is served under, the <c>DPoP</c> challenge's realm.</param>
    private static void AssertMissingCredentialsChallenge(ServerHttpResponse response, string issuer)
    {
        Assert.IsTrue(response.Headers.TryGetValue("WWW-Authenticate", out string? challenge),
            "RFC 6750 §3: the refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual(MissingCredentialsChallenge(issuer), challenge);
    }


    /// <summary>
    /// The challenge UserInfo answers a request without usable credentials with, written out:
    /// <c>Bearer realm="&lt;issuer&gt;", scope="openid", DPoP realm="&lt;issuer&gt;", scope="openid", algs="..."</c>, the realm of
    /// both challenges the issuer.
    /// </summary>
    /// <param name="issuer">The issuer the registration is served under, the realm of both challenges.</param>
    /// <returns>The <c>WWW-Authenticate</c> value.</returns>
    private static string MissingCredentialsChallenge(string issuer) =>
        $"Bearer realm=\"{issuer}\", scope=\"openid\", {ResourceDpopProofs.DpopChallenge(issuer, error: null, scope: "openid")}";


    /// <summary>
    /// The <c>Bearer</c> challenge UserInfo answers a refused <c>Bearer</c> presentation with, written out:
    /// <c>Bearer realm="&lt;issuer&gt;", error="&lt;error&gt;"</c>, followed by <c>, scope="&lt;scope&gt;"</c> when a scope is
    /// named, the realm the issuer the host serves the registration under, as the <c>DPoP</c> challenge carries it
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see>: "A "realm" attribute MAY
    /// be included to indicate the scope of protection in the manner described in HTTP/1.1 [RFC2617].").
    /// </summary>
    /// <param name="host">The host holding the registration.</param>
    /// <param name="material">The registration.</param>
    /// <param name="error">The challenge's <c>error</c>.</param>
    /// <param name="scope">The challenge's <c>scope</c>, or <see langword="null"/> for none.</param>
    /// <returns>The <c>WWW-Authenticate</c> value.</returns>
    private static string UserInfoBearerChallenge(TestHostShell host, VerifierKeyMaterial material, string error, string? scope = null) =>
        scope is null
            ? $"Bearer realm=\"{IssuerOf(host, material)}\", error=\"{error}\""
            : $"Bearer realm=\"{IssuerOf(host, material)}\", error=\"{error}\", scope=\"{scope}\"";


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
    /// Presents a proof correct in every claim, carrying the nonce UserInfo provided, with the presentation's token under
    /// the <c>DPoP</c> scheme at UserInfo over a raw TLS connection, so the answer's field lines are read as received.
    /// </summary>
    /// <param name="presentation">The presentation state.</param>
    /// <returns>The answer as received.</returns>
    private async Task<HttpResponseData> SendProofOverRawWireAsync(DpopPresentationContext presentation)
    {
        string proof = await ResourceDpopProofs.BuildAsync(
            presentation.DpopKey, "POST", presentation.UserInfoUrl, presentation.AccessToken, presentation.Nonce,
            TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        return await RawHttpsRequest.SendAsync(
            presentation.Host, WellKnownHttpMethods.Post, new Uri(presentation.UserInfoUrl),
            [
                new(WellKnownHttpHeaderNames.Authorization, $"DPoP {presentation.AccessToken}"),
                new(WellKnownHttpHeaderNames.DPoP, proof)
            ],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Asserts a UserInfo server-side failure received over a raw TLS connection: no captured server fault, 500, no
    /// <c>WWW-Authenticate</c> field, no <c>Access-Control-Expose-Headers</c> field, and a JSON error body whose
    /// <c>error</c> is <c>server_error</c> and whose <c>error_description</c> is <paramref name="expectedDescription"/>.
    /// </summary>
    /// <param name="host">The host whose listener answered.</param>
    /// <param name="response">The answer as received.</param>
    /// <param name="expectedDescription">The expected <c>error_description</c>.</param>
    private static void AssertServerErrorOverRawWire(TestHostShell host, HttpResponseData response, string expectedDescription)
    {
        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.IsEmpty(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate), "A server error carries no challenge.");
        Assert.IsEmpty(response.Headers.Headers.GetValues("Access-Control-Expose-Headers"), "A server error carries no exposure field.");
        DpopCodeBindingWire.AssertCarriesJsonErrorBody(response.Body);
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual("server_error", document.RootElement.GetProperty("error").GetString(), response.Body);
        Assert.AreEqual(expectedDescription, document.RootElement.GetProperty("error_description").GetString(), response.Body);
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


    /// <summary>
    /// Issues an access token through the authorization-code flow whose pushed authorization request and token request
    /// are sent over the wire, the pushed request naming <paramref name="resource"/> as its <c>resource</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 Section 2</see>), and returns it.
    /// </summary>
    /// <param name="host">The host the flow is driven against.</param>
    /// <param name="material">The registration.</param>
    /// <param name="scope">The requested scope.</param>
    /// <param name="resource">The resource indicator the pushed request names.</param>
    /// <returns>The access token.</returns>
    private async ValueTask<string> IssueAccessTokenOverTheWireAsync(
        TestHostShell host, VerifierKeyMaterial material, string scope, string resource)
    {
        InProcessAuthCodeDriveResult result = await InProcessAuthCodeDriver.DriveAsync(
            host, material, SubjectId, RedirectUri,
            new InProcessAuthCodeDriveOptions { Scope = scope, Resource = resource, UsesRealWireTransport = true },
            TestContext.CancellationToken).ConfigureAwait(false);

        using JsonDocument body = JsonDocument.Parse(result.TokenResponse.Body);

        return body.RootElement.GetProperty("access_token").GetString()!;
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
            RouteValues: RouteValues.Empty)
        {
            RequestTarget = path
        };

        ExchangeContext context = [];
        context.SetTenantId(segment);
        return await host.Server.DispatchAsync(request, context, TestContext.CancellationToken)
            .ConfigureAwait(false);
    }


}
