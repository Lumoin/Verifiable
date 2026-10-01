using Microsoft.Extensions.Time.Testing;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Assessment;
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
/// dispatch directly via <see cref="TestHostShell.DispatchAtEndpointAsync(string, string, string, RequestFields, ExchangeContext, CancellationToken)"/>
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
    private static Uri ClientBaseUri { get; } = new("https://client.example.com");
    private static Uri RedirectUri { get; } =
        new("https://client.example.com/callback");

    /// <summary>The test-local claim id of the application contributor that writes the access token's <c>sub</c>.</summary>
    private static ClaimId AccessTokenSubjectClaimId { get; } = ClaimId.Create(9120, "TestAccessTokenSubject");


    [TestMethod]
    public async Task TokenEndpointEmitsIdTokenWhenOpenIdScopeRequested()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(
            subject: SubjectId,
            name: "Alice",
            email: "alice@example.com",
            emailVerified: true);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

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
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

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
        _ = host.SeedTestSubject(
            subject: SubjectId,
            name: "Alice",
            email: "alice@example.com");

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

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

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

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

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

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
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

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


    /// <summary>
    /// ID-token issuance places the application-resolved subject identifier in the required sub claim.
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">Core §2</see>.
    /// </summary>
    [TestMethod]
    public async Task ResolveSubjectIdentifierIsConsultedOnIdTokenIssuance()
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

        ServerHttpResponse tokenResponse = await DriveCodeExchangeAsync(
            host, material, WellKnownScopes.OpenId).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument body = JsonDocument.Parse(tokenResponse.Body);
        string idToken = body.RootElement.GetProperty("id_token").GetString()!;
        using JsonDocument payload = JwtPayloadReader.ParsePayloadJson(idToken);

        Assert.AreEqual($"hashed-{SubjectId}",
            payload.RootElement.GetProperty(WellKnownJwtClaimNames.Sub).GetString(),
            "ID Token sub must reflect the AS-installed "
            + "ResolveSubjectIdentifierAsync delegate, not the raw end-user "
            + "identifier from IssuanceContext.Subject.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0
    /// Section 2</see> describes the ID Token's <c>sub</c> Claim: "REQUIRED. Subject Identifier." A subject
    /// resolver that returns a value of white space only names no End-User, so the code exchange of a request that
    /// asked for <c>openid</c> is answered over the wire with 500 and the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c>: no
    /// token of the response is returned, neither an <c>id_token</c> nor an <c>access_token</c>. The value is the
    /// resolver's own defect; answering it <c>server_error</c> with no token of the response is this library's rule.
    /// </summary>
    [TestMethod]
    public async Task AResolverThatReturnsABlankSubjectReturnsNoTokenAsync()
    {
        await AssertTheCodeExchangeReturnsNoTokenAsync(candidateIntegration =>
            candidateIntegration.ResolveSubjectIdentifierAsync =
                static (_, _, _, _) => ValueTask.FromResult(" ")).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0
    /// Section 2</see> describes the ID Token's <c>sub</c> Claim: "REQUIRED. Subject Identifier." A subject
    /// resolver that throws contributes no <c>sub</c>, and the ID Token producer composes none of its own, so the
    /// code exchange of a request that asked for <c>openid</c> is answered over the wire with 500 and the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c>: no
    /// token of the response is returned, neither an <c>id_token</c> nor an <c>access_token</c>, and no ID Token
    /// without a subject is sent. Answering the resolver's fault <c>server_error</c> with no token of the response
    /// is this library's rule.
    /// </summary>
    [TestMethod]
    public async Task AResolverThatThrowsReturnsNoTokenAsync()
    {
        await AssertTheCodeExchangeReturnsNoTokenAsync(candidateIntegration =>
            candidateIntegration.ResolveSubjectIdentifierAsync =
                static (_, _, _, _) => throw new InvalidOperationException("The subject identifier store is unavailable."))
            .ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0
    /// Section 2</see> describes the ID Token's <c>sub</c> Claim: "REQUIRED. Subject Identifier." A subject
    /// resolver that returns null names no End-User, so the code exchange of a request that asked for
    /// <c>openid</c> is answered over the wire with 500 and the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c>: no
    /// token of the response is returned, neither an <c>id_token</c> nor an <c>access_token</c>, and no ID Token
    /// whose <c>sub</c> is null is sent. The value is the resolver's own defect; answering it <c>server_error</c>
    /// with no token of the response is this library's rule.
    /// </summary>
    [TestMethod]
    public async Task AResolverThatReturnsNullReturnsNoTokenAsync()
    {
        await AssertTheCodeExchangeReturnsNoTokenAsync(candidateIntegration =>
            candidateIntegration.ResolveSubjectIdentifierAsync =
                static (_, _, _, _) => ValueTask.FromResult<string>(null!)).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2">RFC 9068 Section 2.2</see> lists the access
    /// token's <c>sub</c> claim: "sub REQUIRED - as defined in Section 4.1.2 of [RFC7519]." An application's claim
    /// contributor for the access token target that contributes <c>sub</c> with the value null replaces the
    /// subject the access token's producer composed, and the payload then names no subject, so the code exchange is
    /// answered over the wire with 500 and the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c>: no
    /// token of the response is returned, and no access token whose <c>sub</c> is null is sent. The value is the
    /// contributor's own defect; answering it <c>server_error</c> with no token of the response is this library's
    /// rule.
    /// </summary>
    [TestMethod]
    public async Task AContributorThatWritesANullSubjectForTheAccessTokenReturnsNoTokenAsync()
    {
        List<ClaimDelegate<ClaimContributionTarget>> rules = ContributionProfiles.StandardRules();
        rules.Add(new ClaimDelegate<ClaimContributionTarget>(
            new ClaimDelegateAsync<ClaimContributionTarget>(static (target, _) => ValueTask.FromResult<List<Claim>>(
                target is AccessTokenTarget
                    ?
                    [
                        new Claim(AccessTokenSubjectClaimId, ClaimOutcome.Success,
                            new ClaimContributionContext(WellKnownJwtClaimNames.Sub, null!), Claim.NoSubClaims)
                    ]
                    : [new Claim(AccessTokenSubjectClaimId, ClaimOutcome.NotApplicable)])),
            [AccessTokenSubjectClaimId]));

        await AssertTheCodeExchangeReturnsNoTokenAsync(candidateIntegration =>
            candidateIntegration.ClaimIssuer = new ClaimIssuer<ClaimContributionTarget>(
                WellKnownAssessorIds.ClaimContributors, rules, TimeProvider)).ConfigureAwait(false);
    }


    /// <summary>
    /// Drives the code flow of a request that asks for <c>openid</c> over the loopback listener, the pushed
    /// request, the authorize redirect and the code exchange, with <paramref name="alteration"/> applied to the
    /// host's integration before the flow, and asserts that the code exchange returns no token: 500 with the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> and no
    /// other member. A 200 answer is rendered in the assertion message with the <c>sub</c> its <c>id_token</c> and
    /// its <c>access_token</c> carry, each as its JSON text, <c>absent</c>, or <c>none</c> when that token is not
    /// in the answer.
    /// </summary>
    /// <param name="alteration">The change to the host's integration the tokens are issued under.</param>
    private async Task AssertTheCodeExchangeReturnsNoTokenAsync(Action<AuthorizationServerIntegration> alteration)
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        await TestHostShell.AlterAsync(host.Server, alteration).ConfigureAwait(false);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        //The pushed request, the authorize redirect and the code exchange each cross the loopback listener.
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, TestHostShell.MemoryPool);
        List<KeyValuePair<string, string>> parFields =
        [
            new(OAuthRequestParameterNames.ResponseType, WellKnownResponseTypes.Code),
            new(OAuthRequestParameterNames.ClientId, ClientId),
            new(OAuthRequestParameterNames.CodeChallenge, pkce.EncodedChallenge),
            new(OAuthRequestParameterNames.CodeChallengeMethod, WellKnownCodeChallengeMethods.S256),
            new(OAuthRequestParameterNames.RedirectUri, RedirectUri.OriginalString),
            new(OAuthRequestParameterNames.Scope, WellKnownScopes.OpenId)
        ];
        (int parStatusCode, string parBody, Uri? authorizeLocation, int authorizeStatusCode) =
            await RawAuthCodeWirePushers.PushParAndAuthorizeAsync(
                host, segment, ClientId, SubjectId, parFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parStatusCode, parBody);
        Assert.AreEqual(302, authorizeStatusCode);
        Assert.IsNotNull(authorizeLocation, "The authorize answer is a redirect carrying a Location header.");
        string code = TestBrowser.ExtractQueryParam(authorizeLocation.OriginalString, OAuthRequestParameterNames.Code)!;

        (int status, string body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host,
            segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        //A 200 answer is rendered with the sub its id_token and its access_token carry, as JSON text, or absent.
        string idTokenSubject = "none";
        string accessTokenSubject = "none";
        if(status == 200)
        {
            using JsonDocument answer = JsonDocument.Parse(body);
            idTokenSubject = DescribeIssuedSubject(answer.RootElement, OAuthRequestParameterNames.IdToken);
            accessTokenSubject = DescribeIssuedSubject(answer.RootElement, OAuthRequestParameterNames.AccessToken);
        }

        string record = $"{status} '{body}' id_token sub {idTokenSubject} access_token sub {accessTokenSubject}";

        Assert.AreEqual(500, status, record);
        Assert.AreEqual(
            "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            body,
            record);
    }


    /// <summary>
    /// Renders the <c>sub</c> of the token a token response carries under <paramref name="responseMember"/> for an
    /// assertion message: its JSON text, <c>absent</c> when the token's payload has no <c>sub</c>, or <c>none</c>
    /// when the response carries no such token.
    /// </summary>
    /// <param name="answer">The token response's JSON object.</param>
    /// <param name="responseMember">The response member that carries the compact token.</param>
    /// <returns>The rendering of the token's <c>sub</c>.</returns>
    private static string DescribeIssuedSubject(JsonElement answer, string responseMember)
    {
        if(!answer.TryGetProperty(responseMember, out JsonElement token))
        {
            return "none";
        }

        using JsonDocument payload = JwtPayloadReader.ParsePayloadJson(token.GetString()!);

        return payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.Sub, out JsonElement sub)
            ? sub.GetRawText()
            : "absent";
    }


    [TestMethod]
    public async Task IdTokenCarriesExpStrictlyAfterIatWithIatAtRequestTime()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

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
        InProcessAuthCodeDriveResult result = await InProcessAuthCodeDriver.DriveAsync(
            host, material, SubjectId, RedirectUri,
            new InProcessAuthCodeDriveOptions { Scope = scope },
            TestContext.CancellationToken).ConfigureAwait(false);

        return result.TokenResponse;
    }
}
