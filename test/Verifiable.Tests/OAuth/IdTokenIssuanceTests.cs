using Microsoft.Extensions.Time.Testing;
using System.Collections;
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

    /// <summary>The test-local claim id of the application contributor that writes the access token's <c>aud</c>.</summary>
    private static ClaimId AccessTokenAudienceClaimId { get; } = ClaimId.Create(9121, "TestAccessTokenAudience");

    /// <summary>The test-local claim id of the application contributor that writes the ID Token's <c>aud</c>.</summary>
    private static ClaimId IdTokenAudienceClaimId { get; } = ClaimId.Create(9122, "TestIdTokenAudience");

    /// <summary>The identifier of a recipient that is not the client, which a contributor writes under <c>aud</c>.</summary>
    private static string OtherAudience { get; } = "https://other.example.com";

    /// <summary>The identifier of a resource server a contributor writes under the access token's <c>aud</c>.</summary>
    private static string ResourceAudience { get; } = "https://rs.example.com/orders";


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
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AContributorThatWritesANullSubjectForTheAccessTokenReturnsNoTokenAsync()
    {
        await AssertTheCodeExchangeReturnsNoTokenAsync(candidateIntegration =>
            candidateIntegration.ClaimIssuer = CreateContributionIssuer(
                AccessTokenSubjectClaimId, WellKnownJwtClaimNames.Sub, null!)).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2">RFC 9068 Section 2.2</see> lists the access
    /// token's <c>aud</c> claim: "aud  REQUIRED - as defined in Section 4.1.3 of [RFC7519].  See Section 3 for
    /// indications on how an authorization server should determine the value of "aud" depending on the request."
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3">RFC 7519 Section 4.1.3</see>: "In the general
    /// case, the "aud" value is an array of case-sensitive strings, each containing a StringOrURI value.  In the
    /// special case when the JWT has one audience, the "aud" value MAY be a single case-sensitive string containing a
    /// StringOrURI value." An application's claim contributor for the access token target that writes <c>aud</c> as
    /// a value that names no recipient replaces the audience the access token's producer composed, so the code
    /// exchange is answered over the wire with 500 and the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c>: no
    /// token of the response is returned, and no access token whose <c>aud</c> names no recipient is sent. The value
    /// is the contributor's own defect; answering it <c>server_error</c> with no token of the response is this
    /// library's rule. The rows: a null value; an empty sequence; a sequence holding an entry of white space; a
    /// number.
    /// </summary>
    /// <param name="caseName">The value the contributor writes under <c>aud</c>, by row name.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("null", DisplayName = "a null value")]
    [DataRow("empty-sequence", DisplayName = "an empty sequence")]
    [DataRow("sequence-with-a-blank-entry", DisplayName = "a sequence holding an entry of white space")]
    [DataRow("number", DisplayName = "a number")]
    public async Task AContributorThatWritesAnAudienceNamingNoRecipientForTheAccessTokenReturnsNoTokenAsync(string caseName)
    {
        object audience = caseName switch
        {
            "null" => null!,
            "empty-sequence" => Array.Empty<string>(),
            "sequence-with-a-blank-entry" => new[] { "https://rs.example.com/orders", " " },
            "number" => 42L,
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        await AssertTheCodeExchangeReturnsNoTokenAsync(candidateIntegration =>
            candidateIntegration.ClaimIssuer = CreateContributionIssuer(
                AccessTokenAudienceClaimId, WellKnownJwtClaimNames.Aud, audience)).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3">RFC 7519 Section 4.1.3</see>: "In the general
    /// case, the "aud" value is an array of case-sensitive strings, each containing a StringOrURI value.  In the
    /// special case when the JWT has one audience, the "aud" value MAY be a single case-sensitive string containing a
    /// StringOrURI value." An application's claim contributor for the access token target that writes <c>aud</c> in
    /// either form, each value naming a recipient, is answered over the wire with 200, and the issued access token's
    /// <c>aud</c> is the value the contributor wrote. The rows: one string; a sequence of two strings.
    /// </summary>
    /// <param name="caseName">The value the contributor writes under <c>aud</c>, by row name.</param>
    /// <param name="expectedAudienceJson">The JSON text of the issued access token's <c>aud</c>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("one-string", "\"https://rs.example.com/orders\"", DisplayName = "one string")]
    [DataRow("two-strings", "[\"https://rs.example.com/orders\",\"https://rs.example.com/billing\"]", DisplayName = "a sequence of two strings")]
    public async Task AContributorThatWritesAnAudienceNamingRecipientsForTheAccessTokenIsIssuedItAsync(
        string caseName, string expectedAudienceJson)
    {
        object audience = caseName switch
        {
            "one-string" => "https://rs.example.com/orders",
            "two-strings" => new[] { "https://rs.example.com/orders", "https://rs.example.com/billing" },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        (int status, string body) = await RedeemTheCodeUnderAsync(candidateIntegration =>
            candidateIntegration.ClaimIssuer = CreateContributionIssuer(
                AccessTokenAudienceClaimId, WellKnownJwtClaimNames.Aud, audience)).ConfigureAwait(false);
        Assert.AreEqual(200, status, body);

        using JsonDocument answer = JsonDocument.Parse(body);
        Assert.AreEqual(
            expectedAudienceJson,
            DescribeIssuedClaim(answer.RootElement, OAuthRequestParameterNames.AccessToken, WellKnownJwtClaimNames.Aud),
            body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3">RFC 7519 Section 4.1.3</see>: "In the general
    /// case, the "aud" value is an array of case-sensitive strings, each containing a StringOrURI value." An
    /// application's claim contributor for the access token target that writes <c>aud</c> as a sequence whose one
    /// entry is a resource server's identifier on its first enumerations and the number 7 on every later one is read
    /// once, and the token is signed with what was read and checked: the code exchange is answered over the wire with
    /// 200, and the issued access token's <c>aud</c> is exactly <c>["https://rs.example.com/orders"]</c>. Reading a
    /// written <c>aud</c> once and signing the value read is this library's rule. The rows: the sequence yields the
    /// identifier on its first enumeration only; on its first two.
    /// </summary>
    /// <param name="wellFormedEnumerations">
    /// How many enumerations of the sequence yield the resource server's identifier before it yields the number.
    /// </param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(1, DisplayName = "the identifier on the first enumeration only")]
    [DataRow(2, DisplayName = "the identifier on the first two enumerations")]
    public async Task AContributorWhoseAudienceSequenceChangesWhenEnumeratedAgainIsIssuedTheAudienceReadOnceAsync(
        int wellFormedEnumerations)
    {
        (int status, string body) = await RedeemTheCodeUnderAsync(candidateIntegration =>
            candidateIntegration.ClaimIssuer = CreateContributionIssuer(
                AccessTokenAudienceClaimId,
                WellKnownJwtClaimNames.Aud,
                new ShiftingAudienceSequence(ResourceAudience, wellFormedEnumerations))).ConfigureAwait(false);

        string accessTokenAudience = "none";
        if(status == 200)
        {
            using JsonDocument answer = JsonDocument.Parse(body);
            accessTokenAudience = DescribeIssuedClaim(
                answer.RootElement, OAuthRequestParameterNames.AccessToken, WellKnownJwtClaimNames.Aud);
        }

        string record = $"{status} '{body}' access_token aud {accessTokenAudience}";

        Assert.AreEqual(200, status, record);
        Assert.AreEqual("[\"https://rs.example.com/orders\"]", accessTokenAudience, record);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2">RFC 9068 Section 2.2</see> lists the access
    /// token's <c>aud</c> claim: "aud  REQUIRED - as defined in Section 4.1.3 of [RFC7519].  See Section 3 for
    /// indications on how an authorization server should determine the value of "aud" depending on the request." An
    /// application-defined producer for the access token, installed through
    /// <see cref="AuthorizationServerIntegration.TokenProducers"/>, whose payload carries no <c>aud</c> composes an
    /// access token that names no recipient, so the code exchange is answered over the wire with 500 and the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c>: no
    /// token of the response is returned, and no access token without <c>aud</c> is sent. The payload is the
    /// producer's own defect; answering it <c>server_error</c> with no token of the response is this library's rule.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnAccessTokenProducerThatWritesNoAudienceReturnsNoTokenAsync()
    {
        await AssertTheCodeExchangeReturnsNoTokenAsync(candidateIntegration =>
            candidateIntegration.TokenProducers = new TokenProducerSet(
            [
                WithoutAudience(TokenProducer.Rfc9068AccessToken),
                TokenProducer.Oidc10IdToken
            ])).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0
    /// Section 2</see> describes the ID Token's <c>aud</c> Claim: "REQUIRED. Audience(s) that this ID Token is
    /// intended for. It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value. It MAY also
    /// contain identifiers for other audiences." An application's claim contributor for the ID Token target that
    /// writes <c>aud</c> as an audience that is not the client's <c>client_id</c> replaces the audience the ID
    /// Token's producer composed, so the code exchange is answered over the wire with 500 and the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c>: no
    /// token of the response is returned, and no ID Token that is not intended for the Relying Party is sent. The
    /// value is the contributor's own defect; answering it <c>server_error</c> with no token of the response is this
    /// library's rule. The rows: one string; a sequence of one string.
    /// </summary>
    /// <param name="caseName">The value the contributor writes under the ID Token's <c>aud</c>, by row name.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("one-string", DisplayName = "one string")]
    [DataRow("sequence-of-one", DisplayName = "a sequence of one string")]
    public async Task AContributorThatWritesAnIdTokenAudienceWithoutTheClientIdReturnsNoTokenAsync(string caseName)
    {
        object audience = caseName switch
        {
            "one-string" => OtherAudience,
            "sequence-of-one" => new[] { OtherAudience },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        await AssertTheCodeExchangeReturnsNoTokenAsync(candidateIntegration =>
            candidateIntegration.ClaimIssuer = CreateContributionIssuer(
                IdTokenAudienceClaimId, WellKnownJwtClaimNames.Aud, audience, isWrittenForTheIdToken: true))
            .ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0
    /// Section 2</see> describes the ID Token's <c>aud</c> Claim: "REQUIRED. Audience(s) that this ID Token is
    /// intended for. It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value." An
    /// application-defined producer for the ID Token, installed through
    /// <see cref="AuthorizationServerIntegration.TokenProducers"/>, whose payload carries no <c>aud</c> composes an
    /// ID Token intended for no audience, so the code exchange is answered over the wire with 500 and the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c>: no
    /// token of the response is returned, and no ID Token without <c>aud</c> is sent. The payload is the producer's
    /// own defect; answering it <c>server_error</c> with no token of the response is this library's rule.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnIdTokenProducerThatWritesNoAudienceReturnsNoTokenAsync()
    {
        await AssertTheCodeExchangeReturnsNoTokenAsync(candidateIntegration =>
            candidateIntegration.TokenProducers = new TokenProducerSet(
            [
                TokenProducer.Rfc9068AccessToken,
                WithoutAudience(TokenProducer.Oidc10IdToken)
            ])).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0
    /// Section 2</see> describes the ID Token's <c>aud</c> Claim: "It MUST contain the OAuth 2.0 client_id of the
    /// Relying Party as an audience value. It MAY also contain identifiers for other audiences." An application's
    /// claim contributor for the ID Token target that writes <c>aud</c> as the client's <c>client_id</c> beside
    /// another audience is answered over the wire with 200, and the issued ID Token's <c>aud</c> is exactly
    /// <c>["https://client.example.com","https://other.example.com"]</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AContributorThatWritesTheClientIdBesideAnotherAudienceForTheIdTokenIsIssuedItAsync()
    {
        (int status, string body) = await RedeemTheCodeUnderAsync(candidateIntegration =>
            candidateIntegration.ClaimIssuer = CreateContributionIssuer(
                IdTokenAudienceClaimId,
                WellKnownJwtClaimNames.Aud,
                new[] { ClientId, OtherAudience },
                isWrittenForTheIdToken: true)).ConfigureAwait(false);
        Assert.AreEqual(200, status, body);

        using JsonDocument answer = JsonDocument.Parse(body);
        Assert.AreEqual(
            "[\"https://client.example.com\",\"https://other.example.com\"]",
            DescribeIssuedClaim(answer.RootElement, OAuthRequestParameterNames.IdToken, WellKnownJwtClaimNames.Aud),
            body);
    }


    /// <summary>
    /// Builds the claim issuer of the standard rules plus an application contributor that writes
    /// <paramref name="claimName"/> as <paramref name="claimValue"/> into every access token the host signs, or into
    /// every ID Token when <paramref name="isWrittenForTheIdToken"/> is <see langword="true"/>, the value written over
    /// the one that token's producer composed.
    /// </summary>
    /// <param name="claimId">The test-local claim id of the contributor.</param>
    /// <param name="claimName">The claim the contributor writes.</param>
    /// <param name="claimValue">The value it writes, null included.</param>
    /// <param name="isWrittenForTheIdToken">
    /// Whether the contributor writes for the ID Token target (<see cref="IdTokenTarget"/>) instead of the access token
    /// target (<see cref="AccessTokenTarget"/>).
    /// </param>
    /// <returns>The claim issuer the host's integration is altered to.</returns>
    private ClaimIssuer<ClaimContributionTarget> CreateContributionIssuer(
        ClaimId claimId, string claimName, object claimValue, bool isWrittenForTheIdToken = false)
    {
        List<ClaimDelegate<ClaimContributionTarget>> rules = ContributionProfiles.StandardRules();
        rules.Add(new ClaimDelegate<ClaimContributionTarget>(
            new ClaimDelegateAsync<ClaimContributionTarget>((target, _) => ValueTask.FromResult<List<Claim>>(
                (isWrittenForTheIdToken ? target is IdTokenTarget : target is AccessTokenTarget)
                    ?
                    [
                        new Claim(claimId, ClaimOutcome.Success,
                            new ClaimContributionContext(claimName, claimValue), Claim.NoSubClaims)
                    ]
                    : [new Claim(claimId, ClaimOutcome.NotApplicable)])),
            [claimId]));

        return new ClaimIssuer<ClaimContributionTarget>(WellKnownAssessorIds.ClaimContributors, rules, TimeProvider);
    }


    /// <summary>
    /// Builds a copy of <paramref name="producer"/> whose <see cref="TokenProducer.BuildAsync"/> composes what the
    /// original composes and then removes <c>aud</c> from the payload: an application-defined producer whose payload
    /// carries no <c>aud</c>.
    /// </summary>
    /// <param name="producer">The producer whose composition is kept apart from <c>aud</c>.</param>
    /// <returns>The producer without <c>aud</c>.</returns>
    private static TokenProducer WithoutAudience(TokenProducer producer)
    {

        return producer with
        {
            BuildAsync = async (context, signingKeyId, algorithm, cancellationToken) =>
            {
                TokenProducerOutput output = await producer.BuildAsync(
                    context, signingKeyId, algorithm, cancellationToken).ConfigureAwait(false);
                _ = output.Payload.Remove(WellKnownJwtClaimNames.Aud);

                return output;
            }
        };
    }


    /// <summary>
    /// Drives the code flow of a request that asks for <c>openid</c> over the loopback listener, the pushed
    /// request, the authorize redirect and the code exchange, with <paramref name="alteration"/> applied to the
    /// host's integration before the flow, and asserts that the code exchange returns no token: 500 with the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> and no
    /// other member. A 200 answer is rendered in the assertion message with the <c>sub</c> its <c>id_token</c> and
    /// its <c>access_token</c> carry and the <c>aud</c> each of them carries, each as its JSON text,
    /// <c>absent</c>, or <c>none</c> when that token is not in the answer.
    /// </summary>
    /// <param name="alteration">The change to the host's integration the tokens are issued under.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertTheCodeExchangeReturnsNoTokenAsync(Action<AuthorizationServerIntegration> alteration)
    {
        (int status, string body) = await RedeemTheCodeUnderAsync(alteration).ConfigureAwait(false);

        //A 200 answer is rendered with the sub and the aud its id_token and its access_token carry, as JSON text, or
        //absent.
        string idTokenSubject = "none";
        string accessTokenSubject = "none";
        string idTokenAudience = "none";
        string accessTokenAudience = "none";
        if(status == 200)
        {
            using JsonDocument answer = JsonDocument.Parse(body);
            idTokenSubject = DescribeIssuedClaim(
                answer.RootElement, OAuthRequestParameterNames.IdToken, WellKnownJwtClaimNames.Sub);
            accessTokenSubject = DescribeIssuedClaim(
                answer.RootElement, OAuthRequestParameterNames.AccessToken, WellKnownJwtClaimNames.Sub);
            idTokenAudience = DescribeIssuedClaim(
                answer.RootElement, OAuthRequestParameterNames.IdToken, WellKnownJwtClaimNames.Aud);
            accessTokenAudience = DescribeIssuedClaim(
                answer.RootElement, OAuthRequestParameterNames.AccessToken, WellKnownJwtClaimNames.Aud);
        }

        string record = $"{status} '{body}' id_token sub {idTokenSubject} access_token sub {accessTokenSubject}"
            + $" id_token aud {idTokenAudience} access_token aud {accessTokenAudience}";

        Assert.AreEqual(500, status, record);
        Assert.AreEqual(
            "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            body,
            record);
    }


    /// <summary>
    /// Drives the code flow of a request that asks for <c>openid</c> over the loopback listener, the pushed
    /// request, the authorize redirect and the code exchange, on a host whose integration
    /// <paramref name="alteration"/> changes before the flow.
    /// </summary>
    /// <param name="alteration">The change to the host's integration the tokens are issued under.</param>
    /// <returns>The token endpoint's status code and body for the code exchange.</returns>
    private async Task<(int StatusCode, string Body)> RedeemTheCodeUnderAsync(
        Action<AuthorizationServerIntegration> alteration)
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        await TestHostShell.AlterAsync(host.Server, alteration).ConfigureAwait(false);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        //The pushed request, the authorize redirect and the code exchange each cross the loopback listener.
        (string code, string verifier) = await PushOpenIdAuthorizationAsync(host, segment).ConfigureAwait(false);

        return await RedeemOverTheWireAsync(host, segment, code, verifier).ConfigureAwait(false);
    }


    /// <summary>
    /// A sequence of one <c>aud</c> entry that changes when it is enumerated again: its first
    /// <c>wellFormedEnumerations</c> enumerations yield a recipient's identifier, and every later one yields the
    /// number 7, an entry that names no recipient. It stands for a contributor's lazily computed value, which a
    /// reader that enumerates it more than once reads differently each time.
    /// </summary>
    /// <param name="recipient">The identifier the first enumerations yield.</param>
    /// <param name="wellFormedEnumerations">How many enumerations yield <paramref name="recipient"/>.</param>
    private sealed class ShiftingAudienceSequence(string recipient, int wellFormedEnumerations): IEnumerable<object>
    {
        /// <summary>How many times the sequence has been enumerated.</summary>
        private int Enumerations { get; set; }

        /// <summary>Enumerates the one entry, the identifier or the number by the count of enumerations so far.</summary>
        /// <returns>An enumerator over the one entry.</returns>
        public IEnumerator<object> GetEnumerator()
        {
            Enumerations++;
            IEnumerable<object> entries = [Enumerations <= wellFormedEnumerations ? recipient : 7];

            return entries.GetEnumerator();
        }

        /// <summary>Enumerates the one entry as <see cref="GetEnumerator"/> does.</summary>
        /// <returns>An enumerator over the one entry.</returns>
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-4.1.3">OAuth 2.1 draft-16
    /// Section 4.1.3</see>: "If a second valid token request is made with the same authorization code as a previously
    /// successful token request, the authorization server MUST deny the request". A redemption whose issuance walk
    /// returns a failure because the application's subject resolver throws (the claim issuer records the failed
    /// contribution, so the walk mints no token with a subject), before the step's first store write, issued nothing
    /// and is not a successful token request: the first redemption over the wire is answered 500 with the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c>, and the
    /// same code presented again with the resolver restored is answered 200 with an <c>access_token</c> and an
    /// <c>id_token</c>. Releasing the claim of a walk that ended before the step's first store write is this
    /// library's rule.
    /// </summary>
    [TestMethod]
    public async Task ACodeSurvivesAWalkThatFailsBeforePersistenceAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        ResolveSubjectIdentifierDelegate resolver = host.Server.OAuth().ResolveSubjectIdentifierAsync!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            candidateIntegration.ResolveSubjectIdentifierAsync =
                static (_, _, _, _) => throw new InvalidOperationException("The subject identifier store is unavailable."))
            .ConfigureAwait(false);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        (string code, string verifier) = await PushOpenIdAuthorizationAsync(host, segment).ConfigureAwait(false);
        (int firstStatus, string firstBody) = await RedeemOverTheWireAsync(host, segment, code, verifier).ConfigureAwait(false);
        Assert.AreEqual(500, firstStatus, firstBody);
        Assert.AreEqual(
            "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            firstBody);

        //The resolver is restored under traffic; the code and its verifier are presented again unchanged.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            candidateIntegration.ResolveSubjectIdentifierAsync = resolver).ConfigureAwait(false);
        (int status, string body) = await RedeemOverTheWireAsync(host, segment, code, verifier).ConfigureAwait(false);
        Assert.AreEqual(200, status, body);

        using JsonDocument answer = JsonDocument.Parse(body);
        Assert.IsTrue(answer.RootElement.TryGetProperty(OAuthRequestParameterNames.AccessToken, out _), body);
        Assert.IsTrue(answer.RootElement.TryGetProperty(OAuthRequestParameterNames.IdToken, out _), body);
    }


    /// <summary>
    /// A rule of this library, stated here because the specification sets no order between a failed redemption and
    /// the bookkeeping that follows it: when a redemption's issuance walk returns a failure before the step's first
    /// store write, because the application's subject resolver throws and the claim issuer records the failed
    /// contribution, and the release of its claim then throws before it removes the claim mark, the walk has no
    /// exception of its own, so the release's exception is the request's fault, and the step stays claimed. The
    /// redemption over the wire is answered 500 with the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> that the
    /// host writes for the release's fault, and the same code presented again with both seams restored is answered
    /// 400 with the body
    /// <c>{"error":"invalid_grant","error_description":"The authorization code is unknown, expired, or already used."}</c>.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-4.1.3">OAuth 2.1 draft-16
    /// Section 4.1.3</see> requires the denial only for "a previously successful token request"; a code whose release
    /// failed stays spent by this library's fail-closed rule.
    /// </summary>
    [TestMethod]
    public async Task AReleaseThatThrowsAfterAReturnedFailureFailsTheRedemptionAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        ResolveSubjectIdentifierDelegate resolver = host.Server.OAuth().ResolveSubjectIdentifierAsync!;
        ReleaseServerFlowStateDelegate originalRelease = host.Server.OAuth().ReleaseFlowStateAsync!;

        //The subject resolver throws, so the walk returns a failure, and the release throws its own.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectIdentifierAsync =
                static (_, _, _, _) => throw new InvalidOperationException("The subject identifier store is unavailable.");
            candidateIntegration.ReleaseFlowStateAsync =
                static (_, _, _, _, _) => throw new InvalidOperationException("The claim store is unavailable.");
        }).ConfigureAwait(false);

        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        (string code, string verifier) = await PushOpenIdAuthorizationAsync(host, segment).ConfigureAwait(false);
        (int failedStatus, string failedBody) = await RedeemOverTheWireAsync(host, segment, code, verifier).ConfigureAwait(false);
        Assert.AreEqual(500, failedStatus, failedBody);
        Assert.AreEqual(
            "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            failedBody);
        Exception fault = Assert.ContainsSingle(host.Host("default").ConsumeHttpFaults());
        Assert.AreEqual(typeof(InvalidOperationException), fault.GetType(), fault.Message);
        Assert.AreEqual("The claim store is unavailable.", fault.Message);

        //Both seams are restored under traffic; the code and its verifier are presented again unchanged.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectIdentifierAsync = resolver;
            candidateIntegration.ReleaseFlowStateAsync = originalRelease;
        }).ConfigureAwait(false);
        (int status, string body) = await RedeemOverTheWireAsync(host, segment, code, verifier).ConfigureAwait(false);
        Assert.AreEqual(400, status, body);
        Assert.AreEqual(
            "{\"error\":\"invalid_grant\",\"error_description\":\"The authorization code is unknown, expired, or already used.\"}",
            body);
    }


    /// <summary>
    /// Pushes a request that asks for <c>openid</c> and completes the authorize redirect over the loopback listener,
    /// asserting the pushed request's 201 and the authorize answer's 302.
    /// </summary>
    /// <param name="host">The host serving the flow.</param>
    /// <param name="segment">The tenant segment of the endpoint paths.</param>
    /// <returns>The issued authorization code and the PKCE verifier that redeems it.</returns>
    private async Task<(string Code, string Verifier)> PushOpenIdAuthorizationAsync(TestHostShell host, string segment)
    {
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
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

        return (code, pkce.EncodedVerifier);
    }


    /// <summary>Presents an authorization code and its PKCE verifier at the token endpoint over the loopback listener.</summary>
    /// <param name="host">The host serving the flow.</param>
    /// <param name="segment">The tenant segment of the endpoint paths.</param>
    /// <param name="code">The authorization code presented.</param>
    /// <param name="verifier">The PKCE verifier presented with it.</param>
    /// <returns>The token endpoint's status code and body.</returns>
    private Task<(int StatusCode, string Body)> RedeemOverTheWireAsync(
        TestHostShell host, string segment, string code, string verifier)
    {

        return RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host,
            segment,
            RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, verifier, RedirectUri.OriginalString),
            TestContext.CancellationToken);
    }


    /// <summary>
    /// Renders the claim <paramref name="claimName"/> of the token a token response carries under
    /// <paramref name="responseMember"/>: its JSON text, <c>absent</c> when the token's payload has no such claim, or
    /// <c>none</c> when the response carries no such token.
    /// </summary>
    /// <param name="answer">The token response's JSON object.</param>
    /// <param name="responseMember">The response member that carries the compact token.</param>
    /// <param name="claimName">The claim rendered.</param>
    /// <returns>The rendering of the token's claim.</returns>
    private static string DescribeIssuedClaim(JsonElement answer, string responseMember, string claimName)
    {
        if(!answer.TryGetProperty(responseMember, out JsonElement token))
        {
            return "none";
        }

        using JsonDocument payload = JwtPayloadReader.ParsePayloadJson(token.GetString()!);

        return payload.RootElement.TryGetProperty(claimName, out JsonElement claim)
            ? claim.GetRawText()
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
