using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Wire-level tests for <see cref="TestResourceServerShell"/> +
/// <see cref="ResourceServerHttpApplication"/>. Synthesises access tokens
/// directly with a P-256 key and HTTP-POSTs them to <c>/protected</c>,
/// asserting the composed validator stack responds correctly. Drives the
/// real HTTP path — Kestrel + HttpClient — without involving the AS flow.
/// </summary>
[TestClass]
internal sealed class ResourceServerEndToEndTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string Issuer = "https://issuer.test/tenant-a";
    private const string Audience = "test-resource-server";
    private const string Subject = "user-1";
    private const string ClientId = "client-1";
    private const string Kid = "test-kid";
    private const string Scope = "openid profile";

    private static DateTimeOffset NowInstant { get; } = TestClock.CanonicalEpoch.AddDays(-15);


    [TestMethod]
    public async Task BearerProtectedRequestReturnsClaimsJson()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        FakeTimeProvider time = new(NowInstant);

        await using TestResourceServerShell rs = new(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(keys.PublicKey),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: time);
        await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: Subject,
            scope: Scope,
            clientId: ClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: Issuer,
            audience: [Audience]);
        string token = await BuildAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(rs.HttpCertificate!, rs.HttpBaseAddress);
        using HttpRequestMessage request = new(HttpMethod.Get, "/protected");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using HttpResponseMessage response = await client.SendAsync(request, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString());

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(Subject, doc.RootElement.GetProperty("sub").GetString());
        Assert.AreEqual(Issuer, doc.RootElement.GetProperty("iss").GetString());
        Assert.AreEqual(ClientId, doc.RootElement.GetProperty("client_id").GetString());
    }


    /// <summary>
    /// The verification-key resolver's documented contract, a contract of this library: every
    /// resolution states the <see cref="KeyUsageContext"/> the key is expected under, and the resource
    /// server's validator names the kind it verifies. The design follows
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 §4</see>: "An authorization
    /// server MAY elect to use different keys to sign OpenID Connect ID Tokens and JWT access tokens. This
    /// specification does not provide a mechanism for identifying a specific key as the one used to sign
    /// JWT access tokens." and
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.12">RFC 8725 §3.12</see>: "Use
    /// different keys for different kinds of JWTs. Then the keys used to validate one kind of JWT will
    /// fail to validate other kinds of JWTs." An access token presented as a Bearer token at the
    /// protected resource over the wire is served 200, and the resource server's resolver is asked for
    /// its key once, under <see cref="KeyUsageContext.AccessTokenIssuance"/>.
    /// </summary>
    [TestMethod]
    public async Task ResourceServerResolvesTheAccessTokenKeyUnderAccessTokenIssuanceAsync()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        FakeTimeProvider time = new(NowInstant);
        ConcurrentQueue<KeyUsageContext> recordedUsages = new();

        await using TestResourceServerShell rs = new(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(keys.PublicKey, recordedUsages),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: time);
        await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: Subject,
            scope: Scope,
            clientId: ClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: Issuer,
            audience: [Audience]);
        string token = await BuildAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        using HttpResponseMessage response = await SendProtectedRequestAsync(rs, token).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(Subject, doc.RootElement.GetProperty("sub").GetString());
        Assert.AreEqual(KeyUsageContext.AccessTokenIssuance, Assert.ContainsSingle(recordedUsages));
    }


    [TestMethod]
    public async Task MissingAuthorizationHeaderReturns401WithBearerChallenge()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        FakeTimeProvider time = new(NowInstant);

        await using TestResourceServerShell rs = new(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(keys.PublicKey),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: time);
        await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(rs.HttpCertificate!, rs.HttpBaseAddress);
        using HttpResponseMessage response = await client.GetAsync(new Uri("/protected", UriKind.Relative), TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out var values));
        string challenge = values!.First();
        Assert.IsTrue(challenge.Contains("Bearer", StringComparison.Ordinal),
            $"Challenge must name Bearer scheme; got: {challenge}");
    }


    [TestMethod]
    public async Task AudienceMismatchReturns401()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        FakeTimeProvider time = new(NowInstant);

        await using TestResourceServerShell rs = new(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(keys.PublicKey),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: time);
        await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //Token issued for the wrong audience; RS expects "test-resource-server".
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: Subject,
            scope: Scope,
            clientId: ClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: Issuer,
            audience: ["other-rs"]);
        string token = await BuildAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(rs.HttpCertificate!, rs.HttpBaseAddress);
        using HttpRequestMessage request = new(HttpMethod.Get, "/protected");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using HttpResponseMessage response = await client.SendAsync(request, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "such a protected
    /// resource MUST reject a DPoP-bound access token received as a bearer token per [RFC6750]." and "If the mechanism
    /// used to attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be
    /// used to deliver error information (Figure 18)." An access token bound by <c>cnf.jkt</c>, presented at the
    /// application's resource over the wire under the <c>Bearer</c> scheme, is refused with 401, <c>invalid_token</c> in
    /// the body and the one challenge of the mechanism used,
    /// <c>Bearer realm="protected", error="invalid_token", resource_metadata="..."</c>, no <c>DPoP</c> challenge.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DpopBoundTokenPresentedUnderBearerSchemeReturns401()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        FakeTimeProvider time = new(NowInstant);

        await using TestResourceServerShell rs = new(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(keys.PublicKey),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: time);
        await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //Token carries a cnf.jkt binding — must be presented with DPoP scheme.
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: Subject,
            scope: Scope,
            clientId: ClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: Issuer,
            audience: [Audience]);
        payload[WellKnownJwtClaimNames.Cnf] = new Dictionary<string, object>
        {
            [WellKnownJwtClaimNames.JwkThumbprint] = "some-bound-thumbprint"
        };
        string token = await BuildAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(rs.HttpCertificate!, rs.HttpBaseAddress);
        using HttpRequestMessage request = new(HttpMethod.Get, "/protected");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using HttpResponseMessage response = await client.SendAsync(request, TestContext.CancellationToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.NonValidated.TryGetValues("WWW-Authenticate", out HeaderStringValues values),
            "The refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual(
            $"Bearer realm=\"protected\", error=\"invalid_token\", resource_metadata=\"{rs.MetadataUrl!.OriginalString}\"",
            Assert.ContainsSingle(values));
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_token", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8705#section-3">RFC 8705 Section 3</see>: "The protected resource
    /// MUST obtain, from its TLS implementation layer, the client certificate used for mutual TLS and MUST verify that the
    /// certificate matches the certificate associated with the access token.", which a resource reading no client
    /// certificate cannot do, and <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section
    /// 3.1</see>: "invalid_token The access token provided is expired, revoked, malformed, or invalid for other reasons."
    /// An access token from the trusted issuer whose <c>cnf</c> carries the certificate thumbprint <c>x5t#S256</c> and no
    /// <c>jkt</c>, a confirmation this resource cannot verify, presented at the application's resource over the wire under the
    /// <c>Bearer</c> scheme is refused, its validation answering the dedicated unsupported-confirmation reason: 401 and the
    /// one challenge <c>Bearer realm="protected", error="invalid_token",
    /// error_description="Access token cnf claim carries no jkt confirmation this validator reads.",
    /// resource_metadata="..."</c>, and no claim served.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AccessTokenConfirmedByAMethodOtherThanJktIsRefusedUnderBearerAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey).ConfigureAwait(false);
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: Subject,
            scope: Scope,
            clientId: ClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: Issuer,
            audience: [Audience]);
        payload[WellKnownJwtClaimNames.Cnf] = new Dictionary<string, object>
        {
            ["x5t#S256"] = "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"
        };
        string token = await BuildAccessTokenAsync(asKeys.PrivateKey, payload).ConfigureAwait(false);

        using HttpResponseMessage response = await SendProtectedRequestAsync(rs, token).ConfigureAwait(false);

        await AssertInvalidTokenChallengeAsync(
            rs, response, "Access token cnf claim carries no jkt confirmation this validator reads.").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">RFC 9449 Section 6.1</see>: the <c>jkt</c> value
    /// "MUST be the base64url encoding (as defined in [RFC7515]) of the JWK SHA-256 Thumbprint (according to [RFC7638])
    /// of the DPoP public key (in JWK format) to which the access token is bound.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_token The
    /// access token provided is expired, revoked, malformed, or invalid for other reasons." An access token from the
    /// trusted issuer whose <c>cnf</c> carries a blank <c>jkt</c> names no key and is malformed. Presented at the
    /// application's resource over a raw TLS connection it is refused before any proof is judged: under the
    /// <c>Bearer</c> scheme 401 with the one challenge
    /// <c>Bearer realm="protected", error="invalid_token", error_description="Access token cnf claim carries a blank jkt.", resource_metadata="..."</c>;
    /// under the <c>DPoP</c> scheme, with a proof by a DPoP key of the client's, 401 with <c>invalid_token</c> and the
    /// description "Access token cnf claim carries a blank jkt." in the body and the one challenge
    /// <c>DPoP realm="protected", error="invalid_token", algs="...", resource_metadata="..."</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "the corresponding
    /// challenge SHOULD be used to deliver error information"); no claim is served.
    /// </summary>
    /// <param name="row">The scheme the token is presented under: <see cref="BearerSchemeRow"/> or <see cref="DpopSchemeRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(BearerSchemeRow)]
    [DataRow(DpopSchemeRow)]
    public async Task AccessTokenWhoseCnfCarriesABlankJktIsRefusedAsMalformedAsync(string row)
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, boundThumbprint: string.Empty).ConfigureAwait(false);
        string authorization = row switch
        {
            BearerSchemeRow => $"Bearer {token}",
            DpopSchemeRow => $"DPoP {token}",
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown scheme row.")
        };
        List<string> dpopFieldLines = [];
        if(row == DpopSchemeRow)
        {
            dpopFieldLines.Add(await BuildResourceProofAsync(rs, dpopKey, token, nonce: null).ConfigureAwait(false));
        }

        HttpResponseData response = await SendProtectedOverARawConnectionAsync(rs, authorization, dpopFieldLines).ConfigureAwait(false);

        if(row == BearerSchemeRow)
        {
            Assert.AreEqual(401, response.StatusCode, response.Body);
            Assert.AreEqual(
                "Bearer realm=\"protected\", error=\"invalid_token\", error_description=\"Access token cnf claim carries a blank jkt.\", "
                    + $"resource_metadata=\"{rs.MetadataUrl!.OriginalString}\"",
                Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
            Assert.DoesNotContain("\"sub\"", response.Body, "A refused request is served no claim.");

            return;
        }

        AssertResourceRefusal(rs, response, "invalid_token");
        AssertRefusalDescription(response, "Access token cnf claim carries a blank jkt.");
    }


    /// <summary>
    /// The row presenting the access token under the <c>Bearer</c> scheme. A constant, not a property, because a DataRow
    /// attribute argument must be a compile-time constant.
    /// </summary>
    private const string BearerSchemeRow = "bearer-scheme";

    /// <summary>
    /// The row presenting the access token under the <c>DPoP</c> scheme. A constant, not a property, because a DataRow
    /// attribute argument must be a compile-time constant.
    /// </summary>
    private const string DpopSchemeRow = "dpop-scheme";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>:
    /// "dpop_bound_access_tokens_required OPTIONAL. Boolean value specifying whether the protected resource always
    /// requires the use of DPoP-bound access tokens [RFC9449].", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "If the request lacks
    /// any authentication information (e.g., the client was unaware that authentication is necessary or attempted using
    /// an unsupported authentication method), the resource server SHOULD NOT include an error code or other error
    /// information." At an application's resource that requires DPoP-bound access tokens, an access token bound to no
    /// key, presented over a raw TLS connection under the <c>Bearer</c> scheme, is refused: 401, an empty body, the one
    /// challenge <c>DPoP realm="protected", algs="ES256 ES384 ES512 ES256K RS256 RS384 RS512 PS256 PS384 PS512 EdDSA Ed25519", resource_metadata="..."</c>
    /// with no <c>error</c> and no <c>Bearer</c> challenge, and the one field line
    /// <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResourceServerRequiringDpopRefusesABearerPresentationAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey, requiresDpop: true).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, boundThumbprint: null).ConfigureAwait(false);

        HttpResponseData response = await SendProtectedOverARawConnectionAsync(rs, $"Bearer {token}", []).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            ResourceDpopChallenge(rs, error: null),
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        Assert.AreEqual(string.Empty, response.Body, "No error code or other error information.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "Upon receipt of a
    /// request to a protected resource within the protection space requiring DPoP authentication, the server can respond
    /// with a challenge to the client to provide DPoP authentication information if the request does not include valid
    /// credentials or does not contain an access token sufficient for access.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "If the request lacks
    /// any authentication information (e.g., the client was unaware that authentication is necessary or attempted using
    /// an unsupported authentication method), the resource server SHOULD NOT include an error code or other error
    /// information." At an application's resource that requires DPoP-bound access tokens, an access token bound by
    /// <c>cnf.jkt</c> to a key, presented over a raw TLS connection under the <c>Bearer</c> scheme, is refused before the
    /// token is validated: 401, an empty body, the one challenge
    /// <c>DPoP realm="protected", algs="ES256 ES384 ES512 ES256K RS256 RS384 RS512 PS256 PS384 PS512 EdDSA Ed25519", resource_metadata="..."</c>
    /// with no <c>error</c> and no <c>Bearer</c> challenge, the one field line
    /// <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>, and the resource never asks its
    /// verification-key resolver for the token's key.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResourceServerRequiringDpopRefusesABearerPresentationBeforeValidatingTheTokenAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        ConcurrentQueue<KeyUsageContext> resolverCalls = new();
        await using TestResourceServerShell rs = new(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(asKeys.PublicKey, resolverCalls),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: new FakeTimeProvider(NowInstant),
            requiresDpop: true);
        await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(dpopKey)).ConfigureAwait(false);

        HttpResponseData response = await SendProtectedOverARawConnectionAsync(rs, $"Bearer {token}", []).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            ResourceDpopChallenge(rs, error: null),
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        Assert.AreEqual(string.Empty, response.Body, "No error code or other error information.");
        Assert.IsEmpty(resolverCalls, "The token is refused before it is validated: its key is never resolved.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "Upon receipt of a
    /// request to a protected resource within the protection space requiring DPoP authentication, the server can respond
    /// with a challenge to the client to provide DPoP authentication information if the request does not include valid
    /// credentials or does not contain an access token sufficient for access.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "If the request lacks
    /// any authentication information (e.g., the client was unaware that authentication is necessary or attempted using
    /// an unsupported authentication method), the resource server SHOULD NOT include an error code or other error
    /// information." At an application's resource that requires DPoP-bound access tokens, a request over a raw TLS
    /// connection with no <c>Authorization</c> field is answered 401 with an empty body, the one challenge
    /// <c>DPoP realm="protected", algs="ES256 ES384 ES512 ES256K RS256 RS384 RS512 PS256 PS384 PS512 EdDSA Ed25519", resource_metadata="..."</c>
    /// with no <c>error</c> and no <c>Bearer</c> challenge, and the one field line
    /// <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResourceServerRequiringDpopChallengesARequestWithoutCredentialsWithTheDpopChallengeAloneAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey, requiresDpop: true).ConfigureAwait(false);

        HttpResponseData response = await RawHttpsRequest.SendPinnedAsync(
            rs.HttpCertificate!, WellKnownHttpMethods.Get, new Uri(rs.HttpBaseAddress!, "/protected"), [],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            ResourceDpopChallenge(rs, error: null),
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        Assert.AreEqual(string.Empty, response.Body, "No error code or other error information.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.1">RFC 9110 Section 11.1</see>: "It uses a
    /// case-insensitive token to identify the authentication scheme:", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "A DPoP-bound access
    /// token is sent using the Authorization request header field per Section 11.6.2 of [RFC9110] with an authentication
    /// scheme of DPoP." At an application's resource that requires DPoP-bound access tokens, an access token bound by
    /// <c>cnf.jkt</c> to a key, presented over a raw TLS connection under the scheme spelled <c>dpop</c> with a proof
    /// signed by that key and carrying the nonce the resource provided, is read as a <c>DPoP</c> presentation and served:
    /// 200 with the token's <c>cnf</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResourceServerRequiringDpopReadsALowerCaseDpopSchemeAsTheDpopSchemeAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey, requiresDpop: true).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(dpopKey)).ConfigureAwait(false);
        string nonce = await ObtainResourceNonceWithANonceLessProofAsync(rs, dpopKey, token).ConfigureAwait(false);
        string proof = await BuildResourceProofAsync(rs, dpopKey, token, nonce).ConfigureAwait(false);

        HttpResponseData response = await SendProtectedOverARawConnectionAsync(rs, $"dpop {token}", [proof]).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual(ThumbprintOf(dpopKey), document.RootElement.GetProperty("cnf").GetProperty("jkt").GetString(), response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "credentials = "DPoP"
    /// 1*SP token68", and <see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 Section 2.1</see>:
    /// "credentials = "Bearer" 1*SP b64token", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section 11.2</see>:
    /// "token68        = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="";
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_request The
    /// request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same
    /// parameter, uses more than one method for including an access token, or is otherwise malformed. The resource server
    /// SHOULD respond with the HTTP 400 (Bad Request) status code."; and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "If the mechanism used
    /// to attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be used to
    /// deliver error information (Figure 18)." An <c>Authorization</c> field line sent to the application's resource
    /// over a raw TLS connection naming a scheme with the credentials <c>abc def</c>, which are no token68, attempts that
    /// scheme with a malformed credential, and the resource never asks its verification-key resolver for a key. The rows:
    /// at a resource requiring DPoP-bound access tokens, the <c>DPoP</c> scheme, answered 400 with the body
    /// <c>{"error":"invalid_request","error_description":"The Authorization header credentials are not a token68."}</c>,
    /// the one challenge <c>DPoP realm="protected", error="invalid_request", algs="...", resource_metadata="..."</c> and
    /// the one field line <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>; at a resource that does not
    /// require them, the <c>Bearer</c> scheme, answered 400 with the same body, the one challenge
    /// <c>Bearer realm="protected", error="invalid_request", resource_metadata="..."</c> and no
    /// <c>Access-Control-Expose-Headers</c> field; at a resource requiring DPoP-bound access tokens, the <c>Bearer</c>
    /// scheme, a method the resource does not accept, answered 401 with an empty body, the one challenge
    /// <c>DPoP realm="protected", algs="...", resource_metadata="..."</c> with no <c>error</c> and the exposure field
    /// (RFC 6750 Section 3.1: "If the request lacks any authentication information (e.g., the client was unaware that
    /// authentication is necessary or attempted using an unsupported authentication method), the resource server SHOULD
    /// NOT include an error code or other error information.").
    /// </summary>
    /// <param name="row">The resource and the scheme: <see cref="RequiredDpopCredentialRow"/>, <see cref="BearerCredentialRow"/> or <see cref="RequiredBearerCredentialRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(RequiredDpopCredentialRow)]
    [DataRow(BearerCredentialRow)]
    [DataRow(RequiredBearerCredentialRow)]
    public async Task ResourceServerAnswersACredentialThatIsNoToken68ByItsSchemeAsync(string row)
    {
        (bool requiresDpop, string scheme) = row switch
        {
            RequiredDpopCredentialRow => (true, "DPoP"),
            BearerCredentialRow => (false, "Bearer"),
            RequiredBearerCredentialRow => (true, "Bearer"),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown credential row.")
        };
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        ConcurrentQueue<KeyUsageContext> resolverCalls = new();
        await using TestResourceServerShell rs = new(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(asKeys.PublicKey, resolverCalls),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: new FakeTimeProvider(NowInstant),
            requiresDpop: requiresDpop);
        await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        HttpResponseData response = await SendProtectedOverARawConnectionAsync(rs, $"{scheme} abc def", []).ConfigureAwait(false);

        string expectedChallenge = row switch
        {
            RequiredDpopCredentialRow => ResourceDpopChallenge(rs, "invalid_request"),
            BearerCredentialRow => $"Bearer realm=\"protected\", error=\"invalid_request\", resource_metadata=\"{rs.MetadataUrl!.OriginalString}\"",
            _ => ResourceDpopChallenge(rs, error: null)
        };
        Assert.AreEqual(row == RequiredBearerCredentialRow ? 401 : 400, response.StatusCode, response.Body);
        Assert.AreEqual(
            expectedChallenge,
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        IReadOnlyList<string> exposureFields = response.Headers.Headers.GetValues("Access-Control-Expose-Headers");
        if(row == BearerCredentialRow)
        {
            Assert.IsEmpty(exposureFields, "A Bearer challenge alone exposes no field.");
        }
        else
        {
            Assert.AreEqual(ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(exposureFields));
        }

        Assert.AreEqual(
            row == RequiredBearerCredentialRow
                ? string.Empty
                : "{\"error\":\"invalid_request\",\"error_description\":\"The Authorization header credentials are not a token68.\"}",
            response.Body);
        Assert.IsEmpty(resolverCalls, "The field carries no token: no key is resolved.");
    }


    /// <summary>
    /// The row whose resource requires DPoP-bound access tokens and whose field names the <c>DPoP</c> scheme. A constant,
    /// not a property, because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string RequiredDpopCredentialRow = "required-dpop-credential";

    /// <summary>
    /// The row whose resource does not require DPoP-bound access tokens and whose field names the <c>Bearer</c> scheme. A
    /// constant, not a property, because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string BearerCredentialRow = "bearer-credential";

    /// <summary>
    /// The row whose resource requires DPoP-bound access tokens and whose field names the <c>Bearer</c> scheme. A
    /// constant, not a property, because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string RequiredBearerCredentialRow = "required-bearer-credential";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.1">RFC 9110 Section 11.1</see>: "It uses a
    /// case-insensitive token to identify the authentication scheme:", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 Section 2.1</see>: "credentials =
    /// "Bearer" 1*SP b64token". At an application's resource that does not require DPoP-bound access tokens, an access
    /// token bound to no key, presented over a raw TLS connection under the scheme spelled <c>bearer</c>, is read as a
    /// <c>Bearer</c> presentation and served: 200 with the token's claims.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResourceServerReadsALowerCaseBearerSchemeAsTheBearerSchemeAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, boundThumbprint: null).ConfigureAwait(false);

        HttpResponseData response = await SendProtectedOverARawConnectionAsync(rs, $"bearer {token}", []).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual(Subject, document.RootElement.GetProperty("sub").GetString(), response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_request The
    /// request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same
    /// parameter, uses more than one method for including an access token, or is otherwise malformed. The resource
    /// server SHOULD respond with the HTTP 400 (Bad Request) status code.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.2">RFC 9110 Section 11.6.2</see>'s
    /// "Authorization = credentials", no list, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "If the mechanism used
    /// to attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be used to
    /// deliver error information (Figure 18)." and "Otherwise, both Bearer and DPoP challenges MAY be used to deliver
    /// error information (Figure 19).", where a protection space requiring DPoP authentication
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">Section 7.1</see>) accepts the <c>DPoP</c>
    /// mechanism alone. A request over a raw TLS connection to the application's resource with two
    /// <c>Authorization</c> field lines, each carrying an access token bound by <c>cnf.jkt</c>, is refused before any
    /// token is validated: 400, <c>invalid_request</c> and the description "The Authorization header is not a single
    /// well-formed credential." in the body, and one challenge carrying <c>error="invalid_request"</c>. The rows: at a
    /// resource requiring DPoP-bound access tokens, the lines <c>DPoP</c> then <c>Bearer</c>, answered with the
    /// <c>DPoP</c> challenge alone and the one field line
    /// <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>; at a resource that does not, the lines
    /// <c>DPoP</c> then <c>Bearer</c>, two mechanisms, answered with both challenges in the one field line
    /// <c>Bearer realm="protected", error="invalid_request", resource_metadata="...", DPoP realm="protected", error="invalid_request", algs="...", resource_metadata="..."</c>
    /// and the exposure field; at a resource that does not, the lines <c>DPoP</c> then <c>DPoP</c>, the one mechanism
    /// <c>DPoP</c>, answered with the <c>DPoP</c> challenge alone and the exposure field; at a resource that does not,
    /// the lines <c>Bearer</c> then <c>Bearer</c>, the one mechanism <c>Bearer</c>, answered with the <c>Bearer</c>
    /// challenge alone, <c>Bearer realm="protected", error="invalid_request", resource_metadata="..."</c>, and no
    /// <c>Access-Control-Expose-Headers</c> field.
    /// </summary>
    /// <param name="row">The resource and the lines: <see cref="RequiredDpopThenBearerLinesRow"/>, <see cref="DpopThenBearerLinesRow"/>, <see cref="TwoDpopLinesRow"/> or <see cref="TwoBearerLinesRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(RequiredDpopThenBearerLinesRow)]
    [DataRow(DpopThenBearerLinesRow)]
    [DataRow(TwoDpopLinesRow)]
    [DataRow(TwoBearerLinesRow)]
    public async Task ResourceServerAnswersAnAuthorizationFieldOnTwoLinesWithInvalidRequestAsync(string row)
    {
        (bool requiresDpop, string firstScheme, string secondScheme) = row switch
        {
            RequiredDpopThenBearerLinesRow => (true, "DPoP", "Bearer"),
            DpopThenBearerLinesRow => (false, "DPoP", "Bearer"),
            TwoDpopLinesRow => (false, "DPoP", "DPoP"),
            TwoBearerLinesRow => (false, "Bearer", "Bearer"),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown field lines row.")
        };
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey, requiresDpop: requiresDpop).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(dpopKey)).ConfigureAwait(false);

        HttpResponseData response = await RawHttpsRequest.SendPinnedAsync(
            rs.HttpCertificate!, WellKnownHttpMethods.Get, new Uri(rs.HttpBaseAddress!, "/protected"),
            [
                new(WellKnownHttpHeaderNames.Authorization, $"{firstScheme} {token}"),
                new(WellKnownHttpHeaderNames.Authorization, $"{secondScheme} {token}")
            ],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        string bearerChallenge =
            $"Bearer realm=\"protected\", error=\"invalid_request\", resource_metadata=\"{rs.MetadataUrl!.OriginalString}\"";
        string expectedChallenge = row switch
        {
            DpopThenBearerLinesRow => $"{bearerChallenge}, {ResourceDpopChallenge(rs, "invalid_request")}",
            TwoBearerLinesRow => bearerChallenge,
            _ => ResourceDpopChallenge(rs, "invalid_request")
        };
        Assert.AreEqual(
            expectedChallenge,
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        IReadOnlyList<string> exposureFields = response.Headers.Headers.GetValues("Access-Control-Expose-Headers");
        if(row == TwoBearerLinesRow)
        {
            Assert.IsEmpty(exposureFields, "A Bearer challenge alone exposes no field.");
        }
        else
        {
            Assert.AreEqual(ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(exposureFields));
        }

        AssertRefusalDescription(response, "The Authorization header is not a single well-formed credential.");
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual("invalid_request", document.RootElement.GetProperty("error").GetString(), response.Body);
    }


    /// <summary>
    /// The row whose resource requires DPoP-bound access tokens and whose second field line names <c>Bearer</c>. A
    /// constant, not a property, because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string RequiredDpopThenBearerLinesRow = "required-dpop-then-bearer-lines";

    /// <summary>
    /// The row whose resource does not require DPoP-bound access tokens and whose second field line names <c>Bearer</c>.
    /// A constant, not a property, because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string DpopThenBearerLinesRow = "dpop-then-bearer-lines";

    /// <summary>
    /// The row whose resource does not require DPoP-bound access tokens and whose second field line names <c>DPoP</c>. A
    /// constant, not a property, because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string TwoDpopLinesRow = "two-dpop-lines";

    /// <summary>
    /// The row whose resource does not require DPoP-bound access tokens and whose two field lines both name <c>Bearer</c>.
    /// A constant, not a property, because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string TwoBearerLinesRow = "two-bearer-lines";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "a resource
    /// server MUST check that a DPoP proof was also received in the DPoP header field of the HTTP
    /// request, check the DPoP proof according to the rules in Section 4.3, and check that the public key
    /// of the DPoP proof matches the public key to which the access token is bound" and "The resource server MUST NOT
    /// grant access to the resource unless all checks are successful."; the nonce is the resource's own
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">Section 9</see>: "Resource servers can also choose
    /// to provide a nonce value to be included in DPoP proofs sent to them."), and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.3">Section 11.3</see>: "A server MUST NOT accept any
    /// DPoP proofs without the nonce claim when a DPoP nonce has been provided to the client." An access token bound by
    /// <c>cnf.jkt</c> to a key, presented at the application's resource over the wire under the <c>DPoP</c> scheme with
    /// a proof signed by that key and carrying no nonce, is answered with the nonce challenge; presented again with a
    /// proof carrying the nonce the resource provided, it is served: 200 with the token's <c>cnf</c>, and the proof's
    /// <c>jti</c> is recorded.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DpopBoundProtectedRequestWithMatchingProofReturns200()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);
        FakeTimeProvider time = new(NowInstant);

        await using TestResourceServerShell rs = new(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(asKeys.PublicKey),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: time);
        await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        string thumbprint = dpopKey.GetThumbprint(
            TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: Subject,
            scope: Scope,
            clientId: ClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: Issuer,
            audience: [Audience]);
        payload[WellKnownJwtClaimNames.Cnf] = new Dictionary<string, object>
        {
            [WellKnownJwtClaimNames.JwkThumbprint] = thumbprint
        };
        string token = await BuildAccessTokenAsync(asKeys.PrivateKey, payload).ConfigureAwait(false);

        string nonce = await ObtainResourceNonceWithANonceLessProofAsync(rs, dpopKey, token).ConfigureAwait(false);
        string proof = await BuildResourceProofAsync(rs, dpopKey, token, nonce).ConfigureAwait(false);

        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(rs.HttpCertificate!, rs.HttpBaseAddress);
        using HttpRequestMessage request = new(HttpMethod.Get, "/protected");
        request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", token);
        request.Headers.Add("DPoP", proof);

        using HttpResponseMessage response = await client.SendAsync(request, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode,
            $"DPoP-bound request must succeed. Body: {await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false)}");

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.IsTrue(doc.RootElement.TryGetProperty("cnf", out JsonElement cnf));
        Assert.AreEqual(thumbprint, cnf.GetProperty("jkt").GetString());

        Assert.AreEqual(1, rs.ReplayCache.Count);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "a resource server
    /// MUST check that a DPoP proof was also received in the DPoP header field of the HTTP request", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">Section 9</see>: "Resource servers use an HTTP 401
    /// (Unauthorized) error code with an accompanying WWW-Authenticate: DPoP value and DPoP-Nonce value to accomplish
    /// this." A DPoP-bound access token presented at the application's resource over a raw TLS connection under the
    /// <c>DPoP</c> scheme with no <c>DPoP</c> field is answered with the resource's nonce challenge: 401,
    /// <c>use_dpop_nonce</c> in the body, the one challenge
    /// <c>DPoP realm="protected", error="use_dpop_nonce", algs="ES256 ES384 ES512 ES256K RS256 RS384 RS512 PS256 PS384 PS512 EdDSA Ed25519", resource_metadata="..."</c>,
    /// one <c>DPoP-Nonce</c> field line carrying a nonce, and the one field line
    /// <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResourceServerChallengesADpopPresentationWithoutAProofForItsNonceAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(dpopKey)).ConfigureAwait(false);

        HttpResponseData response = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", []).ConfigureAwait(false);

        AssertResourceRefusal(rs, response, "use_dpop_nonce");
        Assert.IsFalse(
            string.IsNullOrEmpty(Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.DPoPNonce))),
            "The one DPoP-Nonce field line carries a nonce.");
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.3">RFC 9449 Section 11.3</see>: "A server MUST NOT
    /// accept any DPoP proofs without the nonce claim when a DPoP nonce has been provided to the client.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">Section 9</see>: "Resource servers use an HTTP 401
    /// (Unauthorized) error code with an accompanying WWW-Authenticate: DPoP value and DPoP-Nonce value to accomplish
    /// this." A DPoP-bound access token presented at the application's resource over a raw TLS connection with a proof
    /// signed by the bound key and carrying no nonce claim is not served: 401, <c>use_dpop_nonce</c> in the body, the one
    /// challenge <c>DPoP realm="protected", error="use_dpop_nonce", algs="...", resource_metadata="..."</c>, one
    /// <c>DPoP-Nonce</c> field line carrying a nonce, and the one field line
    /// <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResourceServerChallengesAProofWithoutItsNonceAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(dpopKey)).ConfigureAwait(false);
        string proof = await BuildResourceProofAsync(rs, dpopKey, token, nonce: null).ConfigureAwait(false);

        HttpResponseData response = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [proof]).ConfigureAwait(false);

        AssertResourceRefusal(rs, response, "use_dpop_nonce");
        Assert.IsFalse(
            string.IsNullOrEmpty(Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.DPoPNonce))),
            "The one DPoP-Nonce field line carries a nonce.");
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        Assert.AreEqual(0, rs.ReplayCache.Count, "A refused proof's jti is not recorded.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see>: "Note that the nonces
    /// provided by an authorization server and a resource server are different and should not be confused with one
    /// another since nonces will be only accepted by the server that issued them." The application's resource issues its
    /// nonces for the target URI it serves. A nonce it provided at one origin, presented over a raw TLS connection in a
    /// proof signed by the bound key after the resource names its target URIs under another origin, the proof's
    /// <c>htu</c> that origin's <c>/protected</c>, is not accepted: 401, <c>use_dpop_nonce</c> and the description
    /// "DPoP nonce invalid: AudienceMismatch." in the body, the one challenge
    /// <c>DPoP realm="protected", error="use_dpop_nonce", algs="...", resource_metadata="..."</c> and one
    /// <c>DPoP-Nonce</c> field line carrying a fresh nonce.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResourceServerRefusesANonceIssuedForAnotherTargetUriAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(dpopKey)).ConfigureAwait(false);
        string nonce = await ObtainResourceNonceWithANonceLessProofAsync(rs, dpopKey, token).ConfigureAwait(false);

        rs.TargetAuthority = new Uri("https://rs.example");
        string proof = await BuildResourceProofAsync(
            rs, dpopKey, token, nonce, htu: new Uri("https://rs.example/protected")).ConfigureAwait(false);
        HttpResponseData response = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [proof]).ConfigureAwait(false);

        AssertResourceRefusal(rs, response, "use_dpop_nonce");
        AssertRefusalDescription(response, "DPoP nonce invalid: AudienceMismatch.");
        Assert.AreNotEqual(
            nonce, Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.DPoPNonce)),
            "The refusal provides a fresh nonce.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8.1">RFC 9449 Section 8.1</see>: "nonce = 1*NQCHAR", so
    /// an empty <c>nonce</c> claim carries no nonce, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.3">Section 11.3</see>: "A server MUST NOT accept any
    /// DPoP proofs without the nonce claim when a DPoP nonce has been provided to the client." At an application's
    /// resource whose proof validation answers a valid proof's claims with an empty <c>nonce</c>, a DPoP-bound access
    /// token presented over a raw TLS connection with that proof is answered with the resource's nonce challenge: 401,
    /// <c>use_dpop_nonce</c> and the description "DPoP nonce required." in the body, the one challenge
    /// <c>DPoP realm="protected", error="use_dpop_nonce", algs="...", resource_metadata="..."</c> and one
    /// <c>DPoP-Nonce</c> field line carrying a nonce.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResourceServerChallengesAProofWhoseNonceIsEmptyAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        await using TestResourceServerShell rs = await StartResourceServerAsync(
            asKeys.PublicKey, wrapDpopProofValidation: AnswerAnEmptyNonce).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(dpopKey)).ConfigureAwait(false);
        string proof = await BuildResourceProofAsync(rs, dpopKey, token, nonce: null).ConfigureAwait(false);

        HttpResponseData response = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [proof]).ConfigureAwait(false);

        AssertResourceRefusal(rs, response, "use_dpop_nonce");
        AssertRefusalDescription(response, "DPoP nonce required.");
        Assert.IsFalse(
            string.IsNullOrEmpty(Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.DPoPNonce))),
            "The one DPoP-Nonce field line carries a nonce.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "A DPoP-bound access
    /// token is sent using the Authorization request header field per Section 11.6.2 of [RFC9110] with an authentication
    /// scheme of DPoP." An access token bound to no key, presented at the application's resource over a raw TLS
    /// connection under the <c>DPoP</c> scheme, is no DPoP-bound access token and is refused: 401, <c>invalid_token</c>
    /// in the body and the one challenge <c>DPoP realm="protected", error="invalid_token", algs="...", resource_metadata="..."</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResourceServerRefusesAnUnboundTokenPresentedUnderDpopAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, boundThumbprint: null).ConfigureAwait(false);

        HttpResponseData response = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", []).ConfigureAwait(false);

        AssertResourceRefusal(rs, response, "invalid_token");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 12: "confirm
    /// that the public key to which the access token is bound matches the public key from the DPoP proof", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">Section 7.1</see>: "check that the public key of
    /// the DPoP proof matches the public key to which the access token is bound per Section 6." A DPoP-bound access
    /// token presented at the application's resource over a raw TLS connection with a proof signed by another DPoP key and
    /// carrying the nonce the resource provided is refused: 401, <c>invalid_token</c> in the body and the one challenge
    /// <c>DPoP realm="protected", error="invalid_token", algs="...", resource_metadata="..."</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResourceServerRefusesAProofByAKeyOtherThanTheBoundOneAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey boundKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        DpopKey otherKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(boundKey)).ConfigureAwait(false);
        string nonce = await ObtainResourceNonceAsync(rs, token).ConfigureAwait(false);
        string proof = await BuildResourceProofAsync(rs, otherKey, token, nonce).ConfigureAwait(false);

        HttpResponseData response = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [proof]).ConfigureAwait(false);

        AssertResourceRefusal(rs, response, "invalid_token");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>: "To validate a DPoP
    /// proof, the receiving server MUST ensure the following: 1. There is not more than one DPoP HTTP request header
    /// field." A DPoP-bound access token presented at the application's resource over a raw TLS connection with two
    /// <c>DPoP</c> field lines, each a proof signed by the bound key, is refused: 401, <c>invalid_dpop_proof</c> and the
    /// description "More than one DPoP header field was presented." in the body, and the one challenge
    /// <c>DPoP realm="protected", error="invalid_dpop_proof", algs="...", resource_metadata="..."</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResourceServerRefusesTwoDpopFieldsAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(dpopKey)).ConfigureAwait(false);
        string firstProof = await BuildResourceProofAsync(rs, dpopKey, token, nonce: null).ConfigureAwait(false);
        string secondProof = await BuildResourceProofAsync(rs, dpopKey, token, nonce: null).ConfigureAwait(false);

        HttpResponseData response = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [firstProof, secondProof]).ConfigureAwait(false);

        AssertResourceRefusal(rs, response, "invalid_dpop_proof");
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual("More than one DPoP header field was presented.", document.RootElement.GetProperty("error_description").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "The resource server
    /// MUST NOT grant access to the resource unless all checks are successful.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1">RFC 9110 Section 15.6.1</see>: "The 500
    /// (Internal Server Error) status code indicates that the server encountered an unexpected condition that prevented
    /// it from fulfilling the request." At an application's resource with a check of the token's binding unwired, a
    /// DPoP-bound access token presented over a raw TLS connection with a proof signed by the bound key cannot be checked
    /// and is not served: 500, <c>server_error</c> in the body and no <c>WWW-Authenticate</c> field. The rows: the
    /// resource wires no DPoP proof validation and no nonce issuance or validation, its <c>jti</c> consultation wired; the
    /// resource wires the proof validation and the nonce slots and no <c>jti</c> consultation.
    /// </summary>
    /// <param name="row">The unwired checks: <see cref="ProofAndNonceUnwiredRow"/> or <see cref="JtiRecordUnwiredRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(ProofAndNonceUnwiredRow)]
    [DataRow(JtiRecordUnwiredRow)]
    public async Task ResourceServerWithoutProofValidationAnswersABoundTokenWithAServerErrorAsync(string row)
    {
        (bool isDpopProofValidationWired, bool isDpopProofJtiRecordWired) = row switch
        {
            ProofAndNonceUnwiredRow => (false, true),
            JtiRecordUnwiredRow => (true, false),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown wiring row.")
        };
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        await using TestResourceServerShell rs = await StartResourceServerAsync(
            asKeys.PublicKey,
            isDpopProofValidationWired: isDpopProofValidationWired,
            isDpopProofJtiRecordWired: isDpopProofJtiRecordWired).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(dpopKey)).ConfigureAwait(false);
        string proof = await BuildResourceProofAsync(rs, dpopKey, token, nonce: null).ConfigureAwait(false);

        HttpResponseData response = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [proof]).ConfigureAwait(false);

        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.IsEmpty(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate), "A server error carries no challenge.");
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual("server_error", document.RootElement.GetProperty("error").GetString(), response.Body);
    }


    /// <summary>
    /// The row whose resource wires no DPoP proof validation and no nonce issuance or validation. A constant, not a
    /// property, because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string ProofAndNonceUnwiredRow = "proof-and-nonce-unwired";

    /// <summary>
    /// The row whose resource wires no <c>jti</c> consultation. A constant, not a property, because a DataRow attribute
    /// argument must be a compile-time constant.
    /// </summary>
    private const string JtiRecordUnwiredRow = "jti-record-unwired";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "HTTP
    /// requests to the same URI for which the jti value has been seen before would be declined." A proof carrying the
    /// nonce the application's resource provided, which the resource served once, presented again over the wire with the
    /// same token, is refused with 401 and the one challenge
    /// <c>DPoP realm="protected", error="invalid_dpop_proof", algs="...", resource_metadata="..."</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DpopBoundProofReplayedReturns401()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);
        FakeTimeProvider time = new(NowInstant);

        await using TestResourceServerShell rs = new(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(asKeys.PublicKey),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: time);
        await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        string thumbprint = dpopKey.GetThumbprint(
            TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: Subject,
            scope: Scope,
            clientId: ClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: Issuer,
            audience: [Audience]);
        payload[WellKnownJwtClaimNames.Cnf] = new Dictionary<string, object>
        {
            [WellKnownJwtClaimNames.JwkThumbprint] = thumbprint
        };
        string token = await BuildAccessTokenAsync(asKeys.PrivateKey, payload).ConfigureAwait(false);

        string nonce = await ObtainResourceNonceWithANonceLessProofAsync(rs, dpopKey, token).ConfigureAwait(false);
        string proof = await BuildResourceProofAsync(rs, dpopKey, token, nonce).ConfigureAwait(false);

        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(rs.HttpCertificate!, rs.HttpBaseAddress);

        //First call: should succeed and seed the replay tracker.
        using HttpRequestMessage firstRequest = new(HttpMethod.Get, "/protected");
        firstRequest.Headers.Authorization = new AuthenticationHeaderValue("DPoP", token);
        firstRequest.Headers.Add("DPoP", proof);
        using HttpResponseMessage firstResponse = await client.SendAsync(firstRequest, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, firstResponse.StatusCode);

        //Second call with the SAME proof: replayed, must be rejected.
        using HttpRequestMessage replayRequest = new(HttpMethod.Get, "/protected");
        replayRequest.Headers.Authorization = new AuthenticationHeaderValue("DPoP", token);
        replayRequest.Headers.Add("DPoP", proof);
        using HttpResponseMessage replayResponse = await client.SendAsync(replayRequest, TestContext.CancellationToken)
            .ConfigureAwait(false);

        string replayBody = await replayResponse.Content.ReadAsStringAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, replayResponse.StatusCode,
            $"Replayed proof must return 401; body was: {replayBody}");
        Assert.IsTrue(replayResponse.Headers.NonValidated.TryGetValues("WWW-Authenticate", out HeaderStringValues values),
            "The refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual(ResourceDpopChallenge(rs, "invalid_dpop_proof"), Assert.ContainsSingle(values));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "In the context of
    /// the target URI, servers can store the jti value of each DPoP proof for the time window in which the respective
    /// DPoP proof JWT would be accepted to prevent multiple uses of the same DPoP proof. HTTP requests to the same URI for
    /// which the jti value has been seen before would be declined.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">Section 4.2</see>, <c>htu</c>: "The HTTP target URI
    /// (Section 7.1 of [RFC9110]) of the request to which the JWT is attached". A proof for one target URI is another
    /// proof than a proof for a second. At an application's resource serving two protected paths, a DPoP-bound access
    /// token presented over a raw TLS connection at <c>/protected</c> with a proof carrying the <c>jti</c>
    /// <c>shared-jti</c> and the nonce the resource provided there is served 200; presented at
    /// <c>/protected/records</c> with a fresh proof naming that path in its <c>htu</c>, carrying the same <c>jti</c> and
    /// the nonce the resource provided for that path, it is served 200 as well, and the record holds one entry for each
    /// target URI.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DpopProofJtiRecordedAtOneTargetUriIsServedAtAnotherAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(dpopKey)).ConfigureAwait(false);

        string firstNonce = await ObtainResourceNonceWithANonceLessProofAsync(rs, dpopKey, token).ConfigureAwait(false);
        string firstProof = await BuildResourceProofAsync(rs, dpopKey, token, firstNonce, jti: SharedJti).ConfigureAwait(false);
        HttpResponseData first = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [firstProof]).ConfigureAwait(false);
        Assert.AreEqual(200, first.StatusCode, first.Body);

        string secondNonce = await ObtainResourceNonceWithANonceLessProofAsync(rs, dpopKey, token, SecondProtectedPath).ConfigureAwait(false);
        string secondProof = await BuildResourceProofAsync(
            rs, dpopKey, token, secondNonce, jti: SharedJti, htu: new Uri(rs.HttpBaseAddress!, SecondProtectedPath)).ConfigureAwait(false);
        HttpResponseData second = await SendProtectedOverARawConnectionAsync(
            rs, $"DPoP {token}", [secondProof], SecondProtectedPath).ConfigureAwait(false);

        Assert.AreEqual(200, second.StatusCode, second.Body);
        Assert.AreEqual(2, rs.ReplayCache.Count, "The jti is recorded once in the context of each target URI.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "HTTP requests to
    /// the same URI for which the jti value has been seen before would be declined.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>: "servers SHOULD employ
    /// syntax-based normalization (Section 6.2.2 of [RFC3986]) and scheme-based normalization (Section 6.2.3 of
    /// [RFC3986]) before comparing the htu claim.", where
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.1">RFC 3986 Section 6.2.2.1</see> reads "For all
    /// URIs, the hexadecimal digits within a percent-encoding triplet (e.g., "%3a" versus "%3A") are case-insensitive".
    /// The paths <c>/protected/items/a%2Fb</c> and <c>/protected/items/a%2fb</c> name one target URI. At an application's
    /// resource serving its item route, a DPoP-bound access token presented over a raw TLS connection at
    /// <c>/protected/items/a%2Fb</c> with a proof carrying the <c>jti</c> <c>shared-jti</c> and the nonce the resource
    /// provided there is served 200; presented at <c>/protected/items/a%2fb</c> with a proof naming that spelling in its
    /// <c>htu</c>, carrying the same <c>jti</c> and the nonce the resource provided for that spelling, it is refused with
    /// 401, <c>invalid_dpop_proof</c> and the description "The DPoP proof jti has been presented previously." in the body
    /// and the one challenge <c>DPoP realm="protected", error="invalid_dpop_proof", algs="...", resource_metadata="..."</c>,
    /// the record holds one entry, and the application's store was handed the one normalized target
    /// <c>https://&lt;listener&gt;/protected/items/a%2Fb</c> at both presentations.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DpopProofJtiPresentedAtTwoSpellingsOfOneTargetUriIsServedOnceAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        ConcurrentQueue<string> claimedTargets = new();
        await using TestResourceServerShell rs = await StartResourceServerAsync(
            asKeys.PublicKey, wrapDpopProofJtiClaim: RecordEveryClaimedTarget(claimedTargets)).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(dpopKey)).ConfigureAwait(false);

        string firstNonce = await ObtainResourceNonceWithANonceLessProofAsync(rs, dpopKey, token, UpperCaseHexItemPath).ConfigureAwait(false);
        string firstProof = await BuildResourceProofAsync(
            rs, dpopKey, token, firstNonce, jti: SharedJti, htu: new Uri(rs.HttpBaseAddress!, UpperCaseHexItemPath)).ConfigureAwait(false);
        HttpResponseData first = await SendProtectedOverARawConnectionAsync(
            rs, $"DPoP {token}", [firstProof], UpperCaseHexItemPath).ConfigureAwait(false);
        Assert.AreEqual(200, first.StatusCode, first.Body);

        string secondNonce = await ObtainResourceNonceWithANonceLessProofAsync(rs, dpopKey, token, LowerCaseHexItemPath).ConfigureAwait(false);
        string secondProof = await BuildResourceProofAsync(
            rs, dpopKey, token, secondNonce, jti: SharedJti, htu: new Uri(rs.HttpBaseAddress!, LowerCaseHexItemPath)).ConfigureAwait(false);
        HttpResponseData second = await SendProtectedOverARawConnectionAsync(
            rs, $"DPoP {token}", [secondProof], LowerCaseHexItemPath).ConfigureAwait(false);

        AssertResourceRefusal(rs, second, "invalid_dpop_proof");
        AssertRefusalDescription(second, "The DPoP proof jti has been presented previously.");
        Assert.AreEqual(1, rs.ReplayCache.Count, "The jti is recorded once for the one target URI.");
        string normalizedTarget = rs.ResourceIdentity!.OriginalString + UpperCaseHexItemPath;
        string[] targets = [.. claimedTargets];
        Assert.HasCount(2, targets, "Each presentation claims the proof's jti once.");
        Assert.AreEqual(normalizedTarget, targets[0], "The store is handed the normalized target at the first presentation.");
        Assert.AreEqual(normalizedTarget, targets[1], "The store is handed the same normalized target at the second presentation.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "HTTP requests to
    /// the same URI for which the jti value has been seen before would be declined.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>: "servers SHOULD employ
    /// syntax-based normalization (Section 6.2.2 of [RFC3986]) and scheme-based normalization (Section 6.2.3 of
    /// [RFC3986]) before comparing the htu claim.", where
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.1">RFC 3986 Section 6.2.2.1</see> reads "For all
    /// URIs, the hexadecimal digits within a percent-encoding triplet (e.g., "%3a" versus "%3A") are case-insensitive".
    /// The paths <c>/protected/items/a%2Fb</c> and <c>/protected/items/a%2fb</c> name one target URI, at which the
    /// resource accepts its nonces. One proof, naming <c>/protected/items/a%2Fb</c> in its <c>htu</c> and carrying the
    /// nonce the resource provided there, presented with its DPoP-bound access token over a raw TLS connection at
    /// <c>/protected/items/a%2Fb</c> is served 200; the same proof, unchanged, presented at
    /// <c>/protected/items/a%2fb</c> is refused with 401, <c>invalid_dpop_proof</c> and the description "The DPoP proof
    /// jti has been presented previously." in the body and the one challenge
    /// <c>DPoP realm="protected", error="invalid_dpop_proof", algs="...", resource_metadata="..."</c>, and the record
    /// holds one entry.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task OneUnchangedProofPresentedAtTwoSpellingsOfOneTargetUriIsServedOnceAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(dpopKey)).ConfigureAwait(false);
        string nonce = await ObtainResourceNonceWithANonceLessProofAsync(rs, dpopKey, token, UpperCaseHexItemPath).ConfigureAwait(false);
        string proof = await BuildResourceProofAsync(
            rs, dpopKey, token, nonce, htu: new Uri(rs.HttpBaseAddress!, UpperCaseHexItemPath)).ConfigureAwait(false);

        HttpResponseData first = await SendProtectedOverARawConnectionAsync(
            rs, $"DPoP {token}", [proof], UpperCaseHexItemPath).ConfigureAwait(false);
        HttpResponseData second = await SendProtectedOverARawConnectionAsync(
            rs, $"DPoP {token}", [proof], LowerCaseHexItemPath).ConfigureAwait(false);

        Assert.AreEqual(200, first.StatusCode, first.Body);
        AssertResourceRefusal(rs, second, "invalid_dpop_proof");
        AssertRefusalDescription(second, "The DPoP proof jti has been presented previously.");
        Assert.AreEqual(1, rs.ReplayCache.Count, "The jti is recorded once for the one target URI.");
    }


    /// <summary>
    /// Wraps a resource server's <c>jti</c> claim so it records the text of every target URI it is handed in
    /// <paramref name="claimedTargets"/> before handing the claim on: an application's store keying by that text.
    /// </summary>
    /// <param name="claimedTargets">Receives <see cref="Uri.OriginalString"/> of every claimed target URI, in claim order.</param>
    /// <returns>The wrapper recording each target before delegating to the claim it wraps.</returns>
    private static Func<ConsultDpopProofJtiDelegate, ConsultDpopProofJtiDelegate> RecordEveryClaimedTarget(
        ConcurrentQueue<string> claimedTargets) =>
        claim => (jti, targetUri, recordUntil, context, cancellationToken) =>
        {
            claimedTargets.Enqueue(targetUri.OriginalString);

            return claim(jti, targetUri, recordUntil, context, cancellationToken);
        };


    /// <summary>The item path whose percent-encoding names its hexadecimal digits in upper case.</summary>
    private static string UpperCaseHexItemPath { get; } = "/protected/items/a%2Fb";

    /// <summary>The item path whose percent-encoding names its hexadecimal digits in lower case, the same target URI.</summary>
    private static string LowerCaseHexItemPath { get; } = "/protected/items/a%2fb";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "The resource server
    /// MUST NOT grant access to the resource unless all checks are successful.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1">RFC 9110 Section 15.6.1</see>: "The 500
    /// (Internal Server Error) status code indicates that the server encountered an unexpected condition that prevented
    /// it from fulfilling the request." At an application's resource whose <c>jti</c> store records no first use of a
    /// proof, a DPoP-bound access token presented over a raw TLS connection with a proof carrying the nonce the resource
    /// provided is not served: 500, no <c>WWW-Authenticate</c> field and exactly the body
    /// <c>{"error":"server_error","error_description":"&lt;description&gt;"}</c>, which carries no claim. The rows: the
    /// store answers that it cannot record the proof, the description "The DPoP proof jti store could not record the
    /// proof."; the store answers an outcome the resource does not name, the description "The DPoP proof jti consultation
    /// answered an outcome this resource does not recognize.".
    /// </summary>
    /// <param name="row">The store's answer: <see cref="StoreCannotRecordRow"/> or <see cref="UnnamedOutcomeRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(StoreCannotRecordRow)]
    [DataRow(UnnamedOutcomeRow)]
    public async Task ResourceServerAnswersAJtiStoreRecordingNoFirstUseWithAServerErrorAsync(string row)
    {
        (JtiReplayOutcome outcome, string description) = row switch
        {
            StoreCannotRecordRow => (JtiReplayOutcome.StoreUnavailable, "The DPoP proof jti store could not record the proof."),
            UnnamedOutcomeRow => ((JtiReplayOutcome)UnnamedJtiOutcomeValue,
                "The DPoP proof jti consultation answered an outcome this resource does not recognize."),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown store answer row.")
        };
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        await using TestResourceServerShell rs = await StartResourceServerAsync(
            asKeys.PublicKey, wrapDpopProofJtiClaim: AnswerEveryClaimWith(outcome)).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(dpopKey)).ConfigureAwait(false);
        string nonce = await ObtainResourceNonceWithANonceLessProofAsync(rs, dpopKey, token).ConfigureAwait(false);
        string proof = await BuildResourceProofAsync(rs, dpopKey, token, nonce).ConfigureAwait(false);

        HttpResponseData response = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [proof]).ConfigureAwait(false);

        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.IsEmpty(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate), "A server error carries no challenge.");
        Assert.AreEqual($"{{\"error\":\"server_error\",\"error_description\":\"{description}\"}}", response.Body);
    }


    /// <summary>
    /// The row whose <c>jti</c> store answers that it cannot record the proof. A constant, not a property, because a
    /// DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string StoreCannotRecordRow = "store-cannot-record";

    /// <summary>
    /// The row whose <c>jti</c> store answers an outcome the resource does not name. A constant, not a property, because a
    /// DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string UnnamedOutcomeRow = "unnamed-outcome";

    /// <summary>A value of <see cref="JtiReplayOutcome"/> that names none of its members.</summary>
    private static int UnnamedJtiOutcomeValue { get; } = 99;


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "In order to guard
    /// against memory exhaustion attacks, a server that is tracking jti values should reject DPoP proof JWTs with
    /// unnecessarily large jti values or store only a hash thereof." At an application's resource whose <c>jti</c> store
    /// answers that it cannot hold a proof's <c>jti</c> by a rule of its own, a DPoP-bound access token presented over a
    /// raw TLS connection with a proof carrying the nonce the resource provided is refused with 401,
    /// <c>invalid_dpop_proof</c> and the description "DPoP proof jti is empty, too long or carries a character the replay
    /// guard cannot store." in the body, the one challenge
    /// <c>DPoP realm="protected", error="invalid_dpop_proof", algs="...", resource_metadata="..."</c>, and no claim.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResourceServerRefusesAProofWhoseJtiItsStoreCannotHoldAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        await using TestResourceServerShell rs = await StartResourceServerAsync(
            asKeys.PublicKey, wrapDpopProofJtiClaim: AnswerEveryClaimWith(JtiReplayOutcome.Unacceptable)).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(dpopKey)).ConfigureAwait(false);
        string nonce = await ObtainResourceNonceWithANonceLessProofAsync(rs, dpopKey, token).ConfigureAwait(false);
        string proof = await BuildResourceProofAsync(rs, dpopKey, token, nonce).ConfigureAwait(false);

        HttpResponseData response = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [proof]).ConfigureAwait(false);

        AssertResourceRefusal(rs, response, "invalid_dpop_proof");
        AssertRefusalDescription(response, "DPoP proof jti is empty, too long or carries a character the replay guard cannot store.");
    }


    /// <summary>
    /// Wraps a resource server's <c>jti</c> claim so it answers <paramref name="outcome"/> to every claim and records
    /// nothing: an application's own store answering in its place.
    /// </summary>
    /// <param name="outcome">The outcome every claim is answered with.</param>
    /// <returns>The wrapper answering that outcome whatever claim it is handed.</returns>
    private static Func<ConsultDpopProofJtiDelegate, ConsultDpopProofJtiDelegate> AnswerEveryClaimWith(JtiReplayOutcome outcome) =>
        _ => (_, _, _, _, _) => ValueTask.FromResult(outcome);


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "If the request lacks
    /// any authentication information (e.g., the client was unaware that authentication is necessary or attempted using
    /// an unsupported authentication method), the resource server SHOULD NOT include an error code or other error
    /// information.", with <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>:
    /// "If no authentication information has been included with the request, then the challenges SHOULD NOT include an
    /// error code or other error information, as per Section 3.1 of [RFC6750] (Figure 17)." At an application's resource
    /// that does not require DPoP-bound access tokens, a request sent over a raw TLS connection with no
    /// <c>Authorization</c> field, or whose one <c>Authorization</c> field line names a scheme and carries no access token,
    /// is answered as one without credentials, as the library's resources answer it: 401, an empty body, and the one field
    /// line
    /// <c>WWW-Authenticate: Bearer realm="protected", resource_metadata="...", DPoP realm="protected", algs="...", resource_metadata="..."</c>
    /// with no <c>error</c>, and <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>. The rows: no
    /// <c>Authorization</c> field; the line <c>Bearer</c>; the line <c>DPoP</c>; the line <c>Basic xyz</c>, an
    /// unsupported scheme.
    /// </summary>
    /// <param name="authorization">The <c>Authorization</c> field line, or <see langword="null"/> for no such field.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow((string?)null, DisplayName = "no Authorization field")]
    [DataRow("Bearer", DisplayName = "the Bearer scheme alone")]
    [DataRow("DPoP", DisplayName = "the DPoP scheme alone")]
    [DataRow("Basic xyz", DisplayName = "an unsupported scheme")]
    public async Task ResourceServerAnswersAnAuthorizationFieldCarryingNoAccessTokenAsMissingCredentialsAsync(string? authorization)
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey).ConfigureAwait(false);

        HttpResponseData response = await SendProtectedOverARawConnectionAsync(rs, authorization, []).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            $"Bearer realm=\"protected\", resource_metadata=\"{rs.MetadataUrl!.OriginalString}\", {ResourceDpopChallenge(rs, null)}",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields,
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.AccessControlExposeHeaders)));
        Assert.AreEqual(string.Empty, response.Body, "No error code or other error information.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "HTTP requests to
    /// the same URI for which the jti value has been seen before would be declined." and "When strictly enforced, such a
    /// single-use check provides a very strong protection against DPoP proof replay". One proof, carrying the nonce the
    /// application's resource provided, presented with its DPoP-bound access token over eight raw TLS connections started
    /// together and awaited together, is served once: exactly one presentation is answered 200 and exactly seven are
    /// answered 401 with <c>invalid_dpop_proof</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task OneProofPresentedConcurrentlyIsServedOnceAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(dpopKey)).ConfigureAwait(false);
        string nonce = await ObtainResourceNonceWithANonceLessProofAsync(rs, dpopKey, token).ConfigureAwait(false);
        string proof = await BuildResourceProofAsync(rs, dpopKey, token, nonce).ConfigureAwait(false);

        Task<HttpResponseData>[] presentations = [.. Enumerable.Range(0, ConcurrentPresentationCount)
            .Select(_ => SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [proof]))];
        HttpResponseData[] answers = await Task.WhenAll(presentations).ConfigureAwait(false);

        int servedCount = answers.Count(static answer => answer.StatusCode == 200);
        int replayRefusalCount = answers.Count(static answer => answer.StatusCode == 401 && IsRefusedWith(answer, "invalid_dpop_proof"));
        Assert.AreEqual(1, servedCount, "One presentation of the proof is served.");
        Assert.AreEqual(ConcurrentPresentationCount - 1, replayRefusalCount, "Every other presentation is refused as a replay.");
    }


    /// <summary>Whether the body of <paramref name="answer"/> is a JSON object whose <c>error</c> is <paramref name="error"/>.</summary>
    /// <param name="answer">The answer as received.</param>
    /// <param name="error">The error code.</param>
    /// <returns><see langword="true"/> when the body carries that error.</returns>
    private static bool IsRefusedWith(HttpResponseData answer, string error)
    {
        if(string.IsNullOrEmpty(answer.Body))
        {
            return false;
        }

        using JsonDocument document = JsonDocument.Parse(answer.Body);

        return document.RootElement.TryGetProperty("error", out JsonElement value)
            && string.Equals(value.GetString(), error, StringComparison.Ordinal);
    }


    /// <summary>The number of presentations of one proof started together.</summary>
    private static int ConcurrentPresentationCount { get; } = 8;

    /// <summary>The <c>jti</c> two proofs for two target URIs carry.</summary>
    private static string SharedJti { get; } = "shared-jti";

    /// <summary>The application resource's second protected path.</summary>
    private static string SecondProtectedPath { get; } = "/protected/records";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "In the context of
    /// the target URI, servers can store the jti value of each DPoP proof for the time window in which the respective
    /// DPoP proof JWT would be accepted to prevent multiple uses of the same DPoP proof. HTTP requests to the same URI for
    /// which the jti value has been seen before would be declined." The application's resource accepts a proof whose
    /// <c>iat</c> lies within 60 seconds of its clock either way. A proof whose <c>iat</c> lies 59 seconds ahead of the
    /// clock, carrying the nonce the resource provided, is served over a raw TLS connection; with the clock advanced 61
    /// seconds the proof is still within its acceptance window, and the same request replayed is refused: 401,
    /// <c>invalid_dpop_proof</c> and the description "The DPoP proof jti has been presented previously." in the body,
    /// and the one challenge <c>DPoP realm="protected", error="invalid_dpop_proof", algs="...", resource_metadata="..."</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DpopProofWithAFutureIatReplayedWithinItsAcceptanceWindowIsRefusedAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        FakeTimeProvider time = new(NowInstant);
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey, time: time).ConfigureAwait(false);
        Assert.AreEqual(TimeSpan.FromSeconds(60), rs.Integration.DpopFreshnessWindow, "The resource accepts an iat within 60 seconds of its clock.");
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(dpopKey)).ConfigureAwait(false);
        string nonce = await ObtainResourceNonceWithANonceLessProofAsync(rs, dpopKey, token).ConfigureAwait(false);
        string proof = await BuildResourceProofAsync(
            rs, dpopKey, token, nonce, issuedAt: NowInstant + TimeSpan.FromSeconds(59)).ConfigureAwait(false);

        HttpResponseData first = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [proof]).ConfigureAwait(false);
        Assert.AreEqual(200, first.StatusCode, first.Body);

        time.Advance(TimeSpan.FromSeconds(61));
        HttpResponseData replay = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [proof]).ConfigureAwait(false);

        AssertResourceRefusal(rs, replay, "invalid_dpop_proof");
        AssertRefusalDescription(replay, "The DPoP proof jti has been presented previously.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "In the context of
    /// the target URI, servers can store the jti value of each DPoP proof for the time window in which the respective
    /// DPoP proof JWT would be accepted to prevent multiple uses of the same DPoP proof. HTTP requests to the same URI for
    /// which the jti value has been seen before would be declined." The application's resource accepts a proof whose
    /// <c>iat</c> lies within 60 seconds of its clock either way, the 60th second included. A proof whose <c>iat</c> is
    /// the clock's instant, carrying the nonce the resource provided, is served over a raw TLS connection; with the clock
    /// advanced exactly 60 seconds, the last instant the proof is accepted at, the same request replayed is refused: 401,
    /// <c>invalid_dpop_proof</c> and the description "The DPoP proof jti has been presented previously." in the body,
    /// and the one challenge <c>DPoP realm="protected", error="invalid_dpop_proof", algs="...", resource_metadata="..."</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DpopProofReplayedAtTheLastInstantOfItsAcceptanceWindowIsRefusedAsync()
    {
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        FakeTimeProvider time = new(NowInstant);
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey, time: time).ConfigureAwait(false);
        Assert.AreEqual(TimeSpan.FromSeconds(60), rs.Integration.DpopFreshnessWindow, "The resource accepts an iat within 60 seconds of its clock.");
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(dpopKey)).ConfigureAwait(false);
        string nonce = await ObtainResourceNonceWithANonceLessProofAsync(rs, dpopKey, token).ConfigureAwait(false);
        string proof = await BuildResourceProofAsync(rs, dpopKey, token, nonce, issuedAt: NowInstant).ConfigureAwait(false);

        HttpResponseData first = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [proof]).ConfigureAwait(false);
        Assert.AreEqual(200, first.StatusCode, first.Body);

        time.Advance(TimeSpan.FromSeconds(60));
        HttpResponseData replay = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [proof]).ConfigureAwait(false);

        AssertResourceRefusal(rs, replay, "invalid_dpop_proof");
        AssertRefusalDescription(replay, "The DPoP proof jti has been presented previously.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "To limit this,
    /// servers MUST only accept DPoP proofs for a limited time after their creation (preferably only for a relatively
    /// brief period on the order of seconds or minutes).", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">Section 7.1</see>: "The resource server MUST NOT
    /// grant access to the resource unless all checks are successful." The application's resource holds a proof's
    /// <c>iat</c> to within 60 seconds of its clock either way, both bounds included, whatever tolerance its proof
    /// validation applies: a proof created more than the window ago is a proof accepted for longer than the limited time
    /// after its creation that section requires, and a proof dated ahead of the clock by more than the window is no
    /// proof of a recent creation. At a resource whose proof validation accepts an <c>iat</c> within 120 seconds of the
    /// clock, a DPoP-bound access token presented over a raw TLS connection with a proof signed by the bound key,
    /// carrying the nonce the resource provided and an <c>iat</c> 90 seconds away from the clock, is refused before
    /// anything is recorded: 401, <c>invalid_dpop_proof</c> and the description "DPoP proof iat lies outside the
    /// resource's freshness window." in the body, the one challenge
    /// <c>DPoP realm="protected", error="invalid_dpop_proof", algs="...", resource_metadata="..."</c>, and the record
    /// holds no entry; presented with a proof whose <c>iat</c> lies 60 seconds away from the clock, it is served: 200.
    /// The rows: the <c>iat</c> ahead of the clock; the <c>iat</c> behind it.
    /// </summary>
    /// <param name="row">The side of the clock the <c>iat</c> lies on: <see cref="FutureIatRow"/> or <see cref="PastIatRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(FutureIatRow)]
    [DataRow(PastIatRow)]
    public async Task DpopProofWhoseIatLiesOutsideTheResourcesFreshnessWindowIsRefusedAsync(string row)
    {
        int direction = row switch
        {
            FutureIatRow => 1,
            PastIatRow => -1,
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown iat row.")
        };
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        FakeTimeProvider time = new(NowInstant);
        await using TestResourceServerShell rs = await StartResourceServerAsync(
            asKeys.PublicKey, time: time, wrapDpopProofValidation: ValidateWithAnIatTolerance(time, TimeSpan.FromSeconds(120))).ConfigureAwait(false);
        Assert.AreEqual(TimeSpan.FromSeconds(60), rs.Integration.DpopFreshnessWindow, "The resource holds an iat to within 60 seconds of its clock.");
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(dpopKey)).ConfigureAwait(false);
        string nonce = await ObtainResourceNonceWithANonceLessProofAsync(rs, dpopKey, token).ConfigureAwait(false);
        string outsideProof = await BuildResourceProofAsync(
            rs, dpopKey, token, nonce, issuedAt: NowInstant + (direction * TimeSpan.FromSeconds(90))).ConfigureAwait(false);

        HttpResponseData refused = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [outsideProof]).ConfigureAwait(false);

        AssertResourceRefusal(rs, refused, "invalid_dpop_proof");
        AssertRefusalDescription(refused, "DPoP proof iat lies outside the resource's freshness window.");
        Assert.AreEqual(0, rs.ReplayCache.Count, "A refused proof's jti is not recorded.");

        string boundaryProof = await BuildResourceProofAsync(
            rs, dpopKey, token, nonce, issuedAt: NowInstant + (direction * TimeSpan.FromSeconds(60))).ConfigureAwait(false);
        HttpResponseData served = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [boundaryProof]).ConfigureAwait(false);

        Assert.AreEqual(200, served.StatusCode, served.Body);
    }


    /// <summary>
    /// The row whose proofs carry an <c>iat</c> ahead of the clock. A constant, not a property, because a DataRow
    /// attribute argument must be a compile-time constant.
    /// </summary>
    private const string FutureIatRow = "future-iat";

    /// <summary>
    /// The row whose proofs carry an <c>iat</c> behind the clock. A constant, not a property, because a DataRow
    /// attribute argument must be a compile-time constant.
    /// </summary>
    private const string PastIatRow = "past-iat";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "In order to guard
    /// against memory exhaustion attacks, a server that is tracking jti values should reject DPoP proof JWTs with
    /// unnecessarily large jti values or store only a hash thereof." The application's resource tracks a <c>jti</c> that
    /// is not empty, is at most 1024 UTF-16 code units long and holds no control character (Unicode category Cc) and no
    /// unpaired surrogate, the rule the library's resources apply. A DPoP-bound access
    /// token presented over a raw TLS connection with a proof signed by the bound key, carrying the nonce the resource
    /// provided and a <c>jti</c> the record cannot hold, is refused before anything is recorded: 401,
    /// <c>invalid_dpop_proof</c> and the description "DPoP proof jti is empty, too long or carries a character the replay
    /// guard cannot store." in the body, the one challenge
    /// <c>DPoP realm="protected", error="invalid_dpop_proof", algs="...", resource_metadata="..."</c>, and the record
    /// holds no entry. The rows: a <c>jti</c> of 1025 characters; a <c>jti</c> carrying U+0001.
    /// </summary>
    /// <param name="row">The <c>jti</c>: <see cref="OversizedJtiRow"/> or <see cref="ControlCharacterJtiRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(OversizedJtiRow)]
    [DataRow(ControlCharacterJtiRow)]
    public async Task ResourceServerRefusesAProofWhoseJtiTheRecordCannotHoldAsync(string row)
    {
        string jti = row switch
        {
            OversizedJtiRow => new string('j', 1025),
            ControlCharacterJtiRow => ControlCharacterJti,
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown jti row.")
        };
        var asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(TestKeyMaterialProvider.CreateFreshP256KeyMaterial(), WellKnownJwaValues.Es256);
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, ThumbprintOf(dpopKey)).ConfigureAwait(false);
        string nonce = await ObtainResourceNonceWithANonceLessProofAsync(rs, dpopKey, token).ConfigureAwait(false);
        string proof = await BuildResourceProofAsync(rs, dpopKey, token, nonce, jti: jti).ConfigureAwait(false);

        HttpResponseData response = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [proof]).ConfigureAwait(false);

        AssertResourceRefusal(rs, response, "invalid_dpop_proof");
        AssertRefusalDescription(response, "DPoP proof jti is empty, too long or carries a character the replay guard cannot store.");
        Assert.AreEqual(0, rs.ReplayCache.Count, "A jti the record cannot hold is not recorded.");
    }


    /// <summary>
    /// The row whose proof carries a <c>jti</c> of 1025 characters. A constant, not a property, because a DataRow
    /// attribute argument must be a compile-time constant.
    /// </summary>
    private const string OversizedJtiRow = "oversized-jti";

    /// <summary>
    /// The row whose proof carries a <c>jti</c> holding U+0001. A constant, not a property, because a DataRow attribute
    /// argument must be a compile-time constant.
    /// </summary>
    private const string ControlCharacterJtiRow = "control-character-jti";

    /// <summary>A <c>jti</c> holding the control character U+0001 between two visible runs.</summary>
    private static string ControlCharacterJti { get; } = "jti-\u0001-held";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>:
    /// "invalid_token The access token provided is expired, revoked, malformed, or invalid for other
    /// reasons. The resource SHOULD respond with the HTTP 401 (Unauthorized) status code." An access
    /// token whose protected header's <c>kid</c> is a single space names no key and is malformed: the
    /// resource server validating it with <see cref="Verifiable.OAuth.JwsAccessTokenValidator"/> refuses it over the wire
    /// with 401 and a <c>Bearer</c> challenge carrying <c>error="invalid_token"</c>, never a server
    /// error.
    /// </summary>
    [TestMethod]
    public async Task AccessTokenWithWhitespaceKidReturns401()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        FakeTimeProvider time = new(NowInstant);

        await using TestResourceServerShell rs = new(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(keys.PublicKey),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: time);
        await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: Subject,
            scope: Scope,
            clientId: ClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: Issuer,
            audience: [Audience]);
        string token = await BuildAccessTokenAsync(keys.PrivateKey, payload, kid: " ").ConfigureAwait(false);

        using HttpResponseMessage response = await SendProtectedRequestAsync(rs, token).ConfigureAwait(false);

        await AssertInvalidTokenChallengeAsync(rs, response, "JWS header is missing the kid member.").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>:
    /// "invalid_token The access token provided is expired, revoked, malformed, or invalid for other
    /// reasons. The resource SHOULD respond with the HTTP 401 (Unauthorized) status code." An access
    /// token whose <c>exp</c> is 9223372036854775807, a NumericDate no instant is represented for, is
    /// malformed: the resource server validating it with <see cref="Verifiable.OAuth.JwsAccessTokenValidator"/> refuses
    /// it over the wire with 401 and a <c>Bearer</c> challenge carrying <c>error="invalid_token"</c>,
    /// never a server error.
    /// </summary>
    [TestMethod]
    public async Task AccessTokenWithUnrepresentableExpReturns401()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        FakeTimeProvider time = new(NowInstant);

        await using TestResourceServerShell rs = new(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(keys.PublicKey),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: time);
        await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: Subject,
            scope: Scope,
            clientId: ClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: Issuer,
            audience: [Audience]);
        payload[WellKnownJwtClaimNames.Exp] = long.MaxValue;
        string token = await BuildAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        using HttpResponseMessage response = await SendProtectedRequestAsync(rs, token).ConfigureAwait(false);

        await AssertInvalidTokenChallengeAsync(
            rs, response, "Access token exp claim is not a NumericDate naming a representable instant.").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5">RFC 7519 §4.1.5</see>: "The
    /// "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for
    /// processing." An access token otherwise valid and signed by the trusted issuer whose <c>nbf</c> is a
    /// NumericDate no instant is represented for (9223372036854775807, or 253402300800, one second after
    /// 9999-12-31T23:59:59Z) names a time that cannot be checked: the resource server validating it with
    /// <see cref="Verifiable.OAuth.JwsAccessTokenValidator"/> refuses it over the wire with 401 and the
    /// challenge <c>Bearer realm="protected", error="invalid_token", error_description="…"</c>, and never
    /// serves it as a token carrying no <c>nbf</c>.
    /// </summary>
    /// <param name="notBefore">The presented <c>nbf</c>.</param>
    [TestMethod]
    [DataRow(long.MaxValue)]
    [DataRow(253402300800L)]
    public async Task AccessTokenWithUnrepresentableNbfReturns401(long notBefore)
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        FakeTimeProvider time = new(NowInstant);

        await using TestResourceServerShell rs = new(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(keys.PublicKey),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: time);
        await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: Subject,
            scope: Scope,
            clientId: ClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromMinutes(5),
            issuer: Issuer,
            audience: [Audience]);
        payload[WellKnownJwtClaimNames.Nbf] = notBefore;
        string token = await BuildAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        using HttpResponseMessage response = await SendProtectedRequestAsync(rs, token).ConfigureAwait(false);

        await AssertInvalidTokenChallengeAsync(
            rs, response, "Access token nbf claim is not a NumericDate naming a representable instant.").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4">RFC 7519 §4.1.4</see>: "The
    /// processing of the "exp" claim requires that the current date/time MUST be before the expiration
    /// date/time listed in the "exp" claim.", and §2 NumericDate: "other than that non-integer values can be
    /// represented." An access token whose <c>exp</c> is a quarter of a second after the resource server's
    /// clock (the clock half a second past a whole second, the <c>exp</c> three quarters past it) has not
    /// expired: the resource server validating it with <see cref="Verifiable.OAuth.JwsAccessTokenValidator"/>
    /// serves it over the wire with 200 and the token's <c>sub</c>.
    /// </summary>
    [TestMethod]
    public async Task AccessTokenWhoseFractionalExpIsAfterTheClockIsServed()
    {
        long wholeSecond = NowInstant.ToUnixTimeSeconds();
        FakeTimeProvider time = new(DateTimeOffset.FromUnixTimeSeconds(wholeSecond).AddMilliseconds(500));

        TokenPresentation presentation = await PresentTokenAsync(time, payload =>
        {
            payload[WellKnownJwtClaimNames.Exp] = wholeSecond + 0.75;
        }).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, presentation.Status, presentation.Body);
        using JsonDocument document = JsonDocument.Parse(presentation.Body);
        Assert.AreEqual(Subject, document.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5">RFC 7519 §4.1.5</see>: "The
    /// processing of the "nbf" claim requires that the current date/time MUST be after or equal to the
    /// not-before date/time listed in the "nbf" claim.", and §2 NumericDate: "other than that non-integer
    /// values can be represented." An access token whose <c>nbf</c> lies a quarter of a second beyond the
    /// resource server's clock extended by its 60-second tolerance (the clock half a second past a whole
    /// second, the <c>nbf</c> sixty seconds and three quarters past it) is not yet valid: it is refused over
    /// the wire with 401 and the challenge <c>Bearer realm="protected", error="invalid_token",
    /// error_description="Access token nbf is in the future.", resource_metadata="…"</c>.
    /// </summary>
    [TestMethod]
    public async Task AccessTokenWhoseFractionalNbfIsBeyondTheToleranceIsRefused()
    {
        long wholeSecond = NowInstant.ToUnixTimeSeconds();
        FakeTimeProvider time = new(DateTimeOffset.FromUnixTimeSeconds(wholeSecond).AddMilliseconds(500));

        TokenPresentation presentation = await PresentTokenAsync(time, payload =>
        {
            payload[WellKnownJwtClaimNames.Nbf] = wholeSecond + 60.75;
        }).ConfigureAwait(false);

        AssertInvalidTokenChallenge(presentation, "Access token nbf is in the future.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-2">RFC 7519 §2</see> NumericDate: "A JSON
    /// numeric value representing the number of seconds from 1970-01-01T00:00:00Z UTC until the specified
    /// UTC date/time ... other than that non-integer values can be represented." An access token whose
    /// <c>exp</c> is 253402300799.5, half a second into 9999-12-31T23:59:59Z, names a representable
    /// instant after the clock: the resource server serves it over the wire with 200 and the token's
    /// <c>sub</c>.
    /// </summary>
    [TestMethod]
    public async Task AccessTokenWhoseExpIsWithinTheLastRepresentableSecondIsServed()
    {
        FakeTimeProvider time = new(NowInstant);

        TokenPresentation presentation = await PresentTokenAsync(time, payload =>
        {
            payload[WellKnownJwtClaimNames.Exp] = 253402300799.5;
        }).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, presentation.Status, presentation.Body);
        using JsonDocument document = JsonDocument.Parse(presentation.Body);
        Assert.AreEqual(Subject, document.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-2">RFC 7519 §2</see> NumericDate counts
    /// seconds from 1970-01-01T00:00:00Z, "other than that non-integer values can be represented", so
    /// -0.5 names 1969-12-31T23:59:59.5Z and -0.25 the quarter second after it. An access token whose
    /// <c>iat</c> is -0.5 and <c>exp</c> -0.25 has a positive lifetime that ended long before the clock: it
    /// is refused over the wire with 401 and the challenge <c>Bearer realm="protected",
    /// error="invalid_token", error_description="Access token has expired.", resource_metadata="…"</c>.
    /// </summary>
    [TestMethod]
    public async Task AccessTokenWhoseNegativeFractionalClaimsNameAnEndedLifetimeIsRefusedAsExpired()
    {
        FakeTimeProvider time = new(NowInstant);

        TokenPresentation presentation = await PresentTokenAsync(time, payload =>
        {
            payload[WellKnownJwtClaimNames.Iat] = -0.5;
            payload[WellKnownJwtClaimNames.Exp] = -0.25;
        }).ConfigureAwait(false);

        AssertInvalidTokenChallenge(presentation, "Access token has expired.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 §4</see>: "Resource servers
    /// receiving a JWT access token MUST validate it in the following manner", the signature step among
    /// them. An access token from the trusted issuer whose signature segment makes it longer than
    /// <see cref="Jws.DefaultMaxJwsLength"/>, the longest compact JWS the library verifies, cannot be
    /// validated: presented over the wire, the resource server validating it with
    /// <see cref="Verifiable.OAuth.JwsAccessTokenValidator"/> refuses it with 401 and the challenge
    /// <c>Bearer realm="protected", error="invalid_token", error_description="Access token exceeds the
    /// longest compact JWS this validator verifies.", resource_metadata="…"</c>, never a server error.
    /// </summary>
    [TestMethod]
    public async Task AccessTokenLongerThanTheVerifiedMaximumReturns401()
    {
        FakeTimeProvider time = new(NowInstant);

        TokenPresentation presentation = await PresentTokenAsync(
            time, alterPayload: static _ => { }, lengthenSignatureBy: Jws.DefaultMaxJwsLength).ConfigureAwait(false);

        AssertInvalidTokenChallenge(presentation, "Access token exceeds the longest compact JWS this validator verifies.");
    }


    /// <summary>
    /// What a resource server answered one presentation with, read before the server was stopped.
    /// </summary>
    /// <param name="Status">The response status.</param>
    /// <param name="Challenges">Every <c>WWW-Authenticate</c> value of the response.</param>
    /// <param name="Body">The response body.</param>
    /// <param name="MetadataUrl">The resource server's metadata URL the challenge names.</param>
    private sealed record TokenPresentation(HttpStatusCode Status, IReadOnlyList<string> Challenges, string Body, string MetadataUrl);


    /// <summary>
    /// Starts a resource server on <paramref name="time"/>, signs an access token from the trusted issuer
    /// whose claims are issued a minute before that clock and expire five minutes after it, rewritten by
    /// <paramref name="alterPayload"/>, and presents it under the <c>Bearer</c> scheme over the wire,
    /// its signature segment lengthened by <paramref name="lengthenSignatureBy"/> characters.
    /// </summary>
    /// <param name="time">The resource server's clock.</param>
    /// <param name="alterPayload">Rewrites the token's claims before signing.</param>
    /// <param name="lengthenSignatureBy">The number of characters appended to the signed token.</param>
    /// <returns>The response.</returns>
    private async Task<TokenPresentation> PresentTokenAsync(
        FakeTimeProvider time, Action<JwtPayload> alterPayload, int lengthenSignatureBy = 0)
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DateTimeOffset now = time.GetUtcNow();

        await using TestResourceServerShell rs = new(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(keys.PublicKey),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: time);
        await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: Subject,
            scope: Scope,
            clientId: ClientId,
            issuedAt: now - TimeSpan.FromMinutes(1),
            expiresAt: now + TimeSpan.FromMinutes(5),
            issuer: Issuer,
            audience: [Audience]);
        alterPayload(payload);
        string token = await BuildAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false)
            + new string('A', lengthenSignatureBy);

        using HttpResponseMessage response = await SendProtectedRequestAsync(rs, token).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        IReadOnlyList<string> challenges = response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? values)
            ? [.. values]
            : [];

        return new TokenPresentation(response.StatusCode, challenges, body, rs.MetadataUrl!.OriginalString);
    }


    /// <summary>
    /// Asserts a presentation was refused: 401, one <c>WWW-Authenticate</c> value equal to
    /// <c>Bearer realm="protected", error="invalid_token", error_description="<paramref name="description"/>",
    /// resource_metadata="…"</c>, and no claim served.
    /// </summary>
    /// <param name="presentation">The response.</param>
    /// <param name="description">The validator's failure description the challenge carries.</param>
    private static void AssertInvalidTokenChallenge(TokenPresentation presentation, string description)
    {
        Assert.AreEqual(HttpStatusCode.Unauthorized, presentation.Status, presentation.Body);
        Assert.AreEqual(
            $"Bearer realm=\"protected\", error=\"invalid_token\", error_description=\"{description}\", resource_metadata=\"{presentation.MetadataUrl}\"",
            Assert.ContainsSingle(presentation.Challenges));
        Assert.IsFalse(presentation.Body.Contains("\"sub\"", StringComparison.Ordinal), "A refused request is served no claim.");
    }


    /// <summary>
    /// Asserts a refusal of a presented token over the wire: 401, one <c>WWW-Authenticate</c> value equal
    /// to the challenge the resource server writes, <c>Bearer realm="protected", error="invalid_token",
    /// error_description="<paramref name="description"/>", resource_metadata="…"</c>, and no claim served.
    /// </summary>
    /// <param name="rs">The running resource server whose metadata URL the challenge names.</param>
    /// <param name="response">The wire response.</param>
    /// <param name="description">The validator's failure description the challenge carries.</param>
    private async Task AssertInvalidTokenChallengeAsync(TestResourceServerShell rs, HttpResponseMessage response, string description)
    {
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges));
        Assert.AreEqual(
            $"Bearer realm=\"protected\", error=\"invalid_token\", error_description=\"{description}\", resource_metadata=\"{rs.MetadataUrl!.OriginalString}\"",
            challenges.Single());
        Assert.IsFalse(body.Contains("\"sub\"", StringComparison.Ordinal), "A refused request is served no claim.");
    }


    /// <summary>Sends a Bearer-scheme GET for <c>/protected</c> to the resource server over its loopback listener.</summary>
    /// <param name="rs">The running resource server.</param>
    /// <param name="token">The access token presented.</param>
    /// <returns>The wire response; the caller disposes it.</returns>
    private async Task<HttpResponseMessage> SendProtectedRequestAsync(TestResourceServerShell rs, string token)
    {
        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(rs.HttpCertificate!, rs.HttpBaseAddress);
        using HttpRequestMessage request = new(HttpMethod.Get, "/protected");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        return await client.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// The <c>DPoP</c> challenge the application's resource answers with, written out:
    /// <c>DPoP realm="protected", error="&lt;error&gt;", algs="...", resource_metadata="&lt;metadata URL&gt;"</c>, the
    /// realm the resource names its protection space with, the <c>algs</c> the accepted algorithms it wires and the
    /// metadata URL it serves its document at.
    /// </summary>
    /// <param name="rs">The running resource server.</param>
    /// <param name="error">The challenge's <c>error</c>, or <see langword="null"/> for a challenge carrying none.</param>
    /// <returns>The <c>WWW-Authenticate</c> value.</returns>
    private static string ResourceDpopChallenge(TestResourceServerShell rs, string? error) =>
        ResourceDpopProofs.DpopChallenge("protected", error, resourceMetadata: rs.MetadataUrl);


    /// <summary>
    /// Asserts a refusal of a DPoP presentation at the application's resource received over a raw TLS connection: 401,
    /// exactly one <c>WWW-Authenticate</c> field line equal to <see cref="ResourceDpopChallenge"/> with
    /// <paramref name="error"/>, <paramref name="error"/> in the body, and no claim served.
    /// </summary>
    /// <param name="rs">The running resource server.</param>
    /// <param name="response">The answer as received.</param>
    /// <param name="error">The expected error.</param>
    private static void AssertResourceRefusal(TestResourceServerShell rs, HttpResponseData response, string error)
    {
        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            ResourceDpopChallenge(rs, error),
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual(error, document.RootElement.GetProperty("error").GetString(), response.Body);
        Assert.IsFalse(document.RootElement.TryGetProperty("sub", out _), "A refused request is served no claim.");
    }


    /// <summary>Asserts the <c>error_description</c> of a refusal's body as received.</summary>
    /// <param name="response">The answer as received.</param>
    /// <param name="description">The expected description.</param>
    private static void AssertRefusalDescription(HttpResponseData response, string description)
    {
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual(description, document.RootElement.GetProperty("error_description").GetString(), response.Body);
    }


    /// <summary>
    /// Wraps a resource server's DPoP proof validation so it answers a valid proof's claims with an empty <c>nonce</c>:
    /// an application validator that admits <c>"nonce":""</c>.
    /// </summary>
    /// <param name="validate">The wired proof validation.</param>
    /// <returns>The validation answering every success with an empty <c>nonce</c>.</returns>
    private static ValidateDpopProofDelegate AnswerAnEmptyNonce(ValidateDpopProofDelegate validate) =>
        async (request, cancellationToken) =>
        {
            DpopProofValidationResult result = await validate(request, cancellationToken).ConfigureAwait(false);

            return result is { IsSuccess: true, Claims: DpopProofClaims claims, JwkThumbprint: string thumbprint }
                ? DpopProofValidationResult.Success(claims with { Nonce = string.Empty }, thumbprint)
                : result;
        };


    /// <summary>
    /// Wires a resource server's DPoP proof validation in place of the one it wires: <see cref="DpopProofValidator"/>'s
    /// <c>ValidateAsync</c> over the resource's signature verification and <paramref name="timeProvider"/>, holding a
    /// proof's <c>iat</c> to <paramref name="iatTolerance"/> either way of the clock, an application validator with a
    /// tolerance of its own.
    /// </summary>
    /// <param name="timeProvider">The resource server's clock.</param>
    /// <param name="iatTolerance">The validator's tolerance on a proof's <c>iat</c>.</param>
    /// <returns>The wrapper answering that validation whatever validation it is handed.</returns>
    private static Func<ValidateDpopProofDelegate, ValidateDpopProofDelegate> ValidateWithAnIatTolerance(
        TimeProvider timeProvider, TimeSpan iatTolerance) =>
        _ => (request, cancellationToken) => DpopProofValidator.ValidateAsync(
            request, MicrosoftCryptographicFunctionsAdapter.VerifyP256Async, DpopTestSupport.Parser, TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder, timeProvider, BaseMemoryPool.Shared, iatTolerance, cancellationToken);


    /// <summary>
    /// Starts a resource server trusting <see cref="Issuer"/>'s key <paramref name="asPublicKey"/> on
    /// <paramref name="time"/>, or on a clock of its own at <see cref="NowInstant"/>.
    /// </summary>
    /// <param name="asPublicKey">The authorization server's access token key the resource server verifies with.</param>
    /// <param name="requiresDpop">Whether the resource requires DPoP-bound access tokens.</param>
    /// <param name="isDpopProofValidationWired">Whether the resource server wires its proof validation, nonce slots and accepted algorithms.</param>
    /// <param name="isDpopProofJtiRecordWired">Whether the resource server wires its <c>jti</c> claim.</param>
    /// <param name="time">The resource server's clock, or <see langword="null"/> for one at <see cref="NowInstant"/>.</param>
    /// <param name="wrapDpopProofValidation">Wraps the wired proof validation, or <see langword="null"/> to wire it as it is.</param>
    /// <param name="wrapDpopProofJtiClaim">Wraps the wired <c>jti</c> claim, or <see langword="null"/> to wire it as it is.</param>
    /// <returns>The running resource server; the caller disposes it.</returns>
    private async Task<TestResourceServerShell> StartResourceServerAsync(
        PublicKeyMemory asPublicKey,
        bool requiresDpop = false,
        bool isDpopProofValidationWired = true,
        bool isDpopProofJtiRecordWired = true,
        FakeTimeProvider? time = null,
        Func<ValidateDpopProofDelegate, ValidateDpopProofDelegate>? wrapDpopProofValidation = null,
        Func<ConsultDpopProofJtiDelegate, ConsultDpopProofJtiDelegate>? wrapDpopProofJtiClaim = null)
    {
        TestResourceServerShell rs = new(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(asPublicKey),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: time ?? new FakeTimeProvider(NowInstant),
            requiresDpop: requiresDpop,
            isDpopProofValidationWired: isDpopProofValidationWired,
            isDpopProofJtiRecordWired: isDpopProofJtiRecordWired,
            wrapDpopProofValidation: wrapDpopProofValidation,
            wrapDpopProofJtiClaim: wrapDpopProofJtiClaim);
        try
        {
            await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

            return rs;
        }
        catch
        {
            await rs.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }


    /// <summary>
    /// Signs an access token from <see cref="Issuer"/> for <see cref="Audience"/>, issued a minute before
    /// <see cref="NowInstant"/> and expiring an hour after it, bound by <c>cnf.jkt</c> to
    /// <paramref name="boundThumbprint"/> when one is given.
    /// </summary>
    /// <param name="asPrivateKey">The authorization server's access token signing key.</param>
    /// <param name="boundThumbprint">The <c>cnf.jkt</c>, or <see langword="null"/> for an unbound token.</param>
    /// <returns>The compact JWS.</returns>
    private Task<string> IssueTokenAsync(PrivateKeyMemory asPrivateKey, string? boundThumbprint)
    {
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: Subject,
            scope: Scope,
            clientId: ClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: Issuer,
            audience: [Audience]);
        if(boundThumbprint is not null)
        {
            payload[WellKnownJwtClaimNames.Cnf] = new Dictionary<string, object>
            {
                [WellKnownJwtClaimNames.JwkThumbprint] = boundThumbprint
            };
        }

        return BuildAccessTokenAsync(asPrivateKey, payload);
    }


    /// <summary>The JWK SHA-256 Thumbprint of <paramref name="dpopKey"/>'s public key, the value a bound token's <c>cnf.jkt</c> carries.</summary>
    /// <param name="dpopKey">The DPoP key.</param>
    /// <returns>The base64url thumbprint.</returns>
    private static string ThumbprintOf(DpopKey dpopKey) =>
        dpopKey.GetThumbprint(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);


    /// <summary>
    /// Builds a DPoP proof by <paramref name="dpopKey"/> for a GET of <c>/protected</c> on the resource server, issued at
    /// <paramref name="issuedAt"/> or at <see cref="NowInstant"/>, its <c>ath</c> hashing <paramref name="token"/>,
    /// carrying <paramref name="nonce"/> when given and <paramref name="jti"/> or a fresh unique <c>jti</c>.
    /// </summary>
    /// <param name="rs">The running resource server.</param>
    /// <param name="dpopKey">The key that signs the proof.</param>
    /// <param name="token">The access token presented with the proof.</param>
    /// <param name="nonce">The resource's nonce, or <see langword="null"/> to carry none.</param>
    /// <param name="issuedAt">The proof's <c>iat</c>, or <see langword="null"/> for <see cref="NowInstant"/>.</param>
    /// <param name="jti">The proof's <c>jti</c>, or <see langword="null"/> for a fresh unique one.</param>
    /// <param name="htu">The proof's <c>htu</c>, or <see langword="null"/> for the listener's <c>/protected</c>.</param>
    /// <returns>The compact proof.</returns>
    private Task<string> BuildResourceProofAsync(
        TestResourceServerShell rs, DpopKey dpopKey, string token, string? nonce, DateTimeOffset? issuedAt = null, string? jti = null, Uri? htu = null) =>
        ResourceDpopProofs.BuildAsync(
            dpopKey, "GET", (htu ?? new Uri(rs.HttpBaseAddress!, "/protected")).ToString(), token, nonce, issuedAt ?? NowInstant,
            TestContext.CancellationToken, jti: jti);


    /// <summary>
    /// Presents <paramref name="token"/> at the resource server over a raw TLS connection under the <c>DPoP</c> scheme
    /// with no <c>DPoP</c> field, asserts the 401 it is answered with, and returns the one nonce its <c>DPoP-Nonce</c>
    /// field line provides.
    /// </summary>
    /// <param name="rs">The running resource server.</param>
    /// <param name="token">The DPoP-bound access token.</param>
    /// <returns>The nonce the resource provided.</returns>
    private async Task<string> ObtainResourceNonceAsync(TestResourceServerShell rs, string token)
    {
        HttpResponseData challenge = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", []).ConfigureAwait(false);
        Assert.AreEqual(401, challenge.StatusCode, challenge.Body);

        return Assert.ContainsSingle(challenge.Headers.Headers.GetValues(WellKnownHttpHeaderNames.DPoPNonce),
            "The resource's nonce challenge carries one DPoP-Nonce field line.");
    }


    /// <summary>
    /// Presents <paramref name="token"/> at the resource server over a raw TLS connection under the <c>DPoP</c> scheme
    /// with a proof by <paramref name="dpopKey"/> carrying no nonce, asserts the nonce challenge it is answered with (401,
    /// <c>use_dpop_nonce</c> in the body and the one challenge
    /// <c>DPoP realm="protected", error="use_dpop_nonce", algs="...", resource_metadata="..."</c>), and returns the one
    /// nonce its <c>DPoP-Nonce</c> field line provides.
    /// </summary>
    /// <param name="rs">The running resource server.</param>
    /// <param name="dpopKey">The key the token is bound to, which signs the proof.</param>
    /// <param name="token">The DPoP-bound access token.</param>
    /// <param name="path">The protected path the proof names and the request addresses, or <see langword="null"/> for <c>/protected</c>.</param>
    /// <returns>The nonce the resource provided.</returns>
    private async Task<string> ObtainResourceNonceWithANonceLessProofAsync(TestResourceServerShell rs, DpopKey dpopKey, string token, string? path = null)
    {
        string nonceLessProof = await BuildResourceProofAsync(
            rs, dpopKey, token, nonce: null, htu: path is null ? null : new Uri(rs.HttpBaseAddress!, path)).ConfigureAwait(false);
        HttpResponseData challenge = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [nonceLessProof], path).ConfigureAwait(false);
        AssertResourceRefusal(rs, challenge, "use_dpop_nonce");

        return Assert.ContainsSingle(challenge.Headers.Headers.GetValues(WellKnownHttpHeaderNames.DPoPNonce),
            "The resource's nonce challenge carries one DPoP-Nonce field line.");
    }


    /// <summary>
    /// Sends a GET of <paramref name="path"/>, <c>/protected</c> unless a row names another protected path, to the
    /// resource server over a raw TLS connection with <paramref name="authorization"/> as its one <c>Authorization</c>
    /// field line, or no such field when it is <see langword="null"/>, and each of <paramref name="dpopFieldLines"/> on
    /// its own <c>DPoP</c> field line, so every field line of the request and of the answer is as written and as received.
    /// </summary>
    /// <param name="rs">The running resource server.</param>
    /// <param name="authorization">The <c>Authorization</c> field value, or <see langword="null"/> for no such field.</param>
    /// <param name="dpopFieldLines">The <c>DPoP</c> field values, one line each.</param>
    /// <param name="path">The protected path addressed, or <see langword="null"/> for <c>/protected</c>.</param>
    /// <returns>The answer as received.</returns>
    private Task<HttpResponseData> SendProtectedOverARawConnectionAsync(
        TestResourceServerShell rs, string? authorization, IReadOnlyList<string> dpopFieldLines, string? path = null)
    {
        List<KeyValuePair<string, string>> fieldLines = authorization is null
            ? []
            : [new(WellKnownHttpHeaderNames.Authorization, authorization)];
        foreach(string proof in dpopFieldLines)
        {
            fieldLines.Add(new(WellKnownHttpHeaderNames.DPoP, proof));
        }

        return RawHttpsRequest.SendPinnedAsync(
            rs.HttpCertificate!, WellKnownHttpMethods.Get, new Uri(rs.HttpBaseAddress!, path ?? "/protected"), fieldLines,
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken);
    }


    /// <summary>
    /// The resource server's verification-key resolver: answers <paramref name="publicKey"/> for the
    /// key id <see cref="Kid"/> and nothing for any other, and, when <paramref name="recordedUsages"/> is
    /// given, first records the usage each call states.
    /// </summary>
    /// <param name="publicKey">The key the resolver holds.</param>
    /// <param name="recordedUsages">Receives the usage of every call, or <see langword="null"/> to record nothing.</param>
    /// <returns>The resolver.</returns>
    private static ServerVerificationKeyResolverDelegate BuildResolver(
        PublicKeyMemory publicKey, ConcurrentQueue<KeyUsageContext>? recordedUsages = null) =>
        (kid, usage, tenant, ctx, ct) =>
        {
            recordedUsages?.Enqueue(usage);

            return ValueTask.FromResult<PublicKeyMemory?>(
                string.Equals(kid.Value, Kid, StringComparison.Ordinal) ? publicKey : null);
        };


    /// <summary>
    /// Signs an RFC 9068 access token over <paramref name="payload"/> with an <c>at+jwt</c> header whose
    /// <c>kid</c> is <paramref name="kid"/>, or the resolver's key id when none is given.
    /// </summary>
    /// <param name="privateKey">The signing key.</param>
    /// <param name="payload">The token's claims.</param>
    /// <param name="kid">The header <c>kid</c>, or <see langword="null"/> for the resolver's key id.</param>
    /// <returns>The compact JWS.</returns>
    private async Task<string> BuildAccessTokenAsync(PrivateKeyMemory privateKey, JwtPayload payload, string? kid = null)
    {
        JwtHeader header = JwtHeaderExtensions.ForAccessToken(WellKnownJwaValues.Es256, Kid);
        if(kid is not null)
        {
            header[WellKnownJwkMemberNames.Kid] = kid;
        }

        UnsignedJwt unsignedJwt = new(header, payload);

        using JwsMessage jws = await unsignedJwt.SignAsync(
            privateKey,
            HeaderSerializer,
            PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }


    private static ReadOnlySpan<byte> HeaderSerializer(JwtHeader header) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);


    private static ReadOnlySpan<byte> PayloadSerializer(JwtPayload payload) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);
}
