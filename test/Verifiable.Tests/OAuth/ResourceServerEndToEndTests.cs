using Microsoft.Extensions.Time.Testing;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
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

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out var values));
        string challenge = values!.First();
        Assert.IsTrue(challenge.Contains("DPoP", StringComparison.Ordinal),
            $"Challenge for DPoP-bound token must name DPoP scheme; got: {challenge}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 §7.1</see>: "a resource
    /// server MUST check that a DPoP proof was also received in the DPoP header field of the HTTP
    /// request, check the DPoP proof according to the rules in Section 4.3, and check that the public key
    /// of the DPoP proof matches the public key to which the access token is bound". An access token
    /// bound by <c>cnf.jkt</c> to a key, presented over the wire under the <c>DPoP</c> scheme with a proof
    /// signed by that key, is served: 200 with the token's <c>cnf</c>, and the proof's <c>jti</c> is
    /// recorded.
    /// </summary>
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

        string resourceUrl = new Uri(rs.HttpBaseAddress!, "/protected").ToString();
        string proof = await ResourceDpopProofs.BuildAsync(
            dpopKey, "GET", resourceUrl, token, nonce: null, NowInstant, TestContext.CancellationToken).ConfigureAwait(false);

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
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 §11.1</see>: "HTTP
    /// requests to the same URI for which the jti value has been seen before would be declined." A proof
    /// the resource server served once, presented again over the wire with the same token, is refused
    /// with 401 and a challenge carrying <c>invalid_dpop_proof</c>.
    /// </summary>
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

        string resourceUrl = new Uri(rs.HttpBaseAddress!, "/protected").ToString();
        string proof = await ResourceDpopProofs.BuildAsync(
            dpopKey, "GET", resourceUrl, token, nonce: null, NowInstant, TestContext.CancellationToken).ConfigureAwait(false);

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
        Assert.IsTrue(replayResponse.Headers.TryGetValues("WWW-Authenticate", out var values));
        Assert.IsTrue(values!.First().Contains("invalid_dpop_proof", StringComparison.Ordinal));
    }


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


    private static ServerVerificationKeyResolverDelegate BuildResolver(PublicKeyMemory publicKey) =>
        (kid, tenant, ctx, ct) => ValueTask.FromResult<PublicKeyMemory?>(
            string.Equals(kid.Value, Kid, StringComparison.Ordinal) ? publicKey : null);


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
