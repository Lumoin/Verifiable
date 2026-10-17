using Microsoft.Extensions.Time.Testing;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Wire-level tests for the standalone resource-server role of RFC 9728 +
/// RFC 6750 on <see cref="TestResourceServerShell"/>: the
/// <c>/.well-known/oauth-protected-resource</c> document is produced by the
/// library's <see cref="ProtectedResourceMetadataEndpoints"/> builder and
/// survives the consumer's §3.3 resource-match validation; every <c>401</c>
/// carries a <c>WWW-Authenticate</c> challenge built by
/// <see cref="BearerTokenChallenge"/> whose <c>resource_metadata</c>
/// parameter (§5.1) completes the discovery loop over the real wire; a valid
/// token lacking the required scope is refused <c>403</c>
/// <c>insufficient_scope</c> with the <c>scope</c> attribute naming the
/// needed scope (RFC 6750 §3.1); and the OPRM-coherence invariant — the
/// trusted issuer must be among the advertised <c>authorization_servers</c> —
/// is enforced at construction.
/// </summary>
[TestClass]
internal sealed class ResourceServerChallengeTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string Issuer = "https://as1.test/tenant-a";
    private const string Audience = "test-resource-server";
    private const string Subject = "user-1";
    private const string ClientId = "client-1";
    private const string Kid = "test-kid";
    private const string RequiredScope = "mcp:tools";

    private static DateTimeOffset NowInstant { get; } = TestClock.CanonicalEpoch.AddDays(-15);


    [TestMethod]
    public async Task MetadataDocumentComesFromTheLibraryBuilderAndSurvivesResourceMatch()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        FakeTimeProvider time = new(NowInstant);

        await using TestResourceServerShell rs = new(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(keys.PublicKey),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: time,
            requiredScope: RequiredScope);
        await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(rs.HttpCertificate!, rs.HttpBaseAddress);
        using HttpResponseMessage response = await client.GetAsync(
            new Uri(rs.MetadataUrl!.AbsolutePath, UriKind.Relative), TestContext.CancellationToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //§3.2: 200 OK, application/json.
        Assert.AreEqual(200, (int)response.StatusCode, body);
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.Content.Headers.ContentType?.MediaType);

        //The consumer-side strict parser reads the wire bytes alone.
        ProtectedResourceMetadata? metadata =
            ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata(body);
        Assert.IsNotNull(metadata);

        //§3.3: the resource value is identical to the identifier the metadata
        //URL derives from; any other identifier must fail the match.
        Assert.IsTrue(ProtectedResourceMetadataValidation.IsResourceMatch(
            metadata!, rs.ResourceIdentity!.OriginalString));
        Assert.IsFalse(ProtectedResourceMetadataValidation.IsResourceMatch(
            metadata!, "https://attacker.example.com"));

        //The event's MCP-Server row: the document names the RS's one trusted
        //AS, and advertises the scope the RS enforces.
        Assert.IsNotNull(metadata!.AuthorizationServers);
        Assert.AreEqual(Issuer, metadata.AuthorizationServers!.Single());
        Assert.IsNotNull(metadata.ScopesSupported);
        Assert.Contains(RequiredScope, metadata.ScopesSupported!);
        Assert.IsNotNull(metadata.BearerMethodsSupported);
        Assert.IsTrue(BearerMethodValues.IsDefined(metadata.BearerMethodsSupported![0]));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see>: "If the protected
    /// resource metadata was retrieved from a URL returned by the protected resource via the WWW-Authenticate
    /// resource_metadata parameter, then the resource value returned MUST be identical to the URL that the client used to
    /// make the request to the resource server. If these values are not identical, the data contained in the response
    /// MUST NOT be used." A request to <c>https://127.0.0.1:{port}/protected</c> without credentials over the wire is
    /// answered 401 with a <c>Bearer</c> challenge carrying no error and the pointer
    /// <c>https://127.0.0.1:{port}/.well-known/oauth-protected-resource/protected</c>; the document fetched there names
    /// the URL requested as its <c>resource</c> and the authorization server the resource server trusts.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UnauthenticatedRequestChallengeCompletesMetadataDiscovery()
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
        using HttpResponseMessage denied = await client.GetAsync(
            new Uri("/protected", UriKind.Relative), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, denied.StatusCode);
        Assert.IsTrue(denied.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges));

        //RFC 9110 Section 11.6.1: the field value "might contain more than one challenge"; a request without
        //credentials is challenged for each scheme the resource accepts, and the Bearer one is read here.
        string challenge = challenges!.Single(static value => value.StartsWith(WellKnownAuthenticationSchemes.Bearer, StringComparison.OrdinalIgnoreCase));

        //RFC 6750 §3 grammar, asserted through the challenge parser.
        Assert.StartsWith(WellKnownAuthenticationSchemes.Bearer, challenge);
        Assert.IsTrue(BearerTokenChallenge.TryParse(challenge, out BearerTokenChallengeParameters parameters),
            $"The 401 challenge must parse under the RFC 6750 §3 grammar. Header: {challenge}");
        Assert.IsNull(parameters.Error,
            "RFC 6750 §3: a request without authentication information gets a challenge without an error code.");

        //Section 5.1: the challenge advertises the metadata URL, the Section 3 path-insertion form of the URL requested.
        string origin = rs.HttpBaseAddress!.GetLeftPart(UriPartial.Authority);
        string requestUrl = origin + "/protected";
        string? advertised = ProtectedResourceChallenge.TryReadResourceMetadata(challenge);
        Assert.AreEqual(origin + "/.well-known/oauth-protected-resource/protected", advertised);

        //Fetching it over the wire completes the Section 5 discovery loop: parse strictly, then validate Section 3.3
        //against the URL the client requested.
        Uri advertisedUrl = new(advertised!);
        using HttpResponseMessage metadataResponse = await client.GetAsync(
            new Uri(advertisedUrl.AbsolutePath, UriKind.Relative), TestContext.CancellationToken)
            .ConfigureAwait(false);
        string metadataBody = await metadataResponse.Content.ReadAsStringAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(200, (int)metadataResponse.StatusCode, metadataBody);

        ProtectedResourceMetadata? metadata =
            ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata(metadataBody);
        Assert.IsNotNull(metadata);
        Assert.AreEqual(requestUrl, metadata.Resource, "The document names the URL requested as its resource.");
        Assert.IsTrue(ProtectedResourceMetadataValidation.IsResourceMatch(metadata, requestUrl));
        Assert.AreEqual(Issuer, metadata.AuthorizationServers!.Single(),
            "Discovery lands on the AS the resource server trusts.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3">RFC 9728 Section 3</see>: "Protected resources
    /// supporting metadata MUST make a JSON document containing metadata as specified in Section 2 available at a URL
    /// formed by inserting a well-known URI string into the protected resource's resource identifier between the host
    /// component and the path and/or query components, if any.", with <see href="https://www.rfc-editor.org/rfc/rfc9728#section-1.2">Section
    /// 1.2</see>: "it is recognized that there are cases that make a query component a useful and necessary part of a
    /// resource identifier." A resource server whose identifier is <c>https://127.0.0.1:{port}/protected?tenant=t1</c>
    /// answers a request without credentials over the wire with 401 and a <c>Bearer</c> challenge naming
    /// <c>https://127.0.0.1:{port}/.well-known/oauth-protected-resource/protected?tenant=t1</c>, the query kept after the
    /// path; the document fetched there names the identifier as its <c>resource</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResourceIdentifierWithAQueryKeepsItAfterTheInsertedSuffixAsync()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        FakeTimeProvider time = new(NowInstant);

        await using TestResourceServerShell rs = new(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(keys.PublicKey),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: time,
            resourceIdentifierQuery: "?tenant=t1");
        await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string origin = rs.HttpBaseAddress!.GetLeftPart(UriPartial.Authority);

        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(rs.HttpCertificate!, rs.HttpBaseAddress);
        using HttpResponseMessage denied = await client.GetAsync(
            new Uri("/protected?tenant=t1", UriKind.Relative), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, denied.StatusCode);
        Assert.IsTrue(denied.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges));
        string challenge = challenges!.Single(static value => value.StartsWith(WellKnownAuthenticationSchemes.Bearer, StringComparison.OrdinalIgnoreCase));
        string? advertised = ProtectedResourceChallenge.TryReadResourceMetadata(challenge);
        Assert.AreEqual(origin + "/.well-known/oauth-protected-resource/protected?tenant=t1", advertised);

        using HttpResponseMessage metadataResponse = await client.GetAsync(
            new Uri(new Uri(advertised!).PathAndQuery, UriKind.Relative), TestContext.CancellationToken).ConfigureAwait(false);
        string metadataBody = await metadataResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)metadataResponse.StatusCode, metadataBody);
        ProtectedResourceMetadata? metadata = ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata(metadataBody);
        Assert.IsNotNull(metadata);
        Assert.AreEqual(origin + "/protected?tenant=t1", metadata.Resource, "The document names the identifier, its query kept.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.1">RFC 9728 Section 3.1</see>: "If the resource
    /// identifier value contains a path or query component, any terminating slash (/) following the host component MUST
    /// be removed before inserting /.well-known/ and the well-known URI path suffix between the host component and the
    /// path and/or query components.", with <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3">Section
    /// 3</see>: "inserting a well-known URI string into the protected resource's resource identifier between the host
    /// component and the path and/or query components, if any". The query component is inserted after, never edited. A
    /// resource server whose identifier is <c>https://127.0.0.1:{port}/protected</c> followed by the text a row names
    /// answers a request without credentials over the wire with 401 and a <c>Bearer</c> challenge naming exactly the
    /// location a row names; the document fetched there names the identifier as its <c>resource</c>. The rows: the query
    /// <c>?x=/</c>, ending in a slash, the location <c>.../.well-known/oauth-protected-resource/protected?x=/</c>; the
    /// path's terminating slash and the query <c>?v=1</c>, the location
    /// <c>.../.well-known/oauth-protected-resource/protected?v=1</c>.
    /// </summary>
    /// <param name="identifierSuffix">The text the identifier carries after <c>/protected</c>.</param>
    /// <param name="locationSuffix">The text the document's location carries after the inserted suffix.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("?x=/", "/protected?x=/")]
    [DataRow("/?v=1", "/protected?v=1")]
    public async Task ResourceIdentifierEndingInASlashKeepsItsQueryWholeAfterTheInsertedSuffixAsync(string identifierSuffix, string locationSuffix)
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        FakeTimeProvider time = new(NowInstant);

        await using TestResourceServerShell rs = new(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(keys.PublicKey),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: time,
            resourceIdentifierQuery: identifierSuffix);
        await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string origin = rs.HttpBaseAddress!.GetLeftPart(UriPartial.Authority);

        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(rs.HttpCertificate!, rs.HttpBaseAddress);
        using HttpResponseMessage denied = await client.GetAsync(
            new Uri("/protected", UriKind.Relative), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, denied.StatusCode);
        Assert.IsTrue(denied.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges));
        string challenge = challenges!.Single(static value => value.StartsWith(WellKnownAuthenticationSchemes.Bearer, StringComparison.OrdinalIgnoreCase));
        string? advertised = ProtectedResourceChallenge.TryReadResourceMetadata(challenge);
        Assert.AreEqual(origin + "/.well-known/oauth-protected-resource" + locationSuffix, advertised);

        using HttpResponseMessage metadataResponse = await client.GetAsync(
            new Uri(new Uri(advertised!).PathAndQuery, UriKind.Relative), TestContext.CancellationToken).ConfigureAwait(false);
        string metadataBody = await metadataResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)metadataResponse.StatusCode, metadataBody);
        ProtectedResourceMetadata? metadata = ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata(metadataBody);
        Assert.IsNotNull(metadata);
        Assert.AreEqual(origin + "/protected" + identifierSuffix, metadata.Resource, "The document names the identifier as given.");
    }


    [TestMethod]
    public async Task RejectedTokenChallengeCarriesInvalidTokenErrorCode()
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

        //Signed by the trusted key but addressed to another resource — the
        //validator refuses it and the challenge must say invalid_token.
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: Subject,
            scope: "openid profile",
            clientId: ClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: Issuer,
            audience: ["other-rs"]);
        string token = await BuildAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(rs.HttpCertificate!, rs.HttpBaseAddress);
        using HttpRequestMessage request = new(HttpMethod.Get, "/protected");
        request.Headers.Authorization = new AuthenticationHeaderValue(WellKnownAuthenticationSchemes.Bearer, token);
        using HttpResponseMessage response = await client.SendAsync(request, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges));
        string challenge = challenges!.Single();

        //RFC 6750 §3.1: invalid_token → 401 with the error code on the
        //challenge; the §5.1 resource_metadata parameter still rides it.
        Assert.IsTrue(BearerTokenChallenge.TryParse(challenge, out BearerTokenChallengeParameters parameters),
            $"The 401 challenge must parse under the RFC 6750 §3 grammar. Header: {challenge}");
        Assert.AreEqual(OAuthErrors.InvalidToken, parameters.Error);
        Assert.AreEqual(rs.MetadataUrl!.OriginalString,
            ProtectedResourceChallenge.TryReadResourceMetadata(challenge));
    }


    [TestMethod]
    public async Task TokenWithoutRequiredScopeIsRefusedWithInsufficientScopeChallenge()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        FakeTimeProvider time = new(NowInstant);

        await using TestResourceServerShell rs = new(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(keys.PublicKey),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: time,
            requiredScope: RequiredScope);
        await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //A fully valid token — signature, issuer, audience, lifetime — whose
        //scope list lacks the resource's required scope.
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: Subject,
            scope: "openid profile",
            clientId: ClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: Issuer,
            audience: [Audience]);
        string token = await BuildAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(rs.HttpCertificate!, rs.HttpBaseAddress);
        using HttpRequestMessage request = new(HttpMethod.Get, "/protected");
        request.Headers.Authorization = new AuthenticationHeaderValue(WellKnownAuthenticationSchemes.Bearer, token);
        using HttpResponseMessage response = await client.SendAsync(request, TestContext.CancellationToken)
            .ConfigureAwait(false);

        //RFC 6750 §3.1: insufficient_scope → 403; the scope attribute names
        //the scope necessary to access the resource.
        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges));
        string challenge = challenges!.Single();

        Assert.IsTrue(BearerTokenChallenge.TryParse(challenge, out BearerTokenChallengeParameters parameters),
            $"The 403 challenge must parse under the RFC 6750 §3 grammar. Header: {challenge}");
        Assert.AreEqual(OAuthErrors.InsufficientScope, parameters.Error);
        Assert.AreEqual(RequiredScope, parameters.Scope);
    }


    [TestMethod]
    public async Task TokenWithRequiredScopeReachesTheProtectedResource()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        FakeTimeProvider time = new(NowInstant);

        await using TestResourceServerShell rs = new(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(keys.PublicKey),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: time,
            requiredScope: RequiredScope);
        await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: Subject,
            scope: $"openid {RequiredScope}",
            clientId: ClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: Issuer,
            audience: [Audience]);
        string token = await BuildAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(rs.HttpCertificate!, rs.HttpBaseAddress);
        using HttpRequestMessage request = new(HttpMethod.Get, "/protected");
        request.Headers.Authorization = new AuthenticationHeaderValue(WellKnownAuthenticationSchemes.Bearer, token);
        using HttpResponseMessage response = await client.SendAsync(request, TestContext.CancellationToken)
            .ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(Subject, doc.RootElement.GetProperty("sub").GetString());
        string grantedScopes = doc.RootElement.GetProperty("scope").GetString()!;
        Assert.IsTrue(grantedScopes.Split(' ').Contains(RequiredScope, StringComparer.Ordinal),
            $"The echoed scope claim must contain the required scope. Scopes: {grantedScopes}");
    }


    [TestMethod]
    public void ConstructionFailsWhenTrustedIssuerIsNotAmongAdvertisedAuthorizationServers()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        FakeTimeProvider time = new(NowInstant);

        //The event's MCP-Server OPRM-coherence invariant: the RS's trusted AS
        //must be one of the authorization_servers its own document advertises.
        _ = Assert.ThrowsExactly<ArgumentException>(() => new TestResourceServerShell(
            trustedIssuer: new Uri(Issuer),
            expectedAudience: Audience,
            resolveVerificationKey: BuildResolver(keys.PublicKey),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: time,
            requiredScope: null,
            advertisedAuthorizationServers: ["https://other-as.example.com"]));
    }


    private static ServerVerificationKeyResolverDelegate BuildResolver(PublicKeyMemory publicKey) =>
        (kid, usage, tenant, ctx, ct) => ValueTask.FromResult<PublicKeyMemory?>(
            string.Equals(kid.Value, Kid, StringComparison.Ordinal) ? publicKey : null);


    private async Task<string> BuildAccessTokenAsync(PrivateKeyMemory privateKey, JwtPayload payload)
    {
        JwtHeader header = JwtHeaderExtensions.ForAccessToken(WellKnownJwaValues.Es256, Kid);
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
