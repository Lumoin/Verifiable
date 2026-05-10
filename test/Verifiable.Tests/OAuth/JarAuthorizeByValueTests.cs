using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;


/// <summary>
/// Tests for the JAR-by-value direct Authorize matcher in
/// <c>AuthCodeEndpoints.BuildAuthorizeJarByValue</c>. Mirrors a representative
/// subset of <see cref="JarParTests"/> for the GET /authorize entry point with
/// path/method differences and the SubjectId requirement.
/// </summary>
[TestClass]
internal sealed class JarAuthorizeByValueTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;
    private static EncodeDelegate Encoder => TestSetup.Base64UrlEncoder;
    private static DecodeDelegate Decoder => TestSetup.Base64UrlDecoder;

    private static readonly JwtHeaderSerializer JwtHeaderSerializerDelegate =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer JwtPayloadSerializerDelegate =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);

    private const string ClientId = "https://client.example.com";
    private const string TestSubject = "test-subject-001";
    private static readonly Uri ClientBaseUri = new("https://client.example.com");
    private static readonly Uri RegisteredRedirectUri = new("https://client.example.com/callback");

    private static ImmutableHashSet<ServerCapabilityName> JarDirectCapabilities { get; } =
        ImmutableHashSet.Create(
            ServerCapabilityName.AuthorizationCode,
            ServerCapabilityName.DirectAuthorization,
            ServerCapabilityName.JwtSecuredAuthorizationRequest);

    private static ImmutableHashSet<ServerCapabilityName> DirectOnlyCapabilities { get; } =
        ImmutableHashSet.Create(
            ServerCapabilityName.AuthorizationCode,
            ServerCapabilityName.DirectAuthorization);

    private static ImmutableHashSet<ServerCapabilityName> JarOnlyCapabilities { get; } =
        ImmutableHashSet.Create(
            ServerCapabilityName.AuthorizationCode,
            ServerCapabilityName.JwtSecuredAuthorizationRequest);


    [TestMethod]
    public async Task AcceptsValidAuthorizeJarByValueAndIssuesAuthorizationCode()
    {
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await BuildSignedJarAsync(
            material, now, BuildBaseClaims(material, now), TestContext.CancellationToken)
            .ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode,
            $"JAR-by-value direct authorize must redirect on success. Body: {response.Body}");
        Assert.IsNotNull(response.Location);
        Assert.Contains("code=", response.Location!, StringComparison.Ordinal,
            $"Redirect Location must include the authorization code. Got: {response.Location}");
        Assert.StartsWith(
            RegisteredRedirectUri.ToString(),
            response.Location,
            StringComparison.Ordinal,
            $"Redirect Location must target the registered redirect_uri. Got: {response.Location}");
    }


    [TestMethod]
    public async Task RejectsJarWithMissingOuterClientId()
    {
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await BuildSignedJarAsync(
            material, now, BuildBaseClaims(material, now), TestContext.CancellationToken)
            .ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, outerClientId: null, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequest);
    }


    [TestMethod]
    public async Task RejectsJarWithRedirectUriNotInRegistration()
    {
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims[OAuthRequestParameters.RedirectUri] = "https://attacker.example.com/steal";

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithExpiredExp()
    {
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset signedAt = TimeProvider.GetUtcNow();
        string compactJar = await BuildSignedJarAsync(
            material, signedAt, BuildBaseClaims(material, signedAt),
            TestContext.CancellationToken).ConfigureAwait(false);

        TimeProvider.Advance(TimeSpan.FromMinutes(5));

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithWrongTypHeader()
    {
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await BuildSignedJarWithCustomTypAsync(
            material.SigningPrivateKey,
            "JWT",
            BuildBaseClaims(material, now),
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarMissingClientId()
    {
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims.Remove(WellKnownJwtClaims.ClientId);

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarMissingExp()
    {
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims.Remove(WellKnownJwtClaims.Exp);

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarSignedWithDifferentClientKey()
    {
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> attackerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory attackerPublic = attackerKeys.PublicKey;
        using PrivateKeyMemory attackerPrivate = attackerKeys.PrivateKey;

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await BuildSignedJarWithKeyAsync(
            attackerPrivate, BuildBaseClaims(material, now),
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithWrongAudience()
    {
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims[WellKnownJwtClaims.Aud] = "https://different-issuer.example.com/";

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithCodeChallengeMethodPlain()
    {
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims[OAuthRequestParameters.CodeChallengeMethod] = "plain";

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public void JarAuthorizeMatcherAbsentWhenJwtSecuredAuthorizationRequestCapabilityNotAllowed()
    {
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, DirectOnlyCapabilities);

        EndpointChain chain = host.GetEndpoints(material.Registration, new RequestContext());

        bool hasJarAuthorize = chain.Any(e => string.Equals(
            e.Name, "AuthCode.AuthorizeJarByValue", StringComparison.Ordinal));
        Assert.IsFalse(hasJarAuthorize,
            "JAR-by-value Authorize endpoint must not appear when JwtSecuredAuthorizationRequest is not allowed.");
    }


    [TestMethod]
    public void JarAuthorizeMatcherAbsentWhenDirectAuthorizationCapabilityNotAllowed()
    {
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarOnlyCapabilities);

        EndpointChain chain = host.GetEndpoints(material.Registration, new RequestContext());

        bool hasJarAuthorize = chain.Any(e => string.Equals(
            e.Name, "AuthCode.AuthorizeJarByValue", StringComparison.Ordinal));
        Assert.IsFalse(hasJarAuthorize,
            "JAR-by-value Authorize endpoint must not appear when DirectAuthorization is not allowed.");
    }


    [TestMethod]
    public async Task BuildDirectAuthorizeStillAcceptsPureCodeChallengeRequestAfterDisjointnessFix()
    {
        //Disjointness regression: a registration with direct authorize but no
        //JAR capability still accepts a pure PKCE direct authorize request
        //(code_challenge + S256, no 'request' parameter).
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, DirectOnlyCapabilities);

        RequestFields fields = new()
        {
            [OAuthRequestParameters.ClientId] = ClientId,
            [OAuthRequestParameters.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameters.CodeChallengeMethod] = OAuthRequestParameters.CodeChallengeMethodS256,
            [OAuthRequestParameters.RedirectUri] = RegisteredRedirectUri.ToString(),
            [OAuthRequestParameters.Scope] = WellKnownScopes.OpenId
        };

        RequestContext context = new();
        context.SetSubjectId(TestSubject);
        ServerHttpResponse response = await host.DispatchAtPathAsync(
            material.Registration.TenantId.Value,
            ServerEndpointPaths.Authorize,
            "GET",
            fields,
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode,
            $"Pure PKCE direct authorize must still redirect. Body: {response.Body}");
        Assert.IsNotNull(response.Location);
        Assert.Contains("code=", response.Location!, StringComparison.Ordinal,
            $"Redirect Location must include the authorization code. Got: {response.Location}");
    }


    [TestMethod]
    public async Task RejectsRequestWithBothRequestAndRequestUriParameters()
    {
        //RFC 9101 §6.1 — request and request_uri MUST NOT both be present.
        //BuildAuthorizeJarByValue's MatchesRequest declines (request_uri present),
        //so the JAR-by-value path does not run. The PAR-completed BuildAuthorize
        //matcher does match on request_uri presence; with no flow registered
        //against the supplied token it rejects with invalid_request, which is
        //still the structurally-correct "do not silently route to JAR" outcome
        //the disjointness rule is meant to defend.
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await BuildSignedJarAsync(
            material, now, BuildBaseClaims(material, now), TestContext.CancellationToken)
            .ConfigureAwait(false);

        RequestFields fields = new()
        {
            [OAuthRequestParameters.Request] = compactJar,
            [OAuthRequestParameters.RequestUri] = "urn:ietf:params:oauth:request_uri:abc123",
            [OAuthRequestParameters.ClientId] = ClientId
        };

        RequestContext context = new();
        context.SetSubjectId(TestSubject);
        ServerHttpResponse response = await host.DispatchAtPathAsync(
            material.Registration.TenantId.Value,
            ServerEndpointPaths.Authorize,
            "GET",
            fields,
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        //The JAR-by-value matcher MUST NOT have produced a 302 with a code —
        //that would be silent "request" parameter picking. A 4xx is acceptable
        //(it indicates the request was not validated as a JAR-by-value request).
        Assert.AreNotEqual(302, response.StatusCode,
            "JAR-by-value matcher must not silently process a request that also carries request_uri. " +
            $"Got {response.StatusCode}: {response.Body}");
        Assert.IsGreaterThanOrEqualTo(400, response.StatusCode,
            $"Expected 4xx for ambiguous request/request_uri body. Got {response.StatusCode}: {response.Body}");
    }


    [TestMethod]
    public async Task RejectsJarWithIssuerNotMatchingClientId()
    {
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims[WellKnownJwtClaims.Iss] = "https://impostor.example.com";

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithMissingAudience()
    {
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims.Remove(WellKnownJwtClaims.Aud);

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithLifetimeExceedingPolicyCeiling()
    {
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims[WellKnownJwtClaims.Exp] = (now + TimeSpan.FromMinutes(5)).ToUnixTimeSeconds();

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    //Helpers — JAR construction and dispatch.

    private static Dictionary<string, object> BuildBaseClaims(
        VerifierKeyMaterial material, DateTimeOffset now)
    {
        string expectedAud = material.Registration.IssuerUri!.ToString();

        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaims.Iss] = ClientId,
            [WellKnownJwtClaims.Aud] = expectedAud,
            [WellKnownJwtClaims.ClientId] = ClientId,
            [OAuthRequestParameters.ResponseType] = OAuthRequestParameters.ResponseTypeCode,
            [OAuthRequestParameters.RedirectUri] = RegisteredRedirectUri.ToString(),
            [OAuthRequestParameters.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameters.State] = "state-jar-direct-01",
            [WellKnownJwtClaims.Nonce] = "nonce-jar-direct-01",
            [OAuthRequestParameters.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameters.CodeChallengeMethod] = OAuthRequestParameters.CodeChallengeMethodS256,
            [WellKnownJwtClaims.Iat] = now.ToUnixTimeSeconds(),
            [WellKnownJwtClaims.Nbf] = now.ToUnixTimeSeconds(),
            [WellKnownJwtClaims.Exp] = (now + TimeSpan.FromSeconds(30)).ToUnixTimeSeconds()
        };
    }


    private static async Task<string> BuildSignedJarAsync(
        VerifierKeyMaterial material,
        DateTimeOffset now,
        IReadOnlyDictionary<string, object> claims,
        CancellationToken cancellationToken)
    {
        _ = now;
        return await BuildSignedJarWithKeyAsync(
            material.SigningPrivateKey, claims, cancellationToken).ConfigureAwait(false);
    }


    private static async Task<string> BuildSignedJarWithKeyAsync(
        PrivateKeyMemory signingKey,
        IReadOnlyDictionary<string, object> claims,
        CancellationToken cancellationToken)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);

        JwtHeader header = new()
        {
            [WellKnownJwkValues.Alg] = algorithm,
            [WellKnownJwkValues.Typ] = WellKnownMediaTypes.Jwt.OauthAuthzReqJwt
        };

        JwtPayload payload = new();
        foreach(KeyValuePair<string, object> entry in claims)
        {
            payload[entry.Key] = entry.Value;
        }

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage signed = await unsigned.SignAsync(
            signingKey,
            JwtHeaderSerializerDelegate,
            JwtPayloadSerializerDelegate,
            Encoder,
            Pool,
            cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(signed, Encoder);
    }


    private static async Task<string> BuildSignedJarWithCustomTypAsync(
        PrivateKeyMemory signingKey,
        string typValue,
        IReadOnlyDictionary<string, object> claims,
        CancellationToken cancellationToken)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);

        JwtHeader header = new()
        {
            [WellKnownJwkValues.Alg] = algorithm,
            [WellKnownJwkValues.Typ] = typValue
        };

        JwtPayload payload = new();
        foreach(KeyValuePair<string, object> entry in claims)
        {
            payload[entry.Key] = entry.Value;
        }

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage signed = await unsigned.SignAsync(
            signingKey,
            JwtHeaderSerializerDelegate,
            JwtPayloadSerializerDelegate,
            Encoder,
            Pool,
            cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(signed, Encoder);
    }


    private static async ValueTask<ServerHttpResponse> DispatchAuthorizeAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string compactJar,
        string? outerClientId,
        CancellationToken cancellationToken)
    {
        RequestFields fields = new()
        {
            [OAuthRequestParameters.Request] = compactJar
        };

        if(outerClientId is not null)
        {
            fields[OAuthRequestParameters.ClientId] = outerClientId;
        }

        RequestContext context = new();
        context.SetSubjectId(TestSubject);

        return await host.DispatchAtPathAsync(
            material.Registration.TenantId.Value,
            ServerEndpointPaths.Authorize,
            "GET",
            fields,
            context,
            cancellationToken).ConfigureAwait(false);
    }


    private static void AssertErrorCode(ServerHttpResponse response, string expectedCode)
    {
        string expectedFragment = $"\"error\":\"{expectedCode}\"";
        Assert.Contains(expectedFragment, response.Body, StringComparison.Ordinal,
            $"Expected error '{expectedCode}' in response body. Got: {response.Body}");
    }
}
