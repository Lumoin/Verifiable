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
/// Tests for the JAR-PAR matcher in <c>AuthCodeEndpoints.BuildJarPar</c>.
/// Covers RFC 9101 + RFC 9126 + RFC 9700 §4.6 substitution defenses, FAPI 2.0
/// timing constraints, capability gating, disjointness with the PKCE PAR matcher,
/// and the happy path.
/// </summary>
[TestClass]
internal sealed class JarParTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;
    private static EncodeDelegate Encoder => TestSetup.Base64UrlEncoder;
    private static DecodeDelegate Decoder => TestSetup.Base64UrlDecoder;

    //Header and payload serializers shared with the in-process server. Both
    //sides must use the same JSON shape so the signature input the wire
    //carries is byte-identical to what the verifier reconstructs.
    private static readonly JwtHeaderSerializer JwtHeaderSerializerDelegate =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer JwtPayloadSerializerDelegate =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);

    private const string ClientId = "https://client.example.com";
    private static readonly Uri ClientBaseUri = new("https://client.example.com");
    private static readonly Uri RegisteredRedirectUri = new("https://client.example.com/callback");

    private static ImmutableHashSet<ServerCapabilityName> JarParCapabilities { get; } =
        ImmutableHashSet.Create(
            ServerCapabilityName.AuthorizationCode,
            ServerCapabilityName.PushedAuthorization,
            ServerCapabilityName.JwtSecuredAuthorizationRequest);

    private static ImmutableHashSet<ServerCapabilityName> ParOnlyCapabilities { get; } =
        ImmutableHashSet.Create(
            ServerCapabilityName.AuthorizationCode,
            ServerCapabilityName.PushedAuthorization);

    private static ImmutableHashSet<ServerCapabilityName> JarOnlyCapabilities { get; } =
        ImmutableHashSet.Create(
            ServerCapabilityName.AuthorizationCode,
            ServerCapabilityName.JwtSecuredAuthorizationRequest);


    [TestMethod]
    public async Task AcceptsValidJarParAndIssuesRequestUriHandle()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await BuildSignedJarAsync(
            material,
            now,
            BuildBaseClaims(material, now),
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            $"Expected 200 OK from JAR-PAR happy path. Body: {response.Body}");
        Assert.AreEqual("application/json", response.ContentType);
        Assert.Contains("\"request_uri\":", response.Body, StringComparison.Ordinal,
            $"Response body must contain request_uri. Got: {response.Body}");
        Assert.Contains("\"expires_in\":", response.Body, StringComparison.Ordinal,
            $"Response body must contain expires_in. Got: {response.Body}");
    }


    [TestMethod]
    public async Task RejectsJarWithMissingOuterClientId()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await BuildSignedJarAsync(
            material, now, BuildBaseClaims(material, now), TestContext.CancellationToken)
            .ConfigureAwait(false);

        //Outer client_id deliberately absent — the helper must short-circuit
        //before resolving the verification key.
        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, outerClientId: null, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequest);
        Assert.Contains("Missing outer client_id", response.Body, StringComparison.Ordinal,
            $"Response should mention missing outer client_id. Got: {response.Body}");
    }


    [TestMethod]
    public async Task RejectsJarWithOuterClientIdMismatchingJarClientId()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await BuildSignedJarAsync(
            material, now, BuildBaseClaims(material, now), TestContext.CancellationToken)
            .ConfigureAwait(false);

        //Outer client_id mismatches both the registration and the JAR's inner
        //value. RFC 9700 §4.6 substitution defense rejects with invalid_request
        //before signature verification.
        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, "https://attacker.example.com",
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequest);
        Assert.Contains("Outer client_id", response.Body, StringComparison.Ordinal,
            $"Response should mention outer client_id mismatch. Got: {response.Body}");
    }


    [TestMethod]
    public async Task RejectsJarSignedWithDifferentClientKey()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        //Sign the JAR with an unrelated keypair while the registration's
        //JarSigning slot still references the original verification key.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> attackerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory attackerPublic = attackerKeys.PublicKey;
        using PrivateKeyMemory attackerPrivate = attackerKeys.PrivateKey;

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await BuildSignedJarWithKeyAsync(
            attackerPrivate, now, BuildBaseClaims(material, now),
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithIssuerNotMatchingClientId()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        //RFC 9101 §10.2 — iss must equal client_id.
        claims[WellKnownJwtClaimNames.Iss] = "https://impostor.example.com";

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithMissingIssuer()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims.Remove(WellKnownJwtClaimNames.Iss);

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithWrongAudience()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims[WellKnownJwtClaimNames.Aud] = "https://different-issuer.example.com/";

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithMissingAudience()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims.Remove(WellKnownJwtClaimNames.Aud);

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithAudEqualToClientIdRatherThanIssuer()
    {
        //RFC 9101 §10.2 + RFC 9700 §4.2 reading: aud must equal the AS issuer
        //URL, not the client_id. The "EUDI/Microsoft" reading where aud = client_id
        //is rejected by the library.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims[WellKnownJwtClaimNames.Aud] = ClientId;

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithExpiredExp()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset signedAt = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, signedAt);
        string compactJar = await BuildSignedJarAsync(
            material, signedAt, claims, TestContext.CancellationToken).ConfigureAwait(false);

        //Advance the clock past exp + clock skew (skew is 60s, JAR lifetime is 60s).
        TimeProvider.Advance(TimeSpan.FromMinutes(5));

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithNbfInFuture()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        DateTimeOffset farFuture = now + TimeSpan.FromMinutes(10);
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        //Push nbf well past the clock-skew tolerance window (60s default).
        claims[WellKnownJwtClaimNames.Nbf] = farFuture.ToUnixTimeSeconds();
        claims[WellKnownJwtClaimNames.Exp] = (farFuture + TimeSpan.FromSeconds(30)).ToUnixTimeSeconds();
        claims[WellKnownJwtClaimNames.Iat] = now.ToUnixTimeSeconds();

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithLifetimeExceedingPolicyCeiling()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        //Default policy ceiling for AuthCode JAR lifetime is 60 seconds.
        claims[WellKnownJwtClaimNames.Exp] = (now + TimeSpan.FromMinutes(5)).ToUnixTimeSeconds();

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithWrongTypHeader()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await BuildSignedJarWithCustomTypAsync(
            material.SigningPrivateKey,
            "JWT",
            BuildBaseClaims(material, now),
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithRedirectUriNotInRegistration()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims[OAuthRequestParameterNames.RedirectUri] = "https://attacker.example.com/steal";

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithCodeChallengeMethodPlain()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims[OAuthRequestParameterNames.CodeChallengeMethod] = "plain";

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarMissingClientId()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims.Remove(WellKnownJwtClaimNames.ClientId);

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarMissingResponseType()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims.Remove(OAuthRequestParameterNames.ResponseType);

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarMissingRedirectUri()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims.Remove(OAuthRequestParameterNames.RedirectUri);

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarMissingScope()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims.Remove(OAuthRequestParameterNames.Scope);

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarMissingState()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims.Remove(OAuthRequestParameterNames.State);

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarMissingNonce()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims.Remove(WellKnownJwtClaimNames.Nonce);

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarMissingCodeChallenge()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims.Remove(OAuthRequestParameterNames.CodeChallenge);

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarMissingExp()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims.Remove(WellKnownJwtClaimNames.Exp);

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task JarParMatcherAbsentWhenJwtSecuredAuthorizationRequestCapabilityNotAllowed()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, ParOnlyCapabilities);

        EndpointChain chain = await host.GetEndpointsAsync(material.Registration, new RequestContext()).ConfigureAwait(false);

        bool hasJarPar = chain.Any(e => string.Equals(
            e.Name, "AuthCode.JarPar", StringComparison.Ordinal));
        Assert.IsFalse(hasJarPar,
            "JAR-PAR endpoint must not appear when JwtSecuredAuthorizationRequest is not allowed.");
    }


    [TestMethod]
    public async Task JarParMatcherAbsentWhenPushedAuthorizationCapabilityNotAllowed()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarOnlyCapabilities);

        EndpointChain chain = await host.GetEndpointsAsync(material.Registration, new RequestContext()).ConfigureAwait(false);

        bool hasJarPar = chain.Any(e => string.Equals(
            e.Name, "AuthCode.JarPar", StringComparison.Ordinal));
        Assert.IsFalse(hasJarPar,
            "JAR-PAR endpoint must not appear when PushedAuthorization is not allowed.");
    }


    [TestMethod]
    public async Task BuildParStillAcceptsPureCodeChallengeRequestAfterDisjointnessFix()
    {
        //Disjointness regression: a registration with PAR but no JAR capability
        //must still accept a pure PKCE PAR body (code_challenge + S256 method,
        //no 'request' parameter) and produce a request_uri.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, ParOnlyCapabilities);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameterNames.CodeChallengeMethod] = OAuthRequestParameterValues.CodeChallengeMethodS256,
            [OAuthRequestParameterNames.RedirectUri] = RegisteredRedirectUri.ToString(),
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };

        RequestContext context = new();
        ServerHttpResponse response = await host.DispatchAtPathAsync(
            material.Registration.TenantId.Value,
            ServerEndpointPaths.Par,
            "POST",
            fields,
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            $"Pure PKCE PAR must still succeed. Body: {response.Body}");
        Assert.Contains("\"request_uri\":", response.Body, StringComparison.Ordinal,
            $"PKCE PAR response must contain request_uri. Got: {response.Body}");
    }


    [TestMethod]
    public async Task RejectsRequestWithBothCodeChallengeAndRequestParameter()
    {
        //RFC 9101 §6.1 — outer parameters must be ignored when a JAR is present.
        //The matcher routing puts a body carrying 'request' onto the JAR-PAR
        //matcher regardless of any outer code_challenge. Confirm the response
        //is a JAR validation outcome (200 happy path here), not the PKCE one.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await BuildSignedJarAsync(
            material, now, BuildBaseClaims(material, now), TestContext.CancellationToken)
            .ConfigureAwait(false);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.Request] = compactJar,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            //Outer PKCE fields the JAR matcher must ignore.
            [OAuthRequestParameterNames.CodeChallenge] = "outer-challenge-should-be-ignored",
            [OAuthRequestParameterNames.CodeChallengeMethod] = OAuthRequestParameterValues.CodeChallengeMethodS256
        };

        RequestContext context = new();
        ServerHttpResponse response = await host.DispatchAtPathAsync(
            material.Registration.TenantId.Value,
            ServerEndpointPaths.Par,
            "POST",
            fields,
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        //The JAR matcher took over: response is a JAR-shaped success
        //(request_uri + expires_in), proving routing chose the JAR path.
        Assert.AreEqual(200, response.StatusCode,
            $"Body with both 'request' and 'code_challenge' must route to the JAR matcher. Body: {response.Body}");
        Assert.Contains("\"request_uri\":", response.Body, StringComparison.Ordinal,
            $"JAR happy path body must contain request_uri. Got: {response.Body}");
    }


    [TestMethod]
    public async Task AcceptsJarWithAudAsArrayContainingIssuer()
    {
        //RFC 7519 §4.1.3 permits aud as either a single string or an array of
        //strings. CheckTokenAudContainsExpectedIssuer accepts both shapes; the
        //matcher's ValidateJarAudienceAsync runs the check against verified.Claims
        //(the raw payload dictionary) — not the projected
        //AuthCodeRequestObject.Aud which is single-string only. This test
        //exercises the array form by replacing the default string aud claim
        //with an array that contains the expected issuer URL alongside two
        //unrelated entries.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);

        string expectedAud = material.Registration.IssuerUri!.ToString();
        claims[WellKnownJwtClaimNames.Aud] = new[]
        {
            "https://unrelated-aud.example",
            expectedAud,
            "https://another-unrelated.example"
        };

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            $"JAR with aud as array containing the issuer must be accepted. Body: {response.Body}");
        Assert.Contains("\"request_uri\":", response.Body, StringComparison.Ordinal,
            $"Array-form aud happy path must produce a JAR-PAR success body. Got: {response.Body}");
    }


    //Helpers — JAR construction and dispatch.

    private static Dictionary<string, object> BuildBaseClaims(
        VerifierKeyMaterial material, DateTimeOffset now)
    {
        //Issuer URL form mirrors TestHostShell's registration: https://issuer.test/{segment}.
        //ResolveIssuerAsync (or DefaultIssuerResolver) returns this URL via ToString(),
        //which yields the trailing-slash-free form for path-only URIs.
        string expectedAud = material.Registration.IssuerUri!.ToString();

        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Iss] = ClientId,
            [WellKnownJwtClaimNames.Aud] = expectedAud,
            [WellKnownJwtClaimNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ResponseType] = OAuthRequestParameterValues.ResponseTypeCode,
            [OAuthRequestParameterNames.RedirectUri] = RegisteredRedirectUri.ToString(),
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.State] = "state-jar-par-01",
            [WellKnownJwtClaimNames.Nonce] = "nonce-jar-par-01",
            [OAuthRequestParameterNames.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameterNames.CodeChallengeMethod] = OAuthRequestParameterValues.CodeChallengeMethodS256,
            [WellKnownJwtClaimNames.Iat] = now.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Nbf] = now.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = (now + TimeSpan.FromSeconds(30)).ToUnixTimeSeconds()
        };
    }


    private static async Task<string> BuildSignedJarAsync(
        VerifierKeyMaterial material,
        DateTimeOffset now,
        IReadOnlyDictionary<string, object> claims,
        CancellationToken cancellationToken)
    {
        return await BuildSignedJarWithKeyAsync(
            material.SigningPrivateKey, now, claims, cancellationToken).ConfigureAwait(false);
    }


    private static async Task<string> BuildSignedJarWithKeyAsync(
        PrivateKeyMemory signingKey,
        DateTimeOffset now,
        IReadOnlyDictionary<string, object> claims,
        CancellationToken cancellationToken)
    {
        _ = now;

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);

        JwtHeader header = new()
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = WellKnownMediaTypes.Jwt.OauthAuthzReqJwt
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
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = typValue
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


    private static async ValueTask<ServerHttpResponse> DispatchJarParAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string compactJar,
        string? outerClientId,
        CancellationToken cancellationToken)
    {
        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.Request] = compactJar
        };

        if(outerClientId is not null)
        {
            fields[OAuthRequestParameterNames.ClientId] = outerClientId;
        }

        return await host.DispatchAtPathAsync(
            material.Registration.TenantId.Value,
            ServerEndpointPaths.Par,
            "POST",
            fields,
            new RequestContext(),
            cancellationToken).ConfigureAwait(false);
    }


    private static void AssertErrorCode(ServerHttpResponse response, string expectedCode)
    {
        string expectedFragment = $"\"error\":\"{expectedCode}\"";
        Assert.Contains(expectedFragment, response.Body, StringComparison.Ordinal,
            $"Expected error '{expectedCode}' in response body. Got: {response.Body}");
    }
}
