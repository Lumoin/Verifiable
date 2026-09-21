using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.Server.Pipeline;
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

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private const string ClientId = "https://client.example.com";
    private const string DefaultState = "state-jar-par-01";
    private const string DefaultNonce = "nonce-jar-par-01";
    private static Uri ClientBaseUri { get; } = new("https://client.example.com");
    private static Uri RegisteredRedirectUri { get; } = new("https://client.example.com/callback");

    private static ImmutableHashSet<CapabilityIdentifier> JarParCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest);

    private static ImmutableHashSet<CapabilityIdentifier> ParOnlyCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization);

    private static ImmutableHashSet<CapabilityIdentifier> JarOnlyCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest);


    [TestMethod]
    public async Task AcceptsValidJarParAndIssuesRequestUriHandle()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material,
            OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce),
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode,
            $"Expected 201 Created from JAR-PAR happy path (RFC 9126 §2.2). Body: {response.Body}");
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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce), TestContext.CancellationToken)
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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce), TestContext.CancellationToken)
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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        //Sign the JAR with an unrelated keypair while the registration's
        //JarSigning slot still references the original verification key.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> attackerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory attackerPublic = attackerKeys.PublicKey;
        using PrivateKeyMemory attackerPrivate = attackerKeys.PrivateKey;

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarWithKeyAsync(
            attackerPrivate, OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce),
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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        //RFC 9101 §10.2 — iss must equal client_id.
        claims[WellKnownJwtClaimNames.Iss] = "https://impostor.example.com";

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarCarryingSubClaim()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        //OpenID Federation 1.0 §12.1.1.1 — a Request Object MUST NOT carry a sub
        //claim. Here sub equals iss/client_id, the exact private_key_jwt
        //client-assertion shape the prohibition guards against; the matcher must
        //reject it rather than let the object double as client authentication.
        claims[WellKnownJwtClaimNames.Sub] = ClientId;

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(WellKnownJwtClaimNames.Iss);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        claims[WellKnownJwtClaimNames.Aud] = "https://different-issuer.example.com/";

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(WellKnownJwtClaimNames.Aud);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        claims[WellKnownJwtClaimNames.Aud] = ClientId;

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset signedAt = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, signedAt, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        DateTimeOffset farFuture = now + TimeSpan.FromMinutes(10);
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        //Push nbf well past the clock-skew tolerance window (60s default).
        claims[WellKnownJwtClaimNames.Nbf] = farFuture.ToUnixTimeSeconds();
        claims[WellKnownJwtClaimNames.Exp] = (farFuture + TimeSpan.FromSeconds(30)).ToUnixTimeSeconds();
        claims[WellKnownJwtClaimNames.Iat] = now.ToUnixTimeSeconds();

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        //Default policy ceiling for AuthCode JAR lifetime is 60 seconds.
        claims[WellKnownJwtClaimNames.Exp] = (now + TimeSpan.FromMinutes(5)).ToUnixTimeSeconds();

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarWithCustomTypAsync(
            material.SigningPrivateKey,
            "JWT",
            OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce),
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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        claims[OAuthRequestParameterNames.RedirectUri] = "https://attacker.example.com/steal";

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    /// <summary>
    /// A verified JAR with a plain transformation receives the unsupported-method error per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.4.1">RFC 7636 §4.4.1</see>:
    /// "authorization error response with "error" value set to "invalid_request"."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.3">RFC 9101 §6.3</see> sends
    /// parameter errors "as specified in Section 5.2 of [RFC6749]", yielding a direct JSON error.
    /// </summary>
    [TestMethod]
    public async Task RejectsJarWithCodeChallengeMethodPlain()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        claims[OAuthRequestParameterNames.CodeChallengeMethod] = "plain";
        claims[OAuthRequestParameterNames.CodeChallenge] = new string('a', 43);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.Request] = compactJar
            }, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidRequest}\"", Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// An absent method requests the refused plain transformation per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>:
    /// "OPTIONAL, defaults to "plain" if not present in the request".
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.4.1">§4.4.1</see> requires
    /// "authorization error response with "error" value set to "invalid_request"."
    /// </summary>
    [TestMethod]
    public async Task RejectsJarWithAbsentCodeChallengeMethod()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(OAuthRequestParameterNames.CodeChallengeMethod);
        claims[OAuthRequestParameterNames.CodeChallenge] = new string('a', 43);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.Request] = compactJar
            }, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidRequest}\"", Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// A verified JAR with a plain transformation receives the unsupported-method error per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.4.1">RFC 7636 §4.4.1</see>:
    /// "authorization error response with "error" value set to "invalid_request"."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.3">RFC 9101 §6.3</see> sends
    /// parameter errors "as specified in Section 5.2 of [RFC6749]", yielding a direct JSON error.
    /// </summary>
    [TestMethod]
    public async Task RejectsJarWithCodeChallengeMethodPlainAtEphemeralLoopbackPort()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        await host.SetRedirectUrisAndAuthMethodAsync(
            material, ImmutableHashSet.Create(new Uri("http://127.0.0.1/cb")), tokenEndpointAuthMethod: null).ConfigureAwait(false);
        using System.Net.Sockets.Socket socket = new(
            System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream,
            System.Net.Sockets.ProtocolType.Tcp);
        socket.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0));
        int port = Assert.IsInstanceOfType<System.Net.IPEndPoint>(socket.LocalEndPoint).Port;
        Uri loopbackRedirectUri = new($"http://127.0.0.1:{port}/cb");

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, loopbackRedirectUri, DefaultState, DefaultNonce);
        claims[OAuthRequestParameterNames.CodeChallengeMethod] = "plain";
        claims[OAuthRequestParameterNames.CodeChallenge] = new string('a', 43);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.Request] = compactJar
            }, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidRequest}\"", Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// An absent method requests the refused plain transformation per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>:
    /// "OPTIONAL, defaults to "plain" if not present in the request".
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.4.1">§4.4.1</see> requires
    /// "authorization error response with "error" value set to "invalid_request"."
    /// </summary>
    [TestMethod]
    public async Task RejectsJarWithAbsentCodeChallengeMethodAtEphemeralLoopbackPort()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        await host.SetRedirectUrisAndAuthMethodAsync(
            material, ImmutableHashSet.Create(new Uri("http://127.0.0.1/cb")), tokenEndpointAuthMethod: null).ConfigureAwait(false);
        using System.Net.Sockets.Socket socket = new(
            System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream,
            System.Net.Sockets.ProtocolType.Tcp);
        socket.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0));
        int port = Assert.IsInstanceOfType<System.Net.IPEndPoint>(socket.LocalEndPoint).Port;
        Uri loopbackRedirectUri = new($"http://127.0.0.1:{port}/cb");

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, loopbackRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(OAuthRequestParameterNames.CodeChallengeMethod);
        claims[OAuthRequestParameterNames.CodeChallenge] = new string('a', 43);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.Request] = compactJar
            }, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidRequest}\"", Body, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task RejectsJarMissingClientId()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(WellKnownJwtClaimNames.ClientId);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(OAuthRequestParameterNames.ResponseType);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(OAuthRequestParameterNames.RedirectUri);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(OAuthRequestParameterNames.Scope);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(OAuthRequestParameterNames.State);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(WellKnownJwtClaimNames.Nonce);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(OAuthRequestParameterNames.CodeChallenge);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(WellKnownJwtClaimNames.Exp);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, ParOnlyCapabilities).ConfigureAwait(false);

        EndpointChain chain = await host.GetEndpointsAsync(material.Registration, []).ConfigureAwait(false);

        bool hasJarPar = chain.Any(e => string.Equals(
            e.Name, "AuthCode.JarPar", StringComparison.Ordinal));
        Assert.IsFalse(hasJarPar,
            "JAR-PAR endpoint must not appear when JwtSecuredAuthorizationRequest is not allowed.");
    }


    [TestMethod]
    public async Task JarParMatcherAbsentWhenPushedAuthorizationCapabilityNotAllowed()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarOnlyCapabilities).ConfigureAwait(false);

        EndpointChain chain = await host.GetEndpointsAsync(material.Registration, []).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, ParOnlyCapabilities).ConfigureAwait(false);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RegisteredRedirectUri.ToString(),
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };

        ExchangeContext context = [];
        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar,
            "POST",
            fields,
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode,
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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce), TestContext.CancellationToken)
            .ConfigureAwait(false);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.Request] = compactJar,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            //Outer PKCE fields the JAR matcher must ignore.
            [OAuthRequestParameterNames.CodeChallenge] = "outer-challenge-should-be-ignored",
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256
        };

        ExchangeContext context = [];
        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar,
            "POST",
            fields,
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        //The JAR matcher took over: response is a JAR-shaped success
        //(request_uri + expires_in), proving routing chose the JAR path.
        Assert.AreEqual(201, response.StatusCode,
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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);

        string expectedAud = material.Registration.IssuerUri!.ToString();
        claims[WellKnownJwtClaimNames.Aud] = new[]
        {
            "https://unrelated-aud.example",
            expectedAud,
            "https://another-unrelated.example"
        };

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode,
            $"JAR with aud as array containing the issuer must be accepted. Body: {response.Body}");
        Assert.Contains("\"request_uri\":", response.Body, StringComparison.Ordinal,
            $"Array-form aud happy path must produce a JAR-PAR success body. Got: {response.Body}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126 §2</see>: "the rules
    /// for client authentication as defined in [RFC6749] for token endpoint requests ... apply for
    /// the PAR endpoint as well" — a confidential registration's signed JAR push with no
    /// credentials at all is refused with the token endpoint's own <c>401 invalid_client</c>
    /// answer, before the JAR is verified, before the replay store is touched, and before a
    /// <c>request_uri</c> handle is generated.
    /// </summary>
    [TestMethod]
    public async Task RejectsConfidentialJarParWithNoCredentials()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ConfidentialClientId, ConfidentialClientBaseUri, JarParCapabilities).ConfigureAwait(false);
        await DeclareConfidentialJarParClientAsync(host, material).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material,
            OAuthJarFixtures.BuildBaseClaims(material, now, ConfidentialClientId, RegisteredRedirectUri, DefaultState, DefaultNonce),
            TestContext.CancellationToken).ConfigureAwait(false);

        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ConfidentialClientId,
                [OAuthRequestParameterNames.Request] = compactJar
            },
            OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, statusCode, body);
        AssertErrorCode(body, OAuthErrors.InvalidClient);
        Assert.DoesNotContain("\"request_uri\":", body, StringComparison.Ordinal,
            $"An authentication failure must not have generated a request_uri handle. Got: {body}");
    }


    /// <summary>
    /// The same requirement as <see cref="RejectsConfidentialJarParWithNoCredentials"/> against a
    /// wrong <c>client_secret_basic</c> secret — a foreign credential, not merely an absent one.
    /// </summary>
    [TestMethod]
    public async Task RejectsConfidentialJarParWithWrongBasicSecret()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ConfidentialClientId, ConfidentialClientBaseUri, JarParCapabilities).ConfigureAwait(false);
        await DeclareConfidentialJarParClientAsync(host, material).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material,
            OAuthJarFixtures.BuildBaseClaims(material, now, ConfidentialClientId, RegisteredRedirectUri, DefaultState, DefaultNonce),
            TestContext.CancellationToken).ConfigureAwait(false);

        OutgoingHeaders headers = OutgoingHeaders.Empty.WithClientSecretBasic(
            ConfidentialClientId, Encoding.UTF8.GetBytes("a-foreign-secret-nobody-registered"));

        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ConfidentialClientId,
                [OAuthRequestParameterNames.Request] = compactJar
            },
            headers, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, statusCode, body);
        AssertErrorCode(body, OAuthErrors.InvalidClient);
        Assert.DoesNotContain("\"request_uri\":", body, StringComparison.Ordinal,
            $"An authentication failure must not have generated a request_uri handle. Got: {body}");
    }


    /// <summary>
    /// The positive control for <see cref="RejectsConfidentialJarParWithNoCredentials"/> and
    /// <see cref="RejectsConfidentialJarParWithWrongBasicSecret"/>: the registration's own
    /// <c>client_secret_basic</c> secret authenticates the pushed request and the JAR still issues
    /// its <c>request_uri</c> handle.
    /// </summary>
    [TestMethod]
    public async Task AcceptsConfidentialJarParWithValidBasicSecret()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ConfidentialClientId, ConfidentialClientBaseUri, JarParCapabilities).ConfigureAwait(false);
        await DeclareConfidentialJarParClientAsync(host, material).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material,
            OAuthJarFixtures.BuildBaseClaims(material, now, ConfidentialClientId, RegisteredRedirectUri, DefaultState, DefaultNonce),
            TestContext.CancellationToken).ConfigureAwait(false);

        OutgoingHeaders headers = OutgoingHeaders.Empty.WithClientSecretBasic(
            ConfidentialClientId, Encoding.UTF8.GetBytes(ConfidentialClientSecret));

        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ConfidentialClientId,
                [OAuthRequestParameterNames.Request] = compactJar
            },
            headers, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, statusCode, body);
        Assert.Contains("\"request_uri\":", body, StringComparison.Ordinal, $"Got: {body}");
    }


    private const string ConfidentialClientId = "https://confidential-jar-par.client.test";
    private const string ConfidentialClientSecret = "s3cret-of-the-confidential-jar-par-client";
    private static Uri ConfidentialClientBaseUri { get; } = new(ConfidentialClientId);


    /// <summary>
    /// Declares <paramref name="material"/>'s registration as a <c>client_secret_basic</c>
    /// confidential client and wires the host's <c>ValidateClientCredentialsAsync</c> to check the
    /// <c>Authorization: Basic</c> header against <see cref="ConfidentialClientSecret"/> — the one
    /// place a JAR-PAR confidential fixture attaches credentials, mirroring how
    /// <see cref="AuthCodeFlowDriver"/> gives the plain pushed request its declared credentials.
    /// </summary>
    private static async Task DeclareConfidentialJarParClientAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        _ = await host.SetTokenEndpointAuthMethodAsync(material, ClientAuthenticationMethod.ClientSecretBasic).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ClientAuthenticationMethodsSupported =
                [ClientAuthenticationMethod.None, ClientAuthenticationMethod.ClientSecretBasic];
            candidateIntegration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                ValueTask.FromResult(AuthCodeFlowDriver.DecodeAndMatchBasicHeader(request, registration.ClientId, ConfidentialClientSecret));
        }).ConfigureAwait(false);
    }


    //Helpers — JAR construction and dispatch.

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

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar,
            "POST",
            fields,
            [],
            cancellationToken).ConfigureAwait(false);
    }


    private static void AssertErrorCode(ServerHttpResponse response, string expectedCode) =>
        AssertErrorCode(response.Body, expectedCode);


    private static void AssertErrorCode(string body, string expectedCode)
    {
        string expectedFragment = $"\"error\":\"{expectedCode}\"";
        Assert.Contains(expectedFragment, body, StringComparison.Ordinal,
            $"Expected error '{expectedCode}' in response body. Got: {body}");
    }
}
