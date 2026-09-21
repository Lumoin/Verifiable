using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Net;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.Server.Pipeline;
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

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private const string ClientId = "https://client.example.com";
    private const string TestSubject = "test-subject-001";
    private const string JarState = "state-jar-direct-01";
    private const string JarNonce = "nonce-jar-direct-01";
    private static Uri ClientBaseUri { get; } = new("https://client.example.com");
    private static Uri RegisteredRedirectUri { get; } = new("https://client.example.com/callback");

    private static ImmutableHashSet<CapabilityIdentifier> JarDirectCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthDirectAuthorization,
            WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest);

    private static ImmutableHashSet<CapabilityIdentifier> DirectOnlyCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthDirectAuthorization);

    private static ImmutableHashSet<CapabilityIdentifier> JarOnlyCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest);


    [TestMethod]
    public async Task AcceptsValidAuthorizeJarByValueAndIssuesAuthorizationCode()
    {
        await using TestHostShell host = new(TimeProvider);
        //JAR-by-value is a non-PAR path; FAPI 2.0 (the default profile) forbids it, so
        //this exercises it under the RFC 6749 + PKCE profile, which permits it.
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarDirectCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material,
            OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce),
            TestContext.CancellationToken)
            .ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode,
            $"JAR-by-value direct authorize must redirect on success. Body: {response.Body}");
        Assert.IsNotNull(response.Location);
        Assert.Contains("code=", response.Location, StringComparison.Ordinal,
            $"Redirect Location must include the authorization code. Got: {response.Location}");
        Assert.StartsWith(
            RegisteredRedirectUri.ToString(),
            response.Location,
            StringComparison.Ordinal,
            $"Redirect Location must target the registered redirect_uri. Got: {response.Location}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 §5</see>: the front
    /// channel carries only <c>request</c>/<c>request_uri</c> and <c>client_id</c> as REQUIRED
    /// query parameters; every other OAuth 2.0 parameter, including
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">response_type</see>, rides
    /// inside the Request Object. This proves the omission still succeeds.
    /// </summary>
    [TestMethod]
    public async Task AcceptsJarByValueWithResponseTypeOnlyInRequestObject()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarDirectCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce);
        Assert.Contains(OAuthRequestParameterNames.ResponseType, claims.Keys,
            "The fixture carries response_type inside the signed claims, never in the outer query.");

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        //DispatchAuthorizeAsync's outer query never sets response_type — only
        //request and (optionally) client_id — so a success here proves the
        //Request Object claim alone drives the grant.
        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode,
            $"response_type carried only inside the Request Object must still issue a code. Body: {response.Body}");
        Assert.IsNotNull(response.Location);
        Assert.Contains("code=", response.Location, StringComparison.Ordinal,
            $"Redirect Location must include the authorization code. Got: {response.Location}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see>:
    /// "response_type: REQUIRED." <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.3">RFC 9101 §6.3</see>:
    /// "The authorization server MUST only use the parameters in the Request Object... The
    /// authorization server then validates the request, as specified in OAuth 2.0 [RFC6749]."
    /// A Request Object omitting a required claim is an invalid Request Object.
    /// </summary>
    [TestMethod]
    public async Task RejectsJarMissingResponseType()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarDirectCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce);
        _ = claims.Remove(OAuthRequestParameterNames.ResponseType);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithMissingOuterClientId()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarDirectCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material,
            OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce),
            TestContext.CancellationToken)
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
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarDirectCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce);
        claims[OAuthRequestParameterNames.RedirectUri] = "https://attacker.example.com/steal";

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
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
            ClientId, ClientBaseUri, JarDirectCapabilities).ConfigureAwait(false);

        DateTimeOffset signedAt = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material,
            OAuthJarFixtures.BuildBaseClaims(material, signedAt, ClientId, RegisteredRedirectUri, JarState, JarNonce),
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
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarDirectCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarWithCustomTypAsync(
            material.SigningPrivateKey,
            "JWT",
            OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce),
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
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarDirectCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce);
        _ = claims.Remove(WellKnownJwtClaimNames.ClientId);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
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
            ClientId, ClientBaseUri, JarDirectCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce);
        _ = claims.Remove(WellKnownJwtClaimNames.Exp);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithExpiryAtOrBeforeIssuance()
    {
        //exp 10s BEFORE iat: a non-positive lifetime. Within the 5-minute skew it is
        //neither "expired" nor "not yet valid", so only the mutual-consistency check
        //rejects it — without that check this JAR would be accepted.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarDirectCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce);
        claims[WellKnownJwtClaimNames.Iat] = now.ToUnixTimeSeconds();
        claims[WellKnownJwtClaimNames.Nbf] = now.ToUnixTimeSeconds();
        claims[WellKnownJwtClaimNames.Exp] = (now - TimeSpan.FromSeconds(10)).ToUnixTimeSeconds();

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithExpiryAtOrBeforeNotBefore()
    {
        //exp before nbf (but after iat): the validity window never opens. Within skew
        //it is not "not yet valid", so only the mutual-consistency check rejects it.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarDirectCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce);
        claims[WellKnownJwtClaimNames.Iat] = now.ToUnixTimeSeconds();
        claims[WellKnownJwtClaimNames.Nbf] = (now + TimeSpan.FromSeconds(30)).ToUnixTimeSeconds();
        claims[WellKnownJwtClaimNames.Exp] = (now + TimeSpan.FromSeconds(10)).ToUnixTimeSeconds();

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarSignedWithDifferentClientKey()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarDirectCapabilities).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> attackerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory attackerPublic = attackerKeys.PublicKey;
        using PrivateKeyMemory attackerPrivate = attackerKeys.PrivateKey;

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarWithKeyAsync(
            attackerPrivate,
            OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce),
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
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarDirectCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce);
        claims[WellKnownJwtClaimNames.Aud] = "https://different-issuer.example.com/";

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
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
            ClientId, ClientBaseUri, JarDirectCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce);
        claims[OAuthRequestParameterNames.CodeChallengeMethod] = "plain";
        claims[OAuthRequestParameterNames.CodeChallenge] = new string('a', 43);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Uri uri = new(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, material.Registration.TenantId.Value)
            + $"?client_id={Uri.EscapeDataString(ClientId)}&request={Uri.EscapeDataString(compactJar)}");
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, uri, TestSubject, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidRequest}\"", body, StringComparison.Ordinal);
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
            ClientId, ClientBaseUri, JarDirectCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce);
        _ = claims.Remove(OAuthRequestParameterNames.CodeChallengeMethod);
        claims[OAuthRequestParameterNames.CodeChallenge] = new string('a', 43);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Uri uri = new(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, material.Registration.TenantId.Value)
            + $"?client_id={Uri.EscapeDataString(ClientId)}&request={Uri.EscapeDataString(compactJar)}");
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, uri, TestSubject, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidRequest}\"", body, StringComparison.Ordinal);
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
            ClientId, ClientBaseUri, JarDirectCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await host.SetRedirectUrisAndAuthMethodAsync(
            material, ImmutableHashSet.Create(new Uri("http://127.0.0.1/cb")), tokenEndpointAuthMethod: null).ConfigureAwait(false);
        using System.Net.Sockets.Socket socket = new(
            System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream,
            System.Net.Sockets.ProtocolType.Tcp);
        socket.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0));
        int port = Assert.IsInstanceOfType<System.Net.IPEndPoint>(socket.LocalEndPoint).Port;
        Uri loopbackRedirectUri = new($"http://127.0.0.1:{port}/cb");

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, loopbackRedirectUri, JarState, JarNonce);
        claims[OAuthRequestParameterNames.CodeChallengeMethod] = "plain";
        claims[OAuthRequestParameterNames.CodeChallenge] = new string('a', 43);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Uri uri = new(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, material.Registration.TenantId.Value)
            + $"?client_id={Uri.EscapeDataString(ClientId)}&request={Uri.EscapeDataString(compactJar)}");
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, uri, TestSubject, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidRequest}\"", body, StringComparison.Ordinal);
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
            ClientId, ClientBaseUri, JarDirectCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await host.SetRedirectUrisAndAuthMethodAsync(
            material, ImmutableHashSet.Create(new Uri("http://127.0.0.1/cb")), tokenEndpointAuthMethod: null).ConfigureAwait(false);
        using System.Net.Sockets.Socket socket = new(
            System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream,
            System.Net.Sockets.ProtocolType.Tcp);
        socket.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0));
        int port = Assert.IsInstanceOfType<System.Net.IPEndPoint>(socket.LocalEndPoint).Port;
        Uri loopbackRedirectUri = new($"http://127.0.0.1:{port}/cb");

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, loopbackRedirectUri, JarState, JarNonce);
        _ = claims.Remove(OAuthRequestParameterNames.CodeChallengeMethod);
        claims[OAuthRequestParameterNames.CodeChallenge] = new string('a', 43);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Uri uri = new(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, material.Registration.TenantId.Value)
            + $"?client_id={Uri.EscapeDataString(ClientId)}&request={Uri.EscapeDataString(compactJar)}");
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, uri, TestSubject, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidRequest}\"", body, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task JarAuthorizeMatcherAbsentWhenJwtSecuredAuthorizationRequestCapabilityNotAllowed()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, DirectOnlyCapabilities).ConfigureAwait(false);

        EndpointChain chain = await host.GetEndpointsAsync(material.Registration, []).ConfigureAwait(false);

        bool hasJarAuthorize = chain.Any(e => string.Equals(
            e.Name, "AuthCode.AuthorizeJarByValue", StringComparison.Ordinal));
        Assert.IsFalse(hasJarAuthorize,
            "JAR-by-value Authorize endpoint must not appear when JwtSecuredAuthorizationRequest is not allowed.");
    }


    [TestMethod]
    public async Task JarAuthorizeMatcherAbsentWhenDirectAuthorizationCapabilityNotAllowed()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarOnlyCapabilities).ConfigureAwait(false);

        EndpointChain chain = await host.GetEndpointsAsync(material.Registration, []).ConfigureAwait(false);

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
        //(code_challenge + S256, no 'request' parameter). Direct authorize is a
        //non-PAR path forbidden under FAPI 2.0, so it runs under RFC 6749 + PKCE.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, DirectOnlyCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

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
        context.SetSubjectId(TestSubject);
        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize,
            "GET",
            fields,
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode,
            $"Pure PKCE direct authorize must still redirect. Body: {response.Body}");
        Assert.IsNotNull(response.Location);
        Assert.Contains("code=", response.Location, StringComparison.Ordinal,
            $"Redirect Location must include the authorization code. Got: {response.Location}");
    }


    [TestMethod]
    public async Task StaleAuthenticationBeyondDirectMaxAgeFailsWithUnmetRequirement()
    {
        //RFC 9470 §5 / OIDC Core §3.1.2.1 — a direct (non-JAR) authorize request that
        //carries max_age must fail with unmet_authentication_requirements when the
        //established authentication is older than max_age (beyond the default 60 s skew).
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, DirectOnlyCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RegisteredRedirectUri.ToString(),
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.MaxAge] = "300"
        };

        ExchangeContext context = [];
        context.SetSubjectId(TestSubject);
        context.SetAuthTime(now - TimeSpan.FromSeconds(600));

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, "GET",
            fields, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode, response.Body);
        Assert.Contains(
            $"error={OAuthErrors.UnmetAuthenticationRequirements}", response.Location!,
            StringComparison.Ordinal,
            $"A stale authentication on the direct authorize path must fail. Location: {response.Location}");
        Assert.DoesNotContain("code=", response.Location!, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task StaleAuthenticationBeyondJarMaxAgeFailsWithUnmetRequirement()
    {
        //RFC 9470 §5 — the max_age requirement carried inside a JAR-by-value request object
        //is enforced just like the query-parameter form: a stale authentication fails with
        //unmet_authentication_requirements. Proves the JAR projection carries max_age and the
        //shared enforcement runs on the signed-request path (closing the step-up bypass gap).
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarDirectCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce);
        claims[OAuthRequestParameterNames.MaxAge] = 300L;
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.Request] = compactJar,
            [OAuthRequestParameterNames.ClientId] = ClientId
        };
        ExchangeContext context = [];
        context.SetSubjectId(TestSubject);
        context.SetAuthTime(now - TimeSpan.FromSeconds(600));

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, "GET",
            fields, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode, response.Body);
        Assert.Contains(
            $"error={OAuthErrors.UnmetAuthenticationRequirements}", response.Location!,
            StringComparison.Ordinal,
            $"A stale authentication against a JAR max_age must fail. Location: {response.Location}");
        Assert.DoesNotContain("code=", response.Location!, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task DirectAuthorizeSuccessRedirectEchoesState()
    {
        //RFC 6749 §4.1.2 — the direct (query-parameter) authorize path captures state from the
        //request and echoes it on the success redirect alongside the code.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, DirectOnlyCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RegisteredRedirectUri.ToString(),
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.State] = "direct-state-xyz"
        };

        ExchangeContext context = [];
        context.SetSubjectId(TestSubject);
        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, "GET",
            fields, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode, response.Body);
        Assert.Contains("code=", response.Location!, StringComparison.Ordinal);
        Assert.Contains("state=direct-state-xyz", response.Location!, StringComparison.Ordinal,
            $"The direct authorize success redirect must echo state. Location: {response.Location}");
    }


    [TestMethod]
    public async Task JarByValueSuccessRedirectEchoesStateFromRequestObject()
    {
        //RFC 6749 §4.1.2 — the state carried inside the signed request object (a required JAR
        //claim) is echoed on the success redirect, proving the projection carries it through.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarDirectCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material,
            OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce),
            TestContext.CancellationToken)
            .ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode, response.Body);
        //OAuthJarFixtures.BuildBaseClaims was called with JarState ("state-jar-direct-01"); it
        //must round-trip onto the redirect.
        Assert.Contains("state=state-jar-direct-01", response.Location!, StringComparison.Ordinal,
            $"The JAR-by-value success redirect must echo the request object's state. Location: {response.Location}");
    }


    [TestMethod]
    public async Task RejectsDirectAuthorizeWhenProfileRequiresPushedAuthorizationRequests()
    {
        //FAPI 2.0 §5.2.2 — under a PAR-mandating profile (the default Haip10/Fapi20),
        //the direct Authorize path is refused with invalid_request.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, DirectOnlyCapabilities).ConfigureAwait(false);

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
        context.SetSubjectId(TestSubject);
        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize,
            "GET",
            fields,
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode,
            $"PAR-mandating profile must refuse direct authorize. Body: {response.Body}");
        Assert.Contains(OAuthErrors.InvalidRequest, response.Body, StringComparison.Ordinal,
            $"Refusal must carry invalid_request. Got: {response.Body}");
        Assert.Contains("Pushed Authorization Requests", response.Body, StringComparison.Ordinal,
            $"Refusal must name the PAR requirement. Got: {response.Body}");
    }


    [TestMethod]
    public async Task RejectsRequestWithBothRequestAndRequestUriParameters()
    {
        //RFC 9101 §5 — request and request_uri MUST NOT both be present.
        //BuildAuthorizeJarByValue's MatchesRequest declines (request_uri present),
        //so the JAR-by-value path does not run. The PAR-completed BuildAuthorize
        //matcher matches on request_uri presence and rejects the both-present case
        //explicitly with invalid_request — deterministically, before any flow-state
        //correlation, so the spec violation (not an incidental state error) is reported.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarDirectCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material,
            OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce),
            TestContext.CancellationToken)
            .ConfigureAwait(false);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.Request] = compactJar,
            [OAuthRequestParameterNames.RequestUri] = "urn:ietf:params:oauth:request_uri:abc123",
            [OAuthRequestParameterNames.ClientId] = ClientId
        };

        ExchangeContext context = [];
        context.SetSubjectId(TestSubject);
        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize,
            "GET",
            fields,
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        //The JAR-by-value matcher MUST NOT have produced a 302 with a code —
        //that would be silent "request" parameter picking.
        Assert.AreNotEqual((int)HttpStatusCode.Found, response.StatusCode,
            "JAR-by-value matcher must not silently process a request that also carries request_uri. " +
            $"Got {response.StatusCode}: {response.Body}");
        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode,
            $"Both-present must be an explicit invalid_request. Got {response.StatusCode}: {response.Body}");
        Assert.Contains(OAuthErrors.InvalidRequest, response.Body, StringComparison.Ordinal,
            $"Both-present rejection must carry the invalid_request error code. Got: {response.Body}");
        Assert.Contains("request_uri", response.Body, StringComparison.Ordinal,
            $"Both-present rejection must name the RFC 9101 §5 conflict. Got: {response.Body}");
    }


    [TestMethod]
    public async Task RejectsJarWithIssuerNotMatchingClientId()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarDirectCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce);
        claims[WellKnownJwtClaimNames.Iss] = "https://impostor.example.com";

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
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
            ClientId, ClientBaseUri, JarDirectCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce);
        _ = claims.Remove(WellKnownJwtClaimNames.Aud);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
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
            ClientId, ClientBaseUri, JarDirectCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RegisteredRedirectUri, JarState, JarNonce);
        claims[WellKnownJwtClaimNames.Exp] = (now + TimeSpan.FromMinutes(5)).ToUnixTimeSeconds();

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
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
            [OAuthRequestParameterNames.Request] = compactJar
        };

        if(outerClientId is not null)
        {
            fields[OAuthRequestParameterNames.ClientId] = outerClientId;
        }

        ExchangeContext context = [];
        context.SetSubjectId(TestSubject);

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize,
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
