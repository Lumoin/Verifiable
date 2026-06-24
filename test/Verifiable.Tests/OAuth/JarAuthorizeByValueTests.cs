using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Net;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
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

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;
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
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities, PolicyProfile.Rfc6749WithPkce);

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
        await using TestHostShell host = new(TimeProvider);
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
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims[OAuthRequestParameterNames.RedirectUri] = "https://attacker.example.com/steal";

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
        await using TestHostShell host = new(TimeProvider);
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
        await using TestHostShell host = new(TimeProvider);
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
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims.Remove(WellKnownJwtClaimNames.ClientId);

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
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims.Remove(WellKnownJwtClaimNames.Exp);

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims[WellKnownJwtClaimNames.Iat] = now.ToUnixTimeSeconds();
        claims[WellKnownJwtClaimNames.Nbf] = now.ToUnixTimeSeconds();
        claims[WellKnownJwtClaimNames.Exp] = (now - TimeSpan.FromSeconds(10)).ToUnixTimeSeconds();

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims[WellKnownJwtClaimNames.Iat] = now.ToUnixTimeSeconds();
        claims[WellKnownJwtClaimNames.Nbf] = (now + TimeSpan.FromSeconds(30)).ToUnixTimeSeconds();
        claims[WellKnownJwtClaimNames.Exp] = (now + TimeSpan.FromSeconds(10)).ToUnixTimeSeconds();

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
        await using TestHostShell host = new(TimeProvider);
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
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims[WellKnownJwtClaimNames.Aud] = "https://different-issuer.example.com/";

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
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims[OAuthRequestParameterNames.CodeChallengeMethod] = "plain";

        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task JarAuthorizeMatcherAbsentWhenJwtSecuredAuthorizationRequestCapabilityNotAllowed()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, DirectOnlyCapabilities);

        EndpointChain chain = await host.GetEndpointsAsync(material.Registration, new ExchangeContext()).ConfigureAwait(false);

        bool hasJarAuthorize = chain.Any(e => string.Equals(
            e.Name, "AuthCode.AuthorizeJarByValue", StringComparison.Ordinal));
        Assert.IsFalse(hasJarAuthorize,
            "JAR-by-value Authorize endpoint must not appear when JwtSecuredAuthorizationRequest is not allowed.");
    }


    [TestMethod]
    public async Task JarAuthorizeMatcherAbsentWhenDirectAuthorizationCapabilityNotAllowed()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarOnlyCapabilities);

        EndpointChain chain = await host.GetEndpointsAsync(material.Registration, new ExchangeContext()).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, DirectOnlyCapabilities, PolicyProfile.Rfc6749WithPkce);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RegisteredRedirectUri.ToString(),
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };

        ExchangeContext context = new();
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
        Assert.Contains("code=", response.Location!, StringComparison.Ordinal,
            $"Redirect Location must include the authorization code. Got: {response.Location}");
    }


    [TestMethod]
    public async Task StaleAuthenticationBeyondDirectMaxAgeFailsWithUnmetRequirement()
    {
        //RFC 9470 §5 / OIDC Core §3.1.2.1 — a direct (non-JAR) authorize request that
        //carries max_age must fail with unmet_authentication_requirements when the
        //established authentication is older than max_age (beyond the default 60 s skew).
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, DirectOnlyCapabilities, PolicyProfile.Rfc6749WithPkce);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RegisteredRedirectUri.ToString(),
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.MaxAge] = "300"
        };

        ExchangeContext context = new();
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
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities, PolicyProfile.Rfc6749WithPkce);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims[OAuthRequestParameterNames.MaxAge] = 300L;
        string compactJar = await BuildSignedJarAsync(
            material, now, claims, TestContext.CancellationToken).ConfigureAwait(false);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.Request] = compactJar,
            [OAuthRequestParameterNames.ClientId] = ClientId
        };
        ExchangeContext context = new();
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
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, DirectOnlyCapabilities, PolicyProfile.Rfc6749WithPkce);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RegisteredRedirectUri.ToString(),
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.State] = "direct-state-xyz"
        };

        ExchangeContext context = new();
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
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities, PolicyProfile.Rfc6749WithPkce);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await BuildSignedJarAsync(
            material, now, BuildBaseClaims(material, now), TestContext.CancellationToken)
            .ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAuthorizeAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode, response.Body);
        //BuildBaseClaims sets state = "state-jar-direct-01"; it must round-trip onto the redirect.
        Assert.Contains("state=state-jar-direct-01", response.Location!, StringComparison.Ordinal,
            $"The JAR-by-value success redirect must echo the request object's state. Location: {response.Location}");
    }


    [TestMethod]
    public async Task RejectsDirectAuthorizeWhenProfileRequiresPushedAuthorizationRequests()
    {
        //FAPI 2.0 §5.2.2 — under a PAR-mandating profile (the default Haip10/Fapi20),
        //the direct Authorize path is refused with invalid_request.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, DirectOnlyCapabilities);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RegisteredRedirectUri.ToString(),
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };

        ExchangeContext context = new();
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
        Assert.Contains(OAuthErrors.InvalidRequest, response.Body!, StringComparison.Ordinal,
            $"Refusal must carry invalid_request. Got: {response.Body}");
        Assert.Contains("Pushed Authorization Requests", response.Body!, StringComparison.Ordinal,
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
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await BuildSignedJarAsync(
            material, now, BuildBaseClaims(material, now), TestContext.CancellationToken)
            .ConfigureAwait(false);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.Request] = compactJar,
            [OAuthRequestParameterNames.RequestUri] = "urn:ietf:params:oauth:request_uri:abc123",
            [OAuthRequestParameterNames.ClientId] = ClientId
        };

        ExchangeContext context = new();
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
        Assert.Contains(OAuthErrors.InvalidRequest, response.Body!, StringComparison.Ordinal,
            $"Both-present rejection must carry the invalid_request error code. Got: {response.Body}");
        Assert.Contains("request_uri", response.Body!, StringComparison.Ordinal,
            $"Both-present rejection must name the RFC 9101 §5 conflict. Got: {response.Body}");
    }


    [TestMethod]
    public async Task RejectsJarWithIssuerNotMatchingClientId()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims[WellKnownJwtClaimNames.Iss] = "https://impostor.example.com";

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
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims.Remove(WellKnownJwtClaimNames.Aud);

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
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarDirectCapabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = BuildBaseClaims(material, now);
        claims[WellKnownJwtClaimNames.Exp] = (now + TimeSpan.FromMinutes(5)).ToUnixTimeSeconds();

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
            [WellKnownJwtClaimNames.Iss] = ClientId,
            [WellKnownJwtClaimNames.Aud] = expectedAud,
            [WellKnownJwtClaimNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.RedirectUri] = RegisteredRedirectUri.ToString(),
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.State] = "state-jar-direct-01",
            [WellKnownJwtClaimNames.Nonce] = "nonce-jar-direct-01",
            [OAuthRequestParameterNames.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
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

        ExchangeContext context = new();
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
