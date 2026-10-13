using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Client-side tests for the JAR-bearing AuthCode methods on
/// <see cref="AuthCodeClient"/>: <c>StartJarParAsync</c> and
/// <c>StartJarAuthorizeAsync</c>. Each test round-trips through the in-process
/// Authorization Server exposed by <see cref="TestHostShell"/> so the signed
/// JAR's wire shape is validated by the existing
/// <c>AuthCodeEndpoints.BuildJarPar</c> / <c>BuildAuthorizeJarByValue</c>
/// matchers, not by an isolated harness.
/// </summary>
/// <remarks>
/// ES256 only at this step. PQ parameterisation rides in
/// <see cref="JarAuthCodeClientPqTests"/> as a follow-up.
/// </remarks>
[TestClass]
internal sealed class JarAuthCodeClientTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private const string ClientId = "https://client.example.com";
    private static Uri ClientBaseUri { get; } = new("https://client.example.com");
    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

    private static ImmutableHashSet<CapabilityIdentifier> JarParCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest);

    private static ImmutableHashSet<CapabilityIdentifier> JarAuthorizeCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthDirectAuthorization,
            WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest);

    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);


    [TestMethod]
    public async Task JarParAsyncRoundTripsThroughBuildJarParMatcher()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration) = BuildAuthCodeClient(host, material);

        AuthCodeFlowEndpointResult result = await client.AuthCode.StartJarParAsync(
            registration,
            new AuthCodeStartJarParOptions
            {
                Scope = WellKnownScopes.OpenId,
                SigningKey = material.SigningPrivateKey,
                SigningKeyId = material.SigningKeyId.Value,
                RedirectUri = RedirectUri,
                HeaderSerializer = HeaderSerializer,
                PayloadSerializer = PayloadSerializer,
                MemoryPool = BaseMemoryPool.Shared
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, result.Outcome,
            $"Expected Redirect outcome. ErrorCode={result.ErrorCode} ErrorDescription={result.ErrorDescription}");
        Assert.IsNotNull(result.RedirectUri);
        Assert.Contains(OAuthRequestParameterNames.RequestUri, result.RedirectUri.Query, StringComparison.Ordinal,
            "Authorize redirect URI must carry the PAR-issued request_uri.");
    }


    [TestMethod]
    public async Task JarAuthorizeAsyncRoundTripsThroughBuildAuthorizeJarByValueMatcher()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarAuthorizeCapabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration) = BuildAuthCodeClient(host, material);

        AuthCodeFlowEndpointResult result = await client.AuthCode.StartJarAuthorizeAsync(
            registration,
            new AuthCodeStartJarAuthorizeOptions
            {
                Scope = WellKnownScopes.OpenId,
                SigningKey = material.SigningPrivateKey,
                SigningKeyId = material.SigningKeyId.Value,
                RedirectUri = RedirectUri,
                HeaderSerializer = HeaderSerializer,
                PayloadSerializer = PayloadSerializer,
                MemoryPool = BaseMemoryPool.Shared
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, result.Outcome);
        Assert.IsNotNull(result.RedirectUri);
        Assert.Contains(OAuthRequestParameterNames.Request, result.RedirectUri.Query, StringComparison.Ordinal,
            "Authorize redirect URI must carry the signed JAR as the 'request' query parameter.");
        Assert.Contains(OAuthRequestParameterNames.ClientId, result.RedirectUri.Query, StringComparison.Ordinal,
            "Authorize redirect URI must carry the outer 'client_id' per RFC 9101 Section 5.");
    }


    [TestMethod]
    public async Task JarParAsyncSurfacesCancellation()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration) = BuildAuthCodeClient(host, material);

        using CancellationTokenSource cts = new();
        await cts.CancelAsync().ConfigureAwait(false);

        _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
        {
            _ = await client.AuthCode.StartJarParAsync(
                registration,
                new AuthCodeStartJarParOptions
                {
                    Scope = WellKnownScopes.OpenId,
                    SigningKey = material.SigningPrivateKey,
                    SigningKeyId = material.SigningKeyId.Value,
                    RedirectUri = RedirectUri,
                    HeaderSerializer = HeaderSerializer,
                    PayloadSerializer = PayloadSerializer,
                    MemoryPool = BaseMemoryPool.Shared
                },
                cts.Token).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task JarAuthorizeAsyncSurfacesCancellation()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarAuthorizeCapabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration) = BuildAuthCodeClient(host, material);

        using CancellationTokenSource cts = new();
        await cts.CancelAsync().ConfigureAwait(false);

        _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
        {
            _ = await client.AuthCode.StartJarAuthorizeAsync(
                registration,
                new AuthCodeStartJarAuthorizeOptions
                {
                    Scope = WellKnownScopes.OpenId,
                    SigningKey = material.SigningPrivateKey,
                    SigningKeyId = material.SigningKeyId.Value,
                    RedirectUri = RedirectUri,
                    HeaderSerializer = HeaderSerializer,
                    PayloadSerializer = PayloadSerializer,
                    MemoryPool = BaseMemoryPool.Shared
                },
                cts.Token).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// The library's own rule for a lifetime it issues: the client writes a request object's <c>iat</c> and
    /// <c>exp</c> as whole-second NumericDates, so it issues the request object for the whole seconds of its
    /// configured lifetime. A <see cref="AuthCodeStartJarAuthorizeOptions.JarLifetime"/> of 90.7 seconds, the request
    /// object issued half a second past a whole second, gives a request object whose <c>exp</c> is 90 seconds after its
    /// <c>iat</c>. <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5.1">RFC 9101 Section 5.1</see> passes the
    /// request object by value: "The client sends the authorization request as a Request Object to the authorization
    /// endpoint as the "request" parameter value."
    /// </summary>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    public async Task ARequestObjectByValueUnderAFractionalLifetimeLivesItsWholeSecondsAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarAuthorizeCapabilities).ConfigureAwait(false);
        (OAuthClient client, ClientRegistration registration) = BuildAuthCodeClient(host, material);
        TimeProvider.Advance(TimeSpan.FromTicks(TimeSpan.TicksPerSecond / 2));

        AuthCodeFlowEndpointResult result = await client.AuthCode.StartJarAuthorizeAsync(
            registration,
            new AuthCodeStartJarAuthorizeOptions
            {
                Scope = WellKnownScopes.OpenId,
                SigningKey = material.SigningPrivateKey,
                SigningKeyId = material.SigningKeyId.Value,
                RedirectUri = RedirectUri,
                HeaderSerializer = HeaderSerializer,
                PayloadSerializer = PayloadSerializer,
                MemoryPool = BaseMemoryPool.Shared,
                JarLifetime = TimeSpan.FromTicks(907_000_000L)
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result.RedirectUri, $"ErrorCode={result.ErrorCode} ErrorDescription={result.ErrorDescription}");
        string requestObject = ReadQueryParameter(result.RedirectUri, OAuthRequestParameterNames.Request);
        Assert.AreEqual(90L, ReadLifetimeSeconds(requestObject), requestObject);
    }


    /// <summary>
    /// The library's own rule for a lifetime it issues: the client writes a request object's <c>iat</c> and
    /// <c>exp</c> as whole-second NumericDates, so it issues the request object for the whole seconds of its
    /// configured lifetime. A <see cref="AuthCodeStartJarParOptions.JarLifetime"/> of 90.7 seconds, the request object
    /// issued half a second past a whole second, gives a pushed request object
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9126#section-3">RFC 9126 Section 3</see>) whose <c>exp</c>, as the
    /// pushed authorization endpoint receives it, is 90 seconds after its <c>iat</c>.
    /// </summary>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    public async Task APushedRequestObjectUnderAFractionalLifetimeLivesItsWholeSecondsAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);
        string? pushedRequestObject = null;
        (OAuthClient client, ClientRegistration registration, _) = host.CreateInProcessOAuthClientAndRegistration(
            material.Registration,
            "https://client.example.com/callback",
            material.Registration.IssuerUri!.ToString(),
            decorateSendFormPostAsync: send => (endpoint, fields, headers, context, ct) =>
            {
                foreach(KeyValuePair<string, string> field in fields)
                {
                    if(string.Equals(field.Key, OAuthRequestParameterNames.Request, StringComparison.Ordinal))
                    {
                        pushedRequestObject = field.Value;
                    }
                }

                return send(endpoint, fields, headers, context, ct);
            });
        TimeProvider.Advance(TimeSpan.FromTicks(TimeSpan.TicksPerSecond / 2));

        _ = await client.AuthCode.StartJarParAsync(
            registration,
            new AuthCodeStartJarParOptions
            {
                Scope = WellKnownScopes.OpenId,
                SigningKey = material.SigningPrivateKey,
                SigningKeyId = material.SigningKeyId.Value,
                RedirectUri = RedirectUri,
                HeaderSerializer = HeaderSerializer,
                PayloadSerializer = PayloadSerializer,
                MemoryPool = BaseMemoryPool.Shared,
                JarLifetime = TimeSpan.FromTicks(907_000_000L)
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(pushedRequestObject, "The pushed authorization request must carry the request object.");
        Assert.AreEqual(90L, ReadLifetimeSeconds(pushedRequestObject), pushedRequestObject);
    }


    /// <summary>
    /// The library's rule for the caller's own argument: a request object lifetime is at least one and at most
    /// <see cref="int.MaxValue"/> whole seconds, because the client writes <c>iat</c> and <c>exp</c> as whole-second
    /// NumericDates and a lifetime under one second would make <c>exp</c> equal <c>iat</c>. The <c>init</c> accessor
    /// of <see cref="AuthCodeStartJarParOptions.JarLifetime"/> and of
    /// <see cref="AuthCodeStartJarAuthorizeOptions.JarLifetime"/> refuses 500 milliseconds with
    /// <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    /// <param name="options">The options record the row sets the lifetime on.</param>
    [TestMethod]
    [DataRow(PushedOptions)]
    [DataRow(ByValueOptions)]
    public void ARequestObjectLifetimeUnderOneSecondIsRefusedAtItsOptions(string options)
    {
        TimeSpan lifetime = TimeSpan.FromMilliseconds(500);
        Action set = options switch
        {
            PushedOptions => () => _ = new AuthCodeStartJarParOptions
            {
                Scope = WellKnownScopes.OpenId,
                SigningKey = null!,
                SigningKeyId = "request-object-lifetime-key",
                RedirectUri = RedirectUri,
                HeaderSerializer = HeaderSerializer,
                PayloadSerializer = PayloadSerializer,
                MemoryPool = BaseMemoryPool.Shared,
                JarLifetime = lifetime
            },
            ByValueOptions => () => _ = new AuthCodeStartJarAuthorizeOptions
            {
                Scope = WellKnownScopes.OpenId,
                SigningKey = null!,
                SigningKeyId = "request-object-lifetime-key",
                RedirectUri = RedirectUri,
                HeaderSerializer = HeaderSerializer,
                PayloadSerializer = PayloadSerializer,
                MemoryPool = BaseMemoryPool.Shared,
                JarLifetime = lifetime
            },
            _ => throw new ArgumentOutOfRangeException(nameof(options), options, "Unknown options record.")
        };

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(set);
    }


    /// <summary>
    /// The row value naming <see cref="AuthCodeStartJarParOptions"/>. A constant because <see cref="DataRowAttribute"/>
    /// takes compile-time constants only.
    /// </summary>
    private const string PushedOptions = "pushed";


    /// <summary>
    /// The row value naming <see cref="AuthCodeStartJarAuthorizeOptions"/>. A constant because
    /// <see cref="DataRowAttribute"/> takes compile-time constants only.
    /// </summary>
    private const string ByValueOptions = "by value";


    /// <summary>
    /// Reads one query parameter of <paramref name="uri"/>, unescaped.
    /// </summary>
    /// <param name="uri">The URI whose query is read.</param>
    /// <param name="name">The parameter's name.</param>
    /// <returns>The parameter's value.</returns>
    private static string ReadQueryParameter(Uri uri, string name)
    {
        foreach(string pair in uri.Query.TrimStart('?').Split('&'))
        {
            int separator = pair.IndexOf('=', StringComparison.Ordinal);
            if(separator > 0 && string.Equals(Uri.UnescapeDataString(pair[..separator]), name, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(pair[(separator + 1)..]);
            }
        }

        throw new InvalidOperationException($"The URI carries no '{name}' parameter.");
    }


    /// <summary>
    /// Reads a compact JWT's <c>exp</c> less its <c>iat</c>, in seconds.
    /// </summary>
    /// <param name="compactJwt">The compact JWT.</param>
    /// <returns>The JWT's lifetime in seconds as its NumericDates state it.</returns>
    private static long ReadLifetimeSeconds(string compactJwt)
    {
        using JsonDocument payload = JwtPayloadReader.ParsePayloadJson(compactJwt);

        return payload.RootElement.GetProperty(WellKnownJwtClaimNames.Exp).GetInt64()
            - payload.RootElement.GetProperty(WellKnownJwtClaimNames.Iat).GetInt64();
    }


    private static (OAuthClient Client, ClientRegistration Registration) BuildAuthCodeClient(
        TestHostShell host,
        VerifierKeyMaterial material)
    {
        (OAuthClient client, ClientRegistration registration, _) = host.CreateInProcessOAuthClientAndRegistration(
            material.Registration,
            "https://client.example.com/callback",
            material.Registration.IssuerUri!.ToString());
        return (client, registration);
    }
}


/// <summary>
/// Cross-algorithm coverage for the JAR-bearing AuthCode methods. Exercises
/// every signature algorithm <see cref="CryptoFunctionRegistry{TAlgorithm,TPurpose}"/>
/// wires for signing (ES256, ES384, ES521, Secp256k1, RSA-2048, RSA-4096,
/// Ed25519, ML-DSA-44, ML-DSA-65, ML-DSA-87) through the same
/// <c>BuildJarPar</c> matcher round-trip that
/// <see cref="JarAuthCodeClientTests"/> covers for ES256.
/// </summary>
[TestClass]
internal sealed class JarAuthCodeClientPqTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private const string ClientId = "https://client.example.com";
    private static Uri ClientBaseUri { get; } = new("https://client.example.com");
    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

    private static ImmutableHashSet<CapabilityIdentifier> JarParCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest);

    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);


    [TestMethod]
    [DataRow("P256", DisplayName = "ES256")]
    [DataRow("P384", DisplayName = "ES384")]
    [DataRow("P521", DisplayName = "ES512")]
    [DataRow("Secp256k1", DisplayName = "ES256K")]
    [DataRow("Rsa2048", DisplayName = "RS256-2048")]
    [DataRow("Rsa4096", DisplayName = "RS256-4096")]
    [DataRow("Ed25519", DisplayName = "EdDSA")]
    [DataRow("MlDsa44", DisplayName = "ML-DSA-44")]
    [DataRow("MlDsa65", DisplayName = "ML-DSA-65")]
    [DataRow("MlDsa87", DisplayName = "ML-DSA-87")]
    public async Task JarParAsyncRoundTripsForEachAlgorithm(string algorithm)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            CreateFreshKeyMaterial(algorithm);

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterJarSigningClientAsync(
            ClientId, ClientBaseUri, keyPair, JarParCapabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, _) = host.CreateInProcessOAuthClientAndRegistration(
            material.Registration,
            "https://client.example.com/callback",
            material.Registration.IssuerUri!.ToString());

        AuthCodeFlowEndpointResult result = await client.AuthCode.StartJarParAsync(
            registration,
            new AuthCodeStartJarParOptions
            {
                Scope = WellKnownScopes.OpenId,
                SigningKey = material.SigningPrivateKey,
                SigningKeyId = material.SigningKeyId.Value,
                RedirectUri = RedirectUri,
                HeaderSerializer = HeaderSerializer,
                PayloadSerializer = PayloadSerializer,
                MemoryPool = BaseMemoryPool.Shared
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, result.Outcome,
            $"[{algorithm}] expected Redirect outcome. ErrorCode={result.ErrorCode} ErrorDescription={result.ErrorDescription}");
        Assert.IsNotNull(result.RedirectUri);
        Assert.Contains(OAuthRequestParameterNames.RequestUri, result.RedirectUri!.Query, StringComparison.Ordinal);
    }


    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateFreshKeyMaterial(string algorithm) =>
        algorithm switch
        {
            "P256" => TestKeyMaterialProvider.CreateFreshP256KeyMaterial(),
            "P384" => TestKeyMaterialProvider.CreateFreshP384KeyMaterial(),
            "P521" => TestKeyMaterialProvider.CreateFreshP521KeyMaterial(),
            "Secp256k1" => TestKeyMaterialProvider.CreateFreshSecp256k1KeyMaterial(),
            "Rsa2048" => TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial(),
            "Rsa4096" => TestKeyMaterialProvider.CreateFreshRsa4096KeyMaterial(),
            "Ed25519" => TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial(),
            "MlDsa44" => TestKeyMaterialProvider.CreateFreshMlDsa44KeyMaterial(),
            "MlDsa65" => TestKeyMaterialProvider.CreateFreshMlDsa65KeyMaterial(),
            "MlDsa87" => TestKeyMaterialProvider.CreateFreshMlDsa87KeyMaterial(),
            _ => throw new ArgumentException($"Unknown algorithm '{algorithm}'.", nameof(algorithm))
        };
}
