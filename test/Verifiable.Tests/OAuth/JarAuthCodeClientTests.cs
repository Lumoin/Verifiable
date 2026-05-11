using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
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

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private const string ClientId = "https://client.example.com";
    private static readonly Uri ClientBaseUri = new("https://client.example.com");

    private static readonly ImmutableHashSet<ServerCapabilityName> JarParCapabilities =
        ImmutableHashSet.Create(
            ServerCapabilityName.AuthorizationCode,
            ServerCapabilityName.PushedAuthorization,
            ServerCapabilityName.JwtSecuredAuthorizationRequest);

    private static readonly ImmutableHashSet<ServerCapabilityName> JarAuthorizeCapabilities =
        ImmutableHashSet.Create(
            ServerCapabilityName.AuthorizationCode,
            ServerCapabilityName.DirectAuthorization,
            ServerCapabilityName.JwtSecuredAuthorizationRequest);

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);


    [TestMethod]
    public async Task JarParAsyncRoundTripsThroughBuildJarParMatcher()
    {
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        OAuthClient client = BuildAuthCodeClient(host, material);

        AuthCodeFlowEndpointResult result = await client.AuthCode.StartJarParAsync(
            new AuthCodeStartJarParOptions
            {
                Scope = WellKnownScopes.OpenId,
                SigningKey = material.SigningPrivateKey,
                SigningKeyId = material.SigningKeyId.Value,
                HeaderSerializer = HeaderSerializer,
                PayloadSerializer = PayloadSerializer,
                MemoryPool = SensitiveMemoryPool<byte>.Shared
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, result.Outcome,
            $"Expected Redirect outcome. ErrorCode={result.ErrorCode} ErrorDescription={result.ErrorDescription}");
        Assert.IsNotNull(result.RedirectUri);
        Assert.Contains(OAuthRequestParameters.RequestUri, result.RedirectUri!.Query, StringComparison.Ordinal,
            "Authorize redirect URI must carry the PAR-issued request_uri.");
    }


    [TestMethod]
    public async Task JarAuthorizeAsyncRoundTripsThroughBuildAuthorizeJarByValueMatcher()
    {
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarAuthorizeCapabilities);

        OAuthClient client = BuildAuthCodeClient(host, material);

        AuthCodeFlowEndpointResult result = await client.AuthCode.StartJarAuthorizeAsync(
            new AuthCodeStartJarAuthorizeOptions
            {
                Scope = WellKnownScopes.OpenId,
                SigningKey = material.SigningPrivateKey,
                SigningKeyId = material.SigningKeyId.Value,
                HeaderSerializer = HeaderSerializer,
                PayloadSerializer = PayloadSerializer,
                MemoryPool = SensitiveMemoryPool<byte>.Shared
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, result.Outcome);
        Assert.IsNotNull(result.RedirectUri);
        Assert.Contains(OAuthRequestParameters.Request, result.RedirectUri!.Query, StringComparison.Ordinal,
            "Authorize redirect URI must carry the signed JAR as the 'request' query parameter.");
        Assert.Contains(OAuthRequestParameters.ClientId, result.RedirectUri.Query, StringComparison.Ordinal,
            "Authorize redirect URI must carry the outer 'client_id' per RFC 9101 §6.1.");
    }


    [TestMethod]
    public async Task JarParAsyncSurfacesCancellation()
    {
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarParCapabilities);

        OAuthClient client = BuildAuthCodeClient(host, material);

        using CancellationTokenSource cts = new();
        await cts.CancelAsync().ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
        {
            _ = await client.AuthCode.StartJarParAsync(
                new AuthCodeStartJarParOptions
                {
                    Scope = WellKnownScopes.OpenId,
                    SigningKey = material.SigningPrivateKey,
                    SigningKeyId = material.SigningKeyId.Value,
                    HeaderSerializer = HeaderSerializer,
                    PayloadSerializer = PayloadSerializer,
                    MemoryPool = SensitiveMemoryPool<byte>.Shared
                },
                cts.Token).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task JarAuthorizeAsyncSurfacesCancellation()
    {
        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarAuthorizeCapabilities);

        OAuthClient client = BuildAuthCodeClient(host, material);

        using CancellationTokenSource cts = new();
        await cts.CancelAsync().ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
        {
            _ = await client.AuthCode.StartJarAuthorizeAsync(
                new AuthCodeStartJarAuthorizeOptions
                {
                    Scope = WellKnownScopes.OpenId,
                    SigningKey = material.SigningPrivateKey,
                    SigningKeyId = material.SigningKeyId.Value,
                    HeaderSerializer = HeaderSerializer,
                    PayloadSerializer = PayloadSerializer,
                    MemoryPool = SensitiveMemoryPool<byte>.Shared
                },
                cts.Token).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    private static OAuthClient BuildAuthCodeClient(
        TestHostShell host,
        VerifierKeyMaterial material) =>
        host.CreateOAuthClient(
            material.Registration,
            "https://client.example.com/callback",
            material.Registration.IssuerUri!.ToString());
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

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private const string ClientId = "https://client.example.com";
    private static readonly Uri ClientBaseUri = new("https://client.example.com");

    private static readonly ImmutableHashSet<ServerCapabilityName> JarParCapabilities =
        ImmutableHashSet.Create(
            ServerCapabilityName.AuthorizationCode,
            ServerCapabilityName.PushedAuthorization,
            ServerCapabilityName.JwtSecuredAuthorizationRequest);

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer PayloadSerializer =
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

        using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterJarSigningClient(
            ClientId, ClientBaseUri, keyPair, JarParCapabilities);

        OAuthClient client = host.CreateOAuthClient(
            material.Registration,
            "https://client.example.com/callback",
            material.Registration.IssuerUri!.ToString());

        AuthCodeFlowEndpointResult result = await client.AuthCode.StartJarParAsync(
            new AuthCodeStartJarParOptions
            {
                Scope = WellKnownScopes.OpenId,
                SigningKey = material.SigningPrivateKey,
                SigningKeyId = material.SigningKeyId.Value,
                HeaderSerializer = HeaderSerializer,
                PayloadSerializer = PayloadSerializer,
                MemoryPool = SensitiveMemoryPool<byte>.Shared
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, result.Outcome,
            $"[{algorithm}] expected Redirect outcome. ErrorCode={result.ErrorCode} ErrorDescription={result.ErrorDescription}");
        Assert.IsNotNull(result.RedirectUri);
        Assert.Contains(OAuthRequestParameters.RequestUri, result.RedirectUri!.Query, StringComparison.Ordinal);
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
