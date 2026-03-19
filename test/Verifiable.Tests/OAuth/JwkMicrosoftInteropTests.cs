using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Verifies that the library's JWKS wire output is accepted by
/// <see cref="Microsoft.IdentityModel.Tokens.JsonWebKeySet"/>, the parser used
/// by the ASP.NET JWT bearer middleware and other relying-party stacks.
/// </summary>
/// <remarks>
/// <para>
/// The library can produce JWKS that looks structurally correct but fails to
/// parse in real relying-party code because a parameter name is wrong, an
/// encoding differs, or a required field is missing. This test suite catches
/// those regressions before they surface as interop failures in deployment.
/// </para>
/// <para>
/// Algorithms the middleware does not natively support — currently ML-DSA, for
/// which no .NET-side JOSE verifier is standardised — are not asserted here.
/// The library still emits them correctly; verification against specialised
/// post-quantum stacks lives elsewhere.
/// </para>
/// </remarks>
[TestClass]
internal sealed class JwkMicrosoftInteropTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(DateTimeOffset.Parse("2026-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture));

    private static readonly ImmutableHashSet<ServerCapabilityName> JwksCapabilities =
        ImmutableHashSet.Create(ServerCapabilityName.JwksEndpoint);


    [TestMethod]
    public async Task P256JwksParsesAsMicrosoftJsonWebKeySet()
    {
        await AssertMicrosoftParsesKeyAsync(
            TestKeyMaterialProvider.CreateP256KeyMaterial,
            expectedKty: WellKnownKeyTypeValues.Ec,
            expectedAlg: WellKnownJwaValues.Es256,
            expectedCrv: WellKnownCurveValues.P256).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task P384JwksParsesAsMicrosoftJsonWebKeySet()
    {
        await AssertMicrosoftParsesKeyAsync(
            TestKeyMaterialProvider.CreateP384KeyMaterial,
            expectedKty: WellKnownKeyTypeValues.Ec,
            expectedAlg: WellKnownJwaValues.Es384,
            expectedCrv: WellKnownCurveValues.P384).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task P521JwksParsesAsMicrosoftJsonWebKeySet()
    {
        await AssertMicrosoftParsesKeyAsync(
            TestKeyMaterialProvider.CreateP521KeyMaterial,
            expectedKty: WellKnownKeyTypeValues.Ec,
            expectedAlg: WellKnownJwaValues.Es512,
            expectedCrv: WellKnownCurveValues.P521).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task Rsa2048JwksParsesAsMicrosoftJsonWebKeySet()
    {
        await AssertMicrosoftParsesKeyAsync(
            TestKeyMaterialProvider.CreateRsa2048KeyMaterial,
            expectedKty: WellKnownKeyTypeValues.Rsa,
            expectedAlg: WellKnownJwaValues.Rs256,
            expectedCrv: null).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task Ed25519JwksParsesAsMicrosoftJsonWebKeySet()
    {
        await AssertMicrosoftParsesKeyAsync(
            TestKeyMaterialProvider.CreateEd25519KeyMaterial,
            expectedKty: WellKnownKeyTypeValues.Okp,
            expectedAlg: WellKnownJwaValues.EdDsa,
            expectedCrv: WellKnownCurveValues.Ed25519).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task Secp256k1JwksParsesAsMicrosoftJsonWebKeySet()
    {
        await AssertMicrosoftParsesKeyAsync(
            TestKeyMaterialProvider.CreateSecp256k1KeyMaterial,
            expectedKty: WellKnownKeyTypeValues.Ec,
            expectedAlg: WellKnownJwaValues.Es256k1,
            expectedCrv: WellKnownCurveValues.Secp256k1).ConfigureAwait(false);
    }


    private async Task AssertMicrosoftParsesKeyAsync(
        Func<PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>> createKeys,
        string expectedKty,
        string expectedAlg,
        string? expectedCrv)
    {
        using TestHostShell app = new(TimeProvider);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair = createKeys();

        ClientRegistration registration = app.RegisterSigningClient(
            $"client-{expectedKty}-{expectedAlg}", keyPair, JwksCapabilities);

        ServerHttpResponse response = await FetchJwksAsync(
            app, registration, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            $"JWKS endpoint must return HTTP 200 for {expectedAlg}.");

        //Microsoft's parser accepts the raw JWKS JSON and produces a
        //JsonWebKeySet whose Keys collection must expose the expected
        //cryptographic parameters.
        JsonWebKeySet parsed = JsonWebKeySet.Create(response.Body);

        Assert.HasCount(1, parsed.Keys,
            $"Microsoft JsonWebKeySet must contain exactly one key for {expectedAlg}.");

        global::Microsoft.IdentityModel.Tokens.JsonWebKey msJwk = parsed.Keys[0];

        Assert.AreEqual(expectedKty, msJwk.Kty,
            $"Microsoft-parsed kty must match library emission for {expectedAlg}.");
        Assert.AreEqual(expectedAlg, msJwk.Alg,
            $"Microsoft-parsed alg must match library emission for {expectedAlg}.");

        if(expectedCrv is not null)
        {
            Assert.AreEqual(expectedCrv, msJwk.Crv,
                $"Microsoft-parsed crv must match library emission for {expectedAlg}.");
        }
    }


    private static async Task<ServerHttpResponse> FetchJwksAsync(
        TestHostShell app,
        ClientRegistration registration,
        CancellationToken cancellationToken)
    {
        string segment = registration.TenantId;
        RequestContext context = new();
        context.SetTenantId(segment);
        context.SetIssuer(new Uri("https://issuer.example.com"));

        return await app.DispatchBySegmentAsync(
            segment,
            ServerCapabilityName.JwksEndpoint,
            "GET",
            new RequestFields(),
            context,
            cancellationToken).ConfigureAwait(false);
    }
}
