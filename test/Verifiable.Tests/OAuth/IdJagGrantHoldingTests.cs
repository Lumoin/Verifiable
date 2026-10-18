using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.IdJag;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The client's own holding of an identity assertion grant an identity provider minted for it
/// (<see cref="IdJagGrantHolding.HoldAsync"/>): a grant every check holds is held, and each check refuses by its own
/// <see cref="IdJagGrantRefusal"/> a grant failing it alone, so each row's negative passes only where the check binds.
/// </summary>
[TestClass]
internal sealed class IdJagGrantHoldingTests
{
    /// <summary>The identity provider's issuer.</summary>
    private const string ProviderIssuer = "https://idp.example.com";

    /// <summary>The Resource Authorization Server's issuer, the grant's one audience.</summary>
    private const string ResourceServer = "https://resource-as.example.com";

    /// <summary>The client identifier the client authenticates at the Resource Authorization Server with.</summary>
    private const string PresentedClientId = "https://client.example.com/client-metadata.json";

    /// <summary>The MCP server's resource identifier the exchange asked for.</summary>
    private const string AskedResource = "https://mcp.example.com/mcp";

    /// <summary>The key identifier the provider publishes its signing key under.</summary>
    private const string ProviderKeyId = "provider-key-1";

    /// <summary>The test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock the grant's temporal claims are judged by, at a fixed instant.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The expectations every row holds the grant to.</summary>
    private static IdJagGrantExpectations Expectations { get; } = new()
    {
        Issuer = ProviderIssuer,
        ResourceAuthorizationServer = ResourceServer,
        ClientId = PresentedClientId,
        Resource = AskedResource
    };


    /// <summary>A grant every check holds is held, its identifiers read as it carries them.</summary>
    [TestMethod]
    public async Task AGrantEveryCheckHoldsIsHeldWithItsIdentifiers()
    {
        var keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;
        var grant = await SignAsync(privateKey, Header(), Payload()).ConfigureAwait(false);

        var held = await HoldAsync(grant, publicKey, ProviderKeyId).ConfigureAwait(false);

        Assert.IsTrue(held.IsHeld, $"A grant every check holds is held; refused by {held.Refusal} {held.ClaimsFailure}.");
        Assert.AreEqual(ProviderIssuer, held.Facts.Issuer);
        Assert.AreEqual(ResourceServer, held.Facts.Audience);
        Assert.AreEqual(PresentedClientId, held.Facts.ClientId);
        Assert.AreEqual("grant-jti-1", held.Facts.TokenId);
        Assert.AreEqual(ProviderKeyId, held.Facts.KeyId);
        Assert.AreEqual(WellKnownJwaValues.Es256, held.Facts.Algorithm);
    }


    /// <summary>A grant of another <c>typ</c> is refused before its key is resolved.</summary>
    [TestMethod]
    public async Task AGrantOfAnotherTypeIsRefusedBeforeItsKeyIsResolved()
    {
        var keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;
        var header = Header();
        header[WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt;
        var grant = await SignAsync(privateKey, header, Payload()).ConfigureAwait(false);
        var resolved = 0;

        var held = await IdJagGrantHolding.HoldAsync(
            grant,
            Expectations,
            (keyId, algorithm, cancellationToken) =>
            {
                resolved++;

                return ValueTask.FromResult<PublicKeyMemory?>(CopyOf(publicKey));
            },
            TestSetup.Base64UrlDecoder,
            JwtPartJson.Default,
            BaseMemoryPool.Shared,
            TimeProvider,
            TimeSpan.FromSeconds(60),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(IdJagGrantRefusal.TypeNotIdJag, held.Refusal);
        Assert.AreEqual(0, resolved, "A grant of another typ is refused before its key is asked for.");
    }


    /// <summary>A grant naming another issuer than the provider's is refused.</summary>
    [TestMethod]
    public async Task AGrantOfAnotherIssuerIsRefused()
    {
        var keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;
        var payload = Payload();
        payload[WellKnownJwtClaimNames.Iss] = "https://other-idp.example.com";
        var grant = await SignAsync(privateKey, Header(), payload).ConfigureAwait(false);

        var held = await HoldAsync(grant, publicKey, ProviderKeyId).ConfigureAwait(false);

        Assert.AreEqual(IdJagGrantRefusal.IssuerNotExpected, held.Refusal);
        Assert.AreEqual("https://other-idp.example.com", held.Facts.Issuer);
    }


    /// <summary>A grant whose <c>kid</c> names no key the provider publishes is refused.</summary>
    [TestMethod]
    public async Task AGrantWhoseKeyIsNotPublishedIsRefused()
    {
        var keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;
        var grant = await SignAsync(privateKey, Header(), Payload()).ConfigureAwait(false);

        var held = await HoldAsync(grant, publicKey, "another-key").ConfigureAwait(false);

        Assert.AreEqual(IdJagGrantRefusal.KeyUnresolved, held.Refusal);
    }


    /// <summary>A grant signed under another key than the one the provider publishes under its <c>kid</c> is refused.</summary>
    [TestMethod]
    public async Task AGrantSignedUnderAnotherKeyIsRefused()
    {
        var keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;
        var other = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var otherPublic = other.PublicKey;
        using var otherPrivate = other.PrivateKey;
        var grant = await SignAsync(otherPrivate, Header(), Payload()).ConfigureAwait(false);

        var held = await HoldAsync(grant, publicKey, ProviderKeyId).ConfigureAwait(false);

        Assert.AreEqual(IdJagGrantRefusal.SignatureUnverified, held.Refusal);
    }


    /// <summary>A grant for another audience is refused by the library's claim rule, named.</summary>
    [TestMethod]
    public async Task AGrantForAnotherAudienceIsRefusedByTheClaimRule()
    {
        var keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;
        var payload = Payload();
        payload[WellKnownJwtClaimNames.Aud] = "https://another-resource-as.example.com";
        var grant = await SignAsync(privateKey, Header(), payload).ConfigureAwait(false);

        var held = await HoldAsync(grant, publicKey, ProviderKeyId).ConfigureAwait(false);

        Assert.AreEqual(IdJagGrantRefusal.ClaimsRefused, held.Refusal);
        Assert.AreEqual(IdJagValidationFailureReason.AudienceMismatch, held.ClaimsFailure);
    }


    /// <summary>A grant for another client than the one the client presents is refused by the library's claim rule.</summary>
    [TestMethod]
    public async Task AGrantForAnotherClientIsRefusedByTheClaimRule()
    {
        var keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;
        var payload = Payload();
        payload[WellKnownJwtClaimNames.ClientId] = "https://another-client.example.com";
        var grant = await SignAsync(privateKey, Header(), payload).ConfigureAwait(false);

        var held = await HoldAsync(grant, publicKey, ProviderKeyId).ConfigureAwait(false);

        Assert.AreEqual(IdJagGrantRefusal.ClaimsRefused, held.Refusal);
        Assert.AreEqual(IdJagValidationFailureReason.ClientMismatch, held.ClaimsFailure);
    }


    /// <summary>A grant naming another resource than the one asked for is refused.</summary>
    [TestMethod]
    public async Task AGrantForAnotherResourceIsRefused()
    {
        var keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;
        var payload = Payload();
        payload[OAuthRequestParameterNames.Resource] = "https://another-mcp.example.com/mcp";
        var grant = await SignAsync(privateKey, Header(), payload).ConfigureAwait(false);

        var held = await HoldAsync(grant, publicKey, ProviderKeyId).ConfigureAwait(false);

        Assert.AreEqual(IdJagGrantRefusal.ResourceNotAsked, held.Refusal);
    }


    /// <summary>A text that is no compact JWS is refused as malformed, carrying no identifier.</summary>
    [TestMethod]
    public async Task ATextThatIsNoCompactJwsIsRefusedAsMalformed()
    {
        var keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;

        var held = await HoldAsync("not-a-jws", publicKey, ProviderKeyId).ConfigureAwait(false);

        Assert.AreEqual(IdJagGrantRefusal.Malformed, held.Refusal);
        Assert.IsNull(held.Facts.Issuer);
    }


    /// <summary>Holds a grant under a resolver answering the provider's key for one <c>kid</c> under ES256 alone.</summary>
    /// <param name="grant">The grant.</param>
    /// <param name="publicKey">The provider's key.</param>
    /// <param name="publishedKeyId">The <c>kid</c> the provider publishes the key under.</param>
    /// <returns>What the holding found.</returns>
    private ValueTask<IdJagGrantHoldingResult> HoldAsync(string grant, PublicKeyMemory publicKey, string publishedKeyId) =>
        IdJagGrantHolding.HoldAsync(
            grant,
            Expectations,
            (keyId, algorithm, cancellationToken) => ValueTask.FromResult(
                string.Equals(keyId, publishedKeyId, StringComparison.Ordinal) && WellKnownJwaValues.IsEs256(algorithm)
                    ? CopyOf(publicKey)
                    : null),
            TestSetup.Base64UrlDecoder,
            JwtPartJson.Default,
            BaseMemoryPool.Shared,
            TimeProvider,
            TimeSpan.FromSeconds(60),
            TestContext.CancellationToken);


    /// <summary>The header of a grant the provider mints: ES256, its key's <c>kid</c>, <c>typ</c> <c>oauth-id-jag+jwt</c>.</summary>
    /// <returns>The header.</returns>
    private static Dictionary<string, object> Header() => new()
    {
        [WellKnownJoseHeaderNames.Alg] = WellKnownJwaValues.Es256,
        [WellKnownJoseHeaderNames.Typ] = WellKnownMediaTypes.Jwt.OauthIdJagJwt,
        [WellKnownJwkMemberNames.Kid] = ProviderKeyId
    };


    /// <summary>The claims of a grant every check holds, at the clock's instant.</summary>
    /// <returns>The claims.</returns>
    private Dictionary<string, object> Payload()
    {
        var now = TimeProvider.GetUtcNow().ToUnixTimeSeconds();

        return new Dictionary<string, object>
        {
            [WellKnownJwtClaimNames.Iss] = ProviderIssuer,
            [WellKnownJwtClaimNames.Sub] = "person-1",
            [WellKnownJwtClaimNames.Aud] = ResourceServer,
            [WellKnownJwtClaimNames.ClientId] = PresentedClientId,
            [WellKnownJwtClaimNames.Jti] = "grant-jti-1",
            [OAuthRequestParameterNames.Resource] = AskedResource,
            [WellKnownJwtClaimNames.Iat] = now,
            [WellKnownJwtClaimNames.Exp] = now + 300
        };
    }


    /// <summary>Signs a grant under ES256 and serializes it compact.</summary>
    /// <param name="privateKey">The signing key.</param>
    /// <param name="header">The header.</param>
    /// <param name="payload">The claims.</param>
    /// <returns>The compact grant.</returns>
    private async Task<string> SignAsync(PrivateKeyMemory privateKey, Dictionary<string, object> header, Dictionary<string, object> payload)
    {
        using var message = await Jws.SignAsync(
            header,
            payload,
            JwtWireFixtures.EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(message, TestSetup.Base64UrlEncoder);
    }


    /// <summary>A copy of a public key, which the holding owns and releases.</summary>
    /// <param name="publicKey">The key.</param>
    /// <returns>The copy.</returns>
    internal static PublicKeyMemory CopyOf(PublicKeyMemory publicKey)
    {
        var octets = publicKey.AsReadOnlySpan();
        var owner = BaseMemoryPool.Shared.Rent(octets.Length);
        octets.CopyTo(owner.Memory.Span);

        return new PublicKeyMemory(owner, publicKey.Tag);
    }
}
