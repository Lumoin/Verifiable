using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Globalization;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Federation;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// End-to-end tests for the OpenID Federation 1.0 §8.7
/// <c>federation_historical_keys_endpoint</c> exposed by
/// <see cref="FederationEndpoints"/>. The endpoint serves a signed JWK Set JWT
/// (<c>typ = jwk-set+jwt</c>) carrying the entity's historical (rotated and
/// revoked) Federation Entity Keys; the keys themselves come from the
/// application's
/// <see cref="AuthorizationServerIntegration.ResolveHistoricalKeysAsync"/>
/// delegate, while the library assembles the <c>{ iss, iat, keys }</c>
/// envelope and signs it with the entity's federation key.
/// </summary>
[TestClass]
internal sealed class FederationHistoricalKeysEndpointTests
{
    /// <summary>
    /// The per-test context, injected by the test framework.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Deterministic clock the host and the §8.7 <c>iat</c> claim read from.
    /// </summary>
    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    /// <summary>
    /// The memory pool the JWS decode and verify helpers rent from.
    /// </summary>
    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// Drives a GET against the historical keys endpoint and asserts the
    /// §8.7.2 content type and <c>typ</c>, the §8.7.3 <c>iss</c> / <c>iat</c> /
    /// <c>keys</c> claims (including the per-key <c>kid</c> / <c>exp</c> and a
    /// <c>revoked</c> block), and that the JWS verifies under the entity's
    /// federation public key.
    /// </summary>
    [TestMethod]
    public async Task HistoricalKeysEndpointServesSignedJwkSet()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri entityId = new("https://entity.example.com");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial entityKeys = RegisterEntity(app, entityId, federationKeys);

        bool delegateInvoked = false;
        app.Server.OAuth().ResolveHistoricalKeysAsync =
            (_, _, _) =>
            {
                delegateInvoked = true;

                Dictionary<string, object> revokedBlock = new(StringComparer.Ordinal)
                {
                    ["revoked_at"] = 1700000000L,
                    ["reason"] = "key_compromise"
                };

                Dictionary<string, object> revokedKey = new(StringComparer.Ordinal)
                {
                    ["kid"] = "rotated-key-1",
                    ["kty"] = "EC",
                    ["crv"] = "P-256",
                    ["iat"] = 1690000000L,
                    ["exp"] = 1699999999L,
                    ["revoked"] = revokedBlock
                };

                Dictionary<string, object> expiredKey = new(StringComparer.Ordinal)
                {
                    ["kid"] = "rotated-key-2",
                    ["kty"] = "EC",
                    ["crv"] = "P-256",
                    ["exp"] = 1709999999L
                };

                return ValueTask.FromResult<HistoricalKeysContribution?>(
                    new HistoricalKeysContribution
                    {
                        Keys = [revokedKey, expiredKey]
                    });
            };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = entityKeys.Registration.TenantId.Value;
        string compactResponse = await GetHistoricalKeysAsync(
            host, $"/connect/{segment}/federation_historical_keys").ConfigureAwait(false);

        Assert.IsTrue(delegateInvoked,
            "The application delegate must run for a well-formed historical keys request.");

        //The response is a three-segment JWS with the §8.7.2 explicit type.
        Dictionary<string, object> header = DecodeSegment(compactResponse, 0);
        Assert.AreEqual(
            WellKnownFederationMediaTypes.HistoricalKeysJwt,
            (string)header[WellKnownJoseHeaderNames.Typ],
            "The Historical Keys JWT must carry typ=jwk-set+jwt per §8.7.2.");

        Dictionary<string, object> payload = DecodeSegment(compactResponse, 1);
        Assert.AreEqual(entityId.ToString(), (string)payload["iss"],
            "iss must be the entity's Entity Identifier.");
        Assert.IsTrue(payload.ContainsKey("iat"),
            "iat is REQUIRED per §8.7.3.");
        Assert.AreEqual(
            TimeProvider.GetUtcNow().ToUnixTimeSeconds(),
            Convert.ToInt64(payload["iat"], CultureInfo.InvariantCulture),
            "iat must be the host clock's issuance time in seconds since epoch.");

        //The keys array round-trips in the form the application supplied.
        IReadOnlyList<object> keys = (IReadOnlyList<object>)payload["keys"];
        Assert.HasCount(2, keys, "Both historical keys must be present.");

        IReadOnlyDictionary<string, object> key0 =
            (IReadOnlyDictionary<string, object>)keys[0];
        Assert.AreEqual("rotated-key-1", (string)key0["kid"],
            "kid is REQUIRED per §8.7.3.");
        Assert.AreEqual(
            1699999999L,
            Convert.ToInt64(key0["exp"], CultureInfo.InvariantCulture),
            "exp is REQUIRED per §8.7.3.");

        //The revoked block carries its REQUIRED revoked_at and OPTIONAL reason.
        IReadOnlyDictionary<string, object> revoked =
            (IReadOnlyDictionary<string, object>)key0["revoked"];
        Assert.AreEqual(
            1700000000L,
            Convert.ToInt64(revoked["revoked_at"], CultureInfo.InvariantCulture),
            "revoked.revoked_at is REQUIRED when a key is revoked per §8.7.3.");
        Assert.AreEqual("key_compromise", (string)revoked["reason"]);

        IReadOnlyDictionary<string, object> key1 =
            (IReadOnlyDictionary<string, object>)keys[1];
        Assert.AreEqual("rotated-key-2", (string)key1["kid"]);
        Assert.IsFalse(key1.ContainsKey("revoked"),
            "A non-revoked historical key carries no revoked block.");

        //The response verifies under the entity's federation public key.
        bool verified = await Jws.VerifyAsync(
            compactResponse,
            TestSetup.Base64UrlDecoder,
            Pool,
            federationKeys.PublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verified,
            "The Historical Keys JWT must verify under the entity's federation signing key.");
    }


    /// <summary>
    /// Asserts a null contribution yields HTTP 404, mirroring the resolve
    /// endpoint's null-contribution contract.
    /// </summary>
    [TestMethod]
    public async Task HistoricalKeysEndpointReturns404WhenNoHistoricalKeys()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri entityId = new("https://entity.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial entityKeys = RegisterEntity(app, entityId, federationKeys);

        app.Server.OAuth().ResolveHistoricalKeysAsync =
            (_, _, _) => ValueTask.FromResult<HistoricalKeysContribution?>(null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = entityKeys.Registration.TenantId.Value;
        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/federation_historical_keys");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, (int)response.StatusCode,
            "An entity with no historical keys yields HTTP 404 per the null-contribution contract.");
    }


    /// <summary>
    /// Registers a federation-capable entity carrying the
    /// <see cref="WellKnownFederationCapabilityIdentifiers.PublishHistoricalKeys"/>
    /// capability and a federation signing key.
    /// </summary>
    private static VerifierKeyMaterial RegisterEntity(
        TestHostShell app,
        Uri entityId,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys)
    {
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownFederationCapabilityIdentifiers.PublishHistoricalKeys);

        return app.RegisterFederationCapableClient(
            clientId: entityId.ToString(),
            baseUri: entityId,
            federationEntityId: entityId,
            federationSigningKeyPair: federationKeys,
            baseCapabilities: capabilities);
    }


    /// <summary>
    /// Issues the GET, asserts HTTP 200 and the §8.7.2 content type, and
    /// returns the compact JWS body.
    /// </summary>
    private async ValueTask<string> GetHistoricalKeysAsync(HostedAuthorizationServer host, string absolutePath)
    {
        Uri url = new(host.HttpBaseAddress!, absolutePath);
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode,
            $"GET {absolutePath} must return 200. Body: {await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false)}");

        string? actualContentType = response.Content.Headers.ContentType?.MediaType;
        Assert.AreEqual(WellKnownMediaTypes.Application.HistoricalKeysJwt, actualContentType,
            $"GET {absolutePath} must serve {WellKnownMediaTypes.Application.HistoricalKeysJwt}.");

        return await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Decodes one base64url JWS segment into the native CLR claim shape the
    /// test serialization options project.
    /// </summary>
    private static Dictionary<string, object> DecodeSegment(string compactJws, int index)
    {
        string[] parts = compactJws.Split('.');
        Assert.HasCount(3, parts,
            "A Historical Keys JWT must be a JWS compact serialization with three segments.");

        using IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(parts[index], Pool);

        //The test serialization options project JSON onto native CLR types —
        //strings, Int64, nested Dictionary<string, object>, List<object> —
        //so the claims read back in the shape the application supplied.
        return JsonSerializer.Deserialize<Dictionary<string, object>>(
            bytes.Memory.Span, TestSetup.DefaultSerializationOptions)
            ?? throw new InvalidOperationException("JWS segment parsed to null.");
    }
}
