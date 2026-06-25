using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Globalization;
using System.Net.Http;
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
/// End-to-end tests for the OpenID Federation 1.0 §8.4
/// <c>federation_trust_mark_status_endpoint</c> exposed by
/// <see cref="FederationEndpoints"/>. The endpoint serves a signed status JWT
/// (<c>typ = trust-mark-status-response+jwt</c>) carrying the queried
/// <c>trust_mark</c> and its <c>status</c>; the status comes from the
/// application's
/// <see cref="AuthorizationServerIntegration.ResolveTrustMarkStatusAsync"/>
/// delegate, while the library reads the POSTed <c>trust_mark</c> form parameter,
/// assembles the <c>{ iss, iat, trust_mark, status }</c> payload, and signs it
/// with the entity's federation key.
/// </summary>
[TestClass]
internal sealed class FederationTrustMarkStatusEndpointTests
{
    /// <summary>
    /// The per-test context, injected by the test framework.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Deterministic clock the host and the §8.4 <c>iat</c> claim read from.
    /// </summary>
    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    /// <summary>
    /// The memory pool the JWS decode and verify helpers rent from.
    /// </summary>
    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// Drives a form POST against the status endpoint and asserts the §8.4
    /// content type and <c>typ</c>, the <c>iss</c> / <c>iat</c> / <c>trust_mark</c> /
    /// <c>status</c> claims, and that the JWS verifies under the entity's
    /// federation public key.
    /// </summary>
    [TestMethod]
    public async Task TrustMarkStatusEndpointServesSignedStatusResponse()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri issuerEntityId = new("https://issuer.example.com");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial issuerKeys = RegisterIssuer(app, issuerEntityId, federationKeys);

        const string TrustMarkJws = "eyJ0rust.mark.jwt";
        const string Status = "active";

        string? observedTrustMark = null;
        app.Server.OAuth().ResolveTrustMarkStatusAsync = (trustMark, _, _, _) =>
        {
            observedTrustMark = trustMark;
            return ValueTask.FromResult<string?>(Status);
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = issuerKeys.Registration.TenantId.Value;
        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/federation_trust_mark_status");

        Dictionary<string, string> form = new(StringComparer.Ordinal)
        {
            ["trust_mark"] = TrustMarkJws
        };
        using FormUrlEncodedContent content = new(form);
        using HttpResponseMessage response = await host.SharedHttpClient!
            .PostAsync(url, content, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode,
            $"POST federation_trust_mark_status must return 200. Body: {await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false)}");
        Assert.AreEqual(WellKnownMediaTypes.Application.TrustMarkStatusResponseJwt, response.Content.Headers.ContentType?.MediaType,
            "The status response must be served as application/trust-mark-status-response+jwt per §8.4.");

        Assert.AreEqual(TrustMarkJws, observedTrustMark,
            "The delegate must receive the exact posted trust_mark value.");

        string compactResponse = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //The response is a three-segment JWS with the §8.4 explicit type.
        Dictionary<string, object> header = DecodeSegment(compactResponse, 0);
        Assert.AreEqual(
            WellKnownFederationMediaTypes.TrustMarkStatusResponseJwt,
            (string)header[WellKnownJoseHeaderNames.Typ],
            "The status response must carry typ=trust-mark-status-response+jwt per §8.4.");

        Dictionary<string, object> payload = DecodeSegment(compactResponse, 1);
        Assert.AreEqual(issuerEntityId.ToString(), (string)payload["iss"],
            "iss must be the issuing entity's Entity Identifier.");
        Assert.AreEqual(
            TimeProvider.GetUtcNow().ToUnixTimeSeconds(),
            Convert.ToInt64(payload["iat"], CultureInfo.InvariantCulture),
            "iat must be the host clock's issuance time in seconds since epoch.");
        Assert.AreEqual(TrustMarkJws, (string)payload["trust_mark"],
            "trust_mark must echo the queried Trust Mark JWT.");
        Assert.AreEqual(Status, (string)payload["status"],
            "status must be the app-returned status string.");

        //The response verifies under the entity's federation public key.
        bool verified = await Jws.VerifyAsync(
            compactResponse,
            TestSetup.Base64UrlDecoder,
            Pool,
            federationKeys.PublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verified,
            "The status response must verify under the entity's federation signing key.");
    }


    /// <summary>
    /// Asserts a null contribution (unknown Trust Mark) yields HTTP 404 with the
    /// §8.9 not_found body.
    /// </summary>
    [TestMethod]
    public async Task TrustMarkStatusEndpointReturns404WhenTrustMarkUnknown()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri issuerEntityId = new("https://issuer.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial issuerKeys = RegisterIssuer(app, issuerEntityId, federationKeys);

        app.Server.OAuth().ResolveTrustMarkStatusAsync =
            (_, _, _, _) => ValueTask.FromResult<string?>(null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = issuerKeys.Registration.TenantId.Value;
        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/federation_trust_mark_status");

        Dictionary<string, string> form = new(StringComparer.Ordinal)
        {
            ["trust_mark"] = "eyJunknown.mark.jwt"
        };
        using FormUrlEncodedContent content = new(form);
        using HttpResponseMessage response = await host.SharedHttpClient!
            .PostAsync(url, content, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, (int)response.StatusCode,
            "An unknown Trust Mark yields HTTP 404 per the null-contribution contract.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.Content.Headers.ContentType?.MediaType,
            "Federation §8.9: the error response must be an application/json object.");
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.Contains($"\"error\":\"{OAuthErrors.NotFound}\"", body, StringComparison.Ordinal,
            $"Federation §8.9: an unknown trust mark must carry the not_found error code. Got: {body}");
    }


    /// <summary>
    /// Asserts a POST missing the REQUIRED <c>trust_mark</c> form parameter is
    /// rejected with HTTP 400 before the delegate runs.
    /// </summary>
    [TestMethod]
    public async Task TrustMarkStatusEndpointRejectsMissingTrustMark()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri issuerEntityId = new("https://issuer.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial issuerKeys = RegisterIssuer(app, issuerEntityId, federationKeys);

        bool delegateInvoked = false;
        app.Server.OAuth().ResolveTrustMarkStatusAsync = (_, _, _, _) =>
        {
            delegateInvoked = true;
            return ValueTask.FromResult<string?>("active");
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = issuerKeys.Registration.TenantId.Value;
        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/federation_trust_mark_status");

        //§8.4: trust_mark is REQUIRED. A POST with no trust_mark is malformed
        //(400), and the status delegate must not run.
        Dictionary<string, string> form = new(StringComparer.Ordinal);
        using FormUrlEncodedContent content = new(form);
        using HttpResponseMessage response = await host.SharedHttpClient!
            .PostAsync(url, content, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "A status request without the REQUIRED trust_mark parameter is malformed (Federation §8.4).");
        Assert.IsFalse(delegateInvoked,
            "The status delegate must not run for a request rejected at parameter validation.");
    }


    /// <summary>
    /// Registers a federation-capable issuer carrying the
    /// <see cref="WellKnownFederationCapabilityIdentifiers.PublishTrustMarkStatus"/>
    /// capability and a federation signing key.
    /// </summary>
    private static VerifierKeyMaterial RegisterIssuer(
        TestHostShell app,
        Uri issuerEntityId,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys)
    {
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownFederationCapabilityIdentifiers.PublishTrustMarkStatus);

        return app.RegisterFederationCapableClient(
            clientId: issuerEntityId.ToString(),
            baseUri: issuerEntityId,
            federationEntityId: issuerEntityId,
            federationSigningKeyPair: federationKeys,
            baseCapabilities: capabilities);
    }


    /// <summary>
    /// Decodes one base64url JWS segment into the native CLR claim shape the test
    /// serialization options project.
    /// </summary>
    private static Dictionary<string, object> DecodeSegment(string compactJws, int index)
    {
        string[] parts = compactJws.Split('.');
        Assert.HasCount(3, parts,
            "A status response must be a JWS compact serialization with three segments.");

        using IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(parts[index], Pool);

        //The test serialization options project JSON onto native CLR types —
        //strings, Int64, nested Dictionary<string, object>, List<object> —
        //so the claims read back in the shape the application supplied.
        return JsonSerializer.Deserialize<Dictionary<string, object>>(
            bytes.Memory.Span, TestSetup.DefaultSerializationOptions)
            ?? throw new InvalidOperationException("JWS segment parsed to null.");
    }
}
