using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
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
/// End-to-end + specification-conformance tests for the OpenID Federation 1.0
/// §8.1 <c>federation_fetch_endpoint</c> exposed by
/// <see cref="FederationEndpoints"/>: a positive case (serve + validate a
/// signed Subordinate Statement) and the two §8.1 / §3 negatives — an unknown
/// subordinate, and a <c>sub</c> equal to the issuing entity (a Subordinate
/// Statement is never self-issued).
/// </summary>
[TestClass]
internal sealed class FederationFetchEndpointTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string AnchorEntityId = "https://anchor.example.com";
    private const string SubordinateEntityId = "https://subordinate.example.com";


    [TestMethod]
    public async Task FetchEndpointServesSignedSubordinateStatement()
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial anchor = RegisterAnchor(app, anchorKeys);

        app.Server.OAuth().ResolveSubordinateStatementAsync = (subject, _, _, _) =>
        {
            if(!string.Equals(subject.Value, SubordinateEntityId, StringComparison.Ordinal))
            {
                return ValueTask.FromResult<SubordinateStatementContribution?>(null);
            }

            return ValueTask.FromResult<SubordinateStatementContribution?>(
                new SubordinateStatementContribution
                {
                    Jwks = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["keys"] = new List<object>(),
                    },
                });
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = anchor.Registration.TenantId.Value;

        string compact = await GetAsync(
            host,
            $"/connect/{segment}/federation_fetch?sub={Uri.EscapeDataString(SubordinateEntityId)}",
            expectedStatus: 200,
            expectedContentType: WellKnownMediaTypes.Application.EntityStatementJwt).ConfigureAwait(false);

        //A Subordinate Statement is iss != sub, carries the subject's jwks, and
        //is signed by the issuing anchor's federation key.
        Dictionary<string, object> header = DecodeSegment(compact, 0);
        Assert.AreEqual(
            WellKnownFederationMediaTypes.EntityStatementJwt,
            (string)header[WellKnownJoseHeaderNames.Typ]);

        Dictionary<string, object> payload = DecodeSegment(compact, 1);
        Assert.AreEqual(new Uri(AnchorEntityId).ToString(), (string)payload["iss"],
            "iss must be the issuing anchor.");
        Assert.AreEqual(new Uri(SubordinateEntityId).ToString(), (string)payload["sub"],
            "sub must be the queried subordinate.");
        Assert.AreNotEqual((string)payload["iss"], (string)payload["sub"],
            "A Subordinate Statement is never self-issued (iss != sub).");
        Assert.IsTrue(payload.ContainsKey("jwks"),
            "A Subordinate Statement carries the subject's jwks per §3.1.");

        bool verified = await Jws.VerifyAsync(
            compact,
            TestSetup.Base64UrlDecoder,
            Pool,
            anchorKeys.PublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verified, "The Subordinate Statement must verify under the anchor's federation key.");
    }


    [TestMethod]
    public async Task FetchEndpointReturns404ForUnknownSubordinate()
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial anchor = RegisterAnchor(app, anchorKeys);

        //The anchor knows no subordinates → every sub resolves to null.
        app.Server.OAuth().ResolveSubordinateStatementAsync =
            (_, _, _, _) => ValueTask.FromResult<SubordinateStatementContribution?>(null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = anchor.Registration.TenantId.Value;

        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_fetch?sub={Uri.EscapeDataString("https://unknown.example.com")}");
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, (int)response.StatusCode,
            "Federation §8.1: a fetch for a subject the entity does not vouch for yields HTTP 404.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.Content.Headers.ContentType?.MediaType,
            "Federation §8.9: the error response must be an application/json object.");
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.Contains($"\"error\":\"{OAuthErrors.NotFound}\"", body, StringComparison.Ordinal,
            $"Federation §8.9: an unknown subject must carry the not_found error code. Got: {body}");
    }


    [TestMethod]
    public async Task FetchEndpointRejectsSubEqualToIssuer()
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial anchor = RegisterAnchor(app, anchorKeys);

        bool delegateInvoked = false;
        app.Server.OAuth().ResolveSubordinateStatementAsync = (_, _, _, _) =>
        {
            delegateInvoked = true;
            return ValueTask.FromResult<SubordinateStatementContribution?>(null);
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = anchor.Registration.TenantId.Value;

        //Query the anchor about ITSELF — a Subordinate Statement cannot be
        //self-issued (Federation §3).
        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_fetch?sub={Uri.EscapeDataString(AnchorEntityId)}");
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "Federation §3: sub == the issuing entity is a malformed request (a Subordinate Statement is never self-issued) — 400.");
        Assert.IsFalse(delegateInvoked,
            "The self-issued guard must reject before consulting the application resolver.");
    }


    [TestMethod]
    public async Task FetchEndpointRejectsWhenClientAuthenticationFails()
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial anchor = RegisterAnchor(app, anchorKeys);

        //§8.8: the deployment requires client authentication at this endpoint and
        //the requester fails it. The gate must reject with 401 invalid_client
        //before the subordinate-statement resolver is consulted.
        bool resolverInvoked = false;
        app.Server.OAuth().ResolveSubordinateStatementAsync = (_, _, _, _) =>
        {
            resolverInvoked = true;
            return ValueTask.FromResult<SubordinateStatementContribution?>(null);
        };
        app.Server.OAuth().AuthenticateFederationClientAsync = (_, _, _, _, _) =>
            ValueTask.FromResult<FederationClientAuthenticationResult?>(
                FederationClientAuthenticationResult.Rejected("No client authentication was presented."));

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = anchor.Registration.TenantId.Value;

        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_fetch?sub={Uri.EscapeDataString(SubordinateEntityId)}");
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, (int)response.StatusCode,
            "§8.8: a failed client authentication must yield HTTP 401 invalid_client.");
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidClient}\"", body, StringComparison.Ordinal,
            $"The 401 must carry the invalid_client error code. Got: {body}");
        Assert.IsFalse(resolverInvoked,
            "The client-authentication gate must run before the endpoint's own resolver.");
    }


    [TestMethod]
    public async Task FetchEndpointProceedsWhenClientAuthenticationIsNotRequired()
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial anchor = RegisterAnchor(app, anchorKeys);

        app.Server.OAuth().ResolveSubordinateStatementAsync = (subject, _, _, _) =>
            string.Equals(subject.Value, SubordinateEntityId, StringComparison.Ordinal)
                ? ValueTask.FromResult<SubordinateStatementContribution?>(
                    new SubordinateStatementContribution
                    {
                        Jwks = new Dictionary<string, object>(StringComparer.Ordinal) { ["keys"] = new List<object>() },
                    })
                : ValueTask.FromResult<SubordinateStatementContribution?>(null);

        //A null result means client authentication is not required at this
        //endpoint — the request proceeds and is served normally.
        app.Server.OAuth().AuthenticateFederationClientAsync = (_, _, _, _, _) =>
            ValueTask.FromResult<FederationClientAuthenticationResult?>(null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = anchor.Registration.TenantId.Value;

        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_fetch?sub={Uri.EscapeDataString(SubordinateEntityId)}");
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode,
            "A null client-authentication result means not required — the request proceeds.");
    }


    [TestMethod]
    public async Task FetchEndpointMissingSubReturnsJsonError()
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial anchor = RegisterAnchor(app, anchorKeys);

        bool delegateInvoked = false;
        app.Server.OAuth().ResolveSubordinateStatementAsync = (_, _, _, _) =>
        {
            delegateInvoked = true;
            return ValueTask.FromResult<SubordinateStatementContribution?>(null);
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = anchor.Registration.TenantId.Value;

        //§8.1.1: sub is REQUIRED. A blank sub is therefore malformed. §8.1.2: an error
        //response MUST be a JSON object with the content type application/json.
        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/federation_fetch?sub=");
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "A fetch request without the REQUIRED sub parameter is malformed (Federation §8.1.1).");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.Content.Headers.ContentType?.MediaType,
            "Federation §8.1.2: a federation endpoint error response must use content type application/json.");

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Dictionary<string, object> error = JsonSerializer.Deserialize<Dictionary<string, object>>(
            body, TestSetup.DefaultSerializationOptions)
            ?? throw new InvalidOperationException("Error body parsed to null.");
        Assert.IsTrue(error.ContainsKey("error"),
            "Federation §8.1.2: the error response must be a JSON object carrying an error code.");
        Assert.IsFalse(delegateInvoked,
            "A request missing sub must be rejected before consulting the application resolver.");
    }


    private static VerifierKeyMaterial RegisterAnchor(
        TestHostShell app,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorKeys)
    {
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownFederationCapabilityIdentifiers.PublishSubordinateStatement);

        return app.RegisterFederationCapableClient(
            clientId: AnchorEntityId,
            baseUri: new Uri(AnchorEntityId),
            federationEntityId: new Uri(AnchorEntityId),
            federationSigningKeyPair: anchorKeys,
            baseCapabilities: capabilities);
    }


    private async ValueTask<string> GetAsync(
        HostedAuthorizationServer host, string absolutePath, int expectedStatus, string expectedContentType)
    {
        Uri url = new(host.HttpBaseAddress!, absolutePath);
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedStatus, (int)response.StatusCode,
            $"GET {absolutePath} must return {expectedStatus}. Body: {await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false)}");
        Assert.AreEqual(expectedContentType, response.Content.Headers.ContentType?.MediaType,
            $"GET {absolutePath} must serve {expectedContentType}.");

        return await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static Dictionary<string, object> DecodeSegment(string compactJws, int index)
    {
        string[] parts = compactJws.Split('.');
        Assert.HasCount(3, parts, "A Subordinate Statement must be a 3-segment compact JWS.");

        using IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(parts[index], Pool);

        return JsonSerializer.Deserialize<Dictionary<string, object>>(
            bytes.Memory.Span, TestSetup.DefaultSerializationOptions)
            ?? throw new InvalidOperationException("JWS segment parsed to null.");
    }
}
