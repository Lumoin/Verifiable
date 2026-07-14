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
/// End-to-end tests for the OpenID Federation 1.0 §8.3
/// <c>federation_resolve_endpoint</c> exposed by <see cref="FederationEndpoints"/>.
/// The endpoint serves a signed Resolve Response JWT
/// (<c>typ = resolve-response+jwt</c>) carrying a subject's resolved
/// metadata, trust chain, and trust marks; the resolution itself comes from
/// the application's
/// <see cref="AuthorizationServerIntegration.ResolveSubjectTrustChainAsync"/>
/// delegate, while the library parses <c>sub</c> / <c>anchor</c> / <c>type</c>,
/// assembles the payload, and signs it with the resolver's federation key.
/// </summary>
[TestClass]
internal sealed class FederationResolveEndpointTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    [TestMethod]
    public async Task ResolveEndpointServesSignedResolveResponse()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = RegisterResolver(app, resolverEntityId, federationKeys);

        EntityIdentifier subject = new("https://leaf.example.com");
        EntityIdentifier anchor = new("https://anchor.example.com");

        EntityIdentifier? observedSubject = null;
        EntityIdentifier? observedAnchor = null;
        EntityTypeIdentifier? observedType = null;

        app.Server.OAuth().ResolveSubjectTrustChainAsync =
            (sub, trustAnchor, entityTypeFilter, _, _, _) =>
            {
                observedSubject = sub;
                observedAnchor = trustAnchor;
                observedType = entityTypeFilter;

                Dictionary<string, object> rpMetadata = new(StringComparer.Ordinal)
                {
                    ["client_name"] = "Leaf RP"
                };
                Dictionary<string, object> metadata = new(StringComparer.Ordinal)
                {
                    [WellKnownEntityTypeIdentifiers.OpenIdRelyingParty.Value] = rpMetadata
                };

                Dictionary<string, object> trustMark = new(StringComparer.Ordinal)
                {
                    ["trust_mark_type"] = "https://anchor.example.com/marks/onboarded",
                    ["trust_mark"] = "eyJ0rust.mark.jwt"
                };

                return ValueTask.FromResult<ResolveResponseContribution?>(
                    new ResolveResponseContribution
                    {
                        Metadata = metadata,
                        TrustChain = ["eyJleaf.statement.jws", "eyJanchor.statement.jws"],
                        TrustMarks = [trustMark]
                    });
            };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = resolverKeys.Registration.TenantId.Value;
        string query =
            $"?sub={Uri.EscapeDataString(subject.Value)}"
            + $"&anchor={Uri.EscapeDataString(anchor.Value)}"
            + "&type=openid_relying_party";

        string compactResponse = await GetResolveAsync(
            host, $"/connect/{segment}/federation_resolve{query}").ConfigureAwait(false);

        //The library parsed and threaded all three request parameters.
        Assert.IsNotNull(observedSubject);
        Assert.AreEqual(subject.Value, observedSubject.Value.Value);
        Assert.IsNotNull(observedAnchor);
        Assert.AreEqual(anchor.Value, observedAnchor.Value.Value);
        Assert.IsNotNull(observedType);
        Assert.AreEqual(
            WellKnownEntityTypeIdentifiers.OpenIdRelyingParty.Value, observedType.Value.Value);

        //The response is a three-segment JWS with the §8.3 explicit type.
        Dictionary<string, object> header = DecodeSegment(compactResponse, 0);
        Assert.AreEqual(
            WellKnownFederationMediaTypes.ResolveResponseJwt,
            (string)header[WellKnownJoseHeaderNames.Typ],
            "The Resolve Response must carry typ=resolve-response+jwt per §8.3.");

        Dictionary<string, object> payload = DecodeSegment(compactResponse, 1);
        Assert.AreEqual(resolverEntityId.ToString(), (string)payload["iss"],
            "iss must be the resolver's Entity Identifier.");
        Assert.AreEqual(subject.Value, (string)payload["sub"],
            "sub must be the resolved subject.");
        Assert.IsGreaterThan(
            Convert.ToInt64(payload["iat"], CultureInfo.InvariantCulture),
            Convert.ToInt64(payload["exp"], CultureInfo.InvariantCulture),
            "exp must be strictly after iat.");

        //Resolved metadata round-trips.
        IReadOnlyDictionary<string, object> metadata =
            (IReadOnlyDictionary<string, object>)payload["metadata"];
        IReadOnlyDictionary<string, object> rp =
            (IReadOnlyDictionary<string, object>)metadata[WellKnownEntityTypeIdentifiers.OpenIdRelyingParty.Value];
        Assert.AreEqual("Leaf RP", (string)rp["client_name"]);

        //trust_chain and trust_marks are present in the form the application supplied.
        IReadOnlyList<object> chain = (IReadOnlyList<object>)payload["trust_chain"];
        Assert.HasCount(2, chain, "Both chain statements must be present.");
        Assert.AreEqual("eyJleaf.statement.jws", (string)chain[0]);
        Assert.AreEqual("eyJanchor.statement.jws", (string)chain[1]);

        IReadOnlyList<object> marks = (IReadOnlyList<object>)payload["trust_marks"];
        Assert.HasCount(1, marks);
        IReadOnlyDictionary<string, object> mark0 =
            (IReadOnlyDictionary<string, object>)marks[0];
        Assert.AreEqual(
            "https://anchor.example.com/marks/onboarded",
            (string)mark0["trust_mark_type"]);

        //The response verifies under the resolver's federation public key.
        bool verified = await Jws.VerifyAsync(
            compactResponse,
            TestSetup.Base64UrlDecoder,
            Pool,
            federationKeys.PublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verified,
            "The Resolve Response must verify under the resolver's federation signing key.");
    }


    [TestMethod]
    public async Task ResolveEndpointReturns404WhenSubjectUnresolvable()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = RegisterResolver(app, resolverEntityId, federationKeys);

        app.Server.OAuth().ResolveSubjectTrustChainAsync =
            (_, _, _, _, _, _) => ValueTask.FromResult<ResolveResponseContribution?>(null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = resolverKeys.Registration.TenantId.Value;
        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_resolve?sub={Uri.EscapeDataString("https://unknown.example.com")}"
            + $"&anchor={Uri.EscapeDataString("https://anchor.example.com")}");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, (int)response.StatusCode,
            "A subject the resolver cannot resolve yields HTTP 404 per the null-contribution contract.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.Content.Headers.ContentType?.MediaType,
            "Federation §8.9: the error response must be an application/json object.");
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidSubject}\"", body, StringComparison.Ordinal,
            $"Federation §8.9: an unresolvable subject must carry the invalid_subject error code. Got: {body}");
    }


    [TestMethod]
    public async Task ResolveEndpointRejectsMissingSub()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = RegisterResolver(app, resolverEntityId, federationKeys);

        bool delegateInvoked = false;
        app.Server.OAuth().ResolveSubjectTrustChainAsync =
            (_, _, _, _, _, _) =>
            {
                delegateInvoked = true;
                return ValueTask.FromResult<ResolveResponseContribution?>(null);
            };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = resolverKeys.Registration.TenantId.Value;
        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/federation_resolve");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "A resolve request with no sub is malformed (400), not a 404.");
        Assert.IsFalse(delegateInvoked,
            "The application delegate must not run for a request rejected at parameter validation.");
    }


    [TestMethod]
    public async Task ResolveEndpointRejectsMissingAnchor()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = RegisterResolver(app, resolverEntityId, federationKeys);

        bool delegateInvoked = false;
        app.Server.OAuth().ResolveSubjectTrustChainAsync =
            (_, _, _, _, _, _) =>
            {
                delegateInvoked = true;
                return ValueTask.FromResult<ResolveResponseContribution?>(null);
            };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = resolverKeys.Registration.TenantId.Value;

        //§8.3.1: anchor is REQUIRED. A resolve request that names a subject but no Trust
        //Anchor is malformed (400), and the resolution delegate must not run.
        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_resolve?sub={Uri.EscapeDataString("https://leaf.example.com")}");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "A resolve request without the REQUIRED anchor parameter is malformed (Federation §8.3.1).");
        Assert.IsFalse(delegateInvoked,
            "The resolution delegate must not run for a request rejected at parameter validation.");
    }


    private static VerifierKeyMaterial RegisterResolver(
        TestHostShell app,
        Uri resolverEntityId,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys)
    {
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownFederationCapabilityIdentifiers.ResolveTrustChain);

        return app.RegisterFederationCapableClient(
            clientId: resolverEntityId.ToString(),
            baseUri: resolverEntityId,
            federationEntityId: resolverEntityId,
            federationSigningKeyPair: federationKeys,
            baseCapabilities: capabilities);
    }


    private async ValueTask<string> GetResolveAsync(HostedAuthorizationServer host, string absolutePath)
    {
        Uri url = new(host.HttpBaseAddress!, absolutePath);
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode,
            $"GET {absolutePath} must return 200. Body: {await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false)}");

        string? actualContentType = response.Content.Headers.ContentType?.MediaType;
        Assert.AreEqual(WellKnownMediaTypes.Application.ResolveResponseJwt, actualContentType,
            $"GET {absolutePath} must serve {WellKnownMediaTypes.Application.ResolveResponseJwt}.");

        return await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static Dictionary<string, object> DecodeSegment(string compactJws, int index)
    {
        string[] parts = compactJws.Split('.');
        Assert.HasCount(3, parts,
            "A Resolve Response must be a JWS compact serialization with three segments.");

        using IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(parts[index], Pool);

        //The test serialization options project JSON onto native CLR types —
        //strings, Int64, nested Dictionary<string, object>, List<object> —
        //so the claims read back in the shape the application supplied.
        return JsonSerializer.Deserialize<Dictionary<string, object>>(
            bytes.Memory.Span, TestSetup.DefaultSerializationOptions)
            ?? throw new InvalidOperationException("JWS segment parsed to null.");
    }
}
