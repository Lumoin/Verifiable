using Microsoft.Extensions.Time.Testing;
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
/// End-to-end tests for the OpenID Federation 1.0 §8.2
/// <c>federation_list_endpoint</c> exposed by <see cref="FederationEndpoints"/>.
/// The endpoint serves an unsigned JSON array of the issuing entity's
/// immediate subordinate Entity Identifiers; the membership itself comes
/// from the application's
/// <see cref="AuthorizationServerIntegration.ResolveSubordinateListAsync"/>
/// delegate, while the library matches the request, parses the optional
/// <c>entity_type</c> filter, and serialises the array.
/// </summary>
[TestClass]
internal sealed class FederationListEndpointTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);


    [TestMethod]
    public async Task ListEndpointServesUnsignedJsonArrayOfSubordinates()
    {
        await using TestHostShell app = new(TimeProvider);

        //The anchor lists subordinates, so it carries ListSubordinates on
        //top of the federation baseline. PublishEntityConfiguration is added
        //by RegisterFederationCapableClient; ListSubordinates rides in via
        //baseCapabilities.
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownFederationCapabilityIdentifiers.ListSubordinates);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        Uri anchorEntityId = new("https://anchor.example.com");

        using VerifierKeyMaterial anchorKeys = app.RegisterFederationCapableClient(
            clientId: "https://anchor.example.com",
            baseUri: anchorEntityId,
            federationEntityId: anchorEntityId,
            federationSigningKeyPair: federationKeys,
            baseCapabilities: capabilities);

        EntityIdentifier alice = new("https://alice.example.com");
        EntityIdentifier bob = new("https://bob.example.com");
        EntityIdentifier carol = new("https://carol.example.com");

        IReadOnlyList<EntityTypeIdentifier>? observedFilters = null;
        bool filterObserved = false;

        app.Server.OAuth().ResolveSubordinateListAsync = (entityTypeFilters, _, _, _) =>
        {
            observedFilters = entityTypeFilters;
            filterObserved = true;

            return ValueTask.FromResult<IReadOnlyList<EntityIdentifier>>(
                new[] { alice, bob, carol });
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = anchorKeys.Registration.TenantId.Value;

        string body = await GetListAsync(host, $"/connect/{segment}/federation_list").ConfigureAwait(false);

        //An unfiltered list request carries no entity_type, so the delegate
        //sees an empty filter list.
        Assert.IsTrue(filterObserved, "The list delegate must be invoked.");
        Assert.IsNotNull(observedFilters);
        Assert.IsEmpty(observedFilters!,
            "An unfiltered request must pass an empty entity_type filter list to the delegate.");

        List<string> ids = ParseStringArray(body);
        Assert.HasCount(3, ids, "All three subordinates must be listed.");
        Assert.AreSequenceEqual(
            new[] { alice.Value, bob.Value, carol.Value },
            ids.ToArray(),
            "The §8.2 array must preserve the membership order the delegate returned.");
    }


    [TestMethod]
    public async Task ListEndpointPassesEntityTypeFilterToDelegate()
    {
        await using TestHostShell app = new(TimeProvider);

        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownFederationCapabilityIdentifiers.ListSubordinates);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        Uri anchorEntityId = new("https://anchor.example.com");

        using VerifierKeyMaterial anchorKeys = app.RegisterFederationCapableClient(
            clientId: "https://anchor.example.com",
            baseUri: anchorEntityId,
            federationEntityId: anchorEntityId,
            federationSigningKeyPair: federationKeys,
            baseCapabilities: capabilities);

        EntityIdentifier relyingParty = new("https://rp.example.com");
        EntityIdentifier provider = new("https://op.example.com");

        IReadOnlyList<EntityTypeIdentifier>? observedFilters = null;

        //The application filters its membership by the parsed entity_type:
        //only the openid_relying_party subordinate comes back.
        app.Server.OAuth().ResolveSubordinateListAsync = (entityTypeFilters, _, _, _) =>
        {
            observedFilters = entityTypeFilters;

            IReadOnlyList<EntityIdentifier> result =
                entityTypeFilters.Contains(WellKnownEntityTypeIdentifiers.OpenIdRelyingParty)
                    ? new[] { relyingParty }
                    : new[] { relyingParty, provider };

            return ValueTask.FromResult(result);
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = anchorKeys.Registration.TenantId.Value;

        string body = await GetListAsync(
            host,
            $"/connect/{segment}/federation_list?entity_type=openid_relying_party").ConfigureAwait(false);

        Assert.IsNotNull(observedFilters,
            "The entity_type query parameter must reach the delegate as a parsed filter.");
        Assert.HasCount(1, observedFilters!,
            "A single entity_type maps to a one-element filter list.");
        Assert.AreEqual(
            WellKnownEntityTypeIdentifiers.OpenIdRelyingParty.Value,
            observedFilters![0].Value,
            "The parsed filter must carry the wire entity_type value.");

        List<string> ids = ParseStringArray(body);
        Assert.HasCount(1, ids, "The filtered list must contain only the matching subordinate.");
        Assert.AreEqual(relyingParty.Value, ids[0]);
    }


    [TestMethod]
    public async Task ListEndpointServesEmptyArrayForNoSubordinates()
    {
        await using TestHostShell app = new(TimeProvider);

        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownFederationCapabilityIdentifiers.ListSubordinates);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        Uri anchorEntityId = new("https://anchor.example.com");

        using VerifierKeyMaterial anchorKeys = app.RegisterFederationCapableClient(
            clientId: "https://anchor.example.com",
            baseUri: anchorEntityId,
            federationEntityId: anchorEntityId,
            federationSigningKeyPair: federationKeys,
            baseCapabilities: capabilities);

        app.Server.OAuth().ResolveSubordinateListAsync = (_, _, _, _) =>
            ValueTask.FromResult<IReadOnlyList<EntityIdentifier>>([]);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = anchorKeys.Registration.TenantId.Value;

        string body = await GetListAsync(host, $"/connect/{segment}/federation_list").ConfigureAwait(false);

        List<string> ids = ParseStringArray(body);
        Assert.IsEmpty(ids, "An entity with no subordinates serves an empty JSON array.");
    }


    [TestMethod]
    public async Task ListEndpointPassesEveryEntityTypeOfARepeatedFilter()
    {
        await using TestHostShell app = new(TimeProvider);

        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownFederationCapabilityIdentifiers.ListSubordinates);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        Uri anchorEntityId = new("https://anchor.example.com");

        using VerifierKeyMaterial anchorKeys = app.RegisterFederationCapableClient(
            clientId: "https://anchor.example.com",
            baseUri: anchorEntityId,
            federationEntityId: anchorEntityId,
            federationSigningKeyPair: federationKeys,
            baseCapabilities: capabilities);

        EntityIdentifier relyingParty = new("https://rp.example.com");
        EntityIdentifier provider = new("https://op.example.com");

        //§8.2.1: a request with multiple entity_type parameters must filter to
        //ALL of them — the delegate sees both, and returns the union.
        IReadOnlyList<EntityTypeIdentifier>? observedFilters = null;
        app.Server.OAuth().ResolveSubordinateListAsync = (entityTypeFilters, _, _, _) =>
        {
            observedFilters = entityTypeFilters;
            return ValueTask.FromResult<IReadOnlyList<EntityIdentifier>>(new[] { relyingParty, provider });
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = anchorKeys.Registration.TenantId.Value;

        string body = await GetListAsync(
            host,
            $"/connect/{segment}/federation_list?entity_type=openid_relying_party&entity_type=openid_provider")
            .ConfigureAwait(false);

        Assert.IsNotNull(observedFilters);
        Assert.HasCount(2, observedFilters!,
            "Both repeated entity_type values must reach the delegate, not just one.");
        Assert.Contains(WellKnownEntityTypeIdentifiers.OpenIdRelyingParty, observedFilters!);
        Assert.Contains(WellKnownEntityTypeIdentifiers.OpenIdProvider, observedFilters!);

        List<string> ids = ParseStringArray(body);
        Assert.HasCount(2, ids, "The union of the requested types is returned.");
    }


    [TestMethod]
    public async Task ListEndpointIsAlsoServedOverPost()
    {
        await using TestHostShell app = new(TimeProvider);

        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownFederationCapabilityIdentifiers.ListSubordinates);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        Uri anchorEntityId = new("https://anchor.example.com");

        using VerifierKeyMaterial anchorKeys = app.RegisterFederationCapableClient(
            clientId: "https://anchor.example.com",
            baseUri: anchorEntityId,
            federationEntityId: anchorEntityId,
            federationSigningKeyPair: federationKeys,
            baseCapabilities: capabilities);

        app.Server.OAuth().ResolveSubordinateListAsync = (_, _, _, _) =>
            ValueTask.FromResult<IReadOnlyList<EntityIdentifier>>([]);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = anchorKeys.Registration.TenantId.Value;

        //§8.8: federation endpoints accept POST as well as GET (a client-
        //authenticated request MUST be POST). A POST to the list endpoint must
        //match and be served, not fall through to the route default.
        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/federation_list");
        using System.Net.Http.FormUrlEncodedContent content = new([]);
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .PostAsync(url, content, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode,
            "§8.8: the federation list endpoint must also be served over POST.");
    }


    [TestMethod]
    [DataRow("trust_marked=true")]
    [DataRow("trust_mark_type=https%3A%2F%2Ftrust-mark.example%2Fmark")]
    [DataRow("intermediate=true")]
    public async Task ListEndpointRejectsUnsupportedFilterWithUnsupportedParameter(string query)
    {
        await using TestHostShell app = new(TimeProvider);

        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownFederationCapabilityIdentifiers.ListSubordinates);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        Uri anchorEntityId = new("https://anchor.example.com");

        using VerifierKeyMaterial anchorKeys = app.RegisterFederationCapableClient(
            clientId: "https://anchor.example.com",
            baseUri: anchorEntityId,
            federationEntityId: anchorEntityId,
            federationSigningKeyPair: federationKeys,
            baseCapabilities: capabilities);

        bool delegateInvoked = false;
        app.Server.OAuth().ResolveSubordinateListAsync = (_, _, _, _) =>
        {
            delegateInvoked = true;
            return ValueTask.FromResult<IReadOnlyList<EntityIdentifier>>([]);
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = anchorKeys.Registration.TenantId.Value;

        //§8.2.1: a filter the responder does not support MUST yield HTTP 400 with content
        //type application/json and the unsupported_parameter error code — not a silently
        //unfiltered list.
        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/federation_list?{query}");
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            $"An unsupported listing filter ({query}) must be rejected with HTTP 400.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.Content.Headers.ContentType?.MediaType,
            "§8.2.1: the unsupported_parameter error response must use content type application/json.");

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Dictionary<string, object>? error = JsonSerializer.Deserialize<Dictionary<string, object>>(
            body, TestSetup.DefaultSerializationOptions);
        Assert.IsNotNull(error);
        Assert.AreEqual("unsupported_parameter", (string)error["error"],
            "§8.2.1: the error code must be unsupported_parameter.");
        Assert.IsFalse(delegateInvoked,
            "An unsupported filter must be rejected before the membership delegate runs.");
    }


    private async ValueTask<string> GetListAsync(HostedAuthorizationServer host, string absolutePath)
    {
        Uri url = new(host.HttpBaseAddress!, absolutePath);
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode,
            $"GET {absolutePath} must return 200. Body: {await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false)}");

        string? actualContentType = response.Content.Headers.ContentType?.MediaType;
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, actualContentType,
            $"GET {absolutePath} must serve {WellKnownMediaTypes.Application.Json}.");

        return await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static List<string> ParseStringArray(string json)
    {
        List<string>? values = JsonSerializer.Deserialize<List<string>>(
            json, TestSetup.DefaultSerializationOptions);
        Assert.IsNotNull(values, "The §8.2 body must parse as a JSON array of strings.");

        return values;
    }
}
