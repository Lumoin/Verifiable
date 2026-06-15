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

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();


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

        EntityTypeIdentifier? observedFilter = null;
        bool filterObserved = false;

        app.Server.OAuth().ResolveSubordinateListAsync = (entityTypeFilter, _, _, _) =>
        {
            observedFilter = entityTypeFilter;
            filterObserved = true;

            return ValueTask.FromResult<IReadOnlyList<EntityIdentifier>>(
                new[] { alice, bob, carol });
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = anchorKeys.Registration.TenantId.Value;

        string body = await GetListAsync(host, $"/connect/{segment}/federation_list").ConfigureAwait(false);

        //An unfiltered list request carries no entity_type, so the delegate
        //sees a null filter.
        Assert.IsTrue(filterObserved, "The list delegate must be invoked.");
        Assert.IsNull(observedFilter,
            "An unfiltered request must pass a null entity_type filter to the delegate.");

        List<string> ids = ParseStringArray(body);
        Assert.HasCount(3, ids, "All three subordinates must be listed.");
        CollectionAssert.AreEqual(
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

        EntityTypeIdentifier? observedFilter = null;

        //The application filters its membership by the parsed entity_type:
        //only the openid_relying_party subordinate comes back.
        app.Server.OAuth().ResolveSubordinateListAsync = (entityTypeFilter, _, _, _) =>
        {
            observedFilter = entityTypeFilter;

            IReadOnlyList<EntityIdentifier> result =
                entityTypeFilter == WellKnownEntityTypeIdentifiers.OpenIdRelyingParty
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

        Assert.IsNotNull(observedFilter,
            "The entity_type query parameter must reach the delegate as a parsed filter.");
        Assert.AreEqual(
            WellKnownEntityTypeIdentifiers.OpenIdRelyingParty.Value,
            observedFilter.Value.Value,
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
