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
/// End-to-end tests for the OpenID Federation 1.0 §8.5
/// <c>federation_trust_mark_list_endpoint</c> exposed by
/// <see cref="FederationEndpoints"/>. The endpoint serves an unsigned JSON array
/// of the Entity Identifiers holding a queried Trust Mark type; the membership
/// comes from the application's
/// <see cref="AuthorizationServerIntegration.ResolveTrustMarkedListAsync"/>
/// delegate, while the library matches the request, parses the REQUIRED
/// <c>trust_mark_type</c> and OPTIONAL <c>sub</c> filter, and serialises the array.
/// </summary>
[TestClass]
internal sealed class FederationTrustMarkListEndpointTests
{
    /// <summary>
    /// The per-test context, injected by the test framework.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Deterministic clock the host reads from.
    /// </summary>
    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);


    /// <summary>
    /// Drives a GET against the listing endpoint and asserts the §8.5 unsigned
    /// JSON array, that the parsed <c>trust_mark_type</c> reaches the delegate,
    /// and that the membership order is preserved.
    /// </summary>
    [TestMethod]
    public async Task TrustMarkListEndpointServesUnsignedJsonArrayOfSubjects()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri issuerEntityId = new("https://issuer.example.com");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial issuerKeys = RegisterIssuer(app, issuerEntityId, federationKeys);

        EntityTypeIdentifier markType = new("https://issuer.example.com/marks/onboarded");
        EntityIdentifier alice = new("https://alice.example.com");
        EntityIdentifier bob = new("https://bob.example.com");

        EntityTypeIdentifier? observedType = null;
        EntityIdentifier? observedSubjectFilter = null;
        bool delegateInvoked = false;

        app.Server.OAuth().ResolveTrustMarkedListAsync = (trustMarkType, subjectFilter, _, _, _) =>
        {
            observedType = trustMarkType;
            observedSubjectFilter = subjectFilter;
            delegateInvoked = true;

            return ValueTask.FromResult<IReadOnlyList<EntityIdentifier>?>(
                new[] { alice, bob });
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = issuerKeys.Registration.TenantId.Value;
        string body = await GetListAsync(
            host,
            $"/connect/{segment}/federation_trust_mark_list?trust_mark_type={Uri.EscapeDataString(markType.Value)}").ConfigureAwait(false);

        Assert.IsTrue(delegateInvoked, "The listing delegate must be invoked.");
        Assert.IsNotNull(observedType);
        Assert.AreEqual(markType.Value, observedType.Value.Value,
            "The parsed trust_mark_type must reach the delegate.");
        Assert.IsNull(observedSubjectFilter,
            "An unfiltered request must pass a null sub filter to the delegate.");

        List<string> ids = ParseStringArray(body);
        Assert.HasCount(2, ids, "Both trust-marked subjects must be listed.");
        Assert.AreSequenceEqual(
            new[] { alice.Value, bob.Value },
            ids.ToArray(),
            "The §8.5 array must preserve the membership order the delegate returned.");
    }


    /// <summary>
    /// Asserts the OPTIONAL <c>sub</c> filter reaches the delegate as a parsed
    /// Entity Identifier.
    /// </summary>
    [TestMethod]
    public async Task TrustMarkListEndpointPassesSubFilterToDelegate()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri issuerEntityId = new("https://issuer.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial issuerKeys = RegisterIssuer(app, issuerEntityId, federationKeys);

        EntityIdentifier alice = new("https://alice.example.com");

        EntityIdentifier? observedSubjectFilter = null;
        app.Server.OAuth().ResolveTrustMarkedListAsync = (_, subjectFilter, _, _, _) =>
        {
            observedSubjectFilter = subjectFilter;
            return ValueTask.FromResult<IReadOnlyList<EntityIdentifier>?>(new[] { alice });
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = issuerKeys.Registration.TenantId.Value;
        string body = await GetListAsync(
            host,
            $"/connect/{segment}/federation_trust_mark_list"
            + $"?trust_mark_type={Uri.EscapeDataString("https://issuer.example.com/marks/onboarded")}"
            + $"&sub={Uri.EscapeDataString(alice.Value)}").ConfigureAwait(false);

        Assert.IsNotNull(observedSubjectFilter,
            "The sub query parameter must reach the delegate as a parsed filter.");
        Assert.AreEqual(alice.Value, observedSubjectFilter.Value.Value,
            "The parsed filter must carry the wire sub value.");

        List<string> ids = ParseStringArray(body);
        Assert.HasCount(1, ids, "The filtered list must contain only the queried subject.");
        Assert.AreEqual(alice.Value, ids[0]);
    }


    /// <summary>
    /// Asserts a request missing the REQUIRED <c>trust_mark_type</c> parameter is
    /// rejected with HTTP 400 before the delegate runs.
    /// </summary>
    [TestMethod]
    public async Task TrustMarkListEndpointRejectsMissingTrustMarkType()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri issuerEntityId = new("https://issuer.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial issuerKeys = RegisterIssuer(app, issuerEntityId, federationKeys);

        bool delegateInvoked = false;
        app.Server.OAuth().ResolveTrustMarkedListAsync = (_, _, _, _, _) =>
        {
            delegateInvoked = true;
            return ValueTask.FromResult<IReadOnlyList<EntityIdentifier>?>([]);
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = issuerKeys.Registration.TenantId.Value;

        //§8.5: trust_mark_type is REQUIRED. A request with none is malformed
        //(400), and the listing delegate must not run.
        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/federation_trust_mark_list");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "A listing request without the REQUIRED trust_mark_type parameter is malformed (Federation §8.5).");
        Assert.IsFalse(delegateInvoked,
            "The listing delegate must not run for a request rejected at parameter validation.");
    }


    /// <summary>
    /// Registers a federation-capable issuer carrying the
    /// <see cref="WellKnownFederationCapabilityIdentifiers.PublishTrustMarkedList"/>
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
            WellKnownFederationCapabilityIdentifiers.PublishTrustMarkedList);

        return app.RegisterFederationCapableClient(
            clientId: issuerEntityId.ToString(),
            baseUri: issuerEntityId,
            federationEntityId: issuerEntityId,
            federationSigningKeyPair: federationKeys,
            baseCapabilities: capabilities);
    }


    /// <summary>
    /// Issues the GET, asserts HTTP 200 and the §8.5 application/json content
    /// type, and returns the response body.
    /// </summary>
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


    /// <summary>
    /// Parses the §8.5 body as a JSON array of strings.
    /// </summary>
    private static List<string> ParseStringArray(string json)
    {
        List<string>? values = JsonSerializer.Deserialize<List<string>>(
            json, TestSetup.DefaultSerializationOptions);
        Assert.IsNotNull(values, "The §8.5 body must parse as a JSON array of strings.");

        return values;
    }
}
