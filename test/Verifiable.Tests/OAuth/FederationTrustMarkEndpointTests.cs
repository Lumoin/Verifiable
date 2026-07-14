using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Federation;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// End-to-end tests for the OpenID Federation 1.0 §8.6
/// <c>federation_trust_mark_endpoint</c> exposed by <see cref="FederationEndpoints"/>.
/// The endpoint serves the Trust Mark JWT (<c>application/trust-mark+jwt</c>) the
/// issuing entity issued for a queried (trust_mark_type, sub) pair; the JWT comes
/// from the application's
/// <see cref="AuthorizationServerIntegration.ResolveTrustMarkAsync"/> delegate,
/// while the library matches the request, parses <c>trust_mark_type</c> / <c>sub</c>,
/// and serves the JWT verbatim (signing nothing).
/// </summary>
[TestClass]
internal sealed class FederationTrustMarkEndpointTests
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
    /// Drives a GET against the trust mark endpoint and asserts the §8.6 content
    /// type, that the parsed <c>trust_mark_type</c> / <c>sub</c> reach the
    /// delegate, and that the app-provided Trust Mark JWT is served verbatim.
    /// </summary>
    [TestMethod]
    public async Task TrustMarkEndpointServesAppProvidedTrustMarkJwt()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri issuerEntityId = new("https://issuer.example.com");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial issuerKeys = RegisterIssuer(app, issuerEntityId, federationKeys);

        EntityTypeIdentifier markType = new("https://issuer.example.com/marks/onboarded");
        EntityIdentifier subject = new("https://leaf.example.com");
        const string TrustMarkJws = "eyJ0rust.mark.jwt";

        EntityTypeIdentifier? observedType = null;
        EntityIdentifier? observedSubject = null;

        app.Server.OAuth().ResolveTrustMarkAsync = (trustMarkType, sub, _, _, _) =>
        {
            observedType = trustMarkType;
            observedSubject = sub;

            return ValueTask.FromResult<string?>(TrustMarkJws);
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = issuerKeys.Registration.TenantId.Value;
        string query =
            $"?trust_mark_type={Uri.EscapeDataString(markType.Value)}"
            + $"&sub={Uri.EscapeDataString(subject.Value)}";

        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/federation_trust_mark{query}");
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode,
            $"GET federation_trust_mark must return 200. Body: {await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false)}");
        Assert.AreEqual(WellKnownMediaTypes.Application.TrustMarkJwt, response.Content.Headers.ContentType?.MediaType,
            "The trust mark must be served as application/trust-mark+jwt per §8.6.");

        Assert.IsNotNull(observedType);
        Assert.AreEqual(markType.Value, observedType.Value.Value,
            "The parsed trust_mark_type must reach the delegate.");
        Assert.IsNotNull(observedSubject);
        Assert.AreEqual(subject.Value, observedSubject.Value.Value,
            "The parsed sub must reach the delegate.");

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TrustMarkJws, body,
            "The library must serve the application-provided Trust Mark JWT verbatim.");
    }


    /// <summary>
    /// Asserts a null contribution yields HTTP 404 with the §8.9 not_found body.
    /// </summary>
    [TestMethod]
    public async Task TrustMarkEndpointReturns404WhenNoTrustMark()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri issuerEntityId = new("https://issuer.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial issuerKeys = RegisterIssuer(app, issuerEntityId, federationKeys);

        app.Server.OAuth().ResolveTrustMarkAsync =
            (_, _, _, _, _) => ValueTask.FromResult<string?>(null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = issuerKeys.Registration.TenantId.Value;
        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_trust_mark"
            + $"?trust_mark_type={Uri.EscapeDataString("https://issuer.example.com/marks/onboarded")}"
            + $"&sub={Uri.EscapeDataString("https://unknown.example.com")}");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, (int)response.StatusCode,
            "An entity with no matching Trust Mark yields HTTP 404 per the null-contribution contract.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.Content.Headers.ContentType?.MediaType,
            "Federation §8.9: the error response must be an application/json object.");
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.Contains($"\"error\":\"{OAuthErrors.NotFound}\"", body, StringComparison.Ordinal,
            $"Federation §8.9: a missing trust mark must carry the not_found error code. Got: {body}");
    }


    /// <summary>
    /// Asserts a request missing the REQUIRED <c>sub</c> parameter is rejected
    /// with HTTP 400 before the delegate runs.
    /// </summary>
    [TestMethod]
    public async Task TrustMarkEndpointRejectsMissingSub()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri issuerEntityId = new("https://issuer.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial issuerKeys = RegisterIssuer(app, issuerEntityId, federationKeys);

        bool delegateInvoked = false;
        app.Server.OAuth().ResolveTrustMarkAsync = (_, _, _, _, _) =>
        {
            delegateInvoked = true;
            return ValueTask.FromResult<string?>("eyJ0rust.mark.jwt");
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = issuerKeys.Registration.TenantId.Value;

        //§8.6: trust_mark_type and sub are REQUIRED. A request that names the
        //type but no subject is malformed (400), and the delegate must not run.
        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_trust_mark"
            + $"?trust_mark_type={Uri.EscapeDataString("https://issuer.example.com/marks/onboarded")}");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "A trust mark request without the REQUIRED sub parameter is malformed (Federation §8.6).");
        Assert.IsFalse(delegateInvoked,
            "The trust mark delegate must not run for a request rejected at parameter validation.");
    }


    /// <summary>
    /// Registers a federation-capable issuer carrying the
    /// <see cref="WellKnownFederationCapabilityIdentifiers.PublishTrustMark"/>
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
            WellKnownFederationCapabilityIdentifiers.PublishTrustMark);

        return app.RegisterFederationCapableClient(
            clientId: issuerEntityId.ToString(),
            baseUri: issuerEntityId,
            federationEntityId: issuerEntityId,
            federationSigningKeyPair: federationKeys,
            baseCapabilities: capabilities);
    }
}
