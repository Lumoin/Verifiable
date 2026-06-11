using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Server-side OID4VCI 1.0 §7 Nonce Endpoint, driven through the real dispatch pipeline. The
/// endpoint is unprotected (§7.1: the Wallet supplies no access token); the library owns the
/// wire — the <c>{"c_nonce": ...}</c> JSON, the §7.2 <c>Cache-Control: no-store</c>, and the
/// fail-closed candidate gate — while the application mints the <c>c_nonce</c> behind
/// <see cref="IssueCredentialNonceDelegate"/>.
/// </summary>
[TestClass]
internal sealed class Oid4VciNonceEndpointTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so issued artefacts are reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    /// <summary>The Wallet client identifier registered for the nonce tests.</summary>
    private const string ClientId = "https://wallet.client.test";

    /// <summary>The base URI the registered client is reachable at.</summary>
    private static readonly Uri ClientBaseUri = new("https://wallet.client.test");

    /// <summary>The single capability the Nonce Endpoint requires.</summary>
    private static readonly ImmutableHashSet<CapabilityIdentifier> NonceCapabilities =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.Oid4VciNonceEndpoint);


    /// <summary>
    /// A wired Nonce Endpoint answers an unprotected POST with the application's fresh
    /// <c>c_nonce</c> as <c>application/json</c> and the §7.2 <c>Cache-Control: no-store</c>.
    /// </summary>
    [TestMethod]
    public async Task NonceEndpointReturnsFreshCNonceUncacheable()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, NonceCapabilities);

        host.Server.Integration.IssueCredentialNonceAsync = static (_, _) =>
            ValueTask.FromResult("wKI4LT17ac15ES9bw8ac4");

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciNonce,
            "POST",
            new RequestFields(),
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual("application/json", response.ContentType);

        //§7.2: the temporal c_nonce MUST be uncacheable.
        Assert.IsTrue(response.Headers.TryGetValue(WellKnownHttpHeaderNames.CacheControl, out string? cacheControl),
            "The Nonce Response MUST carry Cache-Control.");
        Assert.AreEqual(WellKnownCacheControlValues.NoStore, cacheControl);

        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual("wKI4LT17ac15ES9bw8ac4", document.RootElement.GetProperty("c_nonce").GetString());
    }


    /// <summary>
    /// Fail-closed: declaring the Nonce capability without wiring the nonce-issuance seam
    /// leaves the endpoint absent from the chain, so a request to it returns 404 rather than an
    /// endpoint that cannot mint a challenge.
    /// </summary>
    [TestMethod]
    public async Task NonceEndpointAbsentWhenSeamUnwired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, NonceCapabilities);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciNonce,
            "POST",
            new RequestFields(),
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            "An unwired nonce seam must leave the endpoint absent (fail-closed).");
    }
}
