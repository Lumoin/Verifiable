using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
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
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The Wallet client identifier registered for the nonce tests.</summary>
    private const string ClientId = "https://wallet.client.test";

    /// <summary>The base URI the registered client is reachable at.</summary>
    private static Uri ClientBaseUri { get; } = new("https://wallet.client.test");

    /// <summary>The single capability the Nonce Endpoint requires.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> NonceCapabilities { get; } =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.Oid4VciNonceEndpoint);


    /// <summary>
    /// A Nonce Request sent over the real wire as an HTTP POST with an empty body and no
    /// <c>Authorization</c> field is answered 200 with the application's <c>c_nonce</c> as the one
    /// top-level member of an <c>application/json</c> body, one <c>Cache-Control: no-store</c>
    /// field, and no <c>WWW-Authenticate</c> challenge.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.1">OID4VCI 1.0 Section 7.1</see>:
    /// "A request for a nonce is made by sending an HTTP POST request to the URL provided in the
    /// nonce_endpoint Credential Issuer Metadata parameter. The Nonce Endpoint is not a protected
    /// resource, meaning the Wallet does not need to supply an access token to access it."
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2">OID4VCI 1.0 Section 7.2</see>:
    /// "The Credential Issuer provides a nonce value in an HTTP response with a 2xx status code and the
    /// following parameters included as top-level members in the message body of the HTTP response
    /// using the application/json media type: c_nonce: REQUIRED." and "Due to the temporal nature of
    /// the c_nonce value, the Credential Issuer MUST make the response uncacheable by adding a
    /// Cache-Control header field including the value no-store."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task NonceEndpointAnswersAnUnprotectedPostOverTheWireAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, NonceCapabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.IssueCredentialNonceAsync = static (_, _) =>
                ValueTask.FromResult("wKI4LT17ac15ES9bw8ac4");
        }).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Uri nonceEndpoint = TestHostShell.ComposeEndpointUri(
            host.Host("default").HttpBaseAddress!, material.Registration.TenantId.Value, WellKnownEndpointNames.Oid4VciNonce);

        HttpResponseData response = await HttpClientTransport.SendFormPostAsync(
            host.Host("default").SharedHttpClient!,
            nonceEndpoint,
            [],
            OutgoingHeaders.Empty,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual("application/json", response.Headers.Headers.ContentType, response.Body);
        Assert.AreSequenceEqual(
            [WellKnownCacheControlValues.NoStore],
            response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.CacheControl).ToArray(),
            "The Nonce Response carries one Cache-Control field whose value is no-store.");
        Assert.IsEmpty(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate),
            "The unprotected Nonce Endpoint answers a request without an access token with no challenge.");
        Assert.AreEqual("{\"c_nonce\":\"wKI4LT17ac15ES9bw8ac4\"}", response.Body);
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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, NonceCapabilities).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciNonce,
            "POST",
            new RequestFields(),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            "An unwired nonce seam must leave the endpoint absent (fail-closed).");
    }
}
