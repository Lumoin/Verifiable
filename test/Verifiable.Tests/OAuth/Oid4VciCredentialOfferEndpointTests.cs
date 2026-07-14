using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Server.Routing;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Server-side OID4VCI 1.0 §4.1.3 Credential Offer Endpoint, driven through the real dispatch
/// pipeline. The Wallet fetched the <c>credential_offer_uri</c> out of a by-reference deep link
/// and GETs it; the unprotected endpoint reads the offer <c>id</c>, resolves the stored
/// <see cref="CredentialOffer"/> through the
/// <see cref="ResolveCredentialOfferDelegate"/> seam, and serves the §4.1.1 JSON object
/// (<c>application/json</c>, never signed), 404ing when no live offer matches.
/// </summary>
[TestClass]
internal sealed class Oid4VciCredentialOfferEndpointTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so dispatch behaviour is reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The Credential Issuer client identifier registered for the offer tests.</summary>
    private const string ClientId = "https://issuer.client.test";

    /// <summary>The base URI the registered client is reachable at.</summary>
    private static readonly Uri ClientBaseUri = new("https://issuer.client.test");

    /// <summary>The Credential Issuer identity the served offer carries (§4.1.1 credential_issuer).</summary>
    private static readonly Uri OfferIssuer = new("https://credential-issuer.example.com");

    /// <summary>The supported Credential Configuration identifier the offer advertises.</summary>
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";

    /// <summary>The §4.1.1 pre-authorized_code the served offer's grant block carries.</summary>
    private const string PreAuthorizedCode = "oaKazRN8I0IbtZ0C7JuMn5";

    /// <summary>The id the credential_offer_uri carries; the offer store is keyed by it.</summary>
    private const string OfferId = "GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM";

    private static readonly ImmutableHashSet<CapabilityIdentifier> OfferCapabilities =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.Oid4VciCredentialOfferEndpoint);


    /// <summary>
    /// A wired Credential Offer Endpoint serves the stored offer as the §4.1.1 JSON object: the
    /// response is 200 <c>application/json</c> and strict-parses back to the same Pre-Authorized
    /// Code the offer was built with.
    /// </summary>
    [TestMethod]
    public async Task ServesStoredOfferByReference()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, OfferCapabilities);
        string segment = material.Registration.TenantId.Value;

        host.Server.OAuth().ResolveCredentialOfferAsync =
            (offerId, context, ct) => ValueTask.FromResult<CredentialOffer?>(
                string.Equals(offerId, OfferId, StringComparison.Ordinal) ? BuildStoredOffer() : null);

        ServerHttpResponse response = await DispatchOfferAsync(host, segment, OfferId).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual("application/json", response.ContentType);

        //§4.1.3: the body is the §4.1.1 JSON object — it round-trips through the serializer's
        //parse path to the same issuer, configuration, and pre-authorized_code.
        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement root = doc.RootElement;

        Assert.AreEqual(OfferIssuer.OriginalString, root.GetProperty("credential_issuer").GetString());
        Assert.AreEqual(ConfigurationId, root.GetProperty("credential_configuration_ids")[0].GetString());
        Assert.AreEqual(PreAuthorizedCode,
            root.GetProperty("grants")
                .GetProperty(WellKnownGrantTypes.PreAuthorizedCode)
                .GetProperty("pre-authorized_code").GetString());
    }


    /// <summary>
    /// With the resolve seam wired but the offer store returning <see langword="null"/> for an
    /// unknown id, the endpoint answers HTTP 404 — there is no offer to serve.
    /// </summary>
    [TestMethod]
    public async Task UnknownOfferIdYields404()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, OfferCapabilities);
        string segment = material.Registration.TenantId.Value;

        host.Server.OAuth().ResolveCredentialOfferAsync =
            (offerId, context, ct) => ValueTask.FromResult<CredentialOffer?>(null);

        ServerHttpResponse response = await DispatchOfferAsync(host, segment, "no-such-offer").ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            "An unresolved offer id must answer 404 — there is no offer to serve.");
    }


    /// <summary>
    /// Fail-closed: declaring the capability without wiring the resolve seam leaves the endpoint
    /// absent from the chain, so the dispatch 404s (the endpoint is not present rather than
    /// fronting a store it cannot reach).
    /// </summary>
    [TestMethod]
    public async Task OfferEndpointAbsentWhenResolveSeamUnwired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, OfferCapabilities);
        string segment = material.Registration.TenantId.Value;

        //The resolve seam is deliberately left unwired.
        ServerHttpResponse response = await DispatchOfferAsync(host, segment, OfferId).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            "An unwired resolve seam must leave the offer endpoint absent (fail-closed).");
    }


    /// <summary>
    /// A representative §4.1.1 Pre-Authorized Code offer the store hands back for <see cref="OfferId"/>.
    /// </summary>
    private static CredentialOffer BuildStoredOffer() =>
        new()
        {
            CredentialIssuer = OfferIssuer,
            CredentialConfigurationIds = [ConfigurationId],
            PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant
            {
                PreAuthorizedCode = PreAuthorizedCode,
                TxCode = TxCodeRequirement.Empty
            }
        };


    /// <summary>
    /// GETs the §4.1.3 Credential Offer resource for the tenant, carrying the offer id in the
    /// <c>id</c> request field the endpoint reads.
    /// </summary>
    private async Task<ServerHttpResponse> DispatchOfferAsync(TestHostShell host, string segment, string offerId)
    {
        return await host.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.Oid4VciCredentialOffer,
            WellKnownHttpMethods.Get,
            new RequestFields { [CredentialOfferParameterNames.Id] = offerId },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}
