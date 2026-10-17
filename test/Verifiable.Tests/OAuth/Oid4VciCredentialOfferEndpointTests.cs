using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;
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
    private static Uri ClientBaseUri { get; } = new("https://issuer.client.test");

    /// <summary>The Credential Issuer identity the served offer carries (§4.1.1 credential_issuer).</summary>
    private static Uri OfferIssuer { get; } = new("https://credential-issuer.example.com");

    /// <summary>The supported Credential Configuration identifier the offer advertises.</summary>
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";

    /// <summary>The §4.1.1 pre-authorized_code the served offer's grant block carries.</summary>
    private const string PreAuthorizedCode = "oaKazRN8I0IbtZ0C7JuMn5";

    /// <summary>The id the credential_offer_uri carries; the offer store is keyed by it.</summary>
    private const string OfferId = "GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM";

    /// <summary>The opaque <c>issuer_state</c> an Authorization Code offer carries.</summary>
    private static string OfferIssuerState { get; } = "eyJhbGciOiJSU0Et...FYUaBy";

    private static ImmutableHashSet<CapabilityIdentifier> OfferCapabilities { get; } =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.Oid4VciCredentialOfferEndpoint);


    /// <summary>
    /// A Credential Offer Object fetched over the real wire with an HTTP GET of its
    /// <c>credential_offer_uri</c> is answered 200 with an unsigned <c>application/json</c> body
    /// carrying the stored offer's parameters: the <c>credential_issuer</c>, the
    /// <c>credential_configuration_ids</c> and, per row, the Pre-Authorized Code grant whose
    /// <c>tx_code</c> object is empty, or the Authorization Code grant's <c>issuer_state</c>.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.1">OID4VCI 1.0 Section 4.1.1</see>:
    /// "credential_issuer: REQUIRED.", "credential_configuration_ids: REQUIRED. A non-empty array of
    /// unique strings", "tx_code: OPTIONAL. Object indicating that a Transaction Code is required if
    /// present, even if empty." and "If no length, description, or input_mode is given, this object
    /// MAY be empty."
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.3">OID4VCI 1.0 Section 4.1.3</see>:
    /// "The response from the Credential Issuer that contains a Credential Offer Object MUST use the
    /// media type application/json." and "The Credential Offer cannot be signed and MUST NOT use
    /// application/jwt with "alg": "none"."
    /// </summary>
    /// <param name="grantType">The grant the stored offer carries: <c>pre-authorized</c> or <c>authorization-code</c>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("pre-authorized")]
    [DataRow("authorization-code")]
    public async Task OfferEndpointServesTheStoredOfferOverTheWireAsync(string grantType)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, OfferCapabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        bool isPreAuthorized = string.Equals(grantType, "pre-authorized", StringComparison.Ordinal);
        CredentialOffer stored = isPreAuthorized
            ? BuildStoredOffer()
            : new CredentialOffer
            {
                CredentialIssuer = OfferIssuer,
                CredentialConfigurationIds = [ConfigurationId],
                AuthorizationCodeGrant = new AuthorizationCodeOfferGrant { IssuerState = OfferIssuerState }
            };

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveCredentialOfferAsync =
                (offerId, context, ct) => ValueTask.FromResult<CredentialOffer?>(
                    string.Equals(offerId, OfferId, StringComparison.Ordinal) ? stored : null);
        }).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Uri offerEndpoint = TestHostShell.ComposeEndpointUri(
            host.Host("default").HttpBaseAddress!, segment, WellKnownEndpointNames.Oid4VciCredentialOffer);
        HttpResponseData response = await HttpClientTransport.SendJsonGetAsync(
            host.Host("default").SharedHttpClient!,
            new Uri($"{offerEndpoint}?{CredentialOfferParameterNames.Id}={OfferId}"),
            OutgoingHeaders.Empty,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual("application/json", response.Headers.Headers.ContentType, response.Body);

        using JsonDocument document = JsonDocument.Parse(response.Body);
        JsonElement root = document.RootElement;
        Assert.AreEqual("https://credential-issuer.example.com", root.GetProperty("credential_issuer").GetString());
        Assert.AreSequenceEqual(
            ["UniversityDegree_dc_sd_jwt"],
            root.GetProperty("credential_configuration_ids").EnumerateArray().Select(static id => id.GetString()).ToArray());

        JsonElement grants = root.GetProperty("grants");
        if(isPreAuthorized)
        {
            JsonElement grant = grants.GetProperty(WellKnownGrantTypes.PreAuthorizedCode);
            Assert.AreEqual("oaKazRN8I0IbtZ0C7JuMn5", grant.GetProperty("pre-authorized_code").GetString());
            Assert.IsTrue(grant.TryGetProperty("tx_code", out JsonElement txCode),
                "The served offer carries the tx_code object its stored grant requires, even when empty.");
            Assert.AreEqual(JsonValueKind.Object, txCode.ValueKind);
            Assert.IsEmpty(txCode.EnumerateObject(), "The empty tx_code requirement is served as an empty object.");
        }
        else
        {
            Assert.AreEqual(OfferIssuerState, grants.GetProperty(WellKnownGrantTypes.AuthorizationCode).GetProperty("issuer_state").GetString());
        }
    }


    /// <summary>
    /// With the resolve seam wired but the offer store returning <see langword="null"/> for an
    /// unknown id, the endpoint answers HTTP 404 — there is no offer to serve.
    /// </summary>
    [TestMethod]
    public async Task UnknownOfferIdYields404()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, OfferCapabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveCredentialOfferAsync =
                (offerId, context, ct) => ValueTask.FromResult<CredentialOffer?>(null);
        }).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, OfferCapabilities).ConfigureAwait(false);
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
            [],
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}
