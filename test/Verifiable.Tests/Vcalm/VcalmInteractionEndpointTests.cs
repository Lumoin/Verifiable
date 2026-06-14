using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Vcalm;
using Verifiable.Vcalm.Exchange;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.OAuth;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// Conformance tests for the W3C VCALM 1.0 §3.7 "Initiating Interactions" coordinator surface
/// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
/// Management</see>) — the §3.7.1 interaction-URL composer (the <c>iuv=1</c> MUST), the §3.7.2 QR-code
/// length bounds (the 4296 MUST-NOT / 400 SHOULD-NOT), the §3.7.3 <c>interaction:</c> scheme, the
/// §3.7.4 content-negotiated interaction-protocols-response endpoint, the §3.7.5 inviteRequest endpoint,
/// and the §3.7.6 vcapi entry wiring into the §3.6 exchange engine.
/// </summary>
/// <remarks>
/// §2.1 / §3.7.1: the §3.7 surface is COORDINATOR-hosted (its Web origin a trust signal) and gated by
/// the dedicated <see cref="WellKnownVcalmCapabilities.VcalmCoordinator"/> capability. The §3.7.6 test
/// proves the bootstrapping layer points AT the §3.6 exchange: the vcapi URL in the §3.7.4 protocols map
/// addresses a real §3.6.5 participate endpoint that accepts the empty initiating vcapi message.
/// </remarks>
[TestClass]
internal sealed class VcalmInteractionEndpointTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private const string ClientId = "https://coordinator.client.test";
    private static readonly Uri ClientBaseUri = new("https://coordinator.client.test");

    private static readonly ImmutableHashSet<CapabilityIdentifier> CoordinatorCapabilities =
        ImmutableHashSet.Create(WellKnownVcalmCapabilities.VcalmCoordinator);

    //The §3.7.6 test co-hosts the coordinator role with the §3.6 exchange role so the vcapi URL the
    //§3.7.4 map advertises addresses a real exchange the same host can participate in.
    private static readonly ImmutableHashSet<CapabilityIdentifier> CoordinatorAndExchangeCapabilities =
        ImmutableHashSet.Create(
            WellKnownVcalmCapabilities.VcalmCoordinator, WellKnownVcalmCapabilities.VcalmExchange);

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    //The §3.4 query the exchange engine sends when it requests a presentation in the §3.7.6 wiring test.
    private const string DidAuthQueryJson =
        "[{\"type\":\"DIDAuthentication\",\"acceptedMethods\":[{\"method\":\"key\"}]}]";

    private List<VerifierKeyMaterial> RegisteredMaterials { get; } = [];


    [TestCleanup]
    public void DisposeRegisteredMaterials()
    {
        foreach(VerifierKeyMaterial material in RegisteredMaterials)
        {
            material.Dispose();
        }

        RegisteredMaterials.Clear();
    }


    // ---- §3.7.1 Interaction URL Format ----

    /// <summary>
    /// §3.7.1: the composed interaction URL MUST carry the <c>iuv=1</c> query parameter, and SHOULD be
    /// HTTPS when the coordinator base is HTTPS.
    /// </summary>
    [TestMethod]
    public void ComposedInteractionUrlCarriesIuv1AndPreservesHttps()
    {
        const string coordinatorBase = "https://coordinator.example/interactions/z8n38Dp7a";

        string interactionUrl = VcalmInteractionUrlComposer.ComposeInteractionUrl(coordinatorBase, "z8n38Dp7a");

        Assert.IsTrue(interactionUrl.Contains("iuv=1", StringComparison.Ordinal),
            "§3.7.1: the interaction URL MUST carry iuv=1 (this version of the API).");
        Assert.IsTrue(interactionUrl.StartsWith("https://", StringComparison.Ordinal),
            "§3.7.1: the interaction URL SHOULD be HTTPS when the coordinator base is HTTPS.");
        Assert.IsTrue(interactionUrl.Contains("z8n38Dp7a", StringComparison.Ordinal),
            "§3.7.1: the interaction URL carries the interaction-specific identifier.");
    }


    /// <summary>
    /// §3.7.1: the <c>iuv</c> parameter is appended with <c>&amp;</c> when the coordinator base already
    /// carries a query, so the URL stays a single valid query string.
    /// </summary>
    [TestMethod]
    public void ComposedInteractionUrlAppendsIuvWithAmpersandWhenQueryPresent()
    {
        const string coordinatorBase = "https://coordinator.example/interactions/abc?ref=42";

        string interactionUrl = VcalmInteractionUrlComposer.ComposeInteractionUrl(coordinatorBase, "abc");

        Assert.IsTrue(interactionUrl.Contains("?ref=42&iuv=1", StringComparison.Ordinal),
            "§3.7.1: iuv is appended with '&' when the base already carries a query.");
    }


    // ---- §3.7.2 Interaction QR Code Format (bounds enforcement) ----

    /// <summary>
    /// §3.7.2: a within-bounds interaction URL validates with no advisory.
    /// </summary>
    [TestMethod]
    public void QrValidationAcceptsWithinBoundsUrl()
    {
        const string interactionUrl = "https://coordinator.example/interactions/z8n38Dp7a?iuv=1";

        VcalmInteractionQrValidation validation = VcalmInteractionUrlComposer.ValidateQrBounds(interactionUrl);

        Assert.IsTrue(validation.IsValid, "§3.7.2: a short URL is within the 4296 MUST-NOT bound.");
        Assert.IsFalse(validation.HasAdvisory, "§3.7.2: a short URL is within the 400 SHOULD-NOT bound.");
    }


    /// <summary>
    /// §3.7.2 MUST-NOT: an interaction URL over 4,296 characters is rejected (it cannot be a single QR
    /// code per ISO 18004).
    /// </summary>
    [TestMethod]
    public void QrValidationRejectsUrlOverHardBound()
    {
        string interactionUrl = "https://coordinator.example/interactions/"
            + new string('a', VcalmInteractionUrlComposer.QrMaximumLength)
            + "?iuv=1";

        VcalmInteractionQrValidation validation = VcalmInteractionUrlComposer.ValidateQrBounds(interactionUrl);

        Assert.IsGreaterThan(VcalmInteractionUrlComposer.QrMaximumLength, validation.UrlLength,
            "The fixture URL is over the 4296 hard bound.");
        Assert.IsFalse(validation.IsValid,
            "§3.7.2: a URL over 4,296 alphanumeric characters MUST NOT be used as a QR code (rejected).");
    }


    /// <summary>
    /// §3.7.2 SHOULD-NOT: an interaction URL over 400 but within 4,296 characters validates but carries
    /// a non-fatal advisory.
    /// </summary>
    [TestMethod]
    public void QrValidationFlagsAdvisoryForUrlOverSoftBound()
    {
        string interactionUrl = "https://coordinator.example/interactions/"
            + new string('a', VcalmInteractionUrlComposer.QrAdvisoryLengthLimit)
            + "?iuv=1";

        VcalmInteractionQrValidation validation = VcalmInteractionUrlComposer.ValidateQrBounds(interactionUrl);

        Assert.IsTrue(validation.IsValid,
            "§3.7.2: a URL within the 4,296 MUST-NOT bound is still valid.");
        Assert.IsTrue(validation.HasAdvisory,
            "§3.7.2: a URL over the 400 SHOULD-NOT bound carries a non-fatal advisory.");
    }


    // ---- §3.7.3 Interaction Scheme Format ----

    /// <summary>
    /// §3.7.3: the <c>interaction:</c> scheme string conforms to <c>scheme = "interaction:" interaction-url</c>.
    /// </summary>
    [TestMethod]
    public void InteractionSchemeConformsToSyntax()
    {
        const string interactionUrl = "https://app.example/interactions/z8n38Dp7a?iuv=1";

        string scheme = VcalmInteractionUrlComposer.ComposeInteractionScheme(interactionUrl);

        Assert.AreEqual("interaction:" + interactionUrl, scheme,
            "§3.7.3: scheme = \"interaction:\" interaction-url, with the URL wrapped verbatim.");
        Assert.IsTrue(scheme.StartsWith("interaction:", StringComparison.Ordinal),
            "§3.7.3: the scheme begins with the interaction: prefix.");
    }


    // ---- §3.7.4 Interaction Protocols Response (content-negotiated) ----

    /// <summary>
    /// §3.7.4: GET the interaction URL with <c>Accept: application/json</c> MUST return a
    /// <c>{protocols:{…}}</c> map carrying the expected protocol keys.
    /// </summary>
    [TestMethod]
    public async Task GetInteractionProtocolsWithJsonAcceptReturnsProtocolsMap()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterCoordinator(app);

        const string interactionId = "z8n38Dp7a";
        app.Server.Vcalm().ResolveVcalmInteractionProtocolsAsync = (id, _, _) =>
            ValueTask.FromResult<VcalmInteractionProtocols?>(
                string.Equals(id, interactionId, StringComparison.Ordinal)
                    ? new VcalmInteractionProtocols
                    {
                        InviteRequestUrl = "https://saas.example/interactions/123/invite-request/response",
                        VcapiUrl = "https://saas.example/workflows/123/exchanges/987"
                    }
                    : null);

        ServerHttpResponse response = await app.DispatchVcalmInteractionProtocolsAsync(
            segment, interactionId, WellKnownMediaTypes.Application.Json,
            new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.ContentType,
            "§3.7.4: an application/json Accept returns the JSON protocols map.");

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement protocols = doc.RootElement.GetProperty(VcalmParameterNames.Protocols);
        Assert.IsTrue(protocols.TryGetProperty(VcalmParameterNames.InviteRequest, out _),
            "§3.7.4: the protocols map carries the inviteRequest entry.");
        Assert.IsTrue(protocols.TryGetProperty(VcalmParameterNames.Vcapi, out _),
            "§3.7.4: the protocols map carries the vcapi entry.");
    }


    /// <summary>
    /// §3.7.4 MUST: GET the interaction URL with an unrecognized <c>Accept</c> header MUST return a
    /// <c>text/html</c> body directing a human to suitable software — not the JSON map.
    /// </summary>
    [TestMethod]
    public async Task GetInteractionProtocolsWithUnrecognizedAcceptReturnsHtml()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterCoordinator(app);

        const string interactionId = "z8n38Dp7a";
        app.Server.Vcalm().ResolveVcalmInteractionProtocolsAsync = (id, _, _) =>
            ValueTask.FromResult<VcalmInteractionProtocols?>(new VcalmInteractionProtocols
            {
                InviteRequestUrl = "https://saas.example/interactions/123/invite-request/response"
            });

        ServerHttpResponse response = await app.DispatchVcalmInteractionProtocolsAsync(
            segment, interactionId, "text/html", new ExchangeContext(), TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(WellKnownMediaTypes.Text.Html, response.ContentType,
            "§3.7.4: an unrecognized Accept MUST return a text/html document.");
        Assert.IsTrue(response.Body.Contains("<html", StringComparison.OrdinalIgnoreCase),
            "§3.7.4: the text/html body is an HTML document directing a human to suitable software.");
        Assert.IsFalse(response.Body.TrimStart().StartsWith('{'),
            "§3.7.4: the unrecognized-Accept response is HTML, NOT the JSON protocols map.");
    }


    /// <summary>
    /// §3.7.4: GET the interaction URL with NO Accept header takes the text/html fallback (the
    /// unrecognized-Accept MUST), since only an application/json Accept gets the JSON map.
    /// </summary>
    [TestMethod]
    public async Task GetInteractionProtocolsWithNoAcceptReturnsHtml()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterCoordinator(app);

        app.Server.Vcalm().ResolveVcalmInteractionProtocolsAsync = (id, _, _) =>
            ValueTask.FromResult<VcalmInteractionProtocols?>(new VcalmInteractionProtocols
            {
                VcapiUrl = "https://saas.example/workflows/123/exchanges/987"
            });

        ServerHttpResponse response = await app.DispatchVcalmInteractionProtocolsAsync(
            segment, "z8n38Dp7a", acceptHeader: null, new ExchangeContext(), TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(WellKnownMediaTypes.Text.Html, response.ContentType,
            "§3.7.4: a request with no Accept takes the text/html branch (only application/json gets JSON).");
    }


    /// <summary>
    /// §3.7.4: an unknown interaction id is a 404.
    /// </summary>
    [TestMethod]
    public async Task GetProtocolsOfUnknownInteractionYields404()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterCoordinator(app);

        app.Server.Vcalm().ResolveVcalmInteractionProtocolsAsync = (id, _, _) =>
            ValueTask.FromResult<VcalmInteractionProtocols?>(null);

        ServerHttpResponse response = await app.DispatchVcalmInteractionProtocolsAsync(
            segment, "never-created", WellKnownMediaTypes.Application.Json,
            new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode, "§3.7.4: an unknown interaction id is 404.");
    }


    // ---- §3.7.5 inviteRequest Interaction Protocol ----

    /// <summary>
    /// §3.7.5: a well-formed inviteRequest POST is accepted (200) and recorded under the invite id.
    /// </summary>
    [TestMethod]
    public async Task PostInviteRequestYields200AndIsStored()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterCoordinator(app);

        Dictionary<string, VcalmInviteRequest> store = new(StringComparer.Ordinal);
        app.Server.Vcalm().StoreVcalmInviteRequestAsync = (inviteId, invite, _, _) =>
        {
            store[inviteId] = invite;
            return ValueTask.CompletedTask;
        };

        const string inviteId = "8372974";
        const string body =
            "{\"url\":\"https://website.example/checkout/8372974\",\"purpose\":\"Checkout at ShopCo\","
            + "\"referenceId\":\"417bcaf2-14d9-11f0-99d7-9f094678517b\"}";

        ServerHttpResponse response = await app.DispatchVcalmInviteRequestAsync(
            segment, inviteId, body, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.IsTrue(store.TryGetValue(inviteId, out VcalmInviteRequest? stored),
            "§3.7.5: the accepted invitation is recorded under the invite id.");
        Assert.AreEqual("https://website.example/checkout/8372974", stored!.Url,
            "§3.7.5: the stored invitation carries the url.");
        Assert.AreEqual("Checkout at ShopCo", stored.Purpose, "§3.7.5: the stored invitation carries the purpose.");
    }


    /// <summary>
    /// §3.7.5 / §2.4: a malformed inviteRequest body (not a JSON object) is rejected with HTTP 400.
    /// </summary>
    [TestMethod]
    public async Task PostMalformedInviteRequestYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterCoordinator(app);

        ServerHttpResponse response = await app.DispatchVcalmInviteRequestAsync(
            segment, "8372974", "\"not-an-object\"", new ExchangeContext(), TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "§3.7.5 / §2.4: a malformed inviteRequest body is rejected with 400.");
    }


    /// <summary>
    /// §3.7.5: an inviteRequest body missing the REQUIRED <c>url</c> member is rejected with HTTP 400.
    /// </summary>
    [TestMethod]
    public async Task PostInviteRequestWithoutUrlYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterCoordinator(app);

        ServerHttpResponse response = await app.DispatchVcalmInviteRequestAsync(
            segment, "8372974", "{\"purpose\":\"Checkout\"}", new ExchangeContext(), TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "§3.7.5: an inviteRequest without the url member is rejected with 400.");
    }


    // ---- §3.7.6 vcapi Interaction Protocol (wired to a §3.6 exchange) ----

    /// <summary>
    /// §3.7.6: the vcapi protocol entry in the §3.7.4 protocols map addresses a REAL §3.6.5 participate
    /// endpoint. The coordinator resolves the interaction's vcapi URL to a §3.6 exchange's participate
    /// path; POSTing the empty initiating vcapi message to that endpoint drives the §3.6 exchange (a 200
    /// with a verifiablePresentationRequest), proving §3.7.6 reuses the §3.6 engine rather than
    /// re-implementing it.
    /// </summary>
    [TestMethod]
    public async Task VcapiProtocolEntryAddressesRealExchangeParticipateEndpoint()
    {
        await using TestHostShell app = new(TimeProvider);
        ClientRecord coordinator = RegisterCoordinatorAndExchange(app);
        string segment = coordinator.TenantId.Value;

        //Create a real §3.6 exchange on the same host.
        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //§3.7.4: the coordinator advertises this interaction's vcapi protocol as the §3.6.5 participate
        //URL of the created exchange (the §3.7.6 "initiate a specific exchange" wiring).
        app.Server.Vcalm().ResolveVcalmInteractionProtocolsAsync = (interactionId, ctx, ct) =>
            ResolveProtocolsToExchangeAsync(app, coordinator, exchangeId, ctx, ct);

        //Fetch the §3.7.4 protocols map and read the vcapi URL.
        ServerHttpResponse protocolsResponse = await app.DispatchVcalmInteractionProtocolsAsync(
            segment, "interaction-1", WellKnownMediaTypes.Application.Json,
            new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, protocolsResponse.StatusCode, protocolsResponse.Body);

        using JsonDocument doc = JsonDocument.Parse(protocolsResponse.Body);
        string vcapiUrl = doc.RootElement
            .GetProperty(VcalmParameterNames.Protocols)
            .GetProperty(VcalmParameterNames.Vcapi)
            .GetString()!;
        Assert.IsTrue(vcapiUrl.Contains(exchangeId, StringComparison.Ordinal),
            "§3.7.6: the vcapi URL addresses the created §3.6 exchange.");

        //§3.7.6: POST the empty initiating vcapi message to the §3.6.5 participate endpoint the vcapi URL
        //addresses — the §3.6 engine responds with a verifiablePresentationRequest (more needed).
        ServerHttpResponse participate = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{}", new ExchangeContext(), TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(200, participate.StatusCode, participate.Body);
        using JsonDocument participateDoc = JsonDocument.Parse(participate.Body);
        Assert.IsTrue(
            participateDoc.RootElement.TryGetProperty(VcalmParameterNames.VerifiablePresentationRequest, out _),
            "§3.7.6: the vcapi entry initiates a §3.6 exchange that answers with a verifiablePresentationRequest.");
    }


    //Resolves the §3.7.4 protocols map for the §3.7.6 wiring test: the vcapi URL is the created
    //exchange's §3.6.5 participate URL, composed through the host's endpoint-URI resolver (the engine
    //stamps the exchange id on context so the resolver incorporates it).
    private static async ValueTask<VcalmInteractionProtocols?> ResolveProtocolsToExchangeAsync(
        TestHostShell app, ClientRecord coordinator, string exchangeId, ExchangeContext context, CancellationToken cancellationToken)
    {
        context.SetVcalmExchangeId(exchangeId);

        Uri? participateUri = await app.Server.Integration.ResolveEndpointUriAsync!(
            WellKnownVcalmEndpointNames.VcalmParticipateInExchange, coordinator, context, cancellationToken)
            .ConfigureAwait(false);

        return new VcalmInteractionProtocols
        {
            VcapiUrl = participateUri?.OriginalString
                ?? throw new InvalidOperationException("The participate URL was not composed.")
        };
    }


    private string RegisterCoordinator(TestHostShell app)
    {
        VerifierKeyMaterial material = app.RegisterClient(ClientId, ClientBaseUri, CoordinatorCapabilities);
        RegisteredMaterials.Add(material);

        app.Server.Vcalm().UseDefaultVcalmJsonParsing(JsonOptions);

        return material.Registration.TenantId.Value;
    }


    private ClientRecord RegisterCoordinatorAndExchange(TestHostShell app)
    {
        VerifierKeyMaterial material = app.RegisterClient(ClientId, ClientBaseUri, CoordinatorAndExchangeCapabilities);
        RegisteredMaterials.Add(material);

        app.Server.Vcalm().UseDefaultVcalmJsonParsing(JsonOptions);

        //Wire the §3.6 exchange seams so the vcapi URL the §3.7.4 map advertises addresses a real
        //participate endpoint (the §3.7.6 destination). The exchange-id -> flow-id resolver scans the
        //host's flow store; the step seam requests a DID Authentication presentation on the empty
        //initiating message.
        app.Server.Vcalm().ResolveVcalmExchangeFlowIdAsync = (exchangeId, _, _) =>
            ValueTask.FromResult(ResolveExchangeFlowId(app, exchangeId));

        app.Server.Vcalm().ResolveVcalmExchangeStepAsync = (exchangeId, message, _, _) =>
            ValueTask.FromResult(
                VcalmExchangeStepDecision.RequestPresentation("did-auth", DidAuthQueryJson, domain: "coordinator.verifier.test"));

        return material.Registration;
    }


    //Scans the host's flow store for the exchange flow state carrying the given exchange id.
    private static string? ResolveExchangeFlowId(TestHostShell app, string exchangeId)
    {
        foreach(KeyValuePair<string, (FlowState State, int StepCount)> entry in app.FlowStore)
        {
            string? stateExchangeId = entry.Value.State switch
            {
                VcalmExchangePendingState pending => pending.ExchangeId,
                VcalmExchangeActiveState active => active.ExchangeId,
                VcalmExchangeCompleteState complete => complete.ExchangeId,
                VcalmExchangeInvalidState invalid => invalid.ExchangeId,
                _ => null
            };

            if(string.Equals(stateExchangeId, exchangeId, StringComparison.Ordinal))
            {
                return entry.Key;
            }
        }

        return null;
    }


    private async Task<string> CreateExchangeAndGetIdAsync(TestHostShell app, string segment)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateExchange, "POST",
            new RequestFields(), "{}", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode, response.Body);

        using JsonDocument created = JsonDocument.Parse(response.Body);

        return created.RootElement.GetProperty(VcalmParameterNames.Id).GetString()!;
    }
}
