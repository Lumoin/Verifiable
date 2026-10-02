using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.Server;
using Verifiable.Tests.OAuth;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Vcalm;
using Verifiable.Vcalm.Exchange;

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

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://coordinator.client.test";
    private static Uri ClientBaseUri { get; } = new("https://coordinator.client.test");

    private static ImmutableHashSet<CapabilityIdentifier> CoordinatorCapabilities { get; } =
        ImmutableHashSet.Create(WellKnownVcalmCapabilities.VcalmCoordinator);

    //The §3.7.6 test co-hosts the coordinator role with the §3.6 exchange role so the vcapi URL the
    //§3.7.4 map advertises addresses a real exchange the same host can participate in.
    private static ImmutableHashSet<CapabilityIdentifier> CoordinatorAndExchangeCapabilities { get; } =
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


    // §3.7.1 Interaction URL Format

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


    // §3.7.2 Interaction QR Code Format (bounds enforcement)

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


    // §3.7.3 Interaction Scheme Format

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


    // §3.7.4 Interaction Protocols Response (content-negotiated)

    /// <summary>
    /// §3.7.4: GET the interaction URL with <c>Accept: application/json</c> MUST return a
    /// <c>{protocols:{…}}</c> map carrying the expected protocol keys.
    /// </summary>
    [TestMethod]
    public async Task GetInteractionProtocolsWithJsonAcceptReturnsProtocolsMap()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterCoordinatorAsync(app).ConfigureAwait(false);

        const string interactionId = "z8n38Dp7a";
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmInteractionProtocolsAsync = (id, _, _) =>
                ValueTask.FromResult<VcalmInteractionProtocols?>(
                    string.Equals(id, interactionId, StringComparison.Ordinal)
                        ? new VcalmInteractionProtocols
                        {
                            InviteRequestUrl = "https://saas.example/interactions/123/invite-request/response",
                            VcapiUrl = "https://saas.example/workflows/123/exchanges/987"
                        }

                        : null);
        }).ConfigureAwait(false);

        ServerHttpResponse response = await app.DispatchVcalmInteractionProtocolsAsync(
            segment, interactionId, WellKnownMediaTypes.Application.Json,
            [], TestContext.CancellationToken).ConfigureAwait(false);

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
        string segment = await RegisterCoordinatorAsync(app).ConfigureAwait(false);

        const string interactionId = "z8n38Dp7a";
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmInteractionProtocolsAsync = (id, _, _) =>
                ValueTask.FromResult<VcalmInteractionProtocols?>(new VcalmInteractionProtocols
                {
                    InviteRequestUrl = "https://saas.example/interactions/123/invite-request/response"
                });
        }).ConfigureAwait(false);

        ServerHttpResponse response = await app.DispatchVcalmInteractionProtocolsAsync(
            segment, interactionId, "text/html", [], TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(WellKnownMediaTypes.Text.Html, response.ContentType,
            "§3.7.4: an unrecognized Accept MUST return a text/html document.");
        Assert.IsTrue(response.Body.Contains("<html", StringComparison.OrdinalIgnoreCase),
            "§3.7.4: the text/html body is an HTML document directing a human to suitable software.");
        Assert.IsFalse(response.Body.TrimStart().StartsWith('{', StringComparison.Ordinal),
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
        string segment = await RegisterCoordinatorAsync(app).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmInteractionProtocolsAsync = (id, _, _) =>
                ValueTask.FromResult<VcalmInteractionProtocols?>(new VcalmInteractionProtocols
                {
                    VcapiUrl = "https://saas.example/workflows/123/exchanges/987"
                });
        }).ConfigureAwait(false);

        ServerHttpResponse response = await app.DispatchVcalmInteractionProtocolsAsync(
            segment, "z8n38Dp7a", acceptHeader: null, [], TestContext.CancellationToken)
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
        string segment = await RegisterCoordinatorAsync(app).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmInteractionProtocolsAsync = (id, _, _) =>
                ValueTask.FromResult<VcalmInteractionProtocols?>(null);
        }).ConfigureAwait(false);

        ServerHttpResponse response = await app.DispatchVcalmInteractionProtocolsAsync(
            segment, "never-created", WellKnownMediaTypes.Application.Json,
            [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode, "§3.7.4: an unknown interaction id is 404.");
    }


    // §3.7.5 inviteRequest Interaction Protocol

    /// <summary>
    /// §3.7.5: a well-formed inviteRequest POST is accepted (200) and recorded under the invite id.
    /// </summary>
    [TestMethod]
    public async Task PostInviteRequestYields200AndIsStored()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterCoordinatorAsync(app).ConfigureAwait(false);

        Dictionary<string, VcalmInviteRequest> store = new(StringComparer.Ordinal);
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.StoreVcalmInviteRequestAsync = (inviteId, invite, _, _) =>
            {
                store[inviteId] = invite;

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        const string inviteId = "8372974";
        const string body =
            "{\"url\":\"https://website.example/checkout/8372974\",\"purpose\":\"Checkout at ShopCo\","
            + "\"referenceId\":\"417bcaf2-14d9-11f0-99d7-9f094678517b\"}";

        ServerHttpResponse response = await app.DispatchVcalmInviteRequestAsync(
            segment, inviteId, body, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.IsTrue(store.TryGetValue(inviteId, out VcalmInviteRequest? stored),
            "§3.7.5: the accepted invitation is recorded under the invite id.");
        Assert.AreEqual("https://website.example/checkout/8372974", stored.Url,
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
        string segment = await RegisterCoordinatorAsync(app).ConfigureAwait(false);

        ServerHttpResponse response = await app.DispatchVcalmInviteRequestAsync(
            segment, "8372974", "\"not-an-object\"", [], TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "§3.7.5 / §2.4: a malformed inviteRequest body is rejected with 400.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-4.2.1">RFC 9457 Section 4.2.1</see>: "When
    /// "about:blank" is used, the title SHOULD be the same as the recommended HTTP status phrase for that code (e.g.,
    /// "Not Found" for 404, and so on), although it MAY be localized to suit client preferences (expressed with the
    /// Accept-Language request header)." An inviteRequest body one byte over the configured payload cap is answered
    /// 413 with the type <c>about:blank</c> titled <c>Content Too Large</c>, the phrase
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.5.14">RFC 9110 Section 15.5.14</see> gives 413.
    /// </summary>
    [TestMethod]
    public async Task ABodyOverTheCapIsAboutBlankContentTooLarge()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterCoordinatorAsync(app).ConfigureAwait(false);

        (int statusCode, string body) = await VcalmWireFixtures.PostOneByteOverCapWireAsync(
            app, ComposeInviteRequestPath(segment), authorizationHeader: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(413, statusCode, body);
        using JsonDocument problem = JsonDocument.Parse(body);
        Assert.AreEqual("about:blank", problem.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(), body);
        Assert.AreEqual("Content Too Large", problem.RootElement.GetProperty(VcalmParameterNames.ProblemTitle).GetString(), body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-2">RFC 8259 Section 2</see>: "A JSON text is a
    /// serialized value." with the grammar <c>JSON-text = ws value ws</c>. The body <c>{</c> opens an object it never
    /// closes, so it holds no value and is no JSON text: the inviteRequest operation answers it with HTTP 400 and the
    /// type the <see href="https://www.w3.org/TR/vc-data-model-2.0/#PARSING_ERROR">VC Data Model 2.0 Section 7.2</see>
    /// defines as "There was an error while parsing input."
    /// </summary>
    [TestMethod]
    public async Task BodyThatIsNotAJsonTextAnswersParsingError()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterCoordinatorAsync(app).ConfigureAwait(false);

        await VcalmWireFixtures.AssertPostAnswersParsingErrorWireAsync(
            app, ComposeInviteRequestPath(segment), "{"u8.ToArray(),
            authorizationHeader: null, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-2">RFC 8259 Section 2</see>: "A JSON text is a
    /// serialized value." with the grammar <c>JSON-text = ws value ws</c>. An empty body labelled
    /// <c>application/json</c> holds no value, so it is no JSON text: the inviteRequest operation answers it with HTTP
    /// 400 and the type the
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#PARSING_ERROR">VC Data Model 2.0 Section 7.2</see> defines as
    /// "There was an error while parsing input."
    /// </summary>
    [TestMethod]
    public async Task EmptyBodyAnswersParsingError()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterCoordinatorAsync(app).ConfigureAwait(false);

        await VcalmWireFixtures.AssertPostAnswersParsingErrorWireAsync(
            app, ComposeInviteRequestPath(segment), [],
            authorizationHeader: null, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259 Section 8.1</see>: "JSON text exchanged
    /// between systems that are not part of a closed ecosystem MUST be encoded using UTF-8 [RFC3629]." The bytes
    /// <c>C3 28</c>, a lead byte followed by a byte that cannot continue it, are not UTF-8, so the body is no JSON text
    /// this endpoint receives: the inviteRequest operation answers it with HTTP 400 and the type the
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#PARSING_ERROR">VC Data Model 2.0 Section 7.2</see> defines as
    /// "There was an error while parsing input."
    /// </summary>
    [TestMethod]
    public async Task BodyThatIsNotUtf8AnswersParsingError()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterCoordinatorAsync(app).ConfigureAwait(false);

        await VcalmWireFixtures.AssertPostAnswersParsingErrorWireAsync(
            app, ComposeInviteRequestPath(segment), [0xC3, 0x28],
            authorizationHeader: null, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#MALFORMED_VALUE_ERROR">VC Data Model 2.0 Section 7.2</see>:
    /// "The value associated with a particular property is malformed." The body <c>{"url":7}</c> is a JSON text whose
    /// <c>url</c> is a number where
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#inviterequest-interaction-protocol">VCALM Section 3.7.5</see> names
    /// a URL string, so the inviteRequest operation answers it with HTTP 400 and that malformed-value type.
    /// </summary>
    [TestMethod]
    public async Task UrlOfTheWrongKindAnswersMalformedValueError()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterCoordinatorAsync(app).ConfigureAwait(false);

        await VcalmWireFixtures.AssertPostAnswersMalformedValueErrorWireAsync(
            app, ComposeInviteRequestPath(segment), "{\"url\":7}",
            authorizationHeader: null, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM Section 2.4</see>: "Implementations MUST throw an
    /// error if an endpoint receives data, options, or option values that it does not understand or know how to
    /// process." The application's parse delegate answers an inviteRequest whose <c>url</c> and <c>purpose</c> are
    /// valid but whose <see cref="VcalmInviteRequest.Failure"/> is a value outside the reasons
    /// <see cref="VcalmParseFailure"/> names: the inviteRequest operation answers HTTP 400 with the type the
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#MALFORMED_VALUE_ERROR">VC Data Model 2.0 Section 7.2</see>
    /// defines as "The value associated with a particular property is malformed.", and records no invitation.
    /// </summary>
    [TestMethod]
    public async Task UnnamedParseFailureOfAnInviteRequestAnswersMalformedValueError()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterCoordinatorAsync(app).ConfigureAwait(false);
        ConcurrentDictionary<string, VcalmInviteRequest> store = new(StringComparer.Ordinal);
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.StoreVcalmInviteRequestAsync = (inviteId, invite, _, _) =>
            {
                store[inviteId] = invite;

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            ParseVcalmInviteRequestDelegate parse = candidateIntegration.ParseVcalmInviteRequestAsync!;
            candidateIntegration.ParseVcalmInviteRequestAsync = async (requestBody, context, cancellationToken) =>
                (await parse(requestBody, context, cancellationToken).ConfigureAwait(false))! with { Failure = VcalmWireFixtures.UnnamedParseFailure };
        }).ConfigureAwait(false);

        await VcalmWireFixtures.AssertPostAnswersMalformedValueErrorWireAsync(
            app, ComposeInviteRequestPath(segment),
            "{\"url\":\"https://website.example/checkout/8372974\",\"purpose\":\"Checkout at ShopCo\"}",
            authorizationHeader: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(store, "A request the endpoint does not understand records no invitation.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.2">RFC 8259 Section 8.2</see>: "However, the ABNF in
    /// this specification allows member names and string values to contain bit sequences that cannot encode Unicode
    /// characters; for example, "\uDEAD" (a single unpaired UTF-16 surrogate)." The body is a JSON text whose
    /// <c>url</c> is the escape <c>\ud800</c>, a value that spells no Unicode string, so it is data
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM Section 2.4</see> requires the operation to refuse:
    /// the inviteRequest operation answers HTTP 400 with the type the
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#MALFORMED_VALUE_ERROR">VC Data Model 2.0 Section 7.2</see>
    /// defines as "The value associated with a particular property is malformed.", and the host records no fault.
    /// </summary>
    [TestMethod]
    public async Task UnpairedSurrogateEscapeAnswersMalformedValueError()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterCoordinatorAsync(app).ConfigureAwait(false);

        await VcalmWireFixtures.AssertPostAnswersMalformedValueErrorWireAsync(
            app, ComposeInviteRequestPath(segment), "{\"url\":\"\\ud800\"}",
            authorizationHeader: null, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#content-serialization">VCALM Content Serialization</see>: "All entity
    /// bodies in requests and responses sent to or received from the API endpoints defined by this specification MUST be
    /// serialized as JSON and include the Content-Type header with a media type value of application/json." The
    /// inviteRequest operation answers the body <c>{}</c> labelled <c>text/plain</c> or carrying no Content-Type header
    /// with HTTP 400 and the MALFORMED_VALUE_ERROR type, and answers zero bytes, whether labelled <c>text/plain</c> or
    /// carrying no Content-Type header, with HTTP 400 and the PARSING_ERROR type, since
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-2">RFC 8259 Section 2</see> says "A JSON text is a
    /// serialized value." and zero bytes hold none.
    /// </summary>
    /// <param name="body">The request body text; the empty string sends zero bytes.</param>
    /// <param name="mediaType">The media type the body is labelled with, or <see langword="null"/> to send no Content-Type header.</param>
    /// <param name="expectedTitle">The literal problem title the answer carries.</param>
    [TestMethod]
    [DataRow("{}", "text/plain", "MALFORMED_VALUE_ERROR", DisplayName = "{} as text/plain")]
    [DataRow("{}", null, "MALFORMED_VALUE_ERROR", DisplayName = "{} with no Content-Type header")]
    [DataRow("", null, "PARSING_ERROR", DisplayName = "zero bytes with no Content-Type header")]
    [DataRow("", "text/plain", "PARSING_ERROR", DisplayName = "zero bytes as text/plain")]
    public async Task BodyAtTheRequestBoundaryKeepsItsAnswer(string body, string? mediaType, string expectedTitle)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterCoordinatorAsync(app).ConfigureAwait(false);

        await VcalmWireFixtures.AssertBoundaryAnswerWireAsync(
            app, ComposeInviteRequestPath(segment), body, mediaType, expectedTitle,
            authorizationHeader: null, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// The absolute path of the inviteRequest endpoint of the tenant <paramref name="segment"/>, which holds the VCALM
    /// coordinator capability, for the invite id <c>8372974</c> the inviteRequest example uses.
    /// </summary>
    /// <param name="segment">The tenant segment.</param>
    /// <returns>The endpoint's path on the host.</returns>
    private static string ComposeInviteRequestPath(string segment) =>
        TestHostShell.ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmInviteRequest, segment) + "/8372974/invite-request/response";


    /// <summary>
    /// §3.7.5: an inviteRequest body missing the REQUIRED <c>url</c> member is rejected with HTTP 400.
    /// </summary>
    [TestMethod]
    public async Task PostInviteRequestWithoutUrlYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterCoordinatorAsync(app).ConfigureAwait(false);

        ServerHttpResponse response = await app.DispatchVcalmInviteRequestAsync(
            segment, "8372974", "{\"purpose\":\"Checkout\"}", [], TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "§3.7.5: an inviteRequest without the url member is rejected with 400.");
    }


    // §3.7.6 vcapi Interaction Protocol (wired to a §3.6 exchange)

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
        ClientRecord coordinator = await RegisterCoordinatorAndExchangeAsync(app).ConfigureAwait(false);
        string segment = coordinator.TenantId.Value;

        //Create a real §3.6 exchange on the same host.
        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //§3.7.4: the coordinator advertises this interaction's vcapi protocol as the §3.6.5 participate
        //URL of the created exchange (the §3.7.6 "initiate a specific exchange" wiring).
        await app.Server.RequestAlterationAsync(candidate =>
            candidate.Family<VcalmIntegration>().ResolveVcalmInteractionProtocolsAsync = (interactionId, ctx, ct) =>
                ResolveProtocolsToExchangeAsync(app, coordinator, exchangeId, ctx, ct), TestContext.CancellationToken).ConfigureAwait(false);

        //Fetch the §3.7.4 protocols map and read the vcapi URL.
        ServerHttpResponse protocolsResponse = await app.DispatchVcalmInteractionProtocolsAsync(
            segment, "interaction-1", WellKnownMediaTypes.Application.Json,
            [], TestContext.CancellationToken).ConfigureAwait(false);
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
            segment, "POST", exchangeId, "{}", [], TestContext.CancellationToken)
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


    /// <summary>
    /// Registers the interaction service with its protocol-discovery and invitation delegates.
    /// </summary>
    private async Task<string> RegisterCoordinatorAsync(TestHostShell app)
    {
        VerifierKeyMaterial material = await app.RegisterClientAsync(ClientId, ClientBaseUri, CoordinatorCapabilities).ConfigureAwait(false);
        RegisteredMaterials.Add(material);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultVcalmJsonParsing(JsonOptions);
        }).ConfigureAwait(false);

        return material.Registration.TenantId.Value;
    }


    /// <summary>
    /// Registers the interaction and exchange capabilities together with their request delegates.
    /// </summary>
    private async Task<ClientRecord> RegisterCoordinatorAndExchangeAsync(TestHostShell app)
    {
        VerifierKeyMaterial material = await app.RegisterClientAsync(ClientId, ClientBaseUri, CoordinatorAndExchangeCapabilities).ConfigureAwait(false);
        RegisteredMaterials.Add(material);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultVcalmJsonParsing(JsonOptions);
        }).ConfigureAwait(false);

        //Wire the §3.6 exchange seams so the vcapi URL the §3.7.4 map advertises addresses a real
        //participate endpoint (the §3.7.6 destination). The exchange-id -> flow-id resolver scans the
        //host's flow store; the step seam requests a DID Authentication presentation on the empty
        //initiating message.
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmExchangeFlowIdAsync = (exchangeId, _, _) =>
                ValueTask.FromResult(ResolveExchangeFlowId(app, exchangeId));
        }).ConfigureAwait(false);

        //§3.6.3 / §3.6.6 REQUIRED seam: the coordinator authorization the create-exchange and
        //state-read routes need to materialize at all.
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.AuthorizeVcalmCoordinatorAsync = VcalmWireFixtures.AuthorizeTestCoordinator;
        }).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmExchangeStepAsync = (exchangeId, message, _, _) =>
                ValueTask.FromResult(
                    VcalmExchangeStepDecision.RequestPresentation("did-auth", DidAuthQueryJson, domain: "coordinator.verifier.test"));
        }).ConfigureAwait(false);

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
            new RequestFields(), VcalmWireFixtures.CoordinatorAuthorizationHeaders, "{}",
            [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode, response.Body);

        using JsonDocument created = JsonDocument.Parse(response.Body);

        return created.RootElement.GetProperty(VcalmParameterNames.Id).GetString()!;
    }
}
