using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.Json;
using Verifiable.Tests.OAuth;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Vcalm;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// Conformance tests for the W3C VCALM 1.0 §3.6.1 create-workflow and §3.6.2 get-workflow-configuration
/// administration interfaces (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API
/// for Lifecycle Management</see>) exposed by <see cref="VcalmWorkflowEndpoints"/>, driven through the
/// real dispatch pipeline.
/// </summary>
/// <remarks>
/// §3.6.1: <c>POST /workflows</c> accepts the admin-authored step graph (initialStep REQUIRED, steps
/// REQUIRED, credentialTemplates / authorization OPTIONAL) and validates the step-graph structural MUSTs
/// (initialStep names a defined step; a nextStep names a defined step; the final step carries no
/// nextStep). §3.6.2: <c>GET /workflows/{id}</c> returns the stored configuration; an unknown id is 404.
/// </remarks>
[TestClass]
internal sealed class VcalmWorkflowEndpointTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://workflow.client.test";
    private static Uri ClientBaseUri { get; } = new("https://workflow.client.test");

    private static ImmutableHashSet<CapabilityIdentifier> AdministrationCapabilities { get; } =
        ImmutableHashSet.Create(WellKnownVcalmCapabilities.VcalmAdministration);

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    //A minimal, well-formed two-step workflow: a DID-auth presentation step that advances to a
    //credential-delivery step. The final (issue) step carries NO nextStep, as §3.6.1 requires.
    private const string ValidTwoStepWorkflow =
        "{" +
            "\"initialStep\":\"didAuth\"," +
            "\"steps\":{" +
                "\"didAuth\":{" +
                    "\"createChallenge\":true," +
                    "\"verifiablePresentationRequest\":{\"query\":[{\"type\":\"DIDAuthentication\"}]}," +
                    "\"nextStep\":\"deliver\"" +
                "}," +
                "\"deliver\":{" +
                    "\"issueRequests\":[{\"credentialTemplateId\":\"urn:tmpl-1\"}]" +
                "}" +
            "}," +
            "\"credentialTemplates\":[{\"id\":\"urn:tmpl-1\",\"type\":\"jsonata\",\"template\":\"{}\"}]," +
            "\"authorization\":{\"oauth2\":{\"issuerConfigUrl\":\"https://issuer.test/.well-known/oauth-authorization-server\"}}" +
        "}";


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


    /// <summary>
    /// §3.6.1 create: POST /workflows with a valid two-step config → HTTP 201 carrying the workflow id
    /// and the echoed initialStep.
    /// </summary>
    [TestMethod]
    public async Task CreateWorkflowYields201WithId()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterAdministrationAsync(app).ConfigureAwait(false);

        ServerHttpResponse response = await CreateWorkflowAsync(app, segment, ValidTwoStepWorkflow).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode, response.Body);
        using JsonDocument created = JsonDocument.Parse(response.Body);
        Assert.IsTrue(created.RootElement.TryGetProperty(VcalmParameterNames.Id, out JsonElement idElement),
            "§3.6.1 201 carries the workflow id.");
        Assert.IsFalse(string.IsNullOrEmpty(idElement.GetString()), "The workflow id is non-empty.");
        Assert.AreEqual("didAuth", created.RootElement.GetProperty(VcalmParameterNames.InitialStep).GetString(),
            "§3.6.1: the response echoes the initialStep.");
    }


    /// <summary>
    /// §3.6.2 get: a created workflow is retrievable by id → HTTP 200 carrying its configuration (the
    /// step graph, the credential templates).
    /// </summary>
    [TestMethod]
    public async Task GetWorkflowReturnsStoredConfiguration()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterAdministrationAsync(app).ConfigureAwait(false);

        string workflowId = await CreateWorkflowAndGetIdAsync(app, segment, ValidTwoStepWorkflow).ConfigureAwait(false);

        ServerHttpResponse response = await app.DispatchVcalmWorkflowByIdAsync(
            segment, workflowId, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.AreEqual(workflowId, doc.RootElement.GetProperty(VcalmParameterNames.Id).GetString());
        Assert.AreEqual("didAuth", doc.RootElement.GetProperty(VcalmParameterNames.InitialStep).GetString());

        JsonElement steps = doc.RootElement.GetProperty(VcalmParameterNames.Steps);
        Assert.IsTrue(steps.TryGetProperty("didAuth", out JsonElement didAuthStep),
            "§3.6.2: the stored step graph round-trips.");
        Assert.AreEqual("deliver", didAuthStep.GetProperty(VcalmParameterNames.NextStep).GetString(),
            "§3.6.2: the step's nextStep round-trips.");

        JsonElement templates = doc.RootElement.GetProperty(VcalmParameterNames.CredentialTemplates);
        Assert.AreEqual(1, templates.GetArrayLength(), "§3.6.2: the credentialTemplates round-trip.");
    }


    /// <summary>
    /// §3.6.2 unknown workflow: GET /workflows/{unknown} → HTTP 404.
    /// </summary>
    [TestMethod]
    public async Task GetUnknownWorkflowYields404()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterAdministrationAsync(app).ConfigureAwait(false);

        ServerHttpResponse response = await app.DispatchVcalmWorkflowByIdAsync(
            segment, "urn:uuid:never-created", [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode, "§3.6.2: an unknown workflow id is 404.");
    }


    /// <summary>
    /// §3.6.1 invalid config — the FINAL step carries a nextStep: §3.6.1 "This field MUST NOT be present
    /// on the final step configuration." A nextStep on a terminal step is a dangling reference (no such
    /// step), rejected with HTTP 400.
    /// </summary>
    [TestMethod]
    public async Task CreateWorkflowWithNextStepOnFinalStepYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterAdministrationAsync(app).ConfigureAwait(false);

        //The single step names a nextStep that does not exist — the §3.6.1 "final step MUST NOT carry
        //nextStep" violation manifested as a dangling reference.
        const string invalid =
            "{\"initialStep\":\"only\",\"steps\":{\"only\":{\"nextStep\":\"does-not-exist\"}}}";

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateWorkflow, "POST",
            new RequestFields(), invalid, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "§3.6.1: a final step that carries a nextStep is invalid input.");
    }


    /// <summary>
    /// §3.6.1 invalid config — initialStep names an undefined step → HTTP 400.
    /// </summary>
    [TestMethod]
    public async Task CreateWorkflowWithUndefinedInitialStepYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterAdministrationAsync(app).ConfigureAwait(false);

        const string invalid =
            "{\"initialStep\":\"missing\",\"steps\":{\"present\":{}}}";

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateWorkflow, "POST",
            new RequestFields(), invalid, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "§3.6.1: an initialStep that does not name a defined step is invalid input.");
    }


    /// <summary>
    /// §3.6.1 invalid config — a nextStep CYCLE (stepA → stepB → stepA) has no final step; §3.6.1's
    /// linear chain MUST terminate. Rejected with HTTP 400 at create time (the same defect the
    /// multi-step exchange engine bounds at runtime).
    /// </summary>
    [TestMethod]
    public async Task CreateWorkflowWithStepCycleYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterAdministrationAsync(app).ConfigureAwait(false);

        const string cyclic =
            "{\"initialStep\":\"a\",\"steps\":{" +
                "\"a\":{\"nextStep\":\"b\"}," +
                "\"b\":{\"nextStep\":\"a\"}" +
            "}}";

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateWorkflow, "POST",
            new RequestFields(), cyclic, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "§3.6.1: a nextStep cycle has no final step and is invalid input.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-4.2.1">RFC 9457 Section 4.2.1</see>: "When
    /// "about:blank" is used, the title SHOULD be the same as the recommended HTTP status phrase for that code (e.g.,
    /// "Not Found" for 404, and so on), although it MAY be localized to suit client preferences (expressed with the
    /// Accept-Language request header)." A create-workflow body one byte over the configured payload cap is answered
    /// 413 with the type <c>about:blank</c> titled <c>Content Too Large</c>, the phrase
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.5.14">RFC 9110 Section 15.5.14</see> gives 413.
    /// </summary>
    [TestMethod]
    public async Task ABodyOverTheCapIsAboutBlankContentTooLarge()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterAdministrationAsync(app).ConfigureAwait(false);

        (int statusCode, string body) = await VcalmWireFixtures.PostOneByteOverCapWireAsync(
            app, TestHostShell.ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmCreateWorkflow, segment),
            authorizationHeader: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(413, statusCode, body);
        using JsonDocument problem = JsonDocument.Parse(body);
        Assert.AreEqual("about:blank", problem.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(), body);
        Assert.AreEqual("Content Too Large", problem.RootElement.GetProperty(VcalmParameterNames.ProblemTitle).GetString(), body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-2">RFC 8259 Section 2</see>: "A JSON text is a
    /// serialized value." with the grammar <c>JSON-text = ws value ws</c>. The body <c>{</c> opens an object it never
    /// closes, so it holds no value and is no JSON text: the create-workflow and the exchange step callback operations
    /// each answer it with HTTP 400 and the type the
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#PARSING_ERROR">VC Data Model 2.0 Section 7.2</see> defines as
    /// "There was an error while parsing input."
    /// </summary>
    /// <param name="endpointName">The well-known name of the workflow operation the body is posted to.</param>
    [TestMethod]
    [DataRow("Vcalm.CreateWorkflow")]
    [DataRow("Vcalm.ExchangeStepCallback")]
    public async Task BodyThatIsNotAJsonTextAnswersParsingError(string endpointName)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterAdministrationAsync(app).ConfigureAwait(false);

        await VcalmWireFixtures.AssertPostAnswersParsingErrorWireAsync(
            app, ComposeOperationPath(endpointName, segment), "{"u8.ToArray(),
            authorizationHeader: null, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-2">RFC 8259 Section 2</see>: "A JSON text is a
    /// serialized value." with the grammar <c>JSON-text = ws value ws</c>. An empty body labelled
    /// <c>application/json</c> holds no value, so it is no JSON text: the create-workflow operation answers it with HTTP
    /// 400 and the type the
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#PARSING_ERROR">VC Data Model 2.0 Section 7.2</see> defines as
    /// "There was an error while parsing input."
    /// </summary>
    [TestMethod]
    public async Task EmptyBodyAnswersParsingError()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterAdministrationAsync(app).ConfigureAwait(false);

        await VcalmWireFixtures.AssertPostAnswersParsingErrorWireAsync(
            app, ComposeOperationPath(WellKnownVcalmEndpointNames.VcalmCreateWorkflow, segment), [],
            authorizationHeader: null, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259 Section 8.1</see>: "JSON text exchanged
    /// between systems that are not part of a closed ecosystem MUST be encoded using UTF-8 [RFC3629]." The bytes
    /// <c>C3 28</c>, a lead byte followed by a byte that cannot continue it, are not UTF-8, so the body is no JSON text
    /// this endpoint receives: the create-workflow operation answers it with HTTP 400 and the type the
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#PARSING_ERROR">VC Data Model 2.0 Section 7.2</see> defines as
    /// "There was an error while parsing input."
    /// </summary>
    [TestMethod]
    public async Task BodyThatIsNotUtf8AnswersParsingError()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterAdministrationAsync(app).ConfigureAwait(false);

        await VcalmWireFixtures.AssertPostAnswersParsingErrorWireAsync(
            app, ComposeOperationPath(WellKnownVcalmEndpointNames.VcalmCreateWorkflow, segment), [0xC3, 0x28],
            authorizationHeader: null, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#MALFORMED_VALUE_ERROR">VC Data Model 2.0 Section 7.2</see>:
    /// "The value associated with a particular property is malformed." Each body is a JSON text with one member of a
    /// kind its operation does not take: a number for the <c>initialStep</c> string
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#create-workflow">VCALM Section 3.6.1</see> requires, and a number for
    /// the <c>event</c> object an
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#exchange-step-callbacks">exchange step callback</see> carries; each
    /// operation answers it with HTTP 400 and that malformed-value type.
    /// </summary>
    /// <param name="endpointName">The well-known name of the workflow operation the body is posted to.</param>
    /// <param name="body">The JSON text with the member of the wrong kind.</param>
    [TestMethod]
    [DataRow("Vcalm.CreateWorkflow", "{\"initialStep\":7,\"steps\":{}}")]
    [DataRow("Vcalm.ExchangeStepCallback", "{\"event\":7}")]
    public async Task MemberOfTheWrongKindAnswersMalformedValueError(string endpointName, string body)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterAdministrationAsync(app).ConfigureAwait(false);

        await VcalmWireFixtures.AssertPostAnswersMalformedValueErrorWireAsync(
            app, ComposeOperationPath(endpointName, segment), body,
            authorizationHeader: null, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM Section 2.4</see>: "Implementations MUST throw an
    /// error if an endpoint receives data, options, or option values that it does not understand or know how to
    /// process." The application's parse delegate answers a create-workflow request whose step graph is valid but whose
    /// <see cref="VcalmWorkflowConfiguration.Failure"/> is a value outside the reasons <see cref="VcalmParseFailure"/>
    /// names: the create-workflow operation answers HTTP 400 with the type the
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#MALFORMED_VALUE_ERROR">VC Data Model 2.0 Section 7.2</see>
    /// defines as "The value associated with a particular property is malformed.", and stores no workflow.
    /// </summary>
    [TestMethod]
    public async Task UnnamedParseFailureOfACreateWorkflowRequestAnswersMalformedValueError()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterAdministrationAsync(app).ConfigureAwait(false);
        ConcurrentDictionary<string, VcalmWorkflowConfiguration> stored = new(StringComparer.Ordinal);
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.StoreVcalmWorkflowAsync = (workflowId, configuration, _, _) =>
            {
                stored[workflowId] = configuration;

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            ParseVcalmCreateWorkflowDelegate parse = candidateIntegration.ParseVcalmCreateWorkflowAsync!;
            candidateIntegration.ParseVcalmCreateWorkflowAsync = async (requestBody, context, cancellationToken) =>
                (await parse(requestBody, context, cancellationToken).ConfigureAwait(false))! with { Failure = VcalmWireFixtures.UnnamedParseFailure };
        }).ConfigureAwait(false);

        await VcalmWireFixtures.AssertPostAnswersMalformedValueErrorWireAsync(
            app, ComposeOperationPath(WellKnownVcalmEndpointNames.VcalmCreateWorkflow, segment), ValidTwoStepWorkflow,
            authorizationHeader: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(stored, "A request the endpoint does not understand stores no workflow.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM Section 2.4</see>: "Implementations MUST throw an
    /// error if an endpoint receives data, options, or option values that it does not understand or know how to
    /// process." The application's parse delegate answers an
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#exchange-step-callbacks">exchange step callback</see> whose
    /// <c>exchangeId</c> is valid but whose <see cref="VcalmCallbackRequest.Failure"/> is a value outside the reasons
    /// <see cref="VcalmParseFailure"/> names: the callback operation, which acknowledges a callback it understands with
    /// HTTP 200 and calls no seam of its own, answers HTTP 400 with the type the
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#MALFORMED_VALUE_ERROR">VC Data Model 2.0 Section 7.2</see>
    /// defines as "The value associated with a particular property is malformed."
    /// </summary>
    [TestMethod]
    public async Task UnnamedParseFailureOfACallbackAnswersMalformedValueError()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterAdministrationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            ParseVcalmCallbackDelegate parse = candidateIntegration.ParseVcalmCallbackAsync!;
            candidateIntegration.ParseVcalmCallbackAsync = async (requestBody, context, cancellationToken) =>
                (await parse(requestBody, context, cancellationToken).ConfigureAwait(false))! with { Failure = VcalmWireFixtures.UnnamedParseFailure };
        }).ConfigureAwait(false);

        await VcalmWireFixtures.AssertPostAnswersMalformedValueErrorWireAsync(
            app, ComposeOperationPath(WellKnownVcalmEndpointNames.VcalmExchangeStepCallback, segment),
            "{\"event\":{\"data\":{\"exchangeId\":\"urn:uuid:exchange-1\"}}}",
            authorizationHeader: null, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.2">RFC 8259 Section 8.2</see>: "However, the ABNF in
    /// this specification allows member names and string values to contain bit sequences that cannot encode Unicode
    /// characters; for example, "\uDEAD" (a single unpaired UTF-16 surrogate)." Each body is a JSON text whose string
    /// value is the escape <c>\ud800</c>, a value that spells no Unicode string: the create-workflow body's
    /// <c>initialStep</c> and the exchange step callback's <c>exchangeId</c>. It is data
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM Section 2.4</see> requires the operation to refuse:
    /// each operation answers HTTP 400 with the type the
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#MALFORMED_VALUE_ERROR">VC Data Model 2.0 Section 7.2</see>
    /// defines as "The value associated with a particular property is malformed.", and the host records no fault.
    /// </summary>
    /// <param name="endpointName">The well-known name of the workflow operation the body is posted to.</param>
    /// <param name="body">The JSON text carrying the escape.</param>
    [TestMethod]
    [DataRow("Vcalm.CreateWorkflow", "{\"initialStep\":\"\\ud800\",\"steps\":{}}")]
    [DataRow("Vcalm.ExchangeStepCallback", "{\"event\":{\"data\":{\"exchangeId\":\"\\ud800\"}}}")]
    public async Task UnpairedSurrogateEscapeAnswersMalformedValueError(string endpointName, string body)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterAdministrationAsync(app).ConfigureAwait(false);

        await VcalmWireFixtures.AssertPostAnswersMalformedValueErrorWireAsync(
            app, ComposeOperationPath(endpointName, segment), body,
            authorizationHeader: null, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#content-serialization">VCALM Content Serialization</see>: "All entity
    /// bodies in requests and responses sent to or received from the API endpoints defined by this specification MUST be
    /// serialized as JSON and include the Content-Type header with a media type value of application/json." The
    /// create-workflow operation answers the body <c>{}</c> labelled <c>text/plain</c> or carrying no Content-Type header
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
        string segment = await RegisterAdministrationAsync(app).ConfigureAwait(false);

        await VcalmWireFixtures.AssertBoundaryAnswerWireAsync(
            app, ComposeOperationPath(WellKnownVcalmEndpointNames.VcalmCreateWorkflow, segment), body, mediaType,
            expectedTitle, authorizationHeader: null, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// The absolute path a body-reading operation of the administration tenant <paramref name="segment"/> is posted to:
    /// the create-workflow collection path, or the exchange step callback path of the callback id <c>callback-1</c>.
    /// </summary>
    /// <param name="endpointName">The well-known name of the operation.</param>
    /// <param name="segment">The administration tenant segment.</param>
    /// <returns>The operation's path on the host.</returns>
    private static string ComposeOperationPath(string endpointName, string segment) => endpointName switch
    {
        "Vcalm.ExchangeStepCallback" => TestHostShell.ComposeEndpointPath(endpointName, segment) + "/callback-1",
        _ => TestHostShell.ComposeEndpointPath(endpointName, segment)
    };


    /// <summary>
    /// Registers the workflow administration capability with the configuration and callback delegates.
    /// </summary>
    private async Task<string> RegisterAdministrationAsync(TestHostShell app)
    {
        VerifierKeyMaterial material = await app.RegisterClientAsync(ClientId, ClientBaseUri, AdministrationCapabilities).ConfigureAwait(false);
        RegisteredMaterials.Add(material);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultVcalmJsonParsing(JsonOptions);
        }).ConfigureAwait(false);

        Dictionary<string, VcalmWorkflowConfiguration> workflowStore = new(StringComparer.Ordinal);
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.StoreVcalmWorkflowAsync = (workflowId, configuration, _, _) =>
            {
                workflowStore[workflowId] = configuration;

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.LoadVcalmWorkflowAsync = (workflowId, _, _) =>
                ValueTask.FromResult(workflowStore.GetValueOrDefault(workflowId));
        }).ConfigureAwait(false);

        return material.Registration.TenantId.Value;
    }


    private async Task<ServerHttpResponse> CreateWorkflowAsync(TestHostShell app, string segment, string body) =>
        await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateWorkflow, "POST",
            new RequestFields(), body, [], TestContext.CancellationToken).ConfigureAwait(false);


    private async Task<string> CreateWorkflowAndGetIdAsync(TestHostShell app, string segment, string body)
    {
        ServerHttpResponse response = await CreateWorkflowAsync(app, segment, body).ConfigureAwait(false);
        Assert.AreEqual(201, response.StatusCode, response.Body);
        using JsonDocument created = JsonDocument.Parse(response.Body);

        return created.RootElement.GetProperty(VcalmParameterNames.Id).GetString()!;
    }
}
