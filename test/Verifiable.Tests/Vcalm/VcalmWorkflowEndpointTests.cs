using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Server;
using Verifiable.Vcalm;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.OAuth;

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
    private static readonly Uri ClientBaseUri = new("https://workflow.client.test");

    private static readonly ImmutableHashSet<CapabilityIdentifier> AdministrationCapabilities =
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
        string segment = RegisterAdministration(app);

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
        string segment = RegisterAdministration(app);

        string workflowId = await CreateWorkflowAndGetIdAsync(app, segment, ValidTwoStepWorkflow).ConfigureAwait(false);

        ServerHttpResponse response = await app.DispatchVcalmWorkflowByIdAsync(
            segment, workflowId, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

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
        string segment = RegisterAdministration(app);

        ServerHttpResponse response = await app.DispatchVcalmWorkflowByIdAsync(
            segment, "urn:uuid:never-created", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

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
        string segment = RegisterAdministration(app);

        //The single step names a nextStep that does not exist — the §3.6.1 "final step MUST NOT carry
        //nextStep" violation manifested as a dangling reference.
        const string invalid =
            "{\"initialStep\":\"only\",\"steps\":{\"only\":{\"nextStep\":\"does-not-exist\"}}}";

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateWorkflow, "POST",
            new RequestFields(), invalid, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

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
        string segment = RegisterAdministration(app);

        const string invalid =
            "{\"initialStep\":\"missing\",\"steps\":{\"present\":{}}}";

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateWorkflow, "POST",
            new RequestFields(), invalid, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

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
        string segment = RegisterAdministration(app);

        const string cyclic =
            "{\"initialStep\":\"a\",\"steps\":{" +
                "\"a\":{\"nextStep\":\"b\"}," +
                "\"b\":{\"nextStep\":\"a\"}" +
            "}}";

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateWorkflow, "POST",
            new RequestFields(), cyclic, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "§3.6.1: a nextStep cycle has no final step and is invalid input.");
    }


    //Registers a tenant with the VcalmAdministration capability and wires the workflow store seams.
    private string RegisterAdministration(TestHostShell app)
    {
        VerifierKeyMaterial material = app.RegisterClient(ClientId, ClientBaseUri, AdministrationCapabilities);
        RegisteredMaterials.Add(material);

        app.Server.Vcalm().UseDefaultVcalmJsonParsing(JsonOptions);

        Dictionary<string, VcalmWorkflowConfiguration> workflowStore = new(StringComparer.Ordinal);
        app.Server.Vcalm().StoreVcalmWorkflowAsync = (workflowId, configuration, _, _) =>
        {
            workflowStore[workflowId] = configuration;

            return ValueTask.CompletedTask;
        };

        app.Server.Vcalm().LoadVcalmWorkflowAsync = (workflowId, _, _) =>
            ValueTask.FromResult(workflowStore.GetValueOrDefault(workflowId));

        return material.Registration.TenantId.Value;
    }


    private async Task<ServerHttpResponse> CreateWorkflowAsync(TestHostShell app, string segment, string body) =>
        await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateWorkflow, "POST",
            new RequestFields(), body, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);


    private async Task<string> CreateWorkflowAndGetIdAsync(TestHostShell app, string segment, string body)
    {
        ServerHttpResponse response = await CreateWorkflowAsync(app, segment, body).ConfigureAwait(false);
        Assert.AreEqual(201, response.StatusCode, response.Body);
        using JsonDocument created = JsonDocument.Parse(response.Body);

        return created.RootElement.GetProperty(VcalmParameterNames.Id).GetString()!;
    }
}
