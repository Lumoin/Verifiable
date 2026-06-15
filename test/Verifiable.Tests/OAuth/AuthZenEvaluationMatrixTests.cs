using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthZen;
using Verifiable.OAuth.Server;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Data-driven conformance check for the OpenID AuthZEN Authorization API 1.0
/// Access Evaluation API (<c>POST /access/v1/evaluation</c>). A table of cases
/// — each a typed <see cref="AccessEvaluationRequest"/> plus the expected
/// decision — is driven through the real in-process HTTP PDP, parsed by the
/// shipped default parser (<see cref="AuthZenJsonExtensions.UseDefaultAuthZenJsonParsing"/>),
/// and asserted against the wire <c>decision</c> the endpoint returns.
/// </summary>
/// <remarks>
/// The scenario is ours, expressed in our own information model and wire-name
/// constants (<see cref="AuthZenFieldNames"/>) — no third-party vectors. The
/// PDP rule is a single explicit <see cref="EvaluateAccessDelegate"/> (role-
/// based: anyone may <c>read</c>; only editors may mutate); the case table is
/// the independent oracle (hand-authored expected values), so a regression in
/// the wire path, the parser, or the policy surfaces as a mismatch.
/// </remarks>
[TestClass]
internal sealed class AuthZenEvaluationMatrixTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private const string ClientId = "https://pdp.example.com";

    private const string Alice = "alice@example.com";
    private const string Bob = "bob@example.com";
    private const string Carol = "carol@example.com";

    //The policy's editor set: editors may perform any action; everyone may read.
    private static readonly ImmutableHashSet<string> Editors = [Alice, Bob];

    //The Policy Decision Point as a single delegate — the same rule the oracle
    //table below was authored against.
    private static readonly EvaluateAccessDelegate Policy = (request, _, _, _) =>
    {
        bool permit = string.Equals(request.Action.Name, "read", StringComparison.Ordinal)
            || Editors.Contains(request.Subject.Id);

        return ValueTask.FromResult(permit ? AccessEvaluationDecision.Permit : AccessEvaluationDecision.Deny);
    };

    //The oracle: the full subject x action matrix with hand-authored expected
    //decisions. Built from our typed model, not raw JSON or foreign vectors.
    private static readonly EvaluationCase[] Cases =
    [
        new("editor alice read",   Request(Alice, "read"),   Expected: true),
        new("editor alice create", Request(Alice, "create"), Expected: true),
        new("editor alice update", Request(Alice, "update"), Expected: true),
        new("editor alice delete", Request(Alice, "delete"), Expected: true),

        new("editor bob read",     Request(Bob, "read"),     Expected: true),
        new("editor bob create",   Request(Bob, "create"),   Expected: true),
        new("editor bob update",   Request(Bob, "update"),   Expected: true),
        new("editor bob delete",   Request(Bob, "delete"),   Expected: true),

        new("viewer carol read",   Request(Carol, "read"),   Expected: true),
        new("viewer carol create", Request(Carol, "create"), Expected: false),
        new("viewer carol update", Request(Carol, "update"), Expected: false),
        new("viewer carol delete", Request(Carol, "delete"), Expected: false),
    ];


    [TestMethod]
    public async Task EvaluationDecisionsMatchTheRoleMatrix()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = app.RegisterClient(
            ClientId,
            new Uri(ClientId),
            ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi));

        app.Server.OAuth().UseDefaultAuthZenJsonParsing();
        app.Server.OAuth().EvaluateAccessAsync = Policy;

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;
        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/access/v1/evaluation");

        foreach(EvaluationCase testCase in Cases)
        {
            using System.Net.Http.StringContent content = new(
                ToRequestJson(testCase.Request), Encoding.UTF8, WellKnownMediaTypes.Application.Json);
            using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
                .PostAsync(url, content, TestContext.CancellationToken).ConfigureAwait(false);

            string responseBody = await response.Content
                .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(200, (int)response.StatusCode,
                $"[{testCase.Name}] must return 200. Body: {responseBody}");
            Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.Content.Headers.ContentType?.MediaType,
                $"[{testCase.Name}] response is application/json.");

            using JsonDocument doc = JsonDocument.Parse(responseBody);
            bool decision = doc.RootElement.TryGetProperty(AuthZenFieldNames.Decision, out JsonElement value)
                && value.GetBoolean();

            Assert.AreEqual(testCase.Expected, decision,
                $"[{testCase.Name}] decision mismatch. Body: {responseBody}");
        }

        Assert.HasCount(12, Cases, "The full subject x action matrix is exercised.");
    }


    private static AccessEvaluationRequest Request(string subjectId, string action) =>
        new()
        {
            Subject = new AuthZenSubject { Type = "user", Id = subjectId },
            Action = new AuthZenAction { Name = action },
            Resource = new AuthZenResource { Type = "todo", Id = "todo-1" },
        };


    //Serialise a typed request to its wire JSON using our own wire-name
    //constants (AuthZenFieldNames) so the body goes through the real default
    //parser on the way in — no hand-shaped JSON literals.
    private static string ToRequestJson(AccessEvaluationRequest request)
    {
        JsonObject root = new()
        {
            [AuthZenFieldNames.Subject] = new JsonObject
            {
                [AuthZenFieldNames.Type] = request.Subject.Type,
                [AuthZenFieldNames.Id] = request.Subject.Id,
            },
            [AuthZenFieldNames.Action] = new JsonObject
            {
                [AuthZenFieldNames.Name] = request.Action.Name,
            },
            [AuthZenFieldNames.Resource] = new JsonObject
            {
                [AuthZenFieldNames.Type] = request.Resource.Type,
                [AuthZenFieldNames.Id] = request.Resource.Id,
            },
        };

        return root.ToJsonString();
    }


    private sealed record EvaluationCase(string Name, AccessEvaluationRequest Request, bool Expected);
}
