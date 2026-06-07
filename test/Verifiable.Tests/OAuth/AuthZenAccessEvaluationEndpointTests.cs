using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthZen;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Metadata;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// End-to-end tests for the OpenID AuthZEN Authorization API 1.0 Access
/// Evaluation endpoint (<c>POST /access/v1/evaluation</c>) exposed by
/// <see cref="AuthZenEndpoints"/>. The library owns the wire — read body,
/// parse via the application's
/// <see cref="AuthorizationServerIntegration.ParseAccessEvaluationRequestAsync"/>,
/// ask the application's Policy Decision Point
/// (<see cref="AuthorizationServerIntegration.EvaluateAccessAsync"/>), and
/// serialise the <c>{ "decision": &lt;bool&gt; }</c> response.
/// </summary>
[TestClass]
internal sealed class AuthZenAccessEvaluationEndpointTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private const string ClientId = "https://pdp.example.com";


    [TestMethod]
    public async Task EvaluationEndpointReturnsPermitWithContext()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = RegisterPdp(app);
        WirePdp(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        //alice can_read account 123 — the wired PDP permits with a reason.
        const string Body = """
            {"subject":{"type":"user","id":"alice@example.com"},
             "resource":{"type":"account","id":"123"},
             "action":{"name":"can_read"},
             "context":{"time":"1985-10-26T01:22:00-07:00"}}
            """;

        using JsonDocument response = await PostAsync(host, segment, Body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsTrue(response.RootElement.GetProperty("decision").GetBoolean(),
            "alice reading her own account must be permitted.");
        Assert.AreEqual("owner",
            response.RootElement.GetProperty("context").GetProperty("reason").GetString(),
            "The PDP's decision context must round-trip in the response.");
    }


    [TestMethod]
    public async Task EvaluationEndpointReturnsDeny()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = RegisterPdp(app);
        WirePdp(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        //A different subject — denied.
        const string Body = """
            {"subject":{"type":"user","id":"mallory@example.com"},
             "resource":{"type":"account","id":"123"},
             "action":{"name":"can_read"}}
            """;

        using JsonDocument response = await PostAsync(host, segment, Body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsFalse(response.RootElement.GetProperty("decision").GetBoolean(),
            "A subject the policy does not permit must be denied.");
        Assert.IsFalse(response.RootElement.TryGetProperty("context", out _),
            "A bare deny carries no context.");
    }


    [TestMethod]
    public async Task EvaluationEndpointRejectsMalformedBody()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = RegisterPdp(app);

        bool pdpInvoked = false;
        app.Server.Integration.UseDefaultAuthZenJsonParsing();
        app.Server.Integration.EvaluateAccessAsync = (request, _, _, _) =>
        {
            pdpInvoked = true;
            return ValueTask.FromResult(AccessEvaluationDecision.Permit);
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/access/v1/evaluation");
        using System.Net.Http.StringContent content = new(
            "{ not valid json", Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .PostAsync(url, content, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "A body that does not parse as an Access Evaluation request yields HTTP 400.");
        Assert.IsFalse(pdpInvoked, "The PDP must not run for a request rejected at parsing.");
    }


    [TestMethod]
    public async Task EvaluationEndpointRejectsBodyMissingRequiredField()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = RegisterPdp(app);

        bool pdpInvoked = false;
        app.Server.Integration.UseDefaultAuthZenJsonParsing();
        app.Server.Integration.EvaluateAccessAsync = (request, _, _, _) =>
        {
            pdpInvoked = true;
            return ValueTask.FromResult(AccessEvaluationDecision.Permit);
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        //Well-formed JSON but missing the required action — the strict default
        //parser rejects it.
        const string Body = """
            {"subject":{"type":"user","id":"alice@example.com"},
             "resource":{"type":"account","id":"123"}}
            """;

        using JsonDocument _ = await PostAsync(host, segment, Body, expectedStatus: 400).ConfigureAwait(false);
        Assert.IsFalse(pdpInvoked, "The PDP must not run for a structurally incomplete request.");
    }


    [TestMethod]
    public async Task ConfigurationEndpointAdvertisesRequiredFields()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = RegisterPdp(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/.well-known/authzen-configuration");
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode,
            $"GET .well-known/authzen-configuration must return 200. Body: {body}");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.Content.Headers.ContentType?.MediaType,
            "The PDP metadata document is application/json.");

        using JsonDocument doc = JsonDocument.Parse(body);
        JsonElement root = doc.RootElement;

        //§9.1 REQUIRED: policy_decision_point is the PDP identifier (a URL).
        Assert.IsTrue(root.TryGetProperty(
                AuthZenMetadataParameterNames.PolicyDecisionPoint, out JsonElement pdpId),
            "policy_decision_point is REQUIRED (§9.1).");
        Assert.IsTrue(Uri.TryCreate(pdpId.GetString(), UriKind.Absolute, out _),
            "policy_decision_point must be an absolute URL.");

        //§9.1 REQUIRED: access_evaluation_endpoint is the URL the matcher binds
        //to — the AbsolutePath of the resolved Access Evaluation endpoint.
        Assert.IsTrue(root.TryGetProperty(
                AuthZenMetadataParameterNames.AccessEvaluationEndpoint, out JsonElement evalEndpoint),
            "access_evaluation_endpoint is REQUIRED (§9.1).");
        Assert.IsTrue(Uri.TryCreate(evalEndpoint.GetString(), UriKind.Absolute, out Uri? evalUri),
            "access_evaluation_endpoint must be an absolute URL.");
        Assert.AreEqual($"/connect/{segment}/access/v1/evaluation", evalUri!.AbsolutePath,
            "The advertised access_evaluation_endpoint must be the URL the endpoint serves.");

        //§9.1 OPTIONAL: the batch endpoint shares the AuthZEN capability, so it
        //is on the chain and advertised at its served path.
        Assert.IsTrue(root.TryGetProperty(
                AuthZenMetadataParameterNames.AccessEvaluationsEndpoint, out JsonElement evalsEndpoint),
            "access_evaluations_endpoint is advertised once the batch endpoint is on the chain.");
        Assert.IsTrue(Uri.TryCreate(evalsEndpoint.GetString(), UriKind.Absolute, out Uri? evalsUri),
            "access_evaluations_endpoint must be an absolute URL.");
        Assert.AreEqual($"/connect/{segment}/access/v1/evaluations", evalsUri!.AbsolutePath,
            "The advertised access_evaluations_endpoint must be the URL the endpoint serves.");

        //The search endpoints (§9.1 OPTIONAL) are not implemented yet, so the
        //document must NOT advertise them — only endpoints active on the chain
        //appear.
        Assert.IsFalse(root.TryGetProperty(AuthZenMetadataParameterNames.SearchSubjectEndpoint, out _),
            "search_subject_endpoint must be absent until the search endpoint lands.");
    }


    [TestMethod]
    public async Task BatchExecuteAllReturnsEveryDecisionInOrder()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = RegisterPdp(app);
        WirePdp(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        //Shared action + resource; per-item subjects. No options → execute_all.
        const string Body = """
            {"action":{"name":"can_read"},
             "resource":{"type":"account","id":"123"},
             "evaluations":[
               {"subject":{"type":"user","id":"alice@example.com"}},
               {"subject":{"type":"user","id":"mallory@example.com"}}]}
            """;

        using JsonDocument response = await PostEvaluationsAsync(host, segment, Body, expectedStatus: 200).ConfigureAwait(false);
        JsonElement root = response.RootElement;

        //§6: with the evaluations array present, the top-level decision is omitted.
        Assert.IsFalse(root.TryGetProperty(AuthZenFieldNames.Decision, out _),
            "The batch response omits the top-level decision key.");

        JsonElement evals = root.GetProperty(AuthZenFieldNames.Evaluations);
        Assert.AreEqual(2, evals.GetArrayLength(), "execute_all evaluates every item.");
        Assert.IsTrue(evals[0].GetProperty("decision").GetBoolean(), "alice can_read is permitted.");
        Assert.AreEqual("owner", evals[0].GetProperty("context").GetProperty("reason").GetString(),
            "Each element carries its own decision context.");
        Assert.IsFalse(evals[1].GetProperty("decision").GetBoolean(), "mallory is denied.");
        Assert.IsFalse(evals[1].TryGetProperty("context", out _), "A bare deny carries no context.");
    }


    [TestMethod]
    public async Task BatchDenyOnFirstDenyStopsAtFirstDeny()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = RegisterPdp(app);
        WirePdp(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        //permit, deny, permit — deny_on_first_deny stops after item[1].
        const string Body = """
            {"action":{"name":"can_read"},
             "resource":{"type":"account","id":"123"},
             "options":{"evaluations_semantic":"deny_on_first_deny"},
             "evaluations":[
               {"subject":{"type":"user","id":"alice@example.com"}},
               {"subject":{"type":"user","id":"mallory@example.com"}},
               {"subject":{"type":"user","id":"alice@example.com"}}]}
            """;

        using JsonDocument response = await PostEvaluationsAsync(host, segment, Body, expectedStatus: 200).ConfigureAwait(false);
        JsonElement evals = response.RootElement.GetProperty(AuthZenFieldNames.Evaluations);

        Assert.AreEqual(2, evals.GetArrayLength(),
            "deny_on_first_deny returns only the items up to and including the first deny.");
        Assert.IsTrue(evals[0].GetProperty("decision").GetBoolean());
        Assert.IsFalse(evals[1].GetProperty("decision").GetBoolean());
    }


    [TestMethod]
    public async Task BatchPermitOnFirstPermitStopsAtFirstPermit()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = RegisterPdp(app);
        WirePdp(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        //deny, permit, deny — permit_on_first_permit stops after item[1].
        const string Body = """
            {"action":{"name":"can_read"},
             "resource":{"type":"account","id":"123"},
             "options":{"evaluations_semantic":"permit_on_first_permit"},
             "evaluations":[
               {"subject":{"type":"user","id":"mallory@example.com"}},
               {"subject":{"type":"user","id":"alice@example.com"}},
               {"subject":{"type":"user","id":"mallory@example.com"}}]}
            """;

        using JsonDocument response = await PostEvaluationsAsync(host, segment, Body, expectedStatus: 200).ConfigureAwait(false);
        JsonElement evals = response.RootElement.GetProperty(AuthZenFieldNames.Evaluations);

        Assert.AreEqual(2, evals.GetArrayLength(),
            "permit_on_first_permit returns only the items up to and including the first permit.");
        Assert.IsFalse(evals[0].GetProperty("decision").GetBoolean());
        Assert.IsTrue(evals[1].GetProperty("decision").GetBoolean());
    }


    [TestMethod]
    public async Task BatchAppliesRequestLevelDefaultsToEachItem()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = RegisterPdp(app);
        WirePdp(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        //Subject + action are request-level defaults; each item overrides only
        //the resource. The PDP decides on subject + action, so both permit.
        const string Body = """
            {"subject":{"type":"user","id":"alice@example.com"},
             "action":{"name":"can_read"},
             "evaluations":[
               {"resource":{"type":"document","id":"doc1.md"}},
               {"resource":{"type":"document","id":"doc2.md"}}]}
            """;

        using JsonDocument response = await PostEvaluationsAsync(host, segment, Body, expectedStatus: 200).ConfigureAwait(false);
        JsonElement evals = response.RootElement.GetProperty(AuthZenFieldNames.Evaluations);

        Assert.AreEqual(2, evals.GetArrayLength());
        Assert.IsTrue(evals[0].GetProperty("decision").GetBoolean(),
            "The default subject/action are inherited, so alice can_read doc1 is permitted.");
        Assert.IsTrue(evals[1].GetProperty("decision").GetBoolean(),
            "The default subject/action are inherited, so alice can_read doc2 is permitted.");
    }


    [TestMethod]
    public async Task BatchRejectsUnknownSemantic()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = RegisterPdp(app);

        bool pdpInvoked = false;
        app.Server.Integration.UseDefaultAuthZenJsonParsing();
        app.Server.Integration.EvaluateAccessAsync = (request, _, _, _) =>
        {
            pdpInvoked = true;
            return ValueTask.FromResult(AccessEvaluationDecision.Permit);
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        //A non-spec semantic is rejected at parse time (strict conformance).
        const string Body = """
            {"action":{"name":"can_read"},
             "resource":{"type":"account","id":"123"},
             "options":{"evaluations_semantic":"first_one_wins"},
             "evaluations":[{"subject":{"type":"user","id":"alice@example.com"}}]}
            """;

        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/access/v1/evaluations");
        using System.Net.Http.StringContent content = new(
            Body, Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .PostAsync(url, content, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "An unrecognised evaluations_semantic yields HTTP 400.");
        Assert.IsFalse(pdpInvoked, "The PDP must not run for a request rejected at parsing.");
    }


    [TestMethod]
    public async Task SubjectSearchReturnsResultsWithPagination()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = RegisterPdp(app);
        WireSearch(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        //subject.id is omitted (§7: it MUST be ignored); subject.type is the
        //dimension being enumerated.
        const string Body = """
            {"subject":{"type":"user"},
             "action":{"name":"can_read"},
             "resource":{"type":"account","id":"123"},
             "page":{"limit":2}}
            """;

        using JsonDocument response = await PostSearchAsync(host, segment, "subject", Body, expectedStatus: 200).ConfigureAwait(false);
        JsonElement root = response.RootElement;

        JsonElement results = root.GetProperty(AuthZenFieldNames.Results);
        Assert.AreEqual(2, results.GetArrayLength(), "Both wired subjects are returned.");
        Assert.AreEqual("user", results[0].GetProperty(AuthZenFieldNames.Type).GetString());
        Assert.AreEqual("alice@example.com", results[0].GetProperty(AuthZenFieldNames.Id).GetString());
        Assert.AreEqual("bob@example.com", results[1].GetProperty(AuthZenFieldNames.Id).GetString());

        JsonElement page = root.GetProperty(AuthZenFieldNames.Page);
        Assert.AreEqual("next-123", page.GetProperty(AuthZenFieldNames.NextToken).GetString(),
            "next_token carries the seam's continuation token.");
        Assert.AreEqual(2, page.GetProperty(AuthZenFieldNames.Count).GetInt32());
        Assert.AreEqual(5, page.GetProperty(AuthZenFieldNames.Total).GetInt32());
    }


    [TestMethod]
    public async Task ResourceSearchReturnsResources()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = RegisterPdp(app);
        WireSearch(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        const string Body = """
            {"subject":{"type":"user","id":"alice@example.com"},
             "action":{"name":"can_read"},
             "resource":{"type":"account"}}
            """;

        using JsonDocument response = await PostSearchAsync(host, segment, "resource", Body, expectedStatus: 200).ConfigureAwait(false);
        JsonElement results = response.RootElement.GetProperty(AuthZenFieldNames.Results);

        Assert.AreEqual(1, results.GetArrayLength());
        Assert.AreEqual("account", results[0].GetProperty(AuthZenFieldNames.Type).GetString());
        Assert.AreEqual("123", results[0].GetProperty(AuthZenFieldNames.Id).GetString());

        //A seam that does not paginate yields the end-of-results page.
        Assert.AreEqual("", response.RootElement.GetProperty(AuthZenFieldNames.Page)
            .GetProperty(AuthZenFieldNames.NextToken).GetString(),
            "An unpaginated result emits next_token as the empty string (end of results).");
    }


    [TestMethod]
    public async Task ActionSearchReturnsPermittedActions()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = RegisterPdp(app);
        WireSearch(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        //§7 Action Search carries no action — the response is the permitted set.
        const string Body = """
            {"subject":{"type":"user","id":"alice@example.com"},
             "resource":{"type":"account","id":"123"}}
            """;

        using JsonDocument response = await PostSearchAsync(host, segment, "action", Body, expectedStatus: 200).ConfigureAwait(false);
        JsonElement results = response.RootElement.GetProperty(AuthZenFieldNames.Results);

        Assert.AreEqual(2, results.GetArrayLength());
        Assert.AreEqual("can_read", results[0].GetProperty(AuthZenFieldNames.Name).GetString());
        Assert.AreEqual("can_write", results[1].GetProperty(AuthZenFieldNames.Name).GetString());
    }


    [TestMethod]
    public async Task SubjectSearchRejectsBodyWithoutSubject()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = RegisterPdp(app);

        bool seamInvoked = false;
        app.Server.Integration.UseDefaultAuthZenJsonParsing();
        app.Server.Integration.SearchSubjectsAsync = (request, _, _, _) =>
        {
            seamInvoked = true;
            return ValueTask.FromResult(new SubjectSearchResult());
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        //No subject → the type to enumerate is unknown → 400.
        const string Body = """
            {"action":{"name":"can_read"},"resource":{"type":"account","id":"123"}}
            """;

        using JsonDocument _ = await PostSearchAsync(host, segment, "subject", Body, expectedStatus: 400).ConfigureAwait(false);
        Assert.IsFalse(seamInvoked, "The search seam must not run for a request rejected at validation.");
    }


    [TestMethod]
    public async Task SubjectSearchPaginatesWithCursorAcrossPagesToEnd()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = RegisterPdp(app);

        string[] dataset =
        [
            "u1@example.com", "u2@example.com", "u3@example.com", "u4@example.com", "u5@example.com",
        ];

        //Reference cursor pager: §7 token is an opaque continuation (here the
        //offset), limit is a maximum, next_token is "" at the end. The request
        //is parsed by the SHIPPED default parser, so page{token,limit} comes off
        //the wire through production code.
        app.Server.Integration.UseDefaultAuthZenJsonParsing();
        app.Server.Integration.SearchSubjectsAsync = (request, _, _, _) =>
        {
            int offset = 0;
            if(request.Page?.Token is { Length: > 0 } token && int.TryParse(token, out int parsed))
            {
                offset = parsed;
            }

            int limit = request.Page?.Limit is int l and > 0 ? l : 50;

            List<AuthZenSubject> slice = [];
            for(int i = offset; i < dataset.Length && slice.Count < limit; ++i)
            {
                slice.Add(new AuthZenSubject { Type = "user", Id = dataset[i] });
            }

            int nextOffset = offset + slice.Count;
            string nextToken = nextOffset < dataset.Length
                ? nextOffset.ToString(System.Globalization.CultureInfo.InvariantCulture)
                : "";

            return ValueTask.FromResult(new SubjectSearchResult
            {
                Results = slice,
                Page = new AccessSearchPage
                {
                    NextToken = nextToken,
                    Count = slice.Count,
                    Total = dataset.Length,
                    Properties = new Dictionary<string, object>(StringComparer.Ordinal) { ["source"] = "in-memory" },
                },
            });
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        List<string> collected = [];
        string? token = null;
        int pages = 0;
        while(true)
        {
            //§7: when a token is sent, all other params MUST be identical across
            //pages — only the token advances.
            string pageClause = token is null
                ? "\"page\":{\"limit\":2}"
                : $"\"page\":{{\"limit\":2,\"token\":\"{token}\"}}";
            string body =
                $$"""
                {"subject":{"type":"user"},"action":{"name":"can_read"},"resource":{"type":"todo","id":"t1"},{{pageClause}}}
                """;

            using JsonDocument doc = await PostSearchAsync(host, segment, "subject", body, expectedStatus: 200).ConfigureAwait(false);
            JsonElement root = doc.RootElement;

            foreach(JsonElement result in root.GetProperty(AuthZenFieldNames.Results).EnumerateArray())
            {
                collected.Add(result.GetProperty(AuthZenFieldNames.Id).GetString()!);
            }

            JsonElement page = root.GetProperty(AuthZenFieldNames.Page);
            Assert.AreEqual(5, page.GetProperty(AuthZenFieldNames.Total).GetInt32(),
                "total reports the full result set size on every page.");
            Assert.AreEqual("in-memory",
                page.GetProperty(AuthZenFieldNames.Properties).GetProperty("source").GetString(),
                "The §7 page.properties round-trips.");

            token = page.GetProperty(AuthZenFieldNames.NextToken).GetString();
            pages++;
            if(pages > 10) { Assert.Fail("Pagination must terminate."); }
            if(string.IsNullOrEmpty(token)) { break; }
        }

        Assert.AreEqual(3, pages, "5 items at limit 2 paginate as 2 + 2 + 1.");
        CollectionAssert.AreEqual(dataset, collected,
            "Every item is returned exactly once, in order, across the pages (empty next_token signals the end).");
    }


    [TestMethod]
    public async Task ConfigurationAdvertisesWiredSearchEndpoints()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = RegisterPdp(app);
        WireSearch(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/.well-known/authzen-configuration");
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        JsonElement root = doc.RootElement;

        //Each search endpoint is advertised because its seam is wired (§9.1
        //availability is signalled by the metadata parameter's presence).
        AssertEndpointPath(root, AuthZenMetadataParameterNames.SearchSubjectEndpoint,
            $"/connect/{segment}/access/v1/search/subject");
        AssertEndpointPath(root, AuthZenMetadataParameterNames.SearchResourceEndpoint,
            $"/connect/{segment}/access/v1/search/resource");
        AssertEndpointPath(root, AuthZenMetadataParameterNames.SearchActionEndpoint,
            $"/connect/{segment}/access/v1/search/action");
    }


    private static void AssertEndpointPath(JsonElement metadata, string field, string expectedPath)
    {
        Assert.IsTrue(metadata.TryGetProperty(field, out JsonElement element),
            $"{field} must be advertised when its seam is wired.");
        Assert.IsTrue(Uri.TryCreate(element.GetString(), UriKind.Absolute, out Uri? uri),
            $"{field} must be an absolute URL.");
        Assert.AreEqual(expectedPath, uri!.AbsolutePath,
            $"{field} must be the URL the endpoint serves.");
    }


    [TestMethod]
    public async Task ConfigurationAdvertisesContributedCapabilities()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = RegisterPdp(app);
        app.Server.Integration.ContributeAuthZenMetadataAsync = (_, _, _) =>
            ValueTask.FromResult(new AuthZenMetadataContribution
            {
                Capabilities =
                [
                    "urn:example:authzen:capability:reasons",
                    "urn:example:authzen:capability:search",
                ],
            });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        using JsonDocument doc = await GetConfigurationAsync(host, segment).ConfigureAwait(false);
        JsonElement capabilities = doc.RootElement.GetProperty(AuthZenMetadataParameterNames.Capabilities);

        Assert.AreEqual(2, capabilities.GetArrayLength(), "Both contributed capability URNs are advertised.");
        Assert.AreEqual("urn:example:authzen:capability:reasons", capabilities[0].GetString());
        Assert.AreEqual("urn:example:authzen:capability:search", capabilities[1].GetString());
    }


    [TestMethod]
    public async Task ConfigurationEmbedsSignedMetadataAndSignsAssembledClaims()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = RegisterPdp(app);

        //The application owns signing (key + algorithm); a real deployment signs
        //via Verifiable.JCose Jws.SignAsync. Here we capture the claim set the
        //library hands over and return a sentinel JWS — the library's contract
        //is "assemble the correct claims, embed the returned JWT".
        JwtPayload? signedClaims = null;
        app.Server.Integration.ContributeAuthZenMetadataAsync = (_, _, _) =>
            ValueTask.FromResult(new AuthZenMetadataContribution { Capabilities = ["urn:example:cap"] });
        app.Server.Integration.SignAuthZenMetadataAsync = (claims, _, _, _) =>
        {
            signedClaims = claims;
            return ValueTask.FromResult<string?>("header.payload.signature");
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        using JsonDocument doc = await GetConfigurationAsync(host, segment).ConfigureAwait(false);

        Assert.AreEqual("header.payload.signature",
            doc.RootElement.GetProperty(AuthZenMetadataParameterNames.SignedMetadata).GetString(),
            "The signer's JWT is embedded verbatim as signed_metadata.");

        Assert.IsNotNull(signedClaims, "The signer must be invoked.");
        Assert.IsTrue(signedClaims!.ContainsKey(AuthZenMetadataParameterNames.PolicyDecisionPoint),
            "The signed claim set carries the PDP identifier.");
        Assert.IsTrue(signedClaims.ContainsKey(AuthZenMetadataParameterNames.AccessEvaluationEndpoint),
            "The signed claim set carries the chain-resolved access_evaluation_endpoint.");
        Assert.IsTrue(signedClaims.ContainsKey(AuthZenMetadataParameterNames.Capabilities),
            "The signed claim set carries the contributed capabilities.");
    }


    [TestMethod]
    public async Task CoLocatedPdpAdvertisesAuthZenMetadataInOAuthDiscovery()
    {
        //A co-located PDP + Authorization Server links from its OAuth discovery
        //document to its AuthZEN PDP metadata document. There is no IANA-
        //registered OAuth metadata field for this, so the deployment surfaces it
        //through the EXISTING ContributeDiscoveryFieldsAsync seam under a
        //deployment-chosen key — no AuthZEN-specific library code is needed.
        const string AuthZenConfigurationField = "authzen_configuration_endpoint";

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = app.RegisterClient(
            ClientId,
            new Uri(ClientId),
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi));

        app.Server.Integration.ContributeDiscoveryFieldsAsync = (registration, _, _) =>
        {
            //Derive the AuthZEN metadata URL from the issuer with the library's
            //own well-known-path helper, keeping AS and PDP identities aligned.
            Uri authZenConfiguration = WellKnownPaths.AuthZenConfiguration.ComputeUri(
                registration.IssuerUri!.ToString());

            return ValueTask.FromResult(new DiscoveryDocumentContribution(
                [new DiscoveryStringField(AuthZenConfigurationField, authZenConfiguration.ToString())]));
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/.well-known/openid-configuration");
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.IsTrue(doc.RootElement.TryGetProperty(AuthZenConfigurationField, out JsonElement link),
            "The discovery document surfaces the AuthZEN metadata link via the contributed field.");
        Assert.IsTrue(link.GetString()!.EndsWith("/.well-known/authzen-configuration", StringComparison.Ordinal),
            "The contributed link points at the AuthZEN PDP metadata document.");
    }


    private async ValueTask<JsonDocument> GetConfigurationAsync(HostedAuthorizationServer host, string segment)
    {
        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/.well-known/authzen-configuration");
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode,
            $"GET .well-known/authzen-configuration must return 200. Body: {body}");

        return JsonDocument.Parse(body);
    }


    private static VerifierKeyMaterial RegisterPdp(TestHostShell app) =>
        app.RegisterClient(
            ClientId,
            new Uri(ClientId),
            ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi));


    private static void WirePdp(TestHostShell app)
    {
        //Wire the SHIPPED default STJ parsers (Verifiable.Json) — the e2e flow
        //then exercises the real production parse path, not a test-local one.
        app.Server.Integration.UseDefaultAuthZenJsonParsing();

        //The application's Policy Decision Point: alice may read; everyone else
        //is denied. A permit carries a reason in its context.
        app.Server.Integration.EvaluateAccessAsync = (request, _, _, _) =>
        {
            bool permit = string.Equals(request.Action.Name, "can_read", StringComparison.Ordinal)
                && string.Equals(request.Subject.Id, "alice@example.com", StringComparison.Ordinal);

            return permit
                ? ValueTask.FromResult(new AccessEvaluationDecision
                {
                    Decision = true,
                    Context = new Dictionary<string, object>(StringComparer.Ordinal) { ["reason"] = "owner" },
                })
                : ValueTask.FromResult(AccessEvaluationDecision.Deny);
        };
    }


    //Wires the §7 Search seams: a uniform parser plus canned enumerations.
    //Subject search returns two paginated subjects; resource and action search
    //return single-page results.
    private static void WireSearch(TestHostShell app)
    {
        app.Server.Integration.UseDefaultAuthZenJsonParsing();

        app.Server.Integration.SearchSubjectsAsync = (request, _, _, _) =>
            ValueTask.FromResult(new SubjectSearchResult
            {
                Results =
                [
                    new AuthZenSubject { Type = "user", Id = "alice@example.com" },
                    new AuthZenSubject { Type = "user", Id = "bob@example.com" },
                ],
                Page = new AccessSearchPage { NextToken = "next-123", Count = 2, Total = 5 },
            });

        app.Server.Integration.SearchResourcesAsync = (request, _, _, _) =>
            ValueTask.FromResult(new ResourceSearchResult
            {
                Results = [new AuthZenResource { Type = "account", Id = "123" }],
            });

        app.Server.Integration.SearchActionsAsync = (request, _, _, _) =>
            ValueTask.FromResult(new ActionSearchResult
            {
                Results =
                [
                    new AuthZenAction { Name = "can_read" },
                    new AuthZenAction { Name = "can_write" },
                ],
            });
    }


    private async ValueTask<JsonDocument> PostSearchAsync(
        HostedAuthorizationServer host, string segment, string dimension, string body, int expectedStatus)
    {
        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/access/v1/search/{dimension}");
        return await PostJsonAsync(host, url, body, $"access/v1/search/{dimension}", expectedStatus).ConfigureAwait(false);
    }


    private async ValueTask<JsonDocument> PostAsync(
        HostedAuthorizationServer host, string segment, string body, int expectedStatus)
    {
        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/access/v1/evaluation");
        return await PostJsonAsync(host, url, body, "access/v1/evaluation", expectedStatus).ConfigureAwait(false);
    }


    private async ValueTask<JsonDocument> PostEvaluationsAsync(
        HostedAuthorizationServer host, string segment, string body, int expectedStatus)
    {
        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/access/v1/evaluations");
        return await PostJsonAsync(host, url, body, "access/v1/evaluations", expectedStatus).ConfigureAwait(false);
    }


    private async ValueTask<JsonDocument> PostJsonAsync(
        HostedAuthorizationServer host, Uri url, string body, string label, int expectedStatus)
    {
        using System.Net.Http.StringContent content = new(
            body, Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .PostAsync(url, content, TestContext.CancellationToken).ConfigureAwait(false);

        string responseBody = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(expectedStatus, (int)response.StatusCode,
            $"POST {label} must return {expectedStatus}. Body: {responseBody}");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.Content.Headers.ContentType?.MediaType,
            $"The {label} response is application/json.");

        return JsonDocument.Parse(responseBody);
    }
}
