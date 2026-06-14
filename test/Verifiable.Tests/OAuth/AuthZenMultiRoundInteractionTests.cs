using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthZen;
using Verifiable.OAuth.Server;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Multi-round interaction sequences over the OpenID AuthZEN Authorization
/// API 1.0 Access Evaluation API (<c>POST /access/v1/evaluation</c>, §6):
/// step-up authentication (deny advising step-up → re-evaluation with a
/// stronger subject → permit) and request-for-access with just-in-time
/// provisioning and expiry (deny advising a request URL → entitlement granted
/// → permit → grant expires → deny).
/// </summary>
/// <remarks>
/// The evaluation endpoint is stateless by design; everything multi-round
/// lives outside it. The advice rides the §6 response <c>context</c> object —
/// the open, PDP-defined channel for enforcement information — and the
/// mutable state is the policy's entitlement store, which the test mutates
/// between calls the way an IGA system provisions a just-in-time grant. Each
/// round is a complete wire round trip through the shipped default parser.
/// </remarks>
[TestClass]
internal sealed class AuthZenMultiRoundInteractionTests
{
    private const string ClientId = "https://pdp.example.com";
    private const string Alice = "alice@example.com";
    private const string Bob = "bob@example.com";

    /// <summary>The subject property carrying the authentication context class reference.</summary>
    private const string AcrProperty = "acr";

    /// <summary>The policy's required acr for destructive actions.</summary>
    private const string MfaAcr = "urn:example:loa:mfa";

    /// <summary>The advice keys this scenario's PDPs place in the response context.</summary>
    private const string ReasonKey = "reason";
    private const string RequiredAcrKey = "required_acr";
    private const string RequestUrlKey = "request_url";

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();


    [TestMethod]
    public async Task StepUpAdviceLeadsToPermitOnReEvaluationWithStrongerAuthentication()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = app.RegisterClient(
            ClientId,
            new Uri(ClientId),
            ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi));

        app.Server.OAuth().UseDefaultAuthZenJsonParsing();
        var policy = new StepUpPolicy(requiredAcr: MfaAcr);
        app.Server.OAuth().EvaluateAccessAsync = policy.EvaluateAsync;

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Uri url = EvaluationUrl(app, pdp);

        //Round 1: a password-authenticated session asks to delete — denied,
        //and the context advises which acr a re-evaluation needs.
        (bool decision, JsonElement? context) = await EvaluateAsync(
            app, url, Request(Alice, "delete", acr: "urn:example:loa:pwd")).ConfigureAwait(false);

        Assert.IsFalse(decision, "A password-level session must not delete.");
        Assert.IsNotNull(context, "The deny carries step-up advice in the response context.");
        Assert.AreEqual("step_up_required", context.Value.GetProperty(ReasonKey).GetString());
        Assert.AreEqual(MfaAcr, context.Value.GetProperty(RequiredAcrKey).GetString());

        //Round 2: the subject steps up and the PEP re-evaluates the same
        //request with the stronger acr — permitted.
        (decision, context) = await EvaluateAsync(
            app, url, Request(Alice, "delete", acr: MfaAcr)).ConfigureAwait(false);

        Assert.IsTrue(decision, "The stepped-up re-evaluation is permitted.");
        Assert.IsNull(context, "A bare permit carries no advice.");

        //Reads never required the step-up in the first place.
        (decision, _) = await EvaluateAsync(
            app, url, Request(Alice, "read", acr: "urn:example:loa:pwd")).ConfigureAwait(false);
        Assert.IsTrue(decision, "Reads are permitted at any authentication level.");
    }


    [TestMethod]
    public async Task RequestForAccessIsProvisionedJustInTimeAndExpires()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial pdp = app.RegisterClient(
            ClientId,
            new Uri(ClientId),
            ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi));

        app.Server.OAuth().UseDefaultAuthZenJsonParsing();
        var policy = new EntitlementPolicy(TimeProvider, requestUrl: "https://iga.example.com/requests/new");
        app.Server.OAuth().EvaluateAccessAsync = policy.EvaluateAsync;

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Uri url = EvaluationUrl(app, pdp);
        AccessEvaluationRequest update = Request(Bob, "update");

        //Round 1: no entitlement — denied, and the context advises where to
        //request access.
        (bool decision, JsonElement? context) = await EvaluateAsync(app, url, update).ConfigureAwait(false);

        Assert.IsFalse(decision, "An unentitled subject is denied.");
        Assert.IsNotNull(context);
        Assert.AreEqual("access_request_required", context.Value.GetProperty(ReasonKey).GetString());
        Assert.AreEqual("https://iga.example.com/requests/new", context.Value.GetProperty(RequestUrlKey).GetString());

        //The IGA flow provisions a one-hour just-in-time grant into the
        //policy's entitlement store — the state the rounds thread through.
        policy.Grant(Bob, until: TimeProvider.GetUtcNow().AddHours(1));

        //Round 2: the same request is now permitted.
        (decision, context) = await EvaluateAsync(app, url, update).ConfigureAwait(false);
        Assert.IsTrue(decision, "The just-in-time grant permits the request.");
        Assert.IsNull(context);

        //Round 3: past the grant's validity the same request denies again,
        //advising a fresh access request.
        TimeProvider.Advance(TimeSpan.FromHours(2));

        (decision, context) = await EvaluateAsync(app, url, update).ConfigureAwait(false);
        Assert.IsFalse(decision, "The expired grant no longer permits.");
        Assert.IsNotNull(context);
        Assert.AreEqual("access_request_required", context.Value.GetProperty(ReasonKey).GetString());
    }


    /// <summary>
    /// A PDP requiring a stronger authentication context for destructive
    /// actions: anyone may <c>read</c>; everything else needs the configured
    /// acr in the subject's properties. The deny advises the required acr
    /// through the response context.
    /// </summary>
    private sealed class StepUpPolicy(string requiredAcr)
    {
        public ValueTask<AccessEvaluationDecision> EvaluateAsync(
            AccessEvaluationRequest request,
            ClientRecord registration,
            ExchangeContext context,
            CancellationToken cancellationToken)
        {
            if(string.Equals(request.Action.Name, "read", StringComparison.Ordinal))
            {
                return ValueTask.FromResult(AccessEvaluationDecision.Permit);
            }

            bool steppedUp = request.Subject.Properties is { } properties
                && properties.TryGetValue(AcrProperty, out object? acr)
                && acr is string presentedAcr
                && string.Equals(presentedAcr, requiredAcr, StringComparison.Ordinal);
            if(steppedUp)
            {
                return ValueTask.FromResult(AccessEvaluationDecision.Permit);
            }

            return ValueTask.FromResult(new AccessEvaluationDecision
            {
                Decision = false,
                Context = new Dictionary<string, object>
                {
                    [ReasonKey] = "step_up_required",
                    [RequiredAcrKey] = requiredAcr
                }
            });
        }
    }


    /// <summary>
    /// A PDP over a mutable, time-bounded entitlement store: a subject is
    /// permitted while it holds an unexpired grant. <see cref="Grant"/> models
    /// the IGA system provisioning a just-in-time entitlement between rounds;
    /// the deny advises the access-request URL through the response context.
    /// </summary>
    private sealed class EntitlementPolicy(TimeProvider timeProvider, string requestUrl)
    {
        private Dictionary<string, DateTimeOffset> Grants { get; } = new(StringComparer.Ordinal);

        public void Grant(string subjectId, DateTimeOffset until) => Grants[subjectId] = until;

        public ValueTask<AccessEvaluationDecision> EvaluateAsync(
            AccessEvaluationRequest request,
            ClientRecord registration,
            ExchangeContext context,
            CancellationToken cancellationToken)
        {
            bool entitled = Grants.TryGetValue(request.Subject.Id, out DateTimeOffset until)
                && timeProvider.GetUtcNow() < until;
            if(entitled)
            {
                return ValueTask.FromResult(AccessEvaluationDecision.Permit);
            }

            return ValueTask.FromResult(new AccessEvaluationDecision
            {
                Decision = false,
                Context = new Dictionary<string, object>
                {
                    [ReasonKey] = "access_request_required",
                    [RequestUrlKey] = requestUrl
                }
            });
        }
    }


    private static Uri EvaluationUrl(TestHostShell app, VerifierKeyMaterial pdp)
    {
        HostedAuthorizationServer host = app.Host("default");
        string segment = pdp.Registration.TenantId.Value;

        return new Uri(host.HttpBaseAddress!, $"/connect/{segment}/access/v1/evaluation");
    }


    /// <summary>
    /// Posts one evaluation round over the wire and reads back the §6 response
    /// body: the <c>decision</c> boolean and the optional <c>context</c> object
    /// (cloned so it outlives the parse).
    /// </summary>
    private async Task<(bool Decision, JsonElement? Context)> EvaluateAsync(
        TestHostShell app, Uri url, AccessEvaluationRequest request)
    {
        HostedAuthorizationServer host = app.Host("default");
        using StringContent content = new(
            ToRequestJson(request), Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpResponseMessage response = await host.SharedHttpClient!
            .PostAsync(url, content, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, $"Evaluation must return 200. Body: {body}");

        using JsonDocument doc = JsonDocument.Parse(body);
        bool decision = doc.RootElement.GetProperty(AuthZenFieldNames.Decision).GetBoolean();
        JsonElement? context = doc.RootElement.TryGetProperty(AuthZenFieldNames.Context, out JsonElement element)
            ? element.Clone() : null;

        return (decision, context);
    }


    private static AccessEvaluationRequest Request(string subjectId, string action, string? acr = null) =>
        new()
        {
            Subject = new AuthZenSubject
            {
                Type = "user",
                Id = subjectId,
                Properties = acr is null ? null : new Dictionary<string, object> { [AcrProperty] = acr }
            },
            Action = new AuthZenAction { Name = action },
            Resource = new AuthZenResource { Type = "document", Id = "doc-1" },
        };


    //Serialise a typed request to its wire JSON using our own wire-name
    //constants (AuthZenFieldNames) so the body goes through the real default
    //parser on the way in — no hand-shaped JSON literals.
    private static string ToRequestJson(AccessEvaluationRequest request)
    {
        JsonObject subject = new()
        {
            [AuthZenFieldNames.Type] = request.Subject.Type,
            [AuthZenFieldNames.Id] = request.Subject.Id,
        };

        if(request.Subject.Properties is { } properties)
        {
            JsonObject propertyObject = new();
            foreach(KeyValuePair<string, object> entry in properties)
            {
                propertyObject[entry.Key] = JsonValue.Create((string)entry.Value);
            }

            subject[AuthZenFieldNames.Properties] = propertyObject;
        }

        JsonObject root = new()
        {
            [AuthZenFieldNames.Subject] = subject,
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
}
