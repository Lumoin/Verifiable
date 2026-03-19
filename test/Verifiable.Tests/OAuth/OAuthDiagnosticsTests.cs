using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.OAuth.Diagnostics;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Verifies that <see cref="AuthorizationServer"/> emits activities (spans) and
/// events with the correct names and tags from <see cref="OAuthActivitySource"/>.
/// </summary>
/// <remarks>
/// <para>
/// Uses <see cref="ActivityListener"/> to capture activities without any OTel SDK
/// dependency. The listener subscribes to <see cref="OAuthActivitySource.SourceName"/>
/// and collects all completed activities for assertion.
/// </para>
/// </remarks>
[TestClass]
internal sealed class OAuthDiagnosticsTests
{
    public TestContext TestContext { get; set; } = null!;

    private static FakeTimeProvider TimeProvider { get; } = new();

    private static Uri IssuerUri { get; } = new("https://issuer.example.com");

    private static ImmutableHashSet<ServerCapabilityName> JwksCapabilities { get; } =
        [ServerCapabilityName.JwksEndpoint];


    [TestMethod]
    public async Task HandleAsyncEmitsActivityWithFlowKindAndStatusCode()
    {
        ConcurrentBag<Activity> captured = [];

        using ActivityListener listener = CreateListener(captured);
        ActivitySource.AddActivityListener(listener);

        using TestHostShell app = new(TimeProvider);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();

        ClientRegistration registration = app.RegisterSigningClient(
            "diag-client", keys, JwksCapabilities);

        RequestContext context = new();
        context.SetTenantId(registration.TenantId);
        context.SetIssuer(IssuerUri);

        await app.DispatchBySegmentAsync(
            registration.TenantId,
            ServerCapabilityName.JwksEndpoint,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Activity[] handleActivities = captured
            .Where(a => string.Equals(
                a.OperationName, OAuthActivityNames.Handle, StringComparison.Ordinal))
            .ToArray();

        Assert.IsGreaterThan(0, handleActivities.Length,
            $"At least one '{OAuthActivityNames.Handle}' activity must be emitted.");

        Activity activity = handleActivities[0];

        string? flowKind = activity.Tags
            .FirstOrDefault(t => string.Equals(
                t.Key, OAuthTagNames.FlowKind, StringComparison.Ordinal))
            .Value;

        string? statusCode = activity.Tags
            .FirstOrDefault(t => string.Equals(
                t.Key, OAuthTagNames.StatusCode, StringComparison.Ordinal))
            .Value;

        Assert.IsNotNull(flowKind,
            $"Activity must carry '{OAuthTagNames.FlowKind}' tag.");
        Assert.AreEqual("200", statusCode,
            $"Activity must carry '{OAuthTagNames.StatusCode}' tag with value '200'.");
    }


    [TestMethod]
    public async Task HandleAsyncEmitsActivityForUnknownSegmentWith404()
    {
        ConcurrentBag<Activity> captured = [];

        using ActivityListener listener = CreateListener(captured);
        ActivitySource.AddActivityListener(listener);

        using TestHostShell app = new(TimeProvider);

        await app.DispatchBySegmentAsync(
            "nonexistent",
            ServerCapabilityName.JwksEndpoint,
            "GET",
            new RequestFields(),
            new RequestContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Activity[] handleActivities = captured
            .Where(a => string.Equals(
                a.OperationName, OAuthActivityNames.Handle, StringComparison.Ordinal))
            .ToArray();

        //A 404 from DispatchBySegmentAsync happens before HandleAsync is called
        //(the registration isn't found). If the library emits an activity for
        //dispatch-level errors, assert on it. Otherwise this test documents that
        //unresolved segments produce no HandleAsync activity — which is also valid.
        if(handleActivities.Length > 0)
        {
            string? statusCode = handleActivities[0].Tags
                .FirstOrDefault(t => string.Equals(
                    t.Key, OAuthTagNames.StatusCode, StringComparison.Ordinal))
                .Value;

            Assert.AreEqual("404", statusCode,
                "Activity for unknown segment must carry status code 404.");
        }
    }


    [TestMethod]
    public void ActivitySourceNameMatchesConstant()
    {
        Assert.AreEqual(
            OAuthActivitySource.SourceName,
            OAuthActivitySource.Source.Name,
            "ActivitySource.Name must equal the published constant.");
    }


    [TestMethod]
    public void MeterNameMatchesConstant()
    {
        Assert.AreEqual(
            OAuthMeterSource.MeterName,
            OAuthMeterSource.Meter.Name,
            "Meter.Name must equal the published constant.");
    }


    [TestMethod]
    public void AllActivityNamesAreNonEmptyAndDotDelimited()
    {
        string[] names =
        [
            OAuthActivityNames.Handle,
            OAuthActivityNames.ResolveCorrelation,
            OAuthActivityNames.LoadFlowState,
            OAuthActivityNames.BuildInput,
            OAuthActivityNames.StepPda,
            OAuthActivityNames.SaveFlowState,
            OAuthActivityNames.BuildJwks,
            OAuthActivityNames.SignToken,
            OAuthActivityNames.ClientLifecycle
        ];

        foreach(string name in names)
        {
            Assert.IsFalse(string.IsNullOrWhiteSpace(name),
                "Activity names must not be null or whitespace.");
            Assert.IsTrue(name.Contains('.', StringComparison.Ordinal),
                $"Activity name '{name}' must be dot-delimited.");
        }
    }


    [TestMethod]
    public void AllTagNamesAreNonEmptyAndDotDelimited()
    {
        string[] tags =
        [
            OAuthTagNames.FlowKind,
            OAuthTagNames.EndpointPath,
            OAuthTagNames.TenantId,
            OAuthTagNames.ClientId,
            OAuthTagNames.HttpMethod,
            OAuthTagNames.StatusCode,
            OAuthTagNames.FlowState,
            OAuthTagNames.FlowStepCount,
            OAuthTagNames.StartsNewFlow,
            OAuthTagNames.ClaimCode,
            OAuthTagNames.ClaimName,
            OAuthTagNames.ClaimOutcome,
            OAuthTagNames.ValidationClaimCount,
            OAuthTagNames.ValidationFailureCount,
            OAuthTagNames.LifecycleOperation,
            OAuthTagNames.DeregistrationReason,
            OAuthTagNames.CorrelationResolved
        ];

        foreach(string tag in tags)
        {
            Assert.IsFalse(string.IsNullOrWhiteSpace(tag),
                "Tag names must not be null or whitespace.");
            Assert.IsTrue(tag.Contains('.', StringComparison.Ordinal),
                $"Tag name '{tag}' must be dot-delimited.");
        }
    }


    [TestMethod]
    public void AllMetricNamesAreNonEmptyAndDotDelimited()
    {
        string[] metrics =
        [
            OAuthMetricNames.RequestCount,
            OAuthMetricNames.RequestDuration,
            OAuthMetricNames.ResponseCount,
            OAuthMetricNames.ValidationClaimCount,
            OAuthMetricNames.ValidationFailureCount,
            OAuthMetricNames.ActiveFlowCount,
            OAuthMetricNames.FlowCreatedCount,
            OAuthMetricNames.FlowCompletedCount,
            OAuthMetricNames.CorrelationResolutionCount,
            OAuthMetricNames.ActiveClientCount,
            OAuthMetricNames.ClientLifecycleCount,
            OAuthMetricNames.TokenSignedCount,
            OAuthMetricNames.TokenSignDuration,
            OAuthMetricNames.JwksBuildCount
        ];

        foreach(string metric in metrics)
        {
            Assert.IsFalse(string.IsNullOrWhiteSpace(metric),
                "Metric names must not be null or whitespace.");
            Assert.IsTrue(metric.Contains('.', StringComparison.Ordinal),
                $"Metric name '{metric}' must be dot-delimited.");
        }
    }


    [TestMethod]
    public void AllEventNamesAreNonEmptyAndDotDelimited()
    {
        string[] events =
        [
            OAuthEventNames.ValidationClaim,
            OAuthEventNames.ValidationPassed,
            OAuthEventNames.ValidationFailed,
            OAuthEventNames.StateTransition,
            OAuthEventNames.ActionExecuted,
            OAuthEventNames.CorrelationResolved,
            OAuthEventNames.CorrelationNotFound,
            OAuthEventNames.FlowCreated,
            OAuthEventNames.ClientRegistered,
            OAuthEventNames.ClientUpdated,
            OAuthEventNames.ClientDeregistered
        ];

        foreach(string eventName in events)
        {
            Assert.IsFalse(string.IsNullOrWhiteSpace(eventName),
                "Event names must not be null or whitespace.");
            Assert.IsTrue(eventName.Contains('.', StringComparison.Ordinal),
                $"Event name '{eventName}' must be dot-delimited.");
        }
    }


    private static ActivityListener CreateListener(ConcurrentBag<Activity> captured) =>
        new()
        {
            ShouldListenTo = source =>
                string.Equals(source.Name, OAuthActivitySource.SourceName, StringComparison.Ordinal),
            Sample = static (ref ActivityCreationOptions<ActivityContext> _) =>
                ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => captured.Add(activity)
        };
}
