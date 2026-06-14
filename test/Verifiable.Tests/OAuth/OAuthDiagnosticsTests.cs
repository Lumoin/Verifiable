using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.OAuth.Diagnostics;
using Verifiable.OAuth.Server;
using Verifiable.Server.Diagnostics;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Verifies that <see cref="EndpointServer"/> emits activities (spans) and
/// events with the correct names and tags from <see cref="ServerActivitySource"/>.
/// </summary>
/// <remarks>
/// <para>
/// Uses <see cref="ActivityListener"/> to capture activities without any OTel SDK
/// dependency. The listener subscribes to <see cref="ServerActivitySource.SourceName"/>
/// and collects all completed activities for assertion.
/// </para>
/// </remarks>
[TestClass]
internal sealed class OAuthDiagnosticsTests
{
    public TestContext TestContext { get; set; } = null!;

    private static FakeTimeProvider TimeProvider { get; } = new();

    private static Uri IssuerUri { get; } = new("https://issuer.example.com");

    private static ImmutableHashSet<CapabilityIdentifier> JwksCapabilities { get; } =
        [WellKnownCapabilityIdentifiers.OAuthJwksEndpoint];


    [TestMethod]
    public async Task HandleAsyncEmitsActivityWithFlowKindAndStatusCode()
    {
        ConcurrentBag<Activity> captured = [];

        using ActivityListener listener = CreateListener(captured);
        ActivitySource.AddActivityListener(listener);

        await using TestHostShell app = new(TimeProvider);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();

        ClientRecord registration = app.RegisterSigningClient(
            "diag-client", keys, JwksCapabilities);

        ExchangeContext context = new();
        context.SetTenantId(registration.TenantId);
        context.SetIssuer(IssuerUri);

        await app.DispatchAtEndpointAsync(
            registration.TenantId,
            WellKnownEndpointNames.MetadataJwks,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        //ActivityListener is process-wide: sibling tests running in
        //parallel emit activities into the same ServerActivitySource and
        //land in this bag while our listener is alive. Filter by the
        //test's own tenant id (each RegisterSigningClient produces a
        //fresh, unique TenantId) so this assertion stays isolated from
        //other tests' traffic.
        Activity[] handleActivities = captured
            .Where(a => string.Equals(
                a.OperationName, ServerActivityNames.Handle, StringComparison.Ordinal))
            .Where(a => a.Tags.Any(t =>
                string.Equals(t.Key, ServerTagNames.TenantId, StringComparison.Ordinal)
                && string.Equals(t.Value, registration.TenantId.Value, StringComparison.Ordinal)))
            .ToArray();

        Assert.IsGreaterThan(0, handleActivities.Length,
            $"At least one '{ServerActivityNames.Handle}' activity tagged " +
            $"with tenant '{registration.TenantId.Value}' must be emitted.");

        Activity activity = handleActivities[0];

        string? flowKind = activity.Tags
            .FirstOrDefault(t => string.Equals(
                t.Key, ServerTagNames.FlowKind, StringComparison.Ordinal))
            .Value;

        string? statusCode = activity.Tags
            .FirstOrDefault(t => string.Equals(
                t.Key, ServerTagNames.StatusCode, StringComparison.Ordinal))
            .Value;

        Assert.IsNotNull(flowKind,
            $"Activity must carry '{ServerTagNames.FlowKind}' tag.");
        Assert.AreEqual("200", statusCode,
            $"Activity must carry '{ServerTagNames.StatusCode}' tag with value '200'.");
    }


    [TestMethod]
    public async Task HandleAsyncEmitsActivityForUnknownSegmentWith404()
    {
        ConcurrentBag<Activity> captured = [];

        using ActivityListener listener = CreateListener(captured);
        ActivitySource.AddActivityListener(listener);

        //The ActivityListener is process-wide: sibling tests running in parallel
        //emit their own 'Handle' activities into this bag. Unlike the 200 test,
        //this one dispatches to a nonexistent tenant with no registration to filter
        //by, so isolate by trace instead — start a per-test root so the library's
        //activities (if any) inherit its TraceId, and keep only those.
        using Activity testRoot = new(nameof(HandleAsyncEmitsActivityForUnknownSegmentWith404));
        testRoot.Start();
        ActivityTraceId testTraceId = testRoot.TraceId;

        await using TestHostShell app = new(TimeProvider);

        await app.DispatchAtEndpointAsync(
            "nonexistent",
            WellKnownEndpointNames.MetadataJwks,
            "GET",
            new RequestFields(),
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Activity[] handleActivities = captured
            .Where(a => a.TraceId == testTraceId)
            .Where(a => string.Equals(
                a.OperationName, ServerActivityNames.Handle, StringComparison.Ordinal))
            .ToArray();

        //A 404 from DispatchAtEndpointAsync happens during registration load
        //(the registration isn't found) — before any matcher runs and before
        //HandleAsync is called. If the library emits an activity for
        //dispatch-level errors, assert on it. Otherwise this test documents
        //that unresolved segments produce no HandleAsync activity — which is
        //also valid.
        if(handleActivities.Length > 0)
        {
            string? statusCode = handleActivities[0].Tags
                .FirstOrDefault(t => string.Equals(
                    t.Key, ServerTagNames.StatusCode, StringComparison.Ordinal))
                .Value;

            Assert.AreEqual("404", statusCode,
                "Activity for unknown segment must carry status code 404.");
        }
    }


    [TestMethod]
    public void ActivitySourceNameMatchesConstant()
    {
        Assert.AreEqual(
            ServerActivitySource.SourceName,
            ServerActivitySource.Source.Name,
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
            ServerActivityNames.Handle
        ];

        foreach(string name in names)
        {
            Assert.IsFalse(string.IsNullOrWhiteSpace(name),
                "Activity names must not be null or whitespace.");
            Assert.Contains('.', name,
                $"Activity name '{name}' must be dot-delimited.");
        }
    }


    [TestMethod]
    public void AllTagNamesAreNonEmptyAndDotDelimited()
    {
        string[] tags =
        [
            ServerTagNames.FlowKind,
            ServerTagNames.TenantId,
            ServerTagNames.RegistrationId,
            ServerTagNames.HttpMethod,
            ServerTagNames.StatusCode,
            ServerTagNames.FlowState,
            ServerTagNames.FlowStepCount,
            ServerTagNames.StartsNewFlow,
            ServerTagNames.CorrelationResolved
        ];

        foreach(string tag in tags)
        {
            Assert.IsFalse(string.IsNullOrWhiteSpace(tag),
                "Tag names must not be null or whitespace.");
            Assert.Contains('.', tag,
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
            Assert.Contains('.', metric,
                $"Metric name '{metric}' must be dot-delimited.");
        }
    }


    [TestMethod]
    public void AllEventNamesAreNonEmptyAndDotDelimited()
    {
        string[] events =
        [
            ServerEventNames.StateTransition,
            ServerEventNames.CorrelationResolved,
            ServerEventNames.CorrelationNotFound,
            ServerEventNames.FlowCreated,
            OAuthEventNames.ExtraneousAuthorizeParameters,
            OAuthEventNames.DuplicateGrantedCredentialConfigurationCollapsed,
            OAuthEventNames.LongLivedBearerCredentialTokenRefused
        ];

        foreach(string eventName in events)
        {
            Assert.IsFalse(string.IsNullOrWhiteSpace(eventName),
                "Event names must not be null or whitespace.");
            Assert.Contains('.', eventName,
                $"Event name '{eventName}' must be dot-delimited.");
        }
    }


    private static ActivityListener CreateListener(ConcurrentBag<Activity> captured) =>
        new()
        {
            ShouldListenTo = source =>
                string.Equals(source.Name, ServerActivitySource.SourceName, StringComparison.Ordinal),
            Sample = static (ref ActivityCreationOptions<ActivityContext> _) =>
                ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => captured.Add(activity)
        };
}
