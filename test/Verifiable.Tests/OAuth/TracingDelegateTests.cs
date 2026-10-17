using Microsoft.Extensions.Time.Testing;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Verifiable.Core.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Diagnostics;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.OAuth.Server;
using Verifiable.Server.Diagnostics;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The spans of the library's server operations started through the application's
/// <see cref="StartTraceActivityDelegate"/>, over the real wire: the authorization server's dispatch span through
/// <see cref="ServerIntegration.StartTraceActivity"/>, an application's resource decision span through
/// <see cref="ResourceServerIntegration.StartTraceActivity"/>, the inbound trace context the application's propagator
/// reads, the status of a server error and the values the library's attributes never carry. The sample composition is
/// <see cref="SampleTracing"/> with the traced client of <see cref="LoopbackTls.CreateTracedPinnedHttpClient"/>.
/// </summary>
/// <remarks>
/// An <see cref="ActivityListener"/> is process-wide and the captures subscribe to the host framework's source, which
/// then writes trace context into concurrently running tests' requests, so the class runs alone and every assertion first
/// filters the captured spans by its own trace.
/// </remarks>
[TestClass]
[DoNotParallelize]
internal sealed class TracingDelegateTests
{
    /// <summary>The test context, whose cancellation token bounds every exchange.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The authorization server's clock.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch.AddDays(-15));

    /// <summary>The instant the resource server's clock reads and its access tokens and proofs are issued around.</summary>
    private static DateTimeOffset NowInstant { get; } = TestClock.CanonicalEpoch.AddDays(-15);

    /// <summary>The <c>client_credentials</c> client of the authorization server rows.</summary>
    private const string MachineClientId = "https://tracing.client.test";

    /// <summary>The <c>client_secret_post</c> secret of <see cref="MachineClientId"/>.</summary>
    private const string MachineClientSecret = "tracing-client-secret-0123456789";

    /// <summary>The issuer whose access tokens the resource server accepts.</summary>
    private const string ResourceIssuer = "https://issuer.test/tracing";

    /// <summary>The audience the resource server's access tokens name.</summary>
    private const string ResourceAudience = "tracing-resource";

    /// <summary>The subject of the resource server's access tokens.</summary>
    private const string ResourceSubject = "tracing-subject";

    /// <summary>The key identifier the resource server's verification key is resolved by.</summary>
    private const string ResourceKid = "tracing-kid";

    /// <summary>The <c>traceparent</c> example of the W3C Trace Context Recommendation, Section 3.1.</summary>
    private const string ExampleTraceParent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

    /// <summary>The trace-id of <see cref="ExampleTraceParent"/>.</summary>
    private const string ExampleTraceId = "0af7651916cd43dd8448eb211c80319c";

    /// <summary>The parent-id of <see cref="ExampleTraceParent"/>.</summary>
    private const string ExampleParentId = "b7ad6b7169203331";

    /// <summary>The <c>tracestate</c> example of the W3C Trace Context Recommendation, Section 3.1.</summary>
    private const string ExampleTraceState = "congo=t61rcWkgMzE";

    /// <summary>The <c>tracestate</c> entry the Recommendation's receiving Rojo server adds, Section 3.1.</summary>
    private const string RojoTraceState = "rojo=00f067aa0ba902b7";

    /// <summary>The source names every capture of this class subscribes to: the host framework, the application, the dispatch and the providers.</summary>
    private static IReadOnlyList<string> CapturedSourceNames { get; } =
    [
        TraceTreeCapture.AspNetCoreSourceName,
        SampleTracing.SourceName,
        ServerActivitySource.SourceName,
        CryptoActivitySource.Name
    ];


    /// <summary>
    /// <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#design-overview">W3C Trace Context Level 1,
    /// Section 2.3</see>: "At a minimum they MUST propagate the traceparent and tracestate headers and guarantee traces are
    /// not broken." With <see cref="ServerIntegration.StartTraceActivity"/> wired to the application's delegate, a
    /// <c>client_credentials</c> token request sent over the wire inside the test's root span is answered 200, and the
    /// trace holds exactly one <c>server.handle</c> span, started on the application's source as
    /// <see cref="ActivityKind.Internal"/> and carrying <c>server.tenant.handle</c>, <c>oauth.token.grant_type</c>
    /// <c>client_credentials</c> and <c>server.response.status_code</c> <c>200</c>; no span of the library's static
    /// source is in the trace, and every span of the trace descends from the root.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DispatchSpanComesFromTheApplicationsDelegateAsync()
    {
        SampleTracing sample = new();
        using TraceTreeCapture capture = new(CapturedSourceNames);
        using Activity root = new(nameof(DispatchSpanComesFromTheApplicationsDelegateAsync));
        string handle;
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await RegisterMachineClientAsync(host).ConfigureAwait(false);
            Uri tokenUrl = await StartTokenEndpointAsync(host, material, isDpopEnabled: false).ConfigureAwait(false);
            await TestHostShell.AlterAsync(host.Server, candidate => candidate.StartTraceActivity = sample.StartServerActivity).ConfigureAwait(false);
            handle = material.Registration.TenantHandle!.Value.Value;
            using HttpClient client = LoopbackTls.CreateTracedPinnedHttpClient([host.ServerCertificate], isSingleHop: true);

            _ = root.Start();
            using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
                client, tokenUrl, MachineTokenRequestFields(), TestContext.CancellationToken).ConfigureAwait(false);
            string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The token request is answered without a server fault.");
            Assert.AreEqual(200, (int)response.StatusCode, body);
        }

        root.Stop();
        IReadOnlyList<Activity> inTrace = TraceTreeAssertions.FilterByTrace(capture.StoppedActivities, root.TraceId);
        Activity dispatch = Assert.ContainsSingle(DispatchSpansOf(inTrace), "The trace holds one dispatch span.");
        Assert.AreEqual(SampleTracing.SourceName, dispatch.Source.Name, "The dispatch span is started on the application's source.");
        Assert.AreEqual(ActivityKind.Internal, dispatch.Kind);
        Assert.AreEqual(handle, dispatch.GetTagItem(ServerTagNames.TenantHandle) as string);
        Assert.AreEqual(WellKnownGrantTypes.ClientCredentials, dispatch.GetTagItem(OAuthTagNames.GrantType) as string);
        Assert.AreEqual("200", dispatch.GetTagItem(ServerTagNames.StatusCode) as string);
        Assert.DoesNotContain(
            static activity => string.Equals(activity.Source.Name, ServerActivitySource.SourceName, StringComparison.Ordinal), inTrace,
            "No span of the library's static source is in the trace.");
        TraceTreeAssertions.AssertSingleConnectedTree(capture.StoppedActivities, root);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#header-name">W3C Trace Context Level 1, Section
    /// 3.2.1</see>: "Vendors MUST expect the header name in any case (upper, lower, mixed)"; and
    /// <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#mutating-the-traceparent-field">Section
    /// 3.4</see>: "A vendor receiving a traceparent request header MUST send it to outgoing requests." with
    /// <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#mutating-the-tracestate-field">Section 3.5</see>:
    /// "Vendors receiving a tracestate request header MUST send it to outgoing requests." A <c>client_credentials</c> token
    /// request sent over a raw TLS connection with the Recommendation's <c>traceparent</c> under the field name of the row
    /// and <c>tracestate: congo=t61rcWkgMzE</c> is answered 200; the application's delegate saw exactly the one
    /// <c>traceparent</c> line, and the dispatch span carries trace-id <c>0af7651916cd43dd8448eb211c80319c</c> and
    /// tracestate <c>congo=t61rcWkgMzE</c> and descends from parent-id <c>b7ad6b7169203331</c> through captured spans.
    /// </summary>
    /// <param name="fieldName">The spelling of the <c>traceparent</c> field name the request carries.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("traceparent")]
    [DataRow("TraceParent")]
    public async Task DispatchSpanContinuesTheInboundTraceContextAsync(string fieldName)
    {
        SampleTracing sample = new();
        using TraceTreeCapture capture = new(CapturedSourceNames);
        _ = await SendTokenRequestWithTraceFieldsAsync(
            sample,
            [new(fieldName, ExampleTraceParent), new(WellKnownHttpHeaderNames.TraceState, ExampleTraceState)]).ConfigureAwait(false);

        ObservedTraceFieldLines observed = Assert.ContainsSingle(sample.ObservedFieldLines, "The delegate is called once for the request.");
        Assert.AreEqual(ExampleTraceParent, Assert.ContainsSingle(observed.TraceParentLines), "The delegate sees the one traceparent line.");

        ActivityTraceId traceId = ActivityTraceId.CreateFromString(ExampleTraceId);
        IReadOnlyList<Activity> inTrace = TraceTreeAssertions.FilterByTrace(capture.StoppedActivities, traceId);
        Activity dispatch = Assert.ContainsSingle(DispatchSpansOf(inTrace), "The dispatch span continues the presented trace.");
        Assert.AreEqual(ExampleTraceState, dispatch.TraceStateString);
        TraceTreeAssertions.AssertSingleConnectedTree(capture.StoppedActivities, traceId, ActivitySpanId.CreateFromString(ExampleParentId));
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#tracestate-header-field-values">W3C Trace
    /// Context Level 1, Section 3.3.1.1</see>: "Tracestate MAY be sent or received as multiple header fields. Multiple
    /// tracestate header fields MUST be handled as specified by RFC7230 Section 3.2.2 Field Order." and "When receiving
    /// multiple tracestate header fields, they MUST be combined into a single header according to RFC7230." and
    /// "Vendors MUST accept empty tracestate headers but SHOULD avoid sending them.";
    /// <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#tracestate-limits">Section 3.3.1.5</see>:
    /// "Vendors SHOULD propagate at least 512 characters of a combined header." A <c>client_credentials</c> token request
    /// sent over a raw TLS connection with a valid <c>traceparent</c> and the row's <c>tracestate</c> lines is answered
    /// 200; the application's delegate saw every <c>tracestate</c> line whole in received order, and the dispatch span
    /// carries them combined: <c>rojo=00f067aa0ba902b7</c> then <c>congo=t61rcWkgMzE</c> as
    /// <c>rojo=00f067aa0ba902b7,congo=t61rcWkgMzE</c>; one line of exactly 512 characters, 32 members, whole; one empty
    /// <c>tracestate</c> line reaches the delegate as one empty line, and the dispatch span continues the presented trace
    /// <c>0af7651916cd43dd8448eb211c80319c</c> and carries no list member.
    /// </summary>
    /// <param name="row">The <c>tracestate</c> lines the request carries.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(TwoTraceStateLinesRow)]
    [DataRow(TraceStateOf512CharactersRow)]
    [DataRow(EmptyTraceStateLineRow)]
    public async Task DelegateReadsEveryTracestateLineInReceivedOrderAsync(string row)
    {
        IReadOnlyList<string> traceStateLines = row switch
        {
            TwoTraceStateLinesRow => [RojoTraceState, ExampleTraceState],
            TraceStateOf512CharactersRow => [TraceStateOf512Characters()],
            EmptyTraceStateLineRow => [string.Empty],
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown tracestate row.")
        };
        string? expectedTraceState = row switch
        {
            TwoTraceStateLinesRow => $"{RojoTraceState},{ExampleTraceState}",
            TraceStateOf512CharactersRow => traceStateLines[0],
            _ => null
        };

        SampleTracing sample = new();
        using TraceTreeCapture capture = new(CapturedSourceNames);
        List<KeyValuePair<string, string>> fieldLines = [new(WellKnownHttpHeaderNames.TraceParent, ExampleTraceParent)];
        fieldLines.AddRange(traceStateLines.Select(static line => new KeyValuePair<string, string>(WellKnownHttpHeaderNames.TraceState, line)));
        _ = await SendTokenRequestWithTraceFieldsAsync(sample, fieldLines).ConfigureAwait(false);

        ObservedTraceFieldLines observed = Assert.ContainsSingle(sample.ObservedFieldLines, "The delegate is called once for the request.");
        Assert.AreSequenceEqual(traceStateLines.ToArray(), observed.TraceStateLines.ToArray(), "The delegate sees every tracestate line whole, in received order.");

        IReadOnlyList<Activity> inTrace = TraceTreeAssertions.FilterByTrace(capture.StoppedActivities, ActivityTraceId.CreateFromString(ExampleTraceId));
        Activity dispatch = Assert.ContainsSingle(DispatchSpansOf(inTrace), "The dispatch span continues the presented trace.");
        if(expectedTraceState is null)
        {
            Assert.IsTrue(string.IsNullOrEmpty(dispatch.TraceStateString), "An empty tracestate line carries no list member.");
        }
        else
        {
            Assert.AreEqual(expectedTraceState, dispatch.TraceStateString);
            Assert.HasCount(expectedTraceState.Length, dispatch.TraceStateString!);
        }
    }


    /// <summary>The row of two <c>tracestate</c> lines. A constant, not a property, because a DataRow attribute argument must be a compile-time constant.</summary>
    private const string TwoTraceStateLinesRow = "two-tracestate-lines";

    /// <summary>The row of one <c>tracestate</c> line of 512 characters. A constant, not a property, because a DataRow attribute argument must be a compile-time constant.</summary>
    private const string TraceStateOf512CharactersRow = "tracestate-of-512-characters";

    /// <summary>The row of one empty <c>tracestate</c> line. A constant, not a property, because a DataRow attribute argument must be a compile-time constant.</summary>
    private const string EmptyTraceStateLineRow = "empty-tracestate-line";


    /// <summary>
    /// A <c>tracestate</c> value of exactly 512 characters: 32 list members <c>mNN=</c> with lowercase hexadecimal values,
    /// joined by <c>,</c>, each key beginning with a lowercase letter (W3C Trace Context Level 1, Section 3.3.1.3.1).
    /// </summary>
    /// <returns>The value.</returns>
    private static string TraceStateOf512Characters()
    {
        //32 members and 31 commas leave 481 characters for the members: 31 of 15 characters and one of 16.
        List<string> members = [];
        for(int index = 0; index < 32; index++)
        {
            int valueLength = index == 0 ? 12 : 11;
            string key = "m" + index.ToString("D2", CultureInfo.InvariantCulture);
            members.Add(key + "=" + new string((char)('a' + (index % 6)), valueLength));
        }

        string value = string.Join(',', members);
        Assert.HasCount(512, value, "The value is exactly 512 characters.");

        return value;
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#trace-id">W3C Trace Context Level 1, Section
    /// 3.2.2.3</see>: "If the trace-id value is invalid (for example if it contains non-allowed characters or all zeros),
    /// vendors MUST ignore the traceparent."; <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#parent-id">Section
    /// 3.2.2.4</see>: "Vendors MUST ignore the traceparent when the parent-id is invalid (for example, if it contains
    /// non-lowercase hex characters)."; <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#version">Section
    /// 3.2.2.1</see>: "Version ff is invalid."; <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#tracestate-header">Section
    /// 3.3</see>: "If the vendor failed to parse traceparent, it MUST NOT attempt to parse tracestate." A
    /// <c>client_credentials</c> token request sent over a raw TLS connection with the row's invalid <c>traceparent</c> and
    /// <c>tracestate: congo=t61rcWkgMzE</c> is answered 200, and the dispatch span the application's delegate starts is in a
    /// new trace: its trace-id is neither the presented one nor all zeros, and it carries no tracestate.
    /// </summary>
    /// <param name="traceParent">The invalid <c>traceparent</c> value.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("00-00000000000000000000000000000000-b7ad6b7169203331-01")]
    [DataRow("00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01")]
    [DataRow("00-0af7651916cd43dd8448eb211c80319c-B7AD6B7169203331-01")]
    [DataRow("ff-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")]
    public async Task AnInvalidTraceparentIsIgnoredByTheApplicationsPropagatorAsync(string traceParent)
    {
        SampleTracing sample = new();
        using TraceTreeCapture capture = new([SampleTracing.SourceName, ServerActivitySource.SourceName]);
        string handle = await SendTokenRequestWithTraceFieldsAsync(
            sample,
            [new(WellKnownHttpHeaderNames.TraceParent, traceParent), new(WellKnownHttpHeaderNames.TraceState, ExampleTraceState)]).ConfigureAwait(false);

        Activity dispatch = Assert.ContainsSingle(
            DispatchSpansOf(capture.StoppedActivities).Where(activity =>
                string.Equals(activity.GetTagItem(ServerTagNames.TenantHandle) as string, handle, StringComparison.Ordinal)
                && string.Equals(activity.Source.Name, SampleTracing.SourceName, StringComparison.Ordinal)),
            "The application's delegate starts the request's dispatch span.");
        string presentedTraceId = traceParent.Split('-')[1];
        Assert.AreNotEqual(presentedTraceId, dispatch.TraceId.ToHexString(), "The dispatch span does not continue the presented trace-id.");
        Assert.AreNotEqual(new string('0', 32), dispatch.TraceId.ToHexString(), "The dispatch span's trace-id is not all zeros.");
        Assert.IsTrue(string.IsNullOrEmpty(dispatch.TraceStateString), "The tracestate of an ignored traceparent is not parsed.");
    }


    /// <summary>
    /// <see href="https://opentelemetry.io/docs/specs/semconv/http/http-spans/">OpenTelemetry semantic conventions for HTTP
    /// spans</see>: "For HTTP status codes in the 4xx range span status MUST be left unset in case of SpanKind.SERVER",
    /// "For HTTP status codes in the 5xx range, as well as any other code the client failed to interpret, span status
    /// SHOULD be set to Error." and "If response status code was sent or received and status indicates an error according
    /// to HTTP span status definition, error.type SHOULD be set to the status code number (represented as a string)". With
    /// the delegate unwired, a request the authorization server answers 500 over the wire, the protected resource metadata
    /// of a resource requiring DPoP-bound access tokens whose contribution states otherwise, has a dispatch span with status
    /// <c>Error</c>, <c>error.type</c> <c>500</c>, <c>server.response.status_code</c> <c>500</c> and
    /// <c>server.response.error_code</c> <c>server_error</c>; a token request without <c>grant_type</c>, answered 400,
    /// has status <c>Unset</c>, no <c>error.type</c> and <c>server.response.error_code</c> <c>invalid_request</c>.
    /// </summary>
    /// <param name="statusCode">The status code the request is answered with.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(500)]
    [DataRow(400)]
    public async Task DispatchSpanOfAServerErrorCarriesTheErrorStatusAsync(int statusCode)
    {
        using TraceTreeCapture capture = new(CapturedSourceNames);
        using Activity root = new(nameof(DispatchSpanOfAServerErrorCarriesTheErrorStatusAsync));
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = statusCode switch
            {
                500 => await RegisterProtectedResourceAsync(host).ConfigureAwait(false),
                _ => await host.RegisterDpopClientAsync(MachineClientId, new Uri(MachineClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false)
            };
            Uri target = statusCode switch
            {
                500 => await ContradictingMetadataUrlAsync(host, material).ConfigureAwait(false),
                _ => await StartTokenEndpointAsync(host, material, isDpopEnabled: false).ConfigureAwait(false)
            };
            using HttpClient client = LoopbackTls.CreateTracedPinnedHttpClient([host.ServerCertificate], isSingleHop: true);

            _ = root.Start();
            using HttpResponseMessage response = statusCode switch
            {
                500 => await client.GetAsync(target, TestContext.CancellationToken).ConfigureAwait(false),
                _ => await OAuthTestTransport.PostFormAsync(
                    client, target, new Dictionary<string, string> { [OAuthRequestParameterNames.ClientId] = MachineClientId },
                    TestContext.CancellationToken).ConfigureAwait(false)
            };
            string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
            Assert.AreEqual(statusCode, (int)response.StatusCode, body);
        }

        root.Stop();
        Activity dispatch = Assert.ContainsSingle(
            DispatchSpansOf(TraceTreeAssertions.FilterByTrace(capture.StoppedActivities, root.TraceId)), "The trace holds one dispatch span.");
        Assert.AreEqual(statusCode.ToString(CultureInfo.InvariantCulture), dispatch.GetTagItem(ServerTagNames.StatusCode) as string);
        if(statusCode >= 500)
        {
            Assert.AreEqual(ActivityStatusCode.Error, dispatch.Status, "A 5xx answer sets the span status to Error.");
            Assert.AreEqual("500", dispatch.GetTagItem(ServerTagNames.ErrorType) as string, "A 5xx answer names its status code as error.type.");
            Assert.AreEqual(OAuthErrors.ServerError, dispatch.GetTagItem(ServerTagNames.ErrorCode) as string);
        }
        else
        {
            Assert.AreEqual(ActivityStatusCode.Unset, dispatch.Status, "A 4xx answer leaves the span status unset.");
            Assert.IsNull(dispatch.GetTagItem(ServerTagNames.ErrorType), "A 4xx answer sets no error.type.");
            Assert.AreEqual(OAuthErrors.InvalidRequest, dispatch.GetTagItem(ServerTagNames.ErrorCode) as string);
        }
    }


    /// <summary>
    /// The live configuration rule of the server (<c>documents/AuthorizationServerDesign.md</c>, Section 4.1): a wiring
    /// member altered under traffic governs every later request. Two <c>client_credentials</c> token requests sent over the
    /// wire, the first before <see cref="ServerIntegration.StartTraceActivity"/> is wired through an alteration and the
    /// second after it, are both answered 200; the first request's dispatch span is the library's static source's, the
    /// second's the application's.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DispatchSpanFollowsTheSlotAcrossALiveAlterationAsync()
    {
        SampleTracing sample = new();
        using TraceTreeCapture capture = new(CapturedSourceNames);
        using Activity firstRoot = new("before-the-alteration");
        using Activity secondRoot = new("after-the-alteration");
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await RegisterMachineClientAsync(host).ConfigureAwait(false);
            Uri tokenUrl = await StartTokenEndpointAsync(host, material, isDpopEnabled: false).ConfigureAwait(false);
            using HttpClient client = LoopbackTls.CreateTracedPinnedHttpClient([host.ServerCertificate], isSingleHop: true);

            _ = firstRoot.Start();
            await PostMachineTokenRequestAsync(host, client, tokenUrl).ConfigureAwait(false);
            firstRoot.Stop();

            await TestHostShell.AlterAsync(host.Server, candidate => candidate.StartTraceActivity = sample.StartServerActivity).ConfigureAwait(false);

            _ = secondRoot.Start();
            await PostMachineTokenRequestAsync(host, client, tokenUrl).ConfigureAwait(false);
            secondRoot.Stop();
        }

        Activity first = Assert.ContainsSingle(DispatchSpansOf(TraceTreeAssertions.FilterByTrace(capture.StoppedActivities, firstRoot.TraceId)));
        Activity second = Assert.ContainsSingle(DispatchSpansOf(TraceTreeAssertions.FilterByTrace(capture.StoppedActivities, secondRoot.TraceId)));
        Assert.AreEqual(ServerActivitySource.SourceName, first.Source.Name, "The request before the alteration is traced by the library's default.");
        Assert.AreEqual(SampleTracing.SourceName, second.Source.Name, "The request after the alteration is traced by the application's delegate.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "For such an access
    /// token, a resource server MUST check that a DPoP proof was also received in the DPoP header field of the HTTP
    /// request, check the DPoP proof according to the rules in Section 4.3, and check that the public key of the DPoP proof
    /// matches the public key to which the access token is bound per Section 6."; with
    /// <see href="https://opentelemetry.io/docs/specs/semconv/http/http-spans/">OpenTelemetry semantic conventions for HTTP
    /// spans</see>: "For HTTP status codes in the 4xx range span status MUST be left unset in case of SpanKind.SERVER". A
    /// DPoP-bound access token presented at an application's resource over the traced client, the resource's decision
    /// traced through <see cref="ResourceServerIntegration.StartTraceActivity"/>: with no <c>DPoP</c> field it is answered
    /// 401 <c>use_dpop_nonce</c> and the one <c>oauth.resource.decide</c> span, on the application's source,
    /// <see cref="ActivityKind.Internal"/>, a child of the resource server's <c>Microsoft.AspNetCore.Hosting.HttpRequestIn</c>
    /// span, carries <c>oauth.dpop.resource.decision</c> <c>Deny</c>, <c>oauth.dpop.resource.check</c>
    /// <c>proof_absent</c> and <c>server.response.error_code</c> <c>use_dpop_nonce</c> with status <c>Unset</c>; with a
    /// proof carrying the resource's nonce it is answered 200 and the span carries <c>Permit</c>, no check and no error
    /// code, with status <c>Unset</c>.
    /// </summary>
    /// <param name="row">Whether the presentation carries a proof.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(NoProofRow)]
    [DataRow(ProofWithTheNonceRow)]
    public async Task ApplicationResourceDecisionSpanCarriesTheDecisionAsync(string row)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using FreshDpopKey dpopKey = new();
        using TraceTreeCapture capture = new(CapturedSourceNames);
        using Activity root = new(nameof(ApplicationResourceDecisionSpanCarriesTheDecisionAsync));
        {
            await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey, SampleTracing.StartActivity).ConfigureAwait(false);
            string token = await IssueTokenAsync(asKeys.PrivateKey, await ThumbprintOfAsync(dpopKey.Key).ConfigureAwait(false)).ConfigureAwait(false);
            string? proof = row switch
            {
                ProofWithTheNonceRow => await BuildResourceProofAsync(
                    rs, dpopKey.Key, token, await ObtainResourceNonceAsync(rs, dpopKey.Key, token).ConfigureAwait(false)).ConfigureAwait(false),
                _ => null
            };
            using HttpClient client = LoopbackTls.CreateTracedPinnedHttpClient([rs.HttpCertificate!], isSingleHop: true);

            _ = root.Start();
            using HttpRequestMessage request = new(HttpMethod.Get, new Uri(rs.HttpBaseAddress!, "/protected"));
            _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.Authorization, $"DPoP {token}");
            if(proof is not null)
            {
                _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.DPoP, proof);
            }

            using HttpResponseMessage response = await client.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
            string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(row == NoProofRow ? 401 : 200, (int)response.StatusCode, body);
        }

        root.Stop();
        IReadOnlyList<Activity> inTrace = TraceTreeAssertions.FilterByTrace(capture.StoppedActivities, root.TraceId);
        Activity decide = Assert.ContainsSingle(DecideSpansOf(inTrace), "The trace holds one resource decision span.");
        Assert.AreEqual(SampleTracing.SourceName, decide.Source.Name, "The decision span is started on the application's source.");
        Assert.AreEqual(ActivityKind.Internal, decide.Kind);
        Activity requestIn = Assert.ContainsSingle(
            inTrace.Where(static activity => activity.Kind == ActivityKind.Server
                && string.Equals(activity.Source.Name, TraceTreeCapture.AspNetCoreSourceName, StringComparison.Ordinal)),
            "The resource server's host span is in the trace.");
        Assert.AreEqual(requestIn.SpanId, decide.ParentSpanId, "The decision span is a child of the resource server's host span.");
        Assert.AreEqual(row == NoProofRow ? nameof(DpopResourceDecisionKind.Deny) : nameof(DpopResourceDecisionKind.Permit),
            decide.GetTagItem(OAuthTagNames.DpopResourceDecision) as string);
        Assert.AreEqual(row == NoProofRow ? "proof_absent" : null, decide.GetTagItem(OAuthTagNames.DpopResourceCheck) as string);
        Assert.AreEqual(row == NoProofRow ? OAuthErrors.UseDpopNonce : null, decide.GetTagItem(ServerTagNames.ErrorCode) as string);
        Assert.AreEqual(ActivityStatusCode.Unset, decide.Status);
    }


    /// <summary>The row whose presentation carries no <c>DPoP</c> field. A constant, not a property, because a DataRow attribute argument must be a compile-time constant.</summary>
    private const string NoProofRow = "no-proof";

    /// <summary>The row whose presentation carries a proof with the resource's nonce. A constant, not a property, because a DataRow attribute argument must be a compile-time constant.</summary>
    private const string ProofWithTheNonceRow = "proof-with-the-nonce";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "The resource server
    /// MUST NOT grant access to the resource unless all checks are successful."; the checks of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see> ("There is not more than one DPoP
    /// HTTP request header field."), <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">Section 6.1</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">Section 11.1</see>; with
    /// <see href="https://opentelemetry.io/docs/specs/semconv/http/http-spans/">OpenTelemetry semantic conventions for HTTP
    /// spans</see>: "For HTTP status codes in the 5xx range, as well as any other code the client failed to interpret, span
    /// status SHOULD be set to Error." A presentation at an application's resource over a raw TLS connection inside the
    /// test's trace, its decision traced through the application's delegate, is refused and the
    /// <c>oauth.resource.decide</c> span names the check that refused: a proof by another key, 401 <c>invalid_token</c>,
    /// <c>Deny</c>, <c>key_binding</c>; two <c>DPoP</c> lines, 401 <c>invalid_dpop_proof</c>, <c>Deny</c>,
    /// <c>dpop_field_count</c>; an unbound token under <c>DPoP</c>, 401 <c>invalid_token</c>, <c>Deny</c>,
    /// <c>unbound_under_dpop</c>; the proof presented again, 401 <c>invalid_dpop_proof</c>, <c>Deny</c>, <c>jti</c>; the
    /// resource's DPoP checks unwired, 500 <c>server_error</c>, <c>IndeterminateDeny</c>, <c>checks_not_wired</c>, status
    /// <c>Error</c> and <c>error.type</c> <c>500</c>.
    /// </summary>
    /// <param name="row">The refused presentation.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(ProofByAnotherKeyRow)]
    [DataRow(TwoDpopLinesRow)]
    [DataRow(UnboundTokenUnderDpopRow)]
    [DataRow(ReplayedProofRow)]
    [DataRow(ChecksUnwiredRow)]
    public async Task ApplicationResourceDecisionSpanNamesTheRefusingCheckAsync(string row)
    {
        (int status, string error, string decision, string check) = row switch
        {
            ProofByAnotherKeyRow => (401, OAuthErrors.InvalidToken, nameof(DpopResourceDecisionKind.Deny), "key_binding"),
            TwoDpopLinesRow => (401, OAuthErrors.InvalidDpopProof, nameof(DpopResourceDecisionKind.Deny), "dpop_field_count"),
            UnboundTokenUnderDpopRow => (401, OAuthErrors.InvalidToken, nameof(DpopResourceDecisionKind.Deny), "unbound_under_dpop"),
            ReplayedProofRow => (401, OAuthErrors.InvalidDpopProof, nameof(DpopResourceDecisionKind.Deny), "jti"),
            ChecksUnwiredRow => (500, OAuthErrors.ServerError, nameof(DpopResourceDecisionKind.IndeterminateDeny), "checks_not_wired"),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown refusal row.")
        };

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using FreshDpopKey dpopKey = new();
        using FreshDpopKey otherKey = new();
        using TraceTreeCapture capture = new(CapturedSourceNames);
        using Activity root = new(nameof(ApplicationResourceDecisionSpanNamesTheRefusingCheckAsync));
        {
            await using TestResourceServerShell rs = await StartResourceServerAsync(
                asKeys.PublicKey, SampleTracing.StartActivity, isDpopProofValidationWired: row != ChecksUnwiredRow).ConfigureAwait(false);
            string boundToken = await IssueTokenAsync(asKeys.PrivateKey, await ThumbprintOfAsync(dpopKey.Key).ConfigureAwait(false)).ConfigureAwait(false);
            string token = row == UnboundTokenUnderDpopRow
                ? await IssueTokenAsync(asKeys.PrivateKey, boundThumbprint: null).ConfigureAwait(false)
                : boundToken;
            IReadOnlyList<string> dpopLines = row switch
            {
                ProofByAnotherKeyRow => [await BuildResourceProofAsync(rs, otherKey.Key, token, nonce: null).ConfigureAwait(false)],
                TwoDpopLinesRow =>
                [
                    await BuildResourceProofAsync(rs, dpopKey.Key, token, nonce: null).ConfigureAwait(false),
                    await BuildResourceProofAsync(rs, dpopKey.Key, token, nonce: null).ConfigureAwait(false)
                ],
                ReplayedProofRow => [await PresentOnceAsync(rs, dpopKey.Key, token).ConfigureAwait(false)],
                _ => []
            };

            _ = root.Start();
            HttpResponseData response = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", dpopLines, TraceParentOf(root)).ConfigureAwait(false);
            Assert.AreEqual(status, response.StatusCode, response.Body);
            using JsonDocument document = JsonDocument.Parse(response.Body);
            Assert.AreEqual(error, document.RootElement.GetProperty("error").GetString(), response.Body);
        }

        root.Stop();
        Activity decide = Assert.ContainsSingle(
            DecideSpansOf(TraceTreeAssertions.FilterByTrace(capture.StoppedActivities, root.TraceId)), "The trace holds one resource decision span.");
        Assert.AreEqual(decision, decide.GetTagItem(OAuthTagNames.DpopResourceDecision) as string);
        Assert.AreEqual(check, decide.GetTagItem(OAuthTagNames.DpopResourceCheck) as string, "The decision names the check that refused.");
        Assert.AreEqual(error, decide.GetTagItem(ServerTagNames.ErrorCode) as string);
        if(row == ChecksUnwiredRow)
        {
            Assert.AreEqual(ActivityStatusCode.Error, decide.Status, "A decision answered with a server error sets the span status to Error.");
            Assert.AreEqual("500", decide.GetTagItem(ServerTagNames.ErrorType) as string);
        }
        else
        {
            Assert.AreEqual(ActivityStatusCode.Unset, decide.Status, "A refusal answered 4xx leaves the span status unset.");
            Assert.IsNull(decide.GetTagItem(ServerTagNames.ErrorType));
        }
    }


    /// <summary>The row of a proof signed by a key the token is not bound to. A constant, not a property, because a DataRow attribute argument must be a compile-time constant.</summary>
    private const string ProofByAnotherKeyRow = "proof-by-another-key";

    /// <summary>The row of two <c>DPoP</c> field lines. A constant, not a property, because a DataRow attribute argument must be a compile-time constant.</summary>
    private const string TwoDpopLinesRow = "two-dpop-lines";

    /// <summary>The row of an unbound token under the <c>DPoP</c> scheme. A constant, not a property, because a DataRow attribute argument must be a compile-time constant.</summary>
    private const string UnboundTokenUnderDpopRow = "unbound-token-under-dpop";

    /// <summary>The row of a proof presented a second time. A constant, not a property, because a DataRow attribute argument must be a compile-time constant.</summary>
    private const string ReplayedProofRow = "replayed-proof";

    /// <summary>The row of a resource whose DPoP checks are unwired. A constant, not a property, because a DataRow attribute argument must be a compile-time constant.</summary>
    private const string ChecksUnwiredRow = "checks-unwired";


    /// <summary>
    /// <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#privacy-considerations">W3C Trace Context Level
    /// 1, Section 6</see>: "Tracing vendors MUST NOT use traceparent and tracestate fields for any personally identifiable
    /// or otherwise sensitive information.", held by the library for every attribute and event it emits; with
    /// <see href="https://opentelemetry.io/docs/specs/semconv/http/http-spans/">OpenTelemetry semantic conventions for HTTP
    /// spans</see>: "Including all request headers can be a security risk - explicit configuration helps avoid leaking
    /// sensitive information." In each row's flow over the wire, traced through the application's delegates, no value of a
    /// tag or event tag of the library's spans (<c>server.handle</c>, <c>oauth.resource.decide</c>), of their display name,
    /// status description and event names and of an event the library names, each element of an array value at every
    /// depth read as its own value, equals or contains the access token, a DPoP proof sent, a proof's <c>jti</c>, the
    /// <c>ath</c> a proof presented with the access token carries, the <c>x</c> and <c>y</c> coordinates of a proof's
    /// public JWK, a proof's <c>htu</c> or its <c>iat</c> as decimal seconds, a <c>DPoP-Nonce</c> value received, the proof
    /// key's JWK SHA-256 Thumbprint, the client
    /// secret, an <c>Authorization</c> field value, the tenant key or, at a resource, the end-user subject the access
    /// token names: a DPoP
    /// <c>client_credentials</c> token request with its nonce retry; a permitted presentation at an application's
    /// resource; a permitted DPoP presentation at UserInfo.
    /// </summary>
    /// <param name="row">The flow.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(TokenRequestWithNonceRetryRow)]
    [DataRow(ResourcePermitRow)]
    [DataRow(UserInfoPermitRow)]
    public async Task NoLibraryAttributeOrEventCarriesASecretAsync(string row)
    {
        using TraceTreeCapture capture = new(CapturedSourceNames);
        using Activity root = new(nameof(NoLibraryAttributeOrEventCarriesASecretAsync));
        IReadOnlyDictionary<string, string> secrets = row switch
        {
            TokenRequestWithNonceRetryRow => await TokenRequestWithNonceRetryAsync(root).ConfigureAwait(false),
            ResourcePermitRow => await ResourcePermitAsync(root).ConfigureAwait(false),
            UserInfoPermitRow => await UserInfoPermitAsync(root).ConfigureAwait(false),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown flow row.")
        };

        root.Stop();
        IReadOnlyList<Activity> inTrace = TraceTreeAssertions.FilterByTrace(capture.StoppedActivities, root.TraceId);
        (int expectedCount, int actualCount, string evidence) = row switch
        {
            TokenRequestWithNonceRetryRow => (2, DispatchSpansOf(inTrace).Count, "Both attempts of the token request are dispatched in the trace."),
            ResourcePermitRow => (1, DecideSpansOf(inTrace).Count(static activity => string.Equals(
                activity.GetTagItem(OAuthTagNames.DpopResourceDecision) as string, nameof(DpopResourceDecisionKind.Permit), StringComparison.Ordinal)),
                "The permitted presentation's decision span is in the trace."),
            _ => (1, inTrace.SelectMany(static activity => activity.Events).Count(static activityEvent =>
                string.Equals(activityEvent.Name, OAuthEventNames.DpopResourceDecided, StringComparison.Ordinal)
                && string.Equals(EventTagOf(activityEvent, OAuthTagNames.DpopResourceDecision), nameof(DpopResourceDecisionKind.Permit), StringComparison.Ordinal)),
                "The permitted presentation's decision event is in the trace.")
        };
        Assert.AreEqual(expectedCount, actualCount, evidence);
        AssertNoLibraryValueCarriesASecret(inTrace, secrets);
    }


    /// <summary>The row of a DPoP <c>client_credentials</c> token request with its nonce retry. A constant, not a property, because a DataRow attribute argument must be a compile-time constant.</summary>
    private const string TokenRequestWithNonceRetryRow = "token-request-with-nonce-retry";

    /// <summary>The row of a permitted presentation at an application's resource. A constant, not a property, because a DataRow attribute argument must be a compile-time constant.</summary>
    private const string ResourcePermitRow = "resource-permit";

    /// <summary>The row of a permitted DPoP presentation at UserInfo. A constant, not a property, because a DataRow attribute argument must be a compile-time constant.</summary>
    private const string UserInfoPermitRow = "userinfo-permit";


    /// <summary>
    /// <see href="https://opentelemetry.io/docs/specs/semconv/http/http-spans/">OpenTelemetry semantic conventions for HTTP
    /// spans</see>: "When instrumentation detects such errors it SHOULD set span status to Error and SHOULD set the
    /// error.type attribute." and "If the request fails with an error before response status code was sent or received,
    /// error.type SHOULD be set to exception type (its fully-qualified class name, if applicable) or a component-specific
    /// low cardinality error identifier."; with
    /// <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#privacy-considerations">W3C Trace Context Level
    /// 1, Section 6</see>: "Tracing vendors MUST NOT use traceparent and tracestate fields for any personally identifiable
    /// or otherwise sensitive information.", held by the library for every attribute and event it emits, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "The resource server
    /// MUST NOT grant access to the resource unless all checks are successful." A permitted presentation at an
    /// application's resource over the traced client, the decision traced through the application's delegate, whose
    /// <c>jti</c> record throws an <see cref="InvalidOperationException"/> whose message names the proof's <c>jti</c> and
    /// the access token, is answered 500 with no permit; the trace holds one <c>oauth.resource.decide</c> span, stopped,
    /// with status <c>Error</c> and <c>error.type</c> <c>System.InvalidOperationException</c>, no
    /// <c>oauth.dpop.resource.decision</c> tag and no event; and no value of a tag or event tag of the library's spans, its
    /// status description, its display name or an event name carries the access token, the proof, its <c>jti</c>,
    /// <c>ath</c>, <c>htu</c> or <c>iat</c>, the <c>x</c> and <c>y</c> coordinates of its public JWK, the
    /// <c>DPoP-Nonce</c> value, the proof key's JWK SHA-256 Thumbprint, the <c>Authorization</c> field value or the
    /// token's subject.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnExceptionOfADecisionSlotIsRecordedByItsTypeAloneAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using FreshDpopKey dpopKey = new();
        using TraceTreeCapture capture = new(CapturedSourceNames);
        using Activity root = new(nameof(AnExceptionOfADecisionSlotIsRecordedByItsTypeAloneAsync));
        string thumbprint = await ThumbprintOfAsync(dpopKey.Key).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, thumbprint).ConfigureAwait(false);
        string jti = Guid.NewGuid().ToString("N");
        IReadOnlyDictionary<string, string> secrets;
        {
            await using TestResourceServerShell rs = await StartResourceServerAsync(
                asKeys.PublicKey,
                SampleTracing.StartActivity,
                wrapDpopProofJtiClaim: _ => (presentedJti, _, _, _, _) =>
                    throw new InvalidOperationException($"The jti store refused the proof jti {presentedJti} presented with {token}.")).ConfigureAwait(false);
            string nonce = await ObtainResourceNonceAsync(rs, dpopKey.Key, token).ConfigureAwait(false);
            string proof = await BuildResourceProofAsync(rs, dpopKey.Key, token, nonce, jti).ConfigureAwait(false);
            using HttpClient client = LoopbackTls.CreateTracedPinnedHttpClient([rs.HttpCertificate!], isSingleHop: true);

            _ = root.Start();
            using HttpResponseMessage response = await SendProtectedAsync(client, rs, token, proof).ConfigureAwait(false);
            string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(500, (int)response.StatusCode, "The presentation is answered as a server error, with no permit.");
            Assert.DoesNotContain("\"sub\"", body, "No claim of the token is served.");

            secrets = WithAll(
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["access token"] = token,
                    ["proof"] = proof,
                    ["proof jti"] = jti,
                    ["proof ath"] = await ResourceDpopProofs.ComputeAthAsync(token, TestContext.CancellationToken).ConfigureAwait(false),
                    ["DPoP-Nonce"] = nonce,
                    ["proof key thumbprint"] = thumbprint,
                    ["Authorization"] = $"DPoP {token}",
                    ["subject"] = ResourceSubject
                },
                ProofValuesOf("proof", dpopKey.Key, ResourceProofHtuOf(rs), NowInstant));
        }

        root.Stop();
        IReadOnlyList<Activity> inTrace = TraceTreeAssertions.FilterByTrace(capture.StoppedActivities, root.TraceId);
        Activity decide = Assert.ContainsSingle(DecideSpansOf(inTrace), "The trace holds one resource decision span.");
        Assert.IsTrue(decide.IsStopped, "The decision span is stopped.");
        Assert.AreEqual(ActivityStatusCode.Error, decide.Status, "An exception a slot raises sets the span status to Error.");
        AssertNoLibraryValueCarriesASecret(inTrace, secrets);
        Assert.AreEqual("System.InvalidOperationException", decide.GetTagItem(ServerTagNames.ErrorType) as string, "The exception is recorded by its type's fully-qualified name.");
        Assert.IsNull(decide.GetTagItem(OAuthTagNames.DpopResourceDecision), "An exception is no decision.");
        Assert.IsEmpty(decide.Events, "Nothing of the exception is recorded as an event.");
    }


    /// <summary>
    /// Asserts that no value <see cref="LibraryValuesOf"/> reads from <paramref name="inTrace"/> equals or contains
    /// (ordinal) a value of <paramref name="secrets"/>, naming every secret found by its key.
    /// </summary>
    /// <param name="inTrace">The spans of one trace.</param>
    /// <param name="secrets">The flow's secrets by name.</param>
    private static void AssertNoLibraryValueCarriesASecret(IReadOnlyList<Activity> inTrace, IReadOnlyDictionary<string, string> secrets)
    {
        List<string> values = LibraryValuesOf(inTrace);
        string[] leaks = [.. secrets
            .Where(secret => secret.Value.Length > 0 && values.Any(value => value.Contains(secret.Value, StringComparison.Ordinal)))
            .Select(static secret => secret.Key)];
        Assert.IsEmpty(leaks, $"No library attribute or event value carries a secret; found: {string.Join(", ", leaks)}.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#design-overview">W3C Trace Context Level 1,
    /// Section 2.3</see>: "At a minimum they MUST propagate the traceparent and tracestate headers and guarantee traces are
    /// not broken.", held by <see cref="StartTraceActivityDelegate"/>'s contract: "A returned activity that was already
    /// Activity.Current when the delegate was called is the application's own and is not stopped by the library." An
    /// unbound access token presented under <c>Bearer</c> at an application's resource over the traced client, the
    /// resource's <see cref="ResourceServerIntegration.StartTraceActivity"/> answering the activity current at the call, is
    /// answered 200; the activity current in the resource server's application when the decision returns is its host's
    /// <c>Microsoft.AspNetCore.Hosting.HttpRequestIn</c> span, not stopped then, and that span carries
    /// <c>oauth.dpop.resource.decision</c> <c>Permit</c> with no <c>oauth.dpop.resource.check</c> and no
    /// <c>server.response.error_code</c>; the trace is one connected tree holding no <c>oauth.resource.decide</c> span.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AResourceDelegateAnsweringTheCurrentActivityLeavesItRunningAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using TraceTreeCapture capture = new(CapturedSourceNames);
        using Activity root = new(nameof(AResourceDelegateAnsweringTheCurrentActivityLeavesItRunningAsync));
        (Activity? Activity, bool IsStopped) observed;
        {
            await using TestResourceServerShell rs = await StartResourceServerAsync(
                asKeys.PublicKey, static (_, _, _, _) => Activity.Current).ConfigureAwait(false);
            string token = await IssueTokenAsync(asKeys.PrivateKey, boundThumbprint: null).ConfigureAwait(false);
            using HttpClient client = LoopbackTls.CreateTracedPinnedHttpClient([rs.HttpCertificate!], isSingleHop: true);

            _ = root.Start();
            using HttpRequestMessage request = new(HttpMethod.Get, new Uri(rs.HttpBaseAddress!, "/protected"));
            _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.Authorization, $"Bearer {token}");
            using HttpResponseMessage response = await client.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
            string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, (int)response.StatusCode, body);
            observed = Assert.ContainsSingle(rs.AmbientActivitiesAfterDecision, "The resource decides once.");
        }

        root.Stop();
        IReadOnlyList<Activity> inTrace = TraceTreeAssertions.FilterByTrace(capture.StoppedActivities, root.TraceId);
        Activity requestIn = Assert.ContainsSingle(HostRequestSpansOf(inTrace), "The resource server's host span is in the trace.");
        Assert.AreSame(requestIn, observed.Activity, "The activity current when the decision returns is the host's request activity.");
        Assert.IsFalse(observed.IsStopped, "The library does not stop the activity that was current when its delegate was called.");
        Assert.AreEqual(nameof(DpopResourceDecisionKind.Permit), requestIn.GetTagItem(OAuthTagNames.DpopResourceDecision) as string);
        Assert.IsNull(requestIn.GetTagItem(OAuthTagNames.DpopResourceCheck), "A permit carries no refusing check.");
        Assert.IsNull(requestIn.GetTagItem(ServerTagNames.ErrorCode), "A permit carries no error code.");
        Assert.IsEmpty(DecideSpansOf(inTrace), "The library starts no span of its own.");
        TraceTreeAssertions.AssertSingleConnectedTree(capture.StoppedActivities, root);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#design-overview">W3C Trace Context Level 1,
    /// Section 2.3</see>: "At a minimum they MUST propagate the traceparent and tracestate headers and guarantee traces are
    /// not broken.", held by <see cref="StartTraceActivityDelegate"/>'s contract: "A returned activity that was already
    /// Activity.Current when the delegate was called is the application's own and is not stopped by the library." A
    /// <c>client_credentials</c> token request sent over the traced client to an authorization server whose
    /// <see cref="ServerIntegration.StartTraceActivity"/> answers the activity current at the call is answered 200; the
    /// activity current in the authorization server's application when the dispatch returns is its host's
    /// <c>Microsoft.AspNetCore.Hosting.HttpRequestIn</c> span, not stopped then, and that span carries the dispatch's
    /// <c>server.tenant.handle</c> and <c>server.response.status_code</c> <c>200</c>; the trace is one connected tree
    /// holding no <c>server.handle</c> span.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ADispatchDelegateAnsweringTheCurrentActivityLeavesItRunningAsync()
    {
        using TraceTreeCapture capture = new(CapturedSourceNames);
        using Activity root = new(nameof(ADispatchDelegateAnsweringTheCurrentActivityLeavesItRunningAsync));
        ConcurrentQueue<(Activity? Activity, bool IsStopped)> afterDispatch = new();
        string handle;
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await RegisterMachineClientAsync(host).ConfigureAwait(false);
            Uri tokenUrl = await StartTokenEndpointAsync(host, material, isDpopEnabled: false).ConfigureAwait(false);
            await TestHostShell.AlterAsync(host.Server, static candidate => candidate.StartTraceActivity = static (_, _, _, _) => Activity.Current).ConfigureAwait(false);
            host.Host("default").RewriteAnswer = (_, response) =>
            {
                Activity? current = Activity.Current;
                afterDispatch.Enqueue((current, current?.IsStopped ?? false));

                return response;
            };
            handle = material.Registration.TenantHandle!.Value.Value;
            using HttpClient client = LoopbackTls.CreateTracedPinnedHttpClient([host.ServerCertificate], isSingleHop: true);

            _ = root.Start();
            await PostMachineTokenRequestAsync(host, client, tokenUrl).ConfigureAwait(false);
        }

        root.Stop();
        (Activity? Activity, bool IsStopped) observed = Assert.ContainsSingle(afterDispatch, "The token request is dispatched once.");
        IReadOnlyList<Activity> inTrace = TraceTreeAssertions.FilterByTrace(capture.StoppedActivities, root.TraceId);
        Activity requestIn = Assert.ContainsSingle(HostRequestSpansOf(inTrace), "The authorization server's host span is in the trace.");
        Assert.AreSame(requestIn, observed.Activity, "The activity current when the dispatch returns is the host's request activity.");
        Assert.IsFalse(observed.IsStopped, "The library does not stop the activity that was current when its delegate was called.");
        Assert.AreEqual(handle, requestIn.GetTagItem(ServerTagNames.TenantHandle) as string);
        Assert.AreEqual("200", requestIn.GetTagItem(ServerTagNames.StatusCode) as string);
        Assert.IsEmpty(DispatchSpansOf(inTrace), "The library starts no span of its own.");
        TraceTreeAssertions.AssertSingleConnectedTree(capture.StoppedActivities, root);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "For such an access
    /// token, a resource server MUST check that a DPoP proof was also received in the DPoP header field of the HTTP
    /// request, check the DPoP proof according to the rules in Section 4.3, and check that the public key of the DPoP proof
    /// matches the public key to which the access token is bound per Section 6." and "The resource server MUST NOT grant
    /// access to the resource unless all checks are successful." A DPoP-bound access token presented at an application's
    /// resource whose <see cref="ResourceServerIntegration.StartTraceActivity"/> is unwired, over the traced client, first
    /// with no <c>DPoP</c> field and answered 401 <c>use_dpop_nonce</c>, then with a proof carrying the resource's nonce and
    /// answered 200: each request's host <c>Microsoft.AspNetCore.Hosting.HttpRequestIn</c> span carries exactly one
    /// <c>oauth.dpop.resource.decided</c> event, the refusal's with <c>oauth.dpop.resource.decision</c> <c>Deny</c>,
    /// <c>oauth.dpop.resource.check</c> <c>proof_absent</c> and <c>server.response.error_code</c> <c>use_dpop_nonce</c>,
    /// the permit's with <c>Permit</c> alone; and no <c>oauth.resource.decide</c> span is in the trace.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnUnwiredApplicationResourceRecordsEachDecisionAsAnEventAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using FreshDpopKey dpopKey = new();
        using TraceTreeCapture capture = new(CapturedSourceNames);
        using Activity root = new(nameof(AnUnwiredApplicationResourceRecordsEachDecisionAsAnEventAsync));
        {
            await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey, startTraceActivity: null).ConfigureAwait(false);
            string token = await IssueTokenAsync(asKeys.PrivateKey, await ThumbprintOfAsync(dpopKey.Key).ConfigureAwait(false)).ConfigureAwait(false);
            using HttpClient client = LoopbackTls.CreateTracedPinnedHttpClient([rs.HttpCertificate!], isSingleHop: true);

            _ = root.Start();
            using HttpRequestMessage withoutProof = new(HttpMethod.Get, new Uri(rs.HttpBaseAddress!, "/protected"));
            _ = withoutProof.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.Authorization, $"DPoP {token}");
            using HttpResponseMessage challenge = await client.SendAsync(withoutProof, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(401, (int)challenge.StatusCode, "The presentation without a proof is refused.");
            string nonce = ResourceDpopProofs.ReadNonce(challenge);
            string proof = await BuildResourceProofAsync(rs, dpopKey.Key, token, nonce).ConfigureAwait(false);
            using HttpResponseMessage response = await SendProtectedAsync(client, rs, token, proof).ConfigureAwait(false);
            string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, (int)response.StatusCode, body);
        }

        root.Stop();
        IReadOnlyList<Activity> inTrace = TraceTreeAssertions.FilterByTrace(capture.StoppedActivities, root.TraceId);
        Assert.IsEmpty(DecideSpansOf(inTrace), "With the slot unwired no decision span is started.");
        IReadOnlyList<Activity> requestIns = HostRequestSpansOf(inTrace);
        Assert.HasCount(2, requestIns, "Each presentation is one request at the resource server's host.");
        ActivityEvent[] decisionEvents = [.. requestIns.Select(static requestIn => Assert.ContainsSingle(
            requestIn.Events.Where(static activityEvent => string.Equals(activityEvent.Name, OAuthEventNames.DpopResourceDecided, StringComparison.Ordinal)),
            "Each request's host span carries one decision event."))];
        ActivityEvent refusal = Assert.ContainsSingle(
            decisionEvents.Where(static activityEvent => string.Equals(
                EventTagOf(activityEvent, OAuthTagNames.DpopResourceDecision), nameof(DpopResourceDecisionKind.Deny), StringComparison.Ordinal)),
            "One decision event records the refusal.");
        ActivityEvent permit = Assert.ContainsSingle(
            decisionEvents.Where(static activityEvent => string.Equals(
                EventTagOf(activityEvent, OAuthTagNames.DpopResourceDecision), nameof(DpopResourceDecisionKind.Permit), StringComparison.Ordinal)),
            "One decision event records the permit.");
        Assert.AreEqual("proof_absent", EventTagOf(refusal, OAuthTagNames.DpopResourceCheck), "The refusal names the check that refused.");
        Assert.AreEqual(OAuthErrors.UseDpopNonce, EventTagOf(refusal, ServerTagNames.ErrorCode));
        Assert.IsNull(EventTagOf(permit, OAuthTagNames.DpopResourceCheck), "A permit carries no refusing check.");
        Assert.IsNull(EventTagOf(permit, ServerTagNames.ErrorCode), "A permit carries no error code.");
    }


    /// <summary>The host framework's request spans, <c>Microsoft.AspNetCore.Hosting.HttpRequestIn</c>, among <paramref name="activities"/>.</summary>
    /// <param name="activities">The spans.</param>
    /// <returns>The host request spans.</returns>
    private static IReadOnlyList<Activity> HostRequestSpansOf(IEnumerable<Activity> activities) =>
        [.. activities.Where(static activity => activity.Kind == ActivityKind.Server
            && string.Equals(activity.Source.Name, TraceTreeCapture.AspNetCoreSourceName, StringComparison.Ordinal))];


    /// <summary>The value of the tag <paramref name="name"/> of <paramref name="activityEvent"/> as text, or <see langword="null"/> when the event carries none.</summary>
    /// <param name="activityEvent">The event.</param>
    /// <param name="name">The tag name.</param>
    /// <returns>The value.</returns>
    private static string? EventTagOf(ActivityEvent activityEvent, string name) =>
        activityEvent.Tags.FirstOrDefault(tag => string.Equals(tag.Key, name, StringComparison.Ordinal)).Value as string;


    /// <summary>
    /// <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#design-overview">W3C Trace Context Level 1,
    /// Section 2.3</see>: "At a minimum they MUST propagate the traceparent and tracestate headers and guarantee traces are
    /// not broken."; <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#mutating-the-traceparent-field">Section
    /// 3.4</see>: "A vendor receiving a traceparent request header MUST send it to outgoing requests." and "Vendors MUST
    /// NOT make any other mutations to the traceparent header."; <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#mutating-the-tracestate-field">Section
    /// 3.5</see>: "Vendors receiving a tracestate request header MUST send it to outgoing requests." An unbound access token
    /// presented under <c>Bearer</c> at an application's resource over the traced client, inside a root span carrying
    /// <c>tracestate</c> <c>congo=t61rcWkgMzE</c>, the resource resolving its verification key by fetching the
    /// authorization server's JWKS over the wire inside the request, both servers traced through the application's
    /// delegates, is answered 200 with the token's claims; the trace is one connected tree with a server span at each
    /// host; the authorization server's <c>server.handle</c> descends from the resource server's host span; the resource's
    /// <c>oauth.resource.decide</c> carries <c>Permit</c>; every span carries the root's tracestate; and the authorization
    /// server saw exactly one <c>traceparent</c> line on the JWKS request, whose parent-id is the resource server's client
    /// span's. That client span holds the HTTP client span vocabulary of
    /// <see href="https://opentelemetry.io/docs/specs/semconv/http/http-spans/#http-client-span">OpenTelemetry semantic
    /// conventions for HTTP spans, HTTP client span</see>: <c>http.request.method</c> "Required" "HTTP request method.",
    /// <c>GET</c>; <c>server.address</c> "Required" "Server domain name if available without reverse DNS lookup;
    /// otherwise, IP address or UNIX domain socket name.", the authorization server's host; <c>server.port</c>
    /// "Required" of type "int" "Server port number.", the listener's port; <c>http.response.status_code</c>
    /// "Conditionally Required If and only if one was received/sent." of type "int", <c>200</c>; and, the request having
    /// succeeded, no <c>error.type</c> ("If the request has completed successfully, instrumentations SHOULD NOT set
    /// error.type.") and the status left unset, the status <c>Error</c> being for a 4xx or 5xx answer ("For HTTP status
    /// codes in the 4xx range span status MUST be left unset in case of SpanKind.SERVER and SHOULD be set to Error in case
    /// of SpanKind.CLIENT.").
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResourceServerCallingTheAuthorizationServerFormsOneTraceAsync()
    {
        SampleTracing sample = new();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        ConcurrentBag<PublicKeyMemory> fetchedKeys = [];
        using TraceTreeCapture capture = new(CapturedSourceNames);
        using Activity root = new(nameof(ResourceServerCallingTheAuthorizationServerFormsOneTraceAsync));
        root.TraceStateString = ExampleTraceState;
        Uri asBaseAddress;
        Uri rsBaseAddress;
        Uri jwksUrl;
        try
        {
            await using TestHostShell host = new(TimeProvider);
            ClientRecord registration = await host.RegisterSigningClientAsync(
                "https://tracing.jwks.client.test", asKeys, ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);
            string kid = registration.SigningKeys[KeyUsageContext.AccessTokenIssuance].Current[0].Value;
            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            await TestHostShell.AlterAsync(host.Server, candidate => candidate.StartTraceActivity = sample.StartServerActivity).ConfigureAwait(false);
            asBaseAddress = host.Host("default").HttpBaseAddress!;
            jwksUrl = new Uri(asBaseAddress, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.MetadataJwks, registration.TenantId.Value));

            using HttpClient jwksClient = LoopbackTls.CreateTracedPinnedHttpClient([host.ServerCertificate], isSingleHop: true);
            await using TestResourceServerShell rs = new(
                trustedIssuer: new Uri(ResourceIssuer),
                expectedAudience: ResourceAudience,
                resolveVerificationKey: FetchJwksOnEveryCallResolver(jwksClient, jwksUrl, fetchedKeys),
                verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
                timeProvider: new FakeTimeProvider(NowInstant),
                startTraceActivity: SampleTracing.StartActivity);
            await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            rsBaseAddress = rs.HttpBaseAddress!;
            string token = await IssueTokenAsync(asKeys.PrivateKey, boundThumbprint: null, kid).ConfigureAwait(false);
            using HttpClient client = LoopbackTls.CreateTracedPinnedHttpClient([rs.HttpCertificate!], isSingleHop: true);

            _ = root.Start();
            using HttpRequestMessage request = new(HttpMethod.Get, new Uri(rsBaseAddress, "/protected"));
            _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.Authorization, $"Bearer {token}");
            using HttpResponseMessage response = await client.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
            string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The JWKS requests are answered without a server fault.");
            Assert.AreEqual(200, (int)response.StatusCode, body);
            using JsonDocument document = JsonDocument.Parse(body);
            Assert.AreEqual(ResourceSubject, document.RootElement.GetProperty("sub").GetString(), body);
        }
        finally
        {
            foreach(PublicKeyMemory fetchedKey in fetchedKeys)
            {
                fetchedKey.Dispose();
            }
        }

        root.Stop();
        IReadOnlyList<Activity> captured = capture.StoppedActivities;
        IReadOnlyList<Activity> inTrace = TraceTreeAssertions.FilterByTrace(captured, root.TraceId);
        TraceTreeAssertions.AssertSingleConnectedTree(captured, root);
        TraceTreeAssertions.AssertSpanForEachHost(captured, root, [rsBaseAddress, asBaseAddress]);

        Activity rsClientSpan = ClientSpanTo(inTrace, new Uri(rsBaseAddress, "/protected"));
        Activity rsRequestIn = Assert.ContainsSingle(
            inTrace.Where(activity => activity.Kind == ActivityKind.Server && activity.ParentSpanId == rsClientSpan.SpanId),
            "The resource server's host span is the child of the test's client span.");
        Activity asDispatch = Assert.ContainsSingle(DispatchSpansOf(inTrace), "The authorization server dispatches one request in the trace.");
        Assert.AreEqual(SampleTracing.SourceName, asDispatch.Source.Name, "The authorization server's dispatch span is started by the application's delegate.");
        Assert.IsTrue(IsDescendantOf(asDispatch, rsRequestIn.SpanId, inTrace), "The authorization server's dispatch span descends from the resource server's host span.");
        Activity decide = Assert.ContainsSingle(DecideSpansOf(inTrace), "The resource decides once in the trace.");
        Assert.AreEqual(SampleTracing.SourceName, decide.Source.Name, "The resource decision span is started by the application's delegate.");
        Assert.AreEqual(nameof(DpopResourceDecisionKind.Permit), decide.GetTagItem(OAuthTagNames.DpopResourceDecision) as string);
        string[] spansWithoutTheTraceState = [.. inTrace
            .Where(static activity => !string.Equals(activity.TraceStateString, ExampleTraceState, StringComparison.Ordinal))
            .Select(static activity => activity.OperationName)];
        Assert.IsEmpty(spansWithoutTheTraceState, $"Every span carries the root's tracestate; these do not: {string.Join(", ", spansWithoutTheTraceState)}.");

        Activity jwksClientSpan = ClientSpanTo(inTrace, jwksUrl);
        Assert.AreEqual("GET", jwksClientSpan.GetTagItem("http.request.method") as string, "The client span names the request method.");
        Assert.AreEqual(asBaseAddress.Host, jwksClientSpan.GetTagItem("server.address") as string, "The client span names the authorization server's host.");
        int serverPort = Assert.IsInstanceOfType<int>(jwksClientSpan.GetTagItem("server.port"), "The client span's server.port is an int.");
        Assert.AreEqual(asBaseAddress.Port, serverPort, "The client span names the authorization server's listener port.");
        int responseStatusCode = Assert.IsInstanceOfType<int>(jwksClientSpan.GetTagItem("http.response.status_code"), "The client span's http.response.status_code is an int.");
        Assert.AreEqual(200, responseStatusCode, "The client span carries the status code received.");
        Assert.AreEqual(ActivityStatusCode.Unset, jwksClientSpan.Status, "A successful request leaves the client span's status unset.");
        Assert.IsNull(jwksClientSpan.GetTagItem(ServerTagNames.ErrorType), "A successful request sets no error.type.");
        ObservedTraceFieldLines observed = Assert.ContainsSingle(sample.ObservedFieldLines, "The authorization server is called once.");
        string traceParent = Assert.ContainsSingle(observed.TraceParentLines, "The JWKS request carries one traceparent line.");
        Assert.AreEqual(jwksClientSpan.SpanId.ToHexString(), traceParent.Split('-')[2], "The traceparent's parent-id is the resource server's client span.");
    }


    /// <summary>
    /// Registers the <c>client_credentials</c> client of the authorization server rows under <c>client_secret_post</c>,
    /// with the server checking its secret.
    /// </summary>
    /// <param name="host">The host.</param>
    /// <returns>The registration's key material; the caller disposes it.</returns>
    private async Task<VerifierKeyMaterial> RegisterMachineClientAsync(TestHostShell host)
    {
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthClientCredentials,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);
        VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            MachineClientId, new Uri(MachineClientId), profile: PolicyProfile.Rfc6749WithPkce, capabilities: capabilities).ConfigureAwait(false);
        _ = await host.SetTokenEndpointAuthMethodAsync(
            material, ClientAuthenticationMethod.ClientSecretPost, clientJwks: null, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, static candidate =>
        {
            candidate.ClientAuthenticationMethodsSupported = [ClientAuthenticationMethod.None, ClientAuthenticationMethod.ClientSecretPost];
            candidate.ValidateClientCredentialsAsync = static (reading, registration, context, ct) => ValueTask.FromResult(
                reading.ClientSecret is string secret && string.Equals(secret, MachineClientSecret, StringComparison.Ordinal));
        }).ConfigureAwait(false);

        return material;
    }


    /// <summary>
    /// Starts the host's listener, with DPoP enabled and the registration aligned to the listener's address when
    /// <paramref name="isDpopEnabled"/>, and answers the registration's token endpoint URL on it.
    /// </summary>
    /// <param name="host">The host.</param>
    /// <param name="material">The registration.</param>
    /// <param name="isDpopEnabled">Whether the token endpoint validates DPoP proofs.</param>
    /// <returns>The absolute token endpoint URL.</returns>
    private async Task<Uri> StartTokenEndpointAsync(TestHostShell host, VerifierKeyMaterial material, bool isDpopEnabled)
    {
        if(isDpopEnabled)
        {
            _ = await host.EnableDpopAsync().ConfigureAwait(false);
        }

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        if(isDpopEnabled)
        {
            material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);
        }

        return new Uri(
            host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, material.Registration.TenantId.Value));
    }


    /// <summary>The form fields of the <c>client_credentials</c> token request under <c>client_secret_post</c>.</summary>
    /// <returns>The fields.</returns>
    private static Dictionary<string, string> MachineTokenRequestFields() => new(StringComparer.Ordinal)
    {
        [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
        [OAuthRequestParameterNames.ClientId] = MachineClientId,
        [OAuthRequestParameterNames.ClientSecret] = MachineClientSecret
    };


    /// <summary>Sends the <c>client_credentials</c> token request over <paramref name="client"/> and asserts it is answered 200 without a server fault.</summary>
    /// <param name="host">The host.</param>
    /// <param name="client">The client.</param>
    /// <param name="tokenUrl">The token endpoint URL.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task PostMachineTokenRequestAsync(TestHostShell host, HttpClient client, Uri tokenUrl)
    {
        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            client, tokenUrl, MachineTokenRequestFields(), TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The token request is answered without a server fault.");
        Assert.AreEqual(200, (int)response.StatusCode, body);
    }


    /// <summary>
    /// Sends the <c>client_credentials</c> token request over a raw TLS connection with <paramref name="traceFieldLines"/>
    /// before its own field lines, to a host whose dispatch is traced through <paramref name="sample"/>'s server delegate,
    /// and asserts it is answered 200 without a server fault; the host is disposed before the method returns, so every span
    /// of the request has stopped.
    /// </summary>
    /// <param name="sample">The application's tracing.</param>
    /// <param name="traceFieldLines">The trace field lines, each sent as its own line in the order given.</param>
    /// <returns>The registration's tenant handle.</returns>
    private async Task<string> SendTokenRequestWithTraceFieldsAsync(SampleTracing sample, IReadOnlyList<KeyValuePair<string, string>> traceFieldLines)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(host).ConfigureAwait(false);
        Uri tokenUrl = await StartTokenEndpointAsync(host, material, isDpopEnabled: false).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidate => candidate.StartTraceActivity = sample.StartServerActivity).ConfigureAwait(false);

        List<KeyValuePair<string, string>> fieldLines = [.. traceFieldLines];
        fieldLines.Add(new(WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.FormUrlEncoded));
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, tokenUrl, fieldLines, RawHttpsRequest.FormBody(MachineTokenRequestFields()),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The token request is answered without a server fault.");
        Assert.AreEqual(200, response.StatusCode, response.Body);

        return material.Registration.TenantHandle!.Value.Value;
    }


    /// <summary>
    /// Registers a protected resource co-located with the server: the RFC 9728 metadata capability with discovery and
    /// JWKS, so the document is served at the registration's issuer.
    /// </summary>
    /// <param name="host">The host.</param>
    /// <returns>The registration's key material; the caller disposes it.</returns>
    private static Task<VerifierKeyMaterial> RegisterProtectedResourceAsync(TestHostShell host) =>
        host.RegisterClientAsync(
            MachineClientId,
            new Uri(MachineClientId),
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));


    /// <summary>
    /// Wires the server's resources to require DPoP-bound access tokens while the resource's metadata contribution states
    /// <c>dpop_bound_access_tokens_required: false</c>, so the document cannot be served and its request is answered 500;
    /// starts the listener, reads the issuer from discovery and answers the protected resource metadata URL on the listener.
    /// </summary>
    /// <param name="host">The host.</param>
    /// <param name="material">The resource's registration.</param>
    /// <returns>The metadata URL.</returns>
    private async Task<Uri> ContradictingMetadataUrlAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        ProtectedResourceMetadataContribution contribution = new() { DpopBoundAccessTokensRequired = false };
        await TestHostShell.AlterAsync(host.Server, candidate =>
            candidate.ContributeProtectedResourceMetadataAsync = (_, _, _) => ValueTask.FromResult(contribution)).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, static candidate =>
            candidate.IsDpopBoundAccessTokenRequiredAtResources = true).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        Uri discoveryUrl = new(hosted.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/.well-known/openid-configuration");
        using HttpResponseMessage discovery = await hosted.SharedHttpClient!.GetAsync(discoveryUrl, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await discovery.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)discovery.StatusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Uri metadataUrl = WellKnownPaths.OAuthProtectedResource.ComputeUri(document.RootElement.GetProperty("issuer").GetString()!);

        return new Uri(hosted.HttpBaseAddress!, metadataUrl.AbsolutePath);
    }


    /// <summary>
    /// The DPoP <c>client_credentials</c> token request with its nonce retry, inside <paramref name="root"/>: a proof
    /// without a nonce answered 400 <c>use_dpop_nonce</c> with one <c>DPoP-Nonce</c>, then a proof carrying it answered
    /// 200, the host traced through the application's server delegate.
    /// </summary>
    /// <param name="root">The test's root span, started here.</param>
    /// <returns>The flow's secrets by name.</returns>
    private async Task<IReadOnlyDictionary<string, string>> TokenRequestWithNonceRetryAsync(Activity root)
    {
        SampleTracing sample = new();
        using FreshDpopKey dpopKey = new();
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(host).ConfigureAwait(false);
        Uri tokenUrl = await StartTokenEndpointAsync(host, material, isDpopEnabled: true).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidate => candidate.StartTraceActivity = sample.StartServerActivity).ConfigureAwait(false);
        using HttpClient client = LoopbackTls.CreateTracedPinnedHttpClient([host.ServerCertificate], isSingleHop: true);
        string firstJti = Guid.NewGuid().ToString("N");
        string secondJti = Guid.NewGuid().ToString("N");

        _ = root.Start();
        DateTimeOffset firstIssuedAt = TimeProvider.GetUtcNow();
        string firstProof = await ResourceDpopProofs.BuildAsync(
            dpopKey.Key, WellKnownHttpMethods.Post, tokenUrl.OriginalString, accessToken: null, nonce: null, firstIssuedAt,
            TestContext.CancellationToken, firstJti).ConfigureAwait(false);
        using HttpResponseMessage challenge = await OAuthTestTransport.PostFormAsync(
            client, tokenUrl, MachineTokenRequestFields(), OutgoingHeaders.Empty.WithDpop(firstProof), TestContext.CancellationToken).ConfigureAwait(false);
        string challengeBody = await challenge.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)challenge.StatusCode, challengeBody);
        string nonce = ResourceDpopProofs.ReadNonce(challenge);

        DateTimeOffset secondIssuedAt = TimeProvider.GetUtcNow();
        string secondProof = await ResourceDpopProofs.BuildAsync(
            dpopKey.Key, WellKnownHttpMethods.Post, tokenUrl.OriginalString, accessToken: null, nonce, secondIssuedAt,
            TestContext.CancellationToken, secondJti).ConfigureAwait(false);
        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            client, tokenUrl, MachineTokenRequestFields(), OutgoingHeaders.Empty.WithDpop(secondProof), TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The token requests are answered without a server fault.");
        Assert.AreEqual(200, (int)response.StatusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        string accessToken = document.RootElement.GetProperty(OAuthRequestParameterNames.AccessToken).GetString()!;

        return WithAll(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["access token"] = accessToken,
                ["access token ath"] = await ResourceDpopProofs.ComputeAthAsync(accessToken, TestContext.CancellationToken).ConfigureAwait(false),
                ["first proof"] = firstProof,
                ["second proof"] = secondProof,
                ["first proof jti"] = firstJti,
                ["second proof jti"] = secondJti,
                ["DPoP-Nonce"] = nonce,
                ["proof key thumbprint"] = await ThumbprintOfAsync(dpopKey.Key).ConfigureAwait(false),
                ["client secret"] = MachineClientSecret,
                ["tenant key"] = material.Registration.TenantId.Value
            },
            [
                .. ProofValuesOf("first proof", dpopKey.Key, tokenUrl.OriginalString, firstIssuedAt),
                .. ProofValuesOf("second proof", dpopKey.Key, tokenUrl.OriginalString, secondIssuedAt)
            ]);
    }


    /// <summary>
    /// A permitted presentation at an application's resource over the traced client, inside <paramref name="root"/>: a
    /// proof without a nonce answered with the resource's nonce challenge, then a proof carrying the nonce answered 200,
    /// the decision traced through the application's delegate.
    /// </summary>
    /// <param name="root">The test's root span, started here.</param>
    /// <returns>The flow's secrets by name.</returns>
    private async Task<IReadOnlyDictionary<string, string>> ResourcePermitAsync(Activity root)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> asKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using FreshDpopKey dpopKey = new();
        await using TestResourceServerShell rs = await StartResourceServerAsync(asKeys.PublicKey, SampleTracing.StartActivity).ConfigureAwait(false);
        string thumbprint = await ThumbprintOfAsync(dpopKey.Key).ConfigureAwait(false);
        string token = await IssueTokenAsync(asKeys.PrivateKey, thumbprint).ConfigureAwait(false);
        string firstJti = Guid.NewGuid().ToString("N");
        string secondJti = Guid.NewGuid().ToString("N");
        using HttpClient client = LoopbackTls.CreateTracedPinnedHttpClient([rs.HttpCertificate!], isSingleHop: true);

        _ = root.Start();
        string firstProof = await BuildResourceProofAsync(rs, dpopKey.Key, token, nonce: null, firstJti).ConfigureAwait(false);
        using HttpResponseMessage challenge = await SendProtectedAsync(client, rs, token, firstProof).ConfigureAwait(false);
        Assert.AreEqual(401, (int)challenge.StatusCode);
        string nonce = ResourceDpopProofs.ReadNonce(challenge);
        string secondProof = await BuildResourceProofAsync(rs, dpopKey.Key, token, nonce, secondJti).ConfigureAwait(false);
        using HttpResponseMessage response = await SendProtectedAsync(client, rs, token, secondProof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        return WithAll(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["access token"] = token,
                ["first proof"] = firstProof,
                ["second proof"] = secondProof,
                ["first proof jti"] = firstJti,
                ["second proof jti"] = secondJti,
                ["proof ath"] = await ResourceDpopProofs.ComputeAthAsync(token, TestContext.CancellationToken).ConfigureAwait(false),
                ["DPoP-Nonce"] = nonce,
                ["proof key thumbprint"] = thumbprint,
                ["Authorization"] = $"DPoP {token}",
                ["subject"] = ResourceSubject
            },
            [
                .. ProofValuesOf("first proof", dpopKey.Key, ResourceProofHtuOf(rs), NowInstant),
                .. ProofValuesOf("second proof", dpopKey.Key, ResourceProofHtuOf(rs), NowInstant)
            ]);
    }


    /// <summary>
    /// A permitted DPoP presentation at UserInfo over a raw TLS connection inside <paramref name="root"/>: the
    /// DPoP-bound access token issued over the wire, presented first with no proof and answered with UserInfo's nonce
    /// challenge, then with a proof carrying the nonce and answered 200, the host traced through the application's
    /// server delegate.
    /// </summary>
    /// <param name="root">The test's root span, started here.</param>
    /// <returns>The flow's secrets by name.</returns>
    private async Task<IReadOnlyDictionary<string, string>> UserInfoPermitAsync(Activity root)
    {
        const string userInfoClientId = "https://tracing.userinfo.client.test";
        Uri redirectUri = new("https://client.example.com/callback");
        SampleTracing sample = new();
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(userInfoClientId, new Uri(userInfoClientId)).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: ResourceSubject);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, redirectUri.OriginalString, TestContext.CancellationToken).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidate => candidate.StartTraceActivity = sample.StartServerActivity).ConfigureAwait(false);
        Uri userInfoUrl = await RawAuthCodeWirePushers.ResolveUserInfoUriAsync(host, material, TestContext.CancellationToken).ConfigureAwait(false);
        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
            host.Host("default"), fixture.Client, fixture.Registration, fixture.ClientFlowStore,
            material.Registration.TenantId.Value, redirectUri, ResourceSubject, browserClient,
            scope: WellKnownScopes.OpenId, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string token = (string)drive.TokenResult.Body![OAuthRequestParameterNames.AccessToken];
        string jti = Guid.NewGuid().ToString("N");

        _ = root.Start();
        string authorization = $"DPoP {token}";
        HttpResponseData challenge = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl,
            [new(WellKnownHttpHeaderNames.TraceParent, TraceParentOf(root)), new(WellKnownHttpHeaderNames.Authorization, authorization)],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(401, challenge.StatusCode, challenge.Body);
        string nonce = Assert.ContainsSingle(challenge.Headers.Headers.GetValues(WellKnownHttpHeaderNames.DPoPNonce));
        DateTimeOffset issuedAt = TimeProvider.GetUtcNow();
        string proof = await ResourceDpopProofs.BuildAsync(
            fixture.DpopKey, WellKnownHttpMethods.Post, userInfoUrl.ToString(), token, nonce, issuedAt,
            TestContext.CancellationToken, jti).ConfigureAwait(false);
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, userInfoUrl,
            [
                new(WellKnownHttpHeaderNames.TraceParent, TraceParentOf(root)),
                new(WellKnownHttpHeaderNames.Authorization, authorization),
                new(WellKnownHttpHeaderNames.DPoP, proof)
            ],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The presentations are answered without a server fault.");
        Assert.AreEqual(200, response.StatusCode, response.Body);

        return WithAll(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["access token"] = token,
                ["proof"] = proof,
                ["proof jti"] = jti,
                ["proof ath"] = await ResourceDpopProofs.ComputeAthAsync(token, TestContext.CancellationToken).ConfigureAwait(false),
                ["DPoP-Nonce"] = nonce,
                ["proof key thumbprint"] = await ThumbprintOfAsync(fixture.DpopKey).ConfigureAwait(false),
                ["Authorization"] = authorization,
                ["tenant key"] = material.Registration.TenantId.Value,
                ["subject"] = ResourceSubject
            },
            ProofValuesOf("proof", fixture.DpopKey, userInfoUrl.ToString(), issuedAt));
    }


    /// <summary>
    /// <paramref name="secrets"/> with each of <paramref name="values"/> added under its own name; a name already held
    /// fails the add, so no secret of the flow is written over.
    /// </summary>
    /// <param name="secrets">The flow's secrets by name.</param>
    /// <param name="values">The further secrets by name.</param>
    /// <returns><paramref name="secrets"/>, holding both.</returns>
    private static Dictionary<string, string> WithAll(Dictionary<string, string> secrets, IEnumerable<KeyValuePair<string, string>> values)
    {
        foreach(KeyValuePair<string, string> value in values)
        {
            secrets.Add(value.Key, value.Value);
        }

        return secrets;
    }


    /// <summary>
    /// Every value the library's spans in <paramref name="inTrace"/>, <c>server.handle</c> and
    /// <c>oauth.resource.decide</c>, carry, their display name, their status description, the value of every tag, the
    /// name of every event and the value of every event tag, and the name and the value of every tag of an event the
    /// library names on any span, each value written as invariant text by <see cref="TextsOf"/>.
    /// </summary>
    /// <param name="inTrace">The spans of one trace.</param>
    /// <returns>The values.</returns>
    private static List<string> LibraryValuesOf(IReadOnlyList<Activity> inTrace)
    {
        List<string> values = [];
        foreach(Activity activity in inTrace)
        {
            bool isLibrarySpan = string.Equals(activity.OperationName, ServerActivityNames.Handle, StringComparison.Ordinal)
                || string.Equals(activity.OperationName, OAuthActivityNames.DecideResourceAccess, StringComparison.Ordinal);
            if(isLibrarySpan)
            {
                values.Add(activity.DisplayName);
                values.Add(activity.StatusDescription ?? string.Empty);
                values.AddRange(activity.TagObjects.SelectMany(static tag => TextsOf(tag.Value)));
            }

            IEnumerable<ActivityEvent> events = isLibrarySpan
                ? activity.Events
                : activity.Events.Where(static activityEvent => activityEvent.Name.StartsWith("oauth.", StringComparison.Ordinal)
                    || activityEvent.Name.StartsWith("server.", StringComparison.Ordinal));
            values.AddRange(events.Select(static activityEvent => activityEvent.Name));
            values.AddRange(events.SelectMany(static activityEvent => activityEvent.Tags).SelectMany(static tag => TextsOf(tag.Value)));
        }

        return values;
    }


    /// <summary>
    /// The texts of one attribute value: a string as itself, the texts of each element of an array or of any other
    /// enumerable value, read the same way at every depth, and any other value as its invariant text, so a secret held in
    /// an element of an array value, or of an array inside one, is read as that element.
    /// </summary>
    /// <param name="value">The attribute value.</param>
    /// <returns>The texts.</returns>
    private static IEnumerable<string> TextsOf(object? value) => value switch
    {
        string text => [text],
        IEnumerable elements => [.. elements.Cast<object?>().SelectMany(TextsOf)],
        _ => [Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty]
    };


    /// <summary>The library's dispatch spans, <c>server.handle</c>, among <paramref name="activities"/>.</summary>
    /// <param name="activities">The spans.</param>
    /// <returns>The dispatch spans.</returns>
    private static IReadOnlyList<Activity> DispatchSpansOf(IEnumerable<Activity> activities) =>
        [.. activities.Where(static activity => string.Equals(activity.OperationName, ServerActivityNames.Handle, StringComparison.Ordinal))];


    /// <summary>The resource decision spans, <c>oauth.resource.decide</c>, among <paramref name="activities"/>.</summary>
    /// <param name="activities">The spans.</param>
    /// <returns>The decision spans.</returns>
    private static IReadOnlyList<Activity> DecideSpansOf(IEnumerable<Activity> activities) =>
        [.. activities.Where(static activity => string.Equals(activity.OperationName, OAuthActivityNames.DecideResourceAccess, StringComparison.Ordinal))];


    /// <summary>The one application client span among <paramref name="inTrace"/> whose <c>url.full</c> is <paramref name="target"/>.</summary>
    /// <param name="inTrace">The spans of one trace.</param>
    /// <param name="target">The request URL.</param>
    /// <returns>The client span.</returns>
    private static Activity ClientSpanTo(IReadOnlyList<Activity> inTrace, Uri target) =>
        Assert.ContainsSingle(
            inTrace.Where(activity => activity.Kind == ActivityKind.Client
                && string.Equals(activity.GetTagItem("url.full") as string, target.AbsoluteUri, StringComparison.Ordinal)),
            $"One client span requests {target.AbsoluteUri}.");


    /// <summary>Whether <paramref name="activity"/> descends from the span <paramref name="ancestorSpanId"/> through the spans of <paramref name="inTrace"/>.</summary>
    /// <param name="activity">The span.</param>
    /// <param name="ancestorSpanId">The ancestor.</param>
    /// <param name="inTrace">The spans of one trace.</param>
    /// <returns><see langword="true"/> when an ancestor of <paramref name="activity"/> is the span.</returns>
    private static bool IsDescendantOf(Activity activity, ActivitySpanId ancestorSpanId, IReadOnlyList<Activity> inTrace)
    {
        Dictionary<ActivitySpanId, Activity> bySpanId = inTrace.ToDictionary(static span => span.SpanId);
        HashSet<ActivitySpanId> visited = [activity.SpanId];
        ActivitySpanId parentSpanId = activity.ParentSpanId;
        bool isDescendant = false;
        while(!isDescendant && visited.Add(parentSpanId))
        {
            isDescendant = parentSpanId == ancestorSpanId;
            parentSpanId = bySpanId.TryGetValue(parentSpanId, out Activity? parent) ? parent.ParentSpanId : default;
        }

        return isDescendant;
    }


    /// <summary>The <c>traceparent</c> value naming <paramref name="root"/> as the parent, sampled.</summary>
    /// <param name="root">The test's root span.</param>
    /// <returns>The value.</returns>
    private static string TraceParentOf(Activity root) =>
        $"00-{root.TraceId.ToHexString()}-{root.SpanId.ToHexString()}-01";


    /// <summary>
    /// Starts an application's resource server trusting <see cref="ResourceIssuer"/>'s key <paramref name="asPublicKey"/>
    /// on a clock at <see cref="NowInstant"/>, its decision traced through <paramref name="startTraceActivity"/>.
    /// </summary>
    /// <param name="asPublicKey">The access token verification key.</param>
    /// <param name="startTraceActivity">The application's start of the decision span, or <see langword="null"/> to leave the slot unwired.</param>
    /// <param name="isDpopProofValidationWired">Whether the resource wires its proof validation, nonce slots and accepted algorithms.</param>
    /// <param name="wrapDpopProofJtiClaim">Wraps the resource's <c>jti</c> claim, or <see langword="null"/> to wire it as it is.</param>
    /// <returns>The running resource server; the caller disposes it.</returns>
    private async Task<TestResourceServerShell> StartResourceServerAsync(
        PublicKeyMemory asPublicKey,
        StartTraceActivityDelegate? startTraceActivity,
        bool isDpopProofValidationWired = true,
        Func<ConsultDpopProofJtiDelegate, ConsultDpopProofJtiDelegate>? wrapDpopProofJtiClaim = null)
    {
        TestResourceServerShell rs = new(
            trustedIssuer: new Uri(ResourceIssuer),
            expectedAudience: ResourceAudience,
            resolveVerificationKey: (kid, usage, tenant, context, cancellationToken) => ValueTask.FromResult<PublicKeyMemory?>(
                string.Equals(kid.Value, ResourceKid, StringComparison.Ordinal) ? asPublicKey : null),
            verifySignature: MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            timeProvider: new FakeTimeProvider(NowInstant),
            isDpopProofValidationWired: isDpopProofValidationWired,
            wrapDpopProofJtiClaim: wrapDpopProofJtiClaim,
            startTraceActivity: startTraceActivity);
        try
        {
            await rs.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

            return rs;
        }
        catch
        {
            await rs.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }


    /// <summary>
    /// The resource server's verification key resolution of an application that fetches the authorization server's JWKS
    /// over <paramref name="client"/> on every call, inside the request it resolves for, and answers the key the token
    /// header's <c>kid</c> names; every key it materializes is added to <paramref name="fetchedKeys"/>, which the caller
    /// disposes.
    /// </summary>
    /// <param name="client">The application's traced client.</param>
    /// <param name="jwksUrl">The authorization server's JWKS URL.</param>
    /// <param name="fetchedKeys">Receives every materialized key.</param>
    /// <returns>The resolver.</returns>
    private static ServerVerificationKeyResolverDelegate FetchJwksOnEveryCallResolver(
        HttpClient client, Uri jwksUrl, ConcurrentBag<PublicKeyMemory> fetchedKeys) =>
        async (kid, usage, tenant, context, cancellationToken) =>
        {
            using HttpResponseMessage response = await client.GetAsync(jwksUrl, cancellationToken).ConfigureAwait(false);
            string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            using JsonDocument document = JsonDocument.Parse(body);
            foreach(JsonElement key in document.RootElement.GetProperty(WellKnownJwkMemberNames.Keys).EnumerateArray())
            {
                if(string.Equals(key.GetProperty(WellKnownJwkMemberNames.Kid).GetString(), kid.Value, StringComparison.Ordinal))
                {
                    Dictionary<string, string> jwk = new(StringComparer.Ordinal);
                    foreach(JsonProperty member in key.EnumerateObject().Where(static member => member.Value.ValueKind == JsonValueKind.String))
                    {
                        jwk[member.Name] = member.Value.GetString()!;
                    }

                    PublicKeyMemory publicKey = DpopJwkUtilities.PublicKeyFromJwk(
                        jwk, WellKnownJwaValues.Es256, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);
                    fetchedKeys.Add(publicKey);

                    return publicKey;
                }
            }

            return null;
        };


    /// <summary>
    /// Signs an access token from <see cref="ResourceIssuer"/> for <see cref="ResourceAudience"/> about
    /// <see cref="ResourceSubject"/>, issued a minute before <see cref="NowInstant"/> and expiring an hour after it, under
    /// <paramref name="kid"/>, bound by <c>cnf.jkt</c> to <paramref name="boundThumbprint"/> when one is given.
    /// </summary>
    /// <param name="privateKey">The access token signing key.</param>
    /// <param name="boundThumbprint">The <c>cnf.jkt</c>, or <see langword="null"/> for an unbound token.</param>
    /// <param name="kid">The header <c>kid</c>, <see cref="ResourceKid"/> unless given.</param>
    /// <returns>The compact JWS.</returns>
    private async Task<string> IssueTokenAsync(PrivateKeyMemory privateKey, string? boundThumbprint, string kid = ResourceKid)
    {
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: ResourceSubject,
            scope: WellKnownScopes.OpenId,
            clientId: MachineClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: ResourceIssuer,
            audience: [ResourceAudience]);
        if(boundThumbprint is not null)
        {
            payload[WellKnownJwtClaimNames.Cnf] = new Dictionary<string, object>
            {
                [WellKnownJwtClaimNames.JwkThumbprint] = boundThumbprint
            };
        }

        UnsignedJwt unsignedJwt = new(JwtHeaderExtensions.ForAccessToken(WellKnownJwaValues.Es256, kid), payload);
        using JwsMessage jws = await unsignedJwt.SignAsync(
            privateKey, SerializeHeader, SerializePayload, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }


    /// <summary>Serializes a JWT header to its UTF-8 JSON.</summary>
    /// <param name="header">The header.</param>
    /// <returns>The JSON octets.</returns>
    private static ReadOnlySpan<byte> SerializeHeader(JwtHeader header) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes((Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);


    /// <summary>Serializes a JWT payload to its UTF-8 JSON.</summary>
    /// <param name="payload">The payload.</param>
    /// <returns>The JSON octets.</returns>
    private static ReadOnlySpan<byte> SerializePayload(JwtPayload payload) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes((Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);


    /// <summary>The JWK SHA-256 Thumbprint of <paramref name="dpopKey"/>'s public key, the value a bound token's <c>cnf.jkt</c> carries.</summary>
    /// <param name="dpopKey">The DPoP key.</param>
    /// <returns>The base64url thumbprint.</returns>
    private Task<string> ThumbprintOfAsync(DpopKey dpopKey) =>
        ResourceDpopProofs.ComputeJwkThumbprintAsync(dpopKey, TestContext.CancellationToken);


    /// <summary>
    /// The values a DPoP proof carries beside its <c>jti</c>, <c>ath</c> and <c>nonce</c>, by name under
    /// <paramref name="label"/>: the <c>x</c> and <c>y</c> coordinates, in base64url, of the public JWK its header carries
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>: "jwk: Represents the
    /// public key chosen by the client in JSON Web Key (JWK) [RFC7517] format"), its <c>htu</c> ("htu: The HTTP target URI
    /// (Section 7.1 of [RFC9110]) of the request to which the JWT is attached, without query and fragment parts.") as the
    /// proof names it, and its <c>iat</c> ("iat: Creation timestamp of the JWT (Section 4.1.6 of [RFC7519]).") as the
    /// decimal seconds the claim holds.
    /// </summary>
    /// <param name="label">The proof's name in the flow's secrets, such as <c>proof</c> or <c>second proof</c>.</param>
    /// <param name="dpopKey">The key whose public half the proof's header carries.</param>
    /// <param name="htu">The <c>htu</c> the proof names.</param>
    /// <param name="issuedAt">The <c>iat</c> the proof carries.</param>
    /// <returns>The values by name.</returns>
    private static IEnumerable<KeyValuePair<string, string>> ProofValuesOf(string label, DpopKey dpopKey, string htu, DateTimeOffset issuedAt)
    {
        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(dpopKey.Material.PublicKey, dpopKey.Alg, TestHostShell.Base64UrlEncoder);

        return
        [
            new($"{label} jwk x", jwk["x"]),
            new($"{label} jwk y", jwk["y"]),
            new($"{label} htu", htu),
            new($"{label} iat", issuedAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture))
        ];
    }


    /// <summary>The <c>htu</c> of every proof <see cref="BuildResourceProofAsync"/> builds for <paramref name="rs"/>: its <c>/protected</c> URL.</summary>
    /// <param name="rs">The running resource server.</param>
    /// <returns>The <c>htu</c>.</returns>
    private static string ResourceProofHtuOf(TestResourceServerShell rs) => new Uri(rs.HttpBaseAddress!, "/protected").ToString();


    /// <summary>
    /// Builds a DPoP proof by <paramref name="dpopKey"/> for a GET of <c>/protected</c> on the resource server at
    /// <see cref="NowInstant"/>, its <c>ath</c> hashing <paramref name="token"/>, carrying <paramref name="nonce"/> when
    /// given and <paramref name="jti"/> or a fresh one.
    /// </summary>
    /// <param name="rs">The running resource server.</param>
    /// <param name="dpopKey">The key that signs the proof.</param>
    /// <param name="token">The access token presented with the proof.</param>
    /// <param name="nonce">The resource's nonce, or <see langword="null"/> for none.</param>
    /// <param name="jti">The proof's <c>jti</c>, or <see langword="null"/> for a fresh one.</param>
    /// <returns>The compact proof.</returns>
    private Task<string> BuildResourceProofAsync(TestResourceServerShell rs, DpopKey dpopKey, string token, string? nonce, string? jti = null) =>
        ResourceDpopProofs.BuildAsync(
            dpopKey, WellKnownHttpMethods.Get, ResourceProofHtuOf(rs), token, nonce, NowInstant, TestContext.CancellationToken, jti);


    /// <summary>
    /// Presents <paramref name="token"/> at the resource server over a raw TLS connection with a proof carrying no nonce
    /// and answers the one nonce its <c>DPoP-Nonce</c> field line provides.
    /// </summary>
    /// <param name="rs">The running resource server.</param>
    /// <param name="dpopKey">The key the token is bound to.</param>
    /// <param name="token">The DPoP-bound access token.</param>
    /// <returns>The resource's nonce.</returns>
    private async Task<string> ObtainResourceNonceAsync(TestResourceServerShell rs, DpopKey dpopKey, string token)
    {
        string proof = await BuildResourceProofAsync(rs, dpopKey, token, nonce: null).ConfigureAwait(false);
        HttpResponseData challenge = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [proof], traceParent: null).ConfigureAwait(false);
        Assert.AreEqual(401, challenge.StatusCode, challenge.Body);

        return Assert.ContainsSingle(challenge.Headers.Headers.GetValues(WellKnownHttpHeaderNames.DPoPNonce));
    }


    /// <summary>
    /// Presents a proof carrying the resource's nonce once at the resource server over a raw TLS connection, asserts it is
    /// served, and answers the proof, which a second presentation replays.
    /// </summary>
    /// <param name="rs">The running resource server.</param>
    /// <param name="dpopKey">The key the token is bound to.</param>
    /// <param name="token">The DPoP-bound access token.</param>
    /// <returns>The proof already presented once.</returns>
    private async Task<string> PresentOnceAsync(TestResourceServerShell rs, DpopKey dpopKey, string token)
    {
        string nonce = await ObtainResourceNonceAsync(rs, dpopKey, token).ConfigureAwait(false);
        string proof = await BuildResourceProofAsync(rs, dpopKey, token, nonce).ConfigureAwait(false);
        HttpResponseData first = await SendProtectedOverARawConnectionAsync(rs, $"DPoP {token}", [proof], traceParent: null).ConfigureAwait(false);
        Assert.AreEqual(200, first.StatusCode, first.Body);

        return proof;
    }


    /// <summary>Sends a GET of <c>/protected</c> with <paramref name="token"/> under <c>DPoP</c> and <paramref name="proof"/> over <paramref name="client"/>.</summary>
    /// <param name="client">The client.</param>
    /// <param name="rs">The running resource server.</param>
    /// <param name="token">The DPoP-bound access token.</param>
    /// <param name="proof">The proof.</param>
    /// <returns>The answer; the caller disposes it.</returns>
    private async Task<HttpResponseMessage> SendProtectedAsync(HttpClient client, TestResourceServerShell rs, string token, string proof)
    {
        using HttpRequestMessage request = new(HttpMethod.Get, new Uri(rs.HttpBaseAddress!, "/protected"));
        _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.Authorization, $"DPoP {token}");
        _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.DPoP, proof);

        return await client.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Sends a GET of <c>/protected</c> to the resource server over a raw TLS connection with
    /// <paramref name="traceParent"/> as its <c>traceparent</c> line when given, <paramref name="authorization"/> as its
    /// one <c>Authorization</c> line and each of <paramref name="dpopFieldLines"/> on its own <c>DPoP</c> line.
    /// </summary>
    /// <param name="rs">The running resource server.</param>
    /// <param name="authorization">The <c>Authorization</c> value.</param>
    /// <param name="dpopFieldLines">The <c>DPoP</c> values, one line each.</param>
    /// <param name="traceParent">The <c>traceparent</c> value, or <see langword="null"/> for none.</param>
    /// <returns>The answer as received.</returns>
    private Task<HttpResponseData> SendProtectedOverARawConnectionAsync(
        TestResourceServerShell rs, string authorization, IReadOnlyList<string> dpopFieldLines, string? traceParent)
    {
        List<KeyValuePair<string, string>> fieldLines = traceParent is null
            ? []
            : [new(WellKnownHttpHeaderNames.TraceParent, traceParent)];
        fieldLines.Add(new(WellKnownHttpHeaderNames.Authorization, authorization));
        fieldLines.AddRange(dpopFieldLines.Select(static proof => new KeyValuePair<string, string>(WellKnownHttpHeaderNames.DPoP, proof)));

        return RawHttpsRequest.SendPinnedAsync(
            rs.HttpCertificate!, WellKnownHttpMethods.Get, new Uri(rs.HttpBaseAddress!, "/protected"), fieldLines,
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken);
    }
}
