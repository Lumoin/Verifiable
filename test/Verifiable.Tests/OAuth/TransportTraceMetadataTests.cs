using System.Diagnostics;
using System.Net.Http;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Proves over a real loopback wire that W3C Trace Context response headers land in
/// <see cref="HttpResponseData.TransportMetadata"/> under the documented
/// <see cref="HttpResponseDataKeys"/> constants — in both the plain
/// <see cref="HttpClientTransport"/> and the policy-guarded
/// <see cref="GuardedHttpClientTransport"/> — and that
/// <see cref="OAuthParseError.WithTransportMetadata"/> enrichment surfaces the
/// captured <c>traceparent</c> as the <see cref="DecisionSupport.CorrelationId"/>
/// through the real <see cref="OAuthResponseParsers"/> parse pipeline. Also proves
/// that <see cref="TraceTreeCapture"/> + <see cref="TraceTreeAssertions"/>
/// reconstruct one connected span tree from the runtime's own instrumentation
/// across a real HTTPS round-trip.
/// </summary>
/// <remarks>
/// Not parallelized: <see cref="TraceTreeCapture"/> is a process-wide
/// <see cref="ActivityListener"/> that enables the framework instrumentation
/// sources (<c>Microsoft.AspNetCore</c>, <c>System.Net.Http</c>), which injects
/// <c>traceparent</c> headers into concurrently running tests' HTTP calls and
/// captures their spans here. Serialization plus root-TraceId filtering keeps
/// these assertions deterministic.
/// </remarks>
[TestClass]
[DoNotParallelize]
internal sealed class TransportTraceMetadataTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string TraceParentHeaderName = "traceparent";

    private const string TraceStateHeaderName = "tracestate";

    /// <summary>The W3C Trace Context specification's own <c>traceparent</c> example value.</summary>
    private const string ResponseTraceParent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

    /// <summary>The W3C Trace Context specification's own <c>tracestate</c> example value.</summary>
    private const string ResponseTraceState = "congo=t61rcWkgMzE";


    [TestMethod]
    public async Task ResponseTraceContextHeadersLandInTransportMetadata()
    {
        await using MinimalHttpHost host = await MinimalHttpHost.StartAsync(
            (request, cancellationToken) => Task.FromResult(new MinimalHttpResponse
            {
                StatusCode = 200,
                ContentType = WellKnownMediaTypes.Application.Json,
                Body = /*lang=json,strict*/ """{"ok":true}""",
                Headers = new Dictionary<string, string>
                {
                    [TraceParentHeaderName] = ResponseTraceParent,
                    [TraceStateHeaderName] = ResponseTraceState
                }
            }),
            TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(host.Certificate);

        HttpResponseData response = await HttpClientTransport.SendJsonGetAsync(
            client, host.BaseAddress, OutgoingHeaders.Empty,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode);
        Assert.AreEqual(ResponseTraceParent, response.GetMetadata(HttpResponseDataKeys.TraceParent),
            $"The response 'traceparent' header must land in TransportMetadata under " +
            $"'{HttpResponseDataKeys.TraceParent}'.");
        Assert.AreEqual(ResponseTraceState, response.GetMetadata(HttpResponseDataKeys.TraceState),
            $"The response 'tracestate' header must land in TransportMetadata under " +
            $"'{HttpResponseDataKeys.TraceState}'.");
    }


    [TestMethod]
    public async Task TransportMetadataIsNullWithoutTraceContextResponseHeaders()
    {
        await using MinimalHttpHost host = await MinimalHttpHost.StartAsync(
            (request, cancellationToken) => Task.FromResult(new MinimalHttpResponse
            {
                StatusCode = 200,
                ContentType = WellKnownMediaTypes.Application.Json,
                Body = /*lang=json,strict*/ """{"ok":true}"""
            }),
            TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(host.Certificate);

        HttpResponseData response = await HttpClientTransport.SendJsonGetAsync(
            client, host.BaseAddress, OutgoingHeaders.Empty,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(response.TransportMetadata,
            "Without trace-context response headers there is no transport metadata to capture.");
    }


    [TestMethod]
    public async Task GuardedTransportCopiesResponseTraceContextIntoTransportMetadata()
    {
        await using MinimalHttpHost host = await MinimalHttpHost.StartAsync(
            (request, cancellationToken) => Task.FromResult(new MinimalHttpResponse
            {
                StatusCode = 200,
                ContentType = WellKnownMediaTypes.Application.Json,
                Body = /*lang=json,strict*/ """{"ok":true}""",
                Headers = new Dictionary<string, string>
                {
                    [TraceParentHeaderName] = ResponseTraceParent,
                    [TraceStateHeaderName] = ResponseTraceState
                }
            }),
            TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient client = LoopbackTls.CreateSingleHopPinnedHttpClient(host.Certificate);
        SendFormPostDelegate guardedFormPost = GuardedHttpClientTransport.BuildGuardedFormPost(client);

        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(TestHostShell.LoopbackOutboundFetchPolicy);

        HttpResponseData response = await guardedFormPost(
            host.BaseAddress,
            new Dictionary<string, string> { ["probe"] = "trace-metadata" },
            OutgoingHeaders.Empty,
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode);
        Assert.AreEqual(ResponseTraceParent, response.GetMetadata(HttpResponseDataKeys.TraceParent),
            "The guarded transport must copy the response 'traceparent' header into " +
            "TransportMetadata exactly like the plain transport.");
        Assert.AreEqual(ResponseTraceState, response.GetMetadata(HttpResponseDataKeys.TraceState),
            "The guarded transport must copy the response 'tracestate' header into " +
            "TransportMetadata exactly like the plain transport.");
    }


    [TestMethod]
    public async Task ParseErrorEnrichmentCarriesWireTraceParentAsCorrelationId()
    {
        await using MinimalHttpHost host = await MinimalHttpHost.StartAsync(
            (request, cancellationToken) => Task.FromResult(new MinimalHttpResponse
            {
                StatusCode = 400,
                ContentType = WellKnownMediaTypes.Application.Json,
                Body = /*lang=json,strict*/ """{"error":"invalid_request","error_description":"code_challenge missing"}""",
                Headers = new Dictionary<string, string>
                {
                    [TraceParentHeaderName] = ResponseTraceParent
                }
            }),
            TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(host.Certificate);

        HttpResponseData response = await HttpClientTransport.SendFormPostAsync(
            client,
            host.BaseAddress,
            new Dictionary<string, string> { ["client_id"] = "trace-metadata-test-client" },
            OutgoingHeaders.Empty,
            TestContext.CancellationToken).ConfigureAwait(false);

        Result<ParResponse, OAuthParseError> result = OAuthResponseParsers.ParseParResponse(response);

        Assert.IsFalse(result.IsSuccess);
        OAuthProtocolError protocolError = Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.AreEqual("invalid_request", protocolError.ErrorCode);
        Assert.AreEqual(ResponseTraceParent, protocolError.Support.CorrelationId,
            "The wire response's traceparent must surface as the DecisionSupport correlation id " +
            "through the real parse pipeline.");
        Assert.AreEqual("400", protocolError.Support.Context?[HttpResponseDataKeys.StatusCode],
            "The wire status code must surface in the DecisionSupport context.");
    }


    [TestMethod]
    public async Task CapturedSpansFormOneConnectedTreeWithHostAttributionAndEvent()
    {
        const string HandlerEventName = "test.trace.handler";

        using TraceTreeCapture capture = new();
        using Activity root = new(nameof(CapturedSpansFormOneConnectedTreeWithHostAttributionAndEvent));
        root.Start();

        Uri hostBaseAddress;
        HttpResponseData response;
        {
            await using MinimalHttpHost host = await MinimalHttpHost.StartAsync(
                (request, cancellationToken) =>
                {
                    //Runs inside the ASP.NET Core request pipeline, so Activity.Current is
                    //the Microsoft.AspNetCore.Hosting.HttpRequestIn server span the capture
                    //enabled. The event proves attachment under the server span; the echoed
                    //Activity.Id (W3C traceparent format) proves the server processed the
                    //request inside the client root's trace.
                    Activity.Current?.AddEvent(new ActivityEvent(HandlerEventName));
                    string? serverTraceParent = Activity.Current?.Id;

                    return Task.FromResult(new MinimalHttpResponse
                    {
                        StatusCode = 200,
                        Headers = serverTraceParent is null
                            ? null
                            : new Dictionary<string, string> { [TraceParentHeaderName] = serverTraceParent }
                    });
                },
                TestContext.CancellationToken).ConfigureAwait(false);

            hostBaseAddress = host.BaseAddress;
            using HttpClient client = LoopbackTls.CreatePinnedHttpClient(host.Certificate);

            response = await HttpClientTransport.SendJsonGetAsync(
                client, host.BaseAddress, OutgoingHeaders.Empty,
                TestContext.CancellationToken).ConfigureAwait(false);
        }
        //Leaving the block disposed the host; Kestrel's stop drains request processing,
        //so the server span has stopped and is in the capture before assertions run.

        root.Stop();

        IReadOnlyList<Activity> captured = capture.StoppedActivities;
        TraceTreeAssertions.AssertSingleConnectedTree(captured, root);
        TraceTreeAssertions.AssertSpanForEachHost(captured, root, [hostBaseAddress]);
        TraceTreeAssertions.AssertEventUnderAncestor(captured, root, HandlerEventName, root.SpanId);
        TraceTreeAssertions.AssertEventUnderAncestor(captured, root, HandlerEventName,
            activity => activity.Kind == ActivityKind.Server);

        string? echoedTraceParent = response.GetMetadata(HttpResponseDataKeys.TraceParent);
        Assert.IsNotNull(echoedTraceParent,
            "The server-echoed traceparent must land in TransportMetadata.");
        Assert.Contains(root.TraceId.ToHexString(), echoedTraceParent,
            "The server span's traceparent must belong to the client root's trace, proving " +
            "W3C trace-context propagation across the real wire.");
    }
}
