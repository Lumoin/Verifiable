using System.Diagnostics;
using System.Net.Http.Headers;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The application's propagator on the way out: writes the trace context of <see cref="Activity.Current"/>, the span of
/// the attempt when an <see cref="HttpClientSpanHandler"/> runs before it, into the request through
/// <see cref="DistributedContextPropagator.Current"/>, replacing any value of a field it writes, so one <c>traceparent</c>
/// field line and at most one <c>tracestate</c> field line leave, each name in lowercase
/// (<see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#header-name">W3C Trace Context Level 1, Section
/// 3.2.1</see>: "Vendors MUST expect the header name in any case (upper, lower, mixed), and SHOULD send the header name
/// in lowercase."; <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#mutating-the-traceparent-field">Section
/// 3.4</see>: "A vendor receiving a traceparent request header MUST send it to outgoing requests."). The transport below
/// it has its own propagation turned off, so this handler is the one writer of both fields.
/// </summary>
internal sealed class TraceContextPropagationHandler: DelegatingHandler
{
    /// <summary>Writes the current trace context into <paramref name="request"/> and sends it on.</summary>
    /// <param name="request">The request.</param>
    /// <param name="cancellationToken">The caller's cancellation.</param>
    /// <returns>The answer.</returns>
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        DistributedContextPropagator.Current.Inject(Activity.Current, request.Headers, WriteField);

        return base.SendAsync(request, cancellationToken);
    }


    /// <summary>The propagator's setter over <see cref="HttpRequestHeaders"/>: replaces the field <paramref name="fieldName"/> with the one value <paramref name="fieldValue"/>.</summary>
    /// <param name="carrier">The request's <see cref="HttpRequestHeaders"/>.</param>
    /// <param name="fieldName">The field the propagator writes.</param>
    /// <param name="fieldValue">The value.</param>
    private static void WriteField(object? carrier, string fieldName, string fieldValue)
    {
        if(carrier is HttpRequestHeaders headers)
        {
            _ = headers.Remove(fieldName);
            _ = headers.TryAddWithoutValidation(fieldName, fieldValue);
        }
    }
}
