using System.Collections.Concurrent;
using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Core.Diagnostics;
using Verifiable.Server.Routing;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// An application's tracing composed over the library's <see cref="StartTraceActivityDelegate"/>: the application's own
/// <see cref="ActivitySource"/> (<see cref="Source"/>), the server-side delegate <see cref="StartServerActivity"/> that
/// continues the inbound trace context with the application's propagator, and the delegate <see cref="StartActivity"/>
/// for an operation that runs under an ambient activity. A row wires one instance per test, so the field lines each
/// server delegate call saw (<see cref="ObservedFieldLines"/>) are that test's alone.
/// </summary>
/// <remarks>
/// <para>
/// The propagator is the runtime's <see cref="DistributedContextPropagator.Current"/>; the library reads and writes
/// neither trace field, so the application's propagator is the one that parses them
/// (<see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#trace-id">W3C Trace Context Level 1, Section
/// 3.2.2.3</see>: "If the trace-id value is invalid (for example if it contains non-allowed characters or all zeros),
/// vendors MUST ignore the traceparent.").
/// </para>
/// </remarks>
internal sealed class SampleTracing
{
    /// <summary>The name of the application's <see cref="ActivitySource"/>, the name a capture subscribes to.</summary>
    public static string SourceName => "Verifiable.Tests.TracingSample";

    /// <summary>The application's <see cref="ActivitySource"/>: every span the sample starts, server, operation and client, is started on it.</summary>
    public static ActivitySource Source { get; } = new(SourceName);

    /// <summary>The <c>traceparent</c> and <c>tracestate</c> field lines each call of <see cref="StartServerActivity"/> saw, in call order.</summary>
    public ConcurrentQueue<ObservedTraceFieldLines> ObservedFieldLines { get; } = new();


    /// <summary>
    /// The server-side <see cref="StartTraceActivityDelegate"/>: records the <c>traceparent</c> and <c>tracestate</c>
    /// field lines of the inbound request <paramref name="context"/> carries, then starts
    /// <paramref name="operationName"/> on <see cref="Source"/> under the ambient activity when the host continued the
    /// trace, and otherwise under the remote parent the application's propagator reads from those field lines: every
    /// <c>tracestate</c> line joined in received order
    /// (<see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#tracestate-header-field-values">W3C Trace
    /// Context Level 1, Section 3.3.1.1</see>: "When receiving multiple tracestate header fields, they MUST be combined
    /// into a single header according to RFC7230."), and a <c>traceparent</c> the propagator cannot parse ignored, the
    /// span then the root of a new trace.
    /// </summary>
    /// <param name="operationName">The library's operation name.</param>
    /// <param name="kind">The kind the library means.</param>
    /// <param name="tags">The attributes the library holds at the start.</param>
    /// <param name="context">The exchange's context, carrying the inbound request.</param>
    /// <returns>The started span, or <see langword="null"/> when no listener samples <see cref="Source"/>.</returns>
    public Activity? StartServerActivity(
        string operationName,
        ActivityKind kind,
        IReadOnlyList<KeyValuePair<string, object?>> tags,
        ExchangeContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        RequestHeaders headers = context.IncomingRequest?.Headers ?? RequestHeaders.Empty;
        bool isAmbientActivityPresent = Activity.Current is not null;
        ObservedFieldLines.Enqueue(new ObservedTraceFieldLines(
            LinesOf(headers, WellKnownHttpHeaderNames.TraceParent),
            LinesOf(headers, WellKnownHttpHeaderNames.TraceState),
            isAmbientActivityPresent));

        if(isAmbientActivityPresent)
        {
            return Source.StartActivity(operationName, kind, parentContext: default, tags);
        }

        DistributedContextPropagator.Current.ExtractTraceIdAndState(
            headers, ReadJoinedFieldLines, out string? traceParent, out string? traceState);
        ActivityContext remoteParent = ActivityContext.TryParse(traceParent, traceState, isRemote: true, out ActivityContext parsed)
            ? parsed
            : default;

        return Source.StartActivity(operationName, kind, remoteParent, tags);
    }


    /// <summary>
    /// The <see cref="StartTraceActivityDelegate"/> of an operation that runs inside the application's own request or
    /// call: starts <paramref name="operationName"/> on <see cref="Source"/> under the ambient
    /// <see cref="Activity.Current"/>, reading nothing of <paramref name="context"/>.
    /// </summary>
    /// <param name="operationName">The library's operation name.</param>
    /// <param name="kind">The kind the library means.</param>
    /// <param name="tags">The attributes the library holds at the start.</param>
    /// <param name="context">The exchange's context; unread.</param>
    /// <returns>The started span, or <see langword="null"/> when no listener samples <see cref="Source"/>.</returns>
    public static Activity? StartActivity(
        string operationName,
        ActivityKind kind,
        IReadOnlyList<KeyValuePair<string, object?>> tags,
        ExchangeContext context) =>
        Source.StartActivity(operationName, kind, parentContext: default, tags);


    /// <summary>Every line of the field <paramref name="name"/> in received order, or none.</summary>
    /// <param name="headers">The inbound request's field lines.</param>
    /// <param name="name">The field name.</param>
    /// <returns>The lines.</returns>
    private static IReadOnlyList<string> LinesOf(RequestHeaders headers, string name) =>
        headers.TryGetAll(name, out IReadOnlyList<string>? lines) && lines is not null ? [.. lines] : [];


    /// <summary>
    /// The propagator's getter over <see cref="RequestHeaders"/>: answers the lines of <paramref name="fieldName"/> joined
    /// by <c>,</c> in received order, the one combined value RFC 7230 Section 3.2.2 defines, or <see langword="null"/>
    /// when the field is absent.
    /// </summary>
    /// <param name="carrier">The inbound request's <see cref="RequestHeaders"/>.</param>
    /// <param name="fieldName">The field the propagator reads.</param>
    /// <param name="fieldValue">The combined value, or <see langword="null"/>.</param>
    /// <param name="fieldValues">Always <see langword="null"/>; the combined value is answered.</param>
    private static void ReadJoinedFieldLines(object? carrier, string fieldName, out string? fieldValue, out IEnumerable<string>? fieldValues)
    {
        fieldValues = null;
        fieldValue = carrier is RequestHeaders headers && headers.TryGetAll(fieldName, out IReadOnlyList<string>? lines) && lines is not null
            ? string.Join(',', lines)
            : null;
    }
}


/// <summary>The <c>traceparent</c> and <c>tracestate</c> field lines one server delegate call saw, and whether an ambient activity was current then.</summary>
/// <param name="TraceParentLines">Every <c>traceparent</c> line in received order.</param>
/// <param name="TraceStateLines">Every <c>tracestate</c> line in received order.</param>
/// <param name="IsAmbientActivityPresent">Whether <see cref="Activity.Current"/> was set when the delegate was called, that is whether the host continued the trace.</param>
internal sealed record ObservedTraceFieldLines(
    IReadOnlyList<string> TraceParentLines,
    IReadOnlyList<string> TraceStateLines,
    bool IsAmbientActivityPresent);
