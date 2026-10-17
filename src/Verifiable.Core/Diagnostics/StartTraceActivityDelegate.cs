using System.Diagnostics;

namespace Verifiable.Core.Diagnostics;

/// <summary>
/// The application's start of the span of one library operation: called once when the operation begins, it answers a
/// started <see cref="Activity"/> the library sets the operation's outcome on and stops when the operation ends, or
/// <see langword="null"/> when the operation is not traced. The begin is the call and the end is the activity's stop,
/// which the application observes through its own <see cref="ActivityListener"/>, or an OpenTelemetry tracer provider
/// subscribing to the application's <see cref="ActivitySource"/>.
/// </summary>
/// <remarks>
/// <para>
/// The returned activity is started, so it is <see cref="Activity.Current"/> for the operation: the spans the library's
/// cryptographic providers start nest under it, and the tags and events the library adds to
/// <see cref="Activity.Current"/> during the operation attach to it.
/// </para>
/// <para>
/// The library reads and writes neither <c>traceparent</c> nor <c>tracestate</c>; the application's propagator does,
/// here on the way in from the field lines <paramref name="context"/> carries and in the application's transport on the
/// way out (<see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#mutating-the-traceparent-field">W3C Trace
/// Context Level 1, Section 3.4</see>: "A vendor receiving a traceparent request header MUST send it to outgoing
/// requests." and "Vendors MUST NOT make any other mutations to the traceparent header."). Every line of a field is handed
/// on in received order, whole.
/// </para>
/// <para>
/// A returned activity that was already <see cref="Activity.Current"/> when the delegate was called is the
/// application's own and is not stopped by the library. Any other returned activity is completed and stopped by the
/// library when the operation ends, whatever trace it belongs to. An exception the delegate throws passes to the caller
/// of the operation; at the server's dispatch the delegate is called before the first inspection stage, so a delegate
/// that throws fails the request before any inspection stage runs.
/// </para>
/// </remarks>
/// <param name="operationName">
/// The name of the operation, one of the library's activity names, for example <c>server.handle</c> of
/// <c>ServerActivityNames</c> or <c>oauth.resource.decide</c> of <c>OAuthActivityNames</c>.
/// </param>
/// <param name="kind">
/// The kind the library means for the span: <see cref="ActivityKind.Internal"/> for every operation it traces, since the
/// HTTP server and client spans are the application's host's and transport's
/// (<see href="https://opentelemetry.io/docs/specs/semconv/http/http-spans/">OpenTelemetry semantic conventions for
/// HTTP spans</see>: "Instrumentations SHOULD create an HTTP span for each attempt to send an HTTP request over the wire.").
/// </param>
/// <param name="tags">
/// The attributes the library holds when the operation begins, never a credential, passed so the application can sample
/// on them (<see href="https://opentelemetry.io/docs/specs/semconv/http/http-spans/">OpenTelemetry semantic conventions
/// for HTTP spans</see>: "The following attributes can be important for making sampling decisions and SHOULD be provided
/// at span creation time (if provided at all)").
/// </param>
/// <param name="context">
/// The exchange's context. On a server it carries the inbound request, whose field lines hold the <c>traceparent</c> and
/// <c>tracestate</c> lines the application's propagator reads when its host has not continued the trace. The same
/// request carries its credentials, the <c>Authorization</c> and <c>DPoP</c> field lines and the body, which the
/// application's tracing must not record.
/// </param>
/// <returns>The started activity the library completes and stops, or <see langword="null"/> for no span.</returns>
public delegate Activity? StartTraceActivityDelegate(
    string operationName,
    ActivityKind kind,
    IReadOnlyList<KeyValuePair<string, object?>> tags,
    ExchangeContext context);
