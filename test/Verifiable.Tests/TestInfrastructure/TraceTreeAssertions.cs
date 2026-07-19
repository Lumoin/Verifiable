using System.Diagnostics;
using System.Globalization;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Assertions over a set of captured <see cref="Activity"/> spans (see
/// <see cref="TraceTreeCapture"/>) that prove a flow produced ONE connected
/// W3C Trace Context span tree: every span reachable from the test's root via
/// <see cref="Activity.ParentSpanId"/> links, at least one span attributable to
/// each participating host, and named events attached under their owning span.
/// </summary>
/// <remarks>
/// <para>
/// All assertions first filter the captured set by the root's
/// <see cref="Activity.TraceId"/> (<see cref="FilterByTrace"/>), because an
/// <see cref="ActivityListener"/> is process-wide and captures foreign tests'
/// spans while it is alive.
/// </para>
/// <para>
/// <strong>Host attribution keys.</strong> Attribution is keyed on what the .NET
/// runtime's own instrumentation emits when a listener requests all data:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       <c>System.Net.Http.HttpRequestOut</c> client spans carry the OTel HTTP
///       client semantic-convention tags <c>url.full</c>, <c>server.address</c>, and
///       <c>server.port</c>. A client span is attributed directly: first from
///       <c>url.full</c>, then from <c>server.address</c> + <c>server.port</c>.
///     </description>
///   </item>
///   <item>
///     <description>
///       <c>Microsoft.AspNetCore.Hosting.HttpRequestIn</c> server spans carry
///       <c>http.request.method</c>, <c>url.scheme</c>, <c>url.path</c>,
///       <c>url.query</c>, and <c>network.protocol.version</c> — no request-authority
///       tag, so a server span is generally not host-attributable from its own tags.
///       It inherits the host of its nearest attributable ancestor: its W3C parent is
///       the very <c>HttpRequestOut</c> span that dialed the host, so the inherited
///       attribution is exact. The same inheritance covers library spans (for example
///       <c>server.handle</c>) nested inside a server span. Should a runtime add
///       <c>server.address</c>/<c>server.port</c> to server spans, the direct path
///       already honors them.
///     </description>
///   </item>
/// </list>
/// <para>
/// Host names compare ordinal-ignore-case, with <c>localhost</c>, <c>127.0.0.1</c>,
/// and <c>::1</c> treated as equivalent loopback designators; ports must match
/// exactly. When a span carries a host but no port, it is attributed only if exactly
/// one expected host matches — in a loopback topology every host shares the loopback
/// address and only the port discriminates, so an ambiguous portless match proves
/// nothing.
/// </para>
/// </remarks>
internal static class TraceTreeAssertions
{
    private const string UrlFullTagName = "url.full";
    private const string ServerAddressTagName = "server.address";
    private const string ServerPortTagName = "server.port";


    /// <summary>
    /// Returns the activities whose <see cref="Activity.TraceId"/> equals
    /// <paramref name="traceId"/> — the per-test isolation step that discards spans
    /// emitted by concurrently running tests into the same process-wide listener.
    /// </summary>
    public static IReadOnlyList<Activity> FilterByTrace(IEnumerable<Activity> activities, ActivityTraceId traceId)
    {
        ArgumentNullException.ThrowIfNull(activities);

        return [.. activities.Where(activity => activity.TraceId == traceId)];
    }


    /// <summary>
    /// Asserts that every captured span carrying <paramref name="root"/>'s
    /// <see cref="Activity.TraceId"/> is reachable from <paramref name="root"/> via
    /// <see cref="Activity.ParentSpanId"/> links — a single connected component with
    /// the root at its top. A span whose ancestor chain dead-ends outside the captured
    /// set (a broken or missing parent link) fails the assertion and is named in the
    /// failure message.
    /// </summary>
    /// <param name="capturedActivities">The captured spans, typically <see cref="TraceTreeCapture.StoppedActivities"/>.</param>
    /// <param name="root">The test's root activity; it need not itself be captured.</param>
    public static void AssertSingleConnectedTree(IEnumerable<Activity> capturedActivities, Activity root)
    {
        ArgumentNullException.ThrowIfNull(capturedActivities);
        ArgumentNullException.ThrowIfNull(root);

        IReadOnlyList<Activity> inTrace = FilterByTrace(capturedActivities, root.TraceId);
        Assert.IsGreaterThan(0, inTrace.Count,
            $"No captured span carries the root TraceId '{root.TraceId}'; the trace tree is empty.");

        Dictionary<ActivitySpanId, Activity> bySpanId = BuildSpanIndex(inTrace);

        string[] disconnectedSpans = [.. inTrace
            .Where(activity => !IsSelfOrDescendantOf(activity, root.SpanId, bySpanId))
            .Select(activity =>
                $"'{activity.OperationName}' (SpanId {activity.SpanId}, ParentSpanId {activity.ParentSpanId})")];

        Assert.IsEmpty(disconnectedSpans,
            $"Every span with TraceId '{root.TraceId}' must be reachable from the root span " +
            $"'{root.SpanId}' via ParentSpanId links; {disconnectedSpans.Length} of {inTrace.Count} " +
            $"are not: {string.Join("; ", disconnectedSpans)}.");
    }


    /// <summary>
    /// Asserts that for each base address in <paramref name="hostBaseAddresses"/> the
    /// trace contains at least one span attributable to that host — by default a
    /// server-side span (<see cref="ActivityKind.Server"/>), proving the request was
    /// processed at the host inside the same trace rather than merely dialed. See the
    /// class remarks for the attribution keys and the ancestor-inheritance rule.
    /// </summary>
    /// <param name="capturedActivities">The captured spans, typically <see cref="TraceTreeCapture.StoppedActivities"/>.</param>
    /// <param name="root">The test's root activity; only spans in its trace participate.</param>
    /// <param name="hostBaseAddresses">The base address of every host the flow must have touched.</param>
    /// <param name="isServerSpanRequired">
    /// When <see langword="true"/>, only spans of <see cref="ActivityKind.Server"/>
    /// satisfy a host; when <see langword="false"/>, any attributable span does.
    /// </param>
    public static void AssertSpanForEachHost(
        IEnumerable<Activity> capturedActivities,
        Activity root,
        IReadOnlyCollection<Uri> hostBaseAddresses,
        bool isServerSpanRequired = true)
    {
        ArgumentNullException.ThrowIfNull(capturedActivities);
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(hostBaseAddresses);
        Assert.IsGreaterThan(0, hostBaseAddresses.Count,
            "At least one expected host base address is required.");

        IReadOnlyList<Activity> inTrace = FilterByTrace(capturedActivities, root.TraceId);
        Dictionary<ActivitySpanId, Activity> bySpanId = BuildSpanIndex(inTrace);

        Dictionary<ActivitySpanId, Uri?> attributionsBySpanId = new(inTrace.Count);
        foreach(Activity activity in inTrace)
        {
            attributionsBySpanId[activity.SpanId] = AttributeToHost(activity, hostBaseAddresses, bySpanId);
        }

        List<string> missingHosts = [];
        foreach(Uri hostBaseAddress in hostBaseAddresses)
        {
            bool hasSpanAtHost = inTrace.Any(activity =>
                hostBaseAddress.Equals(attributionsBySpanId[activity.SpanId])
                && (!isServerSpanRequired || activity.Kind == ActivityKind.Server));

            if(!hasSpanAtHost)
            {
                missingHosts.Add(hostBaseAddress.ToString());
            }
        }

        if(missingHosts.Count > 0)
        {
            string observedAttributions = string.Join("; ", inTrace.Select(activity =>
                $"'{activity.OperationName}' ({activity.Kind}) -> " +
                $"{attributionsBySpanId[activity.SpanId]?.ToString() ?? "unattributed"}"));

            Assert.Fail(
                $"Trace '{root.TraceId}' has no {(isServerSpanRequired ? "server-side " : string.Empty)}span " +
                $"attributable to: {string.Join(", ", missingHosts)}. Observed spans: {observedAttributions}.");
        }
    }


    /// <summary>
    /// Asserts that an event named <paramref name="eventName"/> exists in the trace
    /// and is attached on the span identified by <paramref name="ancestorSpanId"/> or
    /// on one of its descendants. The ancestor itself need not be captured — the
    /// ancestor-chain walk compares span identifiers, so the test's own root span
    /// qualifies as an ancestor.
    /// </summary>
    /// <param name="capturedActivities">The captured spans, typically <see cref="TraceTreeCapture.StoppedActivities"/>.</param>
    /// <param name="root">The test's root activity; only spans in its trace participate.</param>
    /// <param name="eventName">The exact (ordinal) <see cref="ActivityEvent.Name"/>.</param>
    /// <param name="ancestorSpanId">The span the event must sit on or under.</param>
    public static void AssertEventUnderAncestor(
        IEnumerable<Activity> capturedActivities,
        Activity root,
        string eventName,
        ActivitySpanId ancestorSpanId)
    {
        ArgumentNullException.ThrowIfNull(capturedActivities);
        ArgumentNullException.ThrowIfNull(root);
        ArgumentException.ThrowIfNullOrWhiteSpace(eventName);

        IReadOnlyList<Activity> inTrace = FilterByTrace(capturedActivities, root.TraceId);
        AssertEventUnderAncestorCore(inTrace, root, eventName, [ancestorSpanId], $"span '{ancestorSpanId}'");
    }


    /// <summary>
    /// Asserts that an event named <paramref name="eventName"/> exists in the trace
    /// and is attached on a captured span matching <paramref name="isAncestorMatch"/>
    /// or on one of that span's descendants. Use this form to name the ancestor
    /// structurally — for example the owning dispatch span by operation name and
    /// tenant tag — instead of by span identifier.
    /// </summary>
    /// <param name="capturedActivities">The captured spans, typically <see cref="TraceTreeCapture.StoppedActivities"/>.</param>
    /// <param name="root">The test's root activity; only spans in its trace participate.</param>
    /// <param name="eventName">The exact (ordinal) <see cref="ActivityEvent.Name"/>.</param>
    /// <param name="isAncestorMatch">Selects the captured span(s) that qualify as the ancestor.</param>
    public static void AssertEventUnderAncestor(
        IEnumerable<Activity> capturedActivities,
        Activity root,
        string eventName,
        Func<Activity, bool> isAncestorMatch)
    {
        ArgumentNullException.ThrowIfNull(capturedActivities);
        ArgumentNullException.ThrowIfNull(root);
        ArgumentException.ThrowIfNullOrWhiteSpace(eventName);
        ArgumentNullException.ThrowIfNull(isAncestorMatch);

        IReadOnlyList<Activity> inTrace = FilterByTrace(capturedActivities, root.TraceId);

        ActivitySpanId[] ancestorSpanIds = [.. inTrace
            .Where(isAncestorMatch)
            .Select(activity => activity.SpanId)];
        Assert.IsGreaterThan(0, ancestorSpanIds.Length,
            $"No captured span in trace '{root.TraceId}' matches the ancestor predicate.");

        AssertEventUnderAncestorCore(inTrace, root, eventName, ancestorSpanIds,
            $"{ancestorSpanIds.Length} predicate-matched span(s)");
    }


    private static void AssertEventUnderAncestorCore(
        IReadOnlyList<Activity> inTrace,
        Activity root,
        string eventName,
        IReadOnlyCollection<ActivitySpanId> ancestorSpanIds,
        string ancestorDescription)
    {
        Dictionary<ActivitySpanId, Activity> bySpanId = BuildSpanIndex(inTrace);

        Activity[] eventCarriers = [.. inTrace.Where(activity =>
            activity.Events.Any(activityEvent =>
                string.Equals(activityEvent.Name, eventName, StringComparison.Ordinal)))];
        Assert.IsGreaterThan(0, eventCarriers.Length,
            $"No span in trace '{root.TraceId}' carries an event named '{eventName}'.");

        bool isAttachedUnderAncestor = eventCarriers.Any(carrier =>
            ancestorSpanIds.Any(ancestorSpanId => IsSelfOrDescendantOf(carrier, ancestorSpanId, bySpanId)));
        Assert.IsTrue(isAttachedUnderAncestor,
            $"Event '{eventName}' occurs on {eventCarriers.Length} span(s) in trace '{root.TraceId}', " +
            $"but none of those spans is under {ancestorDescription}.");
    }


    /// <summary>
    /// Returns whether <paramref name="activity"/> is the span identified by
    /// <paramref name="ancestorSpanId"/> or one of its descendants, walking
    /// <see cref="Activity.ParentSpanId"/> links through the captured index. The walk
    /// compares span identifiers, so an uncaptured ancestor (the test's root) still
    /// terminates it; a visited-set guards against malformed parent cycles.
    /// </summary>
    private static bool IsSelfOrDescendantOf(
        Activity activity,
        ActivitySpanId ancestorSpanId,
        Dictionary<ActivitySpanId, Activity> bySpanId)
    {
        if(activity.SpanId == ancestorSpanId)
        {
            return true;
        }

        HashSet<ActivitySpanId> visited = [activity.SpanId];
        ActivitySpanId parentSpanId = activity.ParentSpanId;
        while(visited.Add(parentSpanId))
        {
            if(parentSpanId == ancestorSpanId)
            {
                return true;
            }

            if(!bySpanId.TryGetValue(parentSpanId, out Activity? parent))
            {
                return false;
            }

            parentSpanId = parent.ParentSpanId;
        }

        return false;
    }


    /// <summary>
    /// Attributes <paramref name="activity"/> to one of
    /// <paramref name="hostBaseAddresses"/>: directly from its own url/server tags
    /// when present, otherwise inherited from the nearest directly-attributable
    /// ancestor (see the class remarks for why server spans rely on inheritance).
    /// Returns <see langword="null"/> when neither the span nor any ancestor is
    /// attributable.
    /// </summary>
    private static Uri? AttributeToHost(
        Activity activity,
        IReadOnlyCollection<Uri> hostBaseAddresses,
        Dictionary<ActivitySpanId, Activity> bySpanId)
    {
        Activity? current = activity;
        HashSet<ActivitySpanId> visited = [];
        while(current is not null && visited.Add(current.SpanId))
        {
            Uri? directAttribution = AttributeDirectly(current, hostBaseAddresses);
            if(directAttribution is not null)
            {
                return directAttribution;
            }

            current = bySpanId.TryGetValue(current.ParentSpanId, out Activity? parent) ? parent : null;
        }

        return null;
    }


    private static Uri? AttributeDirectly(Activity activity, IReadOnlyCollection<Uri> hostBaseAddresses)
    {
        string? urlFull = activity.GetTagItem(UrlFullTagName)?.ToString();
        if(urlFull is not null && Uri.TryCreate(urlFull, UriKind.Absolute, out Uri? url))
        {
            Uri? urlMatch = MatchHostAndPort(hostBaseAddresses, url.Host, url.Port);
            if(urlMatch is not null)
            {
                return urlMatch;
            }
        }

        string? serverAddress = activity.GetTagItem(ServerAddressTagName)?.ToString();
        if(serverAddress is not null)
        {
            string? serverPortText = activity.GetTagItem(ServerPortTagName)?.ToString();
            int? serverPort =
                int.TryParse(serverPortText, NumberStyles.None, CultureInfo.InvariantCulture, out int parsedPort)
                    ? parsedPort
                    : null;

            return MatchHostAndPort(hostBaseAddresses, serverAddress, serverPort);
        }

        return null;
    }


    /// <summary>
    /// Matches a host name (loopback designators equivalent, otherwise
    /// ordinal-ignore-case) and port against the expected base addresses. With a port
    /// the match is exact; without one the match holds only when a single candidate
    /// host name matches, because in a loopback topology only the port discriminates
    /// between hosts.
    /// </summary>
    private static Uri? MatchHostAndPort(IReadOnlyCollection<Uri> hostBaseAddresses, string host, int? port)
    {
        Uri? uniqueHostNameMatch = null;
        foreach(Uri candidate in hostBaseAddresses)
        {
            bool isHostMatch = string.Equals(candidate.Host, host, StringComparison.OrdinalIgnoreCase)
                || (IsLoopbackHostName(candidate.Host) && IsLoopbackHostName(host));
            if(!isHostMatch)
            {
                continue;
            }

            if(port is not null)
            {
                if(candidate.Port == port.Value)
                {
                    return candidate;
                }

                continue;
            }

            if(uniqueHostNameMatch is not null)
            {
                return null;
            }

            uniqueHostNameMatch = candidate;
        }

        return uniqueHostNameMatch;
    }


    private static bool IsLoopbackHostName(string host) =>
        string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
            || string.Equals(host, "127.0.0.1", StringComparison.Ordinal)
            || string.Equals(host, "::1", StringComparison.Ordinal);


    private static Dictionary<ActivitySpanId, Activity> BuildSpanIndex(IReadOnlyList<Activity> activities)
    {
        Dictionary<ActivitySpanId, Activity> bySpanId = new(activities.Count);
        foreach(Activity activity in activities)
        {
            bySpanId[activity.SpanId] = activity;
        }

        return bySpanId;
    }
}
