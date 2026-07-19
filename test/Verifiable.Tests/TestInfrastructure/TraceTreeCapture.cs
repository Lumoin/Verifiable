using System.Collections.Concurrent;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Server.Diagnostics;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// An <see cref="ActivityListener"/> wrapper that captures every stopped
/// <see cref="Activity"/> from an explicit, closed set of <see cref="ActivitySource"/>
/// names so a test can reconstruct and assert one connected W3C Trace Context span
/// tree with <see cref="TraceTreeAssertions"/>.
/// </summary>
/// <remarks>
/// <para>
/// The source-name set is the documentation of what the captured tree covers: the
/// ASP.NET Core server spans (<see cref="AspNetCoreSourceName"/>), the
/// <see cref="System.Net.Http.HttpClient"/> client spans (<see cref="HttpClientSourceName"/>),
/// the library's dispatch spans (<see cref="ServerActivitySource.SourceName"/>), and the
/// cryptographic lifetime spans (<see cref="CryptoActivitySource.Name"/>). There is
/// deliberately no wildcard subscription — a capture that listens to "everything"
/// documents nothing about which instrumentation layers a connected trace must include.
/// </para>
/// <para>
/// Sampling is <see cref="ActivitySamplingResult.AllDataAndRecorded"/> on both the
/// <see cref="ActivityListener.Sample"/> and <see cref="ActivityListener.SampleUsingParentId"/>
/// paths, so framework instrumentation populates its full tag set and marks spans
/// recorded, which propagates the sampled flag in the <c>traceparent</c> headers the
/// runtime injects across process-internal wire hops.
/// </para>
/// <para>
/// An <see cref="ActivityListener"/> is process-wide: while an instance is alive,
/// every concurrently running test's HTTP traffic gains framework activities and
/// <c>traceparent</c> header injection, and those foreign spans land in this capture.
/// Consumers therefore mark their test classes <c>[DoNotParallelize]</c> and assert
/// only over spans filtered by their own root <see cref="Activity.TraceId"/>
/// (<see cref="TraceTreeAssertions.FilterByTrace"/>).
/// </para>
/// </remarks>
internal sealed class TraceTreeCapture: IDisposable
{
    private readonly ConcurrentQueue<Activity> stoppedActivities = new();
    private readonly ActivityListener listener;

    /// <summary>
    /// The ASP.NET Core hosting <see cref="ActivitySource"/> name. It emits the
    /// <c>Microsoft.AspNetCore.Hosting.HttpRequestIn</c> span
    /// (<see cref="ActivityKind.Server"/>) for every request a Kestrel host processes.
    /// </summary>
    public static string AspNetCoreSourceName => "Microsoft.AspNetCore";

    /// <summary>
    /// The <see cref="System.Net.Http.HttpClient"/> <see cref="ActivitySource"/> name.
    /// It emits the <c>System.Net.Http.HttpRequestOut</c> span
    /// (<see cref="ActivityKind.Client"/>) for every outbound request, and injects the
    /// current trace context as the <c>traceparent</c> request header.
    /// </summary>
    public static string HttpClientSourceName => "System.Net.Http";

    /// <summary>
    /// The default source-name set: <see cref="AspNetCoreSourceName"/>,
    /// <see cref="HttpClientSourceName"/>, <see cref="ServerActivitySource.SourceName"/>,
    /// and <see cref="CryptoActivitySource.Name"/>.
    /// </summary>
    public static IReadOnlyList<string> DefaultSourceNames { get; } =
    [
        AspNetCoreSourceName,
        HttpClientSourceName,
        ServerActivitySource.SourceName,
        CryptoActivitySource.Name
    ];


    /// <summary>
    /// Starts capturing stopped activities from <paramref name="sourceNames"/>, or from
    /// <see cref="DefaultSourceNames"/> when <see langword="null"/>. Source names match
    /// by ordinal equality — never by prefix or wildcard.
    /// </summary>
    /// <param name="sourceNames">The exact <see cref="ActivitySource"/> names to listen to.</param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="sourceNames"/> is empty: a capture over no sources
    /// records nothing and would silently weaken every assertion built on it.
    /// </exception>
    public TraceTreeCapture(IReadOnlyCollection<string>? sourceNames = null)
    {
        HashSet<string> subscribedSourceNames = new(sourceNames ?? DefaultSourceNames, StringComparer.Ordinal);
        if(subscribedSourceNames.Count == 0)
        {
            throw new ArgumentException(
                "At least one activity source name is required; an empty set captures nothing.",
                nameof(sourceNames));
        }

        listener = new ActivityListener
        {
            ShouldListenTo = source => subscribedSourceNames.Contains(source.Name),
            Sample = static (ref ActivityCreationOptions<ActivityContext> _) =>
                ActivitySamplingResult.AllDataAndRecorded,
            SampleUsingParentId = static (ref ActivityCreationOptions<string> _) =>
                ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = stoppedActivities.Enqueue
        };

        ActivitySource.AddActivityListener(listener);
    }


    /// <summary>
    /// A snapshot of every activity that has stopped since the capture started, in
    /// stop order. Safe to read while requests are still in flight; spans that have
    /// not stopped yet are absent from the snapshot, so read after the traffic under
    /// assertion has fully completed (for example after the loopback host has drained).
    /// </summary>
    public IReadOnlyList<Activity> StoppedActivities => [.. stoppedActivities];


    /// <inheritdoc/>
    public void Dispose()
    {
        listener.Dispose();
    }
}
