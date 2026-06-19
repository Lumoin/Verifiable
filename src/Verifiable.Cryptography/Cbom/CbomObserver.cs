using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.Cryptography.Cbom;

/// <summary>
/// Captures cryptographic telemetry spans emitted on the
/// <see cref="CryptoActivitySource"/> while a workload runs, then renders an observed
/// ("runtime") CBOM from what actually executed.
/// </summary>
/// <remarks>
/// <para>
/// The underlying <see cref="ActivityListener"/> is process-wide: it sees every
/// <c>Verifiable.Cryptography</c> span in the process, including those produced by
/// sibling work running in parallel. To stay isolated, the observer starts a per-run
/// root <see cref="Activity"/> and keeps only spans whose <see cref="Activity.TraceId"/>
/// matches that root. Child spans started by the workload inherit the root's trace id
/// through <see cref="Activity.Current"/>, so the correlation holds without any
/// cooperation from the cryptographic backends.
/// </para>
/// </remarks>
public sealed class CbomObserver: IDisposable
{
    private readonly ActivityListener listener;
    private readonly ConcurrentQueue<Activity> captured = new();
    private bool isDisposed;


    /// <summary>
    /// Creates a new observer and attaches its listener to the
    /// <see cref="CryptoActivitySource"/>.
    /// </summary>
    public CbomObserver()
    {
        listener = new ActivityListener
        {
            ShouldListenTo = source =>
                string.Equals(source.Name, CryptoActivitySource.Name, StringComparison.Ordinal),
            Sample = static (ref ActivityCreationOptions<ActivityContext> _) =>
                ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => captured.Enqueue(activity)
        };

        ActivitySource.AddActivityListener(listener);
    }


    /// <summary>
    /// Runs <paramref name="workload"/> under a fresh per-run root activity, captures the
    /// cryptographic spans it produces, and renders the observed CBOM.
    /// </summary>
    /// <param name="workload">The asynchronous workload to observe.</param>
    /// <param name="timestamp">The RFC 3339 generation timestamp for the rendered document.</param>
    /// <param name="toolVersion">The version string of the generating tool.</param>
    /// <returns>The observed <see cref="CbomDocument"/>.</returns>
    public async Task<CbomDocument> ObserveAsync(
        Func<Task> workload,
        string timestamp,
        string toolVersion)
    {
        ArgumentNullException.ThrowIfNull(workload);
        ArgumentNullException.ThrowIfNull(timestamp);
        ArgumentNullException.ThrowIfNull(toolVersion);

        //A new ActivitySource guarantees a started root regardless of any ambient listener
        //configuration, so the workload's spans inherit a known TraceId to filter on.
        using ActivitySource runScope = new("Verifiable.Cbom.ObserverRun");
        using ActivityListener rootListener = new()
        {
            ShouldListenTo = source =>
                string.Equals(source.Name, runScope.Name, StringComparison.Ordinal),
            Sample = static (ref ActivityCreationOptions<ActivityContext> _) =>
                ActivitySamplingResult.AllDataAndRecorded
        };
        ActivitySource.AddActivityListener(rootListener);

        ActivityTraceId runTraceId;
        using(Activity? root = runScope.StartActivity("cbom.observe.run"))
        {
            runTraceId = root?.TraceId ?? default;
            await workload().ConfigureAwait(false);
        }

        List<Activity> runActivities = [];
        foreach(Activity activity in captured)
        {
            if(activity.TraceId == runTraceId)
            {
                runActivities.Add(activity);
            }
        }

        return ObservedCbomRenderer.Render(runActivities, timestamp, toolVersion);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(isDisposed)
        {
            return;
        }

        listener.Dispose();
        isDisposed = true;
    }
}
