using System.Collections.Concurrent;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Releases asynchronous contenders together or aborts an incomplete rendezvous when a participant reports a fault.
/// </summary>
internal sealed class CancellableTestBarrier: IAsyncDisposable
{
    /// <summary>Counts arrivals atomically so the final contender releases all waiting requests.</summary>
    private int arrivedCount;

    /// <summary>Names the rendezvous so a missing participant is identifiable in a test failure.</summary>
    private string Name { get; }

    /// <summary>Specifies how many contenders must arrive before any can proceed.</summary>
    private int ParticipantCount { get; }

    /// <summary>Preserves cancellation from the runner instead of reporting it as a missing participant.</summary>
    private CancellationToken TestCancellationToken { get; }

    /// <summary>Cancels the shared rendezvous task only when the enclosing test's runner cancels.</summary>
    private CancellationTokenRegistration RunnerCancellation { get; }

    /// <summary>Publishes the final arrival without running request continuations under the signaling call.</summary>
    private TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Retains each operation and its observation until cleanup can observe faults and dispose response messages.</summary>
    private ConcurrentQueue<Func<Task>> ParticipantCleanup { get; } = new();


    /// <summary>Creates a named rendezvous bounded by runner cancellation and participant faults alone.</summary>
    /// <param name="name">The rendezvous name included in an incomplete-barrier failure.</param>
    /// <param name="participantCount">The positive number of contenders required to release the barrier.</param>
    /// <param name="testCancellationToken">The enclosing test's cancellation token.</param>
    public CancellableTestBarrier(string name, int participantCount, CancellationToken testCancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(participantCount);
        Name = name;
        ParticipantCount = participantCount;
        TestCancellationToken = testCancellationToken;
        RunnerCancellation = testCancellationToken.Register(() =>
        {
            _ = Release.TrySetCanceled(testCancellationToken);
        });
    }


    /// <summary>Registers one contender and waits until every contender has reached the rendezvous.</summary>
    public Task SignalAndWaitAsync()
    {
        if(Interlocked.Increment(ref arrivedCount) == ParticipantCount)
        {
            _ = Release.TrySetResult();
        }

        return WaitForReleaseAsync();
    }


    /// <summary>
    /// Observes release from the test as well as its request callbacks, so a swallowed server exception
    /// cannot hide which barrier failed to fill.
    /// </summary>
    public Task WaitForReleaseAsync()
    {

        return Release.Task;
    }


    /// <summary>
    /// Aborts an incomplete rendezvous with its name, arrival count and original cause so every waiter
    /// observes the participant's fault even when a server converts that exception into an HTTP response.
    /// </summary>
    /// <param name="exception">The participant or test failure that prevents the group from filling.</param>
    public void ReportFault(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        _ = Release.TrySetException(new InvalidOperationException(
            $"Barrier '{Name}' failed: {Volatile.Read(ref arrivedCount)}/{ParticipantCount} participants arrived.",
            exception));
    }


    /// <summary>
    /// Observes a participant's whole operation so an exception or a response before the rendezvous
    /// fills faults the barrier instead of leaving its contenders and observers suspended.
    /// Retains the operation for cleanup and owns disposal of any response message when the barrier's scope ends.
    /// </summary>
    /// <typeparam name="T">The participant's result, preserved for the test's outcome assertions.</typeparam>
    /// <param name="participant">The operation expected to reach the rendezvous before completing.</param>
    /// <returns>The participant's result once its operation completes.</returns>
    public Task<T> ObserveParticipantAsync<T>(Func<Task<T>> participant)
    {
        Task<T> operation = InvokeParticipantAsync(participant);
        Task<T> observation = ObserveCompletionAsync(operation);
        ParticipantCleanup.Enqueue(() => ObserveAndDisposeParticipantAsync(operation, observation));

        return observation;
    }


    /// <summary>Captures synchronous delegate failures as tasks so cleanup retains every participant's outcome.</summary>
    private static async Task<T> InvokeParticipantAsync<T>(Func<Task<T>> participant)
    {

        return await participant().ConfigureAwait(false);
    }


    /// <summary>Reports premature completion or failure without replacing the runner's cancellation with a barrier fault.</summary>
    private async Task<T> ObserveCompletionAsync<T>(Task<T> participant)
    {
        try
        {
            T result = await participant.WaitAsync(TestCancellationToken).ConfigureAwait(false);
            if(!TestCancellationToken.IsCancellationRequested && !Release.Task.IsCompleted)
            {
                ReportFault(new InvalidOperationException("A participant completed before the rendezvous filled."));
            }

            return result;
        }
        catch(Exception exception) when(!TestCancellationToken.IsCancellationRequested)
        {
            ReportFault(exception);
            throw;
        }

    }


    /// <summary>
    /// Observes both tasks even when cancellation ends the test's wait first, and disposes any eventual
    /// response so a late successful request still has an owner after another participant faults.
    /// </summary>
    private static async Task ObserveAndDisposeParticipantAsync<T>(Task<T> operation, Task<T> observation)
    {
        try
        {
            _ = await observation.ConfigureAwait(false);
        }
        catch(Exception)
        {
            //The returned observation and the release task carry failures to the test.
        }

        try
        {
            T result = await operation.ConfigureAwait(false);
            if(result is HttpResponseMessage response)
            {
                response.Dispose();
            }

        }
        catch(Exception)
        {
            //An operation may fail after its runner-cancelled observation; its exception is still observed here.
        }

    }


    /// <summary>
    /// Completes an incomplete rendezvous before draining retained participants or removing its
    /// cancellation registration, so cancellation callback ordering cannot strand a waiting operation.
    /// Runner cancellation is preserved; otherwise disposal reports the barrier's name and arrival count.
    /// Cleanup retains ownership of eventual responses if runner cancellation ends the disposal wait.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if(!Release.Task.IsCompleted)
        {
            if(TestCancellationToken.IsCancellationRequested)
            {
                _ = Release.TrySetCanceled(TestCancellationToken);
            }
            else
            {
                ReportFault(new ObjectDisposedException(nameof(CancellableTestBarrier),
                    "The barrier was disposed before every participant arrived."));
            }

        }

        try
        {
            List<Task> cleanupTasks = [];
            while(ParticipantCleanup.TryDequeue(out Func<Task>? cleanup))
            {
                cleanupTasks.Add(cleanup());
            }

            await Task.WhenAll(cleanupTasks).WaitAsync(TestCancellationToken).ConfigureAwait(false);
        }
        catch(OperationCanceledException) when(TestCancellationToken.IsCancellationRequested)
        {
            //Started cleanup tasks keep ownership of eventual responses after the runner ends this wait.
        }
        finally
        {
            await RunnerCancellation.DisposeAsync().ConfigureAwait(false);
        }

    }

}
