namespace Verifiable.Tests.TestInfrastructure;

/// <summary>Proves that contender release, missing arrivals and runner cancellation remain distinct outcomes.</summary>
[TestClass]
internal sealed class CancellableTestBarrierTests
{
    /// <summary>Supplies runner cancellation so every synchronization check remains bounded by its test.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>Every contender remains suspended until the final arrival releases the complete group.</summary>
    [TestMethod]
    public async Task AllParticipantsWaitUntilTheBarrierFills()
    {
        await using CancellableTestBarrier barrier = new(
            "complete group", 2, TestContext.CancellationToken);
        Task firstArrival = barrier.SignalAndWaitAsync();
        Task observer = barrier.WaitForReleaseAsync();
        Assert.IsFalse(firstArrival.IsCompleted);
        Assert.IsFalse(observer.IsCompleted);

        Task secondArrival = barrier.SignalAndWaitAsync();
        await Task.WhenAll(firstArrival, secondArrival, observer).ConfigureAwait(false);
        int result = await barrier.ObserveParticipantAsync(() => Task.FromResult(200)).ConfigureAwait(false);
        Assert.AreEqual(200, result);
    }


    /// <summary>A reported fault releases every incomplete contender and observer with the rendezvous name, count and cause.</summary>
    [TestMethod]
    public async Task IncompleteBarrierReportsItsNameAndArrivalCount()
    {
        await using CancellableTestBarrier barrier = new(
            "incomplete group", 3, TestContext.CancellationToken);
        Task firstArrival = barrier.SignalAndWaitAsync();
        Task secondArrival = barrier.SignalAndWaitAsync();
        Task observer = barrier.WaitForReleaseAsync();
        Assert.IsFalse(firstArrival.IsCompleted);
        Assert.IsFalse(secondArrival.IsCompleted);
        Assert.IsFalse(observer.IsCompleted);
        InvalidOperationException participantFault = new("The remaining participant cannot arrive.");
        barrier.ReportFault(participantFault);

        foreach(Task waiter in new[] { firstArrival, secondArrival, observer, barrier.WaitForReleaseAsync() })
        {
            Assert.IsTrue(waiter.IsFaulted, "Reporting a fault must complete every wait without another signal.");
            InvalidOperationException failure = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
                () => waiter.WaitAsync(TestContext.CancellationToken)).ConfigureAwait(false);
            Assert.Contains("Barrier 'incomplete group'", failure.Message, StringComparison.Ordinal);
            Assert.Contains("2/3 participants arrived", failure.Message, StringComparison.Ordinal);
            Assert.AreSame(participantFault, failure.InnerException);
        }

    }


    /// <summary>A participant exception faults suspended contenders and observers while preserving the original cause.</summary>
    [TestMethod]
    public async Task ParticipantExceptionFaultsAnIncompleteBarrier()
    {
        await using CancellableTestBarrier barrier = new("failed participant", 2, TestContext.CancellationToken);
        Task firstArrival = barrier.SignalAndWaitAsync();
        Task observer = barrier.WaitForReleaseAsync();
        TaskCompletionSource<int> participant = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<int> operation = barrier.ObserveParticipantAsync(() => participant.Task);
        InvalidOperationException participantFault = new("The participant failed before arriving.");
        participant.SetException(participantFault);

        InvalidOperationException operationFailure = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => operation.WaitAsync(TestContext.CancellationToken)).ConfigureAwait(false);
        Assert.AreSame(participantFault, operationFailure);
        foreach(Task waiter in new[] { firstArrival, observer })
        {
            Assert.IsTrue(waiter.IsFaulted, "Observing a participant exception must immediately fault every wait.");
            InvalidOperationException failure = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
                () => waiter.WaitAsync(TestContext.CancellationToken)).ConfigureAwait(false);
            Assert.Contains("Barrier 'failed participant'", failure.Message, StringComparison.Ordinal);
            Assert.Contains("1/2 participants arrived", failure.Message, StringComparison.Ordinal);
            Assert.AreSame(participantFault, failure.InnerException);
        }

    }


    /// <summary>A completed request that bypasses the rendezvous faults its waiters even when the server swallowed an exception.</summary>
    [TestMethod]
    public async Task ParticipantCompletionBeforeArrivalFaultsAnIncompleteBarrier()
    {
        await using CancellableTestBarrier barrier = new("missing arrival", 2, TestContext.CancellationToken);
        Task firstArrival = barrier.SignalAndWaitAsync();
        Task observer = barrier.WaitForReleaseAsync();
        int response = await barrier.ObserveParticipantAsync(() => Task.FromResult(500)).ConfigureAwait(false);
        Assert.AreEqual(500, response);
        foreach(Task waiter in new[] { firstArrival, observer })
        {
            Assert.IsTrue(waiter.IsFaulted, "A response before the rendezvous fills must immediately fault every wait.");
            InvalidOperationException failure = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
                () => waiter.WaitAsync(TestContext.CancellationToken)).ConfigureAwait(false);
            Assert.Contains("Barrier 'missing arrival'", failure.Message, StringComparison.Ordinal);
            Assert.Contains("1/2 participants arrived", failure.Message, StringComparison.Ordinal);
            _ = Assert.IsInstanceOfType<InvalidOperationException>(failure.InnerException);
        }

    }


    /// <summary>Runner cancellation interrupts both contenders and observers without reporting a barrier failure.</summary>
    [TestMethod]
    public async Task RunnerCancellationIsPropagated()
    {
        using CancellationTokenSource cancellation = CancellationTokenSource.CreateLinkedTokenSource(
            TestContext.CancellationToken);
        await using CancellableTestBarrier barrier = new(
            "cancelled group", 2, cancellation.Token);
        Task firstArrival = barrier.SignalAndWaitAsync();
        Task observer = barrier.WaitForReleaseAsync();
        await cancellation.CancelAsync().ConfigureAwait(false);

        foreach(Task waiter in new[] { firstArrival, observer })
        {
            Assert.IsTrue(waiter.IsCanceled, "Runner cancellation must cancel every wait without a barrier fault.");
            OperationCanceledException failure = await Assert.ThrowsAsync<OperationCanceledException>(
                () => waiter).ConfigureAwait(false);
            Assert.AreEqual(cancellation.Token, failure.CancellationToken);
        }

    }


    /// <summary>
    /// A successful participant invoked by the newest cancellation callback cannot fault an incomplete
    /// barrier before its older cancellation callback runs; cancellation remains the release outcome.
    /// </summary>
    [TestMethod]
    public async Task RunnerCancellationWinsWhenALifoCallbackCompletesAParticipantBeforeBarrierCancellation()
    {
        using CancellationTokenSource cancellation = CancellationTokenSource.CreateLinkedTokenSource(
            TestContext.CancellationToken);
        await using CancellableTestBarrier barrier = new("cancelled during completion", 2, cancellation.Token);
        Task arrival = barrier.SignalAndWaitAsync();
        Task observer = barrier.WaitForReleaseAsync();
        TaskCompletionSource<Task<int>> participantObservation = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using CancellationTokenRegistration participantCancellation = cancellation.Token.Register(() =>
        {
            //Callbacks run in LIFO order, so the barrier's older callback has not cancelled release yet.
            participantObservation.SetResult(barrier.ObserveParticipantAsync(() => Task.FromResult(500)));
        });

        await cancellation.CancelAsync().ConfigureAwait(false);
        Task<int> operation = await participantObservation.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(500, await operation.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false));
        foreach(Task waiter in new[] { arrival, observer })
        {
            OperationCanceledException failure = await Assert.ThrowsAsync<OperationCanceledException>(
                () => waiter.WaitAsync(TestContext.CancellationToken)).ConfigureAwait(false);
            Assert.AreEqual(cancellation.Token, failure.CancellationToken);
        }

    }


    /// <summary>
    /// Disposal from the newest cancellation callback completes the rendezvous before unregistering
    /// its older callback, so a retained participant cannot be stranded by LIFO callback ordering.
    /// </summary>
    [TestMethod]
    public async Task DisposalFromALifoCancellationCallbackReleasesRetainedParticipants()
    {
        using CancellationTokenSource cancellation = CancellationTokenSource.CreateLinkedTokenSource(
            TestContext.CancellationToken);
        await using CancellableTestBarrier barrier = new("disposed during cancellation", 2, cancellation.Token);
        TaskCompletionSource participantFinished = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<int> participant = barrier.ObserveParticipantAsync(async () =>
        {
            try
            {
                await barrier.SignalAndWaitAsync().ConfigureAwait(false);

                return 200;
            }
            finally
            {
                participantFinished.SetResult();
            }

        });
        Task release = barrier.WaitForReleaseAsync();
        TaskCompletionSource<Task> disposalStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using CancellationTokenRegistration disposalCancellation = cancellation.Token.Register(() =>
        {
            //This newest callback starts disposal while the barrier's own callback is still queued.
            disposalStarted.SetResult(barrier.DisposeAsync().AsTask());
        });

        try
        {
            await cancellation.CancelAsync().ConfigureAwait(false);
            Task disposal = await disposalStarted.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
            await disposal.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(release.IsCompleted,
                "Disposal must complete release before removing the barrier's queued cancellation callback.");
            OperationCanceledException failure = await Assert.ThrowsAsync<OperationCanceledException>(
                () => release.WaitAsync(TestContext.CancellationToken)).ConfigureAwait(false);
            Assert.AreEqual(cancellation.Token, failure.CancellationToken);
            await participantFinished.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
            _ = await Assert.ThrowsAsync<OperationCanceledException>(
                () => participant.WaitAsync(TestContext.CancellationToken)).ConfigureAwait(false);
        }
        finally
        {
            //Release the retained operation even when an assertion detects an incomplete rendezvous.
            barrier.ReportFault(new InvalidOperationException("The cancellation ordering check has ended."));
            await participantFinished.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
        }

    }


    /// <summary>
    /// Disposal without cancellation faults incomplete arrivals and observers with the barrier's
    /// name and arrival count, allowing retained operations to finish before cleanup returns.
    /// </summary>
    [TestMethod]
    public async Task DisposalOfAnIncompleteBarrierReportsItsNameAndArrivalCount()
    {
        await using CancellableTestBarrier barrier = new("disposed incomplete group", 2, TestContext.CancellationToken);
        Task<int> participant = barrier.ObserveParticipantAsync(async () =>
        {
            await barrier.SignalAndWaitAsync().ConfigureAwait(false);

            return 200;
        });
        Task release = barrier.WaitForReleaseAsync();
        Task disposal = barrier.DisposeAsync().AsTask();
        try
        {
            Assert.IsTrue(release.IsCompleted, "Disposal must release participants before draining their operations.");
            foreach(Task waiter in new Task[] { release, participant })
            {
                InvalidOperationException failure = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
                    () => waiter.WaitAsync(TestContext.CancellationToken)).ConfigureAwait(false);
                Assert.Contains("Barrier 'disposed incomplete group'", failure.Message, StringComparison.Ordinal);
                Assert.Contains("1/2 participants arrived", failure.Message, StringComparison.Ordinal);
                _ = Assert.IsInstanceOfType<ObjectDisposedException>(failure.InnerException);
            }

        }
        finally
        {
            barrier.ReportFault(new InvalidOperationException("The disposal check has ended."));
            await disposal.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
        }

    }


    /// <summary>
    /// Disposing a faulted barrier waits for all remaining participants and disposes a response that
    /// succeeds later, even when the test leaves those participant observations to the barrier.
    /// </summary>
    [TestMethod]
    public async Task FaultedBarrierDisposalObservesEveryParticipantAndDisposesLateResponses()
    {
        await using CancellableTestBarrier barrier = new("late response", 3, TestContext.CancellationToken);
        Task arrival = barrier.SignalAndWaitAsync();
        TaskCompletionSource<HttpResponseMessage> failedParticipant = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<HttpResponseMessage> lateParticipant = new(TaskCreationOptions.RunContinuationsAsynchronously);
        _ = barrier.ObserveParticipantAsync(() => failedParticipant.Task);
        _ = barrier.ObserveParticipantAsync(() => lateParticipant.Task);
        using HttpResponseMessage response = new() { Content = new StringContent("late success") };
        try
        {
            InvalidOperationException participantFault = new("A participant failed before arriving.");
            failedParticipant.SetException(participantFault);
            InvalidOperationException failure = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
                () => arrival.WaitAsync(TestContext.CancellationToken)).ConfigureAwait(false);
            Assert.AreSame(participantFault, failure.InnerException);

            Task disposal = barrier.DisposeAsync().AsTask();
            bool isWaitingForLateParticipant = !disposal.IsCompleted;
            lateParticipant.SetResult(response);
            await disposal.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(isWaitingForLateParticipant, "Cleanup must observe the participant that is still running.");
            _ = await Assert.ThrowsExactlyAsync<ObjectDisposedException>(
                () => response.Content.ReadAsStringAsync(TestContext.CancellationToken)).ConfigureAwait(false);
        }
        finally
        {
            _ = failedParticipant.TrySetCanceled(TestContext.CancellationToken);
            _ = lateParticipant.TrySetResult(response);
        }

    }

}
