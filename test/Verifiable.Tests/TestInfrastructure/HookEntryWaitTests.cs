using System.Net;
using System.Net.Sockets;
using Verifiable.Tests.OAuth;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Proves <see cref="HookEntryWait"/>: a test that waits for its requests to enter a hook ends when
/// they have entered or when one of them has ended without entering, and ends by its own token's
/// cancellation otherwise. The rows run in-process, with no listener, except the row whose doc
/// says it crosses a real loopback listener: the requests are tasks the row completes, faults or leaves
/// pending. These are tests of test-fixture plumbing, not of a protocol
/// or format this repository implements, so they carry no normative
/// <c>&lt;see href&gt;</c> clause anchor.
/// </summary>
[TestClass]
internal sealed class HookEntryWaitTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Asserts, for a wait asked after the request it guards had ended, that the wait is completed when
    /// it is returned, and that the barrier's own wait (<see cref="Task.WaitAsync(CancellationToken)"/> on
    /// the barrier, what a test awaiting the barrier alone holds) is not completed: that wait ends only
    /// when the barrier is set or the token is cancelled, so a test holding it alone waits without end
    /// for a request that cannot enter the hook any more.
    /// </summary>
    /// <param name="wait">The wait under test, asked after the request ended.</param>
    /// <param name="barrier">The barrier the hook would set; it is unset.</param>
    private void AssertWaitEndedWhereTheBarrierAloneWouldNotEnd(Task wait, Task barrier)
    {
        Task barrierWait = barrier.WaitAsync(TestContext.CancellationToken);

        Assert.IsTrue(wait.IsCompleted, "The request had ended before the wait was asked, so the wait must be completed when it is returned.");
        Assert.IsFalse(barrierWait.IsCompleted, "The barrier's own wait does not end with the request: awaiting it alone waits without end.");
    }


    /// <summary>
    /// A request that faults before the barrier is set ends the wait at once with its own exception,
    /// the same object, not wrapped in another type; the barrier stays unset.
    /// </summary>
    [TestMethod]
    public async Task RequestFaultingBeforeEntryEndsTheWaitWithItsOwnException()
    {
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<int> request = new(TaskCreationOptions.RunContinuationsAsynchronously);
        SocketException fault = new((int)SocketError.NoBufferSpaceAvailable);
        request.SetException(fault);
        Task wait = HookEntryWait.WaitForEntryAsync(entered.Task, request.Task, TestContext.CancellationToken);
        AssertWaitEndedWhereTheBarrierAloneWouldNotEnd(wait, entered.Task);

        SocketException thrown = await Assert.ThrowsExactlyAsync<SocketException>(() => wait).ConfigureAwait(false);

        Assert.AreSame(fault, thrown);
        Assert.IsFalse(entered.Task.IsCompleted, "The wait ends on the request's fault, not on the barrier.");
    }


    /// <summary>
    /// A request that is cancelled before the barrier is set ends the wait at once with its own
    /// cancellation.
    /// </summary>
    [TestMethod]
    public async Task RequestCancelledBeforeEntryEndsTheWaitWithItsCancellation()
    {
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<int> request = new(TaskCreationOptions.RunContinuationsAsynchronously);
        _ = request.TrySetCanceled(TestContext.CancellationToken);
        Task wait = HookEntryWait.WaitForEntryAsync(entered.Task, request.Task, TestContext.CancellationToken);
        AssertWaitEndedWhereTheBarrierAloneWouldNotEnd(wait, entered.Task);

        _ = await Assert.ThrowsAsync<OperationCanceledException>(() => wait).ConfigureAwait(false);

        Assert.IsFalse(entered.Task.IsCompleted, "The wait ends on the request's cancellation, not on the barrier.");
    }


    /// <summary>
    /// A request that completes without the barrier being set fails an assertion that names the request,
    /// its status, and the status code and body of the HTTP response it carries.
    /// </summary>
    [TestMethod]
    public async Task RequestCompletingWithoutEntryFailsAnAssertionNamingItsResponse()
    {
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        HttpResponseMessage response = new(HttpStatusCode.InternalServerError) { Content = new StringContent("refused") };
        try
        {
            TaskCompletionSource<HttpResponseMessage> request = new(TaskCreationOptions.RunContinuationsAsynchronously);
            request.SetResult(response);
            Task AskTheWait() => HookEntryWait.WaitForEntryAsync(entered.Task, request.Task, TestContext.CancellationToken);

            Task wait = AskTheWait();
            AssertWaitEndedWhereTheBarrierAloneWouldNotEnd(wait, entered.Task);

            AssertFailedException failure = await Assert.ThrowsExactlyAsync<AssertFailedException>(() => wait).ConfigureAwait(false);

            Assert.Contains("Request 0", failure.Message, StringComparison.Ordinal);
            Assert.Contains(nameof(TaskStatus.RanToCompletion), failure.Message, StringComparison.Ordinal);
            Assert.Contains("status code 500", failure.Message, StringComparison.Ordinal);
            Assert.Contains("body 'refused'", failure.Message, StringComparison.Ordinal);
            Assert.IsFalse(entered.Task.IsCompleted, "The wait ends on the request's completion, not on the barrier.");
            Assert.AreSame(response, await request.Task.ConfigureAwait(false), "The wait leaves the request's own result untouched.");
        }
        finally
        {
            response.Dispose();
        }
    }


    /// <summary>
    /// Among several requests, the one that completes without the barrier being set is named by its
    /// position, with the status code and body of the pair it carries; the requests that remain pending do not
    /// keep the wait open.
    /// </summary>
    [TestMethod]
    public async Task OneOfSeveralRequestsCompletingWithoutEntryIsNamedByPosition()
    {
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<(int StatusCode, string Body)> pending = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<(int StatusCode, string Body)> completed = Task.FromResult((503, "busy"));
        Task wait = HookEntryWait.WaitForEntryAsync(entered.Task, [pending.Task, completed], TestContext.CancellationToken);
        AssertWaitEndedWhereTheBarrierAloneWouldNotEnd(wait, entered.Task);

        AssertFailedException failure = await Assert.ThrowsExactlyAsync<AssertFailedException>(() => wait).ConfigureAwait(false);

        Assert.Contains("Request 1", failure.Message, StringComparison.Ordinal);
        Assert.Contains("status code 503", failure.Message, StringComparison.Ordinal);
        Assert.Contains("body 'busy'", failure.Message, StringComparison.Ordinal);
        Assert.IsFalse(pending.Task.IsCompleted);
    }


    /// <summary>
    /// A barrier set while the requests are in flight completes the wait, and the requests are left
    /// running. The wait is open until the barrier is set and ends with it, as the barrier's own wait
    /// does, so this row does not tell the helper from that wait.
    /// </summary>
    [TestMethod]
    public async Task BarrierSetWhileTheRequestsAreInFlightCompletesTheWait()
    {
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<int> request = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task wait = HookEntryWait.WaitForEntryAsync(entered.Task, request.Task, TestContext.CancellationToken);
        Assert.IsFalse(wait.IsCompleted, "The wait stays open while the request is in flight and the barrier is unset.");

        entered.SetResult();
        await wait.ConfigureAwait(false);

        Assert.IsFalse(request.Task.IsCompleted, "The wait does not complete the request.");
    }


    /// <summary>
    /// A request that ends after the barrier is set does not fail the wait: it entered the hook before
    /// it ended. The barrier is set before the wait is asked, so the barrier's own wait completes
    /// as well; this row does not tell the helper from that wait.
    /// </summary>
    [TestMethod]
    public async Task RequestEndingAfterTheBarrierIsSetDoesNotFailTheWait()
    {
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        entered.SetResult();
        Task<int> request = Task.FromResult(200);

        await HookEntryWait.WaitForEntryAsync(entered.Task, request, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(request.IsCompletedSuccessfully);
    }


    /// <summary>
    /// A cancelled token ends the wait with that cancellation, while the barrier is unset and the
    /// request is in flight. The barrier's own wait is bound to the same token and ends with the same
    /// cancellation, so this row does not tell the helper from that wait.
    /// </summary>
    [TestMethod]
    public async Task CancelledTokenEndsTheWaitWithTheCancellation()
    {
        using CancellationTokenSource cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<int> request = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task wait = HookEntryWait.WaitForEntryAsync(entered.Task, request.Task, cancellation.Token);
        Assert.IsFalse(wait.IsCompleted);

        await cancellation.CancelAsync().ConfigureAwait(false);

        OperationCanceledException failure = await Assert.ThrowsAsync<OperationCanceledException>(() => wait).ConfigureAwait(false);
        Assert.AreEqual(cancellation.Token, failure.CancellationToken);
    }


    /// <summary>
    /// The shape of eight concurrent requests that each enter one hook, the last entry setting the
    /// barrier, with one request replaced by a task that has already faulted with a
    /// <see cref="SocketException"/> for an exhausted buffer space: the seven others enter and stay held,
    /// the barrier is never set, and the wait ends with that exception instead of waiting for an
    /// eighth entry that cannot happen.
    /// </summary>
    [TestMethod]
    public async Task EightRequestsOfWhichOneFaultedBeforeEntryEndTheWaitWithItsException()
    {
        const int requestCount = 8;
        const int faultedIndex = 3;
        int entries = 0;
        TaskCompletionSource allEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        SocketException fault = new((int)SocketError.NoBufferSpaceAvailable);

        async Task<(int Index, int Status, string Body)> EnterTheHookAsync(int index)
        {
            if(Interlocked.Increment(ref entries) == requestCount)
            {
                _ = allEntered.TrySetResult();
            }

            await release.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

            return (index, 200, "released");
        }

        Task<(int Index, int Status, string Body)>[] requests =
        [
            .. Enumerable.Range(0, requestCount).Select(index => index == faultedIndex
                ? Task.FromException<(int Index, int Status, string Body)>(fault)
                : EnterTheHookAsync(index))
        ];

        try
        {
            Task AskTheWait() => HookEntryWait.WaitForEntryAsync(allEntered.Task, requests, TestContext.CancellationToken);

            Task wait = AskTheWait();
            AssertWaitEndedWhereTheBarrierAloneWouldNotEnd(wait, allEntered.Task);

            SocketException thrown = await Assert.ThrowsExactlyAsync<SocketException>(() => wait).ConfigureAwait(false);

            Assert.AreSame(fault, thrown);
            Assert.AreEqual(SocketError.NoBufferSpaceAvailable, thrown.SocketErrorCode);
            Assert.AreEqual(requestCount - 1, Volatile.Read(ref entries), "The seven healthy requests entered the hook.");
            Assert.IsFalse(allEntered.Task.IsCompleted, "The barrier needs eight entries and only seven can happen.");
        }
        finally
        {
            _ = release.TrySetResult();
            _ = await Task.WhenAll(requests.Where((_, index) => index != faultedIndex)).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// The test host's drain checkpoint waits for the worker to register its drain wait. An alteration
    /// that has ended before any worker registered one (a request refused before its window opened)
    /// ends the checkpoint's wait at once with that request's own exception, the same object, instead
    /// of leaving it waiting for a registration nothing will make; the checkpoint is not parked.
    /// </summary>
    [TestMethod]
    public async Task DrainCheckpointWaitEndsWithTheExceptionOfAnAlterationThatEndedFirst()
    {
        await using TestHostShell app = new(TimeProvider.System);
        TestHostShell.DrainCheckpoint checkpoint = new(app.Server);
        InvalidOperationException fault = new("The alteration was refused before a window opened.");
        TaskCompletionSource alteration = new(TaskCreationOptions.RunContinuationsAsynchronously);
        alteration.SetException(fault);

        Task AskTheCheckpoint() => checkpoint.ReachAsync(alteration.Task, TestContext.CancellationToken);

        Task reach = AskTheCheckpoint();

        Assert.IsTrue(reach.IsCompleted, "The alteration had ended before the wait was asked, so the wait must be completed when it is returned.");
        InvalidOperationException? thrown = null;
        try
        {
            await reach.ConfigureAwait(false);
        }
        catch(InvalidOperationException exception)
        {
            thrown = exception;
        }

        Assert.AreSame(fault, thrown);
        Assert.IsFalse(checkpoint.IsParked, "No drain wait was observed, so nothing is parked.");
    }


    /// <summary>
    /// The eight-request shape over a real loopback listener: eight HTTPS requests each enter one hook
    /// the listener's handler runs, the eighth entry setting the barrier, and one request's connect
    /// fails with a <see cref="SocketException"/> for an exhausted buffer space, a code the connect
    /// retry of <see cref="LoopbackConnect"/> does not cover, injected through the connect preparation
    /// of <see cref="LoopbackTls.CreatePinnedHttpClient(IReadOnlyCollection{System.Security.Cryptography.X509Certificates.X509Certificate2}, int, Action{Socket, int}?, LoopbackKestrelDiagnostics)"/>.
    /// The failing request ends by itself and never reaches the hook. The wait asked after its end is
    /// completed when it is returned and throws that request's own exception, the
    /// <see cref="HttpRequestException"/> over the <see cref="SocketException"/>; the barrier's own wait
    /// is not completed. The seven requests that entered are released and drained.
    /// </summary>
    [TestMethod]
    public async Task EightRequestsOverTheListenerOfWhichOneFailsAtItsConnectEndTheWaitWithItsException()
    {
        const int requestCount = 8;
        const int failingIndex = 5;
        int entries = 0;
        TaskCompletionSource allEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await using MinimalHttpHost host = await MinimalHttpHost.StartAsync(
            async (request, requestCancellation) =>
            {
                if(Interlocked.Increment(ref entries) == requestCount)
                {
                    _ = allEntered.TrySetResult();
                }

                await release.Task.WaitAsync(requestCancellation).ConfigureAwait(false);

                return new MinimalHttpResponse { StatusCode = 200, ContentType = "text/plain", Body = "released" };
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        using LoopbackKestrelDiagnostics diagnostics = LoopbackKestrelDiagnostics.CreateIsolated();

        Task<(int Index, int Status, string Body)>[] requests =
        [
            .. Enumerable.Range(0, requestCount).Select(async index =>
            {
                Action<Socket, int>? failTheConnect = index == failingIndex
                    ? static (_, _) => throw new SocketException((int)SocketError.NoBufferSpaceAvailable)
                    : null;
                using HttpClient client = LoopbackTls.CreatePinnedHttpClient(
                    [host.Certificate], LoopbackConnect.DefaultMaxAttempts, failTheConnect, diagnostics);
                using HttpResponseMessage response = await client.GetAsync(host.BaseAddress, TestContext.CancellationToken).ConfigureAwait(false);
                string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

                return (index, (int)response.StatusCode, body);
            })
        ];
        Task failing = requests[failingIndex];
        Task<(int Index, int Status, string Body)>[] healthy = [.. requests.Where((_, index) => index != failingIndex)];

        try
        {
            Task ended = await Task.WhenAny(failing).WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(ended.IsFaulted, "The request whose connect failed ends by itself, faulted.");
            Task AskTheWait() => HookEntryWait.WaitForEntryAsync(allEntered.Task, requests, TestContext.CancellationToken);

            Task wait = AskTheWait();
            AssertWaitEndedWhereTheBarrierAloneWouldNotEnd(wait, allEntered.Task);

            HttpRequestException thrown = await Assert.ThrowsExactlyAsync<HttpRequestException>(() => wait).ConfigureAwait(false);

            Assert.AreSame(failing.Exception!.InnerException, thrown);
            SocketException socketFailure = Assert.IsInstanceOfType<SocketException>(thrown.InnerException,
                $"The request must fail at its connect. Actual: '{thrown}'.");
            Assert.AreEqual(SocketError.NoBufferSpaceAvailable, socketFailure.SocketErrorCode);
            Assert.IsFalse(allEntered.Task.IsCompleted, "The barrier needs eight entries and only seven requests can enter.");
        }
        finally
        {
            _ = release.TrySetResult();
            _ = await Task.WhenAll(healthy).ConfigureAwait(false);
        }

        (int Index, int Status, string Body)[] drained = await Task.WhenAll(healthy).ConfigureAwait(false);

        Assert.IsTrue(drained.All(result => result.Status == 200), "The seven requests that entered are answered once released.");
    }
}
