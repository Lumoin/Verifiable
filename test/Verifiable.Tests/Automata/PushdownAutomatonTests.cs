using Microsoft.Extensions.Time.Testing;
using System.Diagnostics;
using Verifiable.Core.Automata;

namespace Verifiable.Tests.Automata;

/// <summary>
/// Tests for <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}"/>
/// covering async transitions, fault shielding, observability, hydration,
/// sentinel invariants, and OTel trace context capture.
/// </summary>
[TestClass]
internal sealed class PushdownAutomatonTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void InitialStateIsSet()
    {
        var pda = CreatePda("Start", "Z", (state, input, top, ct) =>
            ValueTask.FromResult<TransitionResult<string, string>?>(null));

        Assert.AreEqual("Start", pda.CurrentState);
        Assert.AreEqual(0, pda.StepCount);
        Assert.AreEqual(1, pda.StackDepth);
        Assert.AreEqual("Z", pda.StackTop);
        Assert.IsFalse(pda.IsAccepted);
        Assert.IsFalse(pda.IsHalted);
        Assert.IsFalse(pda.IsFaulted);
        Assert.IsNull(pda.FaultException);
        Assert.IsNull(pda.PreviousLabel);
    }

    [TestMethod]
    public async Task StepAsyncTransitionsState()
    {
        var pda = CreatePda("Start", "Z", (state, input, top, ct) => (state, input) switch
        {
            ("Start", "a") => Transition("Middle", StackAction<string>.None, "ReadA"),
            ("Middle", "b") => Transition("Accept", StackAction<string>.None, "ReadB"),
            _ => Null()
        });

        bool stepped = await pda.StepAsync("a", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(stepped);
        Assert.AreEqual("Middle", pda.CurrentState);
        Assert.AreEqual(1, pda.StepCount);
        Assert.AreEqual("ReadA", pda.PreviousLabel);
    }

    [TestMethod]
    public async Task StepAsyncReturnsFalseWhenNoTransitionDefined()
    {
        var pda = CreatePda("Start", "Z", (state, input, top, ct) => Null());

        bool stepped = await pda.StepAsync("x", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(stepped);
        Assert.IsTrue(pda.IsHalted);
        Assert.IsFalse(pda.IsFaulted);
        Assert.AreEqual("Start", pda.CurrentState);
    }

    [TestMethod]
    public async Task HaltedAutomatonRejectsAdditionalSteps()
    {
        var pda = CreatePda("Start", "Z", (state, input, top, ct) => Null());

        await pda.StepAsync("x", TestContext.CancellationToken).ConfigureAwait(false);
        bool secondStep = await pda.StepAsync("y", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(secondStep);
        Assert.AreEqual(0, pda.StepCount);
    }

    [TestMethod]
    public async Task PushIncreasesStackDepth()
    {
        var pda = CreatePda("Start", "Z", (state, input, top, ct) =>
            Transition("Pushed", StackAction<string>.Push("A"), "PushA"));

        await pda.StepAsync("x", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(2, pda.StackDepth);
        Assert.AreEqual("A", pda.StackTop);
    }

    [TestMethod]
    public async Task PopDecreasesStackDepth()
    {
        var pda = CreatePda("Start", "Z", (state, input, top, ct) => (state, input) switch
        {
            ("Start", "p") => Transition("Pushed", StackAction<string>.Push("A")),
            ("Pushed", "q") => Transition("Popped", StackAction<string>.Pop),
            _ => Null()
        });

        await pda.StepAsync("p", TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(2, pda.StackDepth);

        await pda.StepAsync("q", TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(1, pda.StackDepth);
        Assert.AreEqual("Z", pda.StackTop);
    }

    [TestMethod]
    public async Task PopSentinelThrowsInvalidOperation()
    {
        var pda = CreatePda("Start", "Z", (state, input, top, ct) =>
            Transition("Bad", StackAction<string>.Pop));

        //Popping sentinel is a programming error — the PDA faults.
        bool stepped = await pda.StepAsync("x", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(stepped);
        Assert.IsTrue(pda.IsFaulted);
        Assert.IsInstanceOfType<InvalidOperationException>(pda.FaultException);
        Assert.AreEqual("Start", pda.CurrentState, "State must not change on fault.");
    }

    [TestMethod]
    public async Task ReplaceSentinelThrowsInvalidOperation()
    {
        var pda = CreatePda("Start", "Z", (state, input, top, ct) =>
            Transition("Bad", StackAction<string>.Replace("X")));

        bool stepped = await pda.StepAsync("x", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(stepped);
        Assert.IsTrue(pda.IsFaulted);
        Assert.IsInstanceOfType<InvalidOperationException>(pda.FaultException);
    }

    [TestMethod]
    public async Task ReplaceSwapsTopSymbol()
    {
        var pda = CreatePda("Start", "Z", (state, input, top, ct) => (state, input) switch
        {
            ("Start", "p") => Transition("Pushed", StackAction<string>.Push("A")),
            ("Pushed", "r") => Transition("Replaced", StackAction<string>.Replace("B")),
            _ => Null()
        });

        await pda.StepAsync("p", TestContext.CancellationToken).ConfigureAwait(false);
        await pda.StepAsync("r", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(2, pda.StackDepth);
        Assert.AreEqual("B", pda.StackTop);
    }

    [TestMethod]
    public async Task RunAsyncProcessesMultipleInputs()
    {
        var pda = CreatePda("Counting", "Z", (state, input, top, ct) =>
            Transition("Counting", StackAction<string>.None, $"Process{input}"));

        int processed = await pda.RunAsync(
            ["1", "2", "3", "4", "5"], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(5, processed);
        Assert.AreEqual(5, pda.StepCount);
    }

    [TestMethod]
    public async Task RunAsyncStopsOnHalt()
    {
        var pda = CreatePda("Running", "Z", (state, input, top, ct) =>
            input is "1" or "2"
                ? Transition("Running", StackAction<string>.None)
                : Null());

        int processed = await pda.RunAsync(
            ["1", "2", "3", "4", "5"], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(2, processed);
        Assert.IsTrue(pda.IsHalted);
    }

    [TestMethod]
    public async Task AcceptPredicateRecognizesAcceptState()
    {
        var pda = CreatePda("Start", "Z", (state, input, top, ct) =>
            Transition("Accept", StackAction<string>.None));

        Assert.IsFalse(pda.IsAccepted);

        await pda.StepAsync("a", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pda.IsAccepted);
    }

    [TestMethod]
    public async Task ObserverReceivesTraceEntries()
    {
        var entries = new List<TraceEntry<string, string>>();
        var observer = new TestObserver<TraceEntry<string, string>>(entries);

        var pda = CreatePda("A", "Z", (state, input, top, ct) => (state, input) switch
        {
            ("A", "1") => Transition("B", StackAction<string>.Push("X"), "AtoB"),
            ("B", "2") => Transition("C", StackAction<string>.Pop, "BtoC"),
            ("C", "3") => Transition("D", StackAction<string>.None, "CtoD"),
            _ => Null()
        });

        using(pda.Subscribe(observer))
        {
            await pda.RunAsync(["1", "2", "3"], TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.HasCount(3, entries);

        Assert.AreEqual("AtoB", entries[0].Label);
        Assert.AreEqual("A", entries[0].StateBefore);
        Assert.AreEqual("B", entries[0].StateAfter);
        Assert.AreEqual(2, entries[0].StackDepth);
        Assert.AreEqual(TraceOutcome.Transitioned, entries[0].Outcome);

        Assert.AreEqual("BtoC", entries[1].Label);
        Assert.AreEqual(1, entries[1].StackDepth);

        Assert.AreEqual("CtoD", entries[2].Label);
        Assert.AreEqual(1, entries[2].StackDepth);

        Assert.IsTrue(pda.IsAccepted);
    }

    [TestMethod]
    public async Task ObserverReceivesHaltEntry()
    {
        var entries = new List<TraceEntry<string, string>>();
        var observer = new TestObserver<TraceEntry<string, string>>(entries);

        var pda = CreatePda("Start", "Z", (state, input, top, ct) => Null());

        using(pda.Subscribe(observer))
        {
            await pda.StepAsync("x", TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.HasCount(1, entries);
        Assert.AreEqual(TraceOutcome.Halted, entries[0].Outcome);
        Assert.AreEqual("Start", entries[0].StateBefore);
        Assert.AreEqual("Start", entries[0].StateAfter);
    }

    [TestMethod]
    public async Task ObserverReceivesFaultEntry()
    {
        var entries = new List<TraceEntry<string, string>>();
        var observer = new TestObserver<TraceEntry<string, string>>(entries);

        var pda = CreatePda("Start", "Z", (state, input, top, ct) =>
            throw new InvalidOperationException("Simulated failure."));

        using(pda.Subscribe(observer))
        {
            await pda.StepAsync("x", TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.HasCount(1, entries);
        Assert.AreEqual(TraceOutcome.Faulted, entries[0].Outcome);
        Assert.AreEqual("Start", entries[0].StateBefore);
        Assert.AreEqual("Start", entries[0].StateAfter);
    }

    [TestMethod]
    public async Task FaultShieldsStateAndStack()
    {
        var pda = CreatePda("Start", "Z", (state, input, top, ct) => (state, input) switch
        {
            ("Start", "ok") => Transition("Good", StackAction<string>.Push("A"), "Ok"),
            ("Good", "fail") => throw new InvalidOperationException("Boom."),
            _ => Null()
        });

        await pda.StepAsync("ok", TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual("Good", pda.CurrentState);
        Assert.AreEqual(2, pda.StackDepth);

        await pda.StepAsync("fail", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pda.IsFaulted);
        Assert.AreEqual("Good", pda.CurrentState, "State must not change on fault.");
        Assert.AreEqual(2, pda.StackDepth, "Stack must not change on fault.");
        Assert.AreEqual("A", pda.StackTop, "Stack top must not change on fault.");
    }

    [TestMethod]
    public async Task FaultedAutomatonRejectsAdditionalSteps()
    {
        var pda = CreatePda("Start", "Z", (state, input, top, ct) =>
            throw new InvalidOperationException("Boom."));

        await pda.StepAsync("x", TestContext.CancellationToken).ConfigureAwait(false);
        bool secondStep = await pda.StepAsync("y", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(secondStep);
    }

    [TestMethod]
    public async Task CancellationPropagatesThroughTransition()
    {
        var pda = CreatePda("Start", "Z",
            (state, input, top, ct) =>
            {
                ct.ThrowIfCancellationRequested();
                return Transition("Done", StackAction<string>.None);
            });

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync().ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
            await pda.StepAsync("x", cts.Token).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.IsFalse(pda.IsFaulted, "Cancellation must not be treated as a fault.");
        Assert.IsFalse(pda.IsHalted, "Cancellation must not be treated as a halt.");
    }

    [TestMethod]
    public async Task TimeProviderControlsTimestamp()
    {
        var fakeTime = new FakeTimeProvider(new DateTimeOffset(2025, 6, 15, 12, 0, 0, TimeSpan.Zero));

        var entries = new List<TraceEntry<string, string>>();
        var observer = new TestObserver<TraceEntry<string, string>>(entries);

        var pda = new PushdownAutomaton<string, string, string>(
            "test-run",
            "Start",
            "Z",
            (state, input, top, ct) => Transition("Next", StackAction<string>.None, "Step1"),
            state => false,
            fakeTime);

        using(pda.Subscribe(observer))
        {
            await pda.StepAsync("a", TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.AreEqual(
            new DateTimeOffset(2025, 6, 15, 12, 0, 0, TimeSpan.Zero),
            entries[0].Timestamp);
    }

    [TestMethod]
    public async Task TraceEntryCarriesRunId()
    {
        var entries = new List<TraceEntry<string, string>>();
        var observer = new TestObserver<TraceEntry<string, string>>(entries);

        var pda = new PushdownAutomaton<string, string, string>(
            "my-run-42",
            "Start",
            "Z",
            (state, input, top, ct) => Transition("Next", StackAction<string>.None),
            state => false);

        using(pda.Subscribe(observer))
        {
            await pda.StepAsync("a", TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.AreEqual("my-run-42", entries[0].RunId);
    }

    [TestMethod]
    public async Task TraceEntryCapturesOTelContext()
    {
        var entries = new List<TraceEntry<string, string>>();
        var observer = new TestObserver<TraceEntry<string, string>>(entries);

        var pda = CreatePda("Start", "Z", (state, input, top, ct) =>
            Transition("Next", StackAction<string>.None));

        using var source = new ActivitySource("Verifiable.Tests");
        using var listener = new ActivityListener
        {
            ShouldListenTo = _ => true,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData
        };
        ActivitySource.AddActivityListener(listener);

        using(var activity = source.StartActivity("TestOperation"))
        using(pda.Subscribe(observer))
        {
            Assert.IsNotNull(activity, "Activity should be created with the listener registered.");
            await pda.StepAsync("a", TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.IsNotNull(entries[0].TraceParent, "TraceParent should capture Activity.Current.Id.");
    }

    [TestMethod]
    public async Task HydrateFromSnapshotProducesEquivalentConfiguration()
    {
        //Run a PDA through some transitions.
        var original = CreatePda("A", "Z", (state, input, top, ct) => (state, input) switch
        {
            ("A", "1") => Transition("B", StackAction<string>.Push("X")),
            ("B", "2") => Transition("C", StackAction<string>.Push("Y")),
            _ => Null()
        });

        await original.RunAsync(["1", "2"], TestContext.CancellationToken).ConfigureAwait(false);

        //Take a snapshot.
        string[] savedStack = original.GetStack();

        //Hydrate a new PDA from the snapshot.
        var hydrated = new PushdownAutomaton<string, string, string>(
            original.RunId,
            original.CurrentState,
            savedStack,
            original.StepCount,
            (state, input, top, ct) => (state, input) switch
            {
                ("A", "1") => Transition("B", StackAction<string>.Push("X")),
                ("B", "2") => Transition("C", StackAction<string>.Push("Y")),
                _ => Null()
            },
            state => state == "D");

        Assert.AreEqual(original.CurrentState, hydrated.CurrentState);
        Assert.AreEqual(original.StepCount, hydrated.StepCount);
        Assert.AreEqual(original.StackDepth, hydrated.StackDepth);
        Assert.AreEqual(original.StackTop, hydrated.StackTop);
    }

    [TestMethod]
    public async Task BalancedParenthesesRecognizer()
    {
        var pda = CreatePda("Reading", "Z", (state, input, top, ct) => (input, top) switch
        {
            ("(", _) => Transition("Reading", StackAction<string>.Push("(")),
            (")", "(") => Transition("Reading", StackAction<string>.Pop),
            _ => Null()
        });

        await pda.RunAsync(
            ["(", "(", ")", "(", ")", ")"],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pda.IsAccepted);
        Assert.AreEqual(1, pda.StackDepth);
        Assert.AreEqual("Z", pda.StackTop);
    }

    [TestMethod]
    public async Task UnbalancedParenthesesHalts()
    {
        var pda = CreatePda("Reading", "Z", (state, input, top, ct) => (input, top) switch
        {
            ("(", _) => Transition("Reading", StackAction<string>.Push("(")),
            (")", "(") => Transition("Reading", StackAction<string>.Pop),
            _ => Null()
        });

        //Extra closing paren — tries to match ')' when top is "Z", no transition defined.
        await pda.RunAsync(["(", ")", ")"], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pda.IsHalted);
    }

    [TestMethod]
    public async Task NestingSimulatesResolverDereferencingComposition()
    {
        var entries = new List<TraceEntry<string, string>>();
        var observer = new TestObserver<TraceEntry<string, string>>(entries);

        var pda = CreatePda("Resolving", "ResolutionFrame", (state, input, top, ct) => (state, input) switch
        {
            ("Resolving", "NeedDereference") => Transition(
                "Dereferencing",
                StackAction<string>.Push("DereferenceFrame"),
                "PushDereference"),
            ("Dereferencing", "DereferenceComplete") => Transition(
                "Resolving",
                StackAction<string>.Pop,
                "PopDereference"),
            ("Resolving", "ResolutionComplete") => Transition(
                "Complete",
                StackAction<string>.None,
                "Finish"),
            _ => Null()
        }, accept: state => state == "Complete");

        using(pda.Subscribe(observer))
        {
            await pda.StepAsync("NeedDereference", TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual("Dereferencing", pda.CurrentState);
            Assert.AreEqual(2, pda.StackDepth);

            await pda.StepAsync("DereferenceComplete", TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual("Resolving", pda.CurrentState);
            Assert.AreEqual(1, pda.StackDepth);

            await pda.StepAsync("ResolutionComplete", TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(pda.IsAccepted);
        }

        Assert.HasCount(3, entries);
        Assert.AreEqual("PushDereference", entries[0].Label);
        Assert.AreEqual("PopDereference", entries[1].Label);
        Assert.AreEqual("Finish", entries[2].Label);
    }

    [TestMethod]
    public async Task AsyncTransitionWithTaskCompletionSource()
    {
        var fetchComplete = new TaskCompletionSource<string>();

        var pda = CreatePda("Waiting", "Z",
            async (state, input, top, ct) =>
            {
                if(state is "Waiting" && input is "start")
                {
                    string data = await fetchComplete.Task.WaitAsync(ct).ConfigureAwait(false);
                    return new TransitionResult<string, string>(
                        $"Done:{data}", StackAction<string>.None, "Fetched");
                }

                return null;
            });

        var stepTask = pda.StepAsync("start", TestContext.CancellationToken);
        Assert.IsFalse(stepTask.IsCompleted, "Step should be awaiting the fetch.");

        fetchComplete.SetResult("payload");
        bool stepped = await stepTask.ConfigureAwait(false);

        Assert.IsTrue(stepped);
        Assert.AreEqual("Done:payload", pda.CurrentState);
    }

    [TestMethod]
    public async Task UnsubscribeStopsTraceDelivery()
    {
        var entries = new List<TraceEntry<string, string>>();
        var observer = new TestObserver<TraceEntry<string, string>>(entries);

        var pda = CreatePda("Start", "Z", (state, input, top, ct) =>
            Transition("Next", StackAction<string>.None));

        var subscription = pda.Subscribe(observer);
        subscription.Dispose();

        //Step after unsubscribe — observer should not receive the entry.
        await pda.StepAsync("a", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(0, entries);
    }

    //Helper methods at end of test class.

    private static PushdownAutomaton<string, string, string> CreatePda(
        string initialState,
        string initialStackSymbol,
        TransitionDelegate<string, string, string> transition,
        Func<string, bool>? accept = null)
    {
        return new PushdownAutomaton<string, string, string>(
            "test-run",
            initialState,
            initialStackSymbol,
            transition,
            accept ?? (state => state is "Accept" or "Complete" or "Reading" or "D"));
    }

    private static ValueTask<TransitionResult<string, string>?> Transition(
        string nextState,
        StackAction<string> stackAction,
        string? label = null)
    {
        return ValueTask.FromResult<TransitionResult<string, string>?>(
            new TransitionResult<string, string>(nextState, stackAction, label));
    }

    private static ValueTask<TransitionResult<string, string>?> Null()
    {
        return ValueTask.FromResult<TransitionResult<string, string>?>(null);
    }

    private sealed class TestObserver<T>(List<T> entries): IObserver<T>
    {
        public void OnNext(T value) => entries.Add(value);
        public void OnError(Exception error) { }
        public void OnCompleted() { }
    }
}