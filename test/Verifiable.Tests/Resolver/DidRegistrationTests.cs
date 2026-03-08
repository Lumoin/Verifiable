using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Automata;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.Methods;
using Verifiable.Core.Resolvers;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for DID registration flows using the PDA, covering create, update, deactivate,
/// client-managed secret mode (signing request/response), and async confirmation.
/// </summary>
[TestClass]
internal sealed class DidRegistrationTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task CreateFlowCompletesImmediately()
    {
        var pda = CreateTestAutomaton((state, input, ct) =>
        {
            if(input is BeginCreate create)
            {
                var doc = new DidDocument { Id = (GenericDidMethod)$"did:{create.Method}:abc123" };
                
                return ValueTask.FromResult<RegistrationFlowState>(new RegistrationCompleted($"did:{create.Method}:abc123", doc));
            }

            return ValueTask.FromResult(state);
        });

        await pda.StepAsync(new BeginCreate("key", null), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pda.IsAccepted);
        Assert.IsInstanceOfType<RegistrationCompleted>(pda.CurrentState);

        var completed = (RegistrationCompleted)pda.CurrentState;
        Assert.AreEqual("did:key:abc123", completed.Did);
        Assert.IsNotNull(completed.Document);
    }

    [TestMethod]
    public async Task CreateFlowWithClientManagedSecretMode()
    {
        var signingRequest = new SigningRequest
        {
            RequestId = "sign-1",
            Payload = new byte[] { 0x01, 0x02, 0x03 },
            Kid = "did:key:z6Mk...#key-1",
            Algorithm = "EdDSA"
        };

        var pda = CreateTestAutomaton((state, input, ct) => (state, input) switch
        {
            //Method handler initiates create and requests signing.
            (RegistrationInitiated, BeginCreate create) => ValueTask.FromResult<RegistrationFlowState>(new AwaitingSignature(signingRequest, state)),

            //After signature is provided, complete the registration.
            (AwaitingSignature, ProvideSignature sig) =>
                ValueTask.FromResult<RegistrationFlowState>(new RegistrationCompleted("did:key:abc123", new DidDocument { Id = (GenericDidMethod)"did:key:abc123" })),

            _ => ValueTask.FromResult(state)
        });

        //Step 1: Begin create — PDA transitions to AwaitingSignature, pushes signing frame.
        await pda.StepAsync(new BeginCreate("key", null), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<AwaitingSignature>(pda.CurrentState);
        Assert.AreEqual(2, pda.StackDepth, "Signing frame should be pushed.");

        var awaiting = (AwaitingSignature)pda.CurrentState;
        Assert.AreEqual("sign-1", awaiting.Request.RequestId);

        //Step 2: Provide signature — PDA transitions to Completed, pops signing frame.
        var response = new SigningResponse
        {
            RequestId = "sign-1",
            Signature = new byte[] { 0xAA, 0xBB },
            Kid = "did:key:z6Mk...#key-1",
            Algorithm = "EdDSA"
        };

        await pda.StepAsync(new ProvideSignature(response), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pda.IsAccepted);
        Assert.AreEqual(1, pda.StackDepth, "Signing frame should be popped.");
        Assert.IsInstanceOfType<RegistrationCompleted>(pda.CurrentState);
    }

    [TestMethod]
    public async Task CreateFlowWithAsyncConfirmation()
    {
        var pda = CreateTestAutomaton((state, input, ct) => (state, input) switch
        {
            (RegistrationInitiated, BeginCreate create) =>
                ValueTask.FromResult<RegistrationFlowState>(
                    new AwaitingConfirmation("job-42")),

            _ => ValueTask.FromResult(state)
        });

        //Step 1: Begin create — backend needs time, returns wait state.
        await pda.StepAsync(
            new BeginCreate("ebsi", null), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<AwaitingConfirmation>(pda.CurrentState);
        var waiting = (AwaitingConfirmation)pda.CurrentState;
        Assert.AreEqual("job-42", waiting.JobId);

        //Step 2: Backend confirms completion.
        var doc = new DidDocument { Id = (GenericDidMethod)"did:ebsi:xyz789" };
        await pda.StepAsync(new ConfirmCompletion("did:ebsi:xyz789", doc), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pda.IsAccepted);
        Assert.IsInstanceOfType<RegistrationCompleted>(pda.CurrentState);
    }

    [TestMethod]
    public async Task UpdateFlowCompletes()
    {
        var pda = CreateTestAutomaton((state, input, ct) =>
        {
            if(input is BeginUpdate update)
            {
                return ValueTask.FromResult<RegistrationFlowState>(
                    new RegistrationCompleted(update.Did, update.Document));
            }

            return ValueTask.FromResult(state);
        });

        var updatedDoc = new DidDocument { Id = (GenericDidMethod)"did:web:example.com" };
        await pda.StepAsync(
            new BeginUpdate("did:web:example.com", updatedDoc), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pda.IsAccepted);
        var completed = (RegistrationCompleted)pda.CurrentState;
        Assert.AreEqual("did:web:example.com", completed.Did);
    }

    [TestMethod]
    public async Task DeactivateFlowCompletes()
    {
        var pda = CreateTestAutomaton((state, input, ct) =>
        {
            if(input is BeginDeactivate deactivate)
            {
                return ValueTask.FromResult<RegistrationFlowState>(
                    new RegistrationCompleted(deactivate.Did, null));
            }

            return ValueTask.FromResult(state);
        });

        await pda.StepAsync(
            new BeginDeactivate("did:web:example.com"), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pda.IsAccepted);
        var completed = (RegistrationCompleted)pda.CurrentState;
        Assert.IsNull(completed.Document, "Deactivated DID should have no document.");
    }

    [TestMethod]
    public async Task ErrorAtAnyPointTransitionsToFailed()
    {
        var pda = CreateTestAutomaton((state, input, ct) =>
            ValueTask.FromResult<RegistrationFlowState>(
                new RegistrationInitiated("key", null)));

        await pda.StepAsync(
            new BeginCreate("key", null), TestContext.CancellationToken).ConfigureAwait(false);

        await pda.StepAsync(
            new RegistrationError("ledgerUnavailable"), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<RegistrationFailed>(pda.CurrentState);
        var failed = (RegistrationFailed)pda.CurrentState;
        Assert.AreEqual("ledgerUnavailable", failed.Error);
    }

    [TestMethod]
    public async Task TraceEntriesAreEmittedDuringRegistration()
    {
        var entries = new List<TraceEntry<RegistrationFlowState, RegistrationInput>>();
        var observer = new TestObserver<TraceEntry<RegistrationFlowState, RegistrationInput>>(entries);

        var pda = CreateTestAutomaton((state, input, ct) =>
            ValueTask.FromResult<RegistrationFlowState>(
                new RegistrationCompleted("did:key:abc", null)));

        using(pda.Subscribe(observer))
        {
            await pda.StepAsync(
                new BeginCreate("key", null), TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.HasCount(1, entries);
        Assert.AreEqual("BeginCreate", entries[0].Label);
        Assert.AreEqual(TraceOutcome.Transitioned, entries[0].Outcome);
    }

    [TestMethod]
    public async Task TimestampsUseInjectedTimeProvider()
    {
        var fakeTime = new FakeTimeProvider(new DateTimeOffset(2025, 9, 1, 8, 0, 0, TimeSpan.Zero));

        var entries = new List<TraceEntry<RegistrationFlowState, RegistrationInput>>();
        var observer = new TestObserver<TraceEntry<RegistrationFlowState, RegistrationInput>>(entries);

        var pda = DidRegistrationTransitions.CreateAutomaton(
            "time-test",
            (state, input, ct) => ValueTask.FromResult<RegistrationFlowState>(
                new RegistrationCompleted("did:key:abc", null)),
            fakeTime);

        using(pda.Subscribe(observer))
        {
            await pda.StepAsync(
                new BeginCreate("key", null), TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.AreEqual(
            new DateTimeOffset(2025, 9, 1, 8, 0, 0, TimeSpan.Zero),
            entries[0].Timestamp);
    }

    //Helper methods at end of test class.

    private static PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> CreateTestAutomaton(
        Func<RegistrationFlowState, RegistrationInput, CancellationToken, ValueTask<RegistrationFlowState>> handler)
    {
        return DidRegistrationTransitions.CreateAutomaton("test-run", handler);
    }

    private sealed class TestObserver<T>(List<T> entries) : IObserver<T>
    {
        public void OnNext(T value) => entries.Add(value);
        public void OnError(Exception error) { }
        public void OnCompleted() { }
    }
}
