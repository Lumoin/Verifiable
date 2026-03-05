using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.Automata;

/// <summary>
/// A generic pushdown automaton (PDA) — a finite state machine with a stack.
/// Recognizes context-free patterns and drives computations that require nesting
/// (e.g., DID resolution composing with dereferencing, OAuth step-up authentication,
/// event log replay with sub-log following).
/// </summary>
/// <remarks>
/// <para>
/// Formally, a PDA is the tuple <c>(Q, Σ, Γ, δ, q₀, Z₀, F)</c> where:
/// </para>
/// <list type="bullet">
///   <item><description><c>Q</c> — finite set of states (<typeparamref name="TState"/>).</description></item>
///   <item><description><c>Σ</c> — input alphabet (<typeparamref name="TInput"/>).</description></item>
///   <item><description><c>Γ</c> — stack alphabet (<typeparamref name="TStackSymbol"/>).</description></item>
///   <item><description><c>δ</c> — transition function (<see cref="TransitionDelegate{TState, TInput, TStackSymbol}"/>).</description></item>
///   <item><description><c>q₀</c> — initial state (provided at construction).</description></item>
///   <item><description><c>Z₀</c> — initial stack symbol (provided at construction, sentinel, never popped).</description></item>
///   <item><description><c>F</c> — accept predicate.</description></item>
/// </list>
/// <para>
/// The PDA is deterministic: each (state, input, stack top) combination produces at most
/// one transition. The stack sentinel <c>Z₀</c> is never popped — attempting to pop it
/// indicates a bug in the transition function and throws <see cref="InvalidOperationException"/>.
/// </para>
/// <para>
/// <strong>Observation:</strong> The PDA implements <see cref="IObservable{T}"/> of
/// <see cref="TraceEntry{TState, TInput}"/>. Subscribers receive entries after each step
/// containing the full context for replay journals, structured logging, OTel correlation,
/// and CloudEvents projection. The PDA emits everything, stores nothing.
/// </para>
/// <para>
/// <strong>Fault shielding:</strong> If the transition delegate throws, the PDA does not
/// apply the transition (state and stack remain unchanged), sets <see cref="IsFaulted"/>
/// to <see langword="true"/>, stores the exception in <see cref="FaultException"/>, and
/// emits a <see cref="TraceOutcome.Faulted"/> trace entry.
/// </para>
/// <para>
/// <strong>Hydration:</strong> The PDA can be constructed from a snapshot
/// (<see cref="CurrentState"/>, stack contents, <see cref="StepCount"/>) to resume
/// computation without replaying all inputs. Hydrating from a snapshot and replaying
/// from initial state produce the same configuration given the same transition function
/// and input log.
/// </para>
/// <para>
/// See <see href="https://en.wikipedia.org/wiki/Pushdown_automaton">Pushdown automaton</see>
/// for the formal definition.
/// </para>
/// </remarks>
/// <typeparam name="TState">The state type. Can be any type the caller defines.</typeparam>
/// <typeparam name="TInput">The input type. Each call to <see cref="StepAsync"/> consumes one input.</typeparam>
/// <typeparam name="TStackSymbol">The stack symbol type.</typeparam>
[DebuggerDisplay("RunId={RunId}, State={CurrentState}, Depth={StackDepth}, Step={StepCount}, Prev={PreviousLabel}")]
public sealed class PushdownAutomaton<TState, TInput, TStackSymbol>: IObservable<TraceEntry<TState, TInput>>
{
    private Stack<TStackSymbol> Stack { get; }
    private List<IObserver<TraceEntry<TState, TInput>>> Observers { get; } = [];
    private TransitionDelegate<TState, TInput, TStackSymbol> Transition { get; }
    private Func<TState, bool> AcceptPredicate { get; }
    private TimeProvider TimeProvider { get; }

    /// <summary>
    /// The stable execution/session identifier provided by the caller at construction.
    /// Used for persistence lookup, trace correlation, and CloudEvents <c>source</c>.
    /// </summary>
    public string RunId { get; }

    /// <summary>
    /// The current state of the automaton.
    /// </summary>
    public TState CurrentState { get; private set; }

    /// <summary>
    /// The number of transitions successfully executed so far.
    /// </summary>
    public int StepCount { get; private set; }

    /// <summary>
    /// The current depth of the stack. Always >= 1 (sentinel is always present).
    /// </summary>
    public int StackDepth => Stack.Count;

    /// <summary>
    /// The symbol currently on top of the stack. Never <see langword="default"/>
    /// because the sentinel symbol is always present.
    /// </summary>
    public TStackSymbol StackTop => Stack.Peek();

    /// <summary>
    /// The label of the most recent successful transition, or <see langword="null"/>
    /// if no transitions have been executed or the last transition was unlabeled.
    /// </summary>
    public string? PreviousLabel { get; private set; }

    /// <summary>
    /// Whether the automaton is currently in an accept state.
    /// </summary>
    public bool IsAccepted => AcceptPredicate(CurrentState);

    /// <summary>
    /// Whether the automaton has halted (the last step produced no transition).
    /// </summary>
    public bool IsHalted { get; private set; }

    /// <summary>
    /// Whether the automaton has faulted (the transition delegate threw an exception).
    /// The automaton's state was not modified when this occurred.
    /// </summary>
    public bool IsFaulted { get; private set; }

    /// <summary>
    /// The exception that caused the fault, or <see langword="null"/> if the automaton
    /// has not faulted.
    /// </summary>
    public Exception? FaultException { get; private set; }

    /// <summary>
    /// Creates a new pushdown automaton from an initial configuration.
    /// </summary>
    /// <param name="runId">A stable execution/session identifier for persistence and trace correlation.</param>
    /// <param name="initialState">The initial state (<c>q₀</c>).</param>
    /// <param name="initialStackSymbol">The initial stack symbol (<c>Z₀</c>), which acts as a sentinel and is never popped.</param>
    /// <param name="transition">The transition function (<c>δ</c>).</param>
    /// <param name="acceptPredicate">A predicate that returns <see langword="true"/> for accept states (<c>F</c>).</param>
    /// <param name="timeProvider">
    /// The time provider for timestamps in trace entries. Defaults to <see cref="System.TimeProvider.System"/>
    /// if <see langword="null"/>. Use <c>FakeTimeProvider</c> in tests.
    /// </param>
    public PushdownAutomaton(
        string runId,
        TState initialState,
        TStackSymbol initialStackSymbol,
        TransitionDelegate<TState, TInput, TStackSymbol> transition,
        Func<TState, bool> acceptPredicate,
        TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);
        ArgumentNullException.ThrowIfNull(transition);
        ArgumentNullException.ThrowIfNull(acceptPredicate);

        RunId = runId;
        CurrentState = initialState;
        Transition = transition;
        AcceptPredicate = acceptPredicate;
        TimeProvider = timeProvider ?? TimeProvider.System;
        Stack = new Stack<TStackSymbol>();
        Stack.Push(initialStackSymbol);
    }

    /// <summary>
    /// Creates a pushdown automaton from a previously saved snapshot.
    /// Produces the same configuration as if all inputs had been replayed
    /// from the initial state, given the same transition function.
    /// </summary>
    /// <param name="runId">The original execution/session identifier.</param>
    /// <param name="savedState">The state at the time of the snapshot.</param>
    /// <param name="savedStack">The stack contents at the time of the snapshot, bottom-to-top order.</param>
    /// <param name="savedStepCount">The step count at the time of the snapshot.</param>
    /// <param name="transition">The transition function (must be the same version as the original).</param>
    /// <param name="acceptPredicate">The accept predicate.</param>
    /// <param name="timeProvider">The time provider. Defaults to <see cref="System.TimeProvider.System"/>.</param>
    public PushdownAutomaton(
        string runId,
        TState savedState,
        IEnumerable<TStackSymbol> savedStack,
        int savedStepCount,
        TransitionDelegate<TState, TInput, TStackSymbol> transition,
        Func<TState, bool> acceptPredicate,
        TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);
        ArgumentNullException.ThrowIfNull(savedStack);
        ArgumentNullException.ThrowIfNull(transition);
        ArgumentNullException.ThrowIfNull(acceptPredicate);

        RunId = runId;
        CurrentState = savedState;
        StepCount = savedStepCount;
        Transition = transition;
        AcceptPredicate = acceptPredicate;
        TimeProvider = timeProvider ?? TimeProvider.System;
        Stack = new Stack<TStackSymbol>();

        foreach(TStackSymbol symbol in savedStack)
        {
            Stack.Push(symbol);
        }

        if(Stack.Count == 0)
        {
            throw new ArgumentException("Saved stack must contain at least the sentinel symbol.", nameof(savedStack));
        }
    }

    /// <summary>
    /// Returns the current stack contents in bottom-to-top order for snapshot serialization.
    /// </summary>
    /// <returns>The stack contents. The first element is the sentinel.</returns>
    public TStackSymbol[] GetStack()
    {
        TStackSymbol[] result = Stack.ToArray();
        //Stack.ToArray() returns top-to-bottom. Reverse for bottom-to-top.
        Array.Reverse(result);
        return result;
    }

    /// <summary>
    /// Executes one transition: reads the input, invokes the transition function
    /// with the current state and stack top, applies the result.
    /// </summary>
    /// <remarks>
    /// <para>
    /// If the transition delegate returns <see langword="null"/>, the automaton halts
    /// and <see cref="IsHalted"/> becomes <see langword="true"/>.
    /// </para>
    /// <para>
    /// If the transition delegate throws, the automaton faults: state and stack are not
    /// modified, <see cref="IsFaulted"/> becomes <see langword="true"/>, and the exception
    /// is stored in <see cref="FaultException"/>.
    /// </para>
    /// <para>
    /// After each step (regardless of outcome), a <see cref="TraceEntry{TState, TInput}"/>
    /// is emitted to all subscribers.
    /// </para>
    /// </remarks>
    /// <param name="input">The input to process.</param>
    /// <param name="cancellationToken">Cancellation token passed to the transition delegate.</param>
    /// <returns>
    /// <see langword="true"/> if a transition was found and applied;
    /// <see langword="false"/> if the automaton halted, faulted, or was already stopped.
    /// </returns>
    public async ValueTask<bool> StepAsync(TInput input, CancellationToken cancellationToken = default)
    {
        if(IsHalted || IsFaulted)
        {
            return false;
        }

        TState stateBefore = CurrentState;
        TStackSymbol top = Stack.Peek();

        TransitionResult<TState, TStackSymbol>? result;
        try
        {
            result = await Transition(CurrentState, input, top, cancellationToken).ConfigureAwait(false);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch(Exception ex)
        {
            IsFaulted = true;
            FaultException = ex;
            EmitTrace(input, stateBefore, stateBefore, null, TraceOutcome.Faulted);
            return false;
        }

        if(result is null)
        {
            IsHalted = true;
            EmitTrace(input, stateBefore, stateBefore, null, TraceOutcome.Halted);
            return false;
        }

        try
        {
            result.StackAction.Apply(Stack);
        }
        catch(InvalidOperationException ex)
        {
            IsFaulted = true;
            FaultException = ex;
            EmitTrace(input, stateBefore, stateBefore, result.Label, TraceOutcome.Faulted);
            return false;
        }

        CurrentState = result.NextState;
        PreviousLabel = result.Label;

        EmitTrace(input, stateBefore, result.NextState, result.Label, TraceOutcome.Transitioned);
        StepCount++;

        return true;
    }

    /// <summary>
    /// Processes a sequence of inputs, executing one transition per input.
    /// Stops early if the automaton halts, faults, or cancellation is requested.
    /// </summary>
    /// <param name="inputs">The inputs to process in order.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The number of inputs successfully processed.</returns>
    public async ValueTask<int> RunAsync(IEnumerable<TInput> inputs, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inputs);

        int count = 0;
        foreach(TInput input in inputs)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if(!await StepAsync(input, cancellationToken).ConfigureAwait(false))
            {
                break;
            }

            count++;
        }

        return count;
    }

    /// <inheritdoc />
    public IDisposable Subscribe(IObserver<TraceEntry<TState, TInput>> observer)
    {
        ArgumentNullException.ThrowIfNull(observer);
        Observers.Add(observer);
        return new Unsubscriber(Observers, observer);
    }

    private void EmitTrace(
        TInput input,
        TState stateBefore,
        TState stateAfter,
        string? label,
        TraceOutcome outcome)
    {
        Activity? activity = Activity.Current;
        var entry = new TraceEntry<TState, TInput>(
            RunId,
            StepCount,
            label,
            Stack.Count,
            input,
            stateBefore,
            stateAfter,
            outcome,
            TimeProvider.GetUtcNow(),
            activity?.Id,
            activity?.TraceStateString);

        foreach(IObserver<TraceEntry<TState, TInput>> observer in Observers)
        {
            observer.OnNext(entry);
        }
    }

    private sealed class Unsubscriber(
        List<IObserver<TraceEntry<TState, TInput>>> observers,
        IObserver<TraceEntry<TState, TInput>> observer): IDisposable
    {
        public void Dispose()
        {
            observers.Remove(observer);
        }
    }
}