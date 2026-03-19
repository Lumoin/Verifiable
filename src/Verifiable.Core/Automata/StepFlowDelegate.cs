using System;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.Automata;

/// <summary>
/// Steps a flow forward: given the current state, step count, and an input,
/// produces the next state and step count.
/// </summary>
/// <remarks>
/// <para>
/// This delegate corresponds to the <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}"/>
/// step operation, but erases the stack symbol type so that callers can drive the
/// PDA without knowing the stack alphabet. Concrete implementations typically
/// delegate to the automaton's <c>Step</c> method or to a snapshot-based
/// <c>CreateFromSnapshot + StepAsync</c> pair.
/// </para>
/// <para>
/// <see cref="PdaRunner.StepWithEffectsAsync{TState, TInput, TContext}"/> calls this
/// delegate once per pure PDA transition. Between transitions the effectful loop
/// executes the action declared by the new state and feeds the result back as the
/// next input.
/// </para>
/// </remarks>
/// <typeparam name="TState">The flow state type.</typeparam>
/// <typeparam name="TInput">The input type consumed by each transition.</typeparam>
/// <param name="currentState">The current state before the transition.</param>
/// <param name="currentStepCount">The step count before the transition.</param>
/// <param name="input">The input to process.</param>
/// <param name="timeProvider">Time source for timestamps in the transition.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The new state and step count after the transition.</returns>
public delegate ValueTask<(TState State, int StepCount)> StepFlowDelegate<TState, TInput>(
    TState currentState,
    int currentStepCount,
    TInput input,
    TimeProvider timeProvider,
    CancellationToken cancellationToken);
