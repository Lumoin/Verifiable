using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.Automata;

/// <summary>
/// Drives a <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}"/> through
/// an effectful loop: step, extract the action declared by the new state, execute
/// the action, feed the result back as the next input, repeat until the state
/// declares no further action.
/// </summary>
/// <remarks>
/// <para>
/// The PDA architecture separates computation into three layers:
/// </para>
/// <list type="number">
///   <item>
///     <description>
///       <strong>Pure PDA.</strong> The
///       <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}"/> and its
///       <see cref="TransitionDelegate{TState, TInput, TStackSymbol}"/> are
///       mathematically pure: given the same state, input, and stack top, they
///       always produce the same next state and stack action. No I/O, no time,
///       no randomness. This makes transitions deterministic, replayable, and
///       formally verifiable.
///     </description>
///   </item>
///   <item>
///     <description>
///       <strong>State-declared actions.</strong> Each state carries a
///       <see cref="PdaAction"/> property (typically named <c>NextAction</c>)
///       that declares what effectful work must happen before the next input
///       can be constructed. The PDA itself never executes this action — it
///       only declares it. <see cref="NullAction"/> means "no work needed,
///       the next input arrives from an external source."
///     </description>
///   </item>
///   <item>
///     <description>
///       <strong>Effectful loop.</strong> This class drives the cycle:
///       step the PDA, extract the action from the new state, dispatch it to
///       a caller-supplied executor, feed the executor's result back as the
///       next PDA input, and repeat until the state declares
///       <see cref="NullAction"/> or no action at all. All side effects —
///       signing, encryption, HTTP calls, hardware operations — happen inside
///       the executor, never inside the PDA transition.
///     </description>
///   </item>
/// </list>
/// <para>
/// This separation means the same PDA transition function drives both the
/// server-side HTTP handler (where the effectful loop runs between HTTP
/// request receipt and response construction) and the client-side flow session
/// (where the effectful loop runs between user actions), and can be tested
/// with deterministic replay by substituting the executor with recorded outputs.
/// </para>
/// <para>
/// The <typeparamref name="TContext"/> parameter threads caller-supplied state
/// through to the action executor without closure capture. This follows the
/// library convention that static lambdas receive all dependencies as parameters.
/// Pass a value tuple when multiple values are needed:
/// </para>
/// <code>
/// await PdaRunner.StepWithEffectsAsync(
///     state, stepCount, input,
///     step: static (s, sc, i, tp, ct) => s.Kind.Step(s, sc, i, tp, ct),
///     actionExtractor: static s => s.NextAction,
///     actionExecutor: static (action, ctx, ct) =>
///         ctx.Executor.ExecuteAsync(action, ctx.RequestContext, ct),
///     actionContext: (Executor: executor, RequestContext: context),
///     timeProvider, cancellationToken);
/// </code>
/// </remarks>
[DebuggerDisplay("PdaRunner")]
public static class PdaRunner
{
    /// <summary>
    /// Performs the initial PDA step with <paramref name="initialInput"/>, then
    /// drives the effectful loop until the resulting state declares no further action.
    /// </summary>
    /// <typeparam name="TState">The flow state type.</typeparam>
    /// <typeparam name="TInput">The input type consumed by each PDA transition.</typeparam>
    /// <typeparam name="TContext">
    /// Caller-supplied context threaded to the action executor. Use a value tuple
    /// to pass multiple values without closure capture.
    /// </typeparam>
    /// <param name="currentState">The PDA state before the first step.</param>
    /// <param name="currentStepCount">The step count before the first step.</param>
    /// <param name="initialInput">The input for the first PDA transition.</param>
    /// <param name="step">
    /// The step delegate that advances the PDA by one transition. Typically
    /// delegates to <c>state.Kind.Step</c> or directly to
    /// <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}.StepAsync"/>.
    /// </param>
    /// <param name="actionExtractor">
    /// Extracts the <see cref="PdaAction"/> declared by a state. Return
    /// <see langword="null"/> or <see cref="NullAction.Instance"/> to stop the loop.
    /// </param>
    /// <param name="actionExecutor">
    /// Executes a <see cref="PdaAction"/> and returns the input to feed into the
    /// next PDA transition. Receives the <paramref name="actionContext"/> as its
    /// second parameter so it can access caller-supplied dependencies without
    /// closure capture.
    /// </param>
    /// <param name="actionContext">
    /// Caller-supplied context forwarded to <paramref name="actionExecutor"/> on
    /// every iteration. Not interpreted by this method.
    /// </param>
    /// <param name="timeProvider">Time source for PDA step timestamps.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The final state and step count after the loop completes.</returns>
    public static async ValueTask<(TState State, int StepCount)> StepWithEffectsAsync<TState, TInput, TContext>(
        TState currentState,
        int currentStepCount,
        TInput initialInput,
        StepFlowDelegate<TState, TInput> step,
        Func<TState, PdaAction?> actionExtractor,
        Func<PdaAction, TContext, CancellationToken, ValueTask<TInput>> actionExecutor,
        TContext actionContext,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(step);
        ArgumentNullException.ThrowIfNull(actionExtractor);
        ArgumentNullException.ThrowIfNull(actionExecutor);
        ArgumentNullException.ThrowIfNull(timeProvider);

        (TState state, int stepCount) = await step(
            currentState, currentStepCount, initialInput, timeProvider, cancellationToken)
            .ConfigureAwait(false);

        PdaAction? action = actionExtractor(state);
        while(action is not null and not NullAction)
        {
            TInput actionInput = await actionExecutor(
                action, actionContext, cancellationToken).ConfigureAwait(false);

            (state, stepCount) = await step(
                state, stepCount, actionInput, timeProvider, cancellationToken)
                .ConfigureAwait(false);

            action = actionExtractor(state);
        }

        return (state, stepCount);
    }
}
