using System.Diagnostics;
using Verifiable.Core.Automata;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Convenience wrapper over <see cref="PdaRunner"/> for OAuth flow states.
/// </summary>
/// <remarks>
/// <para>
/// Binds the generic <see cref="PdaRunner.StepWithEffectsAsync{TState, TInput, TContext}"/>
/// to the OAuth type system: <see cref="OAuthFlowState"/> as the state,
/// <see cref="OAuthFlowInput"/> as the input, <see cref="OAuthFlowState.NextAction"/>
/// as the action extractor, and <see cref="OAuthActionExecutor.ExecuteAsync"/> as
/// the action executor.
/// </para>
/// <para>
/// The <see cref="AuthorizationServerDispatcher"/> calls this instead of inlining
/// the effectful loop. Library users call it directly when driving a flow outside
/// the dispatcher — for example in a Wallet-side flow session or in integration tests
/// that step a flow programmatically.
/// </para>
/// </remarks>
[DebuggerDisplay("FlowRunner")]
public static class FlowRunner
{
    /// <summary>
    /// Steps the flow PDA with <paramref name="initialInput"/> and drives the
    /// effectful loop until the resulting state declares <see cref="NullAction"/>.
    /// </summary>
    /// <param name="currentState">The PDA state before the first step.</param>
    /// <param name="currentStepCount">The step count before the first step.</param>
    /// <param name="initialInput">The input for the first PDA transition.</param>
    /// <param name="executor">
    /// The action executor that handles <see cref="OAuthAction"/> instances between
    /// pure PDA transitions. When <see langword="null"/> the loop does not execute —
    /// the method returns immediately after the first step.
    /// </param>
    /// <param name="context">
    /// The per-request context bag forwarded to the executor on every iteration.
    /// </param>
    /// <param name="options">
    /// The server options forwarded to the executor so handlers can read key resolvers,
    /// encoder delegates, and other server configuration at call time.
    /// </param>
    /// <param name="timeProvider">Time source for PDA step timestamps.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The final state and step count after the loop completes.</returns>
    public static ValueTask<(OAuthFlowState State, int StepCount)> StepWithEffectsAsync(
        OAuthFlowState currentState,
        int currentStepCount,
        OAuthFlowInput initialInput,
        OAuthActionExecutor? executor,
        RequestContext context,
        AuthorizationServerOptions options,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(currentState);
        ArgumentNullException.ThrowIfNull(initialInput);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);

        if(currentState.Kind is not StatefulFlowKind statefulKind)
        {
            throw new InvalidOperationException(
                $"FlowRunner requires a StatefulFlowKind state; got " +
                $"'{currentState.Kind.GetType().Name}'. Stateless endpoints must " +
                $"return an early-exit response from BuildInputAsync before " +
                $"reaching FlowRunner.");
        }

        if(executor is null)
        {
            //No executor configured — perform a single step without the effectful loop.
            return statefulKind.StepAsync(
                currentState, currentStepCount, initialInput, timeProvider, cancellationToken);
        }

        return PdaRunner.StepWithEffectsAsync(
            currentState,
            currentStepCount,
            initialInput,
            step: static (state, stepCount, input, tp, ct) =>
                ((StatefulFlowKind)state.Kind).StepAsync(state, stepCount, input, tp, ct),
            actionExtractor: static state => state.NextAction,
            actionExecutor: static (action, ctx, ct) =>
                ctx.Executor.ExecuteAsync((OAuthAction)action, ctx.Context, ctx.Options, ct),
            actionContext: (Executor: executor, Context: context, Options: options),
            timeProvider,
            cancellationToken);
    }
}
