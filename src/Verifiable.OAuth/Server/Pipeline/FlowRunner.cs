using System.Diagnostics;
using Verifiable.Core.Automata;

namespace Verifiable.OAuth.Server.Pipeline;

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
/// The <see cref="AuthorizationServer"/> calls this instead of inlining the
/// effectful loop. Library users call it directly when driving a flow outside the
/// dispatcher — for example in a Wallet-side flow session or in integration tests
/// that step a flow programmatically.
/// </para>
/// <para>
/// <strong>Inspection emission.</strong> Each successful state transition fires
/// <see cref="AuthorizationServerIntegration.InspectAsync"/> with a
/// <see cref="StateTransitionStage"/> carrying the before-state, the input that
/// drove the transition, and the after-state. Both the no-executor single-step
/// branch and the effectful loop branch emit. A transition that throws does not
/// emit — emission is post-success only.
/// </para>
/// </remarks>
[DebuggerDisplay("FlowRunner")]
internal static class FlowRunner
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
    /// the method returns after the first step (still emitting one inspection).
    /// </param>
    /// <param name="context">
    /// The per-request context bag. Must carry the active
    /// <see cref="AuthorizationServer"/> via
    /// <see cref="RequestContextExtensions.Server"/> (set by the dispatcher at
    /// entry).
    /// </param>
    /// <param name="timeProvider">Time source for PDA step timestamps.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The final state and step count after the loop completes.</returns>
    public static async ValueTask<(OAuthFlowState State, int StepCount)> StepWithEffectsAsync(
        OAuthFlowState currentState,
        int currentStepCount,
        OAuthFlowInput initialInput,
        OAuthActionExecutor? executor,
        RequestContext context,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(currentState);
        ArgumentNullException.ThrowIfNull(initialInput);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(timeProvider);

        AuthorizationServer server = context.Server
            ?? throw new InvalidOperationException(
                "context.Server must be set before FlowRunner.StepWithEffectsAsync.");

        if(currentState.Kind is not StatefulFlowKind statefulKind)
        {
            throw new InvalidOperationException(
                $"FlowRunner requires a StatefulFlowKind state; got " +
                $"'{currentState.Kind.GetType().Name}'. Stateless endpoints must " +
                $"return an early-exit response from BuildInputAsync before " +
                $"reaching FlowRunner.");
        }

        InspectDelegate inspect =
            server.Integration.InspectAsync ?? DefaultInspector.NoOpAsync;

        if(executor is null)
        {
            //No executor configured — single step + one inspection emission.
            (OAuthFlowState state, int stepCount) = await statefulKind.StepAsync(
                currentState, currentStepCount, initialInput, timeProvider, cancellationToken)
                .ConfigureAwait(false);

            await inspect(
                new StateTransitionStage(currentState, initialInput, state),
                context,
                cancellationToken).ConfigureAwait(false);

            return (state, stepCount);
        }

        return await PdaRunner.StepWithEffectsAsync(
            currentState,
            currentStepCount,
            initialInput,
            step: async (state, stepCount, input, tp, ct) =>
            {
                (OAuthFlowState newState, int newCount) = await ((StatefulFlowKind)state.Kind)
                    .StepAsync(state, stepCount, input, tp, ct).ConfigureAwait(false);

                await inspect(
                    new StateTransitionStage(state, input, newState),
                    context,
                    ct).ConfigureAwait(false);

                return (newState, newCount);
            },
            actionExtractor: static state => state.NextAction,
            actionExecutor: static (action, ctx, ct) =>
                ctx.Executor.ExecuteAsync((OAuthAction)action, ctx.Context, ct),
            actionContext: (Executor: executor, Context: context),
            timeProvider,
            cancellationToken).ConfigureAwait(false);
    }
}
