using Verifiable.Core.Automata;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Oid4Vp.States;

namespace Verifiable.OAuth.Oid4Vp.Session;

/// <summary>
/// Stateless single-step executor for the OID4VP authorization flow.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="PushdownAutomaton{TState,TInput,TStackSymbol}"/> is designed for long-lived
/// in-process use, but an ASP.NET application processes each authorization event in a
/// separate HTTP request, possibly on a different server instance. The persisted snapshot
/// — a state record and a step count — is the only thing that crosses between requests.
/// </para>
/// <para>
/// <see cref="StepAsync"/> rehydrates a fresh automaton from the caller-supplied snapshot,
/// executes one transition, captures the result, and discards the automaton. The caller
/// loads the snapshot from durable storage before the call and persists
/// <see cref="Oid4VpStepResult.State"/> and <see cref="Oid4VpStepResult.StepCount"/>
/// afterwards, within the same unit of work.
/// </para>
/// <para>
/// Key material never lives in the persisted state. States carry a
/// <see cref="Verifiable.Cryptography.KeyId"/> which the application's
/// <see cref="ResolveDecryptionKeyDelegate"/> maps back to live key material only at the
/// exact step that needs it. The library never stores, caches, or owns key material.
/// </para>
/// <para>
/// The following sketch illustrates typical ASP.NET usage at the response endpoint:
/// </para>
/// <code>
/// //Load the snapshot from durable storage.
/// (OAuthFlowState current, int stepCount) = await _store.LoadAsync(flowId, ct);
///
/// Oid4VpStepResult result = await Oid4VpFlowSession.StepAsync(
///     current, stepCount,
///     new ResponsePosted(body, TimeProvider.GetUtcNow()),
///     ResolveDecryptionKey,
///     timeProvider, ct);
///
/// //Forward the trace entry to structured logging or OTel.
/// logger.LogInformation("OID4VP step: {Entry}", result.TraceEntry);
///
/// return result.Outcome switch
/// {
///     Oid4VpStepOutcome.Transitioned => await PersistAndRespondAsync(result, ct),
///     Oid4VpStepOutcome.Halted       => BadRequest(),
///     Oid4VpStepOutcome.Faulted      => Problem(result.FaultException!.Message),
///     _                              => throw new UnreachableException()
/// };
/// </code>
/// </remarks>
public static class Oid4VpFlowSession
{
    /// <summary>
    /// Applies one input to the OID4VP flow automaton rehydrated from
    /// <paramref name="currentState"/> and <paramref name="stepCount"/>.
    /// </summary>
    /// <param name="currentState">The state loaded from durable storage.</param>
    /// <param name="stepCount">
    /// The step count persisted alongside the state. Pass zero for a flow that has not
    /// yet been initiated.
    /// </param>
    /// <param name="input">The input record representing the event that just occurred.</param>
    /// <param name="resolveDecryptionKey">
    /// Application-supplied delegate that maps a
    /// <see cref="Verifiable.Cryptography.KeyId"/> to live key material. Only called at
    /// the step that actually requires decryption; <see langword="null"/> is acceptable
    /// for all other steps.
    /// </param>
    /// <param name="timeProvider">The time provider used for trace entry timestamps.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// An <see cref="Oid4VpStepResult"/> carrying the outcome, the new state, the updated
    /// step count, and the trace entry emitted by the automaton.
    /// </returns>
    public static async ValueTask<Oid4VpStepResult> StepAsync(
        OAuthFlowState currentState,
        int stepCount,
        OAuthFlowInput input,
        ResolveDecryptionKeyDelegate? resolveDecryptionKey,
        TimeProvider timeProvider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(currentState);
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentOutOfRangeException.ThrowIfNegative(stepCount);

        TraceEntry<OAuthFlowState, OAuthFlowInput>? capturedEntry = null;

        PushdownAutomaton<OAuthFlowState, OAuthFlowInput, Oid4VpStackSymbol> pda =
            new(
                runId: Guid.NewGuid().ToString(),
                savedState: currentState,
                savedStack: [Oid4VpStackSymbol.Base],
                savedStepCount: stepCount,
                transition: Oid4VpFlowTransitions.Create(),
                acceptPredicate: static state => state is PresentationVerifiedState,
                timeProvider: timeProvider);

        using IDisposable subscription = pda.Subscribe(
            new SingleEntryObserver(entry => capturedEntry = entry));

        await pda.StepAsync(input, cancellationToken).ConfigureAwait(false);

        TraceEntry<OAuthFlowState, OAuthFlowInput> traceEntry = capturedEntry!;

        if(pda.IsFaulted)
        {
            return new Oid4VpStepResult(
                Outcome: Oid4VpStepOutcome.Faulted,
                State: currentState,
                Accepted: false,
                StepCount: stepCount,
                TraceEntry: traceEntry,
                FaultException: pda.FaultException);
        }

        if(pda.IsHalted)
        {
            return new Oid4VpStepResult(
                Outcome: Oid4VpStepOutcome.Halted,
                State: currentState,
                Accepted: false,
                StepCount: stepCount,
                TraceEntry: traceEntry);
        }

        return new Oid4VpStepResult(
            Outcome: Oid4VpStepOutcome.Transitioned,
            State: pda.CurrentState,
            Accepted: pda.IsAccepted,
            StepCount: pda.StepCount,
            TraceEntry: traceEntry);
    }


    private sealed class SingleEntryObserver(
        Action<TraceEntry<OAuthFlowState, OAuthFlowInput>> capture)
        : IObserver<TraceEntry<OAuthFlowState, OAuthFlowInput>>
    {
        public void OnNext(TraceEntry<OAuthFlowState, OAuthFlowInput> value) => capture(value);
        public void OnError(Exception error) { }
        public void OnCompleted() { }
    }
}
