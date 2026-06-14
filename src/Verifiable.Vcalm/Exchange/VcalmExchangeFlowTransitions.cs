using System.Collections.Immutable;
using Verifiable.Foundation.Automata;
using Verifiable.Server;

namespace Verifiable.Vcalm.Exchange;

/// <summary>
/// The transition function for the W3C VCALM 1.0 §3.6 exchange-instance flow PDA. Each transition is
/// one boundary crossing in the exchange lifecycle (§3.6.6 <c>pending → active → (complete | invalid)</c>),
/// driven by the §3.6.5 vcapi participation. The function is PURE: the holder
/// <c>verifiablePresentation</c> verification is an EFFECT run in the participate endpoint's
/// <c>BuildInputAsync</c> (the §3.3.2 verify path), so the verified / rejected verdict arrives here as
/// an input, exactly as the SIOPv2 §11.1 validation arrives as an input.
/// </summary>
/// <remarks>
/// <para>Transitions:</para>
/// <list type="bullet">
///   <item><description>
///     Sentinel + <see cref="VcalmExchangeCreated"/> -> <see cref="VcalmExchangePendingState"/>.
///     The create-exchange endpoint (§3.6.3) minted the exchange.
///   </description></item>
///   <item><description>
///     <see cref="VcalmExchangePendingState"/> + <see cref="VcalmExchangePresentationRequested"/> ->
///     <see cref="VcalmExchangeActiveState"/>. The engine answered the first vcapi message with a
///     §3.4 verifiable presentation request (§3.6: "additional information is requested").
///   </description></item>
///   <item><description>
///     <see cref="VcalmExchangePendingState"/> + <see cref="VcalmExchangeCompleted"/> ->
///     <see cref="VcalmExchangeCompleteState"/>. The engine had nothing to request nor offer (§3.6:
///     an empty reply completes the exchange), or it completed with a <c>redirectUrl</c>.
///   </description></item>
///   <item><description>
///     <see cref="VcalmExchangeActiveState"/> + <see cref="VcalmExchangePresentationVerified"/> ->
///     <see cref="VcalmExchangeCompleteState"/>. The holder presented a <c>verifiablePresentation</c>
///     that verified against the bound challenge / domain.
///   </description></item>
///   <item><description>
///     Any non-terminal state + <see cref="VcalmExchangeRejected"/> ->
///     <see cref="VcalmExchangeInvalidState"/>. A presented message was unacceptable (§3.6 4xx).
///   </description></item>
/// </list>
/// </remarks>
public static class VcalmExchangeFlowTransitions
{
    /// <summary>Creates the transition delegate for the §3.6 exchange-instance flow PDA.</summary>
    public static TransitionDelegate<FlowState, FlowInput, VcalmExchangeStackSymbol> Create() =>
        static (state, input, stackTop, cancellationToken) =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            TransitionResult<FlowState, VcalmExchangeStackSymbol>? result =
                (state, input) switch
                {
                    //Any non-terminal state + VcalmExchangeRejected -> VcalmExchangeInvalid (§3.6 4xx).
                    (not (VcalmExchangeCompleteState or VcalmExchangeInvalidState), VcalmExchangeRejected rejected) =>
                        Transition(
                            new VcalmExchangeInvalidState
                            {
                                FlowId = state.FlowId,
                                ExpectedIssuer = state.ExpectedIssuer,
                                EnteredAt = rejected.FailedAt,
                                ExpiresAt = state.ExpiresAt,
                                Kind = VcalmExchangeFlowKind.Instance,
                                ExchangeId = ExchangeIdOf(state),
                                Expires = ExpiresOf(state),
                                VariablesJson = VariablesOf(state),
                                StepName = rejected.StepName ?? StepNameOf(state),
                                StepResults = MergeResults(StepResultsOf(state), rejected.StepResults),
                                ErrorType = rejected.ErrorType,
                                ErrorTitle = rejected.ErrorTitle,
                                ErrorDetail = rejected.ErrorDetail,
                                FailedAt = rejected.FailedAt
                            },
                            StackAction<VcalmExchangeStackSymbol>.None,
                            "VcalmExchangeInvalid"),

                    //Sentinel (empty FlowId invalid state) + VcalmExchangeCreated -> VcalmExchangePending.
                    (VcalmExchangeInvalidState { FlowId: "" }, VcalmExchangeCreated created) =>
                        Transition(
                            new VcalmExchangePendingState
                            {
                                FlowId = created.FlowId,
                                ExpectedIssuer = state.ExpectedIssuer,
                                EnteredAt = created.CreatedAt,
                                ExpiresAt = created.ExpiresAt,
                                Kind = VcalmExchangeFlowKind.Instance,
                                ExchangeId = created.ExchangeId,
                                Expires = created.Expires,
                                VariablesJson = created.VariablesJson
                            },
                            StackAction<VcalmExchangeStackSymbol>.None,
                            "VcalmExchangePending"),

                    //VcalmExchangePending + VcalmExchangePresentationRequested -> VcalmExchangeActive.
                    //The engine asked for a presentation (§3.6: "additional information is requested").
                    (VcalmExchangePendingState pending, VcalmExchangePresentationRequested requested) =>
                        Transition(
                            new VcalmExchangeActiveState
                            {
                                FlowId = pending.FlowId,
                                ExpectedIssuer = pending.ExpectedIssuer,
                                EnteredAt = requested.RequestedAt,
                                ExpiresAt = pending.ExpiresAt,
                                Kind = VcalmExchangeFlowKind.Instance,
                                ExchangeId = pending.ExchangeId,
                                Expires = pending.Expires,
                                VariablesJson = pending.VariablesJson,
                                StepName = requested.StepName,
                                Challenge = requested.Challenge,
                                Domain = requested.Domain,
                                PresentationQueryJson = requested.PresentationQueryJson,
                                StepResults = requested.StepResults
                            },
                            StackAction<VcalmExchangeStackSymbol>.None,
                            "VcalmExchangeActive"),

                    //VcalmExchangeActive + VcalmExchangeAdvancedToPresentation -> VcalmExchangeActive.
                    //The multi-step advance V-5b lacked: the prior step's presentation verified, its
                    //result was recorded, and the workflow's NEXT step requests another presentation —
                    //bound to a FRESH challenge / domain so the fail-closed property holds per step.
                    (VcalmExchangeActiveState priorActive, VcalmExchangeAdvancedToPresentation advanced) =>
                        Transition(
                            new VcalmExchangeActiveState
                            {
                                FlowId = priorActive.FlowId,
                                ExpectedIssuer = priorActive.ExpectedIssuer,
                                EnteredAt = advanced.AdvancedAt,
                                ExpiresAt = priorActive.ExpiresAt,
                                Kind = VcalmExchangeFlowKind.Instance,
                                ExchangeId = priorActive.ExchangeId,
                                Expires = priorActive.Expires,
                                VariablesJson = priorActive.VariablesJson,
                                StepName = advanced.StepName,
                                Challenge = advanced.Challenge,
                                Domain = advanced.Domain,
                                PresentationQueryJson = advanced.PresentationQueryJson,
                                StepResults = advanced.StepResults
                            },
                            StackAction<VcalmExchangeStackSymbol>.None,
                            "VcalmExchangeActive"),

                    //VcalmExchangePending (or active) + VcalmExchangeCompleted -> VcalmExchangeComplete.
                    //The engine had nothing more to request nor offer; the empty reply (or a redirectUrl)
                    //completes the exchange (§3.6). The completion may arrive straight from pending (an
                    //empty / redirect / issue-then-complete first step) or from active (a multi-step walk
                    //whose final step issued a credential or completed after the prior step's presentation).
                    (not (VcalmExchangeCompleteState or VcalmExchangeInvalidState), VcalmExchangeCompleted completed) =>
                        Transition(
                            new VcalmExchangeCompleteState
                            {
                                FlowId = state.FlowId,
                                ExpectedIssuer = state.ExpectedIssuer,
                                EnteredAt = completed.CompletedAt,
                                ExpiresAt = state.ExpiresAt,
                                Kind = VcalmExchangeFlowKind.Instance,
                                ExchangeId = ExchangeIdOf(state),
                                Expires = ExpiresOf(state),
                                VariablesJson = VariablesOf(state),
                                ResultStepName = null,
                                VerifiablePresentationJson = null,
                                StepResults = MergeResults(StepResultsOf(state), completed.StepResults),
                                RedirectUrl = completed.RedirectUrl,
                                CompletedAt = completed.CompletedAt
                            },
                            StackAction<VcalmExchangeStackSymbol>.None,
                            "VcalmExchangeComplete"),

                    //VcalmExchangeActive + VcalmExchangePresentationVerified -> VcalmExchangeComplete.
                    //The holder presented a verifiablePresentation that verified against the bound
                    //challenge / domain at the FINAL step (no nextStep), so the exchange completes. The
                    //verification ran in the endpoint, outside this transition; the verified input carries
                    //the full accumulated results (every step's output) the complete state surfaces.
                    (VcalmExchangeActiveState active, VcalmExchangePresentationVerified verified) =>
                        Transition(
                            new VcalmExchangeCompleteState
                            {
                                FlowId = active.FlowId,
                                ExpectedIssuer = active.ExpectedIssuer,
                                EnteredAt = verified.VerifiedAt,
                                ExpiresAt = active.ExpiresAt,
                                Kind = VcalmExchangeFlowKind.Instance,
                                ExchangeId = active.ExchangeId,
                                Expires = active.Expires,
                                VariablesJson = active.VariablesJson,
                                ResultStepName = verified.StepName,
                                VerifiablePresentationJson = verified.VerifiablePresentationJson,
                                StepResults = verified.StepResults,
                                RedirectUrl = null,
                                CompletedAt = verified.VerifiedAt
                            },
                            StackAction<VcalmExchangeStackSymbol>.None,
                            "VcalmExchangeComplete"),

                    //Terminal states — PDA halts.
                    (VcalmExchangeCompleteState, _) => null,
                    (VcalmExchangeInvalidState, _) => null,

                    _ => null
                };

            return ValueTask.FromResult<TransitionResult<FlowState, VcalmExchangeStackSymbol>?>(result);
        };


    private static TransitionResult<FlowState, VcalmExchangeStackSymbol> Transition(
        FlowState nextState,
        StackAction<VcalmExchangeStackSymbol> stackAction,
        string label) =>
        new(nextState, stackAction, label);


    //The exchange id carried by whichever non-terminal exchange state is current — used when failing
    //the exchange so the invalid state retains the §3.6.6 reporting fields.
    private static string ExchangeIdOf(FlowState state) => state switch
    {
        VcalmExchangePendingState pending => pending.ExchangeId,
        VcalmExchangeActiveState active => active.ExchangeId,
        VcalmExchangeCompleteState complete => complete.ExchangeId,
        VcalmExchangeInvalidState invalid => invalid.ExchangeId,
        _ => string.Empty
    };


    private static string? ExpiresOf(FlowState state) => state switch
    {
        VcalmExchangePendingState pending => pending.Expires,
        VcalmExchangeActiveState active => active.Expires,
        VcalmExchangeCompleteState complete => complete.Expires,
        VcalmExchangeInvalidState invalid => invalid.Expires,
        _ => null
    };


    private static string? StepNameOf(FlowState state) => state switch
    {
        VcalmExchangeActiveState active => active.StepName,
        VcalmExchangeInvalidState invalid => invalid.StepName,
        _ => null
    };


    private static string? VariablesOf(FlowState state) => state switch
    {
        VcalmExchangePendingState pending => pending.VariablesJson,
        VcalmExchangeActiveState active => active.VariablesJson,
        VcalmExchangeCompleteState complete => complete.VariablesJson,
        VcalmExchangeInvalidState invalid => invalid.VariablesJson,
        _ => null
    };


    //The §3.6.6 variables.results accumulated on whichever non-terminal exchange state is current.
    private static ImmutableDictionary<string, string> StepResultsOf(FlowState state) => state switch
    {
        VcalmExchangeActiveState active => active.StepResults,
        VcalmExchangeCompleteState complete => complete.StepResults,
        VcalmExchangeInvalidState invalid => invalid.StepResults,
        _ => ImmutableDictionary<string, string>.Empty
    };


    //Merges an input's results over the current state's results — the input carries the freshly
    //recorded entries, the state the ones already present; the input wins on a key collision (it is the
    //newer view). Returns the larger map verbatim when the other is empty (the common single-step case).
    private static ImmutableDictionary<string, string> MergeResults(
        ImmutableDictionary<string, string> current, ImmutableDictionary<string, string> incoming)
    {
        if(incoming.IsEmpty)
        {
            return current;
        }

        if(current.IsEmpty)
        {
            return incoming;
        }

        return current.SetItems(incoming);
    }
}
