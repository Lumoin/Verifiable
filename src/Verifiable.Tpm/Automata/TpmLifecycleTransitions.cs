using System.Threading.Tasks;
using Verifiable.Foundation.Automata;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The transition function (δ) of the TPM lifecycle simulator: a pure mapping from
/// (state, input) to the next state and stack action, mirroring TPM 2.0 Library Part 1, clause 10.
/// </summary>
/// <remarks>
/// <para>
/// The function performs no I/O, reads no time, and uses no randomness — the only buffer-touching work
/// (parsing requests, framing responses) happens in <see cref="TpmSimulator"/>. Command admissibility
/// is decided by <see cref="TpmCommandPreconditions"/> before any command is dispatched; a rejected
/// command transitions into a state whose response carries the rejection code, and the lifecycle phase
/// is left unchanged. The automaton never halts in this skeleton (a transition is defined for every
/// input), so a returned <see langword="null"/> would signal a genuinely unexpected input.
/// </para>
/// </remarks>
public static class TpmLifecycleTransitions
{
    /// <summary>
    /// Creates the transition delegate for a TPM lifecycle automaton.
    /// </summary>
    /// <returns>The transition function.</returns>
    public static TransitionDelegate<TpmSimulatorState, TpmSimulatorInput, TpmSimulatorStackSymbol> Create() =>
        static (state, input, stackTop, cancellationToken) =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol>? result = input switch
            {
                TpmInitSignal => OnInit(state),
                _ => OnCommand(state, input)
            };

            return ValueTask.FromResult(result);
        };

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnInit(TpmSimulatorState state) =>
        Transition(
            state with
            {
                Phase = TpmLifecyclePhase.Initializing,
                SelfTest = TpmSelfTestStatus.NotRun,
                ResponseIntent = null
            },
            "TpmInit");

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol>? OnCommand(TpmSimulatorState state, TpmSimulatorInput input)
    {
        TpmCcConstants commandCode = CommandCodeOf(input);
        TpmRcConstants? rejection = TpmCommandPreconditions.Evaluate(commandCode, state.Phase);
        if(rejection is TpmRcConstants responseCode)
        {
            return Reject(state, commandCode, responseCode);
        }

        return input switch
        {
            TpmStartupRequested startup => OnStartup(state, startup.StartupType),
            TpmShutdownRequested shutdown => OnShutdown(state, shutdown.ShutdownType),
            TpmSelfTestRequested => OnSelfTest(state),
            TpmTestResultRequested => OnTestResult(state),
            _ => throw new System.InvalidOperationException($"Command input '{input.GetType().Name}' passed precondition gating but has no dispatch handler.")
        };
    }

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnStartup(TpmSimulatorState state, TpmSuConstants startupType) =>
        startupType switch
        {
            //Startup(CLEAR): TPM Reset or TPM Restart — always becomes operational (clause 10.2.3.2).
            TpmSuConstants.TPM_SU_CLEAR => Transition(
                state with
                {
                    Phase = TpmLifecyclePhase.Operational,
                    LastOrderlyShutdown = null,
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "Startup:Clear"),

            //Startup(STATE) after a Shutdown(STATE): TPM Resume.
            TpmSuConstants.TPM_SU_STATE when state.LastOrderlyShutdown == TpmSuConstants.TPM_SU_STATE => Transition(
                state with
                {
                    Phase = TpmLifecyclePhase.Operational,
                    LastOrderlyShutdown = null,
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "Startup:State"),

            //Startup(STATE) without a preserved Shutdown(STATE): no state to restore (clause 10.2.3.2).
            TpmSuConstants.TPM_SU_STATE => Reject(state, TpmCcConstants.TPM_CC_Startup, TpmRcConstants.TPM_RC_VALUE),

            //An out-of-range startupType value.
            _ => Reject(state, TpmCcConstants.TPM_CC_Startup, TpmRcConstants.TPM_RC_VALUE)
        };

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnShutdown(TpmSimulatorState state, TpmSuConstants shutdownType) =>
        shutdownType switch
        {
            //Record the orderly shutdown type so a later Startup can decide what to restore (clause 10.2.4).
            //The TPM stays operational until the next _TPM_Init; saved-state invalidation by a later
            //state-modifying command is modelled when such commands are added.
            TpmSuConstants.TPM_SU_CLEAR or TpmSuConstants.TPM_SU_STATE => Transition(
                state with
                {
                    LastOrderlyShutdown = shutdownType,
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                shutdownType == TpmSuConstants.TPM_SU_CLEAR ? "Shutdown:Clear" : "Shutdown:State"),

            _ => Reject(state, TpmCcConstants.TPM_CC_Shutdown, TpmRcConstants.TPM_RC_VALUE)
        };

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnSelfTest(TpmSimulatorState state) =>
        state.ConfiguredSelfTest switch
        {
            //A failed self-test returns TPM_RC_FAILURE and enters Failure Mode (clause 10.3, Figure 5).
            TpmSelfTestBehavior.Fails => Transition(
                state with
                {
                    Phase = TpmLifecyclePhase.FailureMode,
                    SelfTest = TpmSelfTestStatus.Failed,
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_FAILURE)
                },
                "SelfTest:Failed"),

            _ => Transition(
                state with
                {
                    SelfTest = TpmSelfTestStatus.Passed,
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "SelfTest:Passed")
        };

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnTestResult(TpmSimulatorState state)
    {
        TpmRcConstants testResult = state.SelfTest == TpmSelfTestStatus.Failed
            ? TpmRcConstants.TPM_RC_FAILURE
            : TpmRcConstants.TPM_RC_SUCCESS;

        return Transition(
            state with { ResponseIntent = new TpmTestResultResponse(TpmRcConstants.TPM_RC_SUCCESS, testResult) },
            "GetTestResult");
    }

    private static TpmCcConstants CommandCodeOf(TpmSimulatorInput input) =>
        input switch
        {
            TpmStartupRequested => TpmCcConstants.TPM_CC_Startup,
            TpmShutdownRequested => TpmCcConstants.TPM_CC_Shutdown,
            TpmSelfTestRequested => TpmCcConstants.TPM_CC_SelfTest,
            TpmTestResultRequested => TpmCcConstants.TPM_CC_GetTestResult,
            TpmUnsupportedCommandReceived unsupported => unsupported.CommandCode,
            _ => throw new System.InvalidOperationException($"Input '{input.GetType().Name}' is not a command and must not reach command dispatch.")
        };

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> Reject(TpmSimulatorState state, TpmCcConstants commandCode, TpmRcConstants responseCode) =>
        Transition(
            state with { ResponseIntent = new TpmHeaderOnlyResponse(responseCode) },
            $"Reject:{commandCode}");

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> Transition(TpmSimulatorState nextState, string label) =>
        new(nextState, StackAction<TpmSimulatorStackSymbol>.None, label);
}
