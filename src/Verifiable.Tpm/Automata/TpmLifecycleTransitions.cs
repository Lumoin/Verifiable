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
    /// The largest number of octets the simulated TPM returns from a single <c>TPM2_GetRandom()</c>.
    /// </summary>
    /// <remarks>
    /// TPM 2.0 Library Part 3, clause 16.1: a request larger than fits in a <c>TPM2B_DIGEST</c> is not
    /// an error — the TPM returns only as much as fits, which is the largest digest it can produce. The
    /// simulator models a TPM whose largest digest is SHA-512 (64 octets), so a request is clamped here.
    /// </remarks>
    public const int MaxRandomBytes = 64;

    /// <summary>
    /// Creates the transition delegate for a TPM lifecycle automaton.
    /// </summary>
    /// <returns>The transition function.</returns>
    public static TransitionDelegate<TpmSimulatorState, TpmSimulatorInput, TpmSimulatorStackSymbol> Create() =>
        static (state, input, stackTop, cancellationToken) =>
        {
            //TpmRandomGenerated is the internal RNG fold-back: it must always be consumed into the
            //disposable TpmRandomResponse so the pooled buffer is never orphaned, so it is neither
            //cancellation-gated nor NextAction-reset here. Every externally-supplied input honours
            //cancellation and starts from a cleared NextAction, so an action left pending by an aborted
            //prior effect (e.g. an RNG backend that threw) cannot re-fire against a later command.
            TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol>? result;
            if(input is TpmRandomGenerated generated)
            {
                result = OnRandomGenerated(state, generated);
            }
            else
            {
                cancellationToken.ThrowIfCancellationRequested();

                TpmSimulatorState ready = state with { NextAction = NullAction.Instance };
                result = input switch
                {
                    TpmInitSignal => OnInit(ready),
                    _ => OnCommand(ready, input)
                };
            }

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
            TpmGetRandomRequested getRandom => OnGetRandom(state, getRandom.BytesRequested),
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

    //TPM2_GetRandom() is the first command that needs an effect: the pure transition cannot draw
    //random octets, so it declares a TpmRngAction and leaves no response yet. The effectful loop
    //fills a pooled buffer via the injected RNG backend and feeds the octets back as a
    //TpmRandomGenerated input, which OnRandomGenerated turns into the framed response.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnGetRandom(TpmSimulatorState state, ushort bytesRequested)
    {
        //A request larger than the largest digest is clamped, not rejected (clause 16.1).
        int byteCount = System.Math.Min((int)bytesRequested, MaxRandomBytes);

        return Transition(
            state with
            {
                NextAction = new TpmRngAction(byteCount),
                ResponseIntent = null
            },
            "GetRandom:Requested");
    }

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnRandomGenerated(TpmSimulatorState state, TpmRandomGenerated generated) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                ResponseIntent = new TpmRandomResponse(TpmRcConstants.TPM_RC_SUCCESS, generated.Bytes, generated.Length)
            },
            "GetRandom:Completed");

    private static TpmCcConstants CommandCodeOf(TpmSimulatorInput input) =>
        input switch
        {
            TpmStartupRequested => TpmCcConstants.TPM_CC_Startup,
            TpmShutdownRequested => TpmCcConstants.TPM_CC_Shutdown,
            TpmSelfTestRequested => TpmCcConstants.TPM_CC_SelfTest,
            TpmTestResultRequested => TpmCcConstants.TPM_CC_GetTestResult,
            TpmGetRandomRequested => TpmCcConstants.TPM_CC_GetRandom,
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
