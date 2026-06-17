using Verifiable.Foundation.Automata;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The complete state of the TPM simulator's pushdown automaton: the lifecycle phase plus the
/// persistent characteristics and results that command admissibility and responses depend on.
/// </summary>
/// <remarks>
/// <para>
/// This is the single "fat" operational record carried by one <c>PushdownAutomaton</c> per simulated
/// TPM (design decision D2: one automaton, one run identifier, one trace stream). The lifecycle
/// skeleton keeps persistent and volatile data flat; the persistent/volatile partition (NV blobs,
/// sessions, transient objects) is introduced when those features are modelled.
/// </para>
/// <para>
/// <see cref="NextAction"/> carries the effectful work the runner must perform before the next input,
/// following the PDA action convention; the lifecycle commands need no effects, so it is
/// <see cref="NullAction.Instance"/> throughout this skeleton. <see cref="ResponseIntent"/> carries the
/// logical response produced by the command that was just processed.
/// </para>
/// </remarks>
/// <param name="TpmId">The stable identifier of this simulated TPM; also the automaton's run identifier.</param>
/// <param name="Phase">The current lifecycle phase.</param>
/// <param name="ConfiguredSelfTest">
/// The modelled self-test behaviour of this TPM (a fixed hardware characteristic), used to decide the
/// outcome of <c>TPM2_SelfTest()</c>.
/// </param>
/// <param name="SelfTest">The self-test outcome since the last <c>_TPM_Init</c>.</param>
/// <param name="LastOrderlyShutdown">
/// The startup type recorded by the most recent <c>TPM2_Shutdown()</c>, or <see langword="null"/> when
/// no orderly Shutdown(STATE) is pending — either none was recorded or a startup has consumed it.
/// Determines whether a subsequent <c>Startup(STATE)</c> can resume (TPM 2.0 Library Part 1, clause
/// 10.2.3.2). A disorderly power loss is not modelled in this skeleton: power-on is always the orderly
/// <c>_TPM_Init</c>, which preserves a recorded shutdown until a startup consumes it.
/// </param>
/// <param name="NextAction">The effectful action the runner must execute next; <see cref="NullAction.Instance"/> when none.</param>
/// <param name="ResponseIntent">The logical response produced by the last command, or <see langword="null"/> when none (e.g. after <c>_TPM_Init</c>).</param>
public sealed record TpmSimulatorState(
    string TpmId,
    TpmLifecyclePhase Phase,
    TpmSelfTestBehavior ConfiguredSelfTest,
    TpmSelfTestStatus SelfTest,
    TpmSuConstants? LastOrderlyShutdown,
    PdaAction NextAction,
    TpmResponseIntent? ResponseIntent)
{
    /// <summary>
    /// Creates the initial state of a simulated TPM: powered off, awaiting <c>_TPM_Init</c>.
    /// </summary>
    /// <param name="tpmId">The stable identifier of this simulated TPM.</param>
    /// <param name="configuredSelfTest">The modelled self-test behaviour.</param>
    /// <returns>A powered-off state.</returns>
    public static TpmSimulatorState PoweredOff(string tpmId, TpmSelfTestBehavior configuredSelfTest) =>
        new(
            tpmId,
            TpmLifecyclePhase.PoweredOff,
            configuredSelfTest,
            TpmSelfTestStatus.NotRun,
            null,
            NullAction.Instance,
            null);
}
