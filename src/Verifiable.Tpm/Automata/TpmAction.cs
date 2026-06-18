using Verifiable.Foundation.Automata;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// Base type for the effectful actions a TPM command transition can declare. A
/// <see cref="TpmAction"/> is produced by the pure transition function as part of the next state
/// (carried in <see cref="TpmSimulatorState.NextAction"/>); the effectful loop in
/// <see cref="TpmSimulator"/> dispatches it to a backend and feeds the result back as the next input.
/// </summary>
/// <remarks>
/// The lifecycle commands modelled in V.2 (<c>TPM2_Startup()</c>, <c>TPM2_Shutdown()</c>,
/// <c>TPM2_SelfTest()</c>, <c>TPM2_GetTestResult()</c>) declare no effects and leave
/// <see cref="NullAction.Instance"/> in place. The first command that needs an effect is
/// <c>TPM2_GetRandom()</c>, whose <see cref="TpmRngAction"/> asks the injected RNG backend for octets.
/// </remarks>
public abstract record TpmAction: PdaAction;

/// <summary>
/// Declares that the simulator must draw <paramref name="ByteCount"/> random octets from its RNG
/// backend before the next transition. Emitted by the <c>TPM2_GetRandom()</c> transition; the
/// effectful loop fills a pooled buffer via the injected backend and feeds the bytes back as a
/// <see cref="TpmRandomGenerated"/> input (TPM 2.0 Library Part 3, clause 16.1).
/// </summary>
/// <param name="ByteCount">
/// The number of octets to produce, already clamped to the largest digest the simulated TPM can
/// return (<see cref="TpmLifecycleTransitions.MaxRandomBytes"/>).
/// </param>
public sealed record TpmRngAction(int ByteCount): TpmAction;
