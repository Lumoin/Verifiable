using System.Buffers;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The input alphabet of the TPM simulator's pushdown automaton. Inputs arrive from three sources: the
/// platform (<see cref="TpmInitSignal"/>), the command transport (the command-arrived records, parsed
/// from the wire by <see cref="TpmSimulator"/> before they enter the automaton), and the effectful
/// loop (the action-result records, such as <see cref="TpmRandomGenerated"/>, fed back after a
/// <see cref="TpmAction"/> has been executed by a backend).
/// </summary>
public abstract record TpmSimulatorInput;

/// <summary>
/// The platform <c>_TPM_Init</c> indication (TPM 2.0 Library Part 1, clause 10.2.2). It is not a TPM
/// command and produces no response; it moves the device into <see cref="TpmLifecyclePhase.Initializing"/>
/// and is the only exit from <see cref="TpmLifecyclePhase.FailureMode"/>.
/// </summary>
public sealed record TpmInitSignal: TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Startup()</c> command (TPM 2.0 Library Part 1, clause 10.2.3).
/// </summary>
/// <param name="StartupType">The startup type argument (<c>TPM_SU_CLEAR</c> or <c>TPM_SU_STATE</c>).</param>
public sealed record TpmStartupRequested(TpmSuConstants StartupType): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_Shutdown()</c> command (TPM 2.0 Library Part 1, clause 10.2.4).
/// </summary>
/// <param name="ShutdownType">The shutdown type argument (<c>TPM_SU_CLEAR</c> or <c>TPM_SU_STATE</c>).</param>
public sealed record TpmShutdownRequested(TpmSuConstants ShutdownType): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_SelfTest()</c> command (TPM 2.0 Library Part 1, clause 10.3).
/// </summary>
/// <param name="IsFullTest">
/// Whether a full self-test of all algorithms was requested. The lifecycle skeleton does not track
/// per-algorithm test state, so this only records the request.
/// </param>
public sealed record TpmSelfTestRequested(bool IsFullTest): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_GetTestResult()</c> command (TPM 2.0 Library Part 1, clause 10.3). Permitted both
/// operationally and in <see cref="TpmLifecyclePhase.FailureMode"/>.
/// </summary>
public sealed record TpmTestResultRequested: TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_GetRandom()</c> command (TPM 2.0 Library Part 3, clause 16.1). Permitted only while
/// operational; on success it draws random octets through the action layer.
/// </summary>
/// <param name="BytesRequested">
/// The number of octets the caller requested. The transition clamps this to the largest digest the
/// simulated TPM can return before declaring the RNG action (clause 16.1: requesting more than fits
/// in a <c>TPM2B_DIGEST</c> is not an error — the TPM returns only what fits).
/// </param>
public sealed record TpmGetRandomRequested(ushort BytesRequested): TpmSimulatorInput;

/// <summary>
/// A <c>TPM2_GetCapability()</c> command (TPM 2.0 Library Part 3, clause 30.2). Permitted while
/// operational and in <see cref="TpmLifecyclePhase.FailureMode"/> (Part 1, clause 10.4).
/// </summary>
/// <param name="Capability">The capability category to query.</param>
/// <param name="Property">The first property (tag) to return.</param>
/// <param name="PropertyCount">The maximum number of properties to return.</param>
public sealed record TpmGetCapabilityRequested(TpmCapConstants Capability, uint Property, uint PropertyCount): TpmSimulatorInput;

/// <summary>
/// The result of executing a <see cref="TpmRngAction"/>: the random octets produced by the RNG
/// backend, fed back into the automaton by the effectful loop so the transition can frame the
/// <c>TPM2_GetRandom()</c> response. This input is internal to the effect loop and never arrives from
/// the command transport.
/// </summary>
/// <param name="Bytes">
/// The pooled buffer holding the produced octets. Ownership flows to the <see cref="TpmRandomResponse"/>
/// the transition produces and is released by <see cref="TpmSimulator"/> once the response is framed.
/// </param>
/// <param name="Length">The number of valid octets in <paramref name="Bytes"/> (the clamped count).</param>
public sealed record TpmRandomGenerated(IMemoryOwner<byte> Bytes, int Length): TpmSimulatorInput;

/// <summary>
/// A command whose code the lifecycle skeleton does not yet model. It is gated by the current phase
/// like any other command (rejected with the phase-appropriate response code).
/// </summary>
/// <param name="CommandCode">The unsupported command code as parsed from the request header.</param>
public sealed record TpmUnsupportedCommandReceived(TpmCcConstants CommandCode): TpmSimulatorInput;
