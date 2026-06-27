using System.Collections.Frozen;
using System.Collections.Generic;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The central, auditable table of command admissibility by lifecycle phase, mirroring the normative
/// behaviour of TPM 2.0 Library Part 1, clause 10.
/// </summary>
/// <remarks>
/// <para>
/// Each modelled command declares the phases in which it may proceed. The transition function consults
/// <see cref="Evaluate"/> before dispatching any command, so the gating rules live in exactly one
/// place and grow command-by-command as more commands are modelled.
/// </para>
/// <para>
/// Two normative rules are encoded in the rejection mapping: a TPM that has not completed
/// <c>TPM2_Startup()</c> answers <c>TPM_RC_INITIALIZE</c> to anything but <c>TPM2_Startup()</c>
/// (clause 10.2.2), and a TPM in <see cref="TpmLifecyclePhase.FailureMode"/> answers
/// <c>TPM_RC_FAILURE</c> to anything but <c>TPM2_GetTestResult()</c> and <c>TPM2_GetCapability()</c>
/// (clause 10.4), both of which the table admits in that phase.
/// </para>
/// <para>
/// <b>Modelled scope (current).</b> The table covers the lifecycle, entropy, capability, and NV commands the
/// simulator computes responses for. The object, session, policy, and attestation command families the library
/// now exercise against the external reference simulator — <c>TPM2_Create()</c>/<c>TPM2_Load()</c>/<c>TPM2_Unseal()</c>
/// (sealed KEYEDHASH objects), <c>TPM2_Sign()</c>, <c>TPM2_Quote()</c>/<c>TPM2_Certify()</c> (attestation),
/// <c>TPM2_MakeCredential()</c>/<c>TPM2_ActivateCredential()</c> (credential activation), <c>TPM2_NV_Write()</c>
/// (NV data storage; the in-house model covers NV define/read authorization, not stored data),
/// <c>TPM2_NV_UndefineSpace()</c>/<c>TPM2_EvictControl()</c> (NV teardown and object persistence),
/// <c>TPM2_StartAuthSession()</c>, and the <c>TPM2_Policy*()</c> family with policy-session authorization — are
/// deliberately not yet modelled here: while operational they fall through to <c>TPM_RC_COMMAND_CODE</c>, the
/// faithful "command unsupported" answer, rather than half-state that would drift from reality. Modelling them
/// (real keygen/sign, sessions with cpHash/rpHash and parameter encryption, KEYEDHASH seal/unseal gated on a
/// policyDigest, and quotes over the PCR composite digest) is the staged buildout in
/// <c>tempdocs/2026-06-23-tpm-inhouse-simulator-design.md</c>.
/// </para>
/// </remarks>
public static class TpmCommandPreconditions
{
    private static readonly FrozenDictionary<TpmCcConstants, FrozenSet<TpmLifecyclePhase>> CommandTable =
        new Dictionary<TpmCcConstants, FrozenSet<TpmLifecyclePhase>>
        {
            [TpmCcConstants.TPM_CC_Startup] = new[] { TpmLifecyclePhase.Initializing }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Shutdown] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_SelfTest] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_GetTestResult] = new[] { TpmLifecyclePhase.Operational, TpmLifecyclePhase.FailureMode }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_GetRandom] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_GetCapability] = new[] { TpmLifecyclePhase.Operational, TpmLifecyclePhase.FailureMode }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_DefineSpace] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_Read] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet()
        }.ToFrozenDictionary();

    /// <summary>
    /// Evaluates whether a command may proceed in the given phase.
    /// </summary>
    /// <param name="commandCode">The command code to evaluate.</param>
    /// <param name="phase">The current lifecycle phase.</param>
    /// <returns>
    /// <see langword="null"/> if the command may proceed; otherwise the response code the TPM returns
    /// for that command in that phase.
    /// </returns>
    public static TpmRcConstants? Evaluate(TpmCcConstants commandCode, TpmLifecyclePhase phase)
    {
        if(CommandTable.TryGetValue(commandCode, out FrozenSet<TpmLifecyclePhase>? allowedPhases) && allowedPhases.Contains(phase))
        {
            return null;
        }

        return (commandCode, phase) switch
        {
            //TPM2_Startup() on an already-operational TPM is "already initialized" (clause 10.2.3).
            (TpmCcConstants.TPM_CC_Startup, TpmLifecyclePhase.Operational) => TpmRcConstants.TPM_RC_INITIALIZE,

            //Failure Mode answers only TPM2_GetTestResult()/TPM2_GetCapability(); all else fails (clause 10.4).
            (_, TpmLifecyclePhase.FailureMode) => TpmRcConstants.TPM_RC_FAILURE,

            //A command not modelled (or not admissible) while operational is an unknown command code.
            (_, TpmLifecyclePhase.Operational) => TpmRcConstants.TPM_RC_COMMAND_CODE,

            //Before startup completes only TPM2_Startup() is accepted; everything else needs initialization.
            _ => TpmRcConstants.TPM_RC_INITIALIZE
        };
    }
}
