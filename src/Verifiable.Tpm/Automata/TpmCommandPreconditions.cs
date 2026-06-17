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
/// (clause 10.4). <c>TPM2_GetCapability()</c> joins the table when it is modelled.
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
            [TpmCcConstants.TPM_CC_GetTestResult] = new[] { TpmLifecyclePhase.Operational, TpmLifecyclePhase.FailureMode }.ToFrozenSet()
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
