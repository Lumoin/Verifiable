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
/// <b>Modelled scope (current).</b> The table covers the lifecycle, entropy, capability, NV define/read/write, NV undefine and object persistence, the
/// ECC and RSA signing-object commands, the sealed-data path <c>TPM2_Create()</c>/<c>TPM2_Load()</c>/<c>TPM2_Unseal()</c> (a KEYEDHASH object sealed under an ECC storage parent and recovered over password authorization), the object-attestation command <c>TPM2_Certify()</c> (an ECC signing key attests another loaded object's Name over a caller nonce, both handles password-authorized), the PCR-attestation path <c>TPM2_PCR_Read()</c>/<c>TPM2_Quote()</c> (reading the SHA-256 bank and quoting a PCR composite digest over a caller nonce with an ECC signing key), and the policy (enhanced authorization) family <c>TPM2_StartAuthSession()</c> (policy and trial sessions) with <c>TPM2_PolicyCommandCode()</c>/<c>TPM2_PolicyAuthValue()</c>/<c>TPM2_PolicyPCR()</c>/<c>TPM2_PolicySecret()</c>/<c>TPM2_PolicyOR()</c>/<c>TPM2_PolicyNV()</c>/<c>TPM2_PolicyGetDigest()</c> driving a session's policyDigest, the bound HMAC-session path <c>TPM2_StartAuthSession()</c> (an HMAC session that negotiates a symmetric definition) with an encrypt-attributed <c>TPM2_GetRandom()</c> whose response is parameter-encrypted and authenticated over the derived session key (the response HMAC and the XOR/AES-CFB channel), the credential-protection path <c>TPM2_MakeCredential()</c>/<c>TPM2_ActivateCredential()</c> (an ECDH-transported seed protects a credential bound to an object's Name, recovered only by a TPM holding both the credential key and the bound object; Part 1, clause 24), and <c>TPM2_FlushContext()</c> releasing a session or transient object, the simulator computes responses for — including <c>TPM2_CreatePrimary()</c> and
/// <c>TPM2_Sign()</c> (ECDSA over an exported P-256 key, and RSASSA/RSAPSS over an exported RSA key). The
/// remaining object, session, and attestation
/// command families — command-side HMAC verification and the parameter encryption of the request (the modelled HMAC session encrypts the response only; the policy sessions modelled here accumulate a policyDigest but do not gate an object's use),
/// and <c>TPM2_PCR_Extend()</c> (PCR measurement; the in-house model covers reading and quoting the reset bank, not extending it)— are deliberately not yet modelled here: while operational they fall through to
/// <c>TPM_RC_COMMAND_CODE</c>, the faithful "command unsupported" answer, rather than half-state that would drift
/// from reality. Modelling them (sessions with cpHash/rpHash and parameter encryption, KEYEDHASH seal/unseal
/// gated on a policyDigest, and PCR extension with a policyPCR gate) is a staged buildout.
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
            [TpmCcConstants.TPM_CC_NV_Read] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_Write] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_UndefineSpace] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_EvictControl] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_CreatePrimary] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Sign] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Create] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Load] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Unseal] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Certify] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_CertifyCreation] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_GetTime] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_Certify] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PCR_Read] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Quote] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_StartAuthSession] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyCommandCode] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyAuthValue] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyPCR] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicySecret] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyOR] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyNV] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyGetDigest] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_MakeCredential] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_ActivateCredential] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_FlushContext] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet()
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
