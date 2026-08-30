using System.Collections.Frozen;
using System.Collections.Generic;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The central, auditable table of command admissibility by lifecycle phase, mirroring the normative
/// behaviour of TPM 2.0 Library Part 1, clause 9.
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
/// (clause 9.2.2), and a TPM in <see cref="TpmLifecyclePhase.FailureMode"/> answers
/// <c>TPM_RC_FAILURE</c> to anything but <c>TPM2_GetTestResult()</c> and <c>TPM2_GetCapability()</c>
/// (clause 9.4), both of which the table admits in that phase.
/// </para>
/// <para>
/// <b>Modelled scope (current).</b> The table covers the lifecycle, entropy, capability, NV define/read/write/increment, NV undefine, NV read-public (the world-readable public-area/Name query, Auth Index: None), NV change-auth (the atomic in-place authValue rotation, the one NV command carrying Auth Role ADMIN and so authorizable only by a policy session) and object persistence, the
/// ECC and RSA signing-object commands, the sealed-data path <c>TPM2_Create()</c>/<c>TPM2_Load()</c>/<c>TPM2_Unseal()</c> (a KEYEDHASH object sealed under an ECC storage parent and recovered over password authorization), the object-attestation command <c>TPM2_Certify()</c> (an ECC signing key attests another loaded object's Name over a caller nonce, both handles password-authorized), the PCR-attestation path <c>TPM2_PCR_Read()</c>/<c>TPM2_Quote()</c> (reading the SHA-256 bank and quoting a PCR composite digest over a caller nonce with an ECC signing key), and the policy (enhanced authorization) family <c>TPM2_StartAuthSession()</c> (policy and trial sessions) with <c>TPM2_PolicyCommandCode()</c>/<c>TPM2_PolicyAuthValue()</c>/<c>TPM2_PolicyPCR()</c>/<c>TPM2_PolicySecret()</c>/<c>TPM2_PolicySigned()</c>/<c>TPM2_PolicyAuthorize()</c>/<c>TPM2_PolicyOR()</c>/<c>TPM2_PolicyNV()</c>/<c>TPM2_PolicyTicket()</c>/<c>TPM2_PolicyGetDigest()</c> driving a session's policyDigest, the bound HMAC-session path <c>TPM2_StartAuthSession()</c> (an HMAC session that negotiates a symmetric definition) with an encrypt-attributed <c>TPM2_GetRandom()</c> whose response is parameter-encrypted and authenticated over the derived session key (the response HMAC and the XOR/AES-CFB channel), the credential-protection path <c>TPM2_MakeCredential()</c>/<c>TPM2_ActivateCredential()</c> (an ECDH-transported seed protects a credential bound to an object's Name, recovered only by a TPM holding both the credential key and the bound object; Part 1, clause 21), the hierarchy and provisioning family <c>TPM2_HierarchyControl()</c>/<c>TPM2_SetPrimaryPolicy()</c>/<c>TPM2_Clear()</c>/<c>TPM2_ClearControl()</c>/<c>TPM2_HierarchyChangeAuth()</c> (the four hierarchy enables, the per-hierarchy authorization policies, the owner change that rotates the storage primary seed and so structurally invalidates every owner and endorsement ticket, and the authValue rotations those hierarchies are administered by; Part 3, clauses 24.2, 24.3, 24.6, 24.7, and 24.8), and <c>TPM2_FlushContext()</c> releasing a session, transient object, or open sequence context, the simulator computes responses for — including <c>TPM2_CreatePrimary()</c>,
/// <c>TPM2_Sign()</c> (ECDSA over an exported P-256 key, and RSASSA/RSAPSS over an exported RSA key), and the
/// sequence families <c>TPM2_SignSequenceStart()</c>/<c>TPM2_SequenceUpdate()</c>/<c>TPM2_SignSequenceComplete()</c>
/// (an ECC or RSA signing key hashes and signs a message accumulated over one or more updates plus an optional
/// trailing block, flushing the sequence on success) and <c>TPM2_VerifySequenceStart()</c>/
/// <c>TPM2_VerifySequenceComplete()</c> (the same accumulator verified against a caller-supplied signature,
/// minting a <c>TPM_ST_MESSAGE_VERIFIED</c> ticket over the raw message rather than its digest). The
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
    private static FrozenDictionary<TpmCcConstants, FrozenSet<TpmLifecyclePhase>> CommandTable { get; } =
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
            [TpmCcConstants.TPM_CC_NV_ChangeAuth] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_Increment] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_Extend] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_SetBits] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_WriteLock] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_ReadLock] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_ReadPublic] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_ReadPublic] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_EvictControl] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_CreatePrimary] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Sign] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_SignDigest] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_SignSequenceStart] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_SequenceUpdate] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_SignSequenceComplete] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Create] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Load] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Unseal] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Certify] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_CertifyCreation] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_GetTime] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_ReadClock] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_ClockSet] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_Certify] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_VerifySignature] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_VerifyDigestSignature] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_VerifySequenceStart] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_VerifySequenceComplete] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_HashSequenceStart] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_SequenceComplete] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Hash] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_HMAC] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_HMAC_Start] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),

            //TPM 2.0 Library Part 1, Table 207 additionally lists both commands Permitted in Read-Only mode —
            //a distinct restriction (post-Clear, pre-orderly-Shutdown NV write throttling) this table does not
            //model at all (it covers only Initializing/Operational/FailureMode); every other modelled command
            //carries the identical gap, so it is noted here rather than as a half-modelled phase.
            [TpmCcConstants.TPM_CC_Encapsulate] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Decapsulate] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PCR_Read] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PCR_Extend] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PCR_Event] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PCR_Reset] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_EventSequenceComplete] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Quote] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_StartAuthSession] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyCommandCode] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyAuthValue] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyPCR] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicySecret] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicySigned] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyAuthorize] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyOR] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyTicket] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyNV] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyCounterTimer] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyPassword] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyCpHash] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyNameHash] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyDuplicationSelect] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyParameters] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyTemplate] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyLocality] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyNvWritten] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyRestart] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyAuthorizeNV] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_PolicyGetDigest] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_MakeCredential] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_ActivateCredential] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Duplicate] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Import] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_DictionaryAttackLockReset] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_DictionaryAttackParameters] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Clear] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_ClearControl] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_HierarchyControl] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_SetPrimaryPolicy] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_HierarchyChangeAuth] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
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
            //TPM2_Startup() on an already-operational TPM is "already initialized" (clause 9.2.3).
            (TpmCcConstants.TPM_CC_Startup, TpmLifecyclePhase.Operational) => TpmRcConstants.TPM_RC_INITIALIZE,

            //Failure Mode answers only TPM2_GetTestResult()/TPM2_GetCapability(); all else fails (clause 9.4).
            (_, TpmLifecyclePhase.FailureMode) => TpmRcConstants.TPM_RC_FAILURE,

            //A command not modelled (or not admissible) while operational is an unknown command code.
            (_, TpmLifecyclePhase.Operational) => TpmRcConstants.TPM_RC_COMMAND_CODE,

            //Before startup completes only TPM2_Startup() is accepted; everything else needs initialization.
            _ => TpmRcConstants.TPM_RC_INITIALIZE
        };
    }
}
