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
/// <b>Modelled scope (current).</b> The table covers the lifecycle, entropy (<c>TPM2_GetRandom()</c> and its
/// additional-input reseed <c>TPM2_StirRandom()</c>, and the algorithm-parameter validator
/// <c>TPM2_TestParms()</c>, all three sharing one zero-handle session table over their companion slot — a
/// decrypt or encrypt claim TestParms's slot can never carry to success, since the command has neither a
/// command nor a response parameter for either to protect, while an audit-only claim succeeds like any other
/// audited command; Part 3, clauses 16.1, 16.2 and 30.3), the same no-authorization session admission shared,
/// through one generic mechanism, by <c>TPM2_ReadClock()</c>, <c>TPM2_Shutdown()</c>, <c>TPM2_SelfTest()</c>,
/// <c>TPM2_GetTestResult()</c>, <c>TPM2_GetCapability()</c> and <c>TPM2_PCR_Read()</c> (each admitting an
/// audit-only companion, <c>TPM2_GetTestResult()</c> also admitting an encrypt companion over its <c>outData</c>)
/// and by <c>TPM2_ReadPublic()</c>/<c>TPM2_NV_ReadPublic()</c> (each admitting an audit or encrypt companion,
/// the encrypt claim protecting <c>outPublic</c>/<c>nvPublic</c>, with the addressed object's or NV Index's Name
/// resolved into cpHash ahead of the companion slots being judged, Part 3, clause 5.4 preceding clause 5.5;
/// Part 3, clauses 29.1, 22.4, 12.4, 30.2 and 31.6, and Tables 6, 8 and 12) — and, over the SAME
/// generic mechanism, by <c>TPM2_Hash()</c> (audit, encrypt or decrypt, the widest of the sixteen, a decrypt
/// claim protecting <c>data</c> and an encrypt claim protecting <c>outHash</c>; Part 3, clause 15.4, Table 69),
/// <c>TPM2_HashSequenceStart()</c>/<c>TPM2_SignSequenceStart()</c>/<c>TPM2_VerifySequenceStart()</c> (audit or
/// decrypt, a decrypt claim protecting <c>auth</c>, the new sequence handle riding the response's own handle
/// slot rather than a TPM2B an encrypt claim could protect; Part 3, clauses 17.4, 17.5 and 17.6, Tables 85, 87
/// and 89), <c>TPM2_VerifySignature()</c> (deprecated in this revision, still mandatory) and
/// <c>TPM2_VerifyDigestSignature()</c> (audit or decrypt, a decrypt claim protecting <c>digest</c> or, for the
/// digest-only form, <c>context</c>; Part 3, clauses 20.2 and 20.4, Tables 116 and 120), <c>TPM2_Encapsulate()</c>
/// (audit or encrypt, an encrypt claim protecting the response's <c>sharedSecret</c>, Table 61's FIRST field —
/// Table 60 carries no command parameter for a decrypt claim to protect; Part 3, clause 14.10, Table 60), and
/// <c>TPM2_MakeCredential()</c> (audit, encrypt or decrypt, a decrypt claim protecting <c>credential</c> and an
/// encrypt claim protecting the response's <c>credentialBlob</c>; Part 3, clause 12.6, Table 28) — the six with
/// a handle (Auth Index None on every one) resolving that handle's Name into cpHash ahead of the companion
/// slots being judged, exactly as <c>TPM2_ReadPublic()</c>'s and <c>TPM2_NV_ReadPublic()</c>'s own handles do, an
/// audit session modelled across the whole session-authorized family (a per-session digest, first-use
/// initialization, the cpHash‖rpHash extend on
/// success, TPM-wide exclusive-session tracking with its command gate and response echo, <c>auditReset</c>, the
/// bind loss on first audit use, and the Startup/FlushContext/ContextSave/ContextLoad interactions; Part 1,
/// clause 17; Part 2, clause 8.4, Table 38), attested by <c>TPM2_GetSessionAuditDigest()</c> (a signing key, or
/// the NULL signer, attests an audit session's pre-command digest and exclusive status over a caller nonce, on
/// <c>TPM2_GetTime()</c>'s own shape plus the audited session's own unauthorized handle; Part 3, clause 18.5),
/// capability, NV define/read/write/increment, NV undefine, NV read-public (the world-readable public-area/Name query, Auth Index: None), NV change-auth (the atomic in-place authValue rotation, the one NV command carrying Auth Role ADMIN and so authorizable only by a policy session), NV undefine-special (the two-session ADMIN-plus-platform deletion of a policy-delete NV Index, <c>TPM2_NV_UndefineSpaceSpecial()</c>) and object persistence, <c>TPM2_LoadExternal()</c> (loading a public area alone, or a public area with an unencrypted sensitive area, as a Temporary Object under a hierarchy or under <c>TPM_RH_NULL</c>, its zero-handle session table admitting a decrypt claim on <c>inPrivate</c> and an encrypt claim on the response <c>name</c> independently; Part 3, clause 12.3), <c>TPM2_ObjectChangeAuth()</c> (rewrapping a loaded sealed object's sensitive area under a new authorization value beneath its parent, the parent judged by recomputing the object's Qualified Name, the ADMIN-role slot authorized by a password, an HMAC session or a policy session as the object's <c>adminWithPolicy</c> attribute admits; Part 3, clause 12.8), the
/// ECC and RSA signing-object commands, the sealed-data path <c>TPM2_Create()</c>/<c>TPM2_Load()</c>/<c>TPM2_Unseal()</c> (a KEYEDHASH object sealed under an ECC storage parent and recovered over password authorization), the public-key encryption command <c>TPM2_RSA_Encrypt()</c> (RSA-encrypting a message to a loaded key's public modulus under a padding scheme Table 42 selects between the key's own retained scheme and the command's <c>inScheme</c> — <c>TPM_ALG_NULL</c>, <c>TPM_ALG_RSAES</c>, or <c>TPM_ALG_OAEP</c> — over Auth Index: None, so no authorization ladder runs at all; its zero-authorizing-slot session table admits a decrypt claim on <c>message</c> and an encrypt claim on the response <c>outData</c> independently, the same table <c>TPM2_LoadExternal()</c>'s carries; Part 3, clause 14.2), the private-key decryption command <c>TPM2_RSA_Decrypt()</c> (recovering <c>cipherText</c> under the same Table 42 scheme selection, authorized at <c>@keyHandle</c>'s USER slot — an unrestricted decrypt key checked by the same asymmetric-key ladder <c>TPM2_Sign()</c> checks its own signing key with, a loaded KEYEDHASH object or an open hash sequence at that slot instead running its own ladder before the command's "required to be an RSA key" gate; its response <c>message</c> eligible for session-based parameter encryption; Part 3, clause 14.3), the object-attestation command <c>TPM2_Certify()</c> (an ECC signing key attests another loaded object's Name over a caller nonce, both handles password-authorized), the PCR-attestation path <c>TPM2_PCR_Read()</c>/<c>TPM2_Quote()</c> (reading the SHA-256 bank and quoting a PCR composite digest over a caller nonce with an ECC signing key), and the policy (enhanced authorization) family <c>TPM2_StartAuthSession()</c> (policy and trial sessions) with <c>TPM2_PolicyCommandCode()</c>/<c>TPM2_PolicyAuthValue()</c>/<c>TPM2_PolicyPCR()</c>/<c>TPM2_PolicySecret()</c>/<c>TPM2_PolicySigned()</c>/<c>TPM2_PolicyAuthorize()</c>/<c>TPM2_PolicyOR()</c>/<c>TPM2_PolicyNV()</c>/<c>TPM2_PolicyTicket()</c>/<c>TPM2_PolicyGetDigest()</c> driving a session's policyDigest, the bound HMAC-session path <c>TPM2_StartAuthSession()</c> (an HMAC session that negotiates a symmetric definition) with an encrypt-attributed <c>TPM2_GetRandom()</c> whose response is parameter-encrypted and authenticated over the derived session key (the response HMAC and the XOR/AES-CFB channel), the credential-protection path <c>TPM2_MakeCredential()</c>/<c>TPM2_ActivateCredential()</c> (an ECDH-transported seed protects a credential bound to an object's Name, recovered only by a TPM holding both the credential key and the bound object; Part 1, clause 21), the hierarchy and provisioning family <c>TPM2_HierarchyControl()</c>/<c>TPM2_SetPrimaryPolicy()</c>/<c>TPM2_Clear()</c>/<c>TPM2_ClearControl()</c>/<c>TPM2_HierarchyChangeAuth()</c>/<c>TPM2_ClockRateAdjust()</c> (the four hierarchy enables, the per-hierarchy authorization policies, the owner change that rotates the storage primary seed and so structurally invalidates every owner and endorsement ticket, the authValue rotations those hierarchies are administered by, and the owner-or-platform-authorized adjustment of the rate <c>Clock</c> and <c>Time</c> advance at; Part 3, clauses 24.2, 24.3, 24.6, 24.7, 24.8, and 29.3), and <c>TPM2_FlushContext()</c> releasing a session, transient object, or open sequence context (including a saved session's tracking entry), and <c>TPM2_ContextSave()</c> (a session, transient object, or sequence context saved outside the TPM as an integrity- and confidentiality-protected <c>TPMS_CONTEXT</c>, its handle carried in the handle area over <c>TPM_ST_NO_SESSIONS</c> alone; TPM 2.0 Library Part 3, clause 28.2) paired with <c>TPM2_ContextLoad()</c> (reloading that <c>TPMS_CONTEXT</c> — the whole structure arriving as the command's single parameter over <c>TPM_ST_NO_SESSIONS</c> alone, no handle area — decrypting and integrity-verifying it before a session reinstalls at its own saved handle or an object/sequence is assigned a freshly drawn one; TPM 2.0 Library Part 3, clause 28.3), the simulator computes responses for — including <c>TPM2_CreatePrimary()</c>,
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
            [TpmCcConstants.TPM_CC_StirRandom] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_TestParms] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_GetCapability] = new[] { TpmLifecyclePhase.Operational, TpmLifecyclePhase.FailureMode }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_DefineSpace] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_Read] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_Write] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_UndefineSpace] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_ChangeAuth] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_Increment] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_Extend] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_SetBits] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_WriteLock] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_NV_GlobalWriteLock] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
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
            [TpmCcConstants.TPM_CC_LoadExternal] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_ObjectChangeAuth] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Unseal] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_RSA_Encrypt] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_RSA_Decrypt] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_Certify] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_CertifyCreation] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_GetTime] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_GetSessionAuditDigest] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_ReadClock] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_ClockRateAdjust] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
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

            //TPM 2.0 Library Part 3, clause 24.9, Table 207 additionally lists both commands Permitted in Read-Only mode —
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
            [TpmCcConstants.TPM_CC_FlushContext] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_ContextSave] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet(),
            [TpmCcConstants.TPM_CC_ContextLoad] = new[] { TpmLifecyclePhase.Operational }.ToFrozenSet()
        }.ToFrozenDictionary();

    /// <summary>
    /// Evaluates whether a command may proceed in the given phase.
    /// </summary>
    /// <param name="commandCode">The command code to evaluate.</param>
    /// <param name="phase">The current lifecycle phase.</param>
    /// <param name="isSessionTagged">
    /// <see langword="true"/> when the command's frame carries the <c>TPM_ST_SESSIONS</c> tag (an
    /// authorization area was present in the wire request). In <see cref="TpmLifecyclePhase.FailureMode"/>
    /// this alone answers <c>TPM_RC_FAILURE</c> ahead of the command-code table, because Part 3 clause 5.3
    /// step 1 requires the command tag to be <c>TPM_ST_NO_SESSIONS</c> in Failure mode: "In Failure mode, the
    /// TPM has no cryptographic capability and processing of sessions is not supported" (TPM 2.0 Library Part
    /// 3, clause 5.3).
    /// </param>
    /// <returns>
    /// <see langword="null"/> if the command may proceed; otherwise the response code the TPM returns
    /// for that command in that phase.
    /// </returns>
    public static TpmRcConstants? Evaluate(TpmCcConstants commandCode, TpmLifecyclePhase phase, bool isSessionTagged)
    {
        //Part 3 clause 5.3 step 1 orders this check ahead of the command-code admission: "If the TPM is in
        //Failure mode, then the commandCode is TPM_CC_GetTestResult or TPM_CC_GetCapability (TPM_RC_FAILURE)
        //and the command tag is TPM_ST_NO_SESSIONS (TPM_RC_FAILURE)" (TPM 2.0 Library Part 3, clause 5.3), so a
        //session-tagged frame answers bare TPM_RC_FAILURE even for the two commands the table otherwise admits
        //into this phase — the same rule clause 10.4.1's TPM2_GetTestResult() General Description restates:
        //"If the TPM is in Failure mode, then tag is required to be TPM_ST_NO_SESSIONS or the TPM shall return
        //TPM_RC_FAILURE" (TPM 2.0 Library Part 3, clause 10.4.1).
        if(phase == TpmLifecyclePhase.FailureMode && isSessionTagged)
        {
            return TpmRcConstants.TPM_RC_FAILURE;
        }

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
