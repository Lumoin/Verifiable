using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Attributes;

/// <summary>
/// Extension methods for <see cref="TpmCcConstants"/>.
/// </summary>
/// <remarks>
/// <para>
/// Provides command-specific metadata that cannot be derived from the command code alone.
/// The spec-defined TPMA_CC contains this information, but it must be retrieved via
/// TPM2_GetCapability(TPM_CAP_COMMANDS) at runtime. This extension provides a static
/// mapping for common commands.
/// </para>
/// <para>
/// <b>Why this exists:</b>
/// </para>
/// <para>
/// The executor uses <see cref="GetCommandAttributes"/> to determine the input handle
/// count (C_HANDLES) for a command, which is needed to correctly split the command
/// layout into: Header | Handles | AuthArea | Parameters.
/// </para>
/// <para>
/// Each row's attribute bits come from the command's own Part 3 header: the <c>{NV}</c>, <c>{E}</c>, and
/// <c>{F}</c> description modifiers (TPM 2.0 Library Part 3, clauses 4.2.6, 4.2.8, and 4.2.7) and whether the
/// response carries a handle area (Part 2, clause 8.9.3.6, <c>rHandle</c>). The executor reads only
/// <see cref="TpmaCc.C_HANDLES"/>; the other bits are what <c>TPM2_GetCapability(TPM_CAP_COMMANDS)</c> would
/// report for the command.
/// </para>
/// <para>
/// <b>Extensibility:</b>
/// </para>
/// <para>
/// Library users can define additional command mappings using the same pattern:
/// </para>
/// <code>
/// public static partial class TpmCcConstantsExtensions
/// {
///     public static TpmaCc GetCommandAttributes(this TpmCcConstants commandCode) => commandCode switch
///     {
///         TpmCcConstants.TPM_CC_MyVendorCommand => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2),
///         _ => DefaultGetCommandAttributes(commandCode)
///     };
/// }
/// </code>
/// </remarks>
public static partial class TpmCcConstantsExtensions
{
    /// <summary>
    /// Gets the TPMA_CC (command code attributes) for a command.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <returns>The command attributes.</returns>
    /// <exception cref="System.NotSupportedException">
    /// Thrown when the command code is not mapped. Add a mapping for the command.
    /// </exception>
    /// <remarks>
    /// <para>
    /// This method returns the spec-defined TPMA_CC for common commands. The most
    /// important field is <see cref="TpmaCc.C_HANDLES"/>, which tells the executor
    /// how many handles are in the command's handle area.
    /// </para>
    /// <para>
    /// <b>Note:</b> This is a partial mapping. Commands not listed here will throw.
    /// Extend this method for additional commands.
    /// </para>
    /// </remarks>
    public static TpmaCc GetCommandAttributes(this TpmCcConstants commandCode) => commandCode switch
    {
        //Section 11.1 - TPM2_StartAuthSession.
        //Handle area: tpmKey, bind (2 handles, neither requires auth).
        //Response: sessionHandle (1 handle).
        TpmCcConstants.TPM_CC_StartAuthSession
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2, hasResponseHandle: true),

        //Section 16.1 - TPM2_GetRandom.
        //Handle area: none (0 handles).
        //Response: no handles.
        TpmCcConstants.TPM_CC_GetRandom
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 0),

        //Section 24.1 - TPM2_CreatePrimary.
        //Handle area: @primaryHandle (1 handle, requires auth).
        //Response: objectHandle (1 handle).
        TpmCcConstants.TPM_CC_CreatePrimary
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1, hasResponseHandle: true),

        //Section 12.1 - TPM2_Create.
        //Handle area: @parentHandle (1 handle, requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_Create
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 12.2 - TPM2_Load.
        //Handle area: @parentHandle (1 handle, requires auth).
        //Response: objectHandle (1 handle).
        TpmCcConstants.TPM_CC_Load
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1, hasResponseHandle: true),

        //Section 28.4 - TPM2_FlushContext.
        //Handle area: none (0 handles).
        //Note: flushHandle is in the parameter area, not handle area.
        //Response: no handles.
        TpmCcConstants.TPM_CC_FlushContext
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 0),

        //Section 30.2 - TPM2_GetCapability.
        //Handle area: none (0 handles).
        //Response: no handles.
        TpmCcConstants.TPM_CC_GetCapability
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 0),

        //Section 31.3 - TPM2_NV_DefineSpace.
        //Handle area: @authHandle (1 handle, requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_NV_DefineSpace
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1, isNv: true),

        //Section 31.13 - TPM2_NV_Read.
        //Handle area: @authHandle, nvIndex (2 handles; authHandle requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_NV_Read
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2),

        //Section 31.7 - TPM2_NV_Write.
        //Handle area: @authHandle, nvIndex (2 handles; authHandle requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_NV_Write
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2, isNv: true),

        //Section 31.4 - TPM2_NV_UndefineSpace.
        //Handle area: @authHandle, nvIndex (2 handles; authHandle requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_NV_UndefineSpace
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2, isNv: true),

        //Section 31.8 - TPM2_NV_Increment.
        //Handle area: @authHandle, nvIndex (2 handles; authHandle requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_NV_Increment
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2, isNv: true),

        //Section 31.9 - TPM2_NV_Extend {NV}.
        //Handle area: @authHandle, nvIndex (2 handles; authHandle requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_NV_Extend
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2, isNv: true),

        //Section 31.10 - TPM2_NV_SetBits {NV}.
        //Handle area: @authHandle, nvIndex (2 handles; authHandle requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_NV_SetBits
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2, isNv: true),

        //Section 31.11 - TPM2_NV_WriteLock {NV}.
        //Handle area: @authHandle, nvIndex (2 handles; authHandle requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_NV_WriteLock
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2, isNv: true),

        //Section 31.14 - TPM2_NV_ReadLock {NV}.
        //Handle area: @authHandle, nvIndex (2 handles; authHandle requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_NV_ReadLock
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2, isNv: true),

        //Section 31.15 - TPM2_NV_ChangeAuth.
        //Handle area: @nvIndex (1 handle; Auth Index: 1, Auth Role: ADMIN - a policy session only, no
        //authValue fallback; unlike every other sessioned NV command there is no separate @authHandle).
        //Response: no handles.
        TpmCcConstants.TPM_CC_NV_ChangeAuth
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1, isNv: true),

        //Section 31.6 - TPM2_NV_ReadPublic.
        //Handle area: nvIndex (1 handle; Auth Index: None - no authorization is checked or accepted).
        //Response: no handles.
        TpmCcConstants.TPM_CC_NV_ReadPublic
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 28.5 - TPM2_EvictControl.
        //Handle area: @auth, objectHandle (2 handles; auth requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_EvictControl
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2, isNv: true),

        //Section 22.4 - TPM2_PCR_Read.
        //Handle area: none (0 handles).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PCR_Read
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 0),

        //Section 22.2 - TPM2_PCR_Extend {NV}.
        //Handle area: @pcrHandle (1 handle, requires USER auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PCR_Extend
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1, isNv: true),

        //Section 22.3 - TPM2_PCR_Event {NV}.
        //Handle area: @pcrHandle (1 handle, requires USER auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PCR_Event
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1, isNv: true),

        //Section 22.8 - TPM2_PCR_Reset {NV}.
        //Handle area: @pcrHandle (1 handle, requires USER auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PCR_Reset
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1, isNv: true),

        //Clause 17.9 - TPM2_EventSequenceComplete {NV F}.
        //Handle area: @pcrHandle (USER auth), @sequenceHandle (USER auth) - 2 handles, both require auth; the
        //sequence is flushed on success.
        //Response: no handles.
        TpmCcConstants.TPM_CC_EventSequenceComplete
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2, isNv: true, isFlushed: true),


        //Section 20.5 - TPM2_Sign.
        //Handle area: @keyHandle (1 handle, requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_Sign
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 20.7 - TPM2_SignDigest.
        //Handle area: @keyHandle (1 handle, requires USER auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_SignDigest
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 18.4 - TPM2_Quote.
        //Handle area: @signHandle (1 handle, requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_Quote
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 18.2 - TPM2_Certify.
        //Handle area: @objectHandle (ADMIN auth), @signHandle (USER auth) - 2 handles, both require auth.
        //Response: no handles.
        TpmCcConstants.TPM_CC_Certify
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2),

        //Section 18.3 - TPM2_CertifyCreation.
        //Handle area: @signHandle (USER auth), objectHandle (no auth) - 2 handles, only signHandle requires auth.
        //Response: no handles.
        TpmCcConstants.TPM_CC_CertifyCreation
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2),

        //Section 18.7 - TPM2_GetTime.
        //Handle area: @privacyAdminHandle (USER auth), @signHandle (USER auth) - 2 handles, both require auth.
        //Response: no handles.
        TpmCcConstants.TPM_CC_GetTime
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2),

        //Section 29.1 - TPM2_ReadClock.
        //Handle area: none (0 handles) - the only zero-handle attest-adjacent command in this simulator.
        //Response: no handles.
        TpmCcConstants.TPM_CC_ReadClock
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 0),

        //Section 29.2 - TPM2_ClockSet.
        //Handle area: @auth (1 handle, requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_ClockSet
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1, isNv: true),

        //Section 31.16 - TPM2_NV_Certify.
        //Handle area: @signHandle (USER auth), @authHandle (USER auth), nvIndex (no auth) - 3 handles.
        //Response: no handles.
        TpmCcConstants.TPM_CC_NV_Certify
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 3),

        //Section 20.2 - TPM2_VerifySignature.
        //Handle area: keyHandle (1 handle, no auth required - a public-key operation).
        //Response: no handles.
        TpmCcConstants.TPM_CC_VerifySignature
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 20.4 - TPM2_VerifyDigestSignature.
        //Handle area: keyHandle (1 handle, no auth required - a public-key operation).
        //Response: no handles.
        TpmCcConstants.TPM_CC_VerifyDigestSignature
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Clause 14.10 - TPM2_Encapsulate.
        //Handle area: keyHandle (1 handle, no auth required - reference to the public portion of a KEM key).
        //Response: no handles.
        TpmCcConstants.TPM_CC_Encapsulate
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Clause 14.11 - TPM2_Decapsulate.
        //Handle area: @keyHandle (1 handle, requires USER auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_Decapsulate
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Clause 17.5 - TPM2_SignSequenceStart.
        //Handle area: keyHandle (1 handle, no auth required - checked later at completion).
        //Response: sequenceHandle (1 handle).
        TpmCcConstants.TPM_CC_SignSequenceStart
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1, hasResponseHandle: true),

        //Clause 17.6 - TPM2_VerifySequenceStart.
        //Handle area: keyHandle (1 handle, no auth required - checked later at completion).
        //Response: sequenceHandle (1 handle).
        TpmCcConstants.TPM_CC_VerifySequenceStart
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1, hasResponseHandle: true),

        //Clause 17.7 - TPM2_SequenceUpdate.
        //Handle area: @sequenceHandle (1 handle, requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_SequenceUpdate
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Clause 15.4 - TPM2_Hash.
        //Handle area: none (Table 69).
        //Response: no handles.
        TpmCcConstants.TPM_CC_Hash
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 0),

        //Clause 17.4 - TPM2_HashSequenceStart.
        //Handle area: none (Table 85).
        //Response: sequenceHandle (1 handle).
        TpmCcConstants.TPM_CC_HashSequenceStart
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 0, hasResponseHandle: true),

        //Clause 17.2 - TPM2_HMAC_Start.
        //Handle area: @handle (1 handle, requires USER auth - the HMAC key).
        //Response: sequenceHandle (1 handle).
        TpmCcConstants.TPM_CC_HMAC_Start
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1, hasResponseHandle: true),

        //Clause 15.5 - TPM2_HMAC.
        //Handle area: @handle (1 handle, requires USER auth - the HMAC key).
        //Response: no handles.
        TpmCcConstants.TPM_CC_HMAC
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Clause 17.8 - TPM2_SequenceComplete {F}.
        //Handle area: @sequenceHandle (1 handle, requires auth); the sequence is flushed on success.
        //Response: no handles.
        TpmCcConstants.TPM_CC_SequenceComplete
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1, isFlushed: true),

        //Clause 20.3 - TPM2_VerifySequenceComplete.
        //Handle area: @sequenceHandle (requires auth), keyHandle (no auth) - 2 handles; {F} flushes the
        //sequence context on completion.
        //Response: no handles.
        TpmCcConstants.TPM_CC_VerifySequenceComplete
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2, isFlushed: true),

        //Clause 20.6 - TPM2_SignSequenceComplete.
        //Handle area: @sequenceHandle (requires auth), @keyHandle (requires auth) - 2 handles; {F} flushes
        //the sequence context on completion.
        //Response: no handles.
        TpmCcConstants.TPM_CC_SignSequenceComplete
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2, isFlushed: true),

        //Section 12.6 - TPM2_MakeCredential.
        //Handle area: handle (1 handle, no auth - uses only the public area).
        //Response: no handles.
        TpmCcConstants.TPM_CC_MakeCredential
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 12.5 - TPM2_ActivateCredential.
        //Handle area: @activateHandle (ADMIN auth), @keyHandle (USER auth) - 2 handles, both require auth.
        //Response: no handles.
        TpmCcConstants.TPM_CC_ActivateCredential
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2),

        //Section 13.1 - TPM2_Duplicate.
        //Handle area: @objectHandle (DUP-role auth), newParentHandle (no auth) - 2 handles, one requires auth.
        //Response: no handles.
        TpmCcConstants.TPM_CC_Duplicate
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2),

        //Section 13.3 - TPM2_Import.
        //Handle area: @parentHandle (USER auth) - 1 handle, requires auth.
        //Response: no handles.
        TpmCcConstants.TPM_CC_Import
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 12.7 - TPM2_Unseal.
        //Handle area: @itemHandle (1 handle, requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_Unseal
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 14.5 - TPM2_ECDH_ZGen.
        //Handle area: @keyHandle (1 handle, requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_ECDH_ZGen
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 12.4 - TPM2_ReadPublic.
        //Handle area: objectHandle (1 handle, no auth required).
        //Response: no handles.
        TpmCcConstants.TPM_CC_ReadPublic
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 23.18 - TPM2_PolicyAuthValue.
        //Handle area: policySession (1 handle, no auth required).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicyAuthValue
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 23.4 - TPM2_PolicyCommandCode.
        //Handle area: policySession (1 handle, no auth required).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicyCommandCode
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 23.7 - TPM2_PolicyPCR.
        //Handle area: policySession (1 handle, no auth required).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicyPCR
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 23.6 - TPM2_PolicyOR.
        //Handle area: policySession (1 handle, no auth required).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicyOR
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 23.9 - TPM2_PolicyNV.
        //Handle area: @authHandle (requires auth), nvIndex (no auth), policySession (no auth) - 3 handles.
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicyNV
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 3),

        //Section 23.6 - TPM2_PolicyGetDigest.
        //Handle area: policySession (1 handle, no auth required).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicyGetDigest
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 23.4 - TPM2_PolicySecret.
        //Handle area: @authHandle (requires auth), policySession (no auth) - 2 handles.
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicySecret
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2),

        //Section 23.3 - TPM2_PolicySigned.
        //Handle area: @authObject (validates the signature, no auth required), policySession (no auth) - 2 handles.
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicySigned
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2),

        //Section 23.5 - TPM2_PolicyTicket.
        //Handle area: policySession (1 handle, no auth required).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicyTicket
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 23.16 - TPM2_PolicyAuthorize.
        //Handle area: policySession (no auth required) - 1 handle.
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicyAuthorize
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 23.10 - TPM2_PolicyCounterTimer.
        //Handle area: policySession (1 handle, no auth required).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicyCounterTimer
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 11.2 - TPM2_PolicyRestart, Table 16.
        //Handle area: sessionHandle (1 handle, no auth required).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicyRestart
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 23.8 - TPM2_PolicyLocality, Table 154.
        //Handle area: policySession (1 handle, no auth required).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicyLocality
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 23.13 - TPM2_PolicyCpHash, Table 164.
        //Handle area: policySession (1 handle, no auth required).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicyCpHash
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 23.14 - TPM2_PolicyNameHash, Table 166.
        //Handle area: policySession (1 handle, no auth required).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicyNameHash
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 23.15 - TPM2_PolicyDuplicationSelect, Table 168.
        //Handle area: policySession (1 handle, no auth required).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicyDuplicationSelect
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 23.24 - TPM2_PolicyParameters, Table 187.
        //Handle area: policySession (1 handle, no auth required).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicyParameters
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 23.18 - TPM2_PolicyPassword, Table 174.
        //Handle area: policySession (1 handle, no auth required).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicyPassword
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 23.20 - TPM2_PolicyNvWritten, Table 178.
        //Handle area: policySession (1 handle, no auth required).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicyNvWritten
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 23.21 - TPM2_PolicyTemplate, Table 180.
        //Handle area: policySession (1 handle, no auth required).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicyTemplate
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 23.22 - TPM2_PolicyAuthorizeNV, Table 182.
        //Handle area: @authHandle (requires USER auth), nvIndex (no auth), policySession (no auth) - 3 handles.
        //Response: no handles.
        TpmCcConstants.TPM_CC_PolicyAuthorizeNV
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 3),

        //Section 25.2 - TPM2_DictionaryAttackLockReset.
        //Handle area: lockHandle (1 handle, requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_DictionaryAttackLockReset
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1, isNv: true),

        //Section 25.3 - TPM2_DictionaryAttackParameters.
        //Handle area: lockHandle (1 handle, requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_DictionaryAttackParameters
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1, isNv: true),

        //Section 24.8 - TPM2_HierarchyChangeAuth.
        //Handle area: @authHandle (1 handle, requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_HierarchyChangeAuth
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1, isNv: true),

        //Section 24.6 - TPM2_Clear.
        //Handle area: @authHandle (1 handle, requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_Clear
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1, isNv: true, isExtensive: true),

        //Section 24.7 - TPM2_ClearControl.
        //Handle area: @auth (1 handle, requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_ClearControl
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1, isNv: true),

        //Section 24.2 - TPM2_HierarchyControl.
        //Handle area: @authHandle (1 handle, requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_HierarchyControl
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1, isNv: true, isExtensive: true),

        //Section 24.3 - TPM2_SetPrimaryPolicy.
        //Handle area: @authHandle (1 handle, requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_SetPrimaryPolicy
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1, isNv: true),

        _ => throw new System.NotSupportedException($"TPMA_CC mapping missing for '{commandCode}'.")
    };
}
