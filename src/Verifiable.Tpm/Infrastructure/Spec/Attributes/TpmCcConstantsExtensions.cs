using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Attributes;

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
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2),

        //Section 16.1 - TPM2_GetRandom.
        //Handle area: none (0 handles).
        //Response: no handles.
        TpmCcConstants.TPM_CC_GetRandom
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 0),

        //Section 24.1 - TPM2_CreatePrimary.
        //Handle area: @primaryHandle (1 handle, requires auth).
        //Response: objectHandle (1 handle).
        TpmCcConstants.TPM_CC_CreatePrimary
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 12.1 - TPM2_Create.
        //Handle area: @parentHandle (1 handle, requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_Create
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 12.2 - TPM2_Load.
        //Handle area: @parentHandle (1 handle, requires auth).
        //Response: objectHandle (1 handle).
        TpmCcConstants.TPM_CC_Load
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

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
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

        //Section 31.13 - TPM2_NV_Read.
        //Handle area: @authHandle, nvIndex (2 handles; authHandle requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_NV_Read
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2),

        //Section 31.7 - TPM2_NV_Write.
        //Handle area: @authHandle, nvIndex (2 handles; authHandle requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_NV_Write
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2),

        //Section 31.4 - TPM2_NV_UndefineSpace.
        //Handle area: @authHandle, nvIndex (2 handles; authHandle requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_NV_UndefineSpace
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2),

        //Section 28.5 - TPM2_EvictControl.
        //Handle area: @auth, objectHandle (2 handles; auth requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_EvictControl
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 2),

        //Section 22.4 - TPM2_PCR_Read.
        //Handle area: none (0 handles).
        //Response: no handles.
        TpmCcConstants.TPM_CC_PCR_Read
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 0),


        //Section 20.2 - TPM2_Sign.
        //Handle area: @keyHandle (1 handle, requires auth).
        //Response: no handles.
        TpmCcConstants.TPM_CC_Sign
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

        //Section 31.16 - TPM2_NV_Certify.
        //Handle area: @signHandle (USER auth), @authHandle (USER auth), nvIndex (no auth) - 3 handles.
        //Response: no handles.
        TpmCcConstants.TPM_CC_NV_Certify
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 3),

        //Section 20.1 - TPM2_VerifySignature.
        //Handle area: keyHandle (1 handle, no auth required - a public-key operation).
        //Response: no handles.
        TpmCcConstants.TPM_CC_VerifySignature
            => TpmaCc.FromCommandCode((uint)commandCode, cHandles: 1),

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

        _ => throw new System.NotSupportedException($"TPMA_CC mapping missing for '{commandCode}'.")
    };
}
