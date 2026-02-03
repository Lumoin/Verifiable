using System;

namespace Verifiable.Tpm.Structures.Spec.Constants;

/// <summary>
/// TPM_SU constants (Table 24).
/// </summary>
/// <remarks>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>
/// (Part 2: Structures, section "6 Constants", Table 24).
/// </para>
/// </remarks>
public enum TpmSuConstants : ushort
{
    /// <summary>
    /// on TPM2_Shutdown(), indicates that the TPM should prepare for loss of power and save state required for an orderly startup (TPM Reset). on TPM2_Startup(), indicates that the TPM should perform TPM Reset or TPM Restart Name Value Description
    /// </summary>
    TPM_SU_CLEAR = 0x0000,

    /// <summary>
    /// on TPM2_Shutdown(), indicates that the TPM should prepare for loss of power and save state required for an orderly startup (TPM Restart or TPM Resume) on TPM2_Startup(), indicates that the TPM should restore the state saved by TPM2_Shutdown(TPM_SU_STATE) #TPM_RC_VALUE response code when incorrect value is used
    /// </summary>
    TPM_SU_STATE = 0x0001
}