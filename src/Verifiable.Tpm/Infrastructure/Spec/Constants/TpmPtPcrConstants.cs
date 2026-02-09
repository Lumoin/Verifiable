using System;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Tpm.Structures.Spec.Constants;

/// <summary>
/// TPM_PT_PCR constants (Table 31).
/// </summary>
/// <remarks>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>
/// (Part 2: Structures, section "6 Constants", Table 31).
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1069:Enums values should not be duplicated", Justification = "TPM 2.0 specification allows duplicate values for compatibility and other reasons.")]
public enum TpmPtPcrConstants : uint
{
    /// <summary>
    /// bottom of the range of TPM_PT_PCR properties
    /// </summary>
    TPM_PT_PCR_FIRST = 0x00000000,

    /// <summary>
    /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR is saved and restored by TPM_SU_STATE
    /// </summary>
    TPM_PT_PCR_SAVE = 0x00000000,

    /// <summary>
    /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from locality 0 This property is only present if a locality other than 0 is implemented.
    /// </summary>
    TPM_PT_PCR_EXTEND_L0 = 0x00000001,

    /// <summary>
    /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 0
    /// </summary>
    TPM_PT_PCR_RESET_L0 = 0x00000002,

    /// <summary>
    /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from locality 1 This property is only present if locality 1 is implemented.
    /// </summary>
    TPM_PT_PCR_EXTEND_L1 = 0x00000003,

    /// <summary>
    /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 1 This property is only present if locality 1 is implemented.
    /// </summary>
    TPM_PT_PCR_RESET_L1 = 0x00000004,

    /// <summary>
    /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from locality 2 This property is only present if localities 1 and 2 are implemented.
    /// </summary>
    TPM_PT_PCR_EXTEND_L2 = 0x00000005,

    /// <summary>
    /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 2 This property is only present if localities 1 and 2 are implemented.
    /// </summary>
    TPM_PT_PCR_RESET_L2 = 0x00000006,

    /// <summary>
    /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from locality 3 This property is only present if localities 1, 2, and 3 are implemented.
    /// </summary>
    TPM_PT_PCR_EXTEND_L3 = 0x00000007,

    /// <summary>
    /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 3 This property is only present if localities 1, 2, and 3 are implemented.
    /// </summary>
    TPM_PT_PCR_RESET_L3 = 0x00000008,

    /// <summary>
    /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from locality 4 This property is only present if localities 1, 2, 3, and 4 are implemented. Capability Name Value Comments
    /// </summary>
    TPM_PT_PCR_EXTEND_L4 = 0x00000009,

    /// <summary>
    /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 4 This property is only present if localities 1, 2, 3, and 4 are implemented.
    /// </summary>
    TPM_PT_PCR_RESET_L4 = 0x0000000A,

    /// <summary>
    /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR is reset by a D-RTM event These PCR are reset to -1 on TPM2_Startup() and reset to 0 on a _TPM_Hash_End event following a _TPM_Hash_Start event.
    /// </summary>
    TPM_PT_PCR_DRTM_RESET = 0x00000012,

    /// <summary>
    /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR is controlled by policy This property is only present if the TPM supports policy control of a PCR.
    /// </summary>
    TPM_PT_PCR_POLICY = 0x00000013,

    /// <summary>
    /// a SET bit in the TPMS_PCR_SELECT indicates that the PCR is controlled by an authorization value This property is only present if the TPM supports authorization control of a PCR.
    /// </summary>
    TPM_PT_PCR_AUTH = 0x00000014,

    /// <summary>
    /// top of the range of TPM_PT_PCR properties of the implementation If the TPM receives a request for a PCR property with a value larger than this, the TPM will return a zero- length list and set the moreData parameter to NO. Note: This is an implementation-specific value. The value shown reflects the Reference Code implementation. .
    /// </summary>
    TPM_PT_PCR_LAST = 0x00000014
}