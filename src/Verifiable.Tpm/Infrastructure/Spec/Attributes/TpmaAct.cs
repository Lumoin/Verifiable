using System;

namespace Verifiable.Tpm.Infrastructure.Spec.Attributes;

/// <summary>
/// TPMA_ACT - Authenticated Countdown Timer (ACT) state.
/// </summary>
/// <remarks>
/// <para>
/// Reports the ACT state. Once SET, SIGNALED will remain SET until cleared by TPM2_ACT_SetTimeout(), TPM Reset, or TPM Restart.
/// SIGNALED is preserved across TPM Resume and copied into PRESERVED_SIGNALED.
/// </para>
/// <para>
/// Retrieval: <c>TPM2_GetCapability(capability == TPM_CAP_ACT, property == TPM_RH_ACT_x)</c>, where x is ACT number (0-F).
/// </para>
/// <para>
/// Specification: <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2: Structures, section 8.12 (TPMA_ACT).
/// </para>
/// </remarks>
[Flags]
public enum TpmaAct: uint
{
    /// <summary>
    /// SIGNALED (bit 0): SET (1) indicates the ACT has signaled; CLEAR (0) indicates it has not signaled.
    /// </summary>
    SIGNALED = 0x0000_0001,

    /// <summary>
    /// PRESERVED_SIGNALED (bit 1): preserves the state of SIGNALED depending on the power cycle; on TPM Resume, SIGNALED is copied to this field.
    /// </summary>
    PRESERVED_SIGNALED = 0x0000_0002
}
