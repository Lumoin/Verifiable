using System;

namespace Verifiable.Tpm.Infrastructure.Spec.Attributes;

/// <summary>
/// TPMA_PERMANENT - persistent TPM state attribute bits.
/// </summary>
/// <remarks>
/// <para>
/// Persistent attributes are not changed as a result of _TPM_Init or any TPM2_Startup(). Some attributes may change as a result of specific
/// ProtectedCapabilities.
/// </para>
/// <para>
/// Retrieval: <c>TPM2_GetCapability(capability == TPM_CAP_TPM_PROPERTIES, property == TPM_PT_PERMANENT)</c>.
/// </para>
/// <para>
/// Specification: <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2: Structures, section 8.6 (TPMA_PERMANENT).
/// </para>
/// </remarks>
[Flags]
public enum TpmaPermanent: uint
{
    /// <summary>
    /// OWNER_AUTH_SET (bit 0): SET (1) indicates TPM2_HierarchyChangeAuth() with ownerAuth has been executed since the last TPM2_Clear().
    /// CLEAR (0) indicates ownerAuth has not been changed since TPM2_Clear().
    /// </summary>
    OWNER_AUTH_SET = 0x0000_0001,

    /// <summary>
    /// ENDORSEMENT_AUTH_SET (bit 1): SET (1) indicates TPM2_HierarchyChangeAuth() with endorsementAuth has been executed since the last TPM2_Clear().
    /// CLEAR (0) indicates endorsementAuth has not been changed since TPM2_Clear().
    /// </summary>
    ENDORSEMENT_AUTH_SET = 0x0000_0002,

    /// <summary>
    /// LOCKOUT_AUTH_SET (bit 2): SET (1) indicates TPM2_HierarchyChangeAuth() with lockoutAuth has been executed since the last TPM2_Clear().
    /// CLEAR (0) indicates lockoutAuth has not been changed since TPM2_Clear().
    /// </summary>
    LOCKOUT_AUTH_SET = 0x0000_0004,

    /// <summary>
    /// DISABLE_CLEAR (bit 8): SET (1) indicates TPM2_Clear() is disabled; CLEAR (0) indicates TPM2_Clear() is enabled.
    /// </summary>
    DISABLE_CLEAR = 0x0000_0100,

    /// <summary>
    /// IN_LOCKOUT (bit 9): SET (1) indicates the TPM is in lockout when failedTries is equal to maxTries.
    /// </summary>
    IN_LOCKOUT = 0x0000_0200,

    /// <summary>
    /// TPM_GENERATED_EPS (bit 10): SET (1) indicates the EPS was created by the TPM; CLEAR (0) indicates the EPS was created outside of the TPM
    /// using a manufacturer-specific process.
    /// </summary>
    TPM_GENERATED_EPS = 0x0000_0400
}
