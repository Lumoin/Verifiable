using System;

namespace Verifiable.Tpm.Infrastructure.Spec.Attributes;

/// <summary>
/// TPMA_STARTUP_CLEAR - attributes that are cleared or set at startup/reset.
/// </summary>
/// <remarks>
/// <para>
/// Retrieval: <c>TPM2_GetCapability(capability == TPM_CAP_TPM_PROPERTIES, property == TPM_PT_STARTUP_CLEAR)</c>.
/// </para>
/// <para>
/// Specification: <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2: Structures, section 8.7 (TPMA_STARTUP_CLEAR).
/// </para>
/// </remarks>
[Flags]
public enum TpmaStartupClear: uint
{
    /// <summary>
    /// PH_ENABLE (bit 0): SET (1) indicates the platform hierarchy is enabled and platformAuth or platformPolicy may be used for authorization.
    /// CLEAR (0) indicates platformAuth and platformPolicy may not be used and objects in the platform hierarchy cannot be used.
    /// </summary>
    PH_ENABLE = 0x0000_0001,

    /// <summary>
    /// SH_ENABLE (bit 1): SET (1) indicates the Storage hierarchy is enabled and ownerAuth or ownerPolicy may be used for authorization; NV indices
    /// defined using owner authorization are accessible. CLEAR (0) indicates those authorizations and objects cannot be used.
    /// </summary>
    SH_ENABLE = 0x0000_0002,

    /// <summary>
    /// EH_ENABLE (bit 2): SET (1) indicates the EPS hierarchy is enabled and Endorsement Authorization may be used to authorize commands.
    /// CLEAR (0) indicates Endorsement Authorization may not be used and objects in the endorsement hierarchy cannot be used.
    /// </summary>
    EH_ENABLE = 0x0000_0004,

    /// <summary>
    /// PH_ENABLE_NV (bit 3): SET (1) indicates NV indices with TPMA_NV_PLATFORMCREATE set may be accessed; CLEAR (0) indicates they may not be accessed.
    /// </summary>
    PH_ENABLE_NV = 0x0000_0008,

    /// <summary>
    /// READ_ONLY (bit 4): SET (1) indicates all enabled hierarchies, including the NULL hierarchy, are read-only; CLEAR (0) indicates they can be modified.
    /// </summary>
    READ_ONLY = 0x0000_0010,

    /// <summary>
    /// ORDERLY (bit 31): SET (1) indicates the TPM received a TPM2_Shutdown() and a matching TPM2_Startup(); CLEAR (0) indicates Startup(CLEAR)
    /// was not preceded by a Shutdown of any type.
    /// </summary>
    ORDERLY = 0x8000_0000
}
