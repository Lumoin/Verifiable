using System;

namespace Verifiable.Tpm.Infrastructure.Spec.Attributes;

/// <summary>
/// TPMA_MEMORY - memory management attribute bits.
/// </summary>
/// <remarks>
/// <para>
/// Reports the memory management method used by the TPM for transient objects and authorization sessions.
/// </para>
/// <para>
/// Retrieval: <c>TPM2_GetCapability(capability == TPM_CAP_TPM_PROPERTIES, property == TPM_PT_MEMORY)</c>.
/// </para>
/// <para>
/// Specification: <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2: Structures, section 8.8 (TPMA_MEMORY).
/// </para>
/// </remarks>
[Flags]
public enum TpmaMemory: uint
{
    /// <summary>
    /// SHARED_RAM (bit 0): SET (1) indicates RAM used for authorization session contexts is shared with transient objects; CLEAR (0) indicates not shared.
    /// </summary>
    SHARED_RAM = 0x0000_0001,

    /// <summary>
    /// SHARED_NV (bit 1): SET (1) indicates NV used for persistent objects is shared with NV used for NV Index values; CLEAR (0) indicates separate NV areas.
    /// </summary>
    SHARED_NV = 0x0000_0002,

    /// <summary>
    /// OBJECT_COPIED_TO_RAM (bit 2): SET (1) indicates the TPM copies persistent objects to a transient-object slot in RAM when referenced; CLEAR (0) indicates
    /// it does not use transient-object slots when persistent objects are referenced.
    /// </summary>
    OBJECT_COPIED_TO_RAM = 0x0000_0004
}
