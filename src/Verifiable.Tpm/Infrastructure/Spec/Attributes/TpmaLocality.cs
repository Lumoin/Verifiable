using System;

namespace Verifiable.Tpm.Infrastructure.Spec.Attributes;

/// <summary>
/// TPMA_LOCALITY - locality attribute bits.
/// </summary>
/// <remarks>
/// <para>
/// Used in TPMS_CREATION_DATA to indicate the locality of the command that created the object, and in TPM2_PolicyLocality() to indicate
/// which localities are approved by a policy.
/// </para>
/// <para>
/// Specification: <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2: Structures, section 8.5 (TPMA_LOCALITY).
/// </para>
/// </remarks>
[Flags]
public enum TpmaLocality: byte
{
    /// <summary>TPM_LOC_ZERO (bit 0).</summary>
    TPM_LOC_ZERO = 0x01,

    /// <summary>TPM_LOC_ONE (bit 1).</summary>
    TPM_LOC_ONE = 0x02,

    /// <summary>TPM_LOC_TWO (bit 2).</summary>
    TPM_LOC_TWO = 0x04,

    /// <summary>TPM_LOC_THREE (bit 3).</summary>
    TPM_LOC_THREE = 0x08,

    /// <summary>TPM_LOC_FOUR (bit 4).</summary>
    TPM_LOC_FOUR = 0x10,

    /// <summary>
    /// EXTENDED (bits 7:5): if any of these bits is set, an extended locality is indicated.
    /// </summary>
    /// <remarks>
    /// This member is a convenience mask for bits 7:5 and is not a distinct named bit in the table.
    /// </remarks>
    EXTENDED_MASK = 0xE0
}
