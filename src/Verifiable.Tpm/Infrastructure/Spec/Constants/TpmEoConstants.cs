using System;

namespace Verifiable.Tpm.Structures.Spec.Constants;

/// <summary>
/// TPM_EO constants (Table 22).
/// </summary>
/// <remarks>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>
/// (Part 2: Structures, section "6 Constants", Table 22).
/// </para>
/// </remarks>
public enum TpmEoConstants : ushort
{
    /// <summary>
    /// = B
    /// </summary>
    TPM_EO_EQ = 0x0000,

    /// <summary>
    /// ≠ B
    /// </summary>
    TPM_EO_NEQ = 0x0001,

    /// <summary>
    /// &gt; B signed
    /// </summary>
    TPM_EO_SIGNED_GT = 0x0002,

    /// <summary>
    /// &gt; B unsigned
    /// </summary>
    TPM_EO_UNSIGNED_GT = 0x0003,

    /// <summary>
    /// &lt; B signed
    /// </summary>
    TPM_EO_SIGNED_LT = 0x0004,

    /// <summary>
    /// &lt; B unsigned Operation Name Value Comments
    /// </summary>
    TPM_EO_UNSIGNED_LT = 0x0005,

    /// <summary>
    /// ≥ B signed
    /// </summary>
    TPM_EO_SIGNED_GE = 0x0006,

    /// <summary>
    /// ≥ B unsigned
    /// </summary>
    TPM_EO_UNSIGNED_GE = 0x0007,

    /// <summary>
    /// ≤ B signed
    /// </summary>
    TPM_EO_SIGNED_LE = 0x0008,

    /// <summary>
    /// ≤ B unsigned
    /// </summary>
    TPM_EO_UNSIGNED_LE = 0x0009,

    /// <summary>
    /// all bits SET in B are SET in A ((A&amp;B)=B)
    /// </summary>
    TPM_EO_BITSET = 0x000A,

    /// <summary>
    /// all bits SET in B are CLEAR in A ((A&amp;B)=0) #TPM_RC_VALUE response code returned when unmarshaling of this type fails
    /// </summary>
    TPM_EO_BITCLEAR = 0x000B
}