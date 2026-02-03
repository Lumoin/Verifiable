using System;

namespace Verifiable.Tpm.Infrastructure.Spec.Attributes;

/// <summary>
/// TPMA_NV_EXP - expanded NV Index attributes (UINT64).
/// </summary>
/// <remarks>
/// <para>
/// Describes expanded attributes that apply to certain types of NV indices. The low 32 bits are as defined in TPMA_NV.
/// </para>
/// <para>
/// Added in version 1.83.
/// </para>
/// <para>
/// Specification: <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2: Structures, section 13.5 (TPMA_NV_EXP).
/// </para>
/// </remarks>
[Flags]
public enum TpmaNvExp: ulong
{
    /// <summary>
    /// TPMA_EXTERNAL_NV_ENCRYPTION (bit 32): SET (1) indicates external NV index contents are encrypted; CLEAR (0) indicates not encrypted.
    /// </summary>
    TPMA_EXTERNAL_NV_ENCRYPTION = 1ul << 32,

    /// <summary>
    /// TPMA_EXTERNAL_NV_INTEGRITY (bit 33): SET (1) indicates external NV index contents are integrity-protected; CLEAR (0) indicates not integrity-protected.
    /// </summary>
    TPMA_EXTERNAL_NV_INTEGRITY = 1ul << 33,

    /// <summary>
    /// TPMA_EXTERNAL_NV_ANTIROLLBACK (bit 34): SET (1) indicates external NV index contents are rollback-protected; CLEAR (0) indicates not rollback-protected.
    /// </summary>
    TPMA_EXTERNAL_NV_ANTIROLLBACK = 1ul << 34,
}
