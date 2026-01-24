using System;

namespace Verifiable.Tpm.Structures;

/// <summary>
/// TPMA_MODES bit definitions indicating TPM operational modes.
/// </summary>
/// <remarks>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 2: Structures, Section 8.9 - TPMA_MODES.
/// </para>
/// <para>
/// Retrieved via TPM2_GetCapability with property <see cref="Tpm2PtConstants.TPM2_PT_MODES"/>.
/// </para>
/// </remarks>
[Flags]
public enum TpmaModes: uint
{
    /// <summary>
    /// No mode flags set.
    /// </summary>
    None = 0,

    /// <summary>
    /// TPMA_MODES_FIPS_140_2: The TPM is designed to comply with FIPS 140-2 requirements.
    /// </summary>
    TPMA_MODES_FIPS_140_2 = 0x00000001
}