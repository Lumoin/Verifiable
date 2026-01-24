using System;

namespace Verifiable.Tpm.Structures.Spec.Constants;

/// <summary>
/// TPM_CLOCK_ADJUST constants (Table 21).
/// </summary>
/// <remarks>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>
/// (Part 2: Structures, section "6 Constants", Table 21).
/// </para>
/// </remarks>
public enum TpmClockAdjustConstants : sbyte
{
    /// <summary>
    /// no change to the Clock update rate
    /// </summary>
    TPM_CLOCK_NO_CHANGE = 0,

    /// <summary>
    /// speed the Clock update rate by one fine adjustment step
    /// </summary>
    TPM_CLOCK_FINE_FASTER = 1,

    /// <summary>
    /// speed the Clock update rate by one medium adjustment step
    /// </summary>
    TPM_CLOCK_MEDIUM_FASTER = 2,

    /// <summary>
    /// speed the Clock update rate by one coarse adjustment step #TPM_RC_VALUE
    /// </summary>
    TPM_CLOCK_COARSE_FASTER = 3
}