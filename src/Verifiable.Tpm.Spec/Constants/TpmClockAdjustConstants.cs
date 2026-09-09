using System;

namespace Verifiable.Tpm.Spec.Constants;

/// <summary>
/// TPM_CLOCK_ADJUST constants (Table 19).
/// </summary>
/// <remarks>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>
/// (Part 2: Structures, clause 6.7, Table 19).
/// </para>
/// </remarks>
public enum TpmClockAdjustConstants : sbyte
{
    /// <summary>
    /// slow the Clock update rate by one coarse adjustment step
    /// </summary>
    TPM_CLOCK_COARSE_SLOWER = -3,

    /// <summary>
    /// slow the Clock update rate by one medium adjustment step
    /// </summary>
    TPM_CLOCK_MEDIUM_SLOWER = -2,

    /// <summary>
    /// slow the Clock update rate by one fine adjustment step
    /// </summary>
    TPM_CLOCK_FINE_SLOWER = -1,

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
    /// speed the Clock update rate by one coarse adjustment step
    /// </summary>
    TPM_CLOCK_COARSE_FASTER = 3
}
