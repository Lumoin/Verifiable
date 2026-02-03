namespace Verifiable.Tpm.Structures.Spec.Constants;

/// <summary>
/// TPM_SPEC constants (Table 8).
/// </summary>
/// <remarks>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>
/// (Part 2: Structures, section "6 Constants", Table 8).
/// </para>
/// </remarks>
public static class TpmSpecConstants
{
    /// <summary>
    /// “2.0” with null terminator
    /// </summary>
    public const uint TPM_SPEC_FAMILY = 0x322E3000;

    /// <summary>
    /// the level number for the specification
    /// </summary>
    public const uint TPM_SPEC_LEVEL = 00;

    /// <summary>
    /// the version number of the specification
    /// </summary>
    public const uint TPM_SPEC_VERSION = 184;

    /// <summary>
    /// the year of the version
    /// </summary>
    public const uint TPM_SPEC_YEAR = 2025;

    /// <summary>
    /// the day of the year (March 20)
    /// </summary>
    public const uint TPM_SPEC_DAY_OF_YEAR = 79;
}