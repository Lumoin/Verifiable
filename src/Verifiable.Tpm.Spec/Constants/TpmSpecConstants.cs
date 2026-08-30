namespace Verifiable.Tpm.Spec.Constants;

/// <summary>
/// TPM_SPEC constants (Table 6).
/// </summary>
/// <remarks>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>
/// (Part 2: Structures, Version 185, section "6 Constants", Table 6).
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
    public const uint TPM_SPEC_VERSION = 185;

    /// <summary>
    /// shall be zero
    /// </summary>
    public const uint TPM_SPEC_YEAR = 0;

    /// <summary>
    /// the errata version implemented by the TPM; the base publication implements none. Version 185 renamed
    /// this slot from TPM_SPEC_DAY_OF_YEAR and reports an errata version number here instead of a date.
    /// </summary>
    public const uint TPM_SPEC_ERRATA = 0;
}
