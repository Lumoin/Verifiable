using System;

namespace Verifiable.Tpm.Infrastructure.Spec.Attributes;

/// <summary>
/// TPMA_MODES bit definitions indicating TPM operational modes.
/// </summary>
/// <remarks>
/// <para>
/// Purpose: This attribute reports whether the TPM is designed for specific compliance modes.
/// </para>
/// <para>
/// Retrieval: Read using <c>TPM2_GetCapability</c> with
/// <c>capability == TPM_CAP_TPM_PROPERTIES</c> and <c>property == TPM_PT_MODES</c>.
/// </para>
/// <para>
/// Notes from the specification:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///     To determine certification status for a TPM with <c>FIPS_140_2</c> set, consult the NIST Module Validation List.
///     </description>
///   </item>
///   <item>
///     <description>
///     The <c>FIPS_140_3_INDICATOR</c> field (bits 3:2) was added in version 1.83.
///     </description>
///   </item>
///   <item>
///     <description>
///     <c>FIPS_140_3_INDICATOR</c> is only meaningful if <c>FIPS_140_3</c> is set, and it describes the FIPS 140-3
///     category of the service provided by the last command successfully executed before the capability query.
///     </description>
///   </item>
/// </list>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification
/// </see>
/// (Part 2: Structures, section "TPMA_MODES").
/// </para>
/// </remarks>
[Flags]
public enum TpmaModes : uint
{
    /// <summary>
    /// FIPS_140_2:
    /// SET (1) indicates that the TPM is designed to comply with all FIPS 140-2 requirements at Level 1 or higher.
    /// </summary>
    FIPS_140_2 = 0x0000_0001,

    /// <summary>
    /// FIPS_140_3:
    /// SET (1) indicates that the TPM is designed to comply with all FIPS 140-3 requirements at Level 1 or higher.
    /// </summary>
    /// <remarks>
    /// Note (spec): In the Reference Code, this bit is CLEAR.
    /// </remarks>
    FIPS_140_3 = 0x0000_0002,
}

/// <summary>
/// Helper definitions for multi-bit fields within <see cref="TpmaModes"/>.
/// </summary>
/// <remarks>
/// <para>
/// This type is NOT part of the TPM 2.0 specification.
/// </para>
/// <para>
/// It is provided as a language-binding convenience to interpret the packed bit-field
/// <c>FIPS_140_3_INDICATOR</c> (bits 3:2) defined by TPMA_MODES.
/// </para>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification
/// </see>
/// (Part 2: Structures, section "TPMA_MODES").
/// </para>
/// </remarks>
public static class TpmaModesFields
{
    /// <summary>
    /// FIPS_140_3_INDICATOR field mask (bits 3:2).
    /// </summary>
    public const uint FIPS_140_3_INDICATOR_MASK = 0x0000_000C;

    /// <summary>
    /// FIPS_140_3_INDICATOR field shift (bits 3:2).
    /// </summary>
    public const int FIPS_140_3_INDICATOR_SHIFT = 2;

    /// <summary>
    /// Extracts the <c>FIPS_140_3_INDICATOR</c> field value (0..3) from a TPMA_MODES value.
    /// </summary>
    public static uint GetFips140_3Indicator(TpmaModes modes)
    {
        return ((uint)modes & FIPS_140_3_INDICATOR_MASK) >> FIPS_140_3_INDICATOR_SHIFT;
    }

    /// <summary>
    /// Interprets the <c>FIPS_140_3_INDICATOR</c> field meaning as described by the specification.
    /// </summary>
    /// <remarks>
    /// Values:
    /// <list type="bullet">
    ///   <item><description><c>00</c>: service belongs to category 2, 3, or 5 (non-security-relevant services)</description></item>
    ///   <item><description><c>01</c>: service belongs to category 1 (approved security services)</description></item>
    ///   <item><description><c>10</c>: service belongs to category 4 (non-approved security services)</description></item>
    ///   <item><description><c>11</c>: reserved value</description></item>
    /// </list>
    /// Note (spec): In the Reference Code, these bits are set to (00) and have no meaning.
    /// </remarks>
    public static string DescribeFips140_3Indicator(uint indicator)
    {
        return indicator switch
        {
            0 => "Category 2, 3, or 5 (non-security-relevant services)",
            1 => "Category 1 (approved security services)",
            2 => "Category 4 (non-approved security services)",
            3 => "Reserved value",
            _ => "Invalid (out of range)",
        };
    }
}
