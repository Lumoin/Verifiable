namespace Verifiable.Tpm.Structures.Spec.Constants;

/// <summary>
/// TPM_ECC_CURVE constants (Table 12).
/// </summary>
/// <remarks>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>
/// (Part 2: Structures, section "6 Constants", Table 12).
/// </para>
/// </remarks>
public enum TpmEccCurveConstants: ushort
{
    /// <summary>
    /// (no comment text in extracted table)
    /// </summary>
    TPM_ECC_NONE = 0x0000,

    /// <summary>
    /// (no comment text in extracted table)
    /// </summary>
    TPM_ECC_NIST_P192 = 0x0001,

    /// <summary>
    /// (no comment text in extracted table)
    /// </summary>
    TPM_ECC_NIST_P224 = 0x0002,

    /// <summary>
    /// (no comment text in extracted table)
    /// </summary>
    TPM_ECC_NIST_P256 = 0x0003,

    /// <summary>
    /// (no comment text in extracted table)
    /// </summary>
    TPM_ECC_NIST_P384 = 0x0004,

    /// <summary>
    /// (no comment text in extracted table)
    /// </summary>
    TPM_ECC_NIST_P521 = 0x0005,

    /// <summary>
    /// curve to support ECDAA Name Value Comments
    /// </summary>
    TPM_ECC_BN_P256 = 0x0010,

    /// <summary>
    /// curve to support ECDAA
    /// </summary>
    TPM_ECC_BN_P638 = 0x0011,

    /// <summary>
    /// (no comment text in extracted table)
    /// </summary>
    TPM_ECC_SM2_P256 = 0x0020,

    /// <summary>
    /// Brainpool
    /// </summary>
    TPM_ECC_BP_P256_R1 = 0x0030,

    /// <summary>
    /// Brainpool
    /// </summary>
    TPM_ECC_BP_P384_R1 = 0x0031,

    /// <summary>
    /// Brainpool
    /// </summary>
    TPM_ECC_BP_P512_R1 = 0x0032,

    /// <summary>
    /// curve to support EdDSA
    /// </summary>
    TPM_ECC_CURVE_25519 = 0x0040,

    /// <summary>
    /// curve to support EdDSA
    /// </summary>
    TPM_ECC_CURVE_448 = 0x0041
}