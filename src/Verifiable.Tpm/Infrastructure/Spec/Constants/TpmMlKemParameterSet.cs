namespace Verifiable.Tpm.Infrastructure.Spec.Constants;

/// <summary>
/// ML-KEM parameter set identifiers (TPMI_MLKEM_PARAMETER_SET).
/// </summary>
/// <remarks>
/// <para>
/// ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) defines three
/// security levels per NIST FIPS 203.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 6.3.21 (v1.85).
/// </para>
/// </remarks>
public enum TpmMlKemParameterSet: ushort
{
    /// <summary>
    /// TPM_MLKEM_512: ML-KEM-512 parameter set (security category 1).
    /// </summary>
    /// <remarks>
    /// Public key size: 800 bytes. Ciphertext size: 768 bytes. Shared secret: 32 bytes.
    /// </remarks>
    TPM_MLKEM_512 = 0x0001,

    /// <summary>
    /// TPM_MLKEM_768: ML-KEM-768 parameter set (security category 3).
    /// </summary>
    /// <remarks>
    /// Public key size: 1184 bytes. Ciphertext size: 1088 bytes. Shared secret: 32 bytes.
    /// </remarks>
    TPM_MLKEM_768 = 0x0002,

    /// <summary>
    /// TPM_MLKEM_1024: ML-KEM-1024 parameter set (security category 5).
    /// </summary>
    /// <remarks>
    /// Public key size: 1568 bytes. Ciphertext size: 1568 bytes. Shared secret: 32 bytes.
    /// </remarks>
    TPM_MLKEM_1024 = 0x0003
}