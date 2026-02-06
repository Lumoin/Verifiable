using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Tpm.Infrastructure.Spec.Constants;

/// <summary>
/// ML-DSA parameter set identifiers (TPMI_MLDSA_PARAMETER_SET).
/// </summary>
/// <remarks>
/// <para>
/// ML-DSA (Module-Lattice-Based Digital Signature Algorithm) defines three
/// security levels per NIST FIPS 204.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 6.3.22 (v1.85).
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1008:Enums should have zero value", Justification = "This follows the TPM 2.0 specification.")]
public enum TpmMlDsaParameterSet: ushort
{
    /// <summary>
    /// TPM_MLDSA_44: ML-DSA-44 parameter set (security category 2).
    /// </summary>
    /// <remarks>
    /// Public key size: 1312 bytes. Signature size: 2420 bytes.
    /// </remarks>
    TPM_MLDSA_44 = 0x0001,

    /// <summary>
    /// TPM_MLDSA_65: ML-DSA-65 parameter set (security category 3).
    /// </summary>
    /// <remarks>
    /// Public key size: 1952 bytes. Signature size: 3293 bytes.
    /// </remarks>
    TPM_MLDSA_65 = 0x0002,

    /// <summary>
    /// TPM_MLDSA_87: ML-DSA-87 parameter set (security category 5).
    /// </summary>
    /// <remarks>
    /// Public key size: 2592 bytes. Signature size: 4627 bytes.
    /// </remarks>
    TPM_MLDSA_87 = 0x0003
}