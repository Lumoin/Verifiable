namespace Verifiable.Tpm.Infrastructure.Spec.Constants;

/// <summary>
/// ML-DSA parameter set constants per NIST FIPS 204 and TPM 2.0 v1.85.
/// </summary>
/// <remarks>
/// <para>
/// ML-DSA (Module-Lattice-Based Digital Signature Algorithm) defines three
/// security levels with different key and signature sizes.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 12.2.3.7 (v1.85).
/// </para>
/// </remarks>
public static class TpmMlDsaParmsConstants
{
    /// <summary>
    /// ML-DSA-44 parameter set identifier (security category 2).
    /// </summary>
    public const ushort TPM_MLDSA_44 = 0x0001;

    /// <summary>
    /// ML-DSA-65 parameter set identifier (security category 3).
    /// </summary>
    public const ushort TPM_MLDSA_65 = 0x0002;

    /// <summary>
    /// ML-DSA-87 parameter set identifier (security category 5).
    /// </summary>
    public const ushort TPM_MLDSA_87 = 0x0003;

    /// <summary>
    /// ML-DSA-44 public key size in bytes.
    /// </summary>
    public const int MLDSA_44_PublicKeySize = 1312;

    /// <summary>
    /// ML-DSA-65 public key size in bytes.
    /// </summary>
    public const int MLDSA_65_PublicKeySize = 1952;

    /// <summary>
    /// ML-DSA-87 public key size in bytes.
    /// </summary>
    public const int MLDSA_87_PublicKeySize = 2592;

    /// <summary>
    /// ML-DSA-44 signature size in bytes.
    /// </summary>
    public const int MLDSA_44_SignatureSize = 2420;

    /// <summary>
    /// ML-DSA-65 signature size in bytes.
    /// </summary>
    public const int MLDSA_65_SignatureSize = 3293;

    /// <summary>
    /// ML-DSA-87 signature size in bytes.
    /// </summary>
    public const int MLDSA_87_SignatureSize = 4627;

    /// <summary>
    /// Maximum ML-DSA public key size (ML-DSA-87).
    /// </summary>
    public const int MaxPublicKeySize = MLDSA_87_PublicKeySize;

    /// <summary>
    /// Maximum ML-DSA signature size (ML-DSA-87).
    /// </summary>
    public const int MaxSignatureSize = MLDSA_87_SignatureSize;

    /// <summary>
    /// Gets the public key size for a given parameter set.
    /// </summary>
    /// <param name="parameterSet">The parameter set identifier.</param>
    /// <returns>The public key size in bytes.</returns>
    /// <exception cref="System.ArgumentException">Unknown parameter set.</exception>
    public static int GetPublicKeySize(ushort parameterSet) => parameterSet switch
    {
        TPM_MLDSA_44 => MLDSA_44_PublicKeySize,
        TPM_MLDSA_65 => MLDSA_65_PublicKeySize,
        TPM_MLDSA_87 => MLDSA_87_PublicKeySize,
        _ => throw new System.ArgumentException($"Unknown ML-DSA parameter set: 0x{parameterSet:X4}.", nameof(parameterSet))
    };

    /// <summary>
    /// Gets the signature size for a given parameter set.
    /// </summary>
    /// <param name="parameterSet">The parameter set identifier.</param>
    /// <returns>The signature size in bytes.</returns>
    /// <exception cref="System.ArgumentException">Unknown parameter set.</exception>
    public static int GetSignatureSize(ushort parameterSet) => parameterSet switch
    {
        TPM_MLDSA_44 => MLDSA_44_SignatureSize,
        TPM_MLDSA_65 => MLDSA_65_SignatureSize,
        TPM_MLDSA_87 => MLDSA_87_SignatureSize,
        _ => throw new System.ArgumentException($"Unknown ML-DSA parameter set: 0x{parameterSet:X4}.", nameof(parameterSet))
    };

    /// <summary>
    /// Gets the friendly name for a parameter set.
    /// </summary>
    /// <param name="parameterSet">The parameter set identifier.</param>
    /// <returns>The parameter set name.</returns>
    public static string GetName(ushort parameterSet) => parameterSet switch
    {
        TPM_MLDSA_44 => "ML-DSA-44",
        TPM_MLDSA_65 => "ML-DSA-65",
        TPM_MLDSA_87 => "ML-DSA-87",
        _ => $"Unknown(0x{parameterSet:X4})"
    };
}