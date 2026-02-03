namespace Verifiable.Tpm.Infrastructure.Spec.Constants;

/// <summary>
/// ML-KEM parameter set constants per NIST FIPS 203 and TPM 2.0 v1.85.
/// </summary>
/// <remarks>
/// <para>
/// ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) defines three
/// security levels with different key, ciphertext, and shared secret sizes.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 12.2.3.6 (v1.85).
/// </para>
/// </remarks>
public static class TpmMlKemParmsConstants
{
    /// <summary>
    /// ML-KEM-512 parameter set identifier (security category 1).
    /// </summary>
    public const ushort MLKEM_512 = 0x0001;

    /// <summary>
    /// ML-KEM-768 parameter set identifier (security category 3).
    /// </summary>
    public const ushort MLKEM_768 = 0x0002;

    /// <summary>
    /// ML-KEM-1024 parameter set identifier (security category 5).
    /// </summary>
    public const ushort MLKEM_1024 = 0x0003;

    /// <summary>
    /// ML-KEM-512 public key size in bytes.
    /// </summary>
    public const int MLKEM_512_PublicKeySize = 800;

    /// <summary>
    /// ML-KEM-768 public key size in bytes.
    /// </summary>
    public const int MLKEM_768_PublicKeySize = 1184;

    /// <summary>
    /// ML-KEM-1024 public key size in bytes.
    /// </summary>
    public const int MLKEM_1024_PublicKeySize = 1568;

    /// <summary>
    /// ML-KEM-512 ciphertext size in bytes.
    /// </summary>
    public const int MLKEM_512_CiphertextSize = 768;

    /// <summary>
    /// ML-KEM-768 ciphertext size in bytes.
    /// </summary>
    public const int MLKEM_768_CiphertextSize = 1088;

    /// <summary>
    /// ML-KEM-1024 ciphertext size in bytes.
    /// </summary>
    public const int MLKEM_1024_CiphertextSize = 1568;

    /// <summary>
    /// Shared secret size in bytes (same for all parameter sets).
    /// </summary>
    public const int SharedSecretSize = 32;

    /// <summary>
    /// Maximum ML-KEM public key size (ML-KEM-1024).
    /// </summary>
    public const int MaxPublicKeySize = MLKEM_1024_PublicKeySize;

    /// <summary>
    /// Maximum ML-KEM ciphertext size (ML-KEM-1024).
    /// </summary>
    public const int MaxCiphertextSize = MLKEM_1024_CiphertextSize;

    /// <summary>
    /// Gets the public key size for a given parameter set.
    /// </summary>
    /// <param name="parameterSet">The parameter set identifier.</param>
    /// <returns>The public key size in bytes.</returns>
    /// <exception cref="System.ArgumentException">Unknown parameter set.</exception>
    public static int GetPublicKeySize(ushort parameterSet) => parameterSet switch
    {
        MLKEM_512 => MLKEM_512_PublicKeySize,
        MLKEM_768 => MLKEM_768_PublicKeySize,
        MLKEM_1024 => MLKEM_1024_PublicKeySize,
        _ => throw new System.ArgumentException($"Unknown ML-KEM parameter set: 0x{parameterSet:X4}.", nameof(parameterSet))
    };

    /// <summary>
    /// Gets the ciphertext size for a given parameter set.
    /// </summary>
    /// <param name="parameterSet">The parameter set identifier.</param>
    /// <returns>The ciphertext size in bytes.</returns>
    /// <exception cref="System.ArgumentException">Unknown parameter set.</exception>
    public static int GetCiphertextSize(ushort parameterSet) => parameterSet switch
    {
        MLKEM_512 => MLKEM_512_CiphertextSize,
        MLKEM_768 => MLKEM_768_CiphertextSize,
        MLKEM_1024 => MLKEM_1024_CiphertextSize,
        _ => throw new System.ArgumentException($"Unknown ML-KEM parameter set: 0x{parameterSet:X4}.", nameof(parameterSet))
    };

    /// <summary>
    /// Gets the friendly name for a parameter set.
    /// </summary>
    /// <param name="parameterSet">The parameter set identifier.</param>
    /// <returns>The parameter set name.</returns>
    public static string GetName(ushort parameterSet) => parameterSet switch
    {
        MLKEM_512 => "ML-KEM-512",
        MLKEM_768 => "ML-KEM-768",
        MLKEM_1024 => "ML-KEM-1024",
        _ => $"Unknown(0x{parameterSet:X4})"
    };
}