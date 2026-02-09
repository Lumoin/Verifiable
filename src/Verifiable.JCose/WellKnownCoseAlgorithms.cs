using Verifiable.Cryptography;
using Verifiable.Jose;

namespace Verifiable.JCose;

/// <summary>
/// COSE algorithm identifiers as defined in
/// <see href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms</see>.
/// </summary>
/// <remarks>
/// <para>
/// COSE uses integer identifiers for algorithms, unlike JOSE which uses strings.
/// Negative values are used to avoid collisions with content type values.
/// </para>
/// <para>
/// See <see href="https://www.rfc-editor.org/rfc/rfc9053">RFC 9053 - COSE Algorithms</see>.
/// </para>
/// </remarks>
public static class WellKnownCoseAlgorithms
{
    /// <summary>
    /// EdDSA signature algorithm.
    /// </summary>
    /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9053#section-2.2">RFC 9053 §2.2</see>.</remarks>
    public const int EdDsa = -8;

    /// <summary>
    /// ECDSA with SHA-256 (P-256 curve).
    /// </summary>
    /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9053#section-2.1">RFC 9053 §2.1</see>.</remarks>
    public const int Es256 = -7;

    /// <summary>
    /// ECDSA with SHA-384 (P-384 curve).
    /// </summary>
    /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9053#section-2.1">RFC 9053 §2.1</see>.</remarks>
    public const int Es384 = -35;

    /// <summary>
    /// ECDSA with SHA-512 (P-521 curve).
    /// </summary>
    /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9053#section-2.1">RFC 9053 §2.1</see>.</remarks>
    public const int Es512 = -36;

    /// <summary>
    /// RSASSA-PSS with SHA-256.
    /// </summary>
    /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc8230#section-2">RFC 8230 §2</see>.</remarks>
    public const int Ps256 = -37;

    /// <summary>
    /// RSASSA-PSS with SHA-384.
    /// </summary>
    /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc8230#section-2">RFC 8230 §2</see>.</remarks>
    public const int Ps384 = -38;

    /// <summary>
    /// RSASSA-PSS with SHA-512.
    /// </summary>
    /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc8230#section-2">RFC 8230 §2</see>.</remarks>
    public const int Ps512 = -39;

    /// <summary>
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    /// </summary>
    /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc8812#section-2">RFC 8812 §2</see>.</remarks>
    public const int Rs256 = -257;

    /// <summary>
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    /// </summary>
    /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc8812#section-2">RFC 8812 §2</see>.</remarks>
    public const int Rs384 = -258;

    /// <summary>
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    /// </summary>
    /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc8812#section-2">RFC 8812 §2</see>.</remarks>
    public const int Rs512 = -259;

    /// <summary>
    /// HMAC with SHA-256.
    /// </summary>
    /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9053#section-3.1">RFC 9053 §3.1</see>.</remarks>
    public const int Hs256 = 5;

    /// <summary>
    /// HMAC with SHA-384.
    /// </summary>
    /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9053#section-3.1">RFC 9053 §3.1</see>.</remarks>
    public const int Hs384 = 6;

    /// <summary>
    /// HMAC with SHA-512.
    /// </summary>
    /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9053#section-3.1">RFC 9053 §3.1</see>.</remarks>
    public const int Hs512 = 7;

    /// <summary>
    /// AES-GCM with 128-bit key.
    /// </summary>
    /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9053#section-4.1">RFC 9053 §4.1</see>.</remarks>
    public const int A128Gcm = 1;

    /// <summary>
    /// AES-GCM with 192-bit key.
    /// </summary>
    /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9053#section-4.1">RFC 9053 §4.1</see>.</remarks>
    public const int A192Gcm = 2;

    /// <summary>
    /// AES-GCM with 256-bit key.
    /// </summary>
    /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9053#section-4.1">RFC 9053 §4.1</see>.</remarks>
    public const int A256Gcm = 3;

    /// <summary>
    /// SHA-256 hash algorithm.
    /// </summary>
    /// <remarks>Used in sd_alg header for SD-CWT.</remarks>
    public const int Sha256 = -16;

    /// <summary>
    /// SHA-384 hash algorithm.
    /// </summary>
    /// <remarks>Used in sd_alg header for SD-CWT.</remarks>
    public const int Sha384 = -43;

    /// <summary>
    /// SHA-512 hash algorithm.
    /// </summary>
    /// <remarks>Used in sd_alg header for SD-CWT.</remarks>
    public const int Sha512 = -44;

    /// <summary>
    /// Direct use of CEK (no key wrapping).
    /// </summary>
    /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9053#section-6.1">RFC 9053 §6.1</see>.</remarks>
    public const int Direct = -6;

    /// <summary>
    /// ECDH-ES + HKDF-256.
    /// </summary>
    /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9053#section-6.3">RFC 9053 §6.3</see>.</remarks>
    public const int EcdhEsHkdf256 = -25;

    /// <summary>
    /// ECDH-ES + HKDF-512.
    /// </summary>
    /// <remarks>See <see href="https://www.rfc-editor.org/rfc/rfc9053#section-6.3">RFC 9053 §6.3</see>.</remarks>
    public const int EcdhEsHkdf512 = -26;

    /// <summary>
    /// ML-DSA-44 post-quantum digital signature (NIST FIPS 204, security level 2).
    /// </summary>
    /// <remarks>
    /// See <see href="https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/">draft-ietf-cose-dilithium</see>.
    /// Requested IANA assignment: -48.
    /// </remarks>
    public const int MlDsa44 = -48;

    /// <summary>
    /// ML-DSA-65 post-quantum digital signature (NIST FIPS 204, security level 3).
    /// </summary>
    /// <remarks>
    /// See <see href="https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/">draft-ietf-cose-dilithium</see>.
    /// Requested IANA assignment: -49.
    /// </remarks>
    public const int MlDsa65 = -49;

    /// <summary>
    /// ML-DSA-87 post-quantum digital signature (NIST FIPS 204, security level 5).
    /// </summary>
    /// <remarks>
    /// See <see href="https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/">draft-ietf-cose-dilithium</see>.
    /// Requested IANA assignment: -50.
    /// </remarks>
    public const int MlDsa87 = -50;


    /// <summary>
    /// Determines if the algorithm is <see cref="EdDsa"/>.
    /// </summary>
    /// <param name="algorithm">The algorithm identifier.</param>
    /// <returns><see langword="true"/> if the algorithm is EdDSA; otherwise, <see langword="false"/>.</returns>
    public static bool IsEdDsa(int algorithm) => algorithm == EdDsa;


    /// <summary>
    /// Determines if the algorithm is <see cref="Es256"/>.
    /// </summary>
    /// <param name="algorithm">The algorithm identifier.</param>
    /// <returns><see langword="true"/> if the algorithm is ES256; otherwise, <see langword="false"/>.</returns>
    public static bool IsEs256(int algorithm) => algorithm == Es256;


    /// <summary>
    /// Determines if the algorithm is <see cref="Es384"/>.
    /// </summary>
    /// <param name="algorithm">The algorithm identifier.</param>
    /// <returns><see langword="true"/> if the algorithm is ES384; otherwise, <see langword="false"/>.</returns>
    public static bool IsEs384(int algorithm) => algorithm == Es384;


    /// <summary>
    /// Determines if the algorithm is <see cref="Es512"/>.
    /// </summary>
    /// <param name="algorithm">The algorithm identifier.</param>
    /// <returns><see langword="true"/> if the algorithm is ES512; otherwise, <see langword="false"/>.</returns>
    public static bool IsEs512(int algorithm) => algorithm == Es512;


    /// <summary>
    /// Determines if the algorithm is <see cref="Ps256"/>.
    /// </summary>
    /// <param name="algorithm">The algorithm identifier.</param>
    /// <returns><see langword="true"/> if the algorithm is PS256; otherwise, <see langword="false"/>.</returns>
    public static bool IsPs256(int algorithm) => algorithm == Ps256;


    /// <summary>
    /// Determines if the algorithm is <see cref="Ps384"/>.
    /// </summary>
    /// <param name="algorithm">The algorithm identifier.</param>
    /// <returns><see langword="true"/> if the algorithm is PS384; otherwise, <see langword="false"/>.</returns>
    public static bool IsPs384(int algorithm) => algorithm == Ps384;


    /// <summary>
    /// Determines if the algorithm is <see cref="Ps512"/>.
    /// </summary>
    /// <param name="algorithm">The algorithm identifier.</param>
    /// <returns><see langword="true"/> if the algorithm is PS512; otherwise, <see langword="false"/>.</returns>
    public static bool IsPs512(int algorithm) => algorithm == Ps512;


    /// <summary>
    /// Determines if the algorithm is <see cref="Sha256"/>.
    /// </summary>
    /// <param name="algorithm">The algorithm identifier.</param>
    /// <returns><see langword="true"/> if the algorithm is SHA-256; otherwise, <see langword="false"/>.</returns>
    public static bool IsSha256(int algorithm) => algorithm == Sha256;


    /// <summary>
    /// Determines if the algorithm is <see cref="Sha384"/>.
    /// </summary>
    /// <param name="algorithm">The algorithm identifier.</param>
    /// <returns><see langword="true"/> if the algorithm is SHA-384; otherwise, <see langword="false"/>.</returns>
    public static bool IsSha384(int algorithm) => algorithm == Sha384;


    /// <summary>
    /// Determines if the algorithm is <see cref="Sha512"/>.
    /// </summary>
    /// <param name="algorithm">The algorithm identifier.</param>
    /// <returns><see langword="true"/> if the algorithm is SHA-512; otherwise, <see langword="false"/>.</returns>
    public static bool IsSha512(int algorithm) => algorithm == Sha512;


    /// <summary>
    /// Determines if the algorithm is <see cref="MlDsa44"/>.
    /// </summary>
    /// <param name="algorithm">The algorithm identifier.</param>
    /// <returns><see langword="true"/> if the algorithm is ML-DSA-44; otherwise, <see langword="false"/>.</returns>
    public static bool IsMlDsa44(int algorithm) => algorithm == MlDsa44;


    /// <summary>
    /// Determines if the algorithm is <see cref="MlDsa65"/>.
    /// </summary>
    /// <param name="algorithm">The algorithm identifier.</param>
    /// <returns><see langword="true"/> if the algorithm is ML-DSA-65; otherwise, <see langword="false"/>.</returns>
    public static bool IsMlDsa65(int algorithm) => algorithm == MlDsa65;


    /// <summary>
    /// Determines if the algorithm is <see cref="MlDsa87"/>.
    /// </summary>
    /// <param name="algorithm">The algorithm identifier.</param>
    /// <returns><see langword="true"/> if the algorithm is ML-DSA-87; otherwise, <see langword="false"/>.</returns>
    public static bool IsMlDsa87(int algorithm) => algorithm == MlDsa87;


    /// <summary>
    /// Determines if the algorithm is any ML-DSA variant.
    /// </summary>
    /// <param name="algorithm">The algorithm identifier.</param>
    /// <returns><see langword="true"/> if the algorithm is any ML-DSA variant; otherwise, <see langword="false"/>.</returns>
    public static bool IsMlDsa(int algorithm) => algorithm is MlDsa44 or MlDsa65 or MlDsa87;


    /// <summary>
    /// Gets the algorithm name for a COSE algorithm identifier.
    /// </summary>
    /// <param name="algorithm">The COSE algorithm identifier.</param>
    /// <returns>The algorithm name, or null if unknown.</returns>
    public static string? GetAlgorithmName(int algorithm) => algorithm switch
    {
        EdDsa => WellKnownJwaValues.EdDsa,
        Es256 => WellKnownJwaValues.Es256,
        Es384 => WellKnownJwaValues.Es384,
        Es512 => WellKnownJwaValues.Es512,
        Ps256 => WellKnownJwaValues.Ps256,
        Ps384 => WellKnownJwaValues.Ps384,
        Ps512 => WellKnownJwaValues.Ps512,
        Rs256 => WellKnownJwaValues.Rs256,
        Rs384 => WellKnownJwaValues.Rs384,
        Rs512 => WellKnownJwaValues.Rs512,
        Hs256 => WellKnownJwaValues.Hs256,
        Hs384 => WellKnownJwaValues.Hs384,
        Hs512 => WellKnownJwaValues.Hs512,
        Sha256 => Cryptography.WellKnownHashAlgorithms.Sha256Cose,
        Sha384 => Cryptography.WellKnownHashAlgorithms.Sha384Cose,
        Sha512 => Cryptography.WellKnownHashAlgorithms.Sha512Cose,
        A128Gcm => WellKnownJweEncryptionAlgorithms.A128Gcm,
        A192Gcm => WellKnownJweEncryptionAlgorithms.A192Gcm,
        A256Gcm => WellKnownJweEncryptionAlgorithms.A256Gcm,
        MlDsa44 => WellKnownJwaValues.MlDsa44,
        MlDsa65 => WellKnownJwaValues.MlDsa65,
        MlDsa87 => WellKnownJwaValues.MlDsa87,
        _ => null
    };
}