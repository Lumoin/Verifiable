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
    /// Gets the algorithm name for a COSE algorithm identifier.
    /// </summary>
    /// <param name="algorithm">The COSE algorithm identifier.</param>
    /// <returns>The algorithm name, or null if unknown.</returns>
    public static string? GetAlgorithmName(int algorithm) => algorithm switch
    {
        EdDsa => "EdDSA",
        Es256 => "ES256",
        Es384 => "ES384",
        Es512 => "ES512",
        Ps256 => "PS256",
        Ps384 => "PS384",
        Ps512 => "PS512",
        Rs256 => "RS256",
        Rs384 => "RS384",
        Rs512 => "RS512",
        Hs256 => "HS256",
        Hs384 => "HS384",
        Hs512 => "HS512",
        Sha256 => "SHA-256",
        Sha384 => "SHA-384",
        Sha512 => "SHA-512",
        A128Gcm => "A128GCM",
        A192Gcm => "A192GCM",
        A256Gcm => "A256GCM",
        _ => null
    };
}