using System.Security.Cryptography;

namespace Verifiable.Cryptography;

/// <summary>
/// Well-known hash algorithm identifiers, sizes, and conversion utilities.
/// </summary>
/// <remarks>
/// <para>
/// Different specifications use different naming conventions for the same hash algorithms:
/// </para>
/// <list type="bullet">
/// <item><description>.NET uses uppercase without hyphen: "SHA256", "SHA384", "SHA512".</description></item>
/// <item><description>IANA/IETF specs use lowercase with hyphen: "sha-256", "sha-384", "sha-512".</description></item>
/// <item><description>Some systems use lowercase without hyphen: "sha256", "sha384", "sha512".</description></item>
/// </list>
/// <para>
/// This class provides constants for all variants and methods to convert between them,
/// enabling consistent handling across JOSE, COSE, SD-JWT, SD-CWT, and other specifications.
/// </para>
/// </remarks>
public static class WellKnownHashAlgorithms
{
    /// <summary>
    /// SHA-256 algorithm name in .NET format.
    /// </summary>
    /// <remarks>
    /// Matches <see cref="HashAlgorithmName.SHA256"/>.<see cref="HashAlgorithmName.Name"/>.
    /// </remarks>
    public const string Sha256 = "SHA256";

    /// <summary>
    /// SHA-384 algorithm name in .NET format.
    /// </summary>
    /// <remarks>
    /// Matches <see cref="HashAlgorithmName.SHA384"/>.<see cref="HashAlgorithmName.Name"/>.
    /// </remarks>
    public const string Sha384 = "SHA384";

    /// <summary>
    /// SHA-512 algorithm name in .NET format.
    /// </summary>
    /// <remarks>
    /// Matches <see cref="HashAlgorithmName.SHA512"/>.<see cref="HashAlgorithmName.Name"/>.
    /// </remarks>
    public const string Sha512 = "SHA512";

    /// <summary>
    /// SHA-256 algorithm name in IANA format.
    /// </summary>
    /// <remarks>
    /// Used in SD-JWT <c>_sd_alg</c> claim, COSE algorithm parameters, and IETF specifications.
    /// </remarks>
    public const string Sha256Iana = "sha-256";

    /// <summary>
    /// SHA-384 algorithm name in IANA format.
    /// </summary>
    /// <remarks>
    /// Used in SD-JWT <c>_sd_alg</c> claim, COSE algorithm parameters, and IETF specifications.
    /// </remarks>
    public const string Sha384Iana = "sha-384";

    /// <summary>
    /// SHA-512 algorithm name in IANA format.
    /// </summary>
    /// <remarks>
    /// Used in SD-JWT <c>_sd_alg</c> claim, COSE algorithm parameters, and IETF specifications.
    /// </remarks>
    public const string Sha512Iana = "sha-512";

    /// <summary>
    /// SHA-256 algorithm name in COSE display format (uppercase, hyphenated).
    /// </summary>
    /// <remarks>
    /// Used in the IANA COSE Algorithms registry display names.
    /// See <see href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms</see>.
    /// </remarks>
    public const string Sha256Cose = "SHA-256";

    /// <summary>
    /// SHA-384 algorithm name in COSE display format (uppercase, hyphenated).
    /// </summary>
    /// <remarks>
    /// Used in the IANA COSE Algorithms registry display names.
    /// See <see href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms</see>.
    /// </remarks>
    public const string Sha384Cose = "SHA-384";

    /// <summary>
    /// SHA-512 algorithm name in COSE display format (uppercase, hyphenated).
    /// </summary>
    /// <remarks>
    /// Used in the IANA COSE Algorithms registry display names.
    /// See <see href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms</see>.
    /// </remarks>
    public const string Sha512Cose = "SHA-512";

    /// <summary>
    /// SHA-256 output size in bytes.
    /// </summary>
    public const int Sha256SizeBytes = 32;

    /// <summary>
    /// SHA-384 output size in bytes.
    /// </summary>
    public const int Sha384SizeBytes = 48;

    /// <summary>
    /// SHA-512 output size in bytes.
    /// </summary>
    public const int Sha512SizeBytes = 64;

    /// <summary>
    /// SHA-256 output size in bits.
    /// </summary>
    public const int Sha256SizeBits = 256;

    /// <summary>
    /// SHA-384 output size in bits.
    /// </summary>
    public const int Sha384SizeBits = 384;

    /// <summary>
    /// SHA-512 output size in bits.
    /// </summary>
    public const int Sha512SizeBits = 512;


    /// <summary>
    /// Determines whether the specified value represents SHA-256.
    /// </summary>
    /// <param name="value">The algorithm name to check.</param>
    /// <returns><see langword="true"/> if the value represents SHA-256; otherwise, <see langword="false"/>.</returns>
    public static bool IsSha256(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }

        return string.Equals(value, Sha256, StringComparison.OrdinalIgnoreCase) 
            || string.Equals(value, Sha256Iana, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Sha256Cose, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "sha256", StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// Determines whether the specified value represents SHA-384.
    /// </summary>
    /// <param name="value">The algorithm name to check.</param>
    /// <returns><see langword="true"/> if the value represents SHA-384; otherwise, <see langword="false"/>.</returns>
    public static bool IsSha384(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }

        return string.Equals(value, Sha384, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Sha384Iana, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Sha384Cose, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "sha384", StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// Determines whether the specified value represents SHA-512.
    /// </summary>
    /// <param name="value">The algorithm name to check.</param>
    /// <returns><see langword="true"/> if the value represents SHA-512; otherwise, <see langword="false"/>.</returns>
    public static bool IsSha512(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }

        return string.Equals(value, Sha512, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Sha512Iana, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, Sha512Cose, StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "sha512", StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// Converts a string algorithm name to <see cref="HashAlgorithmName"/>.
    /// </summary>
    /// <param name="value">The algorithm name in any supported format.</param>
    /// <returns>The corresponding <see cref="HashAlgorithmName"/>.</returns>
    /// <exception cref="ArgumentException">Thrown for unsupported algorithm names.</exception>
    public static HashAlgorithmName ToHashAlgorithmName(string value)
    {
        if(IsSha256(value))
        {
            return HashAlgorithmName.SHA256;
        }

        if(IsSha384(value))
        {
            return HashAlgorithmName.SHA384;
        }

        if(IsSha512(value))
        {
            return HashAlgorithmName.SHA512;
        }

        throw new ArgumentException($"Unsupported hash algorithm: '{value}'.", nameof(value));
    }


    /// <summary>
    /// Converts a <see cref="HashAlgorithmName"/> to IANA format.
    /// </summary>
    /// <param name="algorithm">The hash algorithm.</param>
    /// <returns>The IANA-formatted algorithm name.</returns>
    /// <exception cref="ArgumentException">Thrown for unsupported algorithms.</exception>
    /// <remarks>
    /// Use this when serializing algorithm names for SD-JWT, SD-CWT, or other IETF specifications.
    /// </remarks>
    public static string ToIanaName(HashAlgorithmName algorithm)
    {
        return algorithm.Name switch
        {
            Sha256 => Sha256Iana,
            Sha384 => Sha384Iana,
            Sha512 => Sha512Iana,
            _ => throw new ArgumentException($"Unsupported hash algorithm: '{algorithm.Name}'.", nameof(algorithm))
        };
    }


    /// <summary>
    /// Converts a string algorithm name to IANA format.
    /// </summary>
    /// <param name="value">The algorithm name in any supported format.</param>
    /// <returns>The IANA-formatted algorithm name.</returns>
    /// <exception cref="ArgumentException">Thrown for unsupported algorithm names.</exception>
    public static string ToIanaName(string value)
    {
        if(IsSha256(value))
        {
            return Sha256Iana;
        }

        if(IsSha384(value))
        {
            return Sha384Iana;
        }

        if(IsSha512(value))
        {
            return Sha512Iana;
        }

        throw new ArgumentException($"Unsupported hash algorithm: '{value}'.", nameof(value));
    }


    /// <summary>
    /// Converts a <see cref="HashAlgorithmName"/> to COSE display format (uppercase, hyphenated).
    /// </summary>
    /// <param name="algorithm">The hash algorithm.</param>
    /// <returns>The COSE-formatted algorithm name.</returns>
    /// <exception cref="ArgumentException">Thrown for unsupported algorithms.</exception>
    /// <remarks>
    /// Use this when producing display names for the IANA COSE Algorithms registry.
    /// </remarks>
    public static string ToCoseName(HashAlgorithmName algorithm)
    {
        return algorithm.Name switch
        {
            Sha256 => Sha256Cose,
            Sha384 => Sha384Cose,
            Sha512 => Sha512Cose,
            _ => throw new ArgumentException($"Unsupported hash algorithm: '{algorithm.Name}'.", nameof(algorithm))
        };
    }


    /// <summary>
    /// Converts a string algorithm name to COSE display format (uppercase, hyphenated).
    /// </summary>
    /// <param name="value">The algorithm name in any supported format.</param>
    /// <returns>The COSE-formatted algorithm name.</returns>
    /// <exception cref="ArgumentException">Thrown for unsupported algorithm names.</exception>
    public static string ToCoseName(string value)
    {
        if(IsSha256(value))
        {
            return Sha256Cose;
        }

        if(IsSha384(value))
        {
            return Sha384Cose;
        }

        if(IsSha512(value))
        {
            return Sha512Cose;
        }

        throw new ArgumentException($"Unsupported hash algorithm: '{value}'.", nameof(value));
    }


    /// <summary>
    /// Gets the output size in bytes for the specified algorithm.
    /// </summary>
    /// <param name="algorithm">The hash algorithm.</param>
    /// <returns>The hash output size in bytes.</returns>
    /// <exception cref="ArgumentException">Thrown for unsupported algorithms.</exception>
    public static int GetSizeBytes(HashAlgorithmName algorithm)
    {
        return algorithm.Name switch
        {
            Sha256 => Sha256SizeBytes,
            Sha384 => Sha384SizeBytes,
            Sha512 => Sha512SizeBytes,
            _ => throw new ArgumentException($"Unknown hash algorithm: '{algorithm.Name}'.", nameof(algorithm))
        };
    }


    /// <summary>
    /// Gets the output size in bytes for the specified algorithm name.
    /// </summary>
    /// <param name="value">The algorithm name in any supported format.</param>
    /// <returns>The hash output size in bytes.</returns>
    /// <exception cref="ArgumentException">Thrown for unsupported algorithm names.</exception>
    public static int GetSizeBytes(string value)
    {
        if(IsSha256(value))
        {
            return Sha256SizeBytes;
        }

        if(IsSha384(value))
        {
            return Sha384SizeBytes;
        }

        if(IsSha512(value))
        {
            return Sha512SizeBytes;
        }

        throw new ArgumentException($"Unknown hash algorithm: '{value}'.", nameof(value));
    }


    /// <summary>
    /// Gets the output size in bits for the specified algorithm.
    /// </summary>
    /// <param name="algorithm">The hash algorithm.</param>
    /// <returns>The hash output size in bits.</returns>
    /// <exception cref="ArgumentException">Thrown for unsupported algorithms.</exception>
    public static int GetSizeBits(HashAlgorithmName algorithm)
    {
        return algorithm.Name switch
        {
            Sha256 => Sha256SizeBits,
            Sha384 => Sha384SizeBits,
            Sha512 => Sha512SizeBits,
            _ => throw new ArgumentException($"Unknown hash algorithm: '{algorithm.Name}'.", nameof(algorithm))
        };
    }
}