using System.Text;
using Verifiable.Cryptography;
using Verifiable.Jose;

namespace Verifiable.JCose.Sd;

/// <summary>
/// Key Binding JWT (KB-JWT) operations for SD-JWT holder binding.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Purpose:</strong>
/// </para>
/// <para>
/// A Key Binding JWT proves that the presenter of an SD-JWT possesses the private key
/// corresponding to the public key embedded in the credential's <c>cnf</c> (confirmation) claim.
/// </para>
/// <para>
/// <strong>Structure:</strong>
/// </para>
/// <code>
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                        KB-JWT Structure                                 │
/// ├─────────────────────────────────────────────────────────────────────────┤
/// │                                                                         │
/// │  Header:   { "alg": "ES256", "typ": "kb+jwt" }                         │
/// │                                                                         │
/// │  Payload:  {                                                            │
/// │              "iat": 1748537244,                                         │
/// │              "aud": "https://verifier.example.org",                    │
/// │              "nonce": "1234567890",                                     │
/// │              "sd_hash": "0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_..."          │
/// │            }                                                            │
/// │                                                                         │
/// │  Signature: ES256 signature over header.payload                        │
/// │                                                                         │
/// └─────────────────────────────────────────────────────────────────────────┘
/// </code>
/// <para>
/// See <see href="https://www.rfc-editor.org/rfc/rfc9901.html#section-4.3">RFC 9901 Section 4.3</see>.
/// </para>
/// </remarks>
public static class KeyBindingJwt
{
    /// <summary>
    /// Creates the header for a Key Binding JWT.
    /// </summary>
    /// <param name="algorithm">The signing algorithm (e.g., "ES256").</param>
    /// <returns>The header as a dictionary.</returns>
    public static Dictionary<string, object> CreateHeader(string algorithm)
    {
        ArgumentException.ThrowIfNullOrEmpty(algorithm);

        return new Dictionary<string, object>
        {
            [JwkProperties.Alg] = algorithm,
            [JwkProperties.Typ] = SdConstants.KeyBindingJwtType
        };
    }


    /// <summary>
    /// Creates the payload for a Key Binding JWT.
    /// </summary>
    /// <param name="token">The SD-JWT token to bind to.</param>
    /// <param name="audience">The intended audience (verifier).</param>
    /// <param name="nonce">A fresh nonce from the verifier.</param>
    /// <param name="issuedAt">The issuance timestamp.</param>
    /// <param name="hashAlgorithm">The hash algorithm for sd_hash (e.g., "sha-256").</param>
    /// <param name="base64UrlEncode">Delegate for Base64Url encoding.</param>
    /// <returns>The payload as a dictionary.</returns>
    public static Dictionary<string, object> CreatePayload(
        SdJwtToken token,
        string audience,
        string nonce,
        DateTimeOffset issuedAt,
        string hashAlgorithm,
        EncodeDelegate base64UrlEncode)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentException.ThrowIfNullOrEmpty(audience);
        ArgumentException.ThrowIfNullOrEmpty(nonce);
        ArgumentNullException.ThrowIfNull(base64UrlEncode);

        string sdHash = ComputeSdHash(token, hashAlgorithm, base64UrlEncode);

        return new Dictionary<string, object>
        {
            [WellKnownJwtClaims.Iat] = issuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaims.Aud] = audience,
            [SdConstants.NonceClaim] = nonce,
            [SdConstants.SdHashClaim] = sdHash
        };
    }


    /// <summary>
    /// Computes the sd_hash value for a Key Binding JWT.
    /// </summary>
    /// <param name="token">The SD-JWT token.</param>
    /// <param name="hashAlgorithm">The hash algorithm name (e.g., "sha-256").</param>
    /// <param name="base64UrlEncode">Delegate for Base64Url encoding.</param>
    /// <returns>The Base64Url-encoded sd_hash value.</returns>
    /// <remarks>
    /// The sd_hash is computed over the ASCII bytes of the SD-JWT presentation string
    /// (without the key binding JWT), including the trailing tilde.
    /// </remarks>
    public static string ComputeSdHash(
        SdJwtToken token,
        string hashAlgorithm,
        EncodeDelegate base64UrlEncode)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentException.ThrowIfNullOrEmpty(hashAlgorithm);
        ArgumentNullException.ThrowIfNull(base64UrlEncode);

        string sdJwtForHashing = GetSdJwtForHashing(token, base64UrlEncode);
        byte[] sdJwtBytes = Encoding.ASCII.GetBytes(sdJwtForHashing);
        byte[] hashBytes = HashUtilities.ComputeHash(sdJwtBytes, hashAlgorithm);

        return base64UrlEncode(hashBytes);
    }


    /// <summary>
    /// Validates the sd_hash claim in a Key Binding JWT payload.
    /// </summary>
    /// <param name="kbJwtPayload">The parsed KB-JWT payload.</param>
    /// <param name="token">The SD-JWT token being presented.</param>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <param name="base64UrlEncode">Delegate for Base64Url encoding.</param>
    /// <returns><c>true</c> if the sd_hash matches; otherwise, <c>false</c>.</returns>
    public static bool ValidateSdHash(
        Dictionary<string, object> kbJwtPayload,
        SdJwtToken token,
        string hashAlgorithm,
        EncodeDelegate base64UrlEncode)
    {
        ArgumentNullException.ThrowIfNull(kbJwtPayload);
        ArgumentNullException.ThrowIfNull(token);

        if(!kbJwtPayload.TryGetValue(SdConstants.SdHashClaim, out object? sdHashObj) ||
            sdHashObj is not string presentedSdHash)
        {
            return false;
        }

        string expectedSdHash = ComputeSdHash(token, hashAlgorithm, base64UrlEncode);

        return string.Equals(presentedSdHash, expectedSdHash, StringComparison.Ordinal);
    }


    /// <summary>
    /// Validates the standard claims in a Key Binding JWT payload.
    /// </summary>
    /// <param name="kbJwtPayload">The parsed KB-JWT payload.</param>
    /// <param name="expectedAudience">The expected audience, or <c>null</c> to skip check.</param>
    /// <param name="expectedNonce">The expected nonce, or <c>null</c> to skip check.</param>
    /// <param name="timeProvider">The time provider for timestamp validation.</param>
    /// <param name="allowedClockSkew">The allowed clock skew for timestamp validation.</param>
    /// <returns>The validation result.</returns>
    public static KeyBindingValidationResult ValidateClaims(
        Dictionary<string, object> kbJwtPayload,
        string? expectedAudience,
        string? expectedNonce,
        TimeProvider timeProvider,
        TimeSpan allowedClockSkew)
    {
        ArgumentNullException.ThrowIfNull(kbJwtPayload);
        ArgumentNullException.ThrowIfNull(timeProvider);

        //Validate audience if expected.
        if(expectedAudience is not null)
        {
            if(!kbJwtPayload.TryGetValue(WellKnownJwtClaims.Aud, out object? audObj) ||
                audObj is not string audience ||
                !string.Equals(audience, expectedAudience, StringComparison.Ordinal))
            {
                return KeyBindingValidationResult.AudienceMismatch;
            }
        }

        //Validate nonce if expected.
        if(expectedNonce is not null)
        {
            if(!kbJwtPayload.TryGetValue(SdConstants.NonceClaim, out object? nonceObj) ||
                nonceObj is not string nonce ||
                !string.Equals(nonce, expectedNonce, StringComparison.Ordinal))
            {
                return KeyBindingValidationResult.NonceMismatch;
            }
        }

        //Validate iat (issued at).
        if(!kbJwtPayload.TryGetValue(WellKnownJwtClaims.Iat, out object? iatObj))
        {
            return KeyBindingValidationResult.MissingIat;
        }

        long iat = iatObj switch
        {
            long l => l,
            int i => i,
            double d => (long)d,
            _ => 0
        };

        if(iat == 0)
        {
            return KeyBindingValidationResult.MissingIat;
        }

        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(iat);
        DateTimeOffset now = timeProvider.GetUtcNow();

        //Check if iat is in the future (beyond allowed skew).
        if(issuedAt > now.Add(allowedClockSkew))
        {
            return KeyBindingValidationResult.IatInFuture;
        }

        return KeyBindingValidationResult.Valid;
    }


    /// <summary>
    /// Checks if a string has valid JWT structure (three dot-separated parts).
    /// </summary>
    /// <param name="value">The string to check.</param>
    /// <returns><c>true</c> if the string has valid JWT structure; otherwise, <c>false</c>.</returns>
    public static bool IsValidJwtStructure(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }

        int dotCount = 0;

        foreach(char c in value)
        {
            if(c == '.')
            {
                dotCount++;
            }
        }

        return dotCount == 2;
    }


    /// <summary>
    /// Gets the SD-JWT string suitable for hashing (without key binding, with trailing tilde).
    /// </summary>
    private static string GetSdJwtForHashing(SdJwtToken token, EncodeDelegate base64UrlEncode)
    {
        var builder = new StringBuilder();
        builder.Append(token.IssuerSigned);
        builder.Append(SdConstants.JwtSeparator);

        foreach(SdDisclosure disclosure in token.Disclosures)
        {
            string encoded = SerializeDisclosure(disclosure, base64UrlEncode);
            builder.Append(encoded);
            builder.Append(SdConstants.JwtSeparator);
        }

        return builder.ToString();
    }


    /// <summary>
    /// Serializes a disclosure to its Base64Url-encoded form.
    /// </summary>
    private static string SerializeDisclosure(SdDisclosure disclosure, EncodeDelegate base64UrlEncode)
    {
        //Encode salt as Base64Url string for JSON representation.
        string saltString = base64UrlEncode(disclosure.Salt.Span);

        //Build JSON array manually to avoid System.Text.Json dependency.
        string json;

        if(disclosure.ClaimName is not null)
        {
            json = $"[\"{saltString}\", \"{disclosure.ClaimName}\", {SerializeValue(disclosure.ClaimValue)}]";
        }
        else
        {
            json = $"[\"{saltString}\", {SerializeValue(disclosure.ClaimValue)}]";
        }

        return base64UrlEncode(Encoding.UTF8.GetBytes(json));
    }


    private static string SerializeValue(object? value)
    {
        return value switch
        {
            null => "null",
            string s => $"\"{EscapeJsonString(s)}\"",
            bool b => b ? "true" : "false",
            int i => i.ToString(System.Globalization.CultureInfo.InvariantCulture),
            long l => l.ToString(System.Globalization.CultureInfo.InvariantCulture),
            double d => d.ToString(System.Globalization.CultureInfo.InvariantCulture),
            decimal m => m.ToString(System.Globalization.CultureInfo.InvariantCulture),
            _ => $"\"{value}\""
        };
    }


    private static string EscapeJsonString(string s)
    {
        return s.Replace("\\", "\\\\", StringComparison.Ordinal)
                .Replace("\"", "\\\"", StringComparison.Ordinal)
                .Replace("\n", "\\n", StringComparison.Ordinal)
                .Replace("\r", "\\r", StringComparison.Ordinal)
                .Replace("\t", "\\t", StringComparison.Ordinal);
    }
}


/// <summary>
/// Result of Key Binding JWT validation.
/// </summary>
public enum KeyBindingValidationResult
{
    /// <summary>
    /// The Key Binding JWT is valid.
    /// </summary>
    Valid,

    /// <summary>
    /// The audience claim does not match the expected value.
    /// </summary>
    AudienceMismatch,

    /// <summary>
    /// The nonce claim does not match the expected value.
    /// </summary>
    NonceMismatch,

    /// <summary>
    /// The iat (issued at) claim is missing.
    /// </summary>
    MissingIat,

    /// <summary>
    /// The iat (issued at) claim is in the future beyond allowed clock skew.
    /// </summary>
    IatInFuture,

    /// <summary>
    /// The sd_hash claim does not match the computed value.
    /// </summary>
    SdHashMismatch
}


/// <summary>
/// Hash utilities for SD-JWT operations.
/// </summary>
internal static class HashUtilities
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "This file will be refactored (TODO).")]
    public static byte[] ComputeHash(byte[] data, string algorithmName)
    {
        System.Security.Cryptography.HashAlgorithmName hashAlgorithm = algorithmName.ToLowerInvariant() switch
        {
            "sha-256" => System.Security.Cryptography.HashAlgorithmName.SHA256,
            "sha-384" => System.Security.Cryptography.HashAlgorithmName.SHA384,
            "sha-512" => System.Security.Cryptography.HashAlgorithmName.SHA512,
            _ => throw new ArgumentException($"Unsupported hash algorithm: {algorithmName}", nameof(algorithmName))
        };

        return hashAlgorithm.Name switch
        {
            "SHA256" => System.Security.Cryptography.SHA256.HashData(data),
            "SHA384" => System.Security.Cryptography.SHA384.HashData(data),
            "SHA512" => System.Security.Cryptography.SHA512.HashData(data),
            _ => throw new ArgumentException($"Unsupported hash algorithm: {algorithmName}", nameof(algorithmName))
        };
    }
}