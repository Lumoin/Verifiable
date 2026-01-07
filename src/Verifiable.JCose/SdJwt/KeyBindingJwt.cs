using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;

namespace Verifiable.Jose.SdJwt;

/// <summary>
/// Operations for Key Binding JWT (KB-JWT) used to prove possession of the Holder's key.
/// </summary>
/// <remarks>
/// <para>
/// The KB-JWT binds an SD-JWT presentation to the Holder by signing over:
/// </para>
/// <list type="bullet">
/// <item><description>A hash of the SD-JWT (sd_hash claim).</description></item>
/// <item><description>A nonce for freshness.</description></item>
/// <item><description>An audience identifying the Verifier.</description></item>
/// <item><description>An issued-at timestamp.</description></item>
/// </list>
/// <para>
/// See <see href="https://www.rfc-editor.org/rfc/rfc9901.html#section-4.3">RFC 9901 Section 4.3</see>.
/// </para>
/// </remarks>
public static class KeyBindingJwt
{
    /// <summary>
    /// Creates the payload for a Key Binding JWT.
    /// </summary>
    /// <param name="sdJwtToken">The SD-JWT token to bind to.</param>
    /// <param name="audience">The intended Verifier (aud claim).</param>
    /// <param name="nonce">A fresh nonce value.</param>
    /// <param name="issuedAt">The time the KB-JWT is created.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use (must match the SD-JWT's _sd_alg).</param>
    /// <param name="base64UrlEncoder">Delegate for base64url encoding.</param>
    /// <returns>The KB-JWT payload as a dictionary.</returns>
    public static Dictionary<string, object> CreatePayload(
        SdJwtToken sdJwtToken,
        string audience,
        string nonce,
        DateTimeOffset issuedAt,
        string hashAlgorithm,
        EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(sdJwtToken, nameof(sdJwtToken));
        ArgumentException.ThrowIfNullOrWhiteSpace(audience, nameof(audience));
        ArgumentException.ThrowIfNullOrWhiteSpace(nonce, nameof(nonce));
        ArgumentNullException.ThrowIfNull(base64UrlEncoder, nameof(base64UrlEncoder));

        string sdHash = sdJwtToken.ComputeSdHash(hashAlgorithm, base64UrlEncoder);

        return new Dictionary<string, object>
        {
            [WellKnownJwtClaims.Iat] = issuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaims.Aud] = audience,
            [SdJwtConstants.NonceClaim] = nonce,
            [SdJwtConstants.SdHashClaimName] = sdHash
        };
    }


    /// <summary>
    /// Creates the header for a Key Binding JWT.
    /// </summary>
    /// <param name="algorithm">The signing algorithm (e.g., "ES256").</param>
    /// <returns>The KB-JWT header as a dictionary.</returns>
    public static Dictionary<string, object> CreateHeader(string algorithm)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm, nameof(algorithm));

        return new Dictionary<string, object>
        {
            [JwkProperties.Alg] = algorithm,
            [JwkProperties.Typ] = SdJwtConstants.KeyBindingJwtType
        };
    }


    /// <summary>
    /// Validates the sd_hash claim in a Key Binding JWT payload against an SD-JWT.
    /// </summary>
    /// <param name="kbJwtPayload">The parsed KB-JWT payload as a dictionary.</param>
    /// <param name="sdJwtToken">The SD-JWT token to validate against.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url encoding.</param>
    /// <returns>True if the sd_hash matches; otherwise, false.</returns>
    public static bool ValidateSdHash(
        Dictionary<string, object> kbJwtPayload,
        SdJwtToken sdJwtToken,
        string hashAlgorithm,
        EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(kbJwtPayload, nameof(kbJwtPayload));
        ArgumentNullException.ThrowIfNull(sdJwtToken, nameof(sdJwtToken));
        ArgumentNullException.ThrowIfNull(base64UrlEncoder, nameof(base64UrlEncoder));

        if(!kbJwtPayload.TryGetValue(SdJwtConstants.SdHashClaimName, out object? sdHashObj))
        {
            return false;
        }

        if(sdHashObj is not string claimedSdHash || string.IsNullOrEmpty(claimedSdHash))
        {
            return false;
        }

        string expectedSdHash = sdJwtToken.ComputeSdHash(hashAlgorithm, base64UrlEncoder);

        return string.Equals(claimedSdHash, expectedSdHash, StringComparison.Ordinal);
    }


    /// <summary>
    /// Validates the required claims in a Key Binding JWT payload.
    /// </summary>
    /// <param name="payload">The KB-JWT payload as a dictionary.</param>
    /// <param name="expectedAudience">The expected audience value, or null to skip audience validation.</param>
    /// <param name="expectedNonce">The expected nonce value, or null to skip nonce validation.</param>
    /// <param name="timeProvider">Time provider for iat validation.</param>
    /// <param name="allowedClockSkew">Maximum allowed clock skew for time validation.</param>
    /// <returns>A validation result indicating success or the specific validation failure.</returns>
    public static KeyBindingValidationResult ValidateClaims(
        Dictionary<string, object> payload,
        string? expectedAudience,
        string? expectedNonce,
        TimeProvider timeProvider,
        TimeSpan allowedClockSkew)
    {
        ArgumentNullException.ThrowIfNull(payload, nameof(payload));
        ArgumentNullException.ThrowIfNull(timeProvider, nameof(timeProvider));

        //Validate iat (required).
        if(!payload.TryGetValue(WellKnownJwtClaims.Iat, out object? iatObj))
        {
            return KeyBindingValidationResult.MissingIat;
        }

        long iatValue;
        if(iatObj is long longIat)
        {
            iatValue = longIat;
        }
        else if(iatObj is int intIat)
        {
            iatValue = intIat;
        }
        else if(iatObj is decimal decimalIat)
        {
            iatValue = (long)decimalIat;
        }
        else
        {
            return KeyBindingValidationResult.InvalidIat;
        }

        DateTimeOffset iat = DateTimeOffset.FromUnixTimeSeconds(iatValue);
        DateTimeOffset now = timeProvider.GetUtcNow();

        //Check if iat is too far in the future.
        if(iat > now.Add(allowedClockSkew))
        {
            return KeyBindingValidationResult.IatInFuture;
        }

        //Validate aud (required).
        if(!payload.TryGetValue(WellKnownJwtClaims.Aud, out object? audObj))
        {
            return KeyBindingValidationResult.MissingAud;
        }

        if(audObj is not string aud || string.IsNullOrEmpty(aud))
        {
            return KeyBindingValidationResult.InvalidAud;
        }

        if(expectedAudience is not null && !string.Equals(aud, expectedAudience, StringComparison.Ordinal))
        {
            return KeyBindingValidationResult.AudienceMismatch;
        }

        //Validate nonce (required).
        if(!payload.TryGetValue(SdJwtConstants.NonceClaim, out object? nonceObj))
        {
            return KeyBindingValidationResult.MissingNonce;
        }

        if(nonceObj is not string nonce || string.IsNullOrEmpty(nonce))
        {
            return KeyBindingValidationResult.InvalidNonce;
        }

        if(expectedNonce is not null && !string.Equals(nonce, expectedNonce, StringComparison.Ordinal))
        {
            return KeyBindingValidationResult.NonceMismatch;
        }

        //Validate sd_hash (required).
        if(!payload.TryGetValue(SdJwtConstants.SdHashClaimName, out object? sdHashObj))
        {
            return KeyBindingValidationResult.MissingSdHash;
        }

        if(sdHashObj is not string sdHash || string.IsNullOrEmpty(sdHash))
        {
            return KeyBindingValidationResult.InvalidSdHash;
        }

        return KeyBindingValidationResult.Valid;
    }


    /// <summary>
    /// Validates a JWT has the correct structure (three dot-separated parts).
    /// </summary>
    /// <param name="jwt">The JWT string to validate.</param>
    /// <returns>True if the JWT has valid structure; otherwise, false.</returns>
    public static bool IsValidJwtStructure(string jwt)
    {
        if(string.IsNullOrWhiteSpace(jwt))
        {
            return false;
        }

        string[] parts = jwt.Split('.');
        if(parts.Length != 3)
        {
            return false;
        }

        //Each part should be non-empty and contain only valid base64url characters.
        foreach(string part in parts)
        {
            if(string.IsNullOrEmpty(part))
            {
                return false;
            }

            foreach(char c in part)
            {
                if(!IsBase64UrlChar(c))
                {
                    return false;
                }
            }
        }

        return true;
    }


    private static bool IsBase64UrlChar(char c)
    {
        return (c >= 'A' && c <= 'Z') ||
               (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') ||
               c == '-' ||
               c == '_';
    }
}


/// <summary>
/// Result of Key Binding JWT claim validation.
/// </summary>
public enum KeyBindingValidationResult
{
    /// <summary>
    /// All claims are valid.
    /// </summary>
    Valid,

    /// <summary>
    /// The iat claim is missing.
    /// </summary>
    MissingIat,

    /// <summary>
    /// The iat claim is not a valid number.
    /// </summary>
    InvalidIat,

    /// <summary>
    /// The iat claim is too far in the future.
    /// </summary>
    IatInFuture,

    /// <summary>
    /// The aud claim is missing.
    /// </summary>
    MissingAud,

    /// <summary>
    /// The aud claim is not a valid string.
    /// </summary>
    InvalidAud,

    /// <summary>
    /// The aud claim does not match the expected audience.
    /// </summary>
    AudienceMismatch,

    /// <summary>
    /// The nonce claim is missing.
    /// </summary>
    MissingNonce,

    /// <summary>
    /// The nonce claim is not a valid string.
    /// </summary>
    InvalidNonce,

    /// <summary>
    /// The nonce claim does not match the expected nonce.
    /// </summary>
    NonceMismatch,

    /// <summary>
    /// The sd_hash claim is missing.
    /// </summary>
    MissingSdHash,

    /// <summary>
    /// The sd_hash claim is not a valid string.
    /// </summary>
    InvalidSdHash,

    /// <summary>
    /// The sd_hash claim does not match the computed hash.
    /// </summary>
    SdHashMismatch
}