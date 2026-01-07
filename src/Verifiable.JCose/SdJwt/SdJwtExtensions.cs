using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;

namespace Verifiable.Jose.SdJwt;

/// <summary>
/// Extension methods for SD-JWT types.
/// </summary>
public static class SdJwtExtensions
{
    /// <summary>
    /// Computes the digest of a disclosure using the specified hash algorithm.
    /// </summary>
    /// <param name="disclosure">The disclosure to compute the digest for.</param>
    /// <param name="hashAlgorithmName">The hash algorithm to use (e.g., "sha-256").</param>
    /// <param name="base64UrlEncoder">Delegate for base64url encoding.</param>
    /// <returns>The base64url-encoded digest.</returns>
    /// <remarks>
    /// The digest is computed over the US-ASCII bytes of the base64url-encoded disclosure string,
    /// following the convention in JWS. The resulting hash bytes are then base64url-encoded.
    /// </remarks>
    public static string ComputeDigest(this Disclosure disclosure, string hashAlgorithmName, EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(disclosure, nameof(disclosure));
        ArgumentException.ThrowIfNullOrWhiteSpace(hashAlgorithmName, nameof(hashAlgorithmName));
        ArgumentNullException.ThrowIfNull(base64UrlEncoder, nameof(base64UrlEncoder));

        //Per RFC 9901, hash over the US-ASCII bytes of the base64url-encoded disclosure.
        byte[] disclosureBytes = Encoding.ASCII.GetBytes(disclosure.EncodedValue);
        byte[] hashBytes = ComputeHash(disclosureBytes, hashAlgorithmName);

        return base64UrlEncoder(hashBytes);
    }


    /// <summary>
    /// Serializes an SD-JWT token to its compact serialization format.
    /// </summary>
    /// <param name="token">The SD-JWT token to serialize.</param>
    /// <returns>The compact serialization string.</returns>
    /// <remarks>
    /// <para>
    /// The format is: <c>issuer-signed-jwt~disclosure1~disclosure2~...~[kb-jwt]</c>
    /// </para>
    /// <para>
    /// If there is no key binding JWT, the serialization ends with a tilde.
    /// If there is a key binding JWT, it appears after the last disclosure without a trailing tilde.
    /// </para>
    /// </remarks>
    public static string Serialize(this SdJwtToken token)
    {
        ArgumentNullException.ThrowIfNull(token, nameof(token));

        var builder = new StringBuilder();
        builder.Append(token.IssuerSignedJwt);
        builder.Append(SdJwtConstants.Separator);

        foreach(Disclosure disclosure in token.Disclosures)
        {
            builder.Append(disclosure.EncodedValue);
            builder.Append(SdJwtConstants.Separator);
        }

        if(token.KeyBindingJwt is not null)
        {
            //Remove trailing tilde and append KB-JWT.
            builder.Length--;
            builder.Append(SdJwtConstants.Separator);
            builder.Append(token.KeyBindingJwt);
        }

        return builder.ToString();
    }


    /// <summary>
    /// Gets the SD-JWT string suitable for hashing in Key Binding JWT sd_hash computation.
    /// </summary>
    /// <param name="token">The SD-JWT token.</param>
    /// <returns>The SD-JWT string without the key binding JWT, ending with a tilde.</returns>
    /// <remarks>
    /// Per RFC 9901, the sd_hash is computed over the SD-JWT without the key binding JWT,
    /// but including all disclosures, and ending with a tilde separator.
    /// </remarks>
    public static string GetSdJwtForHashing(this SdJwtToken token)
    {
        ArgumentNullException.ThrowIfNull(token, nameof(token));

        var builder = new StringBuilder();
        builder.Append(token.IssuerSignedJwt);
        builder.Append(SdJwtConstants.Separator);

        foreach(Disclosure disclosure in token.Disclosures)
        {
            builder.Append(disclosure.EncodedValue);
            builder.Append(SdJwtConstants.Separator);
        }

        return builder.ToString();
    }


    /// <summary>
    /// Creates a new SD-JWT token with a subset of disclosures for selective disclosure.
    /// </summary>
    /// <param name="token">The original SD-JWT token.</param>
    /// <param name="selectedDisclosures">The disclosures to include in the presentation.</param>
    /// <returns>A new SD-JWT token containing only the selected disclosures.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when a selected disclosure is not present in the original token.
    /// </exception>
    public static SdJwtToken SelectDisclosures(this SdJwtToken token, IEnumerable<Disclosure> selectedDisclosures)
    {
        ArgumentNullException.ThrowIfNull(token, nameof(token));
        ArgumentNullException.ThrowIfNull(selectedDisclosures, nameof(selectedDisclosures));

        var selected = selectedDisclosures.ToList();

        foreach(Disclosure disclosure in selected)
        {
            if(!token.Disclosures.Contains(disclosure))
            {
                throw new ArgumentException(
                    $"Disclosure '{disclosure.EncodedValue}' is not present in the original token.",
                    nameof(selectedDisclosures));
            }
        }

        return new SdJwtToken(token.IssuerSignedJwt, selected);
    }


    /// <summary>
    /// Creates a new SD-JWT token with a key binding JWT attached.
    /// </summary>
    /// <param name="token">The original SD-JWT token.</param>
    /// <param name="keyBindingJwt">The key binding JWT to attach.</param>
    /// <returns>A new SD-JWT token with the key binding JWT.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when the key binding JWT format is invalid.
    /// </exception>
    public static SdJwtToken WithKeyBinding(this SdJwtToken token, string keyBindingJwt)
    {
        ArgumentNullException.ThrowIfNull(token, nameof(token));
        ArgumentException.ThrowIfNullOrWhiteSpace(keyBindingJwt, nameof(keyBindingJwt));

        //Basic validation that it looks like a JWT.
        string[] parts = keyBindingJwt.Split('.');
        if(parts.Length != 3)
        {
            throw new ArgumentException("Key binding JWT must have exactly three parts.", nameof(keyBindingJwt));
        }

        return new SdJwtToken(token.IssuerSignedJwt, token.Disclosures, keyBindingJwt);
    }


    /// <summary>
    /// Computes the sd_hash value for a Key Binding JWT.
    /// </summary>
    /// <param name="token">The SD-JWT token to compute the hash for.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use (e.g., "sha-256").</param>
    /// <param name="base64UrlEncoder">Delegate for base64url encoding.</param>
    /// <returns>The base64url-encoded sd_hash value.</returns>
    /// <remarks>
    /// The sd_hash is computed over the ASCII bytes of the SD-JWT presentation string
    /// (without the key binding JWT), including the trailing tilde.
    /// </remarks>
    public static string ComputeSdHash(this SdJwtToken token, string hashAlgorithm, EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(token, nameof(token));
        ArgumentException.ThrowIfNullOrWhiteSpace(hashAlgorithm, nameof(hashAlgorithm));
        ArgumentNullException.ThrowIfNull(base64UrlEncoder, nameof(base64UrlEncoder));

        string sdJwtForHashing = token.GetSdJwtForHashing();
        byte[] sdJwtBytes = Encoding.ASCII.GetBytes(sdJwtForHashing);
        byte[] hashBytes = ComputeHash(sdJwtBytes, hashAlgorithm);

        return base64UrlEncoder(hashBytes);
    }


    /// <summary>
    /// Validates that a claim name is allowed for use in disclosures.
    /// </summary>
    /// <param name="claimName">The claim name to validate.</param>
    /// <returns>True if the claim name is valid; otherwise, false.</returns>
    /// <remarks>
    /// Per RFC 9901, the claim names "_sd" and "..." are reserved and cannot be used.
    /// </remarks>
    public static bool IsValidDisclosureClaimName(string claimName)
    {
        if(string.IsNullOrWhiteSpace(claimName))
        {
            return false;
        }

        return claimName != SdJwtConstants.SdClaimName && claimName != SdJwtConstants.ArrayDigestKey;
    }


    private static byte[] ComputeHash(byte[] data, string algorithmName)
    {
        HashAlgorithmName hashAlgorithm = algorithmName.ToLowerInvariant() switch
        {
            "sha-256" => HashAlgorithmName.SHA256,
            "sha-384" => HashAlgorithmName.SHA384,
            "sha-512" => HashAlgorithmName.SHA512,
            _ => throw new ArgumentException($"Unsupported hash algorithm: {algorithmName}", nameof(algorithmName))
        };

        return hashAlgorithm.Name switch
        {
            "SHA256" => SHA256.HashData(data),
            "SHA384" => SHA384.HashData(data),
            "SHA512" => SHA512.HashData(data),
            _ => throw new ArgumentException($"Unsupported hash algorithm: {algorithmName}", nameof(algorithmName))
        };
    }
}