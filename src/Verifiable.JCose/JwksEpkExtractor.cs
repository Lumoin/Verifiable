using System.Buffers;
using Verifiable.Cryptography;

namespace Verifiable.JCose;

/// <summary>
/// Extracts an ECDH encryption public key from a JWKS JSON string.
/// </summary>
/// <remarks>
/// <para>
/// Used on the Wallet side to recover the Verifier's ephemeral P-256 public key from
/// the <c>client_metadata.jwks</c> field of a parsed JAR, so the Wallet can encrypt
/// the VP response using ECDH-ES.
/// </para>
/// <para>
/// Parsing uses <see cref="JwkJsonReader"/> — no JSON serialisation library dependency.
/// Base64url decoding uses the supplied <see cref="DecodeDelegate"/> consistent with
/// the library's delegate convention.
/// </para>
/// </remarks>
public static class JwksEpkExtractor
{
    /// <summary>
    /// Extracts the first EC P-256 key with <c>use=enc</c> from a JWKS JSON string and
    /// returns it as a <see cref="PublicKeyMemory"/> in uncompressed encoding
    /// (<c>0x04 || X || Y</c>), tagged with <see cref="CryptoTags.P256ExchangePublicKey"/>.
    /// </summary>
    /// <param name="jwksJson">
    /// The JWKS JSON string from <c>client_metadata.jwks</c>, e.g.
    /// <c>{"keys":[{"crv":"P-256","kty":"EC","use":"enc","x":"...","y":"..."}]}</c>.
    /// </param>
    /// <param name="base64UrlDecoder">Delegate for Base64url decoding.</param>
    /// <param name="pool">Memory pool for the returned key material.</param>
    /// <returns>
    /// The encryption public key as uncompressed point bytes. The caller owns and must dispose.
    /// </returns>
    /// <exception cref="FormatException">
    /// Thrown when the JWKS does not contain a valid EC P-256 key with <c>use=enc</c>,
    /// or when the key point is not on the P-256 curve.
    /// </exception>
    public static PublicKeyMemory ExtractP256EncryptionKey(
        string jwksJson,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> pool)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jwksJson);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        ReadOnlySpan<byte> json = System.Text.Encoding.UTF8.GetBytes(jwksJson);

        //JWKS format per RFC 7517 §5: {"keys":[{<JWK>},{<JWK>},...]}
        //Extract fields from the first key object in the array.
        string? crv = JwkJsonReader.ExtractNestedStringValueFromArray(json, "keys"u8, "crv"u8);
        string? kty = JwkJsonReader.ExtractNestedStringValueFromArray(json, "keys"u8, "kty"u8);
        string? use = JwkJsonReader.ExtractNestedStringValueFromArray(json, "keys"u8, "use"u8);
        string? x = JwkJsonReader.ExtractNestedStringValueFromArray(json, "keys"u8, "x"u8);
        string? y = JwkJsonReader.ExtractNestedStringValueFromArray(json, "keys"u8, "y"u8);

        if(kty is null || crv is null || x is null || y is null)
        {
            throw new FormatException(
                "JWKS does not contain a key with required EC fields " +
                $"'{WellKnownJwkValues.Kty}', '{WellKnownJwkValues.Crv}', " +
                $"'{WellKnownJwkValues.X}', and '{WellKnownJwkValues.Y}'.");
        }

        if(!WellKnownKeyTypeValues.IsEc(kty))
        {
            throw new FormatException(
                $"JWKS key has '{WellKnownJwkValues.Kty}'='{kty}'. " +
                $"Only '{WellKnownKeyTypeValues.Ec}' keys are supported for ECDH-ES encryption.");
        }

        if(!WellKnownCurveValues.IsP256(crv))
        {
            throw new FormatException(
                $"JWKS key has '{WellKnownJwkValues.Crv}'='{crv}'. " +
                $"Only '{WellKnownCurveValues.P256}' is supported for HAIP 1.0 ECDH-ES.");
        }

        if(use is not null && !string.Equals(use, "enc", StringComparison.Ordinal))
        {
            throw new FormatException(
                $"JWKS key has 'use'='{use}'. Expected 'enc' for an encryption key.");
        }

        using IMemoryOwner<byte> xOwner = base64UrlDecoder(x, pool);
        using IMemoryOwner<byte> yOwner = base64UrlDecoder(y, pool);

        ReadOnlySpan<byte> xSpan = xOwner.Memory.Span;
        ReadOnlySpan<byte> ySpan = yOwner.Memory.Span;

        if(!EllipticCurveUtilities.CheckPointOnCurve(xSpan, ySpan, EllipticCurveTypes.P256))
        {
            throw new FormatException(
                "JWKS encryption key point is not on the P-256 curve. Possible invalid curve attack.");
        }

        //Encode as uncompressed point: 0x04 || X || Y.
        int totalLength = 1 + xSpan.Length + ySpan.Length;
        IMemoryOwner<byte> owner = pool.Rent(totalLength);
        owner.Memory.Span[0] = 0x04;
        xSpan.CopyTo(owner.Memory.Span[1..]);
        ySpan.CopyTo(owner.Memory.Span[(1 + xSpan.Length)..]);

        return new PublicKeyMemory(owner, CryptoTags.P256ExchangePublicKey);
    }
}
