using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// Helpers for serialising a public key to a JWK suitable for embedding
/// in a DPoP proof header, computing its RFC 7638 thumbprint, and
/// reconstructing a <see cref="PublicKeyMemory"/> from a JWK on the
/// receiving side.
/// </summary>
/// <remarks>
/// All three helpers compose existing JCose/Cryptography machinery —
/// <see cref="CryptoFormatConversions.DefaultAlgorithmToJwkConverter"/> for
/// the outbound direction,
/// <see cref="CryptoFormatConversions.DefaultJwkToAlgorithmConverter"/>
/// for the inbound direction, and
/// <see cref="JwkThumbprintUtilities.ComputeECThumbprint(MemoryPool{byte}, string, string, string, string)"/>
/// for the canonical RFC 7638 hash.
/// </remarks>
[DebuggerDisplay("DpopJwkUtilities")]
public static class DpopJwkUtilities
{
    /// <summary>
    /// Serialises <paramref name="publicKey"/> to a JWK dictionary suitable
    /// for the <c>jwk</c> header of a DPoP proof. The dictionary contains
    /// the RFC 7638 canonicalisation members (<c>kty</c>, <c>crv</c>,
    /// <c>x</c>, <c>y</c> for EC keys); no <c>alg</c> or <c>use</c> are
    /// emitted because the JWS protected header carries <c>alg</c>
    /// separately and the JWK in a DPoP proof is implicitly a signature key.
    /// </summary>
    public static IReadOnlyDictionary<string, string> ToJwk(
        PublicKeyMemory publicKey,
        string alg,
        EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentException.ThrowIfNullOrEmpty(alg);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);

        if(!WellKnownJwaValues.IsEcdsa(alg))
        {
            throw new NotSupportedException(
                $"DPoP JWK serialization currently supports ECDSA algorithms only; got '{alg}'.");
        }

        CryptoAlgorithm cryptoAlg = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();

        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            cryptoAlg, purpose, publicKey.AsReadOnlySpan(), base64UrlEncoder);

        Dictionary<string, string> result = new(StringComparer.Ordinal)
        {
            [WellKnownJwkMemberNames.Kty] = jwk.Kty
                ?? throw new InvalidOperationException("DefaultAlgorithmToJwkConverter must produce 'kty'."),
            [WellKnownJwkMemberNames.Crv] = jwk.Crv
                ?? throw new InvalidOperationException("DefaultAlgorithmToJwkConverter must produce 'crv' for EC keys."),
            [WellKnownJwkMemberNames.X] = jwk.X
                ?? throw new InvalidOperationException("DefaultAlgorithmToJwkConverter must produce 'x' for EC keys."),
            [WellKnownJwkMemberNames.Y] = jwk.Y
                ?? throw new InvalidOperationException("DefaultAlgorithmToJwkConverter must produce 'y' for EC keys.")
        };

        return result;
    }


    /// <summary>
    /// Computes the RFC 7638 thumbprint of <paramref name="publicKey"/> as a
    /// base64url-encoded string. Composes
    /// <see cref="JwkThumbprintUtilities.ComputeECThumbprint(MemoryPool{byte}, string, string, string, string)"/>
    /// with the canonical JWK produced by <see cref="ToJwk"/>.
    /// </summary>
    public static string ComputeThumbprint(
        PublicKeyMemory publicKey,
        string alg,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentException.ThrowIfNullOrEmpty(alg);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        if(!WellKnownJwaValues.IsEcdsa(alg))
        {
            throw new NotSupportedException(
                $"DPoP thumbprint currently supports ECDSA keys only; got '{alg}'.");
        }

        IReadOnlyDictionary<string, string> jwk = ToJwk(publicKey, alg, base64UrlEncoder);

        using IMemoryOwner<byte> hash = JwkThumbprintUtilities.ComputeECThumbprint(
            memoryPool,
            jwk[WellKnownJwkMemberNames.Crv],
            jwk[WellKnownJwkMemberNames.Kty],
            jwk[WellKnownJwkMemberNames.X],
            jwk[WellKnownJwkMemberNames.Y]);

        return base64UrlEncoder(hash.Memory.Span);
    }


    /// <summary>
    /// Reconstructs a <see cref="PublicKeyMemory"/> from a JWK dictionary
    /// embedded in a DPoP proof header. The <paramref name="alg"/> parameter
    /// is currently informational — the underlying converter resolves the
    /// algorithm from <c>kty</c> and <c>crv</c> per RFC 7518 — but is
    /// retained so the caller's intent is documented at the call site.
    /// </summary>
    public static PublicKeyMemory PublicKeyFromJwk(
        IReadOnlyDictionary<string, string> jwk,
        string alg,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(jwk);
        ArgumentException.ThrowIfNullOrEmpty(alg);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        Dictionary<string, object> jwkDict = new(jwk.Count, StringComparer.Ordinal);
        foreach(KeyValuePair<string, string> entry in jwk)
        {
            jwkDict[entry.Key] = entry.Value;
        }

        (CryptoAlgorithm algorithm, Purpose purpose, EncodingScheme scheme, IMemoryOwner<byte> keyMaterial) =
            CryptoFormatConversions.DefaultJwkToAlgorithmConverter(jwkDict, memoryPool, base64UrlDecoder);

        Tag tag = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = algorithm,
            [typeof(Purpose)] = purpose,
            [typeof(EncodingScheme)] = scheme
        });

        return new PublicKeyMemory(keyMaterial, tag);
    }
}
