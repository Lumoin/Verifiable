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
    /// the RFC 7638 canonicalisation members for the key's type:
    /// <c>kty</c>, <c>crv</c>, <c>x</c>, <c>y</c> for EC keys;
    /// <c>kty</c>, <c>n</c>, <c>e</c> for RSA keys;
    /// <c>kty</c>, <c>crv</c>, <c>x</c> for OKP keys (Ed25519).
    /// No <c>alg</c> or <c>use</c> are emitted because the JWS protected
    /// header carries <c>alg</c> separately and the JWK in a DPoP proof
    /// is implicitly a signature key.
    /// </summary>
    /// <remarks>
    /// RFC 9449 §4.2 lists ES256/ES384/ES512, RS256/RS384/RS512,
    /// PS256/PS384/PS512, and EdDSA as DPoP-supported algorithms; this
    /// helper produces the JWK shape for the key family backing the
    /// requested <paramref name="alg"/>. The underlying converter at
    /// <see cref="CryptoFormatConversions.DefaultAlgorithmToJwkConverter"/>
    /// is the single source of truth for the algorithm-to-JWK mapping.
    /// </remarks>
    public static IReadOnlyDictionary<string, string> ToJwk(
        PublicKeyMemory publicKey,
        string alg,
        EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentException.ThrowIfNullOrEmpty(alg);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);

        CryptoAlgorithm cryptoAlg = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();

        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            cryptoAlg, purpose, publicKey.AsReadOnlySpan(), base64UrlEncoder);

        string kty = jwk.Kty
            ?? throw new InvalidOperationException("DefaultAlgorithmToJwkConverter must produce 'kty'.");

        return kty switch
        {
            string ec when string.Equals(ec, WellKnownKeyTypeValues.Ec, StringComparison.Ordinal) =>
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [WellKnownJwkMemberNames.Kty] = kty,
                    [WellKnownJwkMemberNames.Crv] = jwk.Crv
                        ?? throw new InvalidOperationException("DefaultAlgorithmToJwkConverter must produce 'crv' for EC keys."),
                    [WellKnownJwkMemberNames.X] = jwk.X
                        ?? throw new InvalidOperationException("DefaultAlgorithmToJwkConverter must produce 'x' for EC keys."),
                    [WellKnownJwkMemberNames.Y] = jwk.Y
                        ?? throw new InvalidOperationException("DefaultAlgorithmToJwkConverter must produce 'y' for EC keys.")
                },

            string rsa when string.Equals(rsa, WellKnownKeyTypeValues.Rsa, StringComparison.Ordinal) =>
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [WellKnownJwkMemberNames.Kty] = kty,
                    [WellKnownJwkMemberNames.N] = jwk.N
                        ?? throw new InvalidOperationException("DefaultAlgorithmToJwkConverter must produce 'n' for RSA keys."),
                    [WellKnownJwkMemberNames.E] = jwk.E
                        ?? throw new InvalidOperationException("DefaultAlgorithmToJwkConverter must produce 'e' for RSA keys.")
                },

            string okp when string.Equals(okp, WellKnownKeyTypeValues.Okp, StringComparison.Ordinal) =>
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [WellKnownJwkMemberNames.Kty] = kty,
                    [WellKnownJwkMemberNames.Crv] = jwk.Crv
                        ?? throw new InvalidOperationException("DefaultAlgorithmToJwkConverter must produce 'crv' for OKP keys."),
                    [WellKnownJwkMemberNames.X] = jwk.X
                        ?? throw new InvalidOperationException("DefaultAlgorithmToJwkConverter must produce 'x' for OKP keys.")
                },

            //Algorithm Key Pair (ML-DSA et al.): unlike the RFC 7518 families, alg is a
            //REQUIRED member of an AKP JWK and participates in its thumbprint canon —
            //the lexicographic sort yields {alg, kty, pub}.
            string akp when string.Equals(akp, WellKnownKeyTypeValues.Akp, StringComparison.Ordinal) =>
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [WellKnownJwkMemberNames.Kty] = kty,
                    [WellKnownJwkMemberNames.Alg] = jwk.Alg
                        ?? throw new InvalidOperationException("DefaultAlgorithmToJwkConverter must produce 'alg' for AKP keys."),
                    [WellKnownJwkMemberNames.Pub] = jwk.Pub
                        ?? throw new InvalidOperationException("DefaultAlgorithmToJwkConverter must produce 'pub' for AKP keys.")
                },

            _ => throw new InvalidOperationException(
                $"DPoP JWK serialization received an unexpected kty '{kty}' from the algorithm-to-JWK converter for alg '{alg}'.")
        };
    }


    /// <summary>
    /// Computes the RFC 7638 thumbprint of <paramref name="publicKey"/> as a
    /// base64url-encoded string. Projects the key to a JWK via
    /// <see cref="ToJwk"/> and forwards to the dictionary overload.
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

        IReadOnlyDictionary<string, string> jwk = ToJwk(publicKey, alg, base64UrlEncoder);
        return ComputeThumbprintFromJwk(jwk, base64UrlEncoder, memoryPool);
    }


    /// <summary>
    /// Computes the RFC 7638 thumbprint of an already-projected JWK as a
    /// base64url-encoded string. Composes
    /// <see cref="JwkThumbprintUtilities.ComputeGenericThumbprint(MemoryPool{byte}, IDictionary{string, string})"/>
    /// which sorts the JWK members lexicographically per RFC 7638 §3.1,
    /// writes the canonical JSON, and hashes with SHA-256. No kty dispatch
    /// is required here — RFC 7638 §3.2's "required members differ per
    /// kty" concern is handled by the caller supplying only those members
    /// (which <see cref="ToJwk"/> already does), and by the lexicographic-
    /// sort step inside the JCose utility.
    /// </summary>
    public static string ComputeThumbprintFromJwk(
        IReadOnlyDictionary<string, string> jwk,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(jwk);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        //ComputeGenericThumbprint requires IDictionary; copy the read-only
        //view into a fresh mutable dictionary. The JWK has at most a
        //handful of entries — a per-call allocation that's negligible
        //against the SHA-256 work that follows.
        Dictionary<string, string> jwkDict = new(jwk, StringComparer.Ordinal);
        using IMemoryOwner<byte> hash = JwkThumbprintUtilities.ComputeGenericThumbprint(
            memoryPool, jwkDict);

        return base64UrlEncoder(hash.Memory.Span);
    }


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="jwk"/> carries any RFC 7518
    /// private or symmetric key member (<c>d</c>, <c>p</c>, <c>q</c>, <c>dp</c>,
    /// <c>dq</c>, <c>qi</c>, <c>oth</c>, <c>k</c>). A DPoP proof's embedded JWK MUST be
    /// a public key per RFC 9449 §4.2, so a caller rejects a proof for which this holds.
    /// Delegates to the neutral <see cref="WellKnownJwkMemberNames.ContainsPrivateOrSymmetricMember"/>
    /// shared with the federation Entity Statement JWKS check.
    /// </summary>
    public static bool ContainsPrivateKeyMaterial(IReadOnlyDictionary<string, string> jwk)
    {
        ArgumentNullException.ThrowIfNull(jwk);

        return WellKnownJwkMemberNames.ContainsPrivateOrSymmetricMember(jwk.Keys);
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

        Tag tag = Tag.Create(algorithm).With(purpose).With(scheme);

        return new PublicKeyMemory(keyMaterial, tag);
    }
}
