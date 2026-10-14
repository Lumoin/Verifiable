using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// A DPoP signing key plus algorithm metadata. The key material is
/// non-owning — the application retains lifecycle ownership and disposes
/// it when the client session ends.
/// </summary>
/// <remarks>
/// The thumbprint is computed lazily on first access and cached. Repeated
/// requests reuse the cached value rather than re-running the SHA-256
/// computation, but the cache is per-instance — applications constructing
/// multiple <see cref="DpopKey"/> wrappers around the same underlying
/// material recompute. Cheap; not worth deduplicating.
/// </remarks>
[DebuggerDisplay("DpopKey alg={Alg,nq}")]
public sealed class DpopKey
{
    private string? cachedThumbprint;

    /// <summary>
    /// A field, not a property: a lock target must be one instance that no accessor can re-mint.
    /// </summary>
    private readonly object thumbprintLock = new();

    /// <summary>The non-owning key material the application created and manages.</summary>
    public PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> Material { get; }

    /// <summary>
    /// The JWS algorithm identifier matching the key type, e.g. <c>ES256</c>
    /// for a P-256 key.
    /// </summary>
    public string Alg { get; }


    /// <summary>
    /// Constructs a DPoP key wrapper. The caller is responsible for
    /// matching <paramref name="alg"/> to the underlying key curve.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>, of the proof's
    /// <c>alg</c>: "An identifier for a JWS asymmetric digital signature algorithm from [IANA.JOSE.ALGS]. It MUST NOT be
    /// none or an identifier for a symmetric algorithm (Message Authentication Code (MAC))." and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.6">Section 11.6</see>: "Implementers MUST ensure
    /// that only asymmetric digital signature algorithms (such as ES256) that are deemed secure can be used for signing
    /// DPoP proofs. In particular, the algorithm none MUST NOT be allowed." Every proof is built under the
    /// <see cref="Alg"/> this DPoP key carries, so the identifier is held here to the JOSE catalogue's asymmetric JWS
    /// signature identifiers (<see cref="DpopProofValidator.IsDpopProofAlg"/>, the one predicate the DPoP header
    /// factory and the servers' proof validation read as well), each sourced at its own catalogue entry: the Brainpool
    /// ECDSA and the ML-DSA identifiers among them come from the drafts their entries cite. A DPoP key declaring any
    /// other identifier, <c>none</c>, a MAC, a JWE identifier or a name the catalogue does not hold, is refused and no
    /// proof is ever built under it. Which identifiers a server accepts is that server's policy. The comparison is
    /// exact, as a JWS <c>alg</c> value is case-sensitive
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515 Section 4.1.1</see>), so a spelling
    /// in another case or with surrounding whitespace is refused.
    /// </remarks>
    /// <param name="material">The non-owning key material the application created and manages.</param>
    /// <param name="alg">The JWS algorithm identifier every proof built with this DPoP key declares.</param>
    /// <exception cref="ArgumentException">
    /// <paramref name="alg"/> is empty or is not, exactly, an asymmetric JWS signature algorithm identifier a DPoP proof
    /// may be signed under.
    /// </exception>
    public DpopKey(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> material,
        string alg)
    {
        ArgumentNullException.ThrowIfNull(material);
        ArgumentException.ThrowIfNullOrEmpty(alg);

        if(!DpopProofValidator.IsDpopProofAlg(alg))
        {
            throw new ArgumentException(
                "A DPoP proof's alg MUST be an identifier for a JWS asymmetric digital signature algorithm, never none or a MAC (RFC 9449 Sections 4.2 and 11.6).", nameof(alg));
        }

        Material = material;
        Alg = alg;
    }


    /// <summary>
    /// Returns the RFC 7638 thumbprint of this key as a base64url-encoded
    /// string, computing it on first access and caching the result.
    /// </summary>
    public string GetThumbprint(
        EncodeDelegate base64UrlEncoder,
        BaseMemoryPool memoryPool)
    {
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        if(cachedThumbprint is not null)
        {
            return cachedThumbprint;
        }
        lock(thumbprintLock)
        {
            if(cachedThumbprint is not null)
            {
                return cachedThumbprint;
            }
            cachedThumbprint = DpopJwkUtilities.ComputeThumbprint(
                Material.PublicKey, Alg, base64UrlEncoder, memoryPool);
            return cachedThumbprint;
        }
    }
}
