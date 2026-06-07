using System.Buffers;
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
    public DpopKey(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> material,
        string alg)
    {
        ArgumentNullException.ThrowIfNull(material);
        ArgumentException.ThrowIfNullOrEmpty(alg);

        Material = material;
        Alg = alg;
    }


    /// <summary>
    /// Returns the RFC 7638 thumbprint of this key as a base64url-encoded
    /// string, computing it on first access and caching the result.
    /// </summary>
    public string GetThumbprint(
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool)
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
