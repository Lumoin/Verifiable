using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The library's default <see cref="ConstructDpopProofDelegate"/>
/// implementation, composing existing <see cref="Jws.SignAsync"/> with
/// DPoP's specific payload + header shape.
/// </summary>
[DebuggerDisplay("DpopProofConstruction")]
public static class DpopProofConstruction
{
    /// <summary>
    /// Builds a DPoP proof. Composes the embedded JWK header, serialises
    /// header and claims via the configured serializer, signs via
    /// <see cref="Jws.SignAsync"/>, and returns the compact wire form.
    /// </summary>
    /// <remarks>
    /// The serializer / encoder / signing / pool parameters mirror
    /// <see cref="Jws.SignAsync"/>'s parameter set so applications wire
    /// the same delegates they use elsewhere in the library.
    /// </remarks>
    public static async ValueTask<string> BuildAsync(
        DpopProofClaims claims,
        DpopKey key,
        EncodeDelegate base64UrlEncoder,
        DpopJwsPartSerializer serializer,
        SigningDelegate signingDelegate,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(serializer);
        ArgumentNullException.ThrowIfNull(signingDelegate);
        ArgumentNullException.ThrowIfNull(memoryPool);

        DpopProofHeader header = new()
        {
            Alg = key.Alg,
            Jwk = DpopJwkUtilities.ToJwk(key.Material.PublicKey, key.Alg, base64UrlEncoder)
        };

        IReadOnlyDictionary<string, object> headerDict = serializer.SerializeHeader(header);
        IReadOnlyDictionary<string, object> payloadDict = serializer.SerializePayload(claims);

        using JwsMessage message = await Jws.SignAsync(
            headerDict,
            payloadDict,
            serializer.EncodePart,
            base64UrlEncoder,
            key.Material.PrivateKey,
            signingDelegate,
            memoryPool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(message, base64UrlEncoder);
    }
}
