using System.Buffers;
using System.Collections.Frozen;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Client;

/// <summary>
/// One of RFC 7518 Section 3.2's HMAC algorithms a <c>client_secret_jwt</c> assertion is MACed under: the JWS <c>alg</c>
/// it is named by, the hash the HMAC runs over, the octets the MAC carries and the tags the key and the MAC are computed
/// and carried under. Its <see cref="SignAsync"/> is the <see cref="SigningDelegate"/> the library's JWS composition is
/// handed, computing the MAC through the registered <see cref="ComputeHmacDelegate"/>.
/// </summary>
internal sealed class ClientSecretMac
{
    /// <summary>HMAC SHA-256 (<c>HS256</c>).</summary>
    private static ClientSecretMac Hs256 { get; } =
        new(WellKnownJwaValues.Hs256, HMACSHA256.HashSizeInBytes, CryptoTags.HmacSha256Key, CryptoTags.HmacSha256Value);

    /// <summary>HMAC SHA-384 (<c>HS384</c>).</summary>
    private static ClientSecretMac Hs384 { get; } =
        new(WellKnownJwaValues.Hs384, HMACSHA384.HashSizeInBytes, CryptoTags.HmacSha384Key, CryptoTags.HmacSha384Value);

    /// <summary>HMAC SHA-512 (<c>HS512</c>).</summary>
    private static ClientSecretMac Hs512 { get; } =
        new(WellKnownJwaValues.Hs512, HMACSHA512.HashSizeInBytes, CryptoTags.HmacSha512Key, CryptoTags.HmacSha512Value);


    /// <summary>Creates one algorithm's description.</summary>
    /// <param name="algorithm">The JWS <c>alg</c>.</param>
    /// <param name="length">The octets the MAC carries, the hash's output.</param>
    /// <param name="keyTag">The tag the key is computed under, naming the hash.</param>
    /// <param name="valueTag">The tag the MAC is carried under as the JWS signature.</param>
    private ClientSecretMac(string algorithm, int length, Tag keyTag, Tag valueTag)
    {
        Algorithm = algorithm;
        Length = length;
        KeyTag = keyTag;
        ValueTag = valueTag;
    }


    /// <summary>The JWS <c>alg</c> the algorithm is named by.</summary>
    public string Algorithm { get; }

    /// <summary>The octets the MAC carries, the hash's output, and the fewest the key may carry (RFC 7518 Section 3.2).</summary>
    public int Length { get; }

    /// <summary>The tag the key is computed under, naming the hash the HMAC runs over.</summary>
    private Tag KeyTag { get; }

    /// <summary>The tag the MAC is carried under as the JWS signature.</summary>
    private Tag ValueTag { get; }


    /// <summary>The HMAC algorithm a JWS <c>alg</c> names (RFC 7518 Section 3.2).</summary>
    /// <param name="algorithm">The <c>alg</c>.</param>
    /// <returns>The algorithm.</returns>
    /// <exception cref="ArgumentException">The <c>alg</c> names none of <c>HS256</c>, <c>HS384</c> and <c>HS512</c>.</exception>
    public static ClientSecretMac Of(string algorithm) => algorithm switch
    {
        _ when WellKnownJwaValues.IsHs256(algorithm) => Hs256,
        _ when WellKnownJwaValues.IsHs384(algorithm) => Hs384,
        _ when WellKnownJwaValues.IsHs512(algorithm) => Hs512,
        _ => throw new ArgumentException(
            $"A client_secret_jwt assertion is MACed under an HMAC algorithm of RFC 7518 Section 3.2 (HS256, HS384 or HS512); '{algorithm}' is none.",
            nameof(algorithm))
    };


    /// <summary>
    /// The MAC of a JWS signing input under the client secret, computed through the registered
    /// <see cref="ComputeHmacDelegate"/> and handed to the JWS composition as its signature, in memory rented from the pool,
    /// which the signature owns.
    /// </summary>
    /// <param name="privateKeyBytes">The client secret's octets.</param>
    /// <param name="dataToSign">The JWS signing input.</param>
    /// <param name="signaturePool">The pool the MAC's octets are rented from.</param>
    /// <param name="context">The operation context, handed to the HMAC function.</param>
    /// <param name="cancellationToken">Cancels the MAC.</param>
    /// <returns>The MAC as the signature, and no event: the HMAC function's own event is published by its seam.</returns>
    public async ValueTask<(Signature Signature, CryptoEvent? Event)> SignAsync(
        ReadOnlyMemory<byte> privateKeyBytes,
        ReadOnlyMemory<byte> dataToSign,
        BaseMemoryPool signaturePool,
        FrozenDictionary<string, object>? context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signaturePool);

        using HmacValue mac = await CryptographicKeyEvents.ComputeHmacAsync(
            dataToSign,
            privateKeyBytes,
            Length,
            KeyTag,
            signaturePool,
            context,
            qualifier: null,
            cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> owner = signaturePool.Rent(Length);

        try
        {
            mac.AsReadOnlySpan()[..Length].CopyTo(owner.Memory.Span);
        }
        catch
        {
            owner.Dispose();

            throw;
        }

        return (new Signature(owner, ValueTag), null);
    }
}
