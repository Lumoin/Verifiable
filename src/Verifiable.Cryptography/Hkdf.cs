using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography;

/// <summary>
/// HKDF - the extract-then-expand HMAC-based key derivation function defined by
/// <see href="https://www.rfc-editor.org/rfc/rfc5869">RFC 5869</see>.
/// </summary>
/// <remarks>
/// <para>
/// HKDF derives keying material from a (possibly non-secret) input keying material value in two
/// stages:
/// </para>
/// <code>
/// HKDF-Extract(salt, IKM) -&gt; PRK:
///   PRK = HMAC-Hash(salt, IKM)
///
/// HKDF-Expand(PRK, info, L) -&gt; OKM:
///   N = ceil(L / HashLen)
///   T(0) = empty string
///   T(i) = HMAC-Hash(PRK, T(i-1) | info | i) for i = 1..N, where i is a single octet
///   OKM = the leftmost L octets of T(1) | T(2) | ... | T(N)
/// </code>
/// <para>
/// This is a distinct construction from <see cref="Kdfa"/> (TPM 2.0's SP800-108 counter-mode KDF,
/// which places a 32-bit counter and a trailing 32-bit length field around a NUL-terminated label)
/// and <see cref="Kdfe"/> (TPM 2.0's SP800-56C one-step KDF, which has no salt/extract stage at
/// all) - HKDF's extract stage folds a separate, possibly-empty <c>salt</c> into the input before
/// any expansion happens, and its per-round counter is a single trailing octet rather than a
/// leading 32-bit field.
/// </para>
/// <para>
/// The inner HMAC routes through the registered <see cref="ComputeHmacDelegate"/> via
/// <see cref="CryptographicKeyEvents.ComputeHmacAsync(ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, int, Tag, MemoryPool{byte}, System.Collections.Frozen.FrozenDictionary{string, object}?, string?, CancellationToken)"/>
/// - the exact same seam <see cref="Kdfa"/> composes its own HMAC rounds through - so HKDF inherits
/// the same observability, provenance stamping, and backend-agility (a hardware-bound HMAC backend
/// serves HKDF exactly as it serves KDFa) without importing a provider assembly or calling
/// <see cref="System.Security.Cryptography.HKDF"/> directly.
/// </para>
/// <para>
/// All intermediate allocations come from the supplied <see cref="MemoryPool{T}"/> and are zeroed
/// before disposal. The returned owner holds derived (and, for <see cref="ExtractAsync"/>, secret
/// pseudorandom) key material; the caller must zero and dispose it after use.
/// </para>
/// </remarks>
public static class Hkdf
{
    /// <summary>
    /// Performs the HKDF-Extract stage: <c>PRK = HMAC-Hash(salt, IKM)</c>.
    /// </summary>
    /// <param name="hashAlgorithm">The underlying hash algorithm (SHA-256 for every CTAP PIN/UV auth protocol two use).</param>
    /// <param name="salt">
    /// The (optionally empty) salt value. An empty <paramref name="salt"/> is not special-cased:
    /// HMAC zero-pads a key shorter than the hash's block size, so an empty salt and a
    /// <c>HashLen</c>-byte all-zero salt hash identically, matching RFC 5869 §2.2's note that
    /// "if not provided, [salt] is set to a string of HashLen zeros" is a convenience framing of
    /// what the HMAC construction already does.
    /// </param>
    /// <param name="ikm">The input keying material - the secret (or shared) value being derived from.</param>
    /// <param name="pool">The memory pool for the returned buffer.</param>
    /// <param name="cancellationToken">A token observed by the underlying HMAC computation.</param>
    /// <returns>
    /// A pool-owned buffer holding the <c>HashLen</c>-byte pseudorandom key (PRK). Ownership
    /// transfers to the caller, which must zero and dispose it.
    /// </returns>
    public static async ValueTask<IMemoryOwner<byte>> ExtractAsync(
        HashAlgorithmName hashAlgorithm,
        ReadOnlyMemory<byte> salt,
        ReadOnlyMemory<byte> ikm,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int digestSize = DigestSize(hashAlgorithm);
        Tag tag = HmacTag(hashAlgorithm);

        //HKDF-Extract's HMAC key is the salt; its message is the IKM (RFC 5869 §2.2 - "'IKM' is
        //used as the HMAC input, not as the HMAC key").
        using HmacValue prk = await CryptographicKeyEvents.ComputeHmacAsync(
            ikm, salt, digestSize, tag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> output = pool.Rent(digestSize);
        prk.AsReadOnlySpan().CopyTo(output.Memory.Span);

        return output;
    }


    /// <summary>
    /// Performs the HKDF-Expand stage: <c>OKM = T(1) | T(2) | ... | T(N)</c>, truncated to
    /// <paramref name="outputLength"/> octets, where <c>T(i) = HMAC-Hash(PRK, T(i-1) | info | i)</c>.
    /// </summary>
    /// <param name="hashAlgorithm">The underlying hash algorithm.</param>
    /// <param name="prk">The pseudorandom key from <see cref="ExtractAsync"/> (or any <c>HashLen</c>-or-longer key).</param>
    /// <param name="info">Optional context and application-specific information; may be empty.</param>
    /// <param name="outputLength">The requested output length in octets. Must be positive and at most <c>255 * HashLen</c> (RFC 5869 §2.3).</param>
    /// <param name="pool">The memory pool for the returned buffer and intermediate rounds.</param>
    /// <param name="cancellationToken">A token observed across the HMAC rounds.</param>
    /// <returns>
    /// A pool-owned buffer holding the <paramref name="outputLength"/>-byte output keying material
    /// (OKM). Ownership transfers to the caller, which must zero and dispose it.
    /// </returns>
    public static async ValueTask<IMemoryOwner<byte>> ExpandAsync(
        HashAlgorithmName hashAlgorithm,
        ReadOnlyMemory<byte> prk,
        ReadOnlyMemory<byte> info,
        int outputLength,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(outputLength);

        int digestSize = DigestSize(hashAlgorithm);

        //RFC 5869 §2.3: L (outputLength) MUST NOT exceed 255 * HashLen, the largest length HKDF's
        //single-octet round counter can address.
        if(outputLength > 255 * digestSize)
        {
            throw new ArgumentOutOfRangeException(nameof(outputLength), outputLength,
                $"outputLength must not exceed 255 * {digestSize} (255 * HashLen) for this hash algorithm.");
        }

        Tag tag = HmacTag(hashAlgorithm);
        int iterations = (outputLength + digestSize - 1) / digestSize;

        IMemoryOwner<byte> output = pool.Rent(outputLength);

        //T(i-1) is carried in this single reusable buffer across rounds; chainLength is 0 before the
        //first round (T(0) is the empty string) and digestSize from the second round onward.
        using IMemoryOwner<byte> chain = pool.Rent(digestSize);
        int chainLength = 0;

        try
        {
            int produced = 0;
            for(int counter = 1; counter <= iterations; ++counter)
            {
                int inputLength = chainLength + info.Length + 1;
                using IMemoryOwner<byte> inputOwner = pool.Rent(inputLength);
                Memory<byte> inputMemory = inputOwner.Memory[..inputLength];

                try
                {
                    Span<byte> input = inputMemory.Span;
                    chain.Memory.Span[..chainLength].CopyTo(input);
                    info.Span.CopyTo(input[chainLength..]);
                    input[chainLength + info.Length] = (byte)counter;

                    using HmacValue block = await CryptographicKeyEvents.ComputeHmacAsync(
                        inputMemory,
                        prk,
                        digestSize,
                        tag,
                        pool,
                        cancellationToken: cancellationToken).ConfigureAwait(false);

                    int take = Math.Min(digestSize, outputLength - produced);
                    block.AsReadOnlySpan()[..take].CopyTo(output.Memory.Span[produced..]);
                    produced += take;

                    block.AsReadOnlySpan().CopyTo(chain.Memory.Span);
                    chainLength = digestSize;
                }
                finally
                {
                    inputMemory.Span.Clear();
                }
            }

            return output;
        }
        catch
        {
            //Zero any partially-derived output keying material before returning the buffer to the pool.
            output.Memory.Span.Clear();
            output.Dispose();

            throw;
        }
        finally
        {
            chain.Memory.Span.Clear();
        }
    }


    /// <summary>
    /// Performs the full extract-then-expand HKDF derivation: <see cref="ExtractAsync"/> followed by
    /// <see cref="ExpandAsync"/>, disposing the intermediate PRK.
    /// </summary>
    /// <param name="hashAlgorithm">The underlying hash algorithm.</param>
    /// <param name="salt">The (optionally empty) salt value.</param>
    /// <param name="ikm">The input keying material.</param>
    /// <param name="info">Optional context and application-specific information; may be empty.</param>
    /// <param name="outputLength">The requested output length in octets.</param>
    /// <param name="pool">The memory pool for every allocation this call makes.</param>
    /// <param name="cancellationToken">A token observed across the HMAC rounds.</param>
    /// <returns>
    /// A pool-owned buffer holding the <paramref name="outputLength"/>-byte output keying material.
    /// Ownership transfers to the caller, which must zero and dispose it.
    /// </returns>
    public static async ValueTask<IMemoryOwner<byte>> DeriveAsync(
        HashAlgorithmName hashAlgorithm,
        ReadOnlyMemory<byte> salt,
        ReadOnlyMemory<byte> ikm,
        ReadOnlyMemory<byte> info,
        int outputLength,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> prk = await ExtractAsync(hashAlgorithm, salt, ikm, pool, cancellationToken).ConfigureAwait(false);
        try
        {
            return await ExpandAsync(hashAlgorithm, prk.Memory, info, outputLength, pool, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            prk.Memory.Span.Clear();
            prk.Dispose();
        }
    }


    /// <summary>
    /// Builds the <see cref="Tag"/> HKDF's inner HMAC rounds carry - the same composition
    /// <see cref="Kdfa"/> uses for its own HMAC seam, so the two derivation functions share
    /// identical CBOM/OTel provenance shape for the same hash family.
    /// </summary>
    private static Tag HmacTag(HashAlgorithmName hashAlgorithm) =>
        Tag.Create(hashAlgorithm).With(Purpose.Hmac).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);


    /// <summary>
    /// Resolves the digest output size in bytes for <paramref name="hashAlgorithm"/>.
    /// </summary>
    private static int DigestSize(HashAlgorithmName hashAlgorithm)
    {
        if(hashAlgorithm == HashAlgorithmName.SHA256)
        {
            return 32;
        }

        if(hashAlgorithm == HashAlgorithmName.SHA384)
        {
            return 48;
        }

        if(hashAlgorithm == HashAlgorithmName.SHA512)
        {
            return 64;
        }

        if(hashAlgorithm == HashAlgorithmName.SHA1)
        {
            return 20;
        }

        throw new NotSupportedException($"Hash algorithm '{hashAlgorithm.Name}' is not supported for HKDF.");
    }
}
