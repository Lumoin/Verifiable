using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography;

/// <summary>
/// KDFe - the TPM 2.0 key derivation function for ECDH-derived secrets (a digest-based one-pass KDF,
/// the SP800-56C / SP800-56A single-step construction).
/// </summary>
/// <remarks>
/// <para>
/// KDFe derives a value (for example the salt of a salted session, or the seed for a duplicated object) from a
/// Diffie-Hellman shared value <c>Z</c> plus a use label and two party-info fields. It is defined in the TCG
/// TPM 2.0 Library, Part 1, Section 9.4.10.3:
/// </para>
/// <code>
/// KDFe(hashAlg, Z, label, partyUInfo, partyVInfo, bits):
///   for i in 1..ceil(bits / digestBits):
///     K_i = H_hashAlg([i]_32 || Z || label || 0x00 || partyUInfo || partyVInfo)
///   return the leftmost (bits) bits of (K_1 || K_2 || ...)
/// </code>
/// <para>
/// where <c>[x]_32</c> is a 32-bit big-endian integer. Each field is concatenated as raw octets with no length
/// prefix, and the counter starts at 1. There is no trailing length field (unlike KDFa).
/// </para>
/// <para>
/// <strong>Label terminator:</strong> the reference TPM's <c>CryptKDFe</c> does not itself append a NUL octet
/// (NIST SP800-56C r2), but every KDFe label the TPM uses is a NUL-terminated string and the TPM verifies that
/// terminator on the decrypt side, so the NUL octet is part of the hashed input. This implementation appends a
/// single <c>0x00</c> after the ASCII <paramref name="label"/> to reproduce exactly that input - callers pass
/// the bare label (for example <c>"SECRET"</c>), not a pre-terminated one.
/// </para>
/// <para>
/// The inner hash routes through the registered <see cref="ComputeDigestDelegate"/> via
/// <see cref="CryptographicKeyEvents.ComputeDigestAsync(ReadOnlyMemory{byte}, int, Tag, MemoryPool{byte}, System.Collections.Frozen.FrozenDictionary{string, object}?, string?, CancellationToken)"/>,
/// so KDFe inherits the same observability and provenance stamping as every other digest. The hash family is
/// carried inline on the <see cref="Tag"/> via <see cref="HashAlgorithmName"/> because TPM sessions may use
/// SHA-1 (which the convenience <see cref="CryptoTags"/> deliberately omit).
/// </para>
/// <para>
/// All intermediate allocations come from the supplied <see cref="MemoryPool{T}"/>. The shared value <c>Z</c>
/// is secret, so the assembled hash input (which embeds it) is zeroed before disposal. The returned owner holds
/// derived key material; the caller must zero and dispose it after use.
/// </para>
/// </remarks>
public static class Kdfe
{
    /// <summary>
    /// Derives <paramref name="outputBits"/> bits of keying material per TPM 2.0 KDFe.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm (the TPM key's nameAlg).</param>
    /// <param name="z">The Diffie-Hellman shared value (the x-coordinate of the ECDH product), unpadded raw octets.</param>
    /// <param name="label">
    /// The use label (for example <c>"SECRET"</c>). TPM labels are ASCII; a single <c>0x00</c> octet is appended
    /// after the label octets to match the NUL-terminated label the TPM hashes, so do not include the terminator
    /// yourself.
    /// </param>
    /// <param name="partyUInfo">The x-coordinate of the ephemeral public point.</param>
    /// <param name="partyVInfo">The x-coordinate of the static TPM key's public point.</param>
    /// <param name="outputBits">The requested output length in bits. Must be a positive multiple of 8.</param>
    /// <param name="pool">The memory pool for all allocations.</param>
    /// <param name="cancellationToken">A token observed across the hash computations.</param>
    /// <returns>
    /// A pool-owned buffer whose first <c>outputBits / 8</c> octets hold the derived key material. Ownership
    /// transfers to the caller, which must zero and dispose it.
    /// </returns>
    public static async ValueTask<IMemoryOwner<byte>> DeriveAsync(
        HashAlgorithmName hashAlgorithm,
        ReadOnlyMemory<byte> z,
        string label,
        ReadOnlyMemory<byte> partyUInfo,
        ReadOnlyMemory<byte> partyVInfo,
        int outputBits,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(label);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(outputBits);

        //KDFe's only sub-octet behavior is masking the high bits of the most-significant octet; every TPM use of
        //KDFe (session salt, object seed) is octet-aligned to a digest size, so a non-octet length is rejected
        //rather than silently masked in a way no TPM agrees with.
        if(outputBits % 8 != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(outputBits), outputBits,
                "outputBits must be a positive multiple of 8.");
        }

        int digestSize = DigestSize(hashAlgorithm);
        int outputBytes = (outputBits + 7) / 8;
        int iterations = (outputBytes + digestSize - 1) / digestSize;

        Tag tag = DigestTag(hashAlgorithm);

        //One iteration's hash input: [i]_32 || Z || label || 0x00 || partyUInfo || partyVInfo.
        //Only the leading counter changes per iteration, so the buffer is built once and the counter is
        //rewritten in place for each block.
        int labelByteCount = Encoding.ASCII.GetByteCount(label);
        int inputLength =
            sizeof(uint)                  //counter.
            + z.Length
            + labelByteCount + 1          //label + terminating 0x00.
            + partyUInfo.Length
            + partyVInfo.Length;

        IMemoryOwner<byte> output = pool.Rent(outputBytes);
        using IMemoryOwner<byte> inputOwner = pool.Rent(inputLength);

        //The buffer is held as Memory across the hash awaits; Span is taken only at synchronous points (a Span
        //cannot survive an await boundary).
        Memory<byte> inputMemory = inputOwner.Memory[..inputLength];

        try
        {
            //Lay out the fixed (counter-independent) portion once; the Span is scoped to this synchronous block
            //so it never crosses the loop's await.
            {
                Span<byte> input = inputMemory.Span;
                input.Clear();
                int offset = sizeof(uint);
                z.Span.CopyTo(input[offset..]);
                offset += z.Length;
                offset += Encoding.ASCII.GetBytes(label, input[offset..]);
                input[offset] = 0x00;
                offset += 1;
                partyUInfo.Span.CopyTo(input[offset..]);
                offset += partyUInfo.Length;
                partyVInfo.Span.CopyTo(input[offset..]);
            }

            int produced = 0;
            for(uint counter = 1; counter <= iterations; counter++)
            {
                BinaryPrimitives.WriteUInt32BigEndian(inputMemory.Span[..sizeof(uint)], counter);

                using DigestValue block = await CryptographicKeyEvents.ComputeDigestAsync(
                    inputMemory,
                    outputByteLength: digestSize,
                    tag: tag,
                    pool: pool,
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                int take = Math.Min(digestSize, outputBytes - produced);
                block.AsReadOnlySpan()[..take].CopyTo(output.Memory.Span[produced..]);
                produced += take;
            }

            return output;
        }
        catch
        {
            //Zero any partially-derived key material before returning the buffer to the pool.
            output.Memory.Span.Clear();
            output.Dispose();

            throw;
        }
        finally
        {
            //The input embeds the secret shared value Z; zero it before the buffer returns to the pool.
            inputMemory.Span.Clear();
        }
    }

    private static Tag DigestTag(HashAlgorithmName hashAlgorithm) =>
        new(new Dictionary<Type, object>
        {
            [typeof(HashAlgorithmName)] = hashAlgorithm,
            [typeof(Purpose)] = Purpose.Digest,
            [typeof(EncodingScheme)] = EncodingScheme.Raw,
            [typeof(MaterialSemantics)] = MaterialSemantics.Direct
        });

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

        throw new NotSupportedException($"Hash algorithm '{hashAlgorithm.Name}' is not supported for KDFe.");
    }
}
