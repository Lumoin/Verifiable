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
/// KDFa - the TPM 2.0 key derivation function (a counter-mode HMAC KDF, equivalent to the
/// SP800-108 counter-mode construction with a fixed input layout).
/// </summary>
/// <remarks>
/// <para>
/// KDFa derives keying material - session keys, HMAC keys, and the keys/masks used for command
/// parameter encryption - from a key plus a label and two context fields. It is defined in the
/// TCG TPM 2.0 Library, Part 1, Section 11.4.10.2:
/// </para>
/// <code>
/// KDFa(hashAlg, key, label, contextU, contextV, bits):
///   for i in 1..ceil(bits / digestBits):
///     K_i = HMAC_hashAlg(key, [i]_32 || label || 0x00 || contextU || contextV || [bits]_32)
///   return the leftmost (bits) bits of (K_1 || K_2 || ...)
/// </code>
/// <para>
/// where <c>[x]_32</c> is a 32-bit big-endian integer, <c>label</c> is an octet string followed by a
/// single terminating <c>0x00</c> octet, and <c>bits</c> is the requested output length in bits placed
/// at the end of every iteration's input.
/// </para>
/// <para>
/// The inner HMAC routes through the registered <see cref="ComputeHmacDelegate"/> via
/// <see cref="CryptographicKeyEvents.ComputeHmacAsync(ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, int, Tag, MemoryPool{byte}, System.Collections.Frozen.FrozenDictionary{string, object}?, string?, CancellationToken)"/>,
/// so KDFa inherits the same observability and provenance stamping as every other MAC. The function is
/// asynchronous because the HMAC backend may be hardware-bound. The hash family is carried inline on the
/// <see cref="Tag"/> via <see cref="HashAlgorithmName"/> rather than a convenience <see cref="CryptoTags"/>
/// entry, because TPM sessions may use SHA-1 (which those convenience tags deliberately omit).
/// </para>
/// <para>
/// All intermediate allocations come from the supplied <see cref="MemoryPool{T}"/> and are zeroed before
/// disposal. The returned owner holds secret key material; the caller must zero and dispose it after use.
/// </para>
/// </remarks>
public static class Kdfa
{
    /// <summary>
    /// Derives <paramref name="outputBits"/> bits of keying material per TPM 2.0 KDFa.
    /// </summary>
    /// <param name="hashAlgorithm">The HMAC hash algorithm (the TPM session's hash).</param>
    /// <param name="key">The KDF key (for a session key this is <c>salt || authValue</c>).</param>
    /// <param name="label">
    /// The use label (for example <c>"ATH"</c>, <c>"CFB"</c>, <c>"XOR"</c>). TPM labels are ASCII; a single
    /// <c>0x00</c> octet is appended after the label octets per the spec, so do not include the terminator
    /// yourself.
    /// </param>
    /// <param name="contextU">The first context field (for a session key, <c>nonceTPM</c>).</param>
    /// <param name="contextV">The second context field (for a session key, <c>nonceCaller</c>).</param>
    /// <param name="outputBits">The requested output length in bits. Must be a positive multiple of 8.</param>
    /// <param name="pool">The memory pool for all allocations.</param>
    /// <param name="cancellationToken">A token observed across the HMAC computations.</param>
    /// <returns>
    /// A pool-owned buffer whose first <c>outputBits / 8</c> octets hold the derived key material (the pool
    /// may return a larger buffer; the caller knows the length from <paramref name="outputBits"/>).
    /// Ownership transfers to the caller, which must zero and dispose it.
    /// </returns>
    public static async ValueTask<IMemoryOwner<byte>> DeriveAsync(
        HashAlgorithmName hashAlgorithm,
        ReadOnlyMemory<byte> key,
        string label,
        ReadOnlyMemory<byte> contextU,
        ReadOnlyMemory<byte> contextV,
        int outputBits,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(label);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(outputBits);

        //KDFa itself performs no sub-octet masking (the caller would have to), and every TPM use of KDFa
        //(session keys, parameter-encryption keys/masks, salts) is octet-aligned, so a non-octet length is
        //rejected rather than silently masked in a way no TPM agrees with.
        if(outputBits % 8 != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(outputBits), outputBits,
                "outputBits must be a positive multiple of 8.");
        }

        int digestSize = DigestSize(hashAlgorithm);
        int outputBytes = (outputBits + 7) / 8;
        int iterations = (outputBytes + digestSize - 1) / digestSize;

        Tag tag = HmacTag(hashAlgorithm);

        //One iteration's HMAC input: [i]_32 || label || 0x00 || contextU || contextV || [bits]_32.
        //Only the leading counter changes per iteration, so the buffer is built once and the counter
        //is rewritten in place for each block.
        int labelByteCount = Encoding.ASCII.GetByteCount(label);
        int inputLength =
            sizeof(uint)                  //counter.
            + labelByteCount + 1          //label + terminating 0x00.
            + contextU.Length
            + contextV.Length
            + sizeof(uint);               //bits.

        IMemoryOwner<byte> output = pool.Rent(outputBytes);
        using IMemoryOwner<byte> inputOwner = pool.Rent(inputLength);

        //The buffer is held as Memory across the HMAC awaits; Span is taken only at synchronous points (a
        //Span cannot survive an await boundary).
        Memory<byte> inputMemory = inputOwner.Memory[..inputLength];

        try
        {
            //Lay out the fixed (counter-independent) portion once; the Span is scoped to this synchronous
            //block so it never crosses the loop's await.
            {
                Span<byte> input = inputMemory.Span;
                input.Clear();
                int offset = sizeof(uint);
                offset += Encoding.ASCII.GetBytes(label, input[offset..]);
                input[offset] = 0x00;
                offset += 1;
                contextU.Span.CopyTo(input[offset..]);
                offset += contextU.Length;
                contextV.Span.CopyTo(input[offset..]);
                offset += contextV.Length;
                BinaryPrimitives.WriteUInt32BigEndian(input[offset..], (uint)outputBits);
            }

            int produced = 0;
            for(uint counter = 1; counter <= iterations; counter++)
            {
                BinaryPrimitives.WriteUInt32BigEndian(inputMemory.Span[..sizeof(uint)], counter);

                using HmacValue block = await CryptographicKeyEvents.ComputeHmacAsync(
                    inputMemory,
                    key,
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
            inputMemory.Span.Clear();
        }
    }

    private static Tag HmacTag(HashAlgorithmName hashAlgorithm) =>
        Tag.Create(hashAlgorithm).With(Purpose.Hmac).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

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

        throw new NotSupportedException($"Hash algorithm '{hashAlgorithm.Name}' is not supported for KDFa.");
    }
}
