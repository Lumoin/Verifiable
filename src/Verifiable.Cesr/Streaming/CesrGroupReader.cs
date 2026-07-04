using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace Verifiable.Cesr.Streaming;

/// <summary>
/// Walks the body of a CESR count group element by element. The body comes from a
/// <see cref="CesrToken.BodyMemory"/>; this reader decodes each leading element and advances by the amount it
/// occupied until the body is exhausted, in either concrete domain (the <c>Read*</c> methods walk a binary
/// (qb2) body, the <c>Read*Text</c> methods walk a text (qb64) body whose characters are one ASCII byte each).
/// </summary>
/// <remarks>
/// <para>
/// This is the mechanism only: it walks a body as a homogeneous sequence of primitives or of indexed
/// signatures. Which of those a given group code frames is genus-specific — the CESR specification fixes only
/// the universal count codes and leaves the rest to each protocol genus
/// (<see href="https://trustoverip.github.io/kswg-cesr-specification/#protocol-genusversion-table">Protocol
/// genus/version table</see>) — so the caller, which knows the genus, chooses which walk to run for a group's
/// code. Mapping a code to its content is the protocol layer's table, not this codec's.
/// </para>
/// </remarks>
public static class CesrGroupReader
{
    /// <summary>
    /// Walks a group body as a sequence of CESR primitives.
    /// </summary>
    /// <param name="body">The binary-domain (qb2) group body, for example a <see cref="CesrToken.BodyMemory"/>.</param>
    /// <param name="pool">The memory pool the recovered raw values are rented from.</param>
    /// <returns>The primitives in order. Each <see cref="CesrParsedPrimitive"/> MUST be disposed by the consumer.</returns>
    /// <exception cref="CesrFormatException">The body does not divide cleanly into primitives.</exception>
    public static IEnumerable<CesrParsedPrimitive> ReadPrimitives(ReadOnlyMemory<byte> body, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return Iterate(body, pool);

        static IEnumerable<CesrParsedPrimitive> Iterate(ReadOnlyMemory<byte> body, MemoryPool<byte> pool)
        {
            int offset = 0;
            while(offset < body.Length)
            {
                CesrParsedPrimitive primitive = CesrPrimitiveCodec.DecodeBinary(body.Span[offset..], pool, out int consumed);
                offset += GuardConsumed(consumed);
                yield return primitive;
            }
        }
    }


    /// <summary>
    /// Walks a group body as a sequence of CESR indexed signatures.
    /// </summary>
    /// <param name="body">The binary-domain (qb2) group body, for example a <see cref="CesrToken.BodyMemory"/>.</param>
    /// <param name="pool">The memory pool the recovered raw signatures are rented from.</param>
    /// <returns>The indexed signatures in order. Each <see cref="CesrParsedIndexedSignature"/> MUST be disposed by the consumer.</returns>
    /// <exception cref="CesrFormatException">The body does not divide cleanly into indexed signatures.</exception>
    public static IEnumerable<CesrParsedIndexedSignature> ReadIndexedSignatures(ReadOnlyMemory<byte> body, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return Iterate(body, pool);

        static IEnumerable<CesrParsedIndexedSignature> Iterate(ReadOnlyMemory<byte> body, MemoryPool<byte> pool)
        {
            int offset = 0;
            while(offset < body.Length)
            {
                CesrParsedIndexedSignature signature = CesrIndexedSignatureCodec.DecodeBinary(body.Span[offset..], pool, out int consumed);
                offset += GuardConsumed(consumed);
                yield return signature;
            }
        }
    }


    /// <summary>
    /// Walks a text-domain (qb64) group body as a sequence of CESR primitives.
    /// </summary>
    /// <param name="body">The text-domain (qb64) group body as ASCII bytes, for example a text <see cref="CesrToken.BodyMemory"/>.</param>
    /// <param name="pool">The memory pool the recovered raw values are rented from.</param>
    /// <returns>The primitives in order. Each <see cref="CesrParsedPrimitive"/> MUST be disposed by the consumer.</returns>
    /// <exception cref="CesrFormatException">The body does not divide cleanly into primitives.</exception>
    public static IEnumerable<CesrParsedPrimitive> ReadPrimitivesText(ReadOnlyMemory<byte> body, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return Iterate(body, pool);

        static IEnumerable<CesrParsedPrimitive> Iterate(ReadOnlyMemory<byte> body, MemoryPool<byte> pool)
        {
            char[] rented = ArrayPool<char>.Shared.Rent(Math.Max(body.Length, 1));
            try
            {
                int charCount = Encoding.ASCII.GetChars(body.Span, rented);
                int offset = 0;
                while(offset < charCount)
                {
                    CesrParsedPrimitive primitive = CesrPrimitiveCodec.DecodeText(rented.AsSpan(offset, charCount - offset), pool, out int consumed);
                    offset += GuardConsumed(consumed);
                    yield return primitive;
                }
            }
            finally
            {
                ArrayPool<char>.Shared.Return(rented);
            }
        }
    }


    /// <summary>
    /// Walks a text-domain (qb64) group body as a sequence of CESR indexed signatures.
    /// </summary>
    /// <param name="body">The text-domain (qb64) group body as ASCII bytes, for example a text <see cref="CesrToken.BodyMemory"/>.</param>
    /// <param name="pool">The memory pool the recovered raw signatures are rented from.</param>
    /// <returns>The indexed signatures in order. Each <see cref="CesrParsedIndexedSignature"/> MUST be disposed by the consumer.</returns>
    /// <exception cref="CesrFormatException">The body does not divide cleanly into indexed signatures.</exception>
    public static IEnumerable<CesrParsedIndexedSignature> ReadIndexedSignaturesText(ReadOnlyMemory<byte> body, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return Iterate(body, pool);

        static IEnumerable<CesrParsedIndexedSignature> Iterate(ReadOnlyMemory<byte> body, MemoryPool<byte> pool)
        {
            char[] rented = ArrayPool<char>.Shared.Rent(Math.Max(body.Length, 1));
            try
            {
                int charCount = Encoding.ASCII.GetChars(body.Span, rented);
                int offset = 0;
                while(offset < charCount)
                {
                    CesrParsedIndexedSignature signature = CesrIndexedSignatureCodec.DecodeText(rented.AsSpan(offset, charCount - offset), pool, out int consumed);
                    offset += GuardConsumed(consumed);
                    yield return signature;
                }
            }
            finally
            {
                ArrayPool<char>.Shared.Return(rented);
            }
        }
    }


    /// <summary>
    /// Guards against a non-advancing decode so a malformed element cannot spin the walk into an infinite loop.
    /// </summary>
    private static int GuardConsumed(int consumed)
    {
        if(consumed <= 0)
        {
            throw new CesrFormatException("A CESR group element did not advance the cursor.");
        }

        return consumed;
    }
}
