using System.Buffers;

namespace Verifiable.Cryptography;

/// <summary>
/// A <see cref="ReadOnlySequenceSegment{T}"/> for building multi-segment
/// <see cref="ReadOnlySequence{T}"/> inputs to the digest and HMAC primitives
/// without pre-buffering.
/// </summary>
/// <remarks>
/// <para>
/// The digest and HMAC delegates accept <see cref="ReadOnlySequence{T}"/> for
/// their input. One-shot callers wrap a <see cref="ReadOnlyMemory{T}"/> via the
/// convenience overloads; multi-segment callers (TPM command-parameter hashing,
/// Schnorr challenge hashing, future RDF or KERI stream consumers) build a chain
/// of <see cref="BufferSegment"/> nodes pointing into pool-rented or stack-owned
/// memory and pass the resulting <see cref="ReadOnlySequence{T}"/> directly.
/// </para>
/// <para>
/// Usage pattern:
/// </para>
/// <code>
/// BufferSegment first = new BufferSegment(segment0);
/// BufferSegment last = first.Append(segment1).Append(segment2);
/// ReadOnlySequence&lt;byte&gt; input = new ReadOnlySequence&lt;byte&gt;(first, 0, last, last.Memory.Length);
/// using DigestValue hash = await CryptographicKeyEvents.ComputeDigestAsync(input, ...);
/// </code>
/// </remarks>
public sealed class BufferSegment: ReadOnlySequenceSegment<byte>
{
    /// <summary>
    /// Initialises a new <see cref="BufferSegment"/> as the head of a chain.
    /// Use <see cref="Append"/> to extend.
    /// </summary>
    public BufferSegment(ReadOnlyMemory<byte> memory)
    {
        Memory = memory;
    }


    /// <summary>
    /// Appends a new segment after this one and returns the appended node.
    /// </summary>
    public BufferSegment Append(ReadOnlyMemory<byte> memory)
    {
        BufferSegment next = new(memory) { RunningIndex = RunningIndex + Memory.Length };
        Next = next;
        return next;
    }
}
