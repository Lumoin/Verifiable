using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Foundation;

/// <summary>
/// A concrete, general-purpose, length-tracked pooled buffer carrier.
/// </summary>
/// <remarks>
/// <para>
/// This is the pooled, disposable counterpart to <see cref="TaggedMemory{T}"/>: where
/// <see cref="TaggedMemory{T}"/> wraps an already-allocated array it does not own (see that type's
/// "Distinction from SensitiveMemory" remarks), <see cref="PooledMemory"/> owns a buffer rented from a
/// <see cref="MemoryPool{T}"/> and is responsible for clearing and returning it. It exists because the
/// <c>Lumoin.Base</c> <see cref="SensitiveMemory"/> hierarchy provides the disposal/clearing contract
/// but no concrete, reusable type for a plain pooled byte buffer with a tracked valid length — every
/// other <see cref="SensitiveMemory"/> subtype in this codebase (for example
/// <c>Verifiable.Apdu.ApduResponse</c>) is domain-specific. <see cref="PooledMemory"/> fills that gap
/// for callers that just need "a pooled, tagged, disposable byte buffer," with no domain shape of its
/// own.
/// </para>
/// <para>
/// <strong>Ownership:</strong> The constructor taking an <see cref="IMemoryOwner{T}"/> transfers
/// ownership of that owner to the new <see cref="PooledMemory"/> instance with no copy; the caller
/// must not use the owner afterwards. <see cref="FromBytes(ReadOnlySpan{byte}, MemoryPool{byte}, Tag)"/>
/// rents a fresh buffer and copies into it, for callers that only have a span to hand over. Either way,
/// the resulting <see cref="PooledMemory"/> is owned by its caller, who must dispose it; disposal clears
/// the memory and returns it to the pool, per <see cref="SensitiveMemory"/>'s contract.
/// </para>
/// <para>
/// <strong>Why track length separately.</strong> A rented <see cref="IMemoryOwner{T}"/> buffer is
/// frequently larger than the data it holds (pools round up to bucket sizes), so
/// <see cref="SensitiveMemory.AsReadOnlySpan"/>/<see cref="SensitiveMemory.AsReadOnlyMemory"/> return the
/// whole rented buffer. <see cref="Length"/> records the actual valid byte count, and
/// <see cref="AsReadOnlySpan"/>/<see cref="AsReadOnlyMemory"/> here shadow the base members to slice to
/// exactly that length — the same pattern <c>Verifiable.Apdu.ApduResponse</c> uses for the same reason.
/// </para>
/// </remarks>
/// <seealso cref="TaggedMemory{T}"/>
/// <seealso cref="SensitiveMemory"/>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PooledMemory: SensitiveMemory
{
    /// <summary>
    /// Initializes a new pooled memory carrier, transferring ownership of <paramref name="storage"/>.
    /// </summary>
    /// <param name="storage">The memory owner containing the buffer; ownership transfers to this instance.</param>
    /// <param name="length">The actual number of valid bytes in the buffer.</param>
    /// <param name="tag">Metadata describing the buffer's role.</param>
    public PooledMemory(IMemoryOwner<byte> storage, int length, Tag tag)
        : base(storage, tag)
    {
        Length = length;
    }

    /// <summary>
    /// Creates a <see cref="PooledMemory"/> by copying <paramref name="bytes"/> into a buffer rented
    /// from <paramref name="pool"/>; the returned instance owns that buffer and must be disposed by the
    /// caller.
    /// </summary>
    /// <param name="bytes">The bytes to copy into the pooled buffer.</param>
    /// <param name="pool">The memory pool the buffer is rented from.</param>
    /// <param name="tag">Metadata describing the buffer's role.</param>
    /// <returns>A <see cref="PooledMemory"/> wrapping a pooled copy of <paramref name="bytes"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static PooledMemory FromBytes(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool, Tag tag)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //At least one byte is always rented, even for an empty source: some MemoryPool<T>
        //implementations (this codebase's own included) reject a zero-length request outright, and an
        //empty PooledMemory (Length 0) is a legitimate value this general-purpose type must support.
        IMemoryOwner<byte> storage = pool.Rent(Math.Max(bytes.Length, 1));
        try
        {
            bytes.CopyTo(storage.Memory.Span);

            return new PooledMemory(storage, bytes.Length, tag);
        }
        catch
        {
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Gets the actual number of valid bytes in the buffer (which may be smaller than the rented
    /// buffer's own capacity).
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets the valid bytes as a span, sliced to <see cref="Length"/> (the base member returns the
    /// whole, possibly larger, rented buffer).
    /// </summary>
    /// <returns>A read-only span over exactly the valid bytes.</returns>
    public new ReadOnlySpan<byte> AsReadOnlySpan() => MemoryOwner.Memory.Span[..Length];

    /// <summary>
    /// Gets the valid bytes as memory, sliced to <see cref="Length"/> (the base member returns the
    /// whole, possibly larger, rented buffer).
    /// </summary>
    /// <returns>A read-only memory over exactly the valid bytes.</returns>
    public new ReadOnlyMemory<byte> AsReadOnlyMemory() => MemoryOwner.Memory[..Length];

    /// <summary>
    /// A short debugger string showing the tag, length, and a short hex preview of the buffer.
    /// </summary>
    private string DebuggerDisplay
    {
        get
        {
            ReadOnlySpan<byte> data = AsReadOnlySpan();
            int previewLength = Math.Min(data.Length, 8);
            string hexPreview = Convert.ToHexStringLower(data[..previewLength]);
            string ellipsis = data.Length > 8 ? "..." : string.Empty;

            return $"PooledMemory({Tag}, {Length}B, {hexPreview}{ellipsis})";
        }
    }
}
