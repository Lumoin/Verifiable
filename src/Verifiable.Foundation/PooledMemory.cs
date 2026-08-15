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
/// must not use the owner afterwards. <see cref="FromBytes(ReadOnlySpan{byte}, BaseMemoryPool, Tag)"/>
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
    public static PooledMemory FromBytes(ReadOnlySpan<byte> bytes, BaseMemoryPool pool, Tag tag)
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
    /// Gets a shared, zero-length <see cref="PooledMemory"/> for the "no bytes" outcome.
    /// </summary>
    /// <remarks>
    /// Backed by <see cref="EmptyMemoryOwner.Instance"/>, so this single instance is safe to share across
    /// every caller that needs an empty result: <see cref="SensitiveMemory.Dispose(bool)"/> special-cases
    /// an <see cref="EmptyMemoryOwner"/> owner by returning without setting the disposed flag, so no
    /// caller's disposal can poison it for a later caller, and it stays readable and re-disposable forever.
    /// </remarks>
    public static PooledMemory Empty { get; } = new(EmptyMemoryOwner.Instance, 0, Tag.Empty);

    /// <summary>
    /// Gets the actual number of valid bytes in the buffer (which may be smaller than the rented
    /// buffer's own capacity).
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets whether the buffer holds zero valid bytes.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Gets the valid bytes as a span, sliced to <see cref="Length"/> (the base member returns the
    /// whole, possibly larger, rented buffer).
    /// </summary>
    /// <remarks>
    /// Unlike <see cref="SensitiveMemory.AsReadOnlySpan"/>, the member this shadows, whether a call after
    /// disposal throws <see cref="ObjectDisposedException"/> is NOT a guarantee this type itself makes —
    /// it depends on the transferred <see cref="IMemoryOwner{T}"/>: every rental from a
    /// <see cref="BaseMemoryPool"/> guards post-dispose access and throws, but a caller-supplied
    /// <see cref="IMemoryOwner{T}"/> passed to the constructor directly is under no such obligation and
    /// may return stale memory silently instead.
    /// </remarks>
    /// <returns>A read-only span over exactly the valid bytes.</returns>
    public new ReadOnlySpan<byte> AsReadOnlySpan() => MemoryOwner.Memory.Span[..Length];

    /// <summary>
    /// Gets the valid bytes as memory, sliced to <see cref="Length"/> (the base member returns the
    /// whole, possibly larger, rented buffer).
    /// </summary>
    /// <remarks>
    /// Unlike <see cref="SensitiveMemory.AsReadOnlyMemory"/>, the member this shadows, whether a call
    /// after disposal throws <see cref="ObjectDisposedException"/> is NOT a guarantee this type itself
    /// makes — it depends on the transferred <see cref="IMemoryOwner{T}"/>: every rental from a
    /// <see cref="BaseMemoryPool"/> guards post-dispose access and throws, but a caller-supplied
    /// <see cref="IMemoryOwner{T}"/> passed to the constructor directly is under no such obligation and
    /// may return stale memory silently instead.
    /// </remarks>
    /// <returns>A read-only memory over exactly the valid bytes.</returns>
    public new ReadOnlyMemory<byte> AsReadOnlyMemory() => MemoryOwner.Memory[..Length];

    /// <summary>
    /// Projects this owned buffer down to a <see cref="TaggedMemory{T}"/> borrow view, carrying the same
    /// bytes and the same <see cref="SensitiveData.Tag"/> instance without transferring the lease.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Calling this method after this instance is disposed throws <see cref="ObjectDisposedException"/>
    /// for every <see cref="BaseMemoryPool"/> rental, because it routes through
    /// <see cref="AsReadOnlyMemory"/> — see that member's remarks for the transferred-owner dependency
    /// this guarantee rests on.
    /// </para>
    /// <para>
    /// The returned view itself, once obtained, is a SNAPSHOT: <see cref="TaggedMemory{T}"/> captures the
    /// <see cref="ReadOnlyMemory{T}"/> eagerly and never extends this instance's lease. Retaining that
    /// view past this instance's disposal is UNDEFINED, not exception-safe — the underlying buffer has
    /// been returned to the pool and may already be cleared or re-rented to an unrelated caller by the
    /// time it is read, with no exception marking the boundary. Use this only to hand bytes to a delegate
    /// that reads them within this instance's own lifetime, keeping disposal ownership here.
    /// </para>
    /// </remarks>
    /// <returns>A borrowed <see cref="TaggedMemory{T}"/> view over the valid bytes.</returns>
    public TaggedMemory<byte> AsTaggedMemory() => new(AsReadOnlyMemory(), Tag);

    /// <summary>
    /// A short debugger string showing the tag and length only, with no content preview: this carrier
    /// has no domain shape of its own and, on at least one real call site, is used to carry an unwrapped
    /// private key's raw bytes, so a content preview here would leak key material into a debugger watch.
    /// </summary>
    private string DebuggerDisplay => $"PooledMemory({Tag}, {Length}B)";
}
