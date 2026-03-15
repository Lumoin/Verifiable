using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Cryptography.Secdsa;

/// <summary>
/// Holds the raw (r, s) bytes of an ECDSA signature as returned by hardware.
/// </summary>
/// <remarks>
/// <para>
/// The encoding is implementation-defined at this level. Consumers that need
/// to parse the scalars use library-specific helpers in Verifiable.BouncyCastle
/// or Verifiable.Microsoft. This type owns its memory and must be disposed.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class RawEcdsaSignatureBytes: IDisposable
{
    /// <summary>Tracks whether this instance has been disposed.</summary>
    private bool Disposed { get; set; }

    /// <summary>Owns the contiguous buffer holding r followed by s.</summary>
    private IMemoryOwner<byte> Owner { get; }

    /// <summary>Byte length of the r component within <see cref="Owner"/>.</summary>
    private int RLength { get; }

    /// <summary>Byte length of the s component within <see cref="Owner"/>.</summary>
    private int SLength { get; }

    /// <summary>
    /// Gets the r component bytes of the signature.
    /// </summary>
    public ReadOnlyMemory<byte> R => Owner.Memory.Slice(0, RLength);

    /// <summary>
    /// Gets the s component bytes of the signature.
    /// </summary>
    public ReadOnlyMemory<byte> S => Owner.Memory.Slice(RLength, SLength);


    /// <summary>
    /// Creates a signature from separately provided r and s byte spans.
    /// </summary>
    /// <param name="r">The r component bytes.</param>
    /// <param name="s">The s component bytes.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>A new <see cref="RawEcdsaSignatureBytes"/> owning a contiguous buffer.</returns>
    public static RawEcdsaSignatureBytes Create(
        ReadOnlySpan<byte> r,
        ReadOnlySpan<byte> s,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        IMemoryOwner<byte> owner = pool.Rent(r.Length + s.Length);
        r.CopyTo(owner.Memory.Span);
        s.CopyTo(owner.Memory.Span.Slice(r.Length));

        return new RawEcdsaSignatureBytes(owner, r.Length, s.Length);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            Owner.Dispose();
            Disposed = true;
        }
    }


    private RawEcdsaSignatureBytes(IMemoryOwner<byte> owner, int rLength, int sLength)
    {
        Owner = owner;
        RLength = rLength;
        SLength = sLength;
    }


    private string DebuggerDisplay => $"RawEcdsaSignatureBytes(R={RLength} bytes, S={SLength} bytes)";
}
