using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Cryptography.Secdsa;

/// <summary>
/// Holds an ephemeral PIN key scalar as a fixed-length big-endian integer.
/// </summary>
/// <remarks>
/// The scalar is derived from the user PIN and a hardware-bound binder key
/// per the constructions in Annex B of the SECDSA specification at
/// https://wellet.nl/SECDSA-EUDI-wallet-latest.pdf. It must be zeroed
/// immediately after use. Use <see cref="SensitiveMemoryPool{T}"/> as the
/// pool to guarantee zeroing of the backing buffer on disposal.
/// This type owns its memory and must be disposed.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PinKeyScalarBytes: IDisposable
{
    /// <summary>Tracks whether this instance has been disposed.</summary>
    private bool Disposed { get; set; }

    /// <summary>Owns the buffer holding the scalar bytes. Must be zeroed before disposal.</summary>
    private IMemoryOwner<byte> Owner { get; }

    /// <summary>The logical byte count of the scalar within <see cref="Owner"/>.</summary>
    private int Length { get; }

    /// <summary>
    /// Gets the scalar bytes as a big-endian integer.
    /// </summary>
    public ReadOnlyMemory<byte> Value => Owner.Memory.Slice(0, Length);

    /// <summary>
    /// Creates a PIN key scalar from a byte span.
    /// </summary>
    /// <param name="scalarBytes">The big-endian scalar bytes.</param>
    /// <param name="pool">
    /// The memory pool to allocate from. Use <see cref="SensitiveMemoryPool{T}.Shared"/>
    /// to ensure the backing buffer is zeroed when returned to the pool.
    /// </param>
    /// <returns>A new <see cref="PinKeyScalarBytes"/> owning the scalar buffer.</returns>
    public static PinKeyScalarBytes Create(ReadOnlySpan<byte> scalarBytes, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        IMemoryOwner<byte> owner = pool.Rent(scalarBytes.Length);
        scalarBytes.CopyTo(owner.Memory.Span);

        return new PinKeyScalarBytes(owner, scalarBytes.Length);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            //Zero before returning to the pool. When SensitiveMemoryPool is used
            //the pool itself also zeroes on return, providing defence in depth.
            Owner.Memory.Span.Slice(0, Length).Clear();
            Owner.Dispose();
            Disposed = true;
        }
    }


    private PinKeyScalarBytes(IMemoryOwner<byte> owner, int length)
    {
        Owner = owner;
        Length = length;
    }


    private string DebuggerDisplay => $"PinKeyScalarBytes({Length} bytes)";
}
