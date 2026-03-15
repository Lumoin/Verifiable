using System.Buffers;
using System.Diagnostics;
using System.Globalization;

namespace Verifiable.Cryptography.Secdsa;

/// <summary>
/// Holds an elliptic curve point in uncompressed form (0x04 || X || Y).
/// </summary>
/// <remarks>
/// For P-256 this is always <see cref="EllipticCurveConstants.P256.UncompressedPointByteCount"/> bytes.
/// This type owns its memory and must be disposed. The uncompressed encoding
/// is the canonical form used across all SECDSA protocol steps.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class EcPointBytes: IDisposable
{
    /// <summary>Tracks whether this instance has been disposed.</summary>
    private bool Disposed { get; set; }

    /// <summary>Owns the buffer holding the full uncompressed point encoding.</summary>
    private IMemoryOwner<byte> Owner { get; }

    /// <summary>The logical byte count of the point encoding within <see cref="Owner"/>.</summary>
    private int Length { get; }

    /// <summary>
    /// Gets the full uncompressed point encoding.
    /// </summary>
    public ReadOnlyMemory<byte> Value => Owner.Memory.Slice(0, Length);

    /// <summary>
    /// Gets the X coordinate bytes (bytes 1–32 for P-256).
    /// </summary>
    public ReadOnlyMemory<byte> X => Owner.Memory.Slice(1, (Length - 1) / 2);

    /// <summary>
    /// Gets the Y coordinate bytes (bytes 33–64 for P-256).
    /// </summary>
    public ReadOnlyMemory<byte> Y => Owner.Memory.Slice(1 + (Length - 1) / 2, (Length - 1) / 2);


    /// <summary>
    /// Creates an EC point from an uncompressed encoding.
    /// </summary>
    /// <param name="uncompressedPoint">The 0x04-prefixed point bytes.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>A new <see cref="EcPointBytes"/> owning the point buffer.</returns>
    public static EcPointBytes Create(ReadOnlySpan<byte> uncompressedPoint, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(uncompressedPoint.Length);
        uncompressedPoint.CopyTo(owner.Memory.Span);
        return new EcPointBytes(owner, uncompressedPoint.Length);
    }


    private EcPointBytes(IMemoryOwner<byte> owner, int length)
    {
        Owner = owner;
        Length = length;
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


    private string DebuggerDisplay =>
        $"EcPointBytes({Length} bytes, prefix=0x{(Length > 0 ? Owner.Memory.Span[0].ToString("X2", CultureInfo.InvariantCulture) : "?")})";
}
