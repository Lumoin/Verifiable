using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Cryptography;

/// <summary>
/// Semantic carrier for an encoded elliptic-curve point in SEC1 uncompressed form
/// (<c>0x04 || X || Y</c>) — a public point such as a scalar multiple of the generator, a mapped
/// generator, or an ephemeral public key. Owns its underlying pool-rented memory; disposing the
/// carrier returns the buffer.
/// </summary>
/// <remarks>
/// <para>
/// The result type of the EC point arithmetic seam (<see cref="EcMultiplyGeneratorDelegate"/>,
/// <see cref="EcMultiplyPointDelegate"/>, <see cref="EcAddPointsDelegate"/>). Sealed,
/// <see cref="SensitiveMemory"/>-derived; carries the curve <see cref="Tag"/> for CBOM/OTel
/// provenance. The X-coordinate of a key-agreement point is taken as a <see cref="Aead.SharedSecret"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("EncodedEcPoint({Length} bytes)")]
public sealed class EncodedEcPoint(IMemoryOwner<byte> sensitiveMemory, Tag tag, Activity? lifetime = null)
    : SensitiveMemory(sensitiveMemory, tag, lifetime)
{
    /// <summary>Gets the length of the encoded point in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Rents pool memory of <paramref name="bytes"/>'s length, copies the bytes in, and wraps the
    /// buffer in an <see cref="EncodedEcPoint"/> carrying <paramref name="curve"/>. The caller takes
    /// ownership of the returned carrier.
    /// </summary>
    public static EncodedEcPoint FromBytes(ReadOnlySpan<byte> bytes, Tag curve, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(curve);
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new EncodedEcPoint(owner, curve);
    }
}
