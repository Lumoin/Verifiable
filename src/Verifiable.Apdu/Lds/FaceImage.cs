using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// The image encoding of a face image stored in an ISO/IEC 19794-5 facial record.
/// </summary>
public enum FaceImageFormat
{
    /// <summary>JPEG (image data type 0).</summary>
    Jpeg,

    /// <summary>JPEG 2000 (image data type 1).</summary>
    Jpeg2000
}


/// <summary>
/// The encoded bytes of a biometric face image extracted from EF.DG2 — the holder's portrait, the
/// most sensitive data on the chip. A tracked carrier rather than a naked buffer: it owns its pooled
/// memory, clears it on disposal, and carries <see cref="ApduTags.FaceImage"/> for provenance.
/// </summary>
[DebuggerDisplay("FaceImage({Format}, {Length} bytes)")]
public sealed class FaceImage: SensitiveMemory
{
    /// <summary>
    /// Initialises a new <see cref="FaceImage"/> from owned image bytes.
    /// </summary>
    /// <param name="storage">The owned, exact-size buffer holding the encoded image. Ownership transfers to this instance.</param>
    /// <param name="format">The image encoding.</param>
    public FaceImage(IMemoryOwner<byte> storage, FaceImageFormat format)
        : base(storage, ApduTags.FaceImage)
    {
        ArgumentNullException.ThrowIfNull(storage);
        Format = format;
    }


    /// <summary>Gets the image encoding.</summary>
    public FaceImageFormat Format { get; }

    /// <summary>Gets the length of the encoded image in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Copies <paramref name="bytes"/> into a pooled <see cref="FaceImage"/>.
    /// </summary>
    public static FaceImage FromBytes(ReadOnlySpan<byte> bytes, FaceImageFormat format, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new FaceImage(owner, format);
    }
}
