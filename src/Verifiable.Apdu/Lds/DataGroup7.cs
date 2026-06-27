using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// The parsed EF.DG7 (Data Group 7) of an ICAO Doc 9303 eMRTD: the holder's displayed signature or usual
/// mark — the scanned signature image printed in the document (Doc 9303 Part 10). A tracked carrier holding
/// the image bytes; decoding the image format is a caller concern.
/// </summary>
/// <remarks>
/// <para>
/// EF.DG7 (file identifier <c>0x0107</c>, BER-TLV template tag <c>0x67</c>) carries a count object
/// (<c>0x02</c>) followed by one or more image objects (<c>5F43</c>). This type extracts the first image into
/// a pooled, tracked carrier carrying <see cref="ApduTags.DisplayedSignature"/>; the writer produces the
/// single-image form a personalised document uses.
/// </para>
/// </remarks>
[DebuggerDisplay("DataGroup7(DisplayedSignature, {Length} bytes)")]
public sealed class DataGroup7: SensitiveMemory
{
    /// <summary>The eMRTD elementary file identifier of EF.DG7.</summary>
    public const ushort FileIdentifier = 0x0107;

    private const int DataGroupTemplateTag = 0x67;
    private const int ImageCountTag = 0x02;
    private const int ImageTag = 0x5F43;


    private DataGroup7(IMemoryOwner<byte> image)
        : base(image, ApduTags.DisplayedSignature)
    {
    }


    /// <summary>Gets the length of the displayed signature image in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Parses an EF.DG7 file, extracting the first displayed signature image.
    /// </summary>
    /// <param name="dataGroup7">The DG7 file bytes (the BER-TLV structure beginning with tag <c>0x67</c>).</param>
    /// <param name="pool">The memory pool for the image carrier.</param>
    /// <returns>The parsed <see cref="DataGroup7"/>. The caller disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the structure is not a well-formed DG7.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented image buffer transfers to the returned DataGroup7, which the caller disposes; the catch disposes it on failure.")]
    public static DataGroup7 Parse(ReadOnlySpan<byte> dataGroup7, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var reader = new ApduReader(dataGroup7);
        if(LdsTlv.ReadTag(ref reader) != DataGroupTemplateTag)
        {
            throw new InvalidOperationException("The data is not an EF.DG7 file (expected BER-TLV tag 0x67).");
        }

        var content = new ApduReader(reader.ReadBytes(reader.ReadTlvLength()));
        ReadOnlySpan<byte> image = default;
        bool found = false;
        while(!content.IsEmpty)
        {
            int tag = LdsTlv.ReadTag(ref content);
            ReadOnlySpan<byte> value = content.ReadBytes(content.ReadTlvLength());
            if(tag == ImageTag && !found)
            {
                image = value;
                found = true;
            }

            //The count object (02) and any further images are not needed; the first image is taken.
        }

        if(!found)
        {
            throw new InvalidOperationException("EF.DG7 carries no displayed signature image (tag 5F43).");
        }

        IMemoryOwner<byte> owner = pool.Rent(image.Length);
        try
        {
            image.CopyTo(owner.Memory.Span);

            return new DataGroup7(owner);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Writes an EF.DG7 file wrapping a single displayed signature image — the inverse of <see cref="Parse"/>.
    /// </summary>
    /// <param name="signatureImage">The displayed signature or usual mark image bytes.</param>
    /// <param name="pool">The memory pool for the file carrier.</param>
    /// <returns>The EF.DG7 <see cref="ElementaryFile"/>. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned ElementaryFile, which the caller disposes; the catch disposes it on failure.")]
    public static ElementaryFile Write(ReadOnlySpan<byte> signatureImage, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int contentLength = BerTlvWriter.ElementSize(ImageCountTag, 1) + BerTlvWriter.ElementSize(ImageTag, signatureImage.Length);
        int total = BerTlvWriter.ElementSize(DataGroupTemplateTag, contentLength);

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            var writer = new BerTlvWriter(owner.Memory.Span[..total]);
            writer.WriteHeader(DataGroupTemplateTag, contentLength);
            writer.WriteElement(ImageCountTag, [0x01]);
            writer.WriteElement(ImageTag, signatureImage);

            return new ElementaryFile(owner, FileIdentifier);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }
}
