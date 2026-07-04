using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// The parsed EF.DG2 (Data Group 2) of an ICAO Doc 9303 eMRTD: the holder's facial image, stored in
/// a CBEFF-wrapped ISO/IEC 19794-5 facial record and authenticated by EF.SOD.
/// </summary>
/// <remarks>
/// <para>
/// DG2 (file identifier <c>0x0102</c>, BER-TLV template tag <c>0x75</c>) nests, per Doc 9303 Part 10:
/// a Biometric Information Group Template (<c>7F61</c>) carrying an instance count and one or more
/// Biometric Information Templates (<c>7F60</c>); each holds a Biometric Header Template (<c>A1</c>)
/// and a biometric data block (<c>5F2E</c> or <c>7F2E</c>). Those CBEFF wrappers are shared with EF.DG3
/// and EF.DG4 through <see cref="CbeffBiometricTemplate"/>. The data block is an ISO/IEC 19794-5 facial
/// record — a fixed header, a facial information block, optional feature points, an image information
/// block, and the encoded image (JPEG or JPEG 2000). This type extracts the first face.
/// </para>
/// </remarks>
public sealed class DataGroup2: IDisposable
{
    /// <summary>The eMRTD elementary file identifier of EF.DG2.</summary>
    public const ushort FileIdentifier = 0x0102;

    private const int DataGroupTemplateTag = 0x75;

    //ISO/IEC 19794-5 facial record header: "FAC\0" then "010\0".
    private static readonly byte[] FacialRecordFormatIdentifier = [0x46, 0x41, 0x43, 0x00];

    private const int FacialRecordHeaderLength = 14;
    private const int FacialInformationBlockLength = 20;
    private const int FeaturePointLength = 8;
    private const int ImageInformationBlockLength = 12;
    private const int JpegImageDataType = 0;

    private bool disposed;


    private DataGroup2(FaceImage faceImage)
    {
        FaceImage = faceImage;
    }


    /// <summary>Gets the holder's facial image. Owned by this data group.</summary>
    public FaceImage FaceImage { get; }


    /// <summary>
    /// Parses an EF.DG2 file, extracting the first facial image into a <see cref="FaceImage"/> carrier.
    /// </summary>
    /// <param name="dataGroup2">The DG2 file bytes (the BER-TLV structure beginning with tag <c>0x75</c>).</param>
    /// <param name="pool">The memory pool for the image carrier.</param>
    /// <returns>The parsed <see cref="DataGroup2"/>. The caller disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the structure is not a well-formed DG2.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the FaceImage carrier transfers to the returned DataGroup2, which the caller disposes.")]
    public static DataGroup2 Parse(ReadOnlySpan<byte> dataGroup2, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        ReadOnlySpan<byte> facialRecord = CbeffBiometricTemplate.ExtractFirstBiometricData(dataGroup2, DataGroupTemplateTag, "DG2");
        (FaceImageFormat format, int imageStart, int imageLength) = LocateFirstFace(facialRecord);

        return new DataGroup2(FaceImage.FromBytes(facialRecord.Slice(imageStart, imageLength), format, pool));
    }


    /// <summary>
    /// Writes an EF.DG2 file wrapping a single face image — the inverse of <see cref="Parse"/>. The image
    /// is placed in an ISO/IEC 19794-5 facial record (one face, no feature points) inside the CBEFF
    /// <c>75</c> / <c>7F61</c> / <c>7F60</c> / <c>A1</c> / <c>5F2E</c> wrappers.
    /// </summary>
    /// <param name="image">The encoded face image (JPEG or JPEG 2000 bytes).</param>
    /// <param name="format">The image encoding.</param>
    /// <param name="pool">The memory pool for the file carrier.</param>
    /// <returns>The EF.DG2 <see cref="ElementaryFile"/>. The caller disposes it.</returns>
    public static ElementaryFile Write(ReadOnlySpan<byte> image, FaceImageFormat format, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int facialBlockLength = FacialInformationBlockLength + ImageInformationBlockLength + image.Length;
        int facialRecordLength = FacialRecordHeaderLength + facialBlockLength;

        //Build the ISO/IEC 19794-5 facial record, then wrap it in the shared CBEFF template.
        using IMemoryOwner<byte> recordOwner = pool.Rent(facialRecordLength);
        var recordWriter = new BerTlvWriter(recordOwner.Memory.Span[..facialRecordLength]);
        WriteFacialRecord(ref recordWriter, image, format, facialBlockLength);

        return CbeffBiometricTemplate.Write(DataGroupTemplateTag, recordOwner.Memory.Span[..facialRecordLength], FileIdentifier, pool);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            FaceImage.Dispose();
            disposed = true;
        }
    }


    /// <summary>
    /// Locates the first facial image within an ISO/IEC 19794-5 facial record, returning its encoding
    /// and the offset and length of the image bytes within <paramref name="facialRecord"/>.
    /// </summary>
    private static (FaceImageFormat Format, int ImageStart, int ImageLength) LocateFirstFace(ReadOnlySpan<byte> facialRecord)
    {
        if(facialRecord.Length < FacialRecordHeaderLength || !facialRecord[..4].SequenceEqual(FacialRecordFormatIdentifier))
        {
            throw new InvalidOperationException("DG2 does not carry an ISO/IEC 19794-5 facial record.");
        }

        int faceCount = BinaryPrimitives.ReadUInt16BigEndian(facialRecord[12..]);
        if(faceCount < 1)
        {
            throw new InvalidOperationException("DG2 facial record contains no facial images.");
        }

        ReadOnlySpan<byte> facialInformation = facialRecord[FacialRecordHeaderLength..];
        if(facialInformation.Length < FacialInformationBlockLength)
        {
            throw new InvalidOperationException("DG2 facial record is truncated before its facial information block.");
        }

        int facialBlockLength = (int)BinaryPrimitives.ReadUInt32BigEndian(facialInformation);
        int featurePoints = BinaryPrimitives.ReadUInt16BigEndian(facialInformation[sizeof(uint)..]);

        //The image information block follows the facial information block and the feature points, whose count is
        //attacker-controlled (up to 65535). Bound its position against the buffer BEFORE indexing into it, and
        //compare by subtraction so a large feature-point count cannot overflow `offset + block` past the guard.
        int imageInformationOffset = FacialInformationBlockLength + (featurePoints * FeaturePointLength);
        if(imageInformationOffset > facialInformation.Length - ImageInformationBlockLength)
        {
            throw new InvalidOperationException("DG2 facial record image information block is out of range.");
        }

        byte imageDataType = facialInformation[imageInformationOffset + 1];
        FaceImageFormat format = imageDataType == JpegImageDataType ? FaceImageFormat.Jpeg : FaceImageFormat.Jpeg2000;

        int imageOffset = imageInformationOffset + ImageInformationBlockLength;
        int imageLength = facialBlockLength - imageOffset;
        if(imageLength <= 0 || imageLength > facialInformation.Length - imageOffset)
        {
            throw new InvalidOperationException("DG2 facial record image length is invalid.");
        }

        return (format, FacialRecordHeaderLength + imageOffset, imageLength);
    }


    /// <summary>
    /// Writes the ISO/IEC 19794-5 facial record: the format header, a single facial-information block with
    /// no feature points, an image-information block selecting the encoding, and the image bytes.
    /// </summary>
    private static void WriteFacialRecord(ref BerTlvWriter writer, ReadOnlySpan<byte> image, FaceImageFormat format, int facialBlockLength)
    {
        //Record header: "FAC\0" "010\0", total record length, and one face.
        writer.WriteValue("FAC\0"u8);
        writer.WriteValue("010\0"u8);
        WriteUInt32(ref writer, FacialRecordHeaderLength + facialBlockLength);
        WriteUInt16(ref writer, 1);

        //Facial information block: the facial block length, then zero feature points and unused fields.
        WriteUInt32(ref writer, facialBlockLength);
        Span<byte> remainingFacialInformation = stackalloc byte[FacialInformationBlockLength - sizeof(uint)];
        remainingFacialInformation.Clear();
        writer.WriteValue(remainingFacialInformation);

        //Image information block: the image data type at offset 1 selects JPEG (0) or JPEG 2000 (1).
        Span<byte> imageInformation = stackalloc byte[ImageInformationBlockLength];
        imageInformation.Clear();
        imageInformation[1] = (byte)(format == FaceImageFormat.Jpeg2000 ? 1 : 0);
        writer.WriteValue(imageInformation);

        writer.WriteValue(image);
    }


    /// <summary>Writes a big-endian unsigned 32-bit integer at the writer's current position.</summary>
    private static void WriteUInt32(ref BerTlvWriter writer, int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, (uint)value);
        writer.WriteValue(bytes);
    }


    /// <summary>Writes a big-endian unsigned 16-bit integer at the writer's current position.</summary>
    private static void WriteUInt16(ref BerTlvWriter writer, int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, (ushort)value);
        writer.WriteValue(bytes);
    }
}
