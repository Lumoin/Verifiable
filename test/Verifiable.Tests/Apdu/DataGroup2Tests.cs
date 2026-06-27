using System;
using System.Buffers.Binary;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates EF.DG2 parsing: the CBEFF wrappers (<c>75</c> / <c>7F61</c> / <c>7F60</c> / <c>A1</c> /
/// <c>5F2E</c>) are navigated and the ISO/IEC 19794-5 facial record is parsed to extract the first
/// face image and its encoding. Synthetic records are used (with a minimal image payload) so the test
/// is owned and committable; the BSI ReferenceDataSet DG2 is a local-only real-data cross-check.
/// </summary>
[TestClass]
internal sealed class DataGroup2Tests
{
    public required TestContext TestContext { get; set; }


    [TestMethod]
    public void ExtractsAJpegFaceImage()
    {
        byte[] image = [0xFF, 0xD8, 0x00, 0x11, 0x22, 0xFF, 0xD9];

        using DataGroup2 dataGroup2 = DataGroup2.Parse(BuildDataGroup2(image, jpeg2000: false), BaseMemoryPool.Shared);

        Assert.AreEqual(FaceImageFormat.Jpeg, dataGroup2.FaceImage.Format, "Image data type 0 is JPEG.");
        Assert.AreEqual(Convert.ToHexString(image), Convert.ToHexString(dataGroup2.FaceImage.AsReadOnlySpan()),
            "The extracted image bytes must equal the facial-record image payload.");
    }


    [TestMethod]
    public void ExtractsAJpeg2000FaceImage()
    {
        //JPEG 2000 codestream magic.
        byte[] image = [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A];

        using DataGroup2 dataGroup2 = DataGroup2.Parse(BuildDataGroup2(image, jpeg2000: true), BaseMemoryPool.Shared);

        Assert.AreEqual(FaceImageFormat.Jpeg2000, dataGroup2.FaceImage.Format, "Image data type 1 is JPEG 2000.");
        Assert.AreEqual(Convert.ToHexString(image), Convert.ToHexString(dataGroup2.FaceImage.AsReadOnlySpan()),
            "The extracted image bytes must equal the facial-record image payload.");
    }


    [TestMethod]
    public void RejectsDataWithoutTheDataGroup2Template()
    {
        byte[] notDataGroup2 = Convert.FromHexString("61055F1F024142");

        bool threw = false;
        try
        {
            using DataGroup2 _ = DataGroup2.Parse(notDataGroup2, BaseMemoryPool.Shared);
        }
        catch(InvalidOperationException)
        {
            threw = true;
        }

        Assert.IsTrue(threw, "Parsing must reject data that is not a DG2 template.");
    }


    /// <summary>
    /// Builds a DG2: <c>75 { 7F61 { 02 count, 7F60 { A1 bht, 5F2E facialRecord } } }</c> with one
    /// facial image of <paramref name="image"/> and no feature points.
    /// </summary>
    private static byte[] BuildDataGroup2(byte[] image, bool jpeg2000)
    {
        const int facialRecordHeaderLength = 14;
        const int facialInformationBlockLength = 20;
        const int imageInformationBlockLength = 12;

        int facialBlockLength = facialInformationBlockLength + imageInformationBlockLength + image.Length;

        byte[] header = new byte[facialRecordHeaderLength];
        "FAC\0"u8.CopyTo(header);
        "010\0"u8.CopyTo(header.AsSpan(4));
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8), (uint)(facialRecordHeaderLength + facialBlockLength));
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(12), 1);

        byte[] facialInformation = new byte[facialInformationBlockLength];
        BinaryPrimitives.WriteUInt32BigEndian(facialInformation, (uint)facialBlockLength);
        //Number of feature points stays 0; the rest of the block is unused for this test.

        byte[] imageInformation = new byte[imageInformationBlockLength];
        imageInformation[1] = (byte)(jpeg2000 ? 1 : 0);

        byte[] facialRecord = Concat(header, facialInformation, imageInformation, image);

        byte[] biometricData = Tlv(0x5F2E, facialRecord);
        byte[] biometricHeader = Tlv(0xA1, [0x80, 0x01, 0x00]);
        byte[] biometricTemplate = Tlv(0x7F60, Concat(biometricHeader, biometricData));
        byte[] group = Tlv(0x7F61, Concat([0x02, 0x01, 0x01], biometricTemplate));

        return Tlv(0x75, group);
    }


    /// <summary>Wraps <paramref name="content"/> in a BER-TLV element (length &lt; 128).</summary>
    private static byte[] Tlv(int tag, byte[] content)
    {
        byte[] tagBytes = tag > 0xFF ? [(byte)(tag >> 8), (byte)tag] : [(byte)tag];
        byte[] result = new byte[tagBytes.Length + 1 + content.Length];
        tagBytes.CopyTo(result, 0);
        result[tagBytes.Length] = (byte)content.Length;
        content.CopyTo(result, tagBytes.Length + 1);

        return result;
    }


    /// <summary>Concatenates byte arrays.</summary>
    private static byte[] Concat(params byte[][] arrays)
    {
        int length = 0;
        foreach(byte[] a in arrays) { length += a.Length; }

        byte[] result = new byte[length];
        int offset = 0;
        foreach(byte[] a in arrays)
        {
            a.CopyTo(result, offset);
            offset += a.Length;
        }

        return result;
    }
}
