using System;
using Verifiable.Apdu;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates the EF.DG2 writer: it wraps a face image in the CBEFF templates and an ISO/IEC 19794-5
/// facial record that round-trips through <see cref="DataGroup2.Parse"/> — the image bytes and encoding
/// are recovered exactly. The owned producer for the biometric data group.
/// </summary>
[TestClass]
internal sealed class DataGroup2WriterTests
{
    [TestMethod]
    public void RoundTripsAJpegFace()
    {
        byte[] image = [0xFF, 0xD8, 0x00, 0x11, 0x22, 0xFF, 0xD9];

        using ElementaryFile dataGroup2 = DataGroup2.Write(image, FaceImageFormat.Jpeg, BaseMemoryPool.Shared);
        using DataGroup2 parsed = DataGroup2.Parse(dataGroup2.AsReadOnlySpan(), BaseMemoryPool.Shared);

        Assert.AreEqual(FaceImageFormat.Jpeg, parsed.FaceImage.Format, "The JPEG encoding must round-trip.");
        Assert.AreEqual(Convert.ToHexString(image), Convert.ToHexString(parsed.FaceImage.AsReadOnlySpan()),
            "The face image bytes must round-trip.");
    }


    [TestMethod]
    public void RoundTripsAJpeg2000Face()
    {
        byte[] image = [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A];

        using ElementaryFile dataGroup2 = DataGroup2.Write(image, FaceImageFormat.Jpeg2000, BaseMemoryPool.Shared);
        using DataGroup2 parsed = DataGroup2.Parse(dataGroup2.AsReadOnlySpan(), BaseMemoryPool.Shared);

        Assert.AreEqual(FaceImageFormat.Jpeg2000, parsed.FaceImage.Format, "The JPEG 2000 encoding must round-trip.");
        Assert.AreEqual(Convert.ToHexString(image), Convert.ToHexString(parsed.FaceImage.AsReadOnlySpan()),
            "The face image bytes must round-trip.");
    }


    [TestMethod]
    public void BeginsWithTheDataGroup2Template()
    {
        using ElementaryFile dataGroup2 = DataGroup2.Write([0xFF, 0xD8, 0xFF, 0xD9], FaceImageFormat.Jpeg, BaseMemoryPool.Shared);

        Assert.AreEqual((byte)0x75, dataGroup2.AsReadOnlySpan()[0], "DG2 begins with the template tag 0x75.");
    }
}
