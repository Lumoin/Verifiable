using Verifiable.Tpm.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for TPM2B buffer structures.
/// </summary>
[TestClass]
public class Tpm2bStructureTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void Tpm2bDigestParsesCorrectly()
    {
        //TPM2B_DIGEST: size (2 bytes) + buffer (variable).
        //SHA-256 produces 32-byte digests.
        const int sha256DigestLength = 32;
        const int sizeFieldLength = sizeof(ushort);
        const int expectedBytesRead = sizeFieldLength + sha256DigestLength;

        byte[] data =
        [
            0x00, 0x20, //Size field: 32 bytes (0x0020 big-endian).
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
        ];

        Tpm2bDigest digest = Tpm2bDigest.ReadFrom(data, out int bytesRead);

        Assert.AreEqual(expectedBytesRead, bytesRead);
        Assert.AreEqual(sha256DigestLength, digest.Buffer.Length);
        Assert.AreEqual(0x01, digest.Buffer.Span[0]);
        Assert.AreEqual(0x20, digest.Buffer.Span[sha256DigestLength - 1]);
    }

    [TestMethod]
    public void Tpm2bMaxBufferRoundTripsCorrectly()
    {
        byte[] originalData = [0xDE, 0xAD, 0xBE, 0xEF];
        var original = new Tpm2bMaxBuffer(originalData);

        //Serialized size: size field (2) + data length (4) = 6.
        const int expectedSerializedSize = sizeof(ushort) + 4;

        Span<byte> buffer = stackalloc byte[original.SerializedSize];

        int written = original.WriteTo(buffer);
        Tpm2bMaxBuffer parsed = Tpm2bMaxBuffer.ReadFrom(buffer, out int bytesRead);

        Assert.AreEqual(expectedSerializedSize, written);
        Assert.AreEqual(expectedSerializedSize, bytesRead);
        Assert.AreEqual(originalData.Length, parsed.Buffer.Length);
        Assert.IsTrue(originalData.AsSpan().SequenceEqual(parsed.Buffer.Span));
    }

    [TestMethod]
    public void Tpm2bMaxBufferSerializedSizeIsCorrect()
    {
        byte[] data = new byte[100];
        var buffer = new Tpm2bMaxBuffer(data);

        //Size field (2) + data length.
        const int expectedSize = sizeof(ushort) + 100;

        Assert.AreEqual(expectedSize, buffer.SerializedSize);
    }

    [TestMethod]
    public void Tpm2bDigestSerializedSizeIsCorrect()
    {
        byte[] data = new byte[64];
        var digest = new Tpm2bDigest(data);

        //Size field (2) + data length.
        const int expectedSize = sizeof(ushort) + 64;

        Assert.AreEqual(expectedSize, digest.SerializedSize);
    }
}