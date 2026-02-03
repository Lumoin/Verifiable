using Verifiable.Tpm.Infrastructure;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for <see cref="TpmWriter"/>.
/// </summary>
[TestClass]
public class TpmWriterTests
{
    [TestMethod]
    public void WriteByteWritesOneByte()
    {
        Span<byte> buffer = stackalloc byte[4];
        var writer = new TpmWriter(buffer);

        writer.WriteByte(0xAB);

        Assert.AreEqual((byte)0xAB, buffer[0]);
        Assert.AreEqual(1, writer.Written);
        Assert.AreEqual(3, writer.Remaining);
    }

    [TestMethod]
    public void WriteUInt16WritesBigEndian()
    {
        Span<byte> buffer = stackalloc byte[4];
        var writer = new TpmWriter(buffer);

        writer.WriteUInt16(0x1234);

        Assert.AreEqual((byte)0x12, buffer[0]);
        Assert.AreEqual((byte)0x34, buffer[1]);
        Assert.AreEqual(2, writer.Written);
    }

    [TestMethod]
    public void WriteUInt32WritesBigEndian()
    {
        Span<byte> buffer = stackalloc byte[4];
        var writer = new TpmWriter(buffer);

        writer.WriteUInt32(0x12345678);

        Assert.AreEqual((byte)0x12, buffer[0]);
        Assert.AreEqual((byte)0x34, buffer[1]);
        Assert.AreEqual((byte)0x56, buffer[2]);
        Assert.AreEqual((byte)0x78, buffer[3]);
        Assert.AreEqual(4, writer.Written);
    }

    [TestMethod]
    public void WriteUInt64WritesBigEndian()
    {
        Span<byte> buffer = stackalloc byte[8];
        var writer = new TpmWriter(buffer);

        writer.WriteUInt64(0x123456789ABCDEF0);

        Assert.AreEqual((byte)0x12, buffer[0]);
        Assert.AreEqual((byte)0x34, buffer[1]);
        Assert.AreEqual((byte)0x56, buffer[2]);
        Assert.AreEqual((byte)0x78, buffer[3]);
        Assert.AreEqual((byte)0x9A, buffer[4]);
        Assert.AreEqual((byte)0xBC, buffer[5]);
        Assert.AreEqual((byte)0xDE, buffer[6]);
        Assert.AreEqual((byte)0xF0, buffer[7]);
        Assert.AreEqual(8, writer.Written);
    }

    [TestMethod]
    public void WriteBytesWritesAllBytes()
    {
        Span<byte> buffer = stackalloc byte[8];
        var writer = new TpmWriter(buffer);

        writer.WriteBytes([0xAA, 0xBB, 0xCC]);

        Assert.AreEqual((byte)0xAA, buffer[0]);
        Assert.AreEqual((byte)0xBB, buffer[1]);
        Assert.AreEqual((byte)0xCC, buffer[2]);
        Assert.AreEqual(3, writer.Written);
    }

    [TestMethod]
    public void WriteTpm2bWritesLengthPrefixedData()
    {
        Span<byte> buffer = stackalloc byte[8];
        var writer = new TpmWriter(buffer);

        writer.WriteTpm2b([0xAA, 0xBB, 0xCC]);

        Assert.AreEqual((byte)0x00, buffer[0]);
        Assert.AreEqual((byte)0x03, buffer[1]);
        Assert.AreEqual((byte)0xAA, buffer[2]);
        Assert.AreEqual((byte)0xBB, buffer[3]);
        Assert.AreEqual((byte)0xCC, buffer[4]);
        Assert.AreEqual(5, writer.Written);
    }

    [TestMethod]
    public void MultipleWritesTrackPositionCorrectly()
    {
        Span<byte> buffer = stackalloc byte[16];
        var writer = new TpmWriter(buffer);

        writer.WriteUInt16(0x0010);
        writer.WriteUInt32(0x12345678);
        writer.WriteByte(0xAB);

        Assert.AreEqual((byte)0x00, buffer[0]);
        Assert.AreEqual((byte)0x10, buffer[1]);
        Assert.AreEqual((byte)0x12, buffer[2]);
        Assert.AreEqual((byte)0x34, buffer[3]);
        Assert.AreEqual((byte)0x56, buffer[4]);
        Assert.AreEqual((byte)0x78, buffer[5]);
        Assert.AreEqual((byte)0xAB, buffer[6]);
        Assert.AreEqual(7, writer.Written);
    }
}
