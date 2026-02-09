using Verifiable.Tpm.Infrastructure;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for <see cref="TpmReader"/>.
/// </summary>
[TestClass]
internal class TpmReaderTests
{
    [TestMethod]
    public void ReadByteConsumesOneByte()
    {
        byte[] buffer = [0xAB, 0xCD];
        var reader = new TpmReader(buffer);

        byte value = reader.ReadByte();

        Assert.AreEqual((byte)0xAB, value);
        Assert.AreEqual(1, reader.Consumed);
        Assert.AreEqual(1, reader.Remaining);
    }

    [TestMethod]
    public void ReadUInt16ReadsBigEndian()
    {
        byte[] buffer = [0x12, 0x34];
        var reader = new TpmReader(buffer);

        ushort value = reader.ReadUInt16();

        Assert.AreEqual((ushort)0x1234, value);
        Assert.AreEqual(2, reader.Consumed);
    }

    [TestMethod]
    public void ReadUInt32ReadsBigEndian()
    {
        byte[] buffer = [0x12, 0x34, 0x56, 0x78];
        var reader = new TpmReader(buffer);

        uint value = reader.ReadUInt32();

        Assert.AreEqual(0x12345678u, value);
        Assert.AreEqual(4, reader.Consumed);
    }

    [TestMethod]
    public void ReadUInt64ReadsBigEndian()
    {
        byte[] buffer = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        var reader = new TpmReader(buffer);

        ulong value = reader.ReadUInt64();

        Assert.AreEqual(0x123456789ABCDEF0ul, value);
        Assert.AreEqual(8, reader.Consumed);
    }

    [TestMethod]
    public void ReadBytesReturnsCorrectSlice()
    {
        byte[] buffer = [0x01, 0x02, 0x03, 0x04, 0x05];
        var reader = new TpmReader(buffer);

        ReadOnlySpan<byte> bytes = reader.ReadBytes(3);

        Assert.AreEqual(3, bytes.Length);
        Assert.AreEqual((byte)0x01, bytes[0]);
        Assert.AreEqual((byte)0x02, bytes[1]);
        Assert.AreEqual((byte)0x03, bytes[2]);
        Assert.AreEqual(3, reader.Consumed);
        Assert.AreEqual(2, reader.Remaining);
    }

    [TestMethod]
    public void ReadTpm2bParsesLengthPrefixedData()
    {
        byte[] buffer = [0x00, 0x03, 0xAA, 0xBB, 0xCC, 0xFF];
        var reader = new TpmReader(buffer);

        ReadOnlySpan<byte> data = reader.ReadTpm2b();

        Assert.AreEqual(3, data.Length);
        Assert.AreEqual((byte)0xAA, data[0]);
        Assert.AreEqual((byte)0xBB, data[1]);
        Assert.AreEqual((byte)0xCC, data[2]);
        Assert.AreEqual(5, reader.Consumed);
    }

    [TestMethod]
    public void PeekBytesDoesNotAdvance()
    {
        byte[] buffer = [0x01, 0x02, 0x03];
        var reader = new TpmReader(buffer);

        ReadOnlySpan<byte> peeked = reader.PeekBytes(2);

        Assert.AreEqual(2, peeked.Length);
        Assert.AreEqual(0, reader.Consumed);
        Assert.AreEqual(3, reader.Remaining);
    }

    [TestMethod]
    public void SkipAdvancesPosition()
    {
        byte[] buffer = [0x01, 0x02, 0x03, 0x04];
        var reader = new TpmReader(buffer);

        reader.Skip(2);

        Assert.AreEqual(2, reader.Consumed);
        Assert.AreEqual((byte)0x03, reader.ReadByte());
    }

    [TestMethod]
    public void MultipleReadsTrackPositionCorrectly()
    {
        byte[] buffer = [0x00, 0x10, 0x12, 0x34, 0x56, 0x78, 0xAB];
        var reader = new TpmReader(buffer);

        ushort first = reader.ReadUInt16();
        uint second = reader.ReadUInt32();
        byte third = reader.ReadByte();

        Assert.AreEqual((ushort)0x0010, first);
        Assert.AreEqual(0x12345678u, second);
        Assert.AreEqual((byte)0xAB, third);
        Assert.AreEqual(7, reader.Consumed);
        Assert.IsTrue(reader.IsEmpty);
    }
}
