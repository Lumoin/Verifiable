using System;

using Verifiable.Apdu;

namespace Verifiable.Tests.Apdu;

[TestClass]
internal sealed class ApduReaderWriterTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void WriterTracksPosition()
    {
        Span<byte> buffer = stackalloc byte[16];
        var writer = new ApduWriter(buffer);

        writer.WriteByte(0x00);
        writer.WriteByte(0xA4);

        Assert.AreEqual(2, writer.Written);
        Assert.AreEqual(14, writer.Remaining);
    }

    [TestMethod]
    public void WriteHeaderProducesCorrectBytes()
    {
        Span<byte> buffer = stackalloc byte[4];
        var writer = new ApduWriter(buffer);

        writer.WriteHeader(0x00, 0xA4, 0x04, 0x00);

        Assert.AreEqual(4, writer.Written);
        Assert.AreEqual((byte)0x00, buffer[0]);
        Assert.AreEqual((byte)0xA4, buffer[1]);
        Assert.AreEqual((byte)0x04, buffer[2]);
        Assert.AreEqual((byte)0x00, buffer[3]);
    }

    [TestMethod]
    public void WriteUint16ProducesBigEndian()
    {
        Span<byte> buffer = stackalloc byte[2];
        var writer = new ApduWriter(buffer);

        writer.WriteUInt16(0x0102);

        Assert.AreEqual((byte)0x01, buffer[0]);
        Assert.AreEqual((byte)0x02, buffer[1]);
    }

    [TestMethod]
    public void WriteBytesProducesExactCopy()
    {
        Span<byte> buffer = stackalloc byte[8];
        var writer = new ApduWriter(buffer);

        ReadOnlySpan<byte> data = [0xA0, 0x00, 0x00, 0x03, 0x08];
        writer.WriteBytes(data);

        Assert.AreEqual(5, writer.Written);
        Assert.IsTrue(buffer[..5].SequenceEqual(data));
    }

    [TestMethod]
    public void ReaderTracksPosition()
    {
        ReadOnlySpan<byte> data = [0x00, 0xA4, 0x04, 0x00, 0x05];
        var reader = new ApduReader(data);

        byte first = reader.ReadByte();

        Assert.AreEqual((byte)0x00, first);
        Assert.AreEqual(1, reader.Consumed);
        Assert.AreEqual(4, reader.Remaining);
        Assert.AreEqual(1, reader.Position);
    }

    [TestMethod]
    public void ReaderReadUint16BigEndian()
    {
        ReadOnlySpan<byte> data = [0x01, 0x02];
        var reader = new ApduReader(data);

        ushort value = reader.ReadUInt16();

        Assert.AreEqual((ushort)0x0102, value);
        Assert.IsTrue(reader.IsEmpty);
    }

    [TestMethod]
    public void ReaderReadBytesReturnsExactSlice()
    {
        ReadOnlySpan<byte> data = [0xA0, 0x00, 0x00, 0x03, 0x08, 0xFF, 0xFF];
        var reader = new ApduReader(data);

        ReadOnlySpan<byte> aid = reader.ReadBytes(5);

        Assert.AreEqual(5, aid.Length);
        Assert.AreEqual((byte)0xA0, aid[0]);
        Assert.AreEqual((byte)0x08, aid[4]);
        Assert.AreEqual(2, reader.Remaining);
    }

    [TestMethod]
    public void ReaderReadRemainingBytesConsumesAll()
    {
        ReadOnlySpan<byte> data = [0x01, 0x02, 0x03];
        var reader = new ApduReader(data);

        reader.ReadByte();
        ReadOnlySpan<byte> remaining = reader.ReadRemainingBytes();

        Assert.AreEqual(2, remaining.Length);
        Assert.IsTrue(reader.IsEmpty);
    }

    [TestMethod]
    public void ReaderPeekDoesNotConsume()
    {
        ReadOnlySpan<byte> data = [0x01, 0x02, 0x03];
        var reader = new ApduReader(data);

        ReadOnlySpan<byte> peeked = reader.PeekBytes(2);

        Assert.AreEqual(2, peeked.Length);
        Assert.AreEqual(0, reader.Consumed);
    }

    [TestMethod]
    public void ReaderSkipAdvancesPosition()
    {
        ReadOnlySpan<byte> data = [0x01, 0x02, 0x03, 0x04];
        var reader = new ApduReader(data);

        reader.Skip(2);

        Assert.AreEqual(2, reader.Consumed);
        Assert.AreEqual(2, reader.Remaining);
    }

    [TestMethod]
    public void ReaderTlvLengthShortForm()
    {
        ReadOnlySpan<byte> data = [0x7F];
        var reader = new ApduReader(data);

        int length = reader.ReadTlvLength();

        Assert.AreEqual(127, length);
    }

    [TestMethod]
    public void ReaderTlvLengthOneByteExtended()
    {
        ReadOnlySpan<byte> data = [0x81, 0xFF];
        var reader = new ApduReader(data);

        int length = reader.ReadTlvLength();

        Assert.AreEqual(255, length);
    }

    [TestMethod]
    public void ReaderTlvLengthTwoByteExtended()
    {
        ReadOnlySpan<byte> data = [0x82, 0x01, 0x2A];
        var reader = new ApduReader(data);

        int length = reader.ReadTlvLength();

        Assert.AreEqual(298, length);
    }

    [TestMethod]
    public void RoundtripSelectCommand()
    {
        //Build a SELECT command: 00 A4 04 00 09 A0 00 00 03 08 00 00 10 00.
        ReadOnlySpan<byte> aid = [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];
        Span<byte> buffer = stackalloc byte[ApduConstants.CommandHeaderSize + 1 + aid.Length];
        var writer = new ApduWriter(buffer);

        writer.WriteHeader(0x00, 0xA4, 0x04, 0x00);
        writer.WriteByte((byte)aid.Length);
        writer.WriteBytes(aid);

        //Parse it back.
        var reader = new ApduReader(buffer);
        byte cla = reader.ReadByte();
        byte ins = reader.ReadByte();
        byte p1 = reader.ReadByte();
        byte p2 = reader.ReadByte();
        byte lc = reader.ReadByte();
        ReadOnlySpan<byte> parsedAid = reader.ReadBytes(lc);

        Assert.AreEqual((byte)0x00, cla);
        Assert.AreEqual((byte)0xA4, ins);
        Assert.AreEqual((byte)0x04, p1);
        Assert.AreEqual((byte)0x00, p2);
        Assert.AreEqual((byte)0x09, lc);
        Assert.IsTrue(parsedAid.SequenceEqual(aid));
        Assert.IsTrue(reader.IsEmpty);
    }
}
