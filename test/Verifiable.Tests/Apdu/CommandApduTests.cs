using System;
using System.Buffers;
using Verifiable.Apdu;

namespace Verifiable.Tests.Apdu;

[TestClass]
internal sealed class CommandApduTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void Case1HeaderOnly()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using CommandApdu command = CommandApdu.BuildCase1(
            0x00, 0xFB, 0x00, 0x00, pool);

        //PIV RESET: 00 FB 00 00.
        ReadOnlySpan<byte> bytes = command.AsReadOnlySpan()[..ApduConstants.CommandHeaderSize];
        Assert.AreEqual((byte)0x00, bytes[0]);
        Assert.AreEqual((byte)0xFB, bytes[1]);
        Assert.AreEqual((byte)0x00, bytes[2]);
        Assert.AreEqual((byte)0x00, bytes[3]);
    }

    [TestMethod]
    public void Case2ShortLeEncoding()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using CommandApdu command = CommandApdu.BuildCase2(
            0x00, 0xFD, 0x00, 0x00, 3, useExtended: false, pool);

        //YUBI GET VERSION: 00 FD 00 00 03.
        ReadOnlySpan<byte> bytes = command.AsReadOnlySpan()[..5];
        Assert.AreEqual((byte)0x00, bytes[0]);
        Assert.AreEqual((byte)0xFD, bytes[1]);
        Assert.AreEqual((byte)0x00, bytes[2]);
        Assert.AreEqual((byte)0x00, bytes[3]);
        Assert.AreEqual((byte)0x03, bytes[4]);
    }

    [TestMethod]
    public void Case2ShortLeZeroMeans256()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using CommandApdu command = CommandApdu.BuildCase2(
            0x00, 0xCA, 0xDF, 0x30, 0, useExtended: false, pool);

        //GET DATA with Le=00 (meaning 256): 00 CA DF 30 00.
        ReadOnlySpan<byte> bytes = command.AsReadOnlySpan()[..5];
        Assert.AreEqual((byte)0x00, bytes[4]);
    }

    [TestMethod]
    public void Case2ExtendedLeEncoding()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using CommandApdu command = CommandApdu.BuildCase2(
            0x00, 0xCB, 0x3F, 0xFF, 0, useExtended: true, pool);

        //Extended Le: 00 CB 3F FF 00 00 00.
        ReadOnlySpan<byte> bytes = command.AsReadOnlySpan()[..7];
        Assert.AreEqual((byte)0x00, bytes[0]);
        Assert.AreEqual((byte)0xCB, bytes[1]);
        Assert.AreEqual((byte)0x00, bytes[4]);
        Assert.AreEqual((byte)0x00, bytes[5]);
        Assert.AreEqual((byte)0x00, bytes[6]);
    }

    [TestMethod]
    public void Case3ShortLcEncoding()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] data = [0x5C, 0x01, 0x7E];

        using CommandApdu command = CommandApdu.BuildCase3(
            0x00, 0xCB, 0x3F, 0xFF, data, pool);

        //GET DATA BER-TLV: 00 CB 3F FF 03 5C 01 7E.
        ReadOnlySpan<byte> bytes = command.AsReadOnlySpan()[..8];
        Assert.AreEqual((byte)0x00, bytes[0]);
        Assert.AreEqual((byte)0xCB, bytes[1]);
        Assert.AreEqual((byte)0x3F, bytes[2]);
        Assert.AreEqual((byte)0xFF, bytes[3]);
        Assert.AreEqual((byte)0x03, bytes[4]);
        Assert.AreEqual((byte)0x5C, bytes[5]);
        Assert.AreEqual((byte)0x01, bytes[6]);
        Assert.AreEqual((byte)0x7E, bytes[7]);
    }

    [TestMethod]
    public void Case3ExtendedLcForLargeData()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] data = new byte[300];
        Array.Fill(data, (byte)0xAA);

        using CommandApdu command = CommandApdu.BuildCase3(
            0x00, 0xDB, 0x3F, 0xFF, data, pool);

        //Extended: header(4) + 0x00(1) + Lc(2) + data(300) = 307 bytes.
        ReadOnlySpan<byte> bytes = command.AsReadOnlySpan()[..307];
        Assert.AreEqual((byte)0x00, bytes[0]);
        Assert.AreEqual((byte)0xDB, bytes[1]);
        Assert.AreEqual((byte)0x00, bytes[4]);
        Assert.AreEqual((byte)0x01, bytes[5]);
        Assert.AreEqual((byte)0x2C, bytes[6]);
        Assert.AreEqual((byte)0xAA, bytes[7]);
    }

    [TestMethod]
    public void Case4ShortEncoding()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] data = [0x5C, 0x03, 0x5F, 0xC1, 0x02];

        using CommandApdu command = CommandApdu.BuildCase4(
            0x00, 0xCB, 0x3F, 0xFF, data, 0, pool);

        //GET DATA with data and Le=0: 00 CB 3F FF 05 5C 03 5F C1 02 00.
        ReadOnlySpan<byte> bytes = command.AsReadOnlySpan()[..11];
        Assert.AreEqual((byte)0x00, bytes[0]);
        Assert.AreEqual((byte)0xCB, bytes[1]);
        Assert.AreEqual((byte)0x05, bytes[4]);
        Assert.AreEqual((byte)0x5C, bytes[5]);
        Assert.AreEqual((byte)0x02, bytes[9]);
        Assert.AreEqual((byte)0x00, bytes[10]);
    }

    [TestMethod]
    public void Case4MatchesYubiKeyPivSelectFromTrace()
    {
        //From the CardForensics trace, exchange #5:
        //00 A4 04 00 09 A0 00 00 03 08 00 00 10 00 00
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] aid = [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];

        using CommandApdu command = CommandApdu.BuildCase4(
            0x00, 0xA4, 0x04, 0x00, aid, 0, pool);

        ReadOnlySpan<byte> bytes = command.AsReadOnlySpan()[..15];
        byte[] expected = [0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x00];

        Assert.IsTrue(bytes.SequenceEqual(expected),
            "Built command should match the wire format from the YubiKey PIV trace.");
    }
}
