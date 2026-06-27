using System;
using System.Diagnostics;

using Verifiable.Apdu;

namespace Verifiable.Tests.Apdu;

[TestClass]
internal sealed class ApduExchangeTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void InstructionByteExtractedFromCommand()
    {
        byte[] command = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];
        byte[] response = [0x61, 0x11, 0x90, 0x00];
        long start = Stopwatch.GetTimestamp();

        var exchange = new ApduExchange(start, start + 1000, command, response);

        Assert.AreEqual((byte)0xA4, exchange.Instruction);
        Assert.AreEqual("Select", exchange.InstructionName);
    }

    [TestMethod]
    public void StatusWordExtractedFromResponse()
    {
        byte[] command = [0x00, 0xCB, 0x3F, 0xFF];
        byte[] response = [0x53, 0x3B, 0x6A, 0x82];
        long start = Stopwatch.GetTimestamp();

        var exchange = new ApduExchange(start, start + 1000, command, response);

        Assert.IsNotNull(exchange.StatusWord);
        Assert.AreEqual((ushort)0x6A82, exchange.StatusWord!.Value.Value);
    }

    [TestMethod]
    public void StatusWordNullForEmptyResponse()
    {
        byte[] command = [0x00, 0xA4, 0x04, 0x00];
        byte[] response = [];
        long start = Stopwatch.GetTimestamp();

        var exchange = new ApduExchange(start, start + 1000, command, response);

        Assert.IsNull(exchange.StatusWord);
    }

    [TestMethod]
    public void StatusWordNullForSingleByteResponse()
    {
        byte[] command = [0x00, 0xA4, 0x04, 0x00];
        byte[] response = [0x90];
        long start = Stopwatch.GetTimestamp();

        var exchange = new ApduExchange(start, start + 1000, command, response);

        Assert.IsNull(exchange.StatusWord);
    }

    [TestMethod]
    public void StatusWordExtractedFromSwOnlyResponse()
    {
        byte[] command = [0x00, 0x20, 0x00, 0x80];
        byte[] response = [0x90, 0x00];
        long start = Stopwatch.GetTimestamp();

        var exchange = new ApduExchange(start, start + 1000, command, response);

        Assert.IsNotNull(exchange.StatusWord);
        Assert.IsTrue(exchange.StatusWord!.Value.IsSuccess);
    }

    [TestMethod]
    public void ElapsedReflectsTimestampDifference()
    {
        byte[] command = [0x00, 0xA4, 0x04, 0x00];
        byte[] response = [0x90, 0x00];
        long start = Stopwatch.GetTimestamp();
        long end = start + Stopwatch.Frequency;

        var exchange = new ApduExchange(start, end, command, response);

        //The elapsed should be approximately one second.
        Assert.IsGreaterThan(900d, exchange.Elapsed.TotalMilliseconds,
            "Elapsed should be approximately one second.");
        Assert.IsLessThan(1100d, exchange.Elapsed.TotalMilliseconds,
            "Elapsed should be approximately one second.");
    }
}
