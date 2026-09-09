using System;
using System.Diagnostics;

using Verifiable.Apdu;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Proves <see cref="ApduExchange"/>'s own field extraction and elapsed-time arithmetic over synthetic
/// tick pairs: <see cref="ApduExchange.Elapsed"/> is <c>Stopwatch.GetElapsedTime(StartTicks, EndTicks)</c>,
/// a pure function of the tick delta, so a fixed literal start tick exercises exactly the same arithmetic
/// a real <c>Stopwatch.GetTimestamp()</c> reading would — only the delta between the two ticks given to the
/// constructor matters, never wall-clock time elapsed while the test itself runs.
/// </summary>
[TestClass]
internal sealed class ApduExchangeTests
{
    public TestContext TestContext { get; set; } = null!;

    /// <summary>Proves the instruction byte is extracted from the command's second octet.</summary>
    [TestMethod]
    public void InstructionByteExtractedFromCommand()
    {
        byte[] command = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];
        byte[] response = [0x61, 0x11, 0x90, 0x00];
        const long start = 0L;

        var exchange = new ApduExchange(start, start + 1000, command, response);

        Assert.AreEqual((byte)0xA4, exchange.Instruction);
        Assert.AreEqual("Select", exchange.InstructionName);
    }

    /// <summary>Proves the status word is extracted from the response's trailing two octets.</summary>
    [TestMethod]
    public void StatusWordExtractedFromResponse()
    {
        byte[] command = [0x00, 0xCB, 0x3F, 0xFF];
        byte[] response = [0x53, 0x3B, 0x6A, 0x82];
        const long start = 0L;

        var exchange = new ApduExchange(start, start + 1000, command, response);

        Assert.IsNotNull(exchange.StatusWord);
        Assert.AreEqual((ushort)0x6A82, exchange.StatusWord!.Value.Value);
    }

    /// <summary>Proves an empty response carries no status word.</summary>
    [TestMethod]
    public void StatusWordNullForEmptyResponse()
    {
        byte[] command = [0x00, 0xA4, 0x04, 0x00];
        byte[] response = [];
        const long start = 0L;

        var exchange = new ApduExchange(start, start + 1000, command, response);

        Assert.IsNull(exchange.StatusWord);
    }

    /// <summary>Proves a single-byte response carries no status word (two octets are required).</summary>
    [TestMethod]
    public void StatusWordNullForSingleByteResponse()
    {
        byte[] command = [0x00, 0xA4, 0x04, 0x00];
        byte[] response = [0x90];
        const long start = 0L;

        var exchange = new ApduExchange(start, start + 1000, command, response);

        Assert.IsNull(exchange.StatusWord);
    }

    /// <summary>Proves the status word is extracted from a response consisting of only the two status-word octets.</summary>
    [TestMethod]
    public void StatusWordExtractedFromSwOnlyResponse()
    {
        byte[] command = [0x00, 0x20, 0x00, 0x80];
        byte[] response = [0x90, 0x00];
        const long start = 0L;

        var exchange = new ApduExchange(start, start + 1000, command, response);

        Assert.IsNotNull(exchange.StatusWord);
        Assert.IsTrue(exchange.StatusWord!.Value.IsSuccess);
    }

    /// <summary>
    /// Proves <see cref="ApduExchange.Elapsed"/>'s own arithmetic over a tick delta of exactly
    /// <see cref="Stopwatch.Frequency"/> — the delta that means one second — converts to approximately one
    /// second: this is a correctness proof of the production property's tick-to-<see cref="TimeSpan"/>
    /// conversion over deterministic synthetic ticks, not a wall-clock measurement of the test itself.
    /// </summary>
    [TestMethod]
    public void ElapsedReflectsTimestampDifference()
    {
        byte[] command = [0x00, 0xA4, 0x04, 0x00];
        byte[] response = [0x90, 0x00];
        const long start = 0L;
        long end = start + Stopwatch.Frequency;

        var exchange = new ApduExchange(start, end, command, response);
        TimeSpan elapsed = exchange.Elapsed;

        //The elapsed should be approximately one second.
        Assert.IsGreaterThan(900d, elapsed.TotalMilliseconds,
            "Elapsed should be approximately one second.");
        Assert.IsLessThan(1100d, elapsed.TotalMilliseconds,
            "Elapsed should be approximately one second.");
    }
}
