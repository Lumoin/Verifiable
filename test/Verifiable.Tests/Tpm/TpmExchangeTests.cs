using Verifiable.Tpm;

namespace Verifiable.Tests.Tpm;


/// <summary>
/// Tests for <see cref="TpmExchange"/> record.
/// </summary>
[TestClass]
internal class TpmExchangeTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void DurationCalculatesCorrectly()
    {
        const long startTicks = 1000;
        const long endTicks = 2000;

        var exchange = new TpmExchange(startTicks, endTicks, Array.Empty<byte>(), Array.Empty<byte>());

        TimeSpan expectedDuration = TimeSpan.FromTicks(endTicks - startTicks);
        Assert.AreEqual(expectedDuration, exchange.Duration);
    }


    [TestMethod]
    public void StoresCommandAndResponseBytes()
    {
        byte[] command = [0x01, 0x02, 0x03];
        byte[] response = [0x04, 0x05];

        var exchange = new TpmExchange(0, 100, command, response);

        Assert.AreEqual(command.Length, exchange.Command.Length);
        Assert.AreEqual(response.Length, exchange.Response.Length);
        Assert.IsTrue(command.AsSpan().SequenceEqual(exchange.Command.Span));
        Assert.IsTrue(response.AsSpan().SequenceEqual(exchange.Response.Span));
    }
}