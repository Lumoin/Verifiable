using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Apdu;

namespace Verifiable.Tests.Apdu;

[TestClass]
internal sealed class VirtualCardTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task RegisteredResponseIsReturned()
    {
        var virtualCard = new VirtualCard();

        byte[] selectPiv = [0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];
        byte[] fciResponse = [0x61, 0x11, 0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x90, 0x00];
        virtualCard.Register(selectPiv, fciResponse);

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        ApduResult<ApduResponse> result = await virtualCard.TransceiveAsync(
            selectPiv, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ApduResponse response = result.Value;
        Assert.IsTrue(response.StatusWord.IsSuccess);
        Assert.IsTrue(response.HasData);
        Assert.AreEqual(10, response.DataLength);
    }

    [TestMethod]
    public async Task UnregisteredCommandReturnsInsNotSupported()
    {
        var virtualCard = new VirtualCard();
        byte[] unknownCommand = [0x00, 0xFF, 0x00, 0x00];

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        ApduResult<ApduResponse> result = await virtualCard.TransceiveAsync(
            unknownCommand, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ApduResponse response = result.Value;
        Assert.IsTrue(response.StatusWord.IsInstructionNotSupported);
        Assert.IsFalse(response.HasData);
    }

    [TestMethod]
    public void HasResponseReturnsTrueForRegistered()
    {
        var virtualCard = new VirtualCard();
        byte[] command = [0x00, 0xA4, 0x04, 0x00];
        byte[] response = [0x90, 0x00];

        virtualCard.Register(command, response);

        Assert.IsTrue(virtualCard.HasResponse(command));
    }

    [TestMethod]
    public void HasResponseReturnsFalseForUnregistered()
    {
        var virtualCard = new VirtualCard();

        Assert.IsFalse(virtualCard.HasResponse([0x00, 0xFF, 0x00, 0x00]));
    }

    [TestMethod]
    public void ClearRemovesAllResponses()
    {
        var virtualCard = new VirtualCard();
        virtualCard.Register([0x00, 0xA4, 0x04, 0x00], [0x90, 0x00]);
        Assert.AreEqual(1, virtualCard.ResponseCount);

        virtualCard.Clear();

        Assert.AreEqual(0, virtualCard.ResponseCount);
    }

    [TestMethod]
    public void LoadFromRecordingPopulatesResponses()
    {
        var exchanges = new ApduExchange[]
        {
            new(0, 100,
                new byte[] { 0x00, 0xA4, 0x04, 0x00 },
                new byte[] { 0x90, 0x00 }),
            new(200, 300,
                new byte[] { 0x00, 0xCB, 0x3F, 0xFF },
                new byte[] { 0x53, 0x3B, 0x90, 0x00 })
        };

        var info = new CardSessionInfo(null, null, ApduPlatform.Virtual, TimeProvider.System.GetUtcNow());
        var recording = new ApduRecording(info, exchanges);

        var virtualCard = new VirtualCard();
        virtualCard.Load(recording);

        Assert.AreEqual(2, virtualCard.ResponseCount);
    }

    [TestMethod]
    public async Task DeviceWithVirtualCardEndToEnd()
    {
        var virtualCard = new VirtualCard();
        byte[] selectPiv = [0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];
        byte[] response = [0x61, 0x11, 0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x90, 0x00];
        virtualCard.Register(selectPiv, response);

        using var device = ApduDevice.Create(virtualCard.TransceiveAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ApduResult<ApduResponse> result = await device.TransceiveAsync(
            selectPiv, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ApduResponse apduResponse = result.Value;
        Assert.IsTrue(apduResponse.StatusWord.IsSuccess);
    }
}
