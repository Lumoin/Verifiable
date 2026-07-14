using System;
using System.Buffers;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Apdu;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Apdu;

[TestClass]
internal sealed class ApduRecorderTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task RecorderCapturesExchanges()
    {
        var virtualCard = new VirtualCard();
        virtualCard.Register(
            [0x00, 0xA4, 0x04, 0x00],
            [0x90, 0x00]);

        using var device = ApduDevice.Create(virtualCard.TransceiveAsync);
        using var recorder = new ApduRecorder();
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using(device.Subscribe(recorder))
        {
            ApduResult<ApduResponse> result = await device.TransceiveAsync(
                new byte[] { 0x00, 0xA4, 0x04, 0x00 }, pool, TestContext.CancellationToken).ConfigureAwait(false);

            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }
        }

        Assert.AreEqual(1, recorder.Count);
    }

    [TestMethod]
    public async Task RecorderStopsAfterOnCompleted()
    {
        var virtualCard = new VirtualCard();
        virtualCard.Register(
            [0x00, 0xA4, 0x04, 0x00],
            [0x90, 0x00]);

        using var device = ApduDevice.Create(virtualCard.TransceiveAsync);
        using var recorder = new ApduRecorder();
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        IDisposable subscription = device.Subscribe(recorder);

        ApduResult<ApduResponse> r1 = await device.TransceiveAsync(
            new byte[] { 0x00, 0xA4, 0x04, 0x00 }, pool, TestContext.CancellationToken).ConfigureAwait(false);
        if(r1.IsSuccess)
        {
            r1.Value.Dispose();
        }

        //Unsubscribe by disposing.
        subscription.Dispose();

        //Device dispose triggers OnCompleted for remaining subscribers.
        //Since we already unsubscribed, recorder should have exactly 1 exchange.
        Assert.AreEqual(1, recorder.Count);
    }

    [TestMethod]
    public async Task RecordingRoundtripThroughVirtualCard()
    {
        //Step 1: Capture a session.
        var originalCard = new VirtualCard();
        byte[] selectCmd = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];
        byte[] selectRsp = [0x61, 0x11, 0x4F, 0x06, 0x90, 0x00];
        byte[] getDataCmd = [0x00, 0xCB, 0x3F, 0xFF, 0x03, 0x5C, 0x01, 0x7E];
        byte[] getDataRsp = [0x7E, 0x12, 0x4F, 0x0B, 0x90, 0x00];

        originalCard.Register(selectCmd, selectRsp);
        originalCard.Register(getDataCmd, getDataRsp);

        using var captureDevice = ApduDevice.Create(originalCard.TransceiveAsync);
        using var recorder = new ApduRecorder();
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using(captureDevice.Subscribe(recorder))
        {
            ApduResult<ApduResponse> r1 = await captureDevice.TransceiveAsync(
                selectCmd, pool, TestContext.CancellationToken).ConfigureAwait(false);
            if(r1.IsSuccess)
            {
                r1.Value.Dispose();
            }

            ApduResult<ApduResponse> r2 = await captureDevice.TransceiveAsync(
                getDataCmd, pool, TestContext.CancellationToken).ConfigureAwait(false);
            if(r2.IsSuccess)
            {
                r2.Value.Dispose();
            }
        }

        //Step 2: Create a recording.
        var info = CardSessionInfo.Create(null, null, ApduPlatform.Virtual, new FakeTimeProvider(TestClock.CanonicalEpoch), "test session");
        ApduRecording recording = recorder.ToRecording(info);

        Assert.HasCount(2, recording.Exchanges);
        Assert.AreEqual("test session", recording.Info.Label);

        //Step 3: Replay the recording.
        var replayCard = new VirtualCard();
        replayCard.Load(recording);

        using var replayDevice = ApduDevice.Create(replayCard.TransceiveAsync);

        ApduResult<ApduResponse> replayed = await replayDevice.TransceiveAsync(
            selectCmd, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(replayed.IsSuccess);
        using ApduResponse replayedResponse = replayed.Value;
        Assert.IsTrue(replayedResponse.StatusWord.IsSuccess);
    }

    [TestMethod]
    public void ClearResetsRecorder()
    {
        using var recorder = new ApduRecorder();
        recorder.OnNext(new ApduExchange(0, 100, new byte[] { 0x00 }, new byte[] { 0x90, 0x00 }));
        Assert.AreEqual(1, recorder.Count);

        recorder.Clear();

        Assert.AreEqual(0, recorder.Count);
    }

    [TestMethod]
    public void GetExchangesReturnsDefensiveCopy()
    {
        using var recorder = new ApduRecorder();
        recorder.OnNext(new ApduExchange(0, 100, new byte[] { 0x00 }, new byte[] { 0x90, 0x00 }));

        ApduExchange[] first = recorder.GetExchanges();
        ApduExchange[] second = recorder.GetExchanges();

        Assert.AreNotSame(first, second);
        Assert.HasCount(1, first);
    }

    [TestMethod]
    public async Task RecorderCapturesExchangeTimingAndInstruction()
    {
        var virtualCard = new VirtualCard();
        byte[] verifyCmd = [0x00, 0x20, 0x00, 0x80, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF];
        byte[] verifyRsp = [0x90, 0x00];
        virtualCard.Register(verifyCmd, verifyRsp);

        using var device = ApduDevice.Create(virtualCard.TransceiveAsync);
        using var recorder = new ApduRecorder();
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using(device.Subscribe(recorder))
        {
            ApduResult<ApduResponse> result = await device.TransceiveAsync(
                verifyCmd, pool, TestContext.CancellationToken).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }
        }

        ApduExchange[] exchanges = recorder.GetExchanges();
        Assert.HasCount(1, exchanges);

        ApduExchange exchange = exchanges[0];
        Assert.AreEqual(InstructionCode.Verify.Code, exchange.Instruction);
        Assert.AreEqual("Verify", exchange.InstructionName);
        Assert.IsNotNull(exchange.StatusWord);
        Assert.IsTrue(exchange.StatusWord!.Value.IsSuccess);
        Assert.IsGreaterThanOrEqualTo(0d, exchange.Elapsed.TotalMilliseconds, "Elapsed time should be non-negative.");
    }
}
