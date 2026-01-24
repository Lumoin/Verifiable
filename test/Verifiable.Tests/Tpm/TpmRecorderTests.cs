using Verifiable.Tpm;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for <see cref="TpmRecorder"/> functionality.
/// </summary>
[TestClass]
public class TpmRecorderTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void RecordsExchanges()
    {
        var recorder = new TpmRecorder();
        var exchange1 = new TpmExchange(0, 100, new byte[] { 0x01 }, new byte[] { 0x02 });
        var exchange2 = new TpmExchange(100, 200, new byte[] { 0x03 }, new byte[] { 0x04 });

        recorder.OnNext(exchange1);
        recorder.OnNext(exchange2);

        Assert.AreEqual(2, recorder.Count);
    }

    [TestMethod]
    public void StopsRecordingAfterCompletion()
    {
        var recorder = new TpmRecorder();
        var exchange = new TpmExchange(0, 100, new byte[] { 0x01 }, new byte[] { 0x02 });

        recorder.OnNext(exchange);
        recorder.OnCompleted();
        recorder.OnNext(new TpmExchange(200, 300, new byte[] { 0x05 }, new byte[] { 0x06 }));

        Assert.AreEqual(1, recorder.Count);
    }

    [TestMethod]
    public void StopsRecordingAfterError()
    {
        var recorder = new TpmRecorder();
        var exchange = new TpmExchange(0, 100, new byte[] { 0x01 }, new byte[] { 0x02 });

        recorder.OnNext(exchange);
        recorder.OnError(new InvalidOperationException("Test error."));
        recorder.OnNext(new TpmExchange(200, 300, new byte[] { 0x05 }, new byte[] { 0x06 }));

        Assert.AreEqual(1, recorder.Count);
    }

    [TestMethod]
    public void CreatesRecordingWithSessionInfo()
    {
        const string expectedManufacturer = "INTC";
        const string expectedFirmwareVersion = "7.2.0";

        var recorder = new TpmRecorder();
        recorder.OnNext(new TpmExchange(0, 100, new byte[] { 0x01 }, new byte[] { 0x02 }));

        TpmSessionInfo info = TpmSessionInfo.Create(expectedManufacturer, expectedFirmwareVersion, TpmPlatform.Windows, TimeProvider.System);

        TpmRecording recording = recorder.ToRecording(info);

        Assert.AreEqual(expectedManufacturer, recording.Info.Manufacturer);
        Assert.AreEqual(expectedFirmwareVersion, recording.Info.FirmwareVersion);
        Assert.AreEqual(TpmPlatform.Windows, recording.Info.Platform);
        Assert.HasCount(1, recording.Exchanges);
    }

    [TestMethod]
    public void ClearResetsState()
    {
        var recorder = new TpmRecorder();
        recorder.OnNext(new TpmExchange(0, 100, new byte[] { 0x01 }, new byte[] { 0x02 }));
        recorder.OnCompleted();

        recorder.Clear();
        recorder.OnNext(new TpmExchange(200, 300, new byte[] { 0x03 }, new byte[] { 0x04 }));

        Assert.AreEqual(1, recorder.Count);
    }

    [TestMethod]
    public void ToRecordingReturnsSnapshotNotLiveReference()
    {
        var recorder = new TpmRecorder();
        recorder.OnNext(new TpmExchange(0, 100, new byte[] { 0x01 }, new byte[] { 0x02 }));

        TpmSessionInfo info = TpmSessionInfo.Create(null, null, TpmPlatform.Unknown, TimeProvider.System);
        TpmRecording recording = recorder.ToRecording(info);

        recorder.OnNext(new TpmExchange(200, 300, new byte[] { 0x03 }, new byte[] { 0x04 }));

        Assert.HasCount(1, recording.Exchanges);
        Assert.AreEqual(2, recorder.Count);
    }

    [TestMethod]
    public void DisposeStopsRecording()
    {
        var recorder = new TpmRecorder();
        recorder.OnNext(new TpmExchange(0, 100, new byte[] { 0x01 }, new byte[] { 0x02 }));

        recorder.Dispose();
        recorder.OnNext(new TpmExchange(200, 300, new byte[] { 0x03 }, new byte[] { 0x04 }));

        Assert.AreEqual(0, recorder.Count);
    }
}