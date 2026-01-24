using Verifiable.Tpm;
using Verifiable.Tpm.Commands;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for <see cref="TpmDevice"/> and its extensions.
/// </summary>
[TestClass]
[TestCategory("RequiresTpm")]
public class TpmDeviceTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void IsFipsModeReturnsBooleanValue()
    {
        if(!TpmDevice.IsAvailable)
        {
            Assert.Inconclusive("TPM not available on this system.");
        }

        using TpmDevice tpm = TpmDevice.Open();

        //Should not throw, returns true or false.
        bool isFips = tpm.IsFipsMode();

        TestContext.WriteLine($"FIPS mode: {isFips}");
    }

    [TestMethod]
    public void GetSessionInfoReturnsMetadata()
    {
        if(!TpmDevice.IsAvailable)
        {
            Assert.Inconclusive("TPM not available on this system.");
        }

        using TpmDevice tpm = TpmDevice.Open();
        TpmSessionInfo info = tpm.GetSessionInfo(TimeProvider.System);

        Assert.IsNotNull(info);
        TestContext.WriteLine($"Manufacturer: {info.Manufacturer}");
        TestContext.WriteLine($"Firmware: {info.FirmwareVersion}");
        TestContext.WriteLine($"Platform: {info.Platform}");
    }

    [TestMethod]
    public void ReadClockReturnsTimeInfo()
    {
        if(!TpmDevice.IsAvailable)
        {
            Assert.Inconclusive("TPM not available on this system.");
        }

        using TpmDevice tpm = TpmDevice.Open();
        ReadClockOutput clock = tpm.ReadClock();

        //Clock values should be non-negative (they're unsigned).
        TestContext.WriteLine($"Time: {clock.Time}");
        TestContext.WriteLine($"Clock: {clock.Clock}");
        TestContext.WriteLine($"ResetCount: {clock.ResetCount}");
        TestContext.WriteLine($"RestartCount: {clock.RestartCount}");
        TestContext.WriteLine($"Safe: {clock.Safe}");
    }

    [TestMethod]
    public void GetRandomReturnsRequestedBytes()
    {
        if(!TpmDevice.IsAvailable)
        {
            Assert.Inconclusive("TPM not available on this system.");
        }

        using TpmDevice tpm = TpmDevice.Open();
        GetRandomOutput result = tpm.GetRandom(16);

        byte[] randomBytes = result.Bytes.ToArray();
        Assert.HasCount(16, randomBytes);

        //Verify not all zeros (statistically unlikely for true random).
        bool hasNonZero = false;
        foreach(byte b in randomBytes)
        {
            if(b != 0)
            {
                hasNonZero = true;
                break;
            }
        }

        Assert.IsTrue(hasNonZero, "Random bytes should not all be zero.");
    }

    [TestMethod]
    public void GetCapabilityReturnsProperties()
    {
        if(!TpmDevice.IsAvailable)
        {
            Assert.Inconclusive("TPM not available on this system.");
        }

        using TpmDevice tpm = TpmDevice.Open();
        GetCapabilityOutput result = tpm.GetCapability(
            Tpm2CapConstants.TPM_CAP_TPM_PROPERTIES,
            (uint)Tpm2PtConstants.TPM2_PT_MANUFACTURER,
            8);

        Assert.IsNotEmpty(result.Properties);

        foreach(TpmProperty prop in result.Properties)
        {
            TestContext.WriteLine($"Property 0x{prop.Property:X8}: 0x{prop.Value:X8}");
        }
    }

    [TestMethod]
    public void HashComputesSha256Digest()
    {
        if(!TpmDevice.IsAvailable)
        {
            Assert.Inconclusive("TPM not available on this system.");
        }

        using TpmDevice tpm = TpmDevice.Open();
        byte[] data = "Hello, TPM!"u8.ToArray();

        HashOutput result = tpm.Hash(Tpm2AlgId.TPM_ALG_SHA256, data);

        byte[] digest = result.Digest.ToArray();
        Assert.HasCount(32, digest);

        TestContext.WriteLine($"Digest: {Convert.ToHexString(digest)}");
    }

    [TestMethod]
    public void IsFipsModeWithRecordingDoesNotThrow()
    {
        if(!TpmDevice.IsAvailable)
        {
            Assert.Inconclusive("TPM not available on this system.");
        }

        var recorder = new TpmRecorder();

        using(TpmDevice tpm = TpmDevice.Open())
        {
            tpm.Subscribe(recorder);

            bool isFips = tpm.IsFipsMode();
            TestContext.WriteLine($"FIPS mode: {isFips}");

            TpmSessionInfo info = tpm.GetSessionInfo(TimeProvider.System);
            TpmRecording recording = recorder.ToRecording(info);

            Assert.IsNotEmpty(recording.Exchanges);

            foreach(TpmExchange exchange in recording.Exchanges)
            {
                TestContext.WriteLine($"Command: {exchange.Command.Length} bytes, Response: {exchange.Response.Length} bytes");
            }
        }
    }

    [TestMethod]
    public void GetSessionInfoWithRecordingCapturesMetadata()
    {
        if(!TpmDevice.IsAvailable)
        {
            Assert.Inconclusive("TPM not available on this system.");
        }

        var recorder = new TpmRecorder();

        using(TpmDevice tpm = TpmDevice.Open())
        {
            tpm.Subscribe(recorder);

            TpmSessionInfo info = tpm.GetSessionInfo(TimeProvider.System);

            TestContext.WriteLine($"Manufacturer: {info.Manufacturer}");
            TestContext.WriteLine($"Firmware: {info.FirmwareVersion}");

            TpmRecording recording = recorder.ToRecording(info);
            Assert.IsNotEmpty(recording.Exchanges);
        }
    }
}