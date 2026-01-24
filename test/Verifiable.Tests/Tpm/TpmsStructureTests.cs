using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for TPMS (TPM structure) types.
/// </summary>
[TestClass]
public class TpmsStructureTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void TpmsClockInfoParsesCorrectly()
    {
        //TPMS_CLOCK_INFO layout: clock (8) + resetCount (4) + restartCount (4) + safe (1) = 17 bytes.
        const ulong expectedClock = 0x12345678UL;
        const uint expectedResetCount = 5;
        const uint expectedRestartCount = 3;
        const bool expectedSafe = true;

        byte[] data =
        [
            0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, //Clock (big-endian).
            0x00, 0x00, 0x00, 0x05, //ResetCount (big-endian).
            0x00, 0x00, 0x00, 0x03, //RestartCount (big-endian).
            0x01 //Safe flag (non-zero = true).
        ];

        TpmsClockInfo clockInfo = TpmsClockInfo.ReadFrom(data);

        Assert.AreEqual(expectedClock, clockInfo.Clock);
        Assert.AreEqual(expectedResetCount, clockInfo.ResetCount);
        Assert.AreEqual(expectedRestartCount, clockInfo.RestartCount);
        Assert.AreEqual(expectedSafe, clockInfo.Safe);
    }

    [TestMethod]
    public void TpmsClockInfoParsesSafeFalseCorrectly()
    {
        byte[] data =
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //Clock.
            0x00, 0x00, 0x00, 0x00, //ResetCount.
            0x00, 0x00, 0x00, 0x00, //RestartCount.
            0x00 //Safe flag (zero = false).
        ];

        TpmsClockInfo clockInfo = TpmsClockInfo.ReadFrom(data);

        Assert.IsFalse(clockInfo.Safe);
    }

    [TestMethod]
    public void TpmsTimeInfoParsesCorrectly()
    {
        //TPMS_TIME_INFO layout: time (8) + TPMS_CLOCK_INFO (17) = 25 bytes.
        const ulong expectedTime = 65536UL;
        const ulong expectedClock = 0xABCDEF00UL;
        const uint expectedResetCount = 2;
        const uint expectedRestartCount = 1;

        byte[] data =
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, //Time: 65536 ms (big-endian).
            0x00, 0x00, 0x00, 0x00, 0xAB, 0xCD, 0xEF, 0x00, //Clock (big-endian).
            0x00, 0x00, 0x00, 0x02, //ResetCount (big-endian).
            0x00, 0x00, 0x00, 0x01, //RestartCount (big-endian).
            0x00 //Safe flag (false).
        ];

        TpmsTimeInfo timeInfo = TpmsTimeInfo.ReadFrom(data);

        Assert.AreEqual(expectedTime, timeInfo.Time);
        Assert.AreEqual(expectedClock, timeInfo.ClockInfo.Clock);
        Assert.AreEqual(expectedResetCount, timeInfo.ClockInfo.ResetCount);
        Assert.AreEqual(expectedRestartCount, timeInfo.ClockInfo.RestartCount);
        Assert.IsFalse(timeInfo.ClockInfo.Safe);
    }

    [TestMethod]
    public void TpmsTaggedPropertyParsesCorrectly()
    {
        //TPMS_TAGGED_PROPERTY layout: property (4) + value (4) = 8 bytes.
        const uint expectedProperty = (uint)TpmPtConstants.TPM_PT_MODES;
        const uint expectedValue = (uint)TpmaModes.FIPS_140_2;

        byte[] data =
        [
            0x00, 0x00, 0x01, 0x2D, //Property: TPM2_PT_MODES (0x12D = PT_FIXED + 45).
            0x00, 0x00, 0x00, 0x01 //Value: FIPS mode flag set.
        ];

        TpmsTaggedProperty taggedProperty = TpmsTaggedProperty.ReadFrom(data);

        Assert.AreEqual(expectedProperty, taggedProperty.Property);
        Assert.AreEqual(expectedValue, taggedProperty.Value);
    }

    [TestMethod]
    public void TpmsClockInfoEqualityWorks()
    {
        var info1 = new TpmsClockInfo(1000, 5, 3, true);
        var info2 = new TpmsClockInfo(1000, 5, 3, true);
        var info3 = new TpmsClockInfo(2000, 5, 3, true);

        Assert.IsTrue(info1 == info2);
        Assert.IsFalse(info1 == info3);
        Assert.IsTrue(info1 != info3);
        Assert.AreEqual(info1.GetHashCode(), info2.GetHashCode());
    }

    [TestMethod]
    public void TpmsTimeInfoEqualityWorks()
    {
        var clock = new TpmsClockInfo(1000, 5, 3, true);
        var time1 = new TpmsTimeInfo(500, clock);
        var time2 = new TpmsTimeInfo(500, clock);
        var time3 = new TpmsTimeInfo(600, clock);

        Assert.IsTrue(time1 == time2);
        Assert.IsFalse(time1 == time3);
        Assert.AreEqual(time1.GetHashCode(), time2.GetHashCode());
    }

    [TestMethod]
    public void TpmsTaggedPropertyEqualityWorks()
    {
        var prop1 = new TpmsTaggedProperty(0x100, 42);
        var prop2 = new TpmsTaggedProperty(0x100, 42);
        var prop3 = new TpmsTaggedProperty(0x100, 43);

        Assert.IsTrue(prop1 == prop2);
        Assert.IsFalse(prop1 == prop3);
        Assert.AreEqual(prop1.GetHashCode(), prop2.GetHashCode());
    }
}