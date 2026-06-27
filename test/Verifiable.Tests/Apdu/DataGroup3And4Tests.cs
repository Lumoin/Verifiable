using System;
using Verifiable.Apdu;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates the EF.DG3 (finger) and EF.DG4 (iris) writers and parsers: each wraps an ISO/IEC 19794-4 /
/// 19794-6 biometric record in the shared CBEFF templates and round-trips it through its parser — the
/// record bytes are recovered exactly and the biometric modality is reported. The format identifier
/// (<c>"FIR\0"</c> / <c>"IIR\0"</c>) is validated on both write and parse.
/// </summary>
[TestClass]
internal sealed class DataGroup3And4Tests
{
    //A minimal finger record: the ISO/IEC 19794-4 format identifier "FIR\0", a version, and filler payload.
    private static readonly byte[] FingerRecord =
        [0x46, 0x49, 0x52, 0x00, 0x30, 0x31, 0x30, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];

    //A minimal iris record: the ISO/IEC 19794-6 format identifier "IIR\0", a version, and filler payload.
    private static readonly byte[] IrisRecord =
        [0x49, 0x49, 0x52, 0x00, 0x30, 0x31, 0x30, 0x00, 0x11, 0x22, 0x33, 0x44];


    [TestMethod]
    public void RoundTripsAFingerRecord()
    {
        using ElementaryFile dataGroup3 = DataGroup3.Write(FingerRecord, BaseMemoryPool.Shared);
        using DataGroup3 parsed = DataGroup3.Parse(dataGroup3.AsReadOnlySpan(), BaseMemoryPool.Shared);

        Assert.AreEqual(BiometricModality.Finger, parsed.BiometricData.Modality, "DG3 reports the finger modality.");
        Assert.AreEqual(Convert.ToHexString(FingerRecord), Convert.ToHexString(parsed.BiometricData.AsReadOnlySpan()),
            "The finger record bytes must round-trip.");
    }


    [TestMethod]
    public void RoundTripsAnIrisRecord()
    {
        using ElementaryFile dataGroup4 = DataGroup4.Write(IrisRecord, BaseMemoryPool.Shared);
        using DataGroup4 parsed = DataGroup4.Parse(dataGroup4.AsReadOnlySpan(), BaseMemoryPool.Shared);

        Assert.AreEqual(BiometricModality.Iris, parsed.BiometricData.Modality, "DG4 reports the iris modality.");
        Assert.AreEqual(Convert.ToHexString(IrisRecord), Convert.ToHexString(parsed.BiometricData.AsReadOnlySpan()),
            "The iris record bytes must round-trip.");
    }


    [TestMethod]
    public void DataGroup3BeginsWithItsTemplateTag()
    {
        using ElementaryFile dataGroup3 = DataGroup3.Write(FingerRecord, BaseMemoryPool.Shared);

        Assert.AreEqual((byte)0x63, dataGroup3.AsReadOnlySpan()[0], "DG3 begins with the template tag 0x63.");
        Assert.AreEqual(DataGroup3.FileIdentifier, dataGroup3.FileIdentifier, "DG3 is written under file identifier 0x0103.");
    }


    [TestMethod]
    public void DataGroup4BeginsWithItsTemplateTag()
    {
        using ElementaryFile dataGroup4 = DataGroup4.Write(IrisRecord, BaseMemoryPool.Shared);

        Assert.AreEqual((byte)0x76, dataGroup4.AsReadOnlySpan()[0], "DG4 begins with the template tag 0x76.");
        Assert.AreEqual(DataGroup4.FileIdentifier, dataGroup4.FileIdentifier, "DG4 is written under file identifier 0x0104.");
    }


    [TestMethod]
    public void DataGroup3WriteRejectsARecordWithoutTheFingerFormatIdentifier()
    {
        byte[] notAFingerRecord = [0x49, 0x49, 0x52, 0x00, 0xAA];

        Assert.ThrowsExactly<InvalidOperationException>(
            () => { using ElementaryFile _ = DataGroup3.Write(notAFingerRecord, BaseMemoryPool.Shared); },
            "A DG3 record must begin with the ISO/IEC 19794-4 format identifier.");
    }


    [TestMethod]
    public void DataGroup3ParseRejectsADataGroup4File()
    {
        using ElementaryFile dataGroup4 = DataGroup4.Write(IrisRecord, BaseMemoryPool.Shared);

        Assert.ThrowsExactly<InvalidOperationException>(
            () => { using DataGroup3 _ = DataGroup3.Parse(dataGroup4.AsReadOnlySpan(), BaseMemoryPool.Shared); },
            "DG3 parse must reject a DG4-tagged file at the template tag.");
    }
}
