using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for <see cref="TpmHeader"/>.
/// </summary>
[TestClass]
internal class TpmHeaderTests
{
    [TestMethod]
    public void HeaderSizeIsTenBytes()
    {
#pragma warning disable MSTEST0032 // Assertion condition is always true
        Assert.AreEqual(TpmHeader.HeaderSize, 10);
#pragma warning restore MSTEST0032 // Assertion condition is always true
    }

    [TestMethod]
    public void ParseReadsFieldsCorrectly()
    {
        //TPM_ST_NO_SESSIONS (0x8001), size 12, TPM_CC_GetRandom (0x0000017B).
        byte[] bytes = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x7B];
        var reader = new TpmReader(bytes);

        TpmHeader header = TpmHeader.Parse(ref reader);

        Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, header.Tag);
        Assert.AreEqual(12u, header.Size);
        Assert.AreEqual((uint)TpmCcConstants.TPM_CC_GetRandom, header.Code);
    }

    [TestMethod]
    public void ParseConsumesExactlyTenBytes()
    {
        byte[] bytes = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x7B, 0xFF, 0xFF];
        var reader = new TpmReader(bytes);

        _ = TpmHeader.Parse(ref reader);

        Assert.AreEqual(TpmHeader.HeaderSize, reader.Consumed);
        Assert.AreEqual(2, reader.Remaining);
    }

    [TestMethod]
    public void WriteToProducesCorrectBytes()
    {
        var header = new TpmHeader(
            (ushort)TpmStConstants.TPM_ST_NO_SESSIONS,
            12,
            (uint)TpmCcConstants.TPM_CC_GetRandom);
        Span<byte> buffer = stackalloc byte[TpmHeader.HeaderSize];
        var writer = new TpmWriter(buffer);

        header.WriteTo(ref writer);

        //Tag: 0x8001 (TPM_ST_NO_SESSIONS).
        Assert.AreEqual((byte)0x80, buffer[0]);
        Assert.AreEqual((byte)0x01, buffer[1]);

        //Size: 12 = 0x0000000C.
        Assert.AreEqual((byte)0x00, buffer[2]);
        Assert.AreEqual((byte)0x00, buffer[3]);
        Assert.AreEqual((byte)0x00, buffer[4]);
        Assert.AreEqual((byte)0x0C, buffer[5]);

        //Code: 0x0000017B (TPM_CC_GetRandom).
        Assert.AreEqual((byte)0x00, buffer[6]);
        Assert.AreEqual((byte)0x00, buffer[7]);
        Assert.AreEqual((byte)0x01, buffer[8]);
        Assert.AreEqual((byte)0x7B, buffer[9]);
    }

    [TestMethod]
    public void RoundtripPreservesValues()
    {
        var original = new TpmHeader(
            (ushort)TpmStConstants.TPM_ST_SESSIONS,
            100,
            (uint)TpmCcConstants.TPM_CC_CreatePrimary);
        Span<byte> buffer = stackalloc byte[TpmHeader.HeaderSize];
        var writer = new TpmWriter(buffer);

        original.WriteTo(ref writer);

        var reader = new TpmReader(buffer);
        TpmHeader parsed = TpmHeader.Parse(ref reader);

        Assert.AreEqual(original, parsed);
    }

    [TestMethod]
    public void RecordEqualityWorks()
    {
        var header1 = new TpmHeader(0x8001, 12, 0x0000017B);
        var header2 = new TpmHeader(0x8001, 12, 0x0000017B);
        var header3 = new TpmHeader(0x8001, 12, 0x0000017A);

        Assert.AreEqual(header1, header2);
        Assert.AreNotEqual(header1, header3);
    }
}