using Verifiable.Tpm.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for <see cref="TpmHeader"/>.
/// </summary>
[TestClass]
public class TpmHeaderTests
{
    [TestMethod]
    public void HeaderSizeIsTenBytes()
    {
        int headerSize = TpmHeader.HeaderSize;
        Assert.AreEqual(10, headerSize);
    }

    [TestMethod]
    public void SerializedSizeEqualsHeaderSize()
    {
        var header = new TpmHeader(0x8001, 10, 0x0000017B);

        Assert.AreEqual(TpmHeader.HeaderSize, header.SerializedSize);
    }

    [TestMethod]
    public void CreateCommandSetsNoSessionsTag()
    {
        TpmHeader header = TpmHeader.CreateCommand(Tpm2CcConstants.TPM2_CC_GetRandom, 12);

        Assert.AreEqual((ushort)Tpm2StConstants.TPM_ST_NO_SESSIONS, header.Tag);
    }

    [TestMethod]
    public void CreateCommandWithSessionsSetsSessionsTag()
    {
        TpmHeader header = TpmHeader.CreateCommandWithSessions(Tpm2CcConstants.TPM2_CC_GetRandom, 50);

        Assert.AreEqual((ushort)Tpm2StConstants.TPM_ST_SESSIONS, header.Tag);
    }

    [TestMethod]
    public void CreateCommandSetsCorrectCode()
    {
        TpmHeader header = TpmHeader.CreateCommand(Tpm2CcConstants.TPM2_CC_GetRandom, 12);

        Assert.AreEqual(Tpm2CcConstants.TPM2_CC_GetRandom, header.CommandCode);
    }

    [TestMethod]
    public void CreateResponseSetsCorrectCode()
    {
        TpmHeader header = TpmHeader.CreateResponse(TpmRc.Success, 10);

        Assert.AreEqual(TpmRc.Success, header.ResponseCode);
        Assert.IsTrue(header.IsSuccess);
    }

    [TestMethod]
    public void CreateResponseWithErrorIsNotSuccess()
    {
        TpmHeader header = TpmHeader.CreateResponse(TpmRc.Failure, 10);

        Assert.AreEqual(TpmRc.Failure, header.ResponseCode);
        Assert.IsFalse(header.IsSuccess);
    }

    [TestMethod]
    public void HasSessionsReturnsTrueForSessionsTag()
    {
        TpmHeader header = TpmHeader.CreateCommandWithSessions(Tpm2CcConstants.TPM2_CC_GetRandom, 50);

        Assert.IsTrue(header.HasSessions);
    }

    [TestMethod]
    public void HasSessionsReturnsFalseForNoSessionsTag()
    {
        TpmHeader header = TpmHeader.CreateCommand(Tpm2CcConstants.TPM2_CC_GetRandom, 12);

        Assert.IsFalse(header.HasSessions);
    }

    [TestMethod]
    public void HeaderRoundtrips()
    {
        var original = TpmHeader.CreateCommand(Tpm2CcConstants.TPM2_CC_GetRandom, 12);
        Span<byte> buffer = stackalloc byte[TpmHeader.HeaderSize];

        original.WriteTo(buffer);
        var (parsed, consumed) = TpmHeader.Parse(buffer);

        Assert.AreEqual(TpmHeader.HeaderSize, consumed);
        Assert.AreEqual(original, parsed);
    }

    [TestMethod]
    public void HeaderWritesToKnownBytes()
    {
        TpmHeader header = TpmHeader.CreateCommand(Tpm2CcConstants.TPM2_CC_GetRandom, 12);
        Span<byte> buffer = stackalloc byte[TpmHeader.HeaderSize];

        header.WriteTo(buffer);

        //Tag: 0x8001 (TPM_ST_NO_SESSIONS).
        Assert.AreEqual((byte)0x80, buffer[0]);
        Assert.AreEqual((byte)0x01, buffer[1]);

        //Size: 12 = 0x0000000C.
        Assert.AreEqual((byte)0x00, buffer[2]);
        Assert.AreEqual((byte)0x00, buffer[3]);
        Assert.AreEqual((byte)0x00, buffer[4]);
        Assert.AreEqual((byte)0x0C, buffer[5]);

        //Code: 0x0000017B (TPM2_CC_GetRandom).
        Assert.AreEqual((byte)0x00, buffer[6]);
        Assert.AreEqual((byte)0x00, buffer[7]);
        Assert.AreEqual((byte)0x01, buffer[8]);
        Assert.AreEqual((byte)0x7B, buffer[9]);
    }

    [TestMethod]
    public void HeaderParsesFromKnownBytes()
    {
        //TPM_ST_NO_SESSIONS (0x8001), size 12, TPM2_CC_GetRandom (0x0000017B).
        byte[] bytes = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x7B];

        var (header, consumed) = TpmHeader.Parse(bytes);

        Assert.AreEqual(10, consumed);
        Assert.AreEqual((ushort)Tpm2StConstants.TPM_ST_NO_SESSIONS, header.Tag);
        Assert.AreEqual(12u, header.Size);
        Assert.AreEqual(Tpm2CcConstants.TPM2_CC_GetRandom, header.CommandCode);
    }

    [TestMethod]
    public void HeaderEqualityWorks()
    {
        var header1 = TpmHeader.CreateCommand(Tpm2CcConstants.TPM2_CC_GetRandom, 12);
        var header2 = TpmHeader.CreateCommand(Tpm2CcConstants.TPM2_CC_GetRandom, 12);
        var header3 = TpmHeader.CreateCommand(Tpm2CcConstants.TPM2_CC_Hash, 12);

        Assert.AreEqual(header1, header2);
        Assert.AreNotEqual(header1, header3);
        Assert.IsTrue(header1 == header2);
        Assert.IsTrue(header1 != header3);
    }
}