using Verifiable.Tpm.Commands;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for <see cref="GetRandomInput"/> and <see cref="GetRandomOutput"/>.
/// </summary>
[TestClass]
public class GetRandomCommandTests
{
    [TestMethod]
    public void GetRandomInputHasCorrectCommandCode()
    {
        Assert.AreEqual(Tpm2CcConstants.TPM2_CC_GetRandom, GetRandomInput.CommandCode);
    }

    [TestMethod]
    public void GetRandomInputSerializedSizeIsCorrect()
    {
        var input = new GetRandomInput(32);

        Assert.AreEqual(sizeof(ushort), input.SerializedSize);
    }

    [TestMethod]
    public void GetRandomInputRoundtrips()
    {
        var original = new GetRandomInput(32);
        Span<byte> buffer = stackalloc byte[original.SerializedSize];

        original.WriteTo(buffer);
        var (parsed, consumed) = GetRandomInput.Parse(buffer);

        Assert.AreEqual(original.SerializedSize, consumed);
        Assert.AreEqual(original, parsed);
    }

    [TestMethod]
    public void GetRandomInputRoundtripsWithZeroBytes()
    {
        var original = new GetRandomInput(0);
        Span<byte> buffer = stackalloc byte[original.SerializedSize];

        original.WriteTo(buffer);
        var (parsed, consumed) = GetRandomInput.Parse(buffer);

        Assert.AreEqual(original, parsed);
    }

    [TestMethod]
    public void GetRandomInputRoundtripsWithMaxBytes()
    {
        var original = new GetRandomInput(ushort.MaxValue);
        Span<byte> buffer = stackalloc byte[original.SerializedSize];

        original.WriteTo(buffer);
        var (parsed, consumed) = GetRandomInput.Parse(buffer);

        Assert.AreEqual(original, parsed);
    }

    [TestMethod]
    public void GetRandomInputEqualityWorks()
    {
        var input1 = new GetRandomInput(32);
        var input2 = new GetRandomInput(32);
        var input3 = new GetRandomInput(64);

        Assert.AreEqual(input1, input2);
        Assert.AreNotEqual(input1, input3);
        Assert.IsTrue(input1 == input2);
        Assert.IsTrue(input1 != input3);
    }

    [TestMethod]
    public void GetRandomOutputSerializedSizeIsCorrect()
    {
        byte[] bytes = [0xDE, 0xAD, 0xBE, 0xEF];
        var output = new GetRandomOutput(bytes);

        Assert.AreEqual(sizeof(ushort) + bytes.Length, output.SerializedSize);
    }

    [TestMethod]
    public void GetRandomOutputRoundtrips()
    {
        byte[] originalBytes = [0xDE, 0xAD, 0xBE, 0xEF];
        var original = new GetRandomOutput(originalBytes);
        Span<byte> buffer = stackalloc byte[original.SerializedSize];

        original.WriteTo(buffer);
        var (parsed, consumed) = GetRandomOutput.Parse(buffer);

        Assert.AreEqual(original.SerializedSize, consumed);
        Assert.AreEqual(original, parsed);
    }

    [TestMethod]
    public void GetRandomOutputRoundtripsWithEmptyBytes()
    {
        var original = new GetRandomOutput(Array.Empty<byte>());
        Span<byte> buffer = stackalloc byte[original.SerializedSize];

        original.WriteTo(buffer);
        var (parsed, consumed) = GetRandomOutput.Parse(buffer);

        Assert.AreEqual(original, parsed);
        Assert.AreEqual(0, parsed.Bytes.Length);
    }

    [TestMethod]
    public void GetRandomOutputEqualityWorks()
    {
        var output1 = new GetRandomOutput(new byte[] { 0x01, 0x02, 0x03 });
        var output2 = new GetRandomOutput(new byte[] { 0x01, 0x02, 0x03 });
        var output3 = new GetRandomOutput(new byte[] { 0x01, 0x02, 0x04 });

        Assert.AreEqual(output1, output2);
        Assert.AreNotEqual(output1, output3);
    }

    [TestMethod]
    public void GetRandomOutputParsesFromKnownBytes()
    {
        //TPM2B_DIGEST: length 4, data DEADBEEF.
        byte[] wireFormat = [0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];

        var (output, consumed) = GetRandomOutput.Parse(wireFormat);

        Assert.AreEqual(6, consumed);
        Assert.AreEqual(4, output.Bytes.Length);
        Assert.AreEqual((byte)0xDE, output.Bytes.Span[0]);
        Assert.AreEqual((byte)0xAD, output.Bytes.Span[1]);
        Assert.AreEqual((byte)0xBE, output.Bytes.Span[2]);
        Assert.AreEqual((byte)0xEF, output.Bytes.Span[3]);
    }

    [TestMethod]
    public void GetRandomInputWritesToKnownBytes()
    {
        var input = new GetRandomInput(0x0020);
        Span<byte> buffer = stackalloc byte[input.SerializedSize];

        input.WriteTo(buffer);

        Assert.AreEqual((byte)0x00, buffer[0]);
        Assert.AreEqual((byte)0x20, buffer[1]);
    }
}
