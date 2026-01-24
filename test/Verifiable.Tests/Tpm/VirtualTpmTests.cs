using System.Buffers;
using Verifiable.Tpm;
using Verifiable.Tpm.Commands;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for <see cref="VirtualTpm"/>.
/// </summary>
[TestClass]
public class VirtualTpmTests
{
    [TestMethod]
    public void RecordTypedInputOutputStoresResponse()
    {
        var virtualTpm = new VirtualTpm();
        var input = new GetRandomInput(16);
        var output = new GetRandomOutput(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });

        virtualTpm.Record(input, output);

        Assert.AreEqual(1, virtualTpm.ResponseCount);
    }

    [TestMethod]
    public void HasResponseReturnsTrueForRecordedTypedInput()
    {
        var virtualTpm = new VirtualTpm();
        var input = new GetRandomInput(16);
        var output = new GetRandomOutput(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });

        virtualTpm.Record(input, output);

        Assert.IsTrue(virtualTpm.HasResponse(input));
    }

    [TestMethod]
    public void HasResponseReturnsFalseForUnrecordedTypedInput()
    {
        var virtualTpm = new VirtualTpm();
        var input = new GetRandomInput(16);

        Assert.IsFalse(virtualTpm.HasResponse(input));
    }

    [TestMethod]
    public void SubmitReturnsRecordedTypedResponse()
    {
        var virtualTpm = new VirtualTpm();
        byte[] randomBytes = [0xDE, 0xAD, 0xBE, 0xEF];
        var input = new GetRandomInput(4);
        var output = new GetRandomOutput(randomBytes);

        virtualTpm.Record(input, output);

        //Build command bytes.
        using IMemoryOwner<byte> commandOwner = TpmBufferBuilder.BuildCommand(input, MemoryPool<byte>.Shared);
        Span<byte> response = stackalloc byte[256];

        int len = virtualTpm.Submit(commandOwner.Memory.Span, response);

        //Parse the response.
        TpmParsedResponse parsed = TpmBufferParser.ParseResponse(
            response[..len],
            Tpm2CcConstants.TPM2_CC_GetRandom,
            TpmTypeRegistry.Default);

        Assert.IsTrue(parsed.IsSuccess);
        GetRandomOutput parsedOutput = parsed.GetOutput<GetRandomOutput>();
        Assert.AreEqual(output, parsedOutput);
    }

    [TestMethod]
    public void RecordErrorStoresErrorResponse()
    {
        var virtualTpm = new VirtualTpm();
        var input = new GetRandomInput(16);

        virtualTpm.RecordError(input, TpmRc.Failure);

        Assert.AreEqual(1, virtualTpm.ResponseCount);
        Assert.IsTrue(virtualTpm.HasResponse(input));
    }

    [TestMethod]
    public void SubmitReturnsRecordedErrorResponse()
    {
        var virtualTpm = new VirtualTpm();
        var input = new GetRandomInput(16);

        virtualTpm.RecordError(input, TpmRc.TPM_RC_LOCKOUT);

        //Build command bytes.
        using IMemoryOwner<byte> commandOwner = TpmBufferBuilder.BuildCommand(input, MemoryPool<byte>.Shared);
        Span<byte> response = stackalloc byte[256];

        int len = virtualTpm.Submit(commandOwner.Memory.Span, response);

        //Parse header only.
        var (header, _) = TpmHeader.Parse(response[..len]);

        Assert.IsFalse(header.IsSuccess);
        Assert.AreEqual(TpmRc.TPM_RC_LOCKOUT, header.ResponseCode);
    }

    [TestMethod]
    public void SubmitReturnsFailureForUnknownCommand()
    {
        var virtualTpm = new VirtualTpm();
        byte[] unknownCommand = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF];
        Span<byte> response = stackalloc byte[256];

        int len = virtualTpm.Submit(unknownCommand, response);

        var (header, _) = TpmHeader.Parse(response[..len]);
        Assert.IsFalse(header.IsSuccess);
        Assert.AreEqual(TpmRc.Failure, header.ResponseCode);
    }

    [TestMethod]
    public void ClearRemovesAllResponses()
    {
        var virtualTpm = new VirtualTpm();
        virtualTpm.Record(new GetRandomInput(16), new GetRandomOutput(new byte[] { 0x01 }));
        virtualTpm.Record(new GetRandomInput(32), new GetRandomOutput(new byte[] { 0x02 }));

        Assert.AreEqual(2, virtualTpm.ResponseCount);

        virtualTpm.Clear();

        Assert.AreEqual(0, virtualTpm.ResponseCount);
    }

    [TestMethod]
    public void RecordRawBytesStoresResponse()
    {
        var virtualTpm = new VirtualTpm();
        byte[] command = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x7B, 0x00, 0x10];
        byte[] response = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xAB, 0xCD];

        virtualTpm.Record(command, response);

        Assert.AreEqual(1, virtualTpm.ResponseCount);
        Assert.IsTrue(virtualTpm.HasResponse(command));
    }

    [TestMethod]
    public void LoadFromExchangesStoresMultipleResponses()
    {
        var virtualTpm = new VirtualTpm();
        TpmExchange[] exchanges =
        [
            new TpmExchange(0, 100, new byte[] { 0x01 }, new byte[] { 0x10 }),
            new TpmExchange(100, 200, new byte[] { 0x02 }, new byte[] { 0x20 })
        ];

        virtualTpm.Load(exchanges);

        Assert.AreEqual(2, virtualTpm.ResponseCount);
    }
}