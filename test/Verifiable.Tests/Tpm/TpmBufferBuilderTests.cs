using System.Buffers;
using Verifiable.Tpm.Commands;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for <see cref="TpmBufferBuilder"/>.
/// </summary>
[TestClass]
public class TpmBufferBuilderTests
{
    [TestMethod]
    public void BuildCommandCreatesCorrectBuffer()
    {
        var input = new GetRandomInput(32);

        using IMemoryOwner<byte> owner = TpmBufferBuilder.BuildCommand(input, MemoryPool<byte>.Shared);

        Assert.AreEqual(TpmHeader.HeaderSize + input.SerializedSize, owner.Memory.Length);

        var (header, _) = TpmHeader.Parse(owner.Memory.Span);
        Assert.AreEqual(Tpm2CcConstants.TPM2_CC_GetRandom, header.CommandCode);
        Assert.AreEqual((uint)owner.Memory.Length, header.Size);
    }

    [TestMethod]
    public void BuildCommandRoundtripsWithParser()
    {
        var registry = new TpmTypeRegistry()
            .Register<GetRandomInput, GetRandomOutput>();

        var original = new GetRandomInput(64);

        using IMemoryOwner<byte> owner = TpmBufferBuilder.BuildCommand(original, MemoryPool<byte>.Shared);
        TpmParsedCommand parsed = TpmBufferParser.ParseCommand(owner.Memory.Span, registry);

        Assert.AreEqual(Tpm2CcConstants.TPM2_CC_GetRandom, parsed.Header.CommandCode);
        Assert.AreEqual(owner.Memory.Length, parsed.TotalBytesConsumed);

        GetRandomInput roundTripped = parsed.GetInput<GetRandomInput>();
        Assert.AreEqual(original, roundTripped);
    }

    [TestMethod]
    public void BuildResponseCreatesCorrectBuffer()
    {
        var output = new GetRandomOutput(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });

        using IMemoryOwner<byte> owner = TpmBufferBuilder.BuildResponse(output, MemoryPool<byte>.Shared);

        Assert.AreEqual(TpmHeader.HeaderSize + output.SerializedSize, owner.Memory.Length);

        var (header, _) = TpmHeader.Parse(owner.Memory.Span);
        Assert.AreEqual(TpmRc.Success, header.ResponseCode);
        Assert.AreEqual((uint)owner.Memory.Length, header.Size);
    }

    [TestMethod]
    public void BuildResponseRoundtripsWithParser()
    {
        var registry = new TpmTypeRegistry()
            .Register<GetRandomInput, GetRandomOutput>();

        byte[] randomBytes = [0xCA, 0xFE, 0xBA, 0xBE];
        var original = new GetRandomOutput(randomBytes);

        using IMemoryOwner<byte> owner = TpmBufferBuilder.BuildResponse(original, MemoryPool<byte>.Shared);
        TpmParsedResponse parsed = TpmBufferParser.ParseResponse(
            owner.Memory.Span,
            Tpm2CcConstants.TPM2_CC_GetRandom,
            registry);

        Assert.IsTrue(parsed.IsSuccess);
        Assert.AreEqual(owner.Memory.Length, parsed.TotalBytesConsumed);

        GetRandomOutput roundTripped = parsed.GetOutput<GetRandomOutput>();
        Assert.AreEqual(original, roundTripped);
    }

    [TestMethod]
    public void BuildErrorResponseCreatesHeaderOnly()
    {
        using IMemoryOwner<byte> owner = TpmBufferBuilder.BuildErrorResponse(TpmRc.Failure, MemoryPool<byte>.Shared);

        Assert.AreEqual(TpmHeader.HeaderSize, owner.Memory.Length);

        var (header, _) = TpmHeader.Parse(owner.Memory.Span);
        Assert.AreEqual(TpmRc.Failure, header.ResponseCode);
        Assert.IsFalse(header.IsSuccess);
    }

    [TestMethod]
    public void BuildErrorResponseRoundtripsWithParser()
    {
        var registry = new TpmTypeRegistry()
            .Register<GetRandomInput, GetRandomOutput>();

        using IMemoryOwner<byte> owner = TpmBufferBuilder.BuildErrorResponse(TpmRc.TPM_RC_LOCKOUT, MemoryPool<byte>.Shared);
        TpmParsedResponse parsed = TpmBufferParser.ParseResponse(
            owner.Memory.Span,
            Tpm2CcConstants.TPM2_CC_GetRandom,
            registry);

        Assert.IsFalse(parsed.IsSuccess);
        Assert.AreEqual(TpmRc.TPM_RC_LOCKOUT, parsed.ResponseCode);
        Assert.IsNull(parsed.Output);
    }

    [TestMethod]
    public void FullCommandResponseRoundtrip()
    {
        var registry = new TpmTypeRegistry()
            .Register<GetRandomInput, GetRandomOutput>();

        var inputOriginal = new GetRandomInput(16);
        byte[] randomBytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        var outputOriginal = new GetRandomOutput(randomBytes);

        //Build command.
        using IMemoryOwner<byte> commandOwner = TpmBufferBuilder.BuildCommand(inputOriginal, MemoryPool<byte>.Shared);
        
        //Parse command.
        TpmParsedCommand parsedCommand = TpmBufferParser.ParseCommand(commandOwner.Memory.Span, registry);
        GetRandomInput parsedInput = parsedCommand.GetInput<GetRandomInput>();
        
        //Build response.
        using IMemoryOwner<byte> responseOwner = TpmBufferBuilder.BuildResponse(outputOriginal, MemoryPool<byte>.Shared);
        
        //Parse response.
        TpmParsedResponse parsedResponse = TpmBufferParser.ParseResponse(
            responseOwner.Memory.Span,
            parsedCommand.Header.CommandCode,
            registry);
        GetRandomOutput parsedOutput = parsedResponse.GetOutput<GetRandomOutput>();

        Assert.AreEqual(inputOriginal, parsedInput);
        Assert.AreEqual(outputOriginal, parsedOutput);
    }
}
