using Verifiable.Tpm.Commands;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for <see cref="TpmBufferParser"/>.
/// </summary>
[TestClass]
public class TpmBufferParserTests
{
    [TestMethod]
    public void ParseCommandParsesHeaderAndInput()
    {
        var registry = new TpmTypeRegistry()
            .Register<GetRandomInput, GetRandomOutput>();

        //Build a GetRandom command: header + 2 bytes (bytesRequested = 32).
        byte[] commandBuffer =
        [
            0x80, 0x01,             //Tag: TPM_ST_NO_SESSIONS.
            0x00, 0x00, 0x00, 0x0C, //Size: 12 bytes.
            0x00, 0x00, 0x01, 0x7B, //Code: TPM2_CC_GetRandom.
            0x00, 0x20              //BytesRequested: 32.
        ];

        TpmParsedCommand result = TpmBufferParser.ParseCommand(commandBuffer, registry);

        Assert.AreEqual(Tpm2CcConstants.TPM2_CC_GetRandom, result.Header.CommandCode);
        Assert.AreEqual(12u, result.Header.Size);
        Assert.AreEqual(12, result.TotalBytesConsumed);
        Assert.IsInstanceOfType<GetRandomInput>(result.Input);

        GetRandomInput input = result.GetInput<GetRandomInput>();
        Assert.AreEqual((ushort)32, input.BytesRequested);
    }

    [TestMethod]
    public void ParseCommandReturnsUnknownInputForUnregisteredCommand()
    {
        var registry = new TpmTypeRegistry();

        byte[] commandBuffer =
        [
            0x80, 0x01,
            0x00, 0x00, 0x00, 0x0C,
            0x00, 0x00, 0x01, 0x7B,
            0x00, 0x20
        ];

        TpmParsedCommand result = TpmBufferParser.ParseCommand(commandBuffer, registry);

        Assert.AreEqual(Tpm2CcConstants.TPM2_CC_GetRandom, result.Header.CommandCode);
        Assert.IsInstanceOfType<UnknownInput>(result.Input);

        var unknown = (UnknownInput)result.Input!;
        Assert.AreEqual(Tpm2CcConstants.TPM2_CC_GetRandom, unknown.CommandCode);
        Assert.AreEqual(2, unknown.RawBytes.Length);
    }

    [TestMethod]
    public void ParseResponseParsesHeaderAndOutput()
    {
        var registry = new TpmTypeRegistry()
            .Register<GetRandomInput, GetRandomOutput>();

        //Build a success response with 4 random bytes.
        byte[] responseBuffer =
        [
            0x80, 0x01,             //Tag: TPM_ST_NO_SESSIONS.
            0x00, 0x00, 0x00, 0x10, //Size: 16 bytes.
            0x00, 0x00, 0x00, 0x00, //Code: TPM_RC_SUCCESS.
            0x00, 0x04,             //Digest length: 4.
            0xDE, 0xAD, 0xBE, 0xEF  //Random bytes.
        ];

        TpmParsedResponse result = TpmBufferParser.ParseResponse(
            responseBuffer,
            Tpm2CcConstants.TPM2_CC_GetRandom,
            registry);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual(TpmRc.Success, result.ResponseCode);
        Assert.AreEqual(16, result.TotalBytesConsumed);
        Assert.IsInstanceOfType<GetRandomOutput>(result.Output);

        GetRandomOutput output = result.GetOutput<GetRandomOutput>();
        Assert.AreEqual(4, output.Bytes.Length);
        Assert.AreEqual((byte)0xDE, output.Bytes.Span[0]);
    }

    [TestMethod]
    public void ParseResponseReturnsNullOutputForErrorResponse()
    {
        var registry = new TpmTypeRegistry()
            .Register<GetRandomInput, GetRandomOutput>();

        //Build an error response (TPM_RC_FAILURE).
        byte[] responseBuffer =
        [
            0x80, 0x01,             //Tag: TPM_ST_NO_SESSIONS.
            0x00, 0x00, 0x00, 0x0A, //Size: 10 bytes (header only).
            0x00, 0x00, 0x01, 0x01  //Code: TPM_RC_FAILURE.
        ];

        TpmParsedResponse result = TpmBufferParser.ParseResponse(
            responseBuffer,
            Tpm2CcConstants.TPM2_CC_GetRandom,
            registry);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(TpmRc.Failure, result.ResponseCode);
        Assert.IsNull(result.Output);
        Assert.AreEqual(TpmHeader.HeaderSize, result.TotalBytesConsumed);
    }

    [TestMethod]
    public void ParseResponseReturnsUnknownOutputForUnregisteredCommand()
    {
        var registry = new TpmTypeRegistry();

        byte[] responseBuffer =
        [
            0x80, 0x01,
            0x00, 0x00, 0x00, 0x10,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x04,
            0xDE, 0xAD, 0xBE, 0xEF
        ];

        TpmParsedResponse result = TpmBufferParser.ParseResponse(
            responseBuffer,
            Tpm2CcConstants.TPM2_CC_GetRandom,
            registry);

        Assert.IsTrue(result.IsSuccess);
        Assert.IsInstanceOfType<UnknownOutput>(result.Output);

        var unknown = (UnknownOutput)result.Output!;
        Assert.AreEqual(6, unknown.RawBytes.Length);
    }

    [TestMethod]
    public void TryParseCommandParametersSucceedsForRegisteredCommand()
    {
        var registry = new TpmTypeRegistry()
            .Register<GetRandomInput, GetRandomOutput>();

        byte[] parameters = [0x00, 0x20];

        bool success = TpmBufferParser.TryParseCommandParameters(
            parameters,
            Tpm2CcConstants.TPM2_CC_GetRandom,
            registry,
            out object? input,
            out int bytesConsumed);

        Assert.IsTrue(success);
        Assert.IsInstanceOfType<GetRandomInput>(input);
        Assert.AreEqual(2, bytesConsumed);
    }

    [TestMethod]
    public void TryParseResponseBodySucceedsForRegisteredCommand()
    {
        var registry = new TpmTypeRegistry()
            .Register<GetRandomInput, GetRandomOutput>();

        byte[] body = [0x00, 0x02, 0xAA, 0xBB];

        bool success = TpmBufferParser.TryParseResponseBody(
            body,
            Tpm2CcConstants.TPM2_CC_GetRandom,
            registry,
            out object? output,
            out int bytesConsumed);

        Assert.IsTrue(success);
        Assert.IsInstanceOfType<GetRandomOutput>(output);
        Assert.AreEqual(4, bytesConsumed);
    }
}
