using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapAuthenticatorClientPinClient"/> against a scripted
/// <see cref="Ctap2TransceiveDelegate"/> — no APDU transport or simulator involved, isolating the
/// RP-side request-build/response-decode logic, mirroring <c>CtapAuthenticatorGetInfoClientTests</c>.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorClientPinClientTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// The request envelope is the <see cref="WellKnownCtapCommands.ClientPin"/> command byte followed
    /// by the CBOR-encoded parameter map, and a success envelope decodes correctly.
    /// </summary>
    [TestMethod]
    public async Task SendsClientPinCommandByteAndDecodesSuccessResponse()
    {
        byte[]? capturedRequest = null;
        var scriptedResponse = new CtapClientPinResponse(PinRetries: 8);

        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            capturedRequest = request.ToArray();
            TaggedMemory<byte> payload = CtapClientPinResponseCborWriter.Write(scriptedResponse);
            byte[] envelope = new byte[payload.Length + 1];
            envelope[0] = WellKnownCtapStatusCodes.Ok;
            payload.Span.CopyTo(envelope.AsSpan(1));

            return ValueTask.FromResult(PooledMemory.FromBytes(envelope, pool, Fido2BufferTags.CtapResponseEnvelope));
        }

        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetPinRetries);
        CtapClientPinResponse decoded = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            Transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsNotNull(capturedRequest);
        Assert.AreEqual(WellKnownCtapCommands.ClientPin, capturedRequest![0]);
        Assert.AreEqual(8, decoded.PinRetries);
    }


    /// <summary>A non-success status byte raises <see cref="CtapCommandException"/> carrying that status code.</summary>
    [TestMethod]
    public async Task ThrowsCtapCommandExceptionOnNonSuccessStatus()
    {
        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes([WellKnownCtapStatusCodes.InvalidParameter], pool, Fido2BufferTags.CtapResponseEnvelope));

        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.SetPin);
        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => CtapAuthenticatorClientPinClient.ClientPinAsync(
                Transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, exception.StatusCode);
    }


    /// <summary>An empty response envelope is rejected before any decode is attempted.</summary>
    [TestMethod]
    public async Task ThrowsFido2FormatExceptionOnEmptyResponse()
    {
        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes(ReadOnlySpan<byte>.Empty, pool, Fido2BufferTags.CtapResponseEnvelope));

        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetUvRetries);
        await Assert.ThrowsExactlyAsync<Fido2FormatException>(
            () => CtapAuthenticatorClientPinClient.ClientPinAsync(
                Transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask());
    }
}
