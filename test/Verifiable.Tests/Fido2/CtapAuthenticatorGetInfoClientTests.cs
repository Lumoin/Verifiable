using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapAuthenticatorGetInfoClient"/> against a scripted
/// <see cref="Ctap2TransceiveDelegate"/> — no APDU transport or simulator involved, isolating the
/// RP-side request-build/response-decode logic.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorGetInfoClientTests
{
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The request envelope is exactly the one-byte authenticatorGetInfo command code, and a success envelope decodes correctly.</summary>
    [TestMethod]
    public async Task SendsSingleByteRequestAndDecodesSuccessResponse()
    {
        byte[]? capturedRequest = null;
        Guid aaguid = Guid.NewGuid();
        var scriptedResponse = new CtapGetInfoResponse(Versions: [WellKnownCtapVersions.Fido23], Aaguid: aaguid);

        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            capturedRequest = request.ToArray();
            TaggedMemory<byte> payload = CtapGetInfoResponseCborWriter.Write(scriptedResponse);
            byte[] envelope = new byte[payload.Length + 1];
            envelope[0] = WellKnownCtapStatusCodes.Ok;
            payload.Span.CopyTo(envelope.AsSpan(1));

            return ValueTask.FromResult(PooledMemory.FromBytes(envelope, pool, Fido2BufferTags.CtapResponseEnvelope));
        }

        CtapGetInfoResponse decoded = await CtapAuthenticatorGetInfoClient.GetInfoAsync(
            Transceive, CtapGetInfoResponseCborReader.Read, BaseMemoryPool.Shared, TestContext.CancellationToken);

        CollectionAssert.AreEqual(new byte[] { WellKnownCtapCommands.GetInfo }, capturedRequest);
        Assert.AreEqual(aaguid, decoded.Aaguid);
        Assert.AreEqual(WellKnownCtapVersions.Fido23, decoded.Versions[0]);
    }


    /// <summary>A non-success status byte raises <see cref="CtapCommandException"/> carrying that status code.</summary>
    [TestMethod]
    public async Task ThrowsCtapCommandExceptionOnNonSuccessStatus()
    {
        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes([WellKnownCtapStatusCodes.InvalidCommand], pool, Fido2BufferTags.CtapResponseEnvelope));

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => CtapAuthenticatorGetInfoClient.GetInfoAsync(
                Transceive, CtapGetInfoResponseCborReader.Read, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidCommand, exception.StatusCode);
    }


    /// <summary>An empty response envelope is rejected before any decode is attempted.</summary>
    [TestMethod]
    public async Task ThrowsFido2FormatExceptionOnEmptyResponse()
    {
        ValueTask<PooledMemory> Transceive(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes(ReadOnlySpan<byte>.Empty, pool, Fido2BufferTags.CtapResponseEnvelope));

        await Assert.ThrowsExactlyAsync<Fido2FormatException>(
            () => CtapAuthenticatorGetInfoClient.GetInfoAsync(
                Transceive, CtapGetInfoResponseCborReader.Read, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask());
    }
}
