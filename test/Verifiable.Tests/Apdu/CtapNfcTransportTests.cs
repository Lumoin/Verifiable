using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.Ctap;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Tests for <see cref="CtapNfcTransport"/>, the client (platform) side of the CTAP2-over-NFC binding.
/// </summary>
[TestClass]
internal sealed class CtapNfcTransportTests
{
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A one-byte opaque CTAP2 request envelope, reused across tests that only need some non-empty request; its value is never interpreted by the transport, only carried in the NFCCTAP_MSG data field.</summary>
    private static byte[] OpaquePayload => [0x04];

    /// <summary>Builds a bare success response (data + SW=9000) rented from <paramref name="pool"/>.</summary>
    private static ApduResponse BuildSuccessResponse(ReadOnlySpan<byte> data, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(data.Length + 2);
        Span<byte> span = owner.Memory.Span;
        data.CopyTo(span);
        span[data.Length] = 0x90;
        span[data.Length + 1] = 0x00;

        return new ApduResponse(owner, data.Length + 2);
    }

    /// <summary>Builds a bare status-word-only response rented from <paramref name="pool"/>.</summary>
    private static ApduResponse BuildStatusOnlyResponse(byte sw1, byte sw2, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(2);
        owner.Memory.Span[0] = sw1;
        owner.Memory.Span[1] = sw2;

        return new ApduResponse(owner, 2);
    }

    [TestMethod]
    public async Task SendsExtendedNfcCtapMsgAndReturnsResponseEnvelope()
    {
        byte[] request = OpaquePayload;
        byte[] expectedResponseData = [0x00, 0xA3, 0x01, 0x02, 0x03];
        byte[]? capturedCommand = null;

        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu, MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            capturedCommand = commandApdu.ToArray();
            ApduResponse response = BuildSuccessResponse(expectedResponseData, pool);

            return ValueTask.FromResult(ApduResult<ApduResponse>.Success(response, response.StatusWord));
        }

        using var device = ApduDevice.Create(Handler);
        CtapNfcTransport transport = CtapNfcTransport.OverApdu(device);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using PooledMemory result = await transport.TransceiveAsync(request, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.AsReadOnlySpan().SequenceEqual(expectedResponseData));
        Assert.IsNotNull(capturedCommand);

        //CLA/INS/P1/P2 from the named CTAP-NFC wire values, followed by the generic ISO/IEC 7816-4
        //extended-length framing: header(4) + 0x00(1) + Lc(2) + data(1) + Le(2) = 10 bytes.
        byte[] expectedCommand =
        [
            WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapMsg.Code,
            WellKnownCtapCommandParameters.SupportsGetResponseP1Bit, 0x00,
            0x00, 0x00, 0x01, .. request, 0x00, 0x00
        ];
        Assert.AreSequenceEqual(expectedCommand, capturedCommand);
    }

    [TestMethod]
    public async Task PollsNfcCtapGetResponseUntilSuccess()
    {
        byte[] expectedResponseData = [0x00, 0x01, 0x02];
        int callCount = 0;
        byte[]? pollCommand = null;

        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu, MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            callCount++;
            if(callCount == 1)
            {
                ApduResponse deferred = BuildStatusOnlyResponse(0x91, 0x00, pool);

                return ValueTask.FromResult(ApduResult<ApduResponse>.Success(deferred, deferred.StatusWord));
            }

            pollCommand = commandApdu.ToArray();
            ApduResponse final = BuildSuccessResponse(expectedResponseData, pool);

            return ValueTask.FromResult(ApduResult<ApduResponse>.Success(final, final.StatusWord));
        }

        using var device = ApduDevice.Create(Handler);
        CtapNfcTransport transport = CtapNfcTransport.OverApdu(device);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using PooledMemory result = await transport.TransceiveAsync(OpaquePayload, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.AsReadOnlySpan().SequenceEqual(expectedResponseData));
        Assert.AreEqual(2, callCount);

        //NFCCTAP_GETRESPONSE normal poll: named CLA/INS, P1=0x00 (RFU, normal poll)/P2=0x00, Le=0x00 (short-form).
        byte[] expectedPoll =
        [
            WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapGetResponse.Code,
            0x00, 0x00, 0x00
        ];
        Assert.AreSequenceEqual(expectedPoll, pollCommand);
    }

    [TestMethod]
    public async Task CancellationSendsCancelVariantThenThrows()
    {
        var commands = new List<byte[]>();

        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu, MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            commands.Add(commandApdu.ToArray());
            ApduResponse deferred = BuildStatusOnlyResponse(0x91, 0x00, pool);

            return ValueTask.FromResult(ApduResult<ApduResponse>.Success(deferred, deferred.StatusWord));
        }

        using var device = ApduDevice.Create(Handler);
        CtapNfcTransport transport = CtapNfcTransport.OverApdu(device);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync().ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(
            () => transport.TransceiveAsync(OpaquePayload, pool, cts.Token).AsTask()).ConfigureAwait(false);

        //Initial NFCCTAP_MSG, then the cancel variant of NFCCTAP_GETRESPONSE (named CLA/INS/cancel P1).
        Assert.HasCount(2, commands);
        byte[] expectedCancel =
        [
            WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapGetResponse.Code,
            WellKnownCtapCommandParameters.CancelP1, 0x00, 0x00
        ];
        Assert.AreSequenceEqual(expectedCancel, commands[1]);
    }

    [TestMethod]
    public async Task CardErrorThrowsWithStatusWord()
    {
        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu, MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            ApduResponse response = BuildStatusOnlyResponse(0x6A, 0x80, pool);

            return ValueTask.FromResult(ApduResult<ApduResponse>.Success(response, response.StatusWord));
        }

        using var device = ApduDevice.Create(Handler);
        CtapNfcTransport transport = CtapNfcTransport.OverApdu(device);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapNfcTransportException exception = await Assert.ThrowsExactlyAsync<CtapNfcTransportException>(
            () => transport.TransceiveAsync(OpaquePayload, pool, TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.IsNotNull(exception.StatusWord);
        Assert.IsTrue(exception.StatusWord.Value.IsWrongData);
    }

    [TestMethod]
    public async Task TransportErrorThrowsWithErrorCode()
    {
        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu, MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            return ValueTask.FromResult(ApduResult<ApduResponse>.TransportError(0x1234));
        }

        using var device = ApduDevice.Create(Handler);
        CtapNfcTransport transport = CtapNfcTransport.OverApdu(device);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        CtapNfcTransportException exception = await Assert.ThrowsExactlyAsync<CtapNfcTransportException>(
            () => transport.TransceiveAsync(OpaquePayload, pool, TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.AreEqual((uint)0x1234, exception.TransportErrorCode);
    }
}
