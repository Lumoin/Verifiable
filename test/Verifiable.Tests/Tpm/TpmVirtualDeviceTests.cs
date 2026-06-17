using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Coverage for <see cref="TpmVirtualDevice"/>: raw record/replay behaviour, the
/// no-match failure response, loading from a recording, and an end-to-end replay through
/// <see cref="TpmCommandExecutor"/> via <see cref="TpmDevice.Create(TpmSubmitHandler, Action?)"/>.
/// </summary>
[TestClass]
internal sealed class TpmVirtualDeviceTests
{
    private const int HeaderSize = 10;
    private const ushort TpmStNoSessions = 0x8001;

    public TestContext TestContext { get; set; } = null!;

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The TpmResponse is owned by the returned TpmResult and disposed by the caller under test.")]
    private static TpmResult<TpmResponse> SuccessFrame(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return TpmResult<TpmResponse>.Success(new TpmResponse(owner, bytes.Length));
    }

    private static byte[] BuildGetRandomResponseFrame(int byteCount)
    {
        //Header (NO_SESSIONS, size, rc=SUCCESS) followed by a TPM2B_DIGEST: UINT16 length + octets.
        int parameterLength = sizeof(ushort) + byteCount;
        int total = HeaderSize + parameterLength;
        byte[] frame = new byte[total];

        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(0), TpmStNoSessions);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(2), (uint)total);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(6), 0u);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(HeaderSize), (ushort)byteCount);
        for(int i = 0; i < byteCount; i++)
        {
            frame[HeaderSize + sizeof(ushort) + i] = (byte)i;
        }

        return frame;
    }

    [TestMethod]
    public async Task RecordAndReplayRoundTripsRawBytes()
    {
        byte[] command = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x7B, 0x00, 0x10];
        byte[] response = BuildGetRandomResponseFrame(16);

        var virtualDevice = new TpmVirtualDevice();
        virtualDevice.Record(command, response);

        Assert.AreEqual(1, virtualDevice.ResponseCount);
        Assert.IsTrue(virtualDevice.HasResponse(command));
        Assert.IsFalse(virtualDevice.HasResponse([0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01, 0x7B]));

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResult<TpmResponse> result = await virtualDevice.SubmitAsync(
            command, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using(TpmResponse replayed = result.Value)
        {
            Assert.IsTrue(replayed.AsReadOnlySpan().SequenceEqual(response));
        }

        virtualDevice.Clear();
        Assert.AreEqual(0, virtualDevice.ResponseCount);
    }

    [TestMethod]
    public async Task SubmitReturnsFailureResponseWhenNoMatch()
    {
        var virtualDevice = new TpmVirtualDevice();
        byte[] command = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x7B, 0x00, 0x10];

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResult<TpmResponse> result = await virtualDevice.SubmitAsync(
            command, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using TpmResponse response = result.Value;
        ReadOnlySpan<byte> bytes = response.AsReadOnlySpan();

        //A header-only failure frame: 10 bytes carrying TPM_RC_FAILURE in the response code.
        Assert.AreEqual(HeaderSize, response.Length);
        uint responseCode = BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(6));
        Assert.AreEqual((uint)TpmRcConstants.TPM_RC_FAILURE, responseCode);
    }

    [TestMethod]
    public void LoadFromRecordingPopulatesResponses()
    {
        byte[] command = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x7B, 0x00, 0x10];
        byte[] response = BuildGetRandomResponseFrame(16);
        var exchange = new TpmExchange(0L, 1L, command, response);
        var sessionInfo = new TpmSessionInfo("Test", "1.0", TpmPlatform.Virtual, DateTimeOffset.UnixEpoch);
        var recording = new TpmRecording(sessionInfo, [exchange]);

        var virtualDevice = new TpmVirtualDevice();
        virtualDevice.Load(recording);

        Assert.AreEqual(1, virtualDevice.ResponseCount);
        Assert.IsTrue(virtualDevice.HasResponse(command));
    }

    [TestMethod]
    public async Task ReplaysGetRandomThroughExecutor()
    {
        const int RequestedBytes = 16;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        byte[] cannedResponse = BuildGetRandomResponseFrame(RequestedBytes);

        //Phase 1: capture the exact command the executor builds for GetRandom, feeding it the canned
        //response so the warm-up succeeds. This avoids hardcoding the on-the-wire command encoding.
        byte[]? capturedCommand = null;

        ValueTask<TpmResult<TpmResponse>> CaptureHandler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> handlerPool,
            CancellationToken cancellationToken)
        {
            capturedCommand = command.ToArray();

            return ValueTask.FromResult(SuccessFrame(cannedResponse, handlerPool));
        }

        using(TpmDevice captureDevice = TpmDevice.Create(CaptureHandler))
        {
            TpmResult<GetRandomResponse> warmup = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                captureDevice, new GetRandomInput(RequestedBytes), [], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(warmup.IsSuccess);
            warmup.Value.Dispose();
        }

        Assert.IsNotNull(capturedCommand);

        //Phase 2: load the captured command and replay it through the virtual device + executor.
        var virtualDevice = new TpmVirtualDevice();
        virtualDevice.Record(capturedCommand, cannedResponse);

        using TpmDevice replayDevice = TpmDevice.Create(virtualDevice.SubmitAsync);
        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            replayDevice, new GetRandomInput(RequestedBytes), [], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Expected success, got '{result.ResponseCode}'.");
        using GetRandomResponse response = result.Value;
        Assert.AreEqual(RequestedBytes, response.RandomBytes.Size);

        ReadOnlySpan<byte> random = response.RandomBytes.AsReadOnlySpan();
        Assert.AreEqual((byte)0x00, random[0]);
        Assert.AreEqual((byte)0x0F, random[RequestedBytes - 1]);
    }
}
