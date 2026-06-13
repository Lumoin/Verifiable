using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Non-hardware coverage for <see cref="TpmCommandExecutor.ExecuteAsync"/>, driving the full
/// request-build and response-parse path through a scripted <see cref="TpmDevice.Create"/> handler.
/// </summary>
/// <remarks>
/// The <c>HwTpm*</c> tests exercise the executor only when a physical TPM is present; on machines
/// without one they skip. These tests cover the sessionless build/parse path deterministically with
/// canned response bytes, so a refactor of the executor envelope handling is guarded by an
/// executing test rather than only by hardware-gated ones.
/// </remarks>
[TestClass]
internal sealed class TpmCommandExecutorTests
{
    //TPM command/response header: tag (UINT16) + size (UINT32) + commandCode/responseCode (UINT32).
    private const int HeaderSize = 10;
    private const ushort TpmStNoSessions = 0x8001;

    public TestContext TestContext { get; set; } = null!;

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The TpmResponse is owned by the returned TpmResult and disposed by the executor under test.")]
    private static TpmResult<TpmResponse> SuccessFrame(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return TpmResult<TpmResponse>.Success(new TpmResponse(owner, bytes.Length));
    }

    private static byte[] BuildNoSessionsFrame(uint responseCode, ReadOnlySpan<byte> parameters)
    {
        int total = HeaderSize + parameters.Length;
        byte[] frame = new byte[total];

        frame[0] = (byte)(TpmStNoSessions >> 8);
        frame[1] = (byte)(TpmStNoSessions & 0xFF);
        frame[2] = (byte)(total >> 24);
        frame[3] = (byte)(total >> 16);
        frame[4] = (byte)(total >> 8);
        frame[5] = (byte)(total & 0xFF);
        frame[6] = (byte)(responseCode >> 24);
        frame[7] = (byte)(responseCode >> 16);
        frame[8] = (byte)(responseCode >> 8);
        frame[9] = (byte)(responseCode & 0xFF);
        parameters.CopyTo(frame.AsSpan(HeaderSize));

        return frame;
    }

    [TestMethod]
    public async Task ExecutorBuildsGetRandomCommandAndParsesResponse()
    {
        const int RequestedBytes = 16;
        byte[]? observedCommand = null;

        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            observedCommand = command.ToArray();

            //GetRandom is sessionless: bytesRequested (UINT16) sits immediately after the header.
            ushort requested = (ushort)((command.Span[HeaderSize] << 8) | command.Span[HeaderSize + 1]);

            //Parameters: TPM2B_DIGEST = UINT16 length + that many octets (deterministic content).
            byte[] parameters = new byte[sizeof(ushort) + requested];
            parameters[0] = (byte)(requested >> 8);
            parameters[1] = (byte)(requested & 0xFF);
            for(int i = 0; i < requested; i++)
            {
                parameters[sizeof(ushort) + i] = (byte)i;
            }

            byte[] frame = BuildNoSessionsFrame(0u, parameters);

            return ValueTask.FromResult(SuccessFrame(frame, pool));
        }

        using var device = TpmDevice.Create(Handler);
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        var input = new GetRandomInput(RequestedBytes);

        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, input, [], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Expected success, got '{result.ResponseCode}'.");
        using GetRandomResponse response = result.Value;
        Assert.AreEqual(RequestedBytes, response.RandomBytes.Size);

        //Parsed content matches what the canned response carried.
        ReadOnlySpan<byte> random = response.RandomBytes.AsReadOnlySpan();
        Assert.AreEqual((byte)0x00, random[0]);
        Assert.AreEqual((byte)0x0F, random[RequestedBytes - 1]);

        //The executor built a well-formed sessionless command carrying the requested length.
        Assert.IsNotNull(observedCommand);
        Assert.AreEqual((byte)(TpmStNoSessions >> 8), observedCommand[0]);
        Assert.AreEqual((byte)(TpmStNoSessions & 0xFF), observedCommand[1]);
        ushort commandRequested = (ushort)((observedCommand[HeaderSize] << 8) | observedCommand[HeaderSize + 1]);
        Assert.AreEqual(RequestedBytes, commandRequested);
    }

    [TestMethod]
    public async Task ExecutorSurfacesTpmErrorResponseCode()
    {
        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            //A header-only error response (no parameters) carrying a non-success response code.
            byte[] frame = BuildNoSessionsFrame((uint)TpmRcConstants.TPM_RC_VALUE, ReadOnlySpan<byte>.Empty);

            return ValueTask.FromResult(SuccessFrame(frame, pool));
        }

        using var device = TpmDevice.Create(Handler);
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        var input = new GetRandomInput(8);

        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, input, [], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTpmError);
        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, result.ResponseCode);
    }

    [TestMethod]
    public async Task ExecutorSurfacesTransportError()
    {
        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            return ValueTask.FromResult(TpmResult<TpmResponse>.TransportError(0x1234u));
        }

        using var device = TpmDevice.Create(Handler);
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        var input = new GetRandomInput(8);

        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, input, [], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTransportError);
    }
}
