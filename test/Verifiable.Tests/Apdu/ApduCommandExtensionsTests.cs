using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Apdu;

namespace Verifiable.Tests.Apdu;

[TestClass]
internal sealed class ApduCommandExtensionsTests
{
    public TestContext TestContext { get; set; } = null!;

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The ApduResponse is owned by the returned ApduResult and disposed by the test that consumes it.")]
    private static ApduResult<ApduResponse> SuccessFrame(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);
        var response = new ApduResponse(owner, bytes.Length);

        return ApduResult<ApduResponse>.Success(response, response.StatusWord);
    }

    [TestMethod]
    public async Task SelectReturnsParsedFileControlInformation()
    {
        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            //SELECT answers with an FCI template (tag 6F) followed by 9000.
            byte[] frame = [0x6F, 0x04, 0x84, 0x02, 0x3F, 0x00, 0x90, 0x00];

            return ValueTask.FromResult(SuccessFrame(frame, pool));
        }

        using var device = ApduDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ApduResult<SelectResponse> result = await device.SelectAsync(
            WellKnownAid.Mrtd, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using SelectResponse response = result.Value;
        Assert.AreEqual(6, response.Length);

        ReadOnlySpan<byte> fci = response.FileControlInformation;
        Assert.AreEqual((byte)0x6F, fci[0]);
        Assert.AreEqual((byte)0x3F, fci[4]);
        Assert.AreEqual((byte)0x00, fci[5]);
    }

    [TestMethod]
    public async Task SelectFileNotFoundIsCardError()
    {
        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            byte[] frame = [0x6A, 0x82];

            return ValueTask.FromResult(SuccessFrame(frame, pool));
        }

        using var device = ApduDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ApduResult<SelectResponse> result = await device.SelectAsync(
            WellKnownAid.Mrtd, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsCardError);
        Assert.IsTrue(result.StatusWord.IsFileOrAppNotFound);
    }

    [TestMethod]
    public async Task SelectTransportErrorPropagates()
    {
        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            return ValueTask.FromResult(ApduResult<ApduResponse>.TransportError(0x80100069));
        }

        using var device = ApduDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ApduResult<SelectResponse> result = await device.SelectAsync(
            WellKnownAid.Mrtd, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTransportError);
    }

    [TestMethod]
    public async Task ReadBinaryEncodesOffsetAndLength()
    {
        byte[]? observedCommand = null;

        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            observedCommand = commandApdu.ToArray();
            byte[] frame = [0x11, 0x22, 0x33, 0x44, 0x55, 0x90, 0x00];

            return ValueTask.FromResult(SuccessFrame(frame, pool));
        }

        using var device = ApduDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ApduResult<ReadBinaryResponse> result = await device.ReadBinaryAsync(
            0x7F12, 5, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ReadBinaryResponse response = result.Value;
        Assert.AreEqual(5, response.Length);

        ReadOnlySpan<byte> data = response.Data;
        Assert.AreEqual((byte)0x11, data[0]);
        Assert.AreEqual((byte)0x55, data[4]);

        //Command is Case 2 short: CLA INS P1 P2 Le, with the 15-bit offset split across P1-P2.
        Assert.IsNotNull(observedCommand);
        Assert.HasCount(5, observedCommand);
        Assert.AreEqual((byte)0x00, observedCommand[0]);
        Assert.AreEqual(InstructionCode.ReadBinary.Code, observedCommand[1]);
        Assert.AreEqual((byte)0x7F, observedCommand[2]);
        Assert.AreEqual((byte)0x12, observedCommand[3]);
        Assert.AreEqual((byte)0x05, observedCommand[4]);
    }

    [TestMethod]
    public async Task ReadBinaryComposesWithResponseChaining()
    {
        //The typed layer runs over ApduExecutor, so a 61xx mid-read is assembled transparently.
        int callCount = 0;

        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            byte ins = commandApdu.Span[1];
            callCount++;

            if(ins == InstructionCode.GetResponse.Code)
            {
                byte[] rest = [0xCC, 0xDD, 0x90, 0x00];

                return ValueTask.FromResult(SuccessFrame(rest, pool));
            }

            //First READ BINARY answer: two bytes plus 6102 (two more available).
            byte[] first = [0xAA, 0xBB, 0x61, 0x02];

            return ValueTask.FromResult(SuccessFrame(first, pool));
        }

        using var device = ApduDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ApduResult<ReadBinaryResponse> result = await device.ReadBinaryAsync(
            0, 4, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ReadBinaryResponse response = result.Value;
        Assert.AreEqual(4, response.Length);

        ReadOnlySpan<byte> data = response.Data;
        Assert.AreEqual((byte)0xAA, data[0]);
        Assert.AreEqual((byte)0xDD, data[3]);
        Assert.AreEqual(2, callCount);
    }

    [TestMethod]
    public async Task GetChallengeRequestsLengthAndReturnsChallenge()
    {
        byte[]? observedCommand = null;

        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            observedCommand = commandApdu.ToArray();
            //Eight challenge bytes plus 9000, the eMRTD Basic Access Control length.
            byte[] frame = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x90, 0x00];

            return ValueTask.FromResult(SuccessFrame(frame, pool));
        }

        using var device = ApduDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ApduResult<GetChallengeResponse> result = await device.GetChallengeAsync(
            8, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using GetChallengeResponse response = result.Value;
        Assert.AreEqual(8, response.Length);

        ReadOnlySpan<byte> challenge = response.Challenge;
        Assert.AreEqual((byte)0x01, challenge[0]);
        Assert.AreEqual((byte)0x08, challenge[7]);

        //Command is 00 84 00 00 08.
        Assert.IsNotNull(observedCommand);
        Assert.HasCount(5, observedCommand);
        Assert.AreEqual((byte)0x00, observedCommand[0]);
        Assert.AreEqual(InstructionCode.GetChallenge.Code, observedCommand[1]);
        Assert.AreEqual((byte)0x00, observedCommand[2]);
        Assert.AreEqual((byte)0x00, observedCommand[3]);
        Assert.AreEqual((byte)0x08, observedCommand[4]);
    }

    [TestMethod]
    public async Task ReadBinaryRejectsOffsetAboveFifteenBits()
    {
        using var device = ApduDevice.Create(static (command, pool, ct) =>
            ValueTask.FromResult(ApduResult<ApduResponse>.TransportError(0)));
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(
            async () => await device.ReadBinaryAsync(0x8000, 1, pool, TestContext.CancellationToken)).ConfigureAwait(false);
    }

    [TestMethod]
    public async Task ReadBinaryRejectsLengthOutOfRange()
    {
        using var device = ApduDevice.Create(static (command, pool, ct) =>
            ValueTask.FromResult(ApduResult<ApduResponse>.TransportError(0)));
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(
            async () => await device.ReadBinaryAsync(0, 0, pool, TestContext.CancellationToken)).ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(
            async () => await device.ReadBinaryAsync(0, 257, pool, TestContext.CancellationToken)).ConfigureAwait(false);
    }

    [TestMethod]
    public async Task GetChallengeRejectsLengthOutOfRange()
    {
        using var device = ApduDevice.Create(static (command, pool, ct) =>
            ValueTask.FromResult(ApduResult<ApduResponse>.TransportError(0)));
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(
            async () => await device.GetChallengeAsync(0, pool, TestContext.CancellationToken)).ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(
            async () => await device.GetChallengeAsync(257, pool, TestContext.CancellationToken)).ConfigureAwait(false);
    }
}
