using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Apdu;

namespace Verifiable.Tests.Apdu;

[TestClass]
internal sealed class ApduExecutorTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task SimpleSuccessResponsePassesThrough()
    {
        var virtualCard = new VirtualCard();
        byte[] command = [0x00, 0xCB, 0x3F, 0xFF, 0x03, 0x5C, 0x01, 0x7E, 0x00];
        byte[] response = [0x7E, 0x12, 0x4F, 0x0B, 0x90, 0x00];
        virtualCard.Register(command, response);

        using var device = ApduDevice.Create(virtualCard.TransceiveAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, command, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ApduResponse apduResponse = result.Value;
        Assert.IsTrue(apduResponse.StatusWord.IsSuccess);
        Assert.AreEqual(4, apduResponse.DataLength);
    }

    [TestMethod]
    public async Task ErrorResponsePassesThrough()
    {
        var virtualCard = new VirtualCard();
        byte[] command = [0x00, 0xCB, 0x3F, 0xFF, 0x03, 0x5C, 0x01, 0x7E, 0x00];
        byte[] response = [0x6A, 0x82];
        virtualCard.Register(command, response);

        using var device = ApduDevice.Create(virtualCard.TransceiveAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, command, pool, TestContext.CancellationToken).ConfigureAwait(false);

        //VirtualCard returns 6A82 as a "success" at the transport level with that SW.
        //The executor does not reinterpret non-chaining SWs.
        Assert.IsTrue(result.IsSuccess);
        using ApduResponse apduResponse = result.Value;
        Assert.IsTrue(apduResponse.StatusWord.IsFileOrAppNotFound);
    }

    [TestMethod]
    public async Task ResponseChainingAssemblesFragments()
    {
        //Simulate a card that returns data in two chunks:
        //First response: 4 bytes of data + SW=6104 (4 more bytes available).
        //GET RESPONSE: 4 bytes of data + SW=9000.
        int callCount = 0;

        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            byte ins = commandApdu.Span[1];
            callCount++;

            if(ins == 0xCB)
            {
                //First call: return partial data with SW=6104.
                byte[] rsp = [0xAA, 0xBB, 0xCC, 0xDD, 0x61, 0x04];
                IMemoryOwner<byte> owner = pool.Rent(rsp.Length);
                rsp.CopyTo(owner.Memory.Span);
                var response = new ApduResponse(owner, rsp.Length);
                return ValueTask.FromResult(ApduResult<ApduResponse>.Success(response, response.StatusWord));
            }

            if(ins == InstructionCode.GetResponse.Code)
            {
                //Second call: return remaining data with SW=9000.
                byte[] rsp = [0xEE, 0xFF, 0x11, 0x22, 0x90, 0x00];
                IMemoryOwner<byte> owner = pool.Rent(rsp.Length);
                rsp.CopyTo(owner.Memory.Span);
                var response = new ApduResponse(owner, rsp.Length);
                return ValueTask.FromResult(ApduResult<ApduResponse>.Success(response, response.StatusWord));
            }

            return ValueTask.FromResult(ApduResult<ApduResponse>.TransportError(0));
        }

        using var device = ApduDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] command = [0x00, 0xCB, 0x3F, 0xFF, 0x00];

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, command, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ApduResponse assembled = result.Value;
        Assert.IsTrue(assembled.StatusWord.IsSuccess);
        Assert.AreEqual(8, assembled.DataLength);

        //Verify assembled data: AABBCCDD + EEFF1122.
        ReadOnlySpan<byte> data = assembled.Data;
        Assert.AreEqual((byte)0xAA, data[0]);
        Assert.AreEqual((byte)0xDD, data[3]);
        Assert.AreEqual((byte)0xEE, data[4]);
        Assert.AreEqual((byte)0x22, data[7]);

        //Two transceive calls: original + GET RESPONSE.
        Assert.AreEqual(2, callCount);
    }

    [TestMethod]
    public async Task LeCorrectionRetriesWithCorrectValue()
    {
        int callCount = 0;

        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            callCount++;

            if(callCount == 1)
            {
                //First call: return 6C05 (wrong Le, correct is 5).
                byte[] rsp = [0x6C, 0x05];
                IMemoryOwner<byte> owner = pool.Rent(rsp.Length);
                rsp.CopyTo(owner.Memory.Span);
                var response = new ApduResponse(owner, rsp.Length);
                return ValueTask.FromResult(ApduResult<ApduResponse>.Success(response, response.StatusWord));
            }

            //Second call: return actual data.
            byte[] rsp2 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x90, 0x00];
            IMemoryOwner<byte> owner2 = pool.Rent(rsp2.Length);
            rsp2.CopyTo(owner2.Memory.Span);
            var response2 = new ApduResponse(owner2, rsp2.Length);
            return ValueTask.FromResult(ApduResult<ApduResponse>.Success(response2, response2.StatusWord));
        }

        using var device = ApduDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        //Case 2 command with Le=0 (ask for max).
        byte[] command = [0x00, 0xCA, 0xDF, 0x30, 0x00];

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, command, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ApduResponse response = result.Value;
        Assert.IsTrue(response.StatusWord.IsSuccess);
        Assert.AreEqual(5, response.DataLength);
        Assert.AreEqual(2, callCount);
    }

    [TestMethod]
    public async Task TransportErrorPropagates()
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
        byte[] command = [0x00, 0xA4, 0x04, 0x00];

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, command, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTransportError);
    }

    [TestMethod]
    public async Task GetResponsePreservesOriginatingCla()
    {
        //The originating command carries CLA 0x0C (ISO 7816-4 secure-messaging bits set). The
        //GET RESPONSE the executor issues must reuse that CLA so the secured channel is honoured,
        //rather than the previously hardcoded 0x00.
        const byte SecureMessagingCla = 0x0C;
        byte getResponseCla = 0xFF;

        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            byte cla = commandApdu.Span[0];
            byte ins = commandApdu.Span[1];

            if(ins == InstructionCode.GetResponse.Code)
            {
                getResponseCla = cla;
                byte[] rsp = [0xEE, 0xFF, 0x90, 0x00];
                IMemoryOwner<byte> owner = pool.Rent(rsp.Length);
                rsp.CopyTo(owner.Memory.Span);
                var response = new ApduResponse(owner, rsp.Length);

                return ValueTask.FromResult(ApduResult<ApduResponse>.Success(response, response.StatusWord));
            }

            //Originating command: partial data + SW=6102 (two more bytes available).
            byte[] first = [0xAA, 0xBB, 0x61, 0x02];
            IMemoryOwner<byte> firstOwner = pool.Rent(first.Length);
            first.CopyTo(firstOwner.Memory.Span);
            var firstResponse = new ApduResponse(firstOwner, first.Length);

            return ValueTask.FromResult(ApduResult<ApduResponse>.Success(firstResponse, firstResponse.StatusWord));
        }

        using var device = ApduDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        //Case 2 short command with CLA 0x0C.
        byte[] command = [SecureMessagingCla, 0xB0, 0x00, 0x00, 0x00];

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, command, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ApduResponse assembled = result.Value;
        Assert.IsTrue(assembled.StatusWord.IsSuccess);
        Assert.AreEqual(SecureMessagingCla, getResponseCla);
    }

    [TestMethod]
    public async Task GetResponsePreservesLogicalChannelClaAndClearsChainingBit()
    {
        //CLA 0x11 carries logical channel 1 (low nibble) and the command-chaining bit 0x10.
        //GET RESPONSE must preserve the logical-channel bits but clear the chaining bit, leaving
        //0x01, because GET RESPONSE is a stand-alone command.
        const byte ChainedChannelOneCla = 0x11;
        const byte ExpectedGetResponseCla = 0x01;
        byte getResponseCla = 0xFF;

        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            byte cla = commandApdu.Span[0];
            byte ins = commandApdu.Span[1];

            if(ins == InstructionCode.GetResponse.Code)
            {
                getResponseCla = cla;
                byte[] rsp = [0x33, 0x90, 0x00];
                IMemoryOwner<byte> owner = pool.Rent(rsp.Length);
                rsp.CopyTo(owner.Memory.Span);
                var response = new ApduResponse(owner, rsp.Length);

                return ValueTask.FromResult(ApduResult<ApduResponse>.Success(response, response.StatusWord));
            }

            byte[] first = [0x22, 0x61, 0x01];
            IMemoryOwner<byte> firstOwner = pool.Rent(first.Length);
            first.CopyTo(firstOwner.Memory.Span);
            var firstResponse = new ApduResponse(firstOwner, first.Length);

            return ValueTask.FromResult(ApduResult<ApduResponse>.Success(firstResponse, firstResponse.StatusWord));
        }

        using var device = ApduDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        byte[] command = [ChainedChannelOneCla, 0xB0, 0x00, 0x00, 0x00];

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, command, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ApduResponse assembled = result.Value;
        Assert.AreEqual(ExpectedGetResponseCla, getResponseCla);
    }

    [TestMethod]
    public async Task LeCorrectionFollowedByChainingAssemblesAndReturnsSuccess()
    {
        //6Cxx then 61xx: the Le-corrected retry answers 61xx, so the corrected response must be
        //routed back through chaining and the caller must see assembled data + 9000.
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
                //Final GET RESPONSE: remaining two bytes + 9000.
                byte[] rsp = [0xEE, 0xFF, 0x90, 0x00];
                IMemoryOwner<byte> owner = pool.Rent(rsp.Length);
                rsp.CopyTo(owner.Memory.Span);
                var response = new ApduResponse(owner, rsp.Length);

                return ValueTask.FromResult(ApduResult<ApduResponse>.Success(response, response.StatusWord));
            }

            if(callCount == 1)
            {
                //First exchange: wrong Le, correct is 5 (6C05).
                byte[] correction = [0x6C, 0x05];
                IMemoryOwner<byte> owner = pool.Rent(correction.Length);
                correction.CopyTo(owner.Memory.Span);
                var response = new ApduResponse(owner, correction.Length);

                return ValueTask.FromResult(ApduResult<ApduResponse>.Success(response, response.StatusWord));
            }

            //Le-corrected retry: partial data + SW=6102 (two more bytes available).
            byte[] retry = [0xAA, 0xBB, 0xCC, 0x61, 0x02];
            IMemoryOwner<byte> retryOwner = pool.Rent(retry.Length);
            retry.CopyTo(retryOwner.Memory.Span);
            var retryResponse = new ApduResponse(retryOwner, retry.Length);

            return ValueTask.FromResult(ApduResult<ApduResponse>.Success(retryResponse, retryResponse.StatusWord));
        }

        using var device = ApduDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        //Case 2 short command (Le=0 asks for max).
        byte[] command = [0x00, 0xB0, 0x00, 0x00, 0x00];

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, command, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ApduResponse assembled = result.Value;
        Assert.IsTrue(assembled.StatusWord.IsSuccess);
        Assert.AreEqual(5, assembled.DataLength);

        ReadOnlySpan<byte> data = assembled.Data;
        Assert.AreEqual((byte)0xAA, data[0]);
        Assert.AreEqual((byte)0xCC, data[2]);
        Assert.AreEqual((byte)0xEE, data[3]);
        Assert.AreEqual((byte)0xFF, data[4]);

        //Original + Le-corrected retry + GET RESPONSE.
        Assert.AreEqual(3, callCount);
    }

    [TestMethod]
    public async Task SecondLeCorrectionReturnsCardErrorWithoutInfiniteLoop()
    {
        //6Cxx then 6Cxx: only one Le correction is attempted. The second 6Cxx is surfaced to the
        //caller as the card's response rather than retried again.
        int callCount = 0;

        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            callCount++;

            //Every exchange answers 6C05, including the corrected retry.
            byte[] correction = [0x6C, 0x05];
            IMemoryOwner<byte> owner = pool.Rent(correction.Length);
            correction.CopyTo(owner.Memory.Span);
            var response = new ApduResponse(owner, correction.Length);

            return ValueTask.FromResult(ApduResult<ApduResponse>.Success(response, response.StatusWord));
        }

        using var device = ApduDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        byte[] command = [0x00, 0xCA, 0xDF, 0x30, 0x00];

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, command, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ApduResponse response = result.Value;
        Assert.IsTrue(response.StatusWord.IsWrongLeWithCorrection);
        Assert.AreEqual(0x6C05, response.StatusWord.Value);

        //Original + a single correction attempt only.
        Assert.AreEqual(2, callCount);
    }

    [TestMethod]
    public async Task ChainOverflowReturnsLastMoreDataStatusNotSuccess()
    {
        //A card that never stops reporting 61xx. The executor drains a bounded number of
        //GET RESPONSE commands, then returns the assembled data with the last 61xx status word
        //(not a fabricated 9000), signalling a truncated chain.
        int callCount = 0;

        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            callCount++;

            //One byte of data plus SW=6101 on every exchange.
            byte[] rsp = [0x5A, 0x61, 0x01];
            IMemoryOwner<byte> owner = pool.Rent(rsp.Length);
            rsp.CopyTo(owner.Memory.Span);
            var response = new ApduResponse(owner, rsp.Length);

            return ValueTask.FromResult(ApduResult<ApduResponse>.Success(response, response.StatusWord));
        }

        using var device = ApduDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        byte[] command = [0x00, 0xB0, 0x00, 0x00, 0x00];

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, command, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ApduResponse assembled = result.Value;

        //The final SW is the last 61xx, not 9000.
        Assert.IsFalse(assembled.StatusWord.IsSuccess);
        Assert.IsTrue(assembled.StatusWord.IsMoreDataAvailable);
        Assert.AreEqual(0x6101, assembled.StatusWord.Value);

        //Every exchange contributes one byte: the initial response plus each bounded GET RESPONSE.
        Assert.AreEqual(callCount, assembled.DataLength);

        //The chain is bounded: one original command plus at most a fixed number of GET RESPONSE
        //commands. 65 = initial + 64 (MaxChainedResponses).
        Assert.AreEqual(65, callCount);
    }

    [TestMethod]
    public async Task GetResponseClampsLeToOriginalRequestedLength()
    {
        //The originating command requests Le=3 but the card reports five bytes available (6105).
        //Per ISO 7816-4 Annex A.4 the first GET RESPONSE must request min(originalLe, SW2) = 3,
        //not the raw SW2 of 5, to avoid over-reading.
        const int OriginalLe = 3;
        var getResponseCommands = new List<byte[]>();

        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            byte ins = commandApdu.Span[1];

            if(ins == InstructionCode.GetResponse.Code)
            {
                getResponseCommands.Add(commandApdu.ToArray());
                byte[] rsp = [0x11, 0x22, 0x33, 0x90, 0x00];
                IMemoryOwner<byte> owner = pool.Rent(rsp.Length);
                rsp.CopyTo(owner.Memory.Span);
                var response = new ApduResponse(owner, rsp.Length);

                return ValueTask.FromResult(ApduResult<ApduResponse>.Success(response, response.StatusWord));
            }

            //Originating command: no data + SW=6105 (five bytes available).
            byte[] first = [0x61, 0x05];
            IMemoryOwner<byte> firstOwner = pool.Rent(first.Length);
            first.CopyTo(firstOwner.Memory.Span);
            var firstResponse = new ApduResponse(firstOwner, first.Length);

            return ValueTask.FromResult(ApduResult<ApduResponse>.Success(firstResponse, firstResponse.StatusWord));
        }

        using var device = ApduDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        //Case 2 short command requesting Le=3.
        byte[] command = [0x00, 0xB0, 0x00, 0x00, OriginalLe];

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, command, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ApduResponse assembled = result.Value;
        Assert.IsTrue(assembled.StatusWord.IsSuccess);

        Assert.HasCount(1, getResponseCommands);

        //GET RESPONSE is Case 2 short: header(4) + Le(1). The Le byte is the corrected length.
        byte[] getResponse = getResponseCommands[0];
        byte requestedLe = getResponse[getResponse.Length - 1];
        Assert.AreEqual(OriginalLe, requestedLe);
    }

    [TestMethod]
    public async Task TruncatedSuccessFrameBecomesTransportErrorNotCrash()
    {
        //A transport that reports success but returns a frame shorter than the mandatory two-byte
        //status word is a protocol integrity failure. The executor must surface it through the
        //result channel as a transport error rather than throwing while reading the status word.
        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            //A single byte: too short to contain SW1-SW2.
            byte[] rsp = [0x90];
            IMemoryOwner<byte> owner = pool.Rent(rsp.Length);
            rsp.CopyTo(owner.Memory.Span);
            var response = new ApduResponse(owner, rsp.Length);

            return ValueTask.FromResult(ApduResult<ApduResponse>.Success(response, StatusWord.Success));
        }

        using var device = ApduDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] command = [0x00, 0xCA, 0xDF, 0x30, 0x00];

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, command, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTransportError);
        Assert.AreEqual(ApduConstants.MalformedResponseTransportError, result.TransportErrorCode);
    }

    [TestMethod]
    public async Task LeCorrectionOnCommandWithoutLeFieldIsSurfacedNotCorrupted()
    {
        //A non-conformant card answers 6Cxx to a Case 1 (header-only, no Le) command. Overwriting
        //the last byte to "correct" the Le would clobber P2 and send a different command, so the
        //executor must surface the 6Cxx to the caller and attempt no retry.
        byte[]? secondCommand = null;
        int callCount = 0;

        ValueTask<ApduResult<ApduResponse>> Handler(
            ReadOnlyMemory<byte> commandApdu,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            callCount++;
            if(callCount == 2)
            {
                secondCommand = commandApdu.ToArray();
            }

            byte[] rsp = [0x6C, 0x05];
            IMemoryOwner<byte> owner = pool.Rent(rsp.Length);
            rsp.CopyTo(owner.Memory.Span);
            var response = new ApduResponse(owner, rsp.Length);

            return ValueTask.FromResult(ApduResult<ApduResponse>.Success(response, response.StatusWord));
        }

        using var device = ApduDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        //Case 1 command: header only, no Le field. P2 is 0x42.
        byte[] command = [0x00, 0xA4, 0x04, 0x42];

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, command, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ApduResponse response = result.Value;
        Assert.IsTrue(response.StatusWord.IsWrongLeWithCorrection);
        Assert.AreEqual(0x6C05, response.StatusWord.Value);

        //No retry was attempted, so P2 was never clobbered into a corrected command.
        Assert.AreEqual(1, callCount);
        Assert.IsNull(secondCommand);
    }
}
