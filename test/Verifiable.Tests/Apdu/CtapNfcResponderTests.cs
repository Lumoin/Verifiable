using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.Ctap;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Tests for <see cref="CtapNfcResponder"/>, the authenticator (card) side of the CTAP2-over-NFC binding.
/// </summary>
[TestClass]
internal sealed class CtapNfcResponderTests
{
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A <see cref="CtapPayloadTransceiveDelegate"/> that never runs; used where the responder should reject the command before reaching the payload seam.</summary>
    private static ValueTask<PooledMemory> UnreachablePayload(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
        throw new InvalidOperationException("The payload seam must not be reached for this command.");

    /// <summary>A one-byte opaque CTAP2 request envelope carried in the NFCCTAP_MSG data field; opaque to the responder, which never inspects it (it only deframes and forwards to the payload seam).</summary>
    private static byte[] OpaquePayload => [0x04];

    [TestMethod]
    public async Task SelectWithFidoAidSucceedsAndReturnsVersionString()
    {
        using CtapNfcResponder responder = CtapNfcResponder.Create(UnreachablePayload);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using CommandApdu select = CommandApdu.BuildCase4(
            WellKnownCommandParameters.InterIndustryClassByte, InstructionCode.Select.Code,
            WellKnownCommandParameters.SelectByDfNameP1, WellKnownCommandParameters.SelectFirstOrOnlyOccurrenceFciP2,
            WellKnownAid.Fido, 0, pool);
        ApduResult<ApduResponse> result = await responder.TransceiveAsync(
            select.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ApduResponse response = result.Value;
        Assert.IsTrue(response.StatusWord.IsSuccess);
        Assert.IsTrue(response.Data.SequenceEqual("FIDO_2_0"u8));
    }

    [TestMethod]
    public async Task SelectWithWrongAidReturnsFileNotFound()
    {
        using CtapNfcResponder responder = CtapNfcResponder.Create(UnreachablePayload);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        //WellKnownAid.Piv instead of WellKnownAid.Fido: deliberately the wrong application.
        using CommandApdu select = CommandApdu.BuildCase4(
            WellKnownCommandParameters.InterIndustryClassByte, InstructionCode.Select.Code,
            WellKnownCommandParameters.SelectByDfNameP1, WellKnownCommandParameters.SelectFirstOrOnlyOccurrenceFciP2,
            WellKnownAid.Piv, 0, pool);
        ApduResult<ApduResponse> result = await responder.TransceiveAsync(
            select.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ApduResponse response = result.Value;
        Assert.IsTrue(response.StatusWord.IsFileOrAppNotFound);
    }

    [TestMethod]
    public async Task SelectWithWrongP1ReturnsIncorrectP1P2()
    {
        using CtapNfcResponder responder = CtapNfcResponder.Create(UnreachablePayload);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        //P1=0x02 (select-by-file-identifier) instead of WellKnownCommandParameters.SelectByDfNameP1 (0x04, select-by-DF-name/AID).
        using CommandApdu select = CommandApdu.BuildCase4(
            WellKnownCommandParameters.InterIndustryClassByte, InstructionCode.Select.Code,
            0x02, WellKnownCommandParameters.SelectFirstOrOnlyOccurrenceFciP2, WellKnownAid.Fido, 0, pool);
        ApduResult<ApduResponse> result = await responder.TransceiveAsync(
            select.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ApduResponse response = result.Value;
        Assert.IsTrue(response.StatusWord.IsIncorrectP1P2);
    }

    [TestMethod]
    public async Task NfcCtapMsgBeforeSelectReturnsConditionsNotSatisfied()
    {
        using CtapNfcResponder responder = CtapNfcResponder.Create(UnreachablePayload);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using CommandApdu msg = CommandApdu.BuildCase4(
            WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapMsg.Code,
            WellKnownCtapCommandParameters.SupportsGetResponseP1Bit, 0x00, OpaquePayload, 0, useExtended: true, pool);
        ApduResult<ApduResponse> result = await responder.TransceiveAsync(
            msg.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ApduResponse response = result.Value;
        Assert.AreEqual(0x6985, response.StatusWord.Value);
    }

    [TestMethod]
    public async Task NfcCtapControlDeselectsThenSubsequentMsgIsRejected()
    {
        using CtapNfcResponder responder = CtapNfcResponder.Create(UnreachablePayload);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using CommandApdu select = CommandApdu.BuildCase4(
            WellKnownCommandParameters.InterIndustryClassByte, InstructionCode.Select.Code,
            WellKnownCommandParameters.SelectByDfNameP1, WellKnownCommandParameters.SelectFirstOrOnlyOccurrenceFciP2,
            WellKnownAid.Fido, 0, pool);
        ApduResult<ApduResponse> selectResult = await responder.TransceiveAsync(
            select.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using(ApduResponse selectResponse = selectResult.Value)
        {
            Assert.IsTrue(selectResponse.StatusWord.IsSuccess);
        }

        using CommandApdu deselect = CommandApdu.BuildCase1(
            WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapControl.Code,
            WellKnownCtapCommandParameters.DeselectControlP1, 0x00, pool);
        ApduResult<ApduResponse> deselectResult = await responder.TransceiveAsync(
            deselect.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using ApduResponse deselectResponse = deselectResult.Value;
        Assert.IsTrue(deselectResponse.StatusWord.IsSuccess);

        using CommandApdu msg = CommandApdu.BuildCase4(
            WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapMsg.Code,
            WellKnownCtapCommandParameters.SupportsGetResponseP1Bit, 0x00, OpaquePayload, 0, useExtended: true, pool);
        ApduResult<ApduResponse> msgResult = await responder.TransceiveAsync(
            msg.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using ApduResponse msgResponse = msgResult.Value;
        Assert.AreEqual(0x6985, msgResponse.StatusWord.Value);
    }

    [TestMethod]
    public async Task NfcCtapGetResponseOutOfSequenceReturnsConditionsNotSatisfied()
    {
        using CtapNfcResponder responder = CtapNfcResponder.Create(UnreachablePayload);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using CommandApdu poll = CommandApdu.BuildCase2(
            WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapGetResponse.Code,
            0x00, 0x00, 0, useExtended: false, pool);
        ApduResult<ApduResponse> result = await responder.TransceiveAsync(
            poll.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        using ApduResponse response = result.Value;
        Assert.AreEqual(0x6985, response.StatusWord.Value);
    }

    [TestMethod]
    public async Task UnknownInstructionReturnsInstructionNotSupported()
    {
        using CtapNfcResponder responder = CtapNfcResponder.Create(UnreachablePayload);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        //INS=0xFE: unrecognized, unlike any of InstructionCode.Select (0xA4), InstructionCode.GetResponse
        //(0xC0), or the WellKnownCtapInstructionCodes (0x10/0x11/0x12) this responder dispatches on.
        byte[] unknown = [0x00, 0xFE, 0x00, 0x00];
        ApduResult<ApduResponse> result = await responder.TransceiveAsync(
            unknown, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using ApduResponse response = result.Value;
        Assert.IsTrue(response.StatusWord.IsInstructionNotSupported);
    }

    [TestMethod]
    public async Task ExtendedRequestRoundTripsInOneFrameThroughRealApduExecutor()
    {
        byte[] scriptedResponse = BuildScriptedPayload(300);
        byte[]? capturedRequest = null;

        ValueTask<PooledMemory> Payload(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            //Copied rather than retained: the incoming request is a view over the terminal-side
            //CommandApdu's pooled buffer, valid only for the duration of this call.
            capturedRequest = request.ToArray();

            return ValueTask.FromResult(PooledMemory.FromBytes(scriptedResponse, pool, CtapTags.ResponseEnvelope));
        }

        using CtapNfcResponder responder = CtapNfcResponder.Create(Payload);
        using var device = ApduDevice.Create(responder.TransceiveAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ApduResult<SelectResponse> selectResult = await device.SelectAsync(
            WellKnownAid.Fido, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(selectResult.IsSuccess);
        selectResult.Value.Dispose();

        CtapNfcTransport transport = CtapNfcTransport.OverApdu(device);

        //An opaque CTAP2 request envelope: its bytes are never interpreted by the responder, only
        //deframed from and reframed into NFCCTAP_MSG, so any non-empty content proves the round trip.
        byte[] request = [0x04, 0xA0];

        using PooledMemory response = await transport.TransceiveAsync(request, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(response.AsReadOnlySpan().SequenceEqual(scriptedResponse));
        Assert.IsNotNull(capturedRequest);
        CollectionAssert.AreEqual(request, capturedRequest,
            "The responder must deframe NFCCTAP_MSG down to exactly the opaque CTAP2 envelope.");
    }

    [TestMethod]
    public async Task ShortFormRequestFragmentsLargeResponseThroughRealApduExecutorAndResponder()
    {
        //A response larger than one short-form frame (256 bytes) forces genuine 61xx/GET RESPONSE
        //chaining, generated by the real CtapNfcResponder and reassembled by the real, unmodified
        //ApduExecutor — exercising both the response-side fragmentation direction and the
        //card-side-responder-over-real-executor round trip in one flow.
        byte[] scriptedResponse = BuildScriptedPayload(600);

        ValueTask<PooledMemory> Payload(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes(scriptedResponse, pool, CtapTags.ResponseEnvelope));

        using CtapNfcResponder responder = CtapNfcResponder.Create(Payload);
        using var device = ApduDevice.Create(responder.TransceiveAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ApduResult<SelectResponse> selectResult = await device.SelectAsync(
            WellKnownAid.Fido, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(selectResult.IsSuccess);
        selectResult.Value.Dispose();

        //A short-form NFCCTAP_MSG (not extended), Le=0 asking for as much as a short response allows.
        using CommandApdu shortFormMsg = CommandApdu.BuildCase4(
            WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapMsg.Code,
            WellKnownCtapCommandParameters.SupportsGetResponseP1Bit, 0x00, OpaquePayload, 0, useExtended: false, pool);

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, shortFormMsg.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using ApduResponse assembled = result.Value;
        Assert.IsTrue(assembled.StatusWord.IsSuccess);
        Assert.IsTrue(assembled.Data.SequenceEqual(scriptedResponse),
            "The executor's free 61xx/GET RESPONSE reassembly must recover exactly the scripted payload the responder fragmented.");
    }

    [TestMethod]
    public async Task DisposeMidDrainReleasesChainAndFurtherTransceiveThrows()
    {
        byte[] scriptedResponse = BuildScriptedPayload(600);

        ValueTask<PooledMemory> Payload(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes(scriptedResponse, pool, CtapTags.ResponseEnvelope));

        //Disposed explicitly mid-test rather than via using: the point under test is disposal while a
        //61xx chain is still outstanding, which must release the retained pooled response buffer.
        var responder = CtapNfcResponder.Create(Payload);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using CommandApdu select = CommandApdu.BuildCase4(
            WellKnownCommandParameters.InterIndustryClassByte, InstructionCode.Select.Code,
            WellKnownCommandParameters.SelectByDfNameP1, WellKnownCommandParameters.SelectFirstOrOnlyOccurrenceFciP2,
            WellKnownAid.Fido, 0, pool);
        ApduResult<ApduResponse> selectResult = await responder.TransceiveAsync(
            select.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using(ApduResponse selectResponse = selectResult.Value)
        {
            Assert.IsTrue(selectResponse.StatusWord.IsSuccess);
        }

        //A short-form NFCCTAP_MSG against a 600-byte response starts a chain; the chain is deliberately
        //not drained.
        using CommandApdu shortFormMsg = CommandApdu.BuildCase4(
            WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapMsg.Code,
            WellKnownCtapCommandParameters.SupportsGetResponseP1Bit, 0x00, OpaquePayload, 0, useExtended: false, pool);
        ApduResult<ApduResponse> firstResult = await responder.TransceiveAsync(
            shortFormMsg.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using(ApduResponse firstChunk = firstResult.Value)
        {
            Assert.AreEqual(0x61, firstChunk.StatusWord.Sw1);
        }

        responder.Dispose();

        await Assert.ThrowsExactlyAsync<ObjectDisposedException>(async () =>
            await responder.TransceiveAsync(shortFormMsg.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    /// <summary>Builds a deterministic byte payload of the given length for round-trip comparison.</summary>
    private static byte[] BuildScriptedPayload(int length)
    {
        byte[] payload = new byte[length];
        for(int index = 0; index < length; index++)
        {
            payload[index] = (byte)index;
        }

        return payload;
    }
}
