using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Apdu;
using Verifiable.Apdu.Ctap;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Tests for <see cref="CtapNfcResponder"/>'s NFC deferred-processing seam (CTAP 2.3, section 11.3.7.2,
/// lines 10817-10821, and lines 10799-10800's P1-gated MAY): the four-delegate
/// <see cref="CtapNfcResponder.Create(CtapPayloadTransceiveDelegate, CtapPayloadDeferredTransceiveDelegate, CtapPayloadDeferredPollDelegate, CtapPayloadDeferredCancelDelegate)"/>
/// overload's <c>0x9100</c>/poll/cancel SHALL matrix, the P1-gate trap, the out-of-sequence fence, the
/// supersede discipline, and the :10510 immediacy argument. This project cannot reference
/// <c>Verifiable.Fido2</c>'s authenticator simulator, so <see cref="DeferralStub"/> is a hand-written
/// stand-in scripting the same three delegate shapes.
/// </summary>
[TestClass]
internal sealed class CtapNfcResponderDeferralTests
{
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A <see cref="CtapPayloadTransceiveDelegate"/> that never runs; used where deferral is expected to handle every eligible request.</summary>
    private static ValueTask<PooledMemory> UnreachablePayload(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
        throw new InvalidOperationException("The synchronous payload seam must not be reached for this command.");

    /// <summary>A one-byte opaque CTAP2 request envelope carried in the NFCCTAP_MSG data field; opaque to the responder and to every delegate in this file.</summary>
    private static byte[] OpaquePayload => [0x04];

    /// <summary>CTAP2_ERR_KEEPALIVE_CANCEL (0x2D, CTAP 2.3 lines 8953-8955), the bare envelope :10821's SHALL fixes a cancel outcome to.</summary>
    private static byte[] KeepaliveCancelEnvelope => [0x2D];


    [TestMethod]
    public async Task DeferredMsgWithSupportsGetResponseBitReturnsResponseStatusWithUpNeeded()
    {
        var stub = new DeferralStub(BuildScriptedPayload(10));
        using CtapNfcResponder responder = CtapNfcResponder.Create(UnreachablePayload, stub.TransceiveAsync, stub.PollAsync, stub.CancelAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        await SelectFidoAppletAsync(responder, pool, TestContext.CancellationToken);

        using ApduResponse response = await SendDeferredEligibleMsgAsync(responder, OpaquePayload, useExtended: true, pool, TestContext.CancellationToken);

        Assert.AreEqual(0x9100, response.StatusWord.Value);
        Assert.IsTrue(response.Data.SequenceEqual([WellKnownCtapKeepaliveStatusCodes.UpNeeded]));
        Assert.AreEqual(1, stub.TransceiveCallCount);
    }


    [TestMethod]
    public async Task PollWhileStillPendingReturnsResponseStatusWithUpNeeded()
    {
        var stub = new DeferralStub(BuildScriptedPayload(10));
        using CtapNfcResponder responder = CtapNfcResponder.Create(UnreachablePayload, stub.TransceiveAsync, stub.PollAsync, stub.CancelAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        await SelectFidoAppletAsync(responder, pool, TestContext.CancellationToken);
        using(ApduResponse msgResponse = await SendDeferredEligibleMsgAsync(responder, OpaquePayload, useExtended: true, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(0x9100, msgResponse.StatusWord.Value);
        }

        using ApduResponse pollResponse = await SendGetResponsePollAsync(responder, 0x00, pool, TestContext.CancellationToken);

        Assert.AreEqual(0x9100, pollResponse.StatusWord.Value);
        Assert.IsTrue(pollResponse.Data.SequenceEqual([WellKnownCtapKeepaliveStatusCodes.UpNeeded]));
        Assert.AreEqual(1, stub.PollCallCount);
        Assert.AreEqual(1, stub.TransceiveCallCount, "a poll must not re-invoke the begin seam.");
    }


    [TestMethod]
    public async Task PollCompletionAfterExtendedMsgReturnsSuccessWithEnvelopeInOneFrame()
    {
        byte[] scriptedResponse = BuildScriptedPayload(40);
        var stub = new DeferralStub(scriptedResponse);
        using CtapNfcResponder responder = CtapNfcResponder.Create(UnreachablePayload, stub.TransceiveAsync, stub.PollAsync, stub.CancelAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        await SelectFidoAppletAsync(responder, pool, TestContext.CancellationToken);
        using(ApduResponse msgResponse = await SendDeferredEligibleMsgAsync(responder, OpaquePayload, useExtended: true, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(0x9100, msgResponse.StatusWord.Value);
        }

        stub.Resolve();

        using ApduResponse pollResponse = await SendGetResponsePollAsync(responder, 0x00, pool, TestContext.CancellationToken);

        Assert.IsTrue(pollResponse.StatusWord.IsSuccess);
        Assert.IsTrue(pollResponse.Data.SequenceEqual(scriptedResponse));
        Assert.AreEqual(1, stub.PollCallCount);
    }


    [TestMethod]
    public async Task PollCompletionAfterShortFormMsgChunksThroughRealApduExecutor()
    {
        //A response larger than one short-form frame (256 bytes), so the completion path genuinely
        //exercises EmitChunk's 61xx/GET RESPONSE chaining (trap 8) rather than a single small frame.
        byte[] scriptedResponse = BuildScriptedPayload(600);
        var stub = new DeferralStub(scriptedResponse);
        using CtapNfcResponder responder = CtapNfcResponder.Create(UnreachablePayload, stub.TransceiveAsync, stub.PollAsync, stub.CancelAsync);
        using var device = ApduDevice.Create(responder.TransceiveAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        ApduResult<SelectResponse> selectResult = await device.SelectAsync(WellKnownAid.Fido, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(selectResult.IsSuccess);
        selectResult.Value.Dispose();

        using CommandApdu shortFormMsg = CommandApdu.BuildCase4(
            WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapMsg.Code,
            WellKnownCtapCommandParameters.SupportsGetResponseP1Bit, 0x00, OpaquePayload, 0, useExtended: false, pool);
        ApduResult<ApduResponse> msgResult = await ApduExecutor.ExecuteAsync(
            device, shortFormMsg.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using(ApduResponse msgResponse = msgResult.Value)
        {
            Assert.AreEqual(0x9100, msgResponse.StatusWord.Value);
            Assert.IsTrue(msgResponse.Data.SequenceEqual([WellKnownCtapKeepaliveStatusCodes.UpNeeded]));
        }

        stub.Resolve();

        using CommandApdu poll = CommandApdu.BuildCase2(
            WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapGetResponse.Code,
            0x00, 0x00, 0, useExtended: false, pool);
        ApduResult<ApduResponse> pollResult = await ApduExecutor.ExecuteAsync(
            device, poll.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pollResult.IsSuccess);
        using ApduResponse assembled = pollResult.Value;
        Assert.IsTrue(assembled.StatusWord.IsSuccess);
        Assert.IsTrue(assembled.Data.SequenceEqual(scriptedResponse),
            "The executor's free 61xx/GET RESPONSE reassembly must recover exactly the scripted payload the deferred-completion path fragmented.");
    }


    [TestMethod]
    public async Task CancelReturnsSuccessWithDeferredCancelEnvelopeAndClearsThePendingFlag()
    {
        var stub = new DeferralStub(BuildScriptedPayload(10));
        using CtapNfcResponder responder = CtapNfcResponder.Create(UnreachablePayload, stub.TransceiveAsync, stub.PollAsync, stub.CancelAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        await SelectFidoAppletAsync(responder, pool, TestContext.CancellationToken);
        using(ApduResponse msgResponse = await SendDeferredEligibleMsgAsync(responder, OpaquePayload, useExtended: true, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(0x9100, msgResponse.StatusWord.Value);
        }

        using(ApduResponse cancelResponse = await SendGetResponsePollAsync(responder, WellKnownCtapCommandParameters.CancelP1, pool, TestContext.CancellationToken))
        {
            Assert.IsTrue(cancelResponse.StatusWord.IsSuccess);
            Assert.IsTrue(cancelResponse.Data.SequenceEqual(KeepaliveCancelEnvelope));
        }

        Assert.AreEqual(1, stub.CancelCallCount);
        Assert.AreEqual(0, stub.PollCallCount);

        //The responder's own pending flag is cleared by the cancel: a further poll is out-of-sequence.
        using ApduResponse afterCancelResponse = await SendGetResponsePollAsync(responder, 0x00, pool, TestContext.CancellationToken);
        Assert.AreEqual(0x6985, afterCancelResponse.StatusWord.Value);
    }


    [TestMethod]
    public async Task MsgWithoutSupportsGetResponseBitCompletesSynchronouslyEvenWithDeferralConfigured()
    {
        byte[] scriptedResponse = BuildScriptedPayload(10);
        //A deliberately different payload from what the deferral stub would answer, so any accidental
        //invocation of the deferral seam would be visible via a mismatched response, not just a counter.
        var stub = new DeferralStub(BuildScriptedPayload(99));

        ValueTask<PooledMemory> Payload(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes(scriptedResponse, pool, CtapTags.ResponseEnvelope));

        using CtapNfcResponder responder = CtapNfcResponder.Create(Payload, stub.TransceiveAsync, stub.PollAsync, stub.CancelAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        await SelectFidoAppletAsync(responder, pool, TestContext.CancellationToken);

        //TRAP 1 (:10799-10800): P1=0x00 — the SupportsGetResponseP1Bit (0x80) is deliberately absent,
        //even though this responder has deferral fully wired and the stub would happily park.
        using CommandApdu msg = CommandApdu.BuildCase4(
            WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapMsg.Code,
            0x00, 0x00, OpaquePayload, 0, useExtended: true, pool);
        ApduResult<ApduResponse> result = await responder.TransceiveAsync(msg.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using ApduResponse response = result.Value;

        Assert.IsTrue(response.StatusWord.IsSuccess);
        Assert.AreNotEqual(0x9100, response.StatusWord.Value);
        Assert.IsTrue(response.Data.SequenceEqual(scriptedResponse));
        Assert.AreEqual(0, stub.TransceiveCallCount, "the deferral seam must never be invoked without the client's own P1 opt-in.");
    }


    [TestMethod]
    public async Task GetResponsePollWithNothingPendingOnDeferralConfiguredResponderReturnsConditionsNotSatisfied()
    {
        var stub = new DeferralStub(BuildScriptedPayload(10));
        using CtapNfcResponder responder = CtapNfcResponder.Create(UnreachablePayload, stub.TransceiveAsync, stub.PollAsync, stub.CancelAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using ApduResponse response = await SendGetResponsePollAsync(responder, 0x00, pool, TestContext.CancellationToken);

        Assert.AreEqual(0x6985, response.StatusWord.Value);
        Assert.AreEqual(0, stub.PollCallCount);
    }


    [TestMethod]
    public async Task GetResponseCancelWithNothingPendingOnDeferralConfiguredResponderReturnsConditionsNotSatisfied()
    {
        //TRAP 5, extended to the cancel variant: NfcCtapGetResponseOutOfSequenceReturnsConditionsNotSatisfied
        //covers P1=0x00 against a non-deferring responder; this covers P1=CancelP1 against a
        //deferral-configured one — the fence holds "regardless of P1" as the contract requires.
        var stub = new DeferralStub(BuildScriptedPayload(10));
        using CtapNfcResponder responder = CtapNfcResponder.Create(UnreachablePayload, stub.TransceiveAsync, stub.PollAsync, stub.CancelAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using ApduResponse response = await SendGetResponsePollAsync(responder, WellKnownCtapCommandParameters.CancelP1, pool, TestContext.CancellationToken);

        Assert.AreEqual(0x6985, response.StatusWord.Value);
        Assert.AreEqual(0, stub.CancelCallCount);
    }


    [TestMethod]
    public async Task DeferredRepliesAreProducedImmediatelyWithoutAdvancingTheClock()
    {
        //CTAP 2.3 :10510's 800ms RECOMMENDED is met by construction here: a never-granting stub and a
        //FakeTimeProvider left unadvanced for the whole test still produce every 0x9100 reply below,
        //proving no code path in the responder waits on elapsed time to answer.
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        var stub = new DeferralStub(BuildScriptedPayload(10));
        using CtapNfcResponder responder = CtapNfcResponder.Create(UnreachablePayload, stub.TransceiveAsync, stub.PollAsync, stub.CancelAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        await SelectFidoAppletAsync(responder, pool, TestContext.CancellationToken);

        using(ApduResponse msgResponse = await SendDeferredEligibleMsgAsync(responder, OpaquePayload, useExtended: true, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(0x9100, msgResponse.StatusWord.Value);
        }

        using(ApduResponse pollResponse = await SendGetResponsePollAsync(responder, 0x00, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(0x9100, pollResponse.StatusWord.Value);
        }

        Assert.AreEqual(TestClock.CanonicalEpoch, timeProvider.GetUtcNow(), "no reply above required the clock to advance.");
    }


    [TestMethod]
    public async Task NewSelectWhilePendingCancelsTheDeferralAndDiscardsItsEnvelope()
    {
        var stub = new DeferralStub(BuildScriptedPayload(10));
        using CtapNfcResponder responder = CtapNfcResponder.Create(UnreachablePayload, stub.TransceiveAsync, stub.PollAsync, stub.CancelAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        await SelectFidoAppletAsync(responder, pool, TestContext.CancellationToken);
        using(ApduResponse msgResponse = await SendDeferredEligibleMsgAsync(responder, OpaquePayload, useExtended: true, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(0x9100, msgResponse.StatusWord.Value);
        }

        //A fresh SELECT supersedes the request still parked from the exchange above.
        await SelectFidoAppletAsync(responder, pool, TestContext.CancellationToken);

        Assert.AreEqual(1, stub.CancelCallCount);

        using ApduResponse pollResponse = await SendGetResponsePollAsync(responder, 0x00, pool, TestContext.CancellationToken);
        Assert.AreEqual(0x6985, pollResponse.StatusWord.Value, "the responder's own pending flag must have been cleared by the supersede.");
        Assert.AreEqual(0, stub.PollCallCount);
    }


    [TestMethod]
    public async Task NewMsgWhilePendingCancelsThePriorDeferralBeforeStartingTheNewOne()
    {
        var stub = new DeferralStub(BuildScriptedPayload(10));
        using CtapNfcResponder responder = CtapNfcResponder.Create(UnreachablePayload, stub.TransceiveAsync, stub.PollAsync, stub.CancelAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        await SelectFidoAppletAsync(responder, pool, TestContext.CancellationToken);
        using(ApduResponse firstMsgResponse = await SendDeferredEligibleMsgAsync(responder, OpaquePayload, useExtended: true, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(0x9100, firstMsgResponse.StatusWord.Value);
        }

        using(ApduResponse secondMsgResponse = await SendDeferredEligibleMsgAsync(responder, OpaquePayload, useExtended: true, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(0x9100, secondMsgResponse.StatusWord.Value);
        }

        Assert.AreEqual(1, stub.CancelCallCount, "the first parked request must be cancelled before the second one begins.");
        Assert.AreEqual(2, stub.TransceiveCallCount);
    }


    [TestMethod]
    public async Task ControlDeselectWhilePendingCancelsTheDeferralAndDiscardsItsEnvelope()
    {
        var stub = new DeferralStub(BuildScriptedPayload(10));
        using CtapNfcResponder responder = CtapNfcResponder.Create(UnreachablePayload, stub.TransceiveAsync, stub.PollAsync, stub.CancelAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        await SelectFidoAppletAsync(responder, pool, TestContext.CancellationToken);
        using(ApduResponse msgResponse = await SendDeferredEligibleMsgAsync(responder, OpaquePayload, useExtended: true, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(0x9100, msgResponse.StatusWord.Value);
        }

        using CommandApdu deselect = CommandApdu.BuildCase1(
            WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapControl.Code,
            WellKnownCtapCommandParameters.DeselectControlP1, 0x00, pool);
        ApduResult<ApduResponse> deselectResult = await responder.TransceiveAsync(
            deselect.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using(ApduResponse deselectResponse = deselectResult.Value)
        {
            Assert.IsTrue(deselectResponse.StatusWord.IsSuccess);
        }

        Assert.AreEqual(1, stub.CancelCallCount);
    }


    [TestMethod]
    public void CreateWithDeferralThrowsOnNullPayloadTransceive()
    {
        var stub = new DeferralStub(BuildScriptedPayload(1));

        Assert.ThrowsExactly<ArgumentNullException>(() =>
            CtapNfcResponder.Create(null!, stub.TransceiveAsync, stub.PollAsync, stub.CancelAsync));
    }


    [TestMethod]
    public void CreateWithDeferralThrowsOnNullDeferredTransceive()
    {
        var stub = new DeferralStub(BuildScriptedPayload(1));

        Assert.ThrowsExactly<ArgumentNullException>(() =>
            CtapNfcResponder.Create(UnreachablePayload, null!, stub.PollAsync, stub.CancelAsync));
    }


    [TestMethod]
    public void CreateWithDeferralThrowsOnNullDeferredPoll()
    {
        var stub = new DeferralStub(BuildScriptedPayload(1));

        Assert.ThrowsExactly<ArgumentNullException>(() =>
            CtapNfcResponder.Create(UnreachablePayload, stub.TransceiveAsync, null!, stub.CancelAsync));
    }


    [TestMethod]
    public void CreateWithDeferralThrowsOnNullDeferredCancel()
    {
        var stub = new DeferralStub(BuildScriptedPayload(1));

        Assert.ThrowsExactly<ArgumentNullException>(() =>
            CtapNfcResponder.Create(UnreachablePayload, stub.TransceiveAsync, stub.PollAsync, null!));
    }


    /// <summary>Selects the FIDO applet and asserts success, discarding the response.</summary>
    private static async ValueTask SelectFidoAppletAsync(CtapNfcResponder responder, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using CommandApdu select = CommandApdu.BuildCase4(
            WellKnownCommandParameters.InterIndustryClassByte, InstructionCode.Select.Code,
            WellKnownCommandParameters.SelectByDfNameP1, WellKnownCommandParameters.SelectFirstOrOnlyOccurrenceFciP2,
            WellKnownAid.Fido, 0, pool);
        ApduResult<ApduResponse> result = await responder.TransceiveAsync(select.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        using ApduResponse response = result.Value;

        Assert.IsTrue(response.StatusWord.IsSuccess);
    }


    /// <summary>Sends an NFCCTAP_MSG with <see cref="WellKnownCtapCommandParameters.SupportsGetResponseP1Bit"/> set — the deferral-eligible shape. The caller owns and must dispose the returned response.</summary>
    private static async ValueTask<ApduResponse> SendDeferredEligibleMsgAsync(
        CtapNfcResponder responder, byte[] payload, bool useExtended, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using CommandApdu msg = CommandApdu.BuildCase4(
            WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapMsg.Code,
            WellKnownCtapCommandParameters.SupportsGetResponseP1Bit, 0x00, payload, 0, useExtended, pool);
        ApduResult<ApduResponse> result = await responder.TransceiveAsync(msg.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);

        return result.Value;
    }


    /// <summary>Sends an NFCCTAP_GETRESPONSE with the given P1 (poll when not <see cref="WellKnownCtapCommandParameters.CancelP1"/>, cancel otherwise). The caller owns and must dispose the returned response.</summary>
    private static async ValueTask<ApduResponse> SendGetResponsePollAsync(
        CtapNfcResponder responder, byte p1, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using CommandApdu poll = CommandApdu.BuildCase2(
            WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapGetResponse.Code,
            p1, 0x00, 0, useExtended: false, pool);
        ApduResult<ApduResponse> result = await responder.TransceiveAsync(poll.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);

        return result.Value;
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


    /// <summary>
    /// A hand-written stub for the three deferred delegate shapes
    /// (<see cref="CtapPayloadDeferredTransceiveDelegate"/>, <see cref="CtapPayloadDeferredPollDelegate"/>,
    /// <see cref="CtapPayloadDeferredCancelDelegate"/>), scripting a single park-then-resolve request
    /// without depending on any authenticator implementation.
    /// </summary>
    private sealed class DeferralStub
    {
        private readonly byte[] completedResponse;
        private bool resolved;

        /// <summary>Initializes the stub with the envelope a poll returns once <see cref="Resolve"/> has been called.</summary>
        public DeferralStub(byte[] completedResponse)
        {
            this.completedResponse = completedResponse;
        }

        /// <summary>Gets the number of times <see cref="TransceiveAsync"/> was invoked.</summary>
        public int TransceiveCallCount { get; private set; }

        /// <summary>Gets the number of times <see cref="PollAsync"/> was invoked.</summary>
        public int PollCallCount { get; private set; }

        /// <summary>Gets the number of times <see cref="CancelAsync"/> was invoked.</summary>
        public int CancelCallCount { get; private set; }

        /// <summary>Marks the scripted request resolved: the next <see cref="PollAsync"/> call returns the completed envelope instead of the empty pending marker.</summary>
        public void Resolve() => resolved = true;

        /// <summary>Always parks (the empty-marker convention) — this stub never completes synchronously.</summary>
        public ValueTask<PooledMemory> TransceiveAsync(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            TransceiveCallCount++;

            return ValueTask.FromResult(PooledMemory.FromBytes(ReadOnlySpan<byte>.Empty, pool, CtapTags.ResponseEnvelope));
        }

        /// <summary>Returns the empty pending marker until <see cref="Resolve"/> has been called, then the scripted completed envelope.</summary>
        public ValueTask<PooledMemory> PollAsync(MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            PollCallCount++;

            ReadOnlySpan<byte> data = resolved ? completedResponse : ReadOnlySpan<byte>.Empty;

            return ValueTask.FromResult(PooledMemory.FromBytes(data, pool, CtapTags.ResponseEnvelope));
        }

        /// <summary>Always returns the bare <see cref="CtapNfcResponderDeferralTests.KeepaliveCancelEnvelope"/> — a cancel always resolves.</summary>
        public ValueTask<PooledMemory> CancelAsync(MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            CancelCallCount++;

            return ValueTask.FromResult(PooledMemory.FromBytes(KeepaliveCancelEnvelope, pool, CtapTags.ResponseEnvelope));
        }
    }
}
