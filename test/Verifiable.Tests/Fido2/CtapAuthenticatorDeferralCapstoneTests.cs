using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Apdu;
using Verifiable.Apdu.Ctap;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// R11's real-wire capstones for the CTAP 2.3 NFC deferral conversation (:10798's P1-gated MAY,
/// :10817-10821's GETRESPONSE poll/cancel SHALLs, :2840's user-action timeout): the deferral-configured
/// composition of <see cref="CtapNfcTransport"/>/<see cref="CtapNfcResponder"/> over a REAL
/// <see cref="CtapAuthenticatorSimulator"/> (<see cref="CtapWave2TransportHarness.CreateWithDeferralAsync"/>),
/// closing the loop between the automata-level proofs in <c>CtapUserPresenceTests</c> and the
/// responder-level, stub-backed proofs in <c>CtapNfcResponderDeferralTests</c>.
/// </summary>
/// <remarks>
/// Every scenario reads a wire-visible fact only: a raw <see cref="ApduResponse.StatusWord"/>/
/// <see cref="ApduResponse.Data"/> pair, a <see cref="CtapCommandException.StatusCode"/>, or a decoded
/// CTAP2 response — never internal simulator state. <see cref="CtapNfcTransport"/> itself is never
/// modified; scenarios that need to observe an individual <c>0x9100</c> reply or force P1 to a value the
/// transport never sends drive <see cref="CtapWave2TransportHarness.Device"/> with the SAME
/// <see cref="CommandApdu"/>/<see cref="ApduExecutor"/> framing primitives the transport itself uses.
/// </remarks>
[TestClass]
internal sealed class CtapAuthenticatorDeferralCapstoneTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// The full :10798/:10818 deferral conversation over the real wire: <c>NFCCTAP_MSG</c> with the
    /// <c>0x80</c> bit parks the request (<c>0x9100</c> + <see cref="WellKnownCtapKeepaliveStatusCodes.UpNeeded"/>),
    /// several <c>NFCCTAP_GETRESPONSE</c> polls keep finding it pending (the same status pair) while a
    /// grant-after-N-consults provider still declines, and the poll whose consult finally grants resumes
    /// the parked <c>authenticatorMakeCredential</c> to a <c>0x9000</c> success envelope. That resumed
    /// response is compared against the SAME request run synchronously on a fresh, always-granting
    /// simulator sharing the same AAGUID — agreement is asserted on every DETERMINISTIC field only
    /// (status, <c>fmt</c>, <c>attStmt</c> presence, <c>rpIdHash</c>, authData flags, <c>signCount</c>,
    /// <c>aaguid</c>, credential <c>kty</c>/<c>alg</c>), per the 2026-07-20 post-verify adjudication that
    /// literal byte-identity is unsatisfiable (mc mints a fresh per-run keypair) — mirroring
    /// <c>CtapUserPresenceTests.PollDeferredTransceiveResumesOnGrantedDecisionMatchingSynchronousResponseStructurally</c>'s
    /// own assertion set, now proven end to end over the wire instead of against the simulator directly.
    /// </summary>
    [TestMethod]
    public async Task DeferredMakeCredentialOverRealWireResolvesAfterSeveralPollsMatchingSynchronousResponseStructurally()
    {
        Guid sharedAaguid = Guid.NewGuid();
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        int consultCount = 0;
        ValueTask<CtapUserPresenceDecision> GrantOnFourthConsultProvider(CancellationToken ct)
        {
            consultCount++;

            return ValueTask.FromResult(consultCount >= 4 ? CtapUserPresenceDecision.Granted : CtapUserPresenceDecision.Pending);
        }

        using CtapAuthenticatorSimulator deferredSimulator = CreateSimulator(
            "wave2-capstone-deferred-success", aaguid: sharedAaguid, simulateUserPresence: GrantOnFourthConsultProvider);
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateWithDeferralAsync(deferredSimulator, pool, cancellationToken);

        CtapMakeCredentialRequest deferredRequest = BuildMakeCredentialRequest(pool);
        byte[] envelope = CtapWave2RequestEnvelopes.BuildMakeCredentialEnvelope(deferredRequest);
        DisposeMakeCredentialRequest(deferredRequest);

        using CommandApdu msg = CommandApdu.BuildCase4(
            WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapMsg.Code,
            WellKnownCtapCommandParameters.SupportsGetResponseP1Bit, 0x00, envelope, 0, useExtended: true, pool);
        ApduResult<ApduResponse> msgResult = await ApduExecutor.ExecuteAsync(harness.Device, msg.AsReadOnlyMemory(), pool, cancellationToken);
        using(ApduResponse msgResponse = msgResult.Value)
        {
            Assert.AreEqual(0x9100, msgResponse.StatusWord.Value);
            Assert.IsTrue(msgResponse.Data.SequenceEqual([WellKnownCtapKeepaliveStatusCodes.UpNeeded]));
        }

        int pendingPollCount = 0;
        byte[]? resumedEnvelopeBytes = null;
        while(resumedEnvelopeBytes is null)
        {
            using CommandApdu poll = CommandApdu.BuildCase2(
                WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapGetResponse.Code,
                0x00, 0x00, 0, useExtended: false, pool);
            ApduResult<ApduResponse> pollResult = await ApduExecutor.ExecuteAsync(harness.Device, poll.AsReadOnlyMemory(), pool, cancellationToken);
            using ApduResponse pollResponse = pollResult.Value;

            if(pollResponse.StatusWord.Value == 0x9100)
            {
                Assert.IsTrue(pollResponse.Data.SequenceEqual([WellKnownCtapKeepaliveStatusCodes.UpNeeded]));
                pendingPollCount++;
                Assert.IsLessThan(10, pendingPollCount, "the grant-after-four-consults provider must resolve well within ten polls.");
                continue;
            }

            Assert.IsTrue(pollResponse.StatusWord.IsSuccess);
            resumedEnvelopeBytes = pollResponse.Data.ToArray();
        }

        Assert.IsGreaterThan(0, pendingPollCount, "the provider's fourth-consult grant must be preceded by at least one still-pending poll.");
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resumedEnvelopeBytes[0]);

        using CtapAuthenticatorSimulator syncSimulator = CreateSimulator("wave2-capstone-deferred-success-sync", aaguid: sharedAaguid);
        CtapMakeCredentialRequest syncRequest = BuildMakeCredentialRequest(pool);
        using PooledMemory syncResponse = await SendMakeCredentialAsync(syncSimulator, syncRequest, pool, cancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, syncResponse.AsReadOnlySpan()[0]);

        CtapMakeCredentialResponse resumedDecoded = CtapMakeCredentialResponseCborReader.Read(resumedEnvelopeBytes.AsMemory(1));
        CtapMakeCredentialResponse syncDecoded = CtapMakeCredentialResponseCborReader.Read(syncResponse.AsReadOnlyMemory()[1..]);

        AssertMakeCredentialResponsesAreStructurallyIdentical(syncDecoded, resumedDecoded, sharedAaguid, pool);
    }


    /// <summary>
    /// CTAP 2.3 :10821: a caller cancellation surfacing mid-poll drives the UNMODIFIED
    /// <see cref="CtapNfcTransport"/>'s own cancel branch — it issues exactly one
    /// <c>NFCCTAP_GETRESPONSE</c> with <see cref="WellKnownCtapCommandParameters.CancelP1"/> before
    /// throwing — against a REAL simulator's <see cref="CtapAuthenticatorSimulator.CancelDeferredTransceiveAsync"/>
    /// (not the stub <c>CtapNfcResponderDeferralTests</c> uses). The user-presence provider itself
    /// triggers the cancellation as a side effect of its ONE consult during the initial park, so the
    /// exact loop iteration the cancellation lands on is deterministic rather than a real-time race. The
    /// simulator's own <see cref="WellKnownCtapStatusCodes.KeepaliveCancel"/> envelope
    /// (<c>CtapUserPresenceTests.CancelDeferredTransceiveReturnsKeepaliveCancelAndDiscardsTheWait</c>) and
    /// the responder's <c>0x9000</c>+<c>[0x2D]</c> wrapping of it
    /// (<c>CtapNfcResponderDeferralTests.CancelReturnsSuccessWithDeferredCancelEnvelopeAndClearsThePendingFlag</c>)
    /// are already proven directly; this capstone's own new fact is that the wait a subsequent poll would
    /// have resumed is provably gone once the REAL <see cref="CtapNfcTransport"/> has cancelled it.
    /// </summary>
    [TestMethod]
    public async Task CancellingDuringADeferredMakeCredentialSendsCancelP1AndSurfacesOperationCanceled()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using var cancellationSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);

        async ValueTask<CtapUserPresenceDecision> CancelDuringFirstConsultProvider(CancellationToken ct)
        {
            await cancellationSource.CancelAsync().ConfigureAwait(false);

            return CtapUserPresenceDecision.Pending;
        }

        using CtapAuthenticatorSimulator simulator = CreateSimulator("wave2-capstone-cancel", simulateUserPresence: CancelDuringFirstConsultProvider);
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateWithDeferralAsync(simulator, pool, TestContext.CancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
        byte[] envelope = CtapWave2RequestEnvelopes.BuildMakeCredentialEnvelope(request);
        DisposeMakeCredentialRequest(request);

        OperationCanceledException cancelled = await Assert.ThrowsExactlyAsync<OperationCanceledException>(
            () => harness.Transceive(envelope, pool, cancellationSource.Token).AsTask());
        Assert.AreEqual(cancellationSource.Token, cancelled.CancellationToken);

        //The transport's own cancel branch already resolved the real simulator's pending wait to
        //[KeepaliveCancel] and discarded it before surfacing the cancellation above -- a fresh poll now
        //finds nothing pending, the same internal-misuse guard the automata-level test exercises directly.
        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            () => simulator.PollDeferredTransceiveAsync(pool, TestContext.CancellationToken).AsTask());
    }


    /// <summary>
    /// CTAP 2.3 :2840's 30-second user-action timeout, driven purely through a <see cref="FakeTimeProvider"/>
    /// seeded at <see cref="TestClock.CanonicalEpoch"/>: a never-granting provider advances the clock by
    /// 11 seconds on every consult, so after the park plus a handful of polls the NEXT poll's own captured
    /// <c>Now</c> already exceeds the 30-second bound and resolves to <see cref="WellKnownCtapStatusCodes.UserActionTimeout"/>
    /// without a further consult — surfaced through <see cref="CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync"/>
    /// as <see cref="CtapCommandException"/>, exactly as it would for any other non-<c>CTAP2_OK</c> status.
    /// </summary>
    [TestMethod]
    public async Task DeferredMakeCredentialTimesOutOverRealWireWhenProviderAdvancesPastThirtySecondsAndSurfacesUserActionTimeoutThroughClient()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        int consultCount = 0;
        ValueTask<CtapUserPresenceDecision> NeverGrantingAdvancingProvider(CancellationToken ct)
        {
            consultCount++;
            timeProvider.Advance(TimeSpan.FromSeconds(11));

            return ValueTask.FromResult(CtapUserPresenceDecision.Pending);
        }

        using CtapAuthenticatorSimulator simulator = CreateSimulator(
            "wave2-capstone-timeout", timeProvider: timeProvider, simulateUserPresence: NeverGrantingAdvancingProvider);
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateWithDeferralAsync(simulator, pool, cancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);

        CtapCommandException commandException = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
                harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
                .AsTask());
        DisposeMakeCredentialRequest(request);

        Assert.AreEqual(WellKnownCtapStatusCodes.UserActionTimeout, commandException.StatusCode);
        Assert.IsGreaterThan(1, consultCount, "the timeout must be crossed by the clock advancing across the initial park and at least one poll, not on the very first consult.");
    }


    /// <summary>
    /// CTAP 2.3 :10799-10800's P1 gate, trap 1, driven against a REAL simulator instead of
    /// <c>CtapNfcResponderDeferralTests</c>' stub: an <c>NFCCTAP_MSG</c> whose P1 omits
    /// <see cref="WellKnownCtapCommandParameters.SupportsGetResponseP1Bit"/> never parks even though the
    /// responder's deferral seam is fully wired and the injected provider would happily stay pending
    /// forever. The absent bit routes through <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/>
    /// (never <see cref="CtapAuthenticatorSimulator.BeginDeferredTransceiveAsync"/>), whose own R1
    /// sync-path abstraction maps a never-granting <see cref="CtapUserPresenceDecision.Pending"/> answer
    /// to <see cref="WellKnownCtapStatusCodes.UserActionTimeout"/> — the same mapping
    /// <c>CtapUserPresenceTests.MakeCredentialPendingProviderReturnsUserActionTimeout</c> proves directly
    /// against the simulator, now proven synchronous end to end over the wire.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialWithoutSupportsGetResponseBitCompletesSynchronouslyAgainstADeferralConfiguredResponderOverRealWire()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CreateSimulator("wave2-capstone-p1gate", simulateUserPresence: AlwaysPending);
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateWithDeferralAsync(simulator, pool, cancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(pool);
        byte[] envelope = CtapWave2RequestEnvelopes.BuildMakeCredentialEnvelope(request);
        DisposeMakeCredentialRequest(request);

        using CommandApdu msg = CommandApdu.BuildCase4(
            WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapMsg.Code,
            0x00, 0x00, envelope, 0, useExtended: true, pool);
        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(harness.Device, msg.AsReadOnlyMemory(), pool, cancellationToken);
        using ApduResponse response = result.Value;

        Assert.IsTrue(response.StatusWord.IsSuccess);
        Assert.AreNotEqual(0x9100, response.StatusWord.Value);
        Assert.AreEqual(WellKnownCtapStatusCodes.UserActionTimeout, response.Data[0]);
    }


    /// <summary>
    /// getInfo's <c>algorithms</c> (<c>0x0A</c>) member appears over the real wire when a credential
    /// signing backend is present. <c>CtapAuthenticatorGetInfoFlowTests.RpClientDrivesSimulatorOverRealApduTransportAndDecodesGetInfo</c>
    /// already proves <c>maxCredentialCountInList</c>/<c>firmwareVersion</c> over the wire, plus the
    /// OMITTED shape of <c>algorithms</c> for a genuinely backendless simulator — it never exercises the
    /// POPULATED shape, since that test's simulator carries no <see cref="CtapCredentialSigningBackend"/>.
    /// This capstone closes that one remaining getInfo E2E gap; the deferral seam plays no role in
    /// <c>authenticatorGetInfo</c>, so the plain (non-deferring) harness composition is sufficient.
    /// </summary>
    [TestMethod]
    public async Task GetInfoAlgorithmsMemberIsPopulatedOverRealWireWhenACredentialSigningBackendIsPresent()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CreateSimulator("wave2-capstone-algorithms");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken);

        CtapGetInfoResponse response = await CtapAuthenticatorGetInfoClient.GetInfoAsync(
            harness.Transceive, CtapGetInfoResponseCborReader.Read, pool, cancellationToken);

        Assert.IsNotNull(response.Algorithms);
        Assert.HasCount(1, response.Algorithms!);
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, response.Algorithms![0].Alg);
        Assert.AreEqual(WellKnownPublicKeyCredentialTypes.PublicKey, response.Algorithms![0].Type);
    }


    /// <summary>
    /// <c>authenticatorConfig</c> (<c>0x0D</c>) is neither <c>mc</c> nor <c>ga</c> — the only two commands
    /// <see cref="CtapAuthenticatorSimulator.BeginDeferredTransceiveAsync"/>'s own switch marks deferrable
    /// — so it always resolves within the SAME <c>NFCCTAP_MSG</c> exchange even though the responder's
    /// deferral seam is fully wired and the client's P1 carries <see cref="WellKnownCtapCommandParameters.SupportsGetResponseP1Bit"/>.
    /// <c>CtapAuthenticatorConfigFlowTests</c> already exercises <see cref="CtapAuthenticatorConfigClient.AuthenticatorConfigAsync"/>
    /// extensively over the plain (non-deferring) harness; this capstone's narrower job is R11(f)'s own
    /// claim — that a deferral-CAPABLE responder never actually defers this command — which only a raw,
    /// single-exchange observation of the FIRST reply can prove, since <see cref="CtapNfcTransport"/>'s
    /// own hidden poll loop would make an eventual success indistinguishable from an immediate one.
    /// </summary>
    [TestMethod]
    public async Task AuthenticatorConfigCompletesSynchronouslyOverRealWireEvenAgainstADeferralConfiguredResponder()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CreateSimulator("wave2-capstone-config-sync");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateWithDeferralAsync(simulator, pool, cancellationToken);

        TaggedMemory<byte> configParameters = CtapAuthenticatorConfigRequestCborWriter.Write(
            new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv));
        byte[] configEnvelope = new byte[configParameters.Length + 1];
        configEnvelope[0] = WellKnownCtapCommands.AuthenticatorConfig;
        configParameters.Span.CopyTo(configEnvelope.AsSpan(1));

        using CommandApdu msg = CommandApdu.BuildCase4(
            WellKnownCtapCommandParameters.ClassByte, WellKnownCtapInstructionCodes.NfcCtapMsg.Code,
            WellKnownCtapCommandParameters.SupportsGetResponseP1Bit, 0x00, configEnvelope, 0, useExtended: true, pool);
        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(harness.Device, msg.AsReadOnlyMemory(), pool, cancellationToken);
        using ApduResponse response = result.Value;

        Assert.IsTrue(response.StatusWord.IsSuccess);
        Assert.AreNotEqual(0x9100, response.StatusWord.Value);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.Data[0]);
    }


    /// <summary>Always answers <see cref="CtapUserPresenceDecision.Pending"/> — a never-granting provider.</summary>
    private static ValueTask<CtapUserPresenceDecision> AlwaysPending(CancellationToken cancellationToken) =>
        ValueTask.FromResult(CtapUserPresenceDecision.Pending);


    /// <summary>
    /// Asserts <paramref name="expected"/> (from a fresh, always-granting synchronous run) and
    /// <paramref name="actual"/> (from a resumed deferred run against a simulator sharing the same
    /// <paramref name="aaguid"/>) agree on every DETERMINISTIC <c>authenticatorMakeCredential</c> response
    /// field. Mirrors <c>CtapUserPresenceTests.PollDeferredTransceiveResumesOnGrantedDecisionMatchingSynchronousResponseStructurally</c>'s
    /// own assertion set (R2's reworded structural-identity clause: literal byte-identity is unsatisfiable
    /// since mc mints a fresh per-run keypair the two independent runs cannot match).
    /// </summary>
    private static void AssertMakeCredentialResponsesAreStructurallyIdentical(
        CtapMakeCredentialResponse expected, CtapMakeCredentialResponse actual, Guid aaguid, MemoryPool<byte> pool)
    {
        Assert.AreEqual(expected.Fmt, actual.Fmt);
        Assert.AreEqual(expected.AttStmt.HasValue, actual.AttStmt.HasValue);

        using AuthenticatorData expectedAuthData = AuthenticatorDataReader.Read(expected.AuthData, CredentialPublicKeyCborReader.Read, pool);
        using AuthenticatorData actualAuthData = AuthenticatorDataReader.Read(actual.AuthData, CredentialPublicKeyCborReader.Read, pool);

        Assert.AreSequenceEqual(expectedAuthData.RpIdHash.AsReadOnlySpan().ToArray(), actualAuthData.RpIdHash.AsReadOnlySpan().ToArray());
        Assert.AreEqual(expectedAuthData.Flags.UserPresent, actualAuthData.Flags.UserPresent);
        Assert.AreEqual(expectedAuthData.Flags.UserVerified, actualAuthData.Flags.UserVerified);
        Assert.AreEqual(expectedAuthData.Flags.AttestedCredentialDataIncluded, actualAuthData.Flags.AttestedCredentialDataIncluded);
        Assert.AreEqual(expectedAuthData.Flags.ExtensionDataIncluded, actualAuthData.Flags.ExtensionDataIncluded);
        Assert.AreEqual(expectedAuthData.SignCount, actualAuthData.SignCount);

        AttestedCredentialData expectedAttested = expectedAuthData.AttestedCredentialData!;
        AttestedCredentialData actualAttested = actualAuthData.AttestedCredentialData!;

        Assert.AreEqual(aaguid, actualAttested.Aaguid);
        Assert.AreEqual(expectedAttested.Aaguid, actualAttested.Aaguid);
        Assert.AreEqual(expectedAttested.CredentialPublicKey.Kty, actualAttested.CredentialPublicKey.Kty);
        Assert.AreEqual(expectedAttested.CredentialPublicKey.Alg, actualAttested.CredentialPublicKey.Alg);
    }
}
