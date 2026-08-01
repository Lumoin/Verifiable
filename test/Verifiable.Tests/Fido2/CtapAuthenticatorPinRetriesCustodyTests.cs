using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Fido2.Ctap.Authenticator.Custody;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for the wavepin <see cref="CtapPinRetriesCustody"/> seam (contract R-1 through R-6): the seam
/// record's null-guarding, the CTAP-side wiring in <c>setPIN</c>/<c>changePIN</c>/<c>getPinToken</c>,
/// verify-before-token ordering, the demoted-cache mirror semantics, the R-5 status-priority rule, the
/// decrypt-failure penalize path, PIN provisioning/rotation, rehydration re-synchronization, and
/// <c>authenticatorReset</c>'s retirement call — all driven through <see cref="InMemoryCtapPinRetriesCustodyStore"/>,
/// a backend-neutral in-memory double (library-method oracle discipline), never the real TPM.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorPinRetriesCustodyTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Verify-before-token ordering (contract R-2): once the persistent tier is blocked, a <c>getPinToken</c>
    /// attempt with the CORRECT PIN still fails with <c>PIN_BLOCKED</c> and never issues a token — proving
    /// the custody verdict, not the local <c>FixedTimeEquals</c> compare (which would have matched, since
    /// the correct PIN is presented), is what decided the outcome. The double's own
    /// <see cref="InMemoryCtapPinRetriesCustodyStore.OperationLog"/> confirms <c>VerifyPinAttemptAsync</c>
    /// ran for this attempt.
    /// </summary>
    [TestMethod]
    public async Task BlockedVerdictRejectsEvenTheCorrectPinAndIssuesNoToken()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Guid aaguid = Guid.NewGuid();
        var stateStore = new DictionaryBackedCtapStateCustodyStore();
        var pinStore = new InMemoryCtapPinRetriesCustodyStore();

        using CtapAuthenticatorSimulator simulator = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
            "pin-custody-blocked-rejects-correct", stateStore.CreateBundle(), aaguid, pinStore.CreateBundle(), cancellationToken: TestContext.CancellationToken);
        await EstablishPinAsync(simulator, pool, "1234");

        pinStore.ForceBlocked();
        int operationsBeforeAttempt = pinStore.OperationLog.Count;

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);
        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: pinHashEnc);

        byte statusCode = await SendExpectingErrorAsync(simulator, request, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinBlocked, statusCode, "a blocked persistent tier must reject even the correct PIN.");
        Assert.AreEqual(0, await GetPinRetriesAsync(simulator, pool), "the mirror must report zero once blocked.");
        Assert.Contains("Verify", pinStore.OperationLog.Skip(operationsBeforeAttempt), "VerifyPinAttemptAsync must have been consulted for this attempt.");
    }


    /// <summary>
    /// Mirror semantics (contract R-4): <c>PinRetries</c> tracks <c>verdict.RetriesRemaining</c> exactly
    /// across a mismatch (decrement), a decrypt-failure penalty (decrement), and a subsequent success
    /// (reset to maximum) — never a locally computed decrement/reset once custody is composed.
    /// </summary>
    [TestMethod]
    public async Task PinRetriesMirrorTracksCustodyVerdictAcrossMismatchPenalizeAndSuccess()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Guid aaguid = Guid.NewGuid();
        var stateStore = new DictionaryBackedCtapStateCustodyStore();
        var pinStore = new InMemoryCtapPinRetriesCustodyStore();

        using CtapAuthenticatorSimulator simulator = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
            "pin-custody-mirror-tracks-verdict", stateStore.CreateBundle(), aaguid, pinStore.CreateBundle(), cancellationToken: TestContext.CancellationToken);
        await EstablishPinAsync(simulator, pool, "1234");
        Assert.AreEqual(8, await GetPinRetriesAsync(simulator, pool));

        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, await AttemptWrongCurrentPinAsync(simulator, pool));
        Assert.AreEqual(7, await GetPinRetriesAsync(simulator, pool), "a mismatch must mirror the custody verdict's RetriesRemaining.");

        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, await AttemptMalformedCurrentPinHashAsync(simulator, pool));
        Assert.AreEqual(6, await GetPinRetriesAsync(simulator, pool), "a decrypt-failure penalty must mirror the custody verdict's RetriesRemaining.");

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", TestContext.CancellationToken);
        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: pinHashEnc);
        await SendAsync(simulator, request, pool);

        Assert.AreEqual(8, await GetPinRetriesAsync(simulator, pool), "a success must mirror the custody verdict's reset-to-maximum RetriesRemaining.");
    }


    /// <summary>
    /// R-5 status priority: when the SAME attempt both exhausts the custody-backed persistent tier and
    /// completes the boot-scoped 3-consecutive-mismatch trilogy, the response is <c>PIN_BLOCKED</c> —
    /// never <c>PIN_AUTH_BLOCKED</c> — and the boot latch (<c>powerCycleState</c>) is NOT set, mirroring
    /// the shipped <c>ChangePinMismatchThatSimultaneouslyExhaustsRetriesAndCompletesTheTrilogyReturnsPinBlocked</c>
    /// ordering, now sourced from <see cref="CtapPinAttemptVerdict.IsBlocked"/> rather than a local decrement.
    /// </summary>
    [TestMethod]
    public async Task BlockedVerdictBeatsTheBootLatchOnTheSameAttempt()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Guid aaguid = Guid.NewGuid();
        var stateStore = new DictionaryBackedCtapStateCustodyStore();
        var pinStore = new InMemoryCtapPinRetriesCustodyStore();

        using CtapAuthenticatorSimulator simulator = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
            "pin-custody-blocked-beats-latch", stateStore.CreateBundle(), aaguid, pinStore.CreateBundle(), cancellationToken: TestContext.CancellationToken);
        await EstablishPinAsync(simulator, pool, "1234");

        //Two isolated mismatches (mismatches=1,2; never latching) before fast-forwarding the persistent
        //tier directly to one attempt away from exhaustion — modeling a custody tier whose count already
        //reflects attempts from elsewhere (a different session against the same NV Index).
        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, await AttemptWrongCurrentPinAsync(simulator, pool));
        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, await AttemptWrongCurrentPinAsync(simulator, pool));
        Assert.IsFalse(await GetPowerCycleStateAsync(simulator, pool));

        //Fast-forwards the custody-side truth to one attempt away from exhaustion WITHOUT touching the
        //simulator's own mirror (which only re-syncs at CreateWithCustodyAsync/on the next verdict) — the
        //mirror still reads 6 here; the THIRD attempt below is what actually consults the custody bundle
        //and folds its fresh verdict back.
        pinStore.SeedPinCount(InMemoryCtapPinRetriesCustodyStore.PinLimit - 1);

        //The THIRD consecutive mismatch: completes the boot-scoped trilogy AND exhausts the persistent
        //tier in the same attempt.
        byte boundaryStatus = await AttemptWrongCurrentPinAsync(simulator, pool);

        Assert.AreEqual(
            WellKnownCtapStatusCodes.PinBlocked, boundaryStatus,
            "a custody verdict of IsBlocked must win over the boot-scoped 3-consecutive-mismatch latch.");
        Assert.AreEqual(0, await GetPinRetriesAsync(simulator, pool));
        Assert.IsFalse(
            await GetPowerCycleStateAsync(simulator, pool),
            "PinBlocked is the permanent block; it must not also latch the power-cycle-recoverable requirement.");
    }


    /// <summary>
    /// A <c>pinHashEnc</c> decrypt failure calls <see cref="CtapPinRetriesCustody.PenalizeAttemptAsync"/> —
    /// never <see cref="CtapPinRetriesCustody.VerifyPinAttemptAsync"/>, since no candidate hash exists to
    /// present — and applies the identical mismatch semantics a decoded mismatch would (CTAP 2.3 lines
    /// 5671/5883/5985).
    /// </summary>
    [TestMethod]
    public async Task DecryptFailureCallsPenalizeNotVerifyAndAppliesMismatchSemantics()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Guid aaguid = Guid.NewGuid();
        var stateStore = new DictionaryBackedCtapStateCustodyStore();
        var pinStore = new InMemoryCtapPinRetriesCustodyStore();

        using CtapAuthenticatorSimulator simulator = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
            "pin-custody-decrypt-failure-penalizes", stateStore.CreateBundle(), aaguid, pinStore.CreateBundle(), cancellationToken: TestContext.CancellationToken);
        await EstablishPinAsync(simulator, pool, "1234");

        int operationsBeforeAttempt = pinStore.OperationLog.Count;
        byte statusCode = await AttemptMalformedCurrentPinHashAsync(simulator, pool);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, statusCode);
        Assert.AreEqual(7, await GetPinRetriesAsync(simulator, pool), "a decrypt failure must decrement the custody-backed tier exactly like a mismatch.");

        List<string> operationsDuringAttempt = [.. pinStore.OperationLog.Skip(operationsBeforeAttempt)];
        Assert.Contains("Penalize", operationsDuringAttempt, "a decrypt failure must call PenalizeAttemptAsync.");
        Assert.DoesNotContain("Verify", operationsDuringAttempt, "a decrypt failure must never call VerifyPinAttemptAsync — no candidate hash exists to present.");
    }


    /// <summary>
    /// <c>setPIN</c> provisions the persistent tier once, and a successful <c>changePIN</c> provisions it
    /// again with the NEW PIN's hash — the double's own recorded <c>pinHash</c> bytes prove the ROTATION
    /// (contract R-2: the persistent tier's own authorization secret moves at provision time).
    /// </summary>
    [TestMethod]
    public async Task ProvisionRunsOnSetPinEstablishmentAndOnChangePinSuccessRotatingTheHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Guid aaguid = Guid.NewGuid();
        var stateStore = new DictionaryBackedCtapStateCustodyStore();
        var pinStore = new InMemoryCtapPinRetriesCustodyStore();

        using CtapAuthenticatorSimulator simulator = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
            "pin-custody-provision-rotates", stateStore.CreateBundle(), aaguid, pinStore.CreateBundle(), cancellationToken: TestContext.CancellationToken);

        await EstablishPinAsync(simulator, pool, "1234");
        Assert.HasCount(1, pinStore.ProvisionedPinHashes, "setPIN establishment must provision the persistent tier exactly once.");
        AssertHashEquals("1234", pinStore.ProvisionedPinHashes[0], pool);

        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam) =
            await session.BuildChangePinMessagesAsync("5678", "1234", TestContext.CancellationToken);
        await SendAsync(simulator, BuildChangePinRequest(session, newPinEnc, pinHashEnc, pinUvAuthParam), pool);

        Assert.HasCount(2, pinStore.ProvisionedPinHashes, "a successful changePIN must provision the persistent tier again.");
        AssertHashEquals("5678", pinStore.ProvisionedPinHashes[1], pool);
        Assert.IsFalse(
            pinStore.ProvisionedPinHashes[0].AsSpan().SequenceEqual(pinStore.ProvisionedPinHashes[1]),
            "the two provisioned hashes must differ — the persistent tier's authorization secret must rotate.");
    }


    /// <summary>
    /// Rehydration re-sync (contract R-4): <see cref="CtapAuthenticatorSimulator.CreateWithCustodyAsync"/>
    /// overrides whatever a rehydrated whole-snapshot's own <c>PinRetries</c> field says with the composed
    /// <see cref="CtapPinRetriesCustody.ReadRetriesAsync"/>'s CURRENT, authoritative value — closing the
    /// stale-snapshot rollback hole a bare whole-snapshot mirror alone cannot.
    /// </summary>
    [TestMethod]
    public async Task RehydrationOverridesAStaleSnapshotsPinRetriesWithTheCustodyAuthoritativeValue()
    {
        const string RunId = "pin-custody-rehydration-resync";
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Guid aaguid = Guid.NewGuid();
        var stateStore = new DictionaryBackedCtapStateCustodyStore();
        var pinStore = new InMemoryCtapPinRetriesCustodyStore();

        using(CtapAuthenticatorSimulator first = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
            RunId, stateStore.CreateBundle(), aaguid, pinStore.CreateBundle(), cancellationToken: TestContext.CancellationToken))
        {
            await EstablishPinAsync(first, pool, "1234");
            Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, await AttemptWrongCurrentPinAsync(first, pool));
            Assert.AreEqual(7, await GetPinRetriesAsync(first, pool));
        }

        //Simulates additional attempts spent against the SAME persistent tier from elsewhere (a different
        //session, or the real TPM Index observing attempts this whole-snapshot never learned of): the
        //custody-side truth moves to 3 remaining, while the persisted whole-snapshot still says 7 (stale).
        pinStore.SeedPinCount(InMemoryCtapPinRetriesCustodyStore.PinLimit - 3);

        using CtapAuthenticatorSimulator second = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
            RunId, stateStore.CreateBundle(), aaguid, pinStore.CreateBundle(), cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(
            3, await GetPinRetriesAsync(second, pool),
            "rehydration must report the custody-authoritative retry budget, never the stale snapshot's own PinRetries field.");
    }


    /// <summary>
    /// <c>authenticatorReset</c> retires the persistent tier (contract R-3/R-9, wavepin), in the same
    /// post-command retirement slot/timing wavenv's own signature-counter retirement uses.
    /// </summary>
    [TestMethod]
    public async Task AuthenticatorResetRetiresThePersistentTier()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Guid aaguid = Guid.NewGuid();
        var stateStore = new DictionaryBackedCtapStateCustodyStore();
        var pinStore = new InMemoryCtapPinRetriesCustodyStore();

        using CtapAuthenticatorSimulator simulator = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
            "pin-custody-reset-retires", stateStore.CreateBundle(), aaguid, pinStore.CreateBundle(), cancellationToken: TestContext.CancellationToken);
        await EstablishPinAsync(simulator, pool, "1234");
        Assert.DoesNotContain("Retire", pinStore.OperationLog);

        using IMemoryOwner<byte> requestOwner = pool.Rent(1);
        requestOwner.Memory.Span[0] = WellKnownCtapCommands.Reset;
        using PooledMemory response = await simulator.TransceiveAsync(requestOwner.Memory[..1], pool, TestContext.CancellationToken);

        Assert.IsTrue(WellKnownCtapStatusCodes.IsOk(response.AsReadOnlySpan()[0]), "authenticatorReset must succeed.");
        Assert.Contains("Retire", pinStore.OperationLog, "authenticatorReset must call RetirePinAsync.");
    }


    /// <summary>
    /// Wavepin review fix F-4: <c>changePIN</c>'s <c>forcePINChange</c> same-PIN-under-force comparison
    /// (CTAP 2.3 §6.5.5.6, line 5700) must compare the proposed new PIN's hash against the just-VERIFIED,
    /// custody-confirmed current hash — never the possibly-stale <c>CurrentStoredPin</c> a rehydrated
    /// snapshot captured before a PIN rotation elsewhere. Instance 1 establishes "1234", forces
    /// <c>forcePINChange</c>, captures the snapshot AT THAT POINT (still "1234", still forced), then rotates
    /// to "5678" (which also clears <c>forcePINChange</c> in instance 1 — exactly why the capture had to
    /// happen first). Instance 2 rehydrates from the stale, pre-rotation snapshot (<c>CurrentStoredPin</c>
    /// still "1234"'s hash, <c>forcePINChange</c> still <see langword="true"/>) against the SAME, shared
    /// persistent-tier custody, whose own authoritative PIN is now "5678". A <c>changePIN</c> presenting the
    /// REAL current PIN ("5678") and a new PIN ("1234") that happens to equal the STALE local hash — but is
    /// NOT the actual current PIN — must SUCCEED: the stale local hash must never be mistaken for the
    /// confirmed current one.
    /// </summary>
    [TestMethod]
    public async Task ForcePinChangeSameAsCurrentCheckUsesTheConfirmedCurrentHashNotAStaleLocalSnapshot()
    {
        const string RunId = "pin-custody-f4-stale-forcepinchange";
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Guid aaguid = Guid.NewGuid();
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        var stateStore = new DictionaryBackedCtapStateCustodyStore();
        var pinStore = new InMemoryCtapPinRetriesCustodyStore();

        byte[] staleSnapshotBytes;
        CtapAuthenticatorSimulator simulator1 = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
            RunId, stateStore.CreateBundle(), aaguid, pinStore.CreateBundle(), cancellationToken: TestContext.CancellationToken);
        try
        {
            await EstablishPinAsync(simulator1, pool, "1234");

            byte[] token = await CtapWaveConfigFixtures.IssueTokenAsync(
                simulator1, pool, protocolId, "1234", WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

            byte[] forceSubCommandParams = CtapWaveConfigFixtures.BuildSubCommandParams(
                newMinPinLength: null, minPinLengthRpIds: null, forceChangePin: true, pinComplexityPolicy: null);
            byte[] forceMessage = CtapWaveConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength, forceSubCommandParams);
            byte[] forceParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, forceMessage, pool, TestContext.CancellationToken);
            var forceRequest = new CtapAuthenticatorConfigRequest(
                SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength, ForceChangePin: true,
                PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: forceParam);
            using PooledMemory forceResponse = await CtapWaveConfigFixtures.SendAuthenticatorConfigAsync(simulator1, forceRequest, pool, TestContext.CancellationToken);
            Assert.IsTrue(WellKnownCtapStatusCodes.IsOk(forceResponse.AsReadOnlySpan()[0]), "setMinPINLength(forceChangePin:true) must succeed.");

            //Captured HERE: CurrentStoredPin = hash("1234"), IsForcePinChangeRequired = true.
            staleSnapshotBytes = stateStore.GetSnapshotBytesCopy(RunId);

            //Rotates the shared persistent tier's own authoritative PIN to "5678" — a successful changePIN
            //also clears forcePINChange in THIS instance (and persists that), which is exactly why the
            //snapshot capture above had to happen before this call.
            await ChangePinExpectingSuccessAsync(simulator1, pool, currentPin: "1234", newPin: "5678");
        }
        finally
        {
            simulator1.Dispose();
        }

        //Replays the stale, pre-rotation snapshot: local CurrentStoredPin still says "1234"'s hash, and
        //forcePINChange still reads true — but the SHARED pinStore's own authoritative PIN is now "5678".
        stateStore.ReplaceSnapshotBytes(RunId, staleSnapshotBytes);

        using CtapAuthenticatorSimulator simulator2 = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
            RunId, stateStore.CreateBundle(), aaguid, pinStore.CreateBundle(), cancellationToken: TestContext.CancellationToken);

        //changePIN(current="5678" [the REAL current PIN], new="1234" [equals only the STALE local hash]):
        //the custody-verified current-PIN check matches "5678"; forcePINChange's own same-PIN check must
        //compare "1234" against the CONFIRMED current hash (of "5678"), never the stale local
        //CurrentStoredPin (of "1234") — the pre-fix code would wrongly reject this with PinPolicyViolation.
        await ChangePinExpectingSuccessAsync(simulator2, pool, currentPin: "5678", newPin: "1234");
    }


    /// <summary>Establishes a PIN on <paramref name="simulator"/> via a fresh protocol-two session.</summary>
    private static async Task EstablishPinAsync(CtapAuthenticatorSimulator simulator, BaseMemoryPool pool, string pin)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, CancellationToken.None);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync(pin, CancellationToken.None);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, CancellationToken.None);
    }


    /// <summary>Attempts a <c>changePIN</c> with a wrong current PIN, returning the exact status code.</summary>
    private async Task<byte> AttemptWrongCurrentPinAsync(CtapAuthenticatorSimulator simulator, BaseMemoryPool pool)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam) =
            await session.BuildChangePinMessagesAsync("5678", "0000", TestContext.CancellationToken);

        return await SendExpectingErrorAsync(simulator, BuildChangePinRequest(session, newPinEnc, pinHashEnc, pinUvAuthParam), pool);
    }


    /// <summary>Attempts a <c>changePIN</c> expected to SUCCEED, from <paramref name="currentPin"/> to <paramref name="newPin"/>.</summary>
    private async Task ChangePinExpectingSuccessAsync(CtapAuthenticatorSimulator simulator, BaseMemoryPool pool, string currentPin, string newPin)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam) =
            await session.BuildChangePinMessagesAsync(newPin, currentPin, TestContext.CancellationToken);

        _ = await SendAsync(simulator, BuildChangePinRequest(session, newPinEnc, pinHashEnc, pinUvAuthParam), pool);
    }


    /// <summary>Attempts a <c>changePIN</c> whose <c>pinHashEnc</c> fails to DECRYPT, returning the exact status code.</summary>
    private async Task<byte> AttemptMalformedCurrentPinHashAsync(CtapAuthenticatorSimulator simulator, BaseMemoryPool pool)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        byte[] malformedPinHashEnc = CtapWave5bPinCryptoFixtures.BuildMalformedPinHashEnc();
        (byte[] newPinEnc, byte[] pinUvAuthParam) =
            await session.BuildChangePinMessagesWithExplicitPinHashEncAsync("5678", malformedPinHashEnc, TestContext.CancellationToken);

        return await SendExpectingErrorAsync(simulator, BuildChangePinRequest(session, newPinEnc, malformedPinHashEnc, pinUvAuthParam), pool);
    }


    /// <summary>Builds a <c>changePIN</c> request from the session and encrypted message members.</summary>
    private static CtapClientPinRequest BuildChangePinRequest(
        CtapWave5bPlatformPinSession session, byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam) =>
        new(
            SubCommand: WellKnownCtapClientPinSubCommands.ChangePin,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose,
            PinUvAuthParam: pinUvAuthParam,
            NewPinEnc: newPinEnc,
            PinHashEnc: pinHashEnc);


    /// <summary>Reads the current <c>pinRetries</c> counter via <c>getPINRetries</c>.</summary>
    private async Task<int> GetPinRetriesAsync(CtapAuthenticatorSimulator simulator, BaseMemoryPool pool)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetPinRetries);
        CtapClientPinResponse response = await SendAsync(simulator, request, pool);

        return response.PinRetries!.Value;
    }


    /// <summary>Reads the current <c>powerCycleState</c> via <c>getPINRetries</c>.</summary>
    private async Task<bool> GetPowerCycleStateAsync(CtapAuthenticatorSimulator simulator, BaseMemoryPool pool)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetPinRetries);
        CtapClientPinResponse response = await SendAsync(simulator, request, pool);

        return response.PowerCycleState!.Value;
    }


    /// <summary>
    /// Asserts <paramref name="actualTruncatedHash"/> equals <paramref name="pin"/>'s stored-hash form
    /// (<c>LEFT(SHA-256(pin), 16)</c>, CTAP 2.3 lines 5592/5710), computed independently through the
    /// SAME registered digest seam <c>CtapAuthenticatorSimulator</c>'s own <c>ComputeStoredPinHash</c>
    /// uses — never a hand-rolled framework hash call (house rule: hash via the registered digest).
    /// </summary>
    private static void AssertHashEquals(string pin, byte[] actualTruncatedHash, BaseMemoryPool pool)
    {
        using DigestValue fullDigest = CryptographicKeyEvents.ComputeDigest(Encoding.UTF8.GetBytes(pin), 32, CryptoTags.Sha256Digest, pool);

        Assert.IsTrue(
            fullDigest.AsReadOnlySpan()[..16].SequenceEqual(actualTruncatedHash),
            $"the provisioned hash must equal LEFT(SHA-256('{pin}'), 16).");
    }


    /// <summary>Sends an <c>authenticatorClientPIN</c> request expected to succeed and decodes its response.</summary>
    private Task<CtapClientPinResponse> SendAsync(CtapAuthenticatorSimulator simulator, CtapClientPinRequest request, BaseMemoryPool pool) =>
        CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, TestContext.CancellationToken).AsTask();


    /// <summary>Sends an <c>authenticatorClientPIN</c> request expected to fail and returns the exact status code.</summary>
    private async Task<byte> SendExpectingErrorAsync(CtapAuthenticatorSimulator simulator, CtapClientPinRequest request, BaseMemoryPool pool)
    {
        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(() => SendAsync(simulator, request, pool));

        return exception.StatusCode;
    }
}
