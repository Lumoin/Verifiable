using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Fido2.Ctap.Authenticator.Custody;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.Tpm;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Pin;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The wavepin capstones for NV-Index-backed persistent PIN-retry custody
/// (<see cref="CtapPinRetriesCustody"/>/<see cref="TpmNvPinRetriesCustody"/>, contract R-11): mirrors
/// <see cref="CtapAuthenticatorNvSignCounterCapstoneTests"/>'s own firewalled discipline exactly — ONE
/// in-house <see cref="TpmSimulator"/> instance plays the durable chip and OUTLIVES every
/// <see cref="CtapAuthenticatorSimulator"/> instance built against it, and every assertion reads a
/// wire-visible fact over the real, unmodified APDU transport (<see cref="CtapWave2TransportHarness"/>) —
/// never internal simulator or TPM state.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorNvPinRetriesCapstoneTests
{
    /// <summary>The persistent tier's fixed attempt ceiling this class drives to exhaustion — CTAP 2.3 §6.5.2.3's <c>MaxPinRetries</c>.</summary>
    private const int PinLimit = 8;

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Capstone 1 (contract R-11(1)): a stale WHOLE-SNAPSHOT cannot restore a spent NV-backed retry budget.
    /// Two mismatches on instance 1 spend the budget from 8 to 6; an EARLY sealed-snapshot blob (captured
    /// right after establishment, whose own cached <c>PinRetries</c> reads 8) is restored over the LATEST
    /// one before instance 1 dies. Instance 2 rehydrates from that stale blob, yet <c>getPINRetries</c> on
    /// the wire reports the TPM-derived 6, never the stale cache's own 8 — the exact move
    /// <see cref="CtapAuthenticatorSimulator.CreateWithCustodyAsync"/>'s rehydration re-sync (contract R-4)
    /// closes. A further mismatch on instance 2 continues counting down from the TPM-authoritative value,
    /// proving continuity rather than a one-off coincidence.
    /// </summary>
    [TestMethod]
    public async Task StaleWholeSnapshotReplayCannotRestoreASpentPinRetryBudgetOverRealApduTransport()
    {
        const string RunId = "wavepin-flagship";
        const uint PinIndexHandle = 0x0100_0800;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        Guid aaguid = Guid.NewGuid();
        byte[] sealAuth = "wavepin-flagship-seal-auth"u8.ToArray();

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("wavepin-flagship-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            var store = new DictionaryBackedTpmSealedSnapshotBlobStore();
            CtapPinRetriesCustody pinCustody = TpmNvPinRetriesCustody.Create(tpm, ReadOnlyMemory<byte>.Empty, PinIndexHandle);

            byte[] earlyBlob;

            CtapAuthenticatorSimulator simulator1 = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, store), aaguid, pinRetriesCustody: pinCustody, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            using(CtapWave2TransportHarness harness1 = await CtapWave2TransportHarness.CreateAsync(simulator1, pool, cancellationToken).ConfigureAwait(false))
            {
                await EstablishPinAsync(harness1.Transceive, pool, protocolId, "1234", cancellationToken).ConfigureAwait(false);

                //Captured right after establishment - the whole-snapshot's own cached PinRetries reads 8 here.
                earlyBlob = store.GetStoredBytesCopy(RunId);

                byte firstStatus = await ChangePinExpectingErrorAsync(harness1.Transceive, pool, protocolId, currentPin: "0000", newPin: "5678", cancellationToken)
                    .ConfigureAwait(false);
                Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, firstStatus);
                Assert.AreEqual(7, await GetPinRetriesAsync(harness1.Transceive, pool, cancellationToken).ConfigureAwait(false));

                byte secondStatus = await ChangePinExpectingErrorAsync(harness1.Transceive, pool, protocolId, currentPin: "0000", newPin: "5678", cancellationToken)
                    .ConfigureAwait(false);
                Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, secondStatus);
                Assert.AreEqual(6, await GetPinRetriesAsync(harness1.Transceive, pool, cancellationToken).ConfigureAwait(false));

                //The stale restore, still on instance 1's own store - instance 2 will load exactly this.
                store.ReplaceStoredBytes(RunId, earlyBlob);
            }

            simulator1.Dispose();

            CtapAuthenticatorSimulator simulator2 = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, store), aaguid, pinRetriesCustody: pinCustody, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            using(CtapWave2TransportHarness harness2 = await CtapWave2TransportHarness.CreateAsync(simulator2, pool, cancellationToken).ConfigureAwait(false))
            {
                Assert.AreEqual(
                    6, await GetPinRetriesAsync(harness2.Transceive, pool, cancellationToken).ConfigureAwait(false),
                    "rehydrating from a STALE whole-snapshot blob (whose own PinRetries field says 8) must report the TPM-derived value (6), never the stale cache.");

                byte thirdStatus = await ChangePinExpectingErrorAsync(harness2.Transceive, pool, protocolId, currentPin: "0000", newPin: "5678", cancellationToken)
                    .ConfigureAwait(false);
                Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, thirdStatus);
                Assert.AreEqual(
                    5, await GetPinRetriesAsync(harness2.Transceive, pool, cancellationToken).ConfigureAwait(false),
                    "a further mismatch on instance 2 must continue counting down from the TPM-authoritative value, never from the stale snapshot's own 8.");
            }

            simulator2.Dispose();
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, cancellationToken).ConfigureAwait(false);
            tpm.Dispose();
        }
    }


    /// <summary>
    /// Capstone 2 (contract R-11(2)): a stale snapshot cannot resurrect a SUPERSEDED PIN. Instance 1
    /// establishes "1234", then successfully changes to "5678" (rotating the TPM Index's own authValue via
    /// <see cref="CtapPinRetriesCustody.ProvisionPinAsync"/>). Instance 2 rehydrates from a snapshot
    /// captured BEFORE that change - its own <c>CurrentStoredPin</c> field still matches "1234"'s hash, but
    /// with custody composed the local compare never runs (contract R-2): the OLD PIN fails and burns a
    /// retry, while the NEW PIN ("5678") succeeds against the surviving, already-rotated TPM Index.
    /// </summary>
    [TestMethod]
    public async Task StaleSnapshotCannotResurrectASupersededPinOverRealApduTransport()
    {
        const string RunId = "wavepin-resurrection";
        const uint PinIndexHandle = 0x0100_0810;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        Guid aaguid = Guid.NewGuid();
        byte[] sealAuth = "wavepin-resurrection-seal-auth"u8.ToArray();

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("wavepin-resurrection-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            var store = new DictionaryBackedTpmSealedSnapshotBlobStore();
            CtapPinRetriesCustody pinCustody = TpmNvPinRetriesCustody.Create(tpm, ReadOnlyMemory<byte>.Empty, PinIndexHandle);

            byte[] preChangeBlob;

            CtapAuthenticatorSimulator simulator1 = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, store), aaguid, pinRetriesCustody: pinCustody, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            using(CtapWave2TransportHarness harness1 = await CtapWave2TransportHarness.CreateAsync(simulator1, pool, cancellationToken).ConfigureAwait(false))
            {
                await EstablishPinAsync(harness1.Transceive, pool, protocolId, "1234", cancellationToken).ConfigureAwait(false);

                //Captured BEFORE the change below - the stale restore a later instance will replay.
                preChangeBlob = store.GetStoredBytesCopy(RunId);

                await ChangePinExpectingSuccessAsync(harness1.Transceive, pool, protocolId, currentPin: "1234", newPin: "5678", cancellationToken).ConfigureAwait(false);

                store.ReplaceStoredBytes(RunId, preChangeBlob);
            }

            simulator1.Dispose();

            CtapAuthenticatorSimulator simulator2 = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, store), aaguid, pinRetriesCustody: pinCustody, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            using(CtapWave2TransportHarness harness2 = await CtapWave2TransportHarness.CreateAsync(simulator2, pool, cancellationToken).ConfigureAwait(false))
            {
                byte oldPinStatus = await ChangePinExpectingErrorAsync(harness2.Transceive, pool, protocolId, currentPin: "1234", newPin: "9999", cancellationToken)
                    .ConfigureAwait(false);
                Assert.AreEqual(
                    WellKnownCtapStatusCodes.PinInvalid, oldPinStatus,
                    "a stale snapshot's own superseded PIN hash must not resurrect the old PIN once the NV Index's own authValue has rotated.");
                Assert.AreEqual(
                    7, await GetPinRetriesAsync(harness2.Transceive, pool, cancellationToken).ConfigureAwait(false),
                    "the rejected OLD-PIN attempt must still burn a retry.");

                await ChangePinExpectingSuccessAsync(harness2.Transceive, pool, protocolId, currentPin: "5678", newPin: "9999", cancellationToken).ConfigureAwait(false);
            }

            simulator2.Dispose();
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, cancellationToken).ConfigureAwait(false);
            tpm.Dispose();
        }
    }


    /// <summary>
    /// Capstone 3 (contract R-11(3)): full exhaustion. Eight mismatches, power-cycling after each one so
    /// only the persistent tier's own retries-exhaustion trips (never the boot-scoped 3-consecutive-mismatch
    /// latch), drive the TPM Index to <c>pinLimit</c>; the 8th mismatch itself reports <c>PIN_BLOCKED</c>,
    /// and even the CORRECT PIN is refused afterward (the Index's own <c>TPM_RC_AUTH_UNAVAILABLE</c>
    /// pre-gate, never compared). The blocked state survives death and rehydration on a second instance;
    /// <c>authenticatorReset</c> followed by a fresh <c>setPIN</c> is the sole recovery (CTAP 2.3 §6.6).
    /// </summary>
    [TestMethod]
    public async Task FullExhaustionBlocksTheCorrectPinSurvivesRehydrationAndRecoversAfterResetOverRealApduTransport()
    {
        const string RunId = "wavepin-exhaustion";
        const uint PinIndexHandle = 0x0100_0820;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        Guid aaguid = Guid.NewGuid();
        byte[] sealAuth = "wavepin-exhaustion-seal-auth"u8.ToArray();

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("wavepin-exhaustion-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            var store = new DictionaryBackedTpmSealedSnapshotBlobStore();
            CtapPinRetriesCustody pinCustody = TpmNvPinRetriesCustody.Create(tpm, ReadOnlyMemory<byte>.Empty, PinIndexHandle);

            CtapAuthenticatorSimulator simulator1 = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, store), aaguid, pinRetriesCustody: pinCustody, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            using(CtapWave2TransportHarness harness1 = await CtapWave2TransportHarness.CreateAsync(simulator1, pool, cancellationToken).ConfigureAwait(false))
            {
                await EstablishPinAsync(harness1.Transceive, pool, protocolId, "1234", cancellationToken).ConfigureAwait(false);

                byte lastStatus = 0;
                for(int attempt = 1; attempt <= PinLimit; attempt++)
                {
                    lastStatus = await ChangePinExpectingErrorAsync(harness1.Transceive, pool, protocolId, currentPin: "0000", newPin: "5678", cancellationToken)
                        .ConfigureAwait(false);
                    simulator1.PowerCycle();
                }

                Assert.AreEqual(WellKnownCtapStatusCodes.PinBlocked, lastStatus, "the 8th mismatch must exhaust the persistent tier and report PIN_BLOCKED.");
                Assert.AreEqual(0, await GetPinRetriesAsync(harness1.Transceive, pool, cancellationToken).ConfigureAwait(false));

                byte correctPinStatusWhileBlocked = await ChangePinExpectingErrorAsync(
                    harness1.Transceive, pool, protocolId, currentPin: "1234", newPin: "5678", cancellationToken).ConfigureAwait(false);
                Assert.AreEqual(WellKnownCtapStatusCodes.PinBlocked, correctPinStatusWhileBlocked, "PIN_BLOCKED must reject even the correct PIN.");
            }

            simulator1.Dispose();

            CtapAuthenticatorSimulator simulator2 = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, store), aaguid, pinRetriesCustody: pinCustody, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            using(CtapWave2TransportHarness harness2 = await CtapWave2TransportHarness.CreateAsync(simulator2, pool, cancellationToken).ConfigureAwait(false))
            {
                Assert.AreEqual(
                    0, await GetPinRetriesAsync(harness2.Transceive, pool, cancellationToken).ConfigureAwait(false),
                    "the blocked state must survive death and rehydration.");
                byte correctPinStatusAfterRehydrate = await ChangePinExpectingErrorAsync(
                    harness2.Transceive, pool, protocolId, currentPin: "1234", newPin: "5678", cancellationToken).ConfigureAwait(false);
                Assert.AreEqual(WellKnownCtapStatusCodes.PinBlocked, correctPinStatusAfterRehydrate);

                using PooledMemory resetResponse = await SendResetAsync(harness2.Transceive, pool, cancellationToken).ConfigureAwait(false);
                Assert.IsTrue(WellKnownCtapStatusCodes.IsOk(resetResponse.AsReadOnlySpan()[0]), "authenticatorReset must succeed.");

                await EstablishPinAsync(harness2.Transceive, pool, protocolId, "1111", cancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    8, await GetPinRetriesAsync(harness2.Transceive, pool, cancellationToken).ConfigureAwait(false),
                    "a fresh setPIN after authenticatorReset must recover a full retry budget.");

                await GetPinTokenExpectingSuccessAsync(harness2.Transceive, pool, protocolId, "1111", cancellationToken).ConfigureAwait(false);
            }

            simulator2.Dispose();
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, cancellationToken).ConfigureAwait(false);
            tpm.Dispose();
        }
    }


    /// <summary>
    /// Capstone 4 (contract R-11(4)): the boot-tier/persistent-tier split. Three CONSECUTIVE mismatches
    /// latch the boot-scoped <c>PIN_AUTH_BLOCKED</c> (CTAP 2.3 lines 5680-5683) - the third attempt still
    /// burns a TPM-backed retry even though its REPORTED status is the latch, not <c>PIN_INVALID</c>.
    /// <see cref="CtapAuthenticatorSimulator.PowerCycle"/> clears the latch, but the TPM-backed remaining
    /// count on the wire is UNCHANGED by it (contract R-1: the persistent tier is TPM-authoritative and
    /// boot-tier-only operations never touch it) - a further mismatch afterward reports the ordinary
    /// <c>PIN_INVALID</c> again and continues counting down from where the persistent tier actually was.
    /// </summary>
    [TestMethod]
    public async Task ThreeConsecutiveMismatchesLatchButPowerCycleLeavesTpmBackedRemainingUnchangedOverRealApduTransport()
    {
        const string RunId = "wavepin-boot-latch";
        const uint PinIndexHandle = 0x0100_0830;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        Guid aaguid = Guid.NewGuid();
        byte[] sealAuth = "wavepin-boot-latch-seal-auth"u8.ToArray();

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("wavepin-boot-latch-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            var store = new DictionaryBackedTpmSealedSnapshotBlobStore();
            CtapPinRetriesCustody pinCustody = TpmNvPinRetriesCustody.Create(tpm, ReadOnlyMemory<byte>.Empty, PinIndexHandle);

            CtapAuthenticatorSimulator simulator = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, store), aaguid, pinRetriesCustody: pinCustody, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            using(CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false))
            {
                await EstablishPinAsync(harness.Transceive, pool, protocolId, "1234", cancellationToken).ConfigureAwait(false);

                byte firstStatus = await ChangePinExpectingErrorAsync(harness.Transceive, pool, protocolId, currentPin: "0000", newPin: "5678", cancellationToken)
                    .ConfigureAwait(false);
                Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, firstStatus);
                Assert.AreEqual(7, await GetPinRetriesAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false));

                byte secondStatus = await ChangePinExpectingErrorAsync(harness.Transceive, pool, protocolId, currentPin: "0000", newPin: "5678", cancellationToken)
                    .ConfigureAwait(false);
                Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, secondStatus);
                Assert.AreEqual(6, await GetPinRetriesAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false));
                Assert.IsFalse(await GetPowerCycleStateAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false));

                byte thirdStatus = await ChangePinExpectingErrorAsync(harness.Transceive, pool, protocolId, currentPin: "0000", newPin: "5678", cancellationToken)
                    .ConfigureAwait(false);
                Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthBlocked, thirdStatus, "the third consecutive mismatch must latch the boot-scoped PIN_AUTH_BLOCKED.");
                Assert.AreEqual(
                    5, await GetPinRetriesAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false),
                    "the third consecutive mismatch must still burn a TPM-backed retry even though the REPORTED status is the boot latch, not PIN_INVALID.");
                Assert.IsTrue(await GetPowerCycleStateAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false));

                simulator.PowerCycle();

                Assert.IsFalse(
                    await GetPowerCycleStateAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false), "PowerCycle must clear the boot-scoped latch.");
                Assert.AreEqual(
                    5, await GetPinRetriesAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false),
                    "PowerCycle must leave the TPM-backed persistent tier's remaining count UNCHANGED - it is a boot-tier-only operation (contract R-1).");

                byte fourthStatus = await ChangePinExpectingErrorAsync(harness.Transceive, pool, protocolId, currentPin: "0000", newPin: "5678", cancellationToken)
                    .ConfigureAwait(false);
                Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, fourthStatus, "with the latch cleared, a further mismatch reports the ordinary PIN_INVALID again.");
                Assert.AreEqual(
                    4, await GetPinRetriesAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false),
                    "the persistent tier must continue counting down from the TPM-authoritative value the PowerCycle left unchanged, never from a reset one.");
            }

            simulator.Dispose();
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, cancellationToken).ConfigureAwait(false);
            tpm.Dispose();
        }
    }


    /// <summary>
    /// Capstone 5 (contract R-11(5)): with NO PIN-retries custody composed at all, a mismatch and a
    /// subsequent success over the real wire transport must behave EXACTLY as before this wave - the
    /// custody-absent byte-identical regression, at the wire level (Package B's own regression suites
    /// proved this at the unit level; this closes the same claim for the real APDU transport).
    /// </summary>
    [TestMethod]
    public async Task CustodyAbsentPinRetriesBehaveByteIdenticallyToPreWaveOverRealApduTransport()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;

        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("wavepin-absent-control");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        await EstablishPinAsync(harness.Transceive, pool, protocolId, "1234", cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(8, await GetPinRetriesAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false));

        byte mismatchStatus = await ChangePinExpectingErrorAsync(harness.Transceive, pool, protocolId, currentPin: "0000", newPin: "5678", cancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, mismatchStatus, "with no PIN-retries custody composed, a mismatch must behave exactly as before this wave.");
        Assert.AreEqual(7, await GetPinRetriesAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false));

        await ChangePinExpectingSuccessAsync(harness.Transceive, pool, protocolId, currentPin: "1234", newPin: "5678", cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            8, await GetPinRetriesAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false),
            "with no custody composed, a success must restore pinRetries to maximum exactly as before this wave.");
    }


    /// <summary>
    /// Capstone 6 (contract R-11(6)): a garbage <c>pinHashEnc</c> that fails to DECRYPT reduces the
    /// TPM-backed remaining budget by EXACTLY one - proving <see cref="TpmNvPinRetriesCustody"/>'s own
    /// zero-length-sentinel <c>PenalizeAttemptAsync</c> composition (which reuses the atomic
    /// Index-authorized verify path rather than a raw owner write) genuinely lands one, and only one,
    /// TPM-side mismatch against the real in-house simulated NV Index.
    /// </summary>
    /// <remarks>
    /// Wavepin review finding F-7(a) (re-scoped 2026-07-25): this capstone deliberately asserts only the
    /// resulting COUNT, not path identity (which arm — <c>PenalizeAttemptAsync</c>'s sentinel or
    /// <c>VerifyPinAttemptAsync</c>'s ordinary path — actually ran). Path identity is structurally
    /// UNPROVABLE at this wire level: a wrong 16-byte candidate routed through the ordinary verify path
    /// produces an IDENTICAL TPM effect (the same <c>TPM_RC_BAD_AUTH</c>, the same <c>pinCount</c>
    /// decrement, the same <c>PIN_INVALID</c> status, the same resulting count) as the zero-length
    /// sentinel routed through penalize, so no wire-visible fact could ever distinguish them — asserting
    /// it here would either be untestable or silently assert something else instead. The end-to-end
    /// effect (the decrement happens exactly once) is proven HERE, over the real transport; which arm
    /// produced it is proven separately, at the seam level, by
    /// <c>CtapAuthenticatorPinRetriesCustodyTests.DecryptFailureCallsPenalizeNotVerifyAndAppliesMismatchSemantics</c>,
    /// which asserts the in-memory double's own operation log contains <c>"Penalize"</c> and not
    /// <c>"Verify"</c> for this exact scenario. Neither test pretends to do the other's job.
    /// </remarks>
    [TestMethod]
    public async Task GarbagePinHashEncReducesTpmBackedRemainingByExactlyOneOverRealApduTransport()
    {
        const string RunId = "wavepin-decrypt-failure";
        const uint PinIndexHandle = 0x0100_0840;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        Guid aaguid = Guid.NewGuid();
        byte[] sealAuth = "wavepin-decrypt-failure-seal-auth"u8.ToArray();

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("wavepin-decrypt-failure-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            var store = new DictionaryBackedTpmSealedSnapshotBlobStore();
            CtapPinRetriesCustody pinCustody = TpmNvPinRetriesCustody.Create(tpm, ReadOnlyMemory<byte>.Empty, PinIndexHandle);

            CtapAuthenticatorSimulator simulator = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, store), aaguid, pinRetriesCustody: pinCustody, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            using(CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false))
            {
                await EstablishPinAsync(harness.Transceive, pool, protocolId, "1234", cancellationToken).ConfigureAwait(false);
                Assert.AreEqual(8, await GetPinRetriesAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false));

                byte status = await AttemptMalformedCurrentPinHashExpectingErrorAsync(harness.Transceive, pool, protocolId, newPin: "5678", cancellationToken)
                    .ConfigureAwait(false);
                Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, status);
                Assert.AreEqual(
                    7, await GetPinRetriesAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false),
                    "a decrypt failure must reduce the TPM-backed remaining budget by exactly one, via the penalize sentinel path.");
            }

            simulator.Dispose();
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, cancellationToken).ConfigureAwait(false);
            tpm.Dispose();
        }
    }


    /// <summary>
    /// Wavepin review fix F-1 headline regression: provision a PIN, discard the whole-snapshot custody
    /// entirely (a fresh, empty store — the most severe form of "the snapshot never learned of the TPM's
    /// own PIN", more severe than merely stale), and re-compose against the SAME TPM chip. <c>setPIN</c>
    /// must be refused on the wire with <c>PIN_AUTH_INVALID</c> (never silently re-establish an
    /// attacker-chosen PIN with zero proof of the real one), and the ORIGINAL PIN must still authenticate —
    /// proving the durable persistent tier, not the discarded local cache, is what actually gates both.
    /// </summary>
    [TestMethod]
    public async Task DiscardingTheWholeSnapshotEntirelyRefusesSetPinAndTheOriginalPinStillAuthenticatesOverRealApduTransport()
    {
        const string RunId = "wavepin-f1-discarded-snapshot";
        const uint PinIndexHandle = 0x0100_0850;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        Guid aaguid = Guid.NewGuid();
        byte[] sealAuth = "wavepin-f1-discarded-snapshot-seal-auth"u8.ToArray();

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("wavepin-f1-discarded-snapshot-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            CtapPinRetriesCustody pinCustody = TpmNvPinRetriesCustody.Create(tpm, ReadOnlyMemory<byte>.Empty, PinIndexHandle);

            CtapAuthenticatorSimulator simulator1 = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, new DictionaryBackedTpmSealedSnapshotBlobStore()), aaguid,
                pinRetriesCustody: pinCustody, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            using(CtapWave2TransportHarness harness1 = await CtapWave2TransportHarness.CreateAsync(simulator1, pool, cancellationToken).ConfigureAwait(false))
            {
                await EstablishPinAsync(harness1.Transceive, pool, protocolId, "1234", cancellationToken).ConfigureAwait(false);
            }

            simulator1.Dispose();

            //A brand-new, empty store models the snapshot never existing at all on the re-composed side —
            //the same TPM chip is the only thing carrying the original PIN's own truth forward.
            CtapAuthenticatorSimulator simulator2 = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, new DictionaryBackedTpmSealedSnapshotBlobStore()), aaguid,
                pinRetriesCustody: pinCustody, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            using(CtapWave2TransportHarness harness2 = await CtapWave2TransportHarness.CreateAsync(simulator2, pool, cancellationToken).ConfigureAwait(false))
            {
                byte setPinStatus = await SetPinExpectingErrorAsync(harness2.Transceive, pool, protocolId, "9999", cancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    WellKnownCtapStatusCodes.PinAuthInvalid, setPinStatus,
                    "setPIN must be refused when the durable tier reports a genuinely provisioned PIN, even though the local snapshot was discarded entirely.");

                await GetPinTokenExpectingSuccessAsync(harness2.Transceive, pool, protocolId, "1234", cancellationToken).ConfigureAwait(false);
            }

            simulator2.Dispose();
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, cancellationToken).ConfigureAwait(false);
            tpm.Dispose();
        }
    }


    /// <summary>
    /// Wavepin review fix F-2 headline regression: provision a PIN, then undefine the NV Index BEHIND the
    /// authenticator's back (owner-authorized, simulating the crash window inside <c>ProvisionPinAsync</c>'s
    /// own undefine→redefine composition) while the whole-snapshot still says a PIN is set, then re-compose.
    /// PIN commands must answer a DEFINED CTAP status — never an escaping exception — and a fresh
    /// <c>setPIN</c> must legitimately re-establish (turning F-2's brick into ordinary recovery), with the
    /// new PIN authenticating afterward.
    /// </summary>
    [TestMethod]
    public async Task UndefiningTheIndexBehindTheAuthenticatorsBackAnswersDefinedStatusesAndSetPinReEstablishesOverRealApduTransport()
    {
        const string RunId = "wavepin-f2-undefine-behind-back";
        const uint PinIndexHandle = 0x0100_0860;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        Guid aaguid = Guid.NewGuid();
        byte[] sealAuth = "wavepin-f2-undefine-behind-back-seal-auth"u8.ToArray();

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("wavepin-f2-undefine-behind-back-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            var store = new DictionaryBackedTpmSealedSnapshotBlobStore();
            CtapPinRetriesCustody pinCustody = TpmNvPinRetriesCustody.Create(tpm, ReadOnlyMemory<byte>.Empty, PinIndexHandle);

            CtapAuthenticatorSimulator simulator1 = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, store), aaguid, pinRetriesCustody: pinCustody, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            using(CtapWave2TransportHarness harness1 = await CtapWave2TransportHarness.CreateAsync(simulator1, pool, cancellationToken).ConfigureAwait(false))
            {
                await EstablishPinAsync(harness1.Transceive, pool, protocolId, "1234", cancellationToken).ConfigureAwait(false);
            }

            simulator1.Dispose();

            //Simulates the crash window: an owner-authorized undefine of the Index, entirely outside the
            //authenticator's own ProvisionPinAsync composition — the store's snapshot still says "1234" is
            //set.
            TpmResult<NvUndefineSpaceResponse> undefineResult =
                await tpm.UndefinePinIndexAsync(ReadOnlyMemory<byte>.Empty, PinIndexHandle, cancellationToken).ConfigureAwait(false);
            Assert.IsTrue(undefineResult.IsSuccess, "the owner-authorized undefine simulating the crash window must succeed.");

            CtapAuthenticatorSimulator simulator2 = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, store), aaguid, pinRetriesCustody: pinCustody, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            using(CtapWave2TransportHarness harness2 = await CtapWave2TransportHarness.CreateAsync(simulator2, pool, cancellationToken).ConfigureAwait(false))
            {
                byte oldPinTokenStatus = await GetPinTokenExpectingErrorAsync(harness2.Transceive, pool, protocolId, "1234", cancellationToken)
                    .ConfigureAwait(false);
                Assert.AreEqual(
                    WellKnownCtapStatusCodes.PinNotSet, oldPinTokenStatus,
                    "with the durable tier's own PIN genuinely gone, the reconciled local state must answer PIN_NOT_SET, never an escaping exception.");

                await EstablishPinAsync(harness2.Transceive, pool, protocolId, "5678", cancellationToken).ConfigureAwait(false);
                await GetPinTokenExpectingSuccessAsync(harness2.Transceive, pool, protocolId, "5678", cancellationToken).ConfigureAwait(false);
            }

            simulator2.Dispose();
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, cancellationToken).ConfigureAwait(false);
            tpm.Dispose();
        }
    }


    /// <summary>
    /// Wavepin review coordinator addendum (2026-07-25): the THIRD F-1/F-2 reachability path, and the most
    /// ORDINARY one of all — attaching <c>pinRetriesCustody</c> for the FIRST time onto an authenticator
    /// whose PIN was established BEFORE any persistent-tier custody existed (an ordinary deployment/upgrade
    /// sequence, never a crash or an attack). The whole-snapshot's own <c>CurrentStoredPin</c> is non-null,
    /// while the NV Index is genuinely absent (never defined) — reconciliation direction (b) must clear the
    /// stale local hash so a fresh <c>setPIN</c> can legitimately re-establish under the newly-attached
    /// custody.
    /// </summary>
    [TestMethod]
    public async Task AttachingPinRetriesCustodyForTheFirstTimeOntoAPreExistingLocalPinClearsTheStaleHashOverRealApduTransport()
    {
        const string RunId = "wavepin-f2-first-attach";
        const uint PinIndexHandle = 0x0100_0870;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        Guid aaguid = Guid.NewGuid();
        byte[] sealAuth = "wavepin-f2-first-attach-seal-auth"u8.ToArray();

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("wavepin-f2-first-attach-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            var store = new DictionaryBackedTpmSealedSnapshotBlobStore();

            //First composition: NO pinRetriesCustody composed at all - the PIN is established under the
            //whole-snapshot custody alone, exactly the pre-wavepin deployment shape.
            CtapAuthenticatorSimulator simulator1 = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, store), aaguid, pinRetriesCustody: null, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            using(CtapWave2TransportHarness harness1 = await CtapWave2TransportHarness.CreateAsync(simulator1, pool, cancellationToken).ConfigureAwait(false))
            {
                await EstablishPinAsync(harness1.Transceive, pool, protocolId, "1234", cancellationToken).ConfigureAwait(false);
            }

            simulator1.Dispose();

            //Second composition: pinRetriesCustody attached for the FIRST TIME, against an Index that has
            //NEVER been defined on this chip - the ordinary upgrade sequence.
            CtapPinRetriesCustody pinCustody = TpmNvPinRetriesCustody.Create(tpm, ReadOnlyMemory<byte>.Empty, PinIndexHandle);
            CtapAuthenticatorSimulator simulator2 = await CtapWave5AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, store), aaguid, pinRetriesCustody: pinCustody, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            using(CtapWave2TransportHarness harness2 = await CtapWave2TransportHarness.CreateAsync(simulator2, pool, cancellationToken).ConfigureAwait(false))
            {
                byte oldPinTokenStatus = await GetPinTokenExpectingErrorAsync(harness2.Transceive, pool, protocolId, "1234", cancellationToken)
                    .ConfigureAwait(false);
                Assert.AreEqual(
                    WellKnownCtapStatusCodes.PinNotSet, oldPinTokenStatus,
                    "attaching custody for the first time onto a pre-existing local PIN, against a never-defined Index, must clear the stale local hash.");

                await EstablishPinAsync(harness2.Transceive, pool, protocolId, "5678", cancellationToken).ConfigureAwait(false);
                await GetPinTokenExpectingSuccessAsync(harness2.Transceive, pool, protocolId, "5678", cancellationToken).ConfigureAwait(false);
            }

            simulator2.Dispose();
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, cancellationToken).ConfigureAwait(false);
            tpm.Dispose();
        }
    }


    /// <summary>
    /// Wavepin review fix F-1/F-2, item 3: within ONE live composition (no rehydration involved), the NV
    /// Index vanishing BEHIND the adapter's own back mid-session — the owner-authorized undefine that
    /// simulates the crash window — must make <see cref="CtapPinRetriesCustody.VerifyPinAttemptAsync"/>
    /// answer a fail-closed non-match verdict, never throw. This is the narrower race
    /// <see cref="CreateWithCustodyAsync"/>'s own rehydration reconciliation cannot reach (it only runs at
    /// composition time): a genuine attempt lands on the live adapter's own <c>TPM_RC_HANDLE</c> tolerance.
    /// </summary>
    [TestMethod]
    public async Task VerifyPinAttemptAsyncTreatsAnIndexUndefinedMidSessionAsAFailClosedNonMatchRatherThanThrowing()
    {
        const uint PinIndexHandle = 0x0100_08a0;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        byte[] pinHash = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("wavepin-f1f2-item3-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            CtapPinRetriesCustody pinCustody = TpmNvPinRetriesCustody.Create(tpm, ReadOnlyMemory<byte>.Empty, PinIndexHandle);
            await pinCustody.ProvisionPinAsync(pinHash, cancellationToken).ConfigureAwait(false);

            //Simulates the Index vanishing mid-session, behind THIS bundle's own back — the same
            //owner-authorized undefine primitive the crash-window scenario composes.
            TpmResult<NvUndefineSpaceResponse> undefineResult =
                await tpm.UndefinePinIndexAsync(ReadOnlyMemory<byte>.Empty, PinIndexHandle, cancellationToken).ConfigureAwait(false);
            Assert.IsTrue(undefineResult.IsSuccess, "the owner-authorized undefine simulating the mid-session crash must succeed.");

            CtapPinAttemptVerdict verdict = await pinCustody.VerifyPinAttemptAsync(pinHash, cancellationToken).ConfigureAwait(false);

            Assert.IsFalse(verdict.IsMatch, "an absent Index must never report a match.");
            Assert.IsFalse(verdict.IsProvisioned, "an absent Index must report IsProvisioned false.");
            Assert.IsFalse(verdict.IsBlocked, "an absent Index is not the same condition as a blocked one.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, cancellationToken).ConfigureAwait(false);
            tpm.Dispose();
        }
    }


    /// <summary>
    /// Wavepin review finding F-6(a): drives a non-tolerated TPM rejection directly into
    /// <see cref="TpmNvPinRetriesCustody"/> (a WRONG, non-empty owner auth against a real Index whose
    /// actual owner auth is empty) and asserts <see cref="TpmNvPinRetriesCustodyException"/> escapes —
    /// proving the adapter's fail-closed throw path is genuinely reachable, rather than merely assumed
    /// (deleting every throw and returning a default verdict would otherwise pass the whole suite).
    /// </summary>
    [TestMethod]
    public async Task WrongOwnerAuthOnTheOwnerReadArmSurfacesAsTpmNvPinRetriesCustodyException()
    {
        const uint PinIndexHandle = 0x0100_0880;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        byte[] pinHash = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("wavepin-f6a-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            //Defines the Index under the chip's REAL (empty) owner auth.
            CtapPinRetriesCustody correctOwnerCustody = TpmNvPinRetriesCustody.Create(tpm, ReadOnlyMemory<byte>.Empty, PinIndexHandle);
            await correctOwnerCustody.ProvisionPinAsync(pinHash, cancellationToken).ConfigureAwait(false);

            //A SECOND bundle over the SAME Index, presenting a WRONG, non-empty owner auth: the
            //owner-authorized read is refused with TPM_RC_BAD_AUTH, which ReadRetriesAsync tolerates ONLY
            //for TPM_RC_HANDLE — a non-tolerated rejection must escape as the adapter's own exception type.
            byte[] wrongOwnerAuth = "wavepin-f6a-wrong-owner-auth"u8.ToArray();
            CtapPinRetriesCustody wrongOwnerCustody = TpmNvPinRetriesCustody.Create(tpm, wrongOwnerAuth, PinIndexHandle);

            _ = await Assert.ThrowsExactlyAsync<TpmNvPinRetriesCustodyException>(
                () => wrongOwnerCustody.ReadRetriesAsync(cancellationToken).AsTask());
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, cancellationToken).ConfigureAwait(false);
            tpm.Dispose();
        }
    }


    /// <summary>
    /// Wavepin review finding F-7(b): <see cref="CtapPinRetriesCustody.RetirePinAsync"/>'s <c>TPM_RC_HANDLE</c>
    /// tolerance — retiring an Index that was NEVER provisioned — is an ordinary idempotent no-op, never a
    /// throw, and leaves the tier in the same fresh, never-provisioned condition a subsequent
    /// <see cref="CtapPinRetriesCustody.ReadRetriesAsync"/> would report for a brand-new authenticator.
    /// </summary>
    [TestMethod]
    public async Task RetirePinAsyncToleratesAnIndexThatWasNeverProvisioned()
    {
        const uint PinIndexHandle = 0x0100_0890;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("wavepin-f7b-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            CtapPinRetriesCustody pinCustody = TpmNvPinRetriesCustody.Create(tpm, ReadOnlyMemory<byte>.Empty, PinIndexHandle);

            //No ProvisionPinAsync call was ever made against this Index — the tolerated TPM_RC_HANDLE
            //must never escape as a throw.
            await pinCustody.RetirePinAsync(cancellationToken).ConfigureAwait(false);

            CtapPinAttemptVerdict verdict = await pinCustody.ReadRetriesAsync(cancellationToken).ConfigureAwait(false);
            Assert.IsFalse(verdict.IsProvisioned, "retiring a never-provisioned Index must leave it never-provisioned.");
            Assert.AreEqual(PinLimit, verdict.RetriesRemaining, "retiring a never-provisioned Index must leave the fresh, full budget unchanged.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, cancellationToken).ConfigureAwait(false);
            tpm.Dispose();
        }
    }


    /// <summary>
    /// Builds a <see cref="CtapStateCustody"/> bundle backed by <paramref name="tpm"/>'s already-loaded
    /// storage parent, <paramref name="sealAuth"/>, and <paramref name="store"/>'s three delegates —
    /// mirroring <see cref="CtapAuthenticatorNvSignCounterCapstoneTests"/>'s own identically named helper.
    /// </summary>
    /// <param name="tpm">The TPM device to seal to and unseal from.</param>
    /// <param name="parentHandle">The already-loaded storage parent's handle.</param>
    /// <param name="sealAuth">The authorization value every snapshot is sealed under.</param>
    /// <param name="store">The blob-store double this bundle's three delegates are bound to.</param>
    /// <returns>The composed seam-bundle record.</returns>
    private static CtapStateCustody BuildStateCustody(
        TpmDevice tpm, uint parentHandle, ReadOnlyMemory<byte> sealAuth, DictionaryBackedTpmSealedSnapshotBlobStore store) =>
        TpmSealedStateCustody.Create(
            tpm, parentHandle, ReadOnlyMemory<byte>.Empty, sealAuth,
            store.TryFetchSealedBlobAsync, store.StoreSealedBlobAsync, store.DeleteSealedBlobAsync);


    /// <summary>
    /// Brings up a fresh in-house simulated TPM ("the durable chip") and one loaded ECC storage parent —
    /// the one long-lived TPM identity every capstone test method seals custody snapshots and the
    /// persistent PIN-retries tier under. Mirrors <see cref="CtapAuthenticatorNvSignCounterCapstoneTests"/>'s
    /// own identically named helper.
    /// </summary>
    /// <param name="chipRunId">The simulated TPM's own run id.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The TPM device and the loaded storage parent's handle.</returns>
    private static async Task<(TpmDevice Tpm, uint ParentHandle)> CreateChipWithLoadedStorageParentAsync(string chipRunId, CancellationToken cancellationToken)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var chip = new TpmSimulator(chipRunId, signingBackend: BouncyCastleTpmEccSigningBackend.Create());
        await chip.PowerOnAsync(cancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(chip, pool, cancellationToken).ConfigureAwait(false);

        TpmDevice tpm = TpmDevice.Create(chip.SubmitAsync);

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);

        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary storage parent failed: '{parentResult.ResponseCode}'.");

        uint parentHandle;
        using(CreatePrimaryResponse parent = parentResult.Value)
        {
            parentHandle = parent.ObjectHandle.Value;
        }

        return (tpm, parentHandle);
    }


    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames
    /// an unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
    /// Mirrors <see cref="CtapAuthenticatorNvSignCounterCapstoneTests"/>'s own identically named helper.
    /// </summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    private static async Task BringOperationalAsync(TpmSimulator simulator, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }


    /// <summary>Sends a bare <c>authenticatorReset</c> request over <paramref name="transceive"/>, returning the raw response envelope.</summary>
    private static ValueTask<PooledMemory> SendResetAsync(Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] request = [WellKnownCtapCommands.Reset];

        return transceive(request, pool, cancellationToken);
    }


    /// <summary>Establishes <paramref name="pin"/> as the authenticator's PIN over <paramref name="transceive"/>'s real transport.</summary>
    private static async Task EstablishPinAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string pin, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(transceive, protocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync(pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        _ = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Attempts <c>setPIN</c> over <paramref name="transceive"/>'s real transport expected to FAIL,
    /// returning the exact status code.
    /// </summary>
    private static async Task<byte> SetPinExpectingErrorAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string pin, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(transceive, protocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync(pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(() => CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).AsTask());

        return exception.StatusCode;
    }


    /// <summary>
    /// Attempts a <c>changePIN</c> over <paramref name="transceive"/>'s real transport expected to SUCCEED.
    /// </summary>
    private static async Task ChangePinExpectingSuccessAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string currentPin, string newPin,
        CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(transceive, protocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        (byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam) =
            await session.BuildChangePinMessagesAsync(newPin, currentPin, cancellationToken).ConfigureAwait(false);
        CtapClientPinRequest request = BuildChangePinRequest(session, newPinEnc, pinHashEnc, pinUvAuthParam, protocolId);

        _ = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Attempts a <c>changePIN</c> with a WRONG current PIN over <paramref name="transceive"/>'s real
    /// transport, returning the exact status code.
    /// </summary>
    private static async Task<byte> ChangePinExpectingErrorAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string currentPin, string newPin,
        CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(transceive, protocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        (byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam) =
            await session.BuildChangePinMessagesAsync(newPin, currentPin, cancellationToken).ConfigureAwait(false);
        CtapClientPinRequest request = BuildChangePinRequest(session, newPinEnc, pinHashEnc, pinUvAuthParam, protocolId);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(() => CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).AsTask());

        return exception.StatusCode;
    }


    /// <summary>
    /// Attempts a <c>changePIN</c> whose <c>pinHashEnc</c> fails to DECRYPT over <paramref name="transceive"/>'s
    /// real transport, returning the exact status code.
    /// </summary>
    private static async Task<byte> AttemptMalformedCurrentPinHashExpectingErrorAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string newPin, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(transceive, protocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        byte[] malformedPinHashEnc = CtapWave5bPinCryptoFixtures.BuildMalformedPinHashEnc();
        (byte[] newPinEnc, byte[] pinUvAuthParam) =
            await session.BuildChangePinMessagesWithExplicitPinHashEncAsync(newPin, malformedPinHashEnc, cancellationToken).ConfigureAwait(false);
        CtapClientPinRequest request = BuildChangePinRequest(session, newPinEnc, malformedPinHashEnc, pinUvAuthParam, protocolId);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(() => CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).AsTask());

        return exception.StatusCode;
    }


    /// <summary>
    /// Issues <c>getPinToken</c> over <paramref name="transceive"/>'s real transport expected to SUCCEED,
    /// proving <paramref name="pin"/> is currently the authenticator's stored PIN.
    /// </summary>
    private static async Task GetPinTokenExpectingSuccessAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string pin, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(transceive, protocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync(pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: pinHashEnc);

        _ = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Attempts <c>getPinToken</c> over <paramref name="transceive"/>'s real transport expected to FAIL,
    /// returning the exact status code.
    /// </summary>
    private static async Task<byte> GetPinTokenExpectingErrorAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string pin, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(transceive, protocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync(pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: pinHashEnc);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(() => CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).AsTask());

        return exception.StatusCode;
    }


    /// <summary>Builds a <c>changePIN</c> request from the session and encrypted message members.</summary>
    private static CtapClientPinRequest BuildChangePinRequest(
        CtapWave5bPlatformPinSession session, byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam, CtapPinUvAuthProtocolId protocolId) =>
        new(
            SubCommand: WellKnownCtapClientPinSubCommands.ChangePin,
            PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose,
            PinUvAuthParam: pinUvAuthParam,
            NewPinEnc: newPinEnc,
            PinHashEnc: pinHashEnc);


    /// <summary>Reads the current <c>pinRetries</c> counter via <c>getPINRetries</c> over <paramref name="transceive"/>'s real transport.</summary>
    private static async Task<int> GetPinRetriesAsync(Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetPinRetries);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);

        return response.PinRetries!.Value;
    }


    /// <summary>Reads the current <c>powerCycleState</c> via <c>getPINRetries</c> over <paramref name="transceive"/>'s real transport.</summary>
    private static async Task<bool> GetPowerCycleStateAsync(Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetPinRetries);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);

        return response.PowerCycleState!.Value;
    }
}
