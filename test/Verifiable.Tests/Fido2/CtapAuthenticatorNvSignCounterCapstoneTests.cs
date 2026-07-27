using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Fido2.Ctap.Authenticator.Custody;
using Verifiable.Fido2.Tpm.Ctap.Authenticator.Custody;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.Tpm;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The wavenv capstones for NV-counter-backed signature-counter custody
/// (<see cref="CtapSignatureCounterCustody"/>/<see cref="TpmNvSignatureCounterCustody"/>, contract R-9): the
/// R-9(b) closure the <see cref="CtapAuthenticatorTpmCustodyCapstoneTests"/> class remarks recorded as
/// deferred. Mirrors that class's own firewalled discipline exactly: ONE in-house <see cref="TpmSimulator"/>
/// instance plays the durable chip and OUTLIVES every <see cref="CtapAuthenticatorSimulator"/> instance
/// built against it, and every assertion reads a wire-visible fact over the real, unmodified APDU transport
/// (<see cref="CtapWave2TransportHarness"/>) — never internal simulator or TPM state.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorNvSignCounterCapstoneTests
{
    /// <summary>
    /// The mint-order creation sequence the FIRST credential minted on a fresh authenticator receives
    /// (<c>NextCredentialSequence</c> starts at zero), and hence the NV counter index offset its own
    /// signature counter occupies.
    /// </summary>
    private const ulong CredentialACreationSequence = 0;

    /// <summary>The creation sequence the SECOND credential minted on that same authenticator receives.</summary>
    private const ulong CredentialBCreationSequence = 1;

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Flagship (contract R-9, capstone 1): a stale WHOLE-SNAPSHOT cannot roll the NV-backed signCount
    /// back. Both custodies are composed together. Three assertions run on instance 1, advancing the wire
    /// signCount 2 -&gt; 3 -&gt; 4; an EARLY sealed-snapshot blob (captured right after the FIRST assertion,
    /// whose cached signCount is 2) is then restored over the LATEST one before instance 1 dies. Instance 2
    /// rehydrates from that stale blob — its in-memory cache reads back signCount 2 — yet its next
    /// assertion's WIRE signCount strictly exceeds 4: the NV Counter Index on the surviving chip, never the
    /// stale cache, is what <see cref="CtapSignatureCounterCustody.IncrementCounterAsync"/> actually reads
    /// from. A whole-snapshot-only implementation would instead resume from the stale cache and answer 3 —
    /// an actual rollback below the last pre-kill wire value of 4 — which this capstone's own
    /// strictly-greater-than-4 assertion would catch.
    /// </summary>
    [TestMethod]
    public async Task StaleWholeSnapshotCannotRollBackNvBackedSignCountOverRealApduTransport()
    {
        const string RpId = "wavenv-flagship.example";
        const string Pin = "1234";
        const string RunId = "wavenv-flagship";
        const uint BaseNvIndexHandle = 0x0100_0700;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        Guid aaguid = Guid.NewGuid();
        byte[] sealAuth = "wavenv-flagship-seal-auth"u8.ToArray();
        byte[] counterAuth = "wavenv-flagship-counter-auth"u8.ToArray();

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("wavenv-flagship-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            var store = new DictionaryBackedTpmSealedSnapshotBlobStore();
            CtapSignatureCounterCustody counterCustody = TpmNvSignatureCounterCustody.Create(tpm, ReadOnlyMemory<byte>.Empty, counterAuth, BaseNvIndexHandle);

            byte[] credentialIdBytes;
            uint lastPreKillWireSignCount;

            CtapAuthenticatorSimulator simulator1 = await CtapWave2AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, store), aaguid, signatureCounterCustody: counterCustody, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            using(CtapWave2TransportHarness harness1 = await CtapWave2TransportHarness.CreateAsync(simulator1, pool, cancellationToken).ConfigureAwait(false))
            {
                await EstablishPinAsync(harness1.Transceive, pool, protocolId, Pin, cancellationToken).ConfigureAwait(false);
                credentialIdBytes = await RegisterDiscoverableCredentialAsync(
                    harness1.Transceive, pool, protocolId, Pin, RpId, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xF0), cancellationToken)
                    .ConfigureAwait(false);

                uint signCountAfterFirstAssertion = await PerformAssertionAndGetSignCountAsync(
                    harness1.Transceive, pool, protocolId, Pin, RpId, credentialIdBytes, cancellationToken).ConfigureAwait(false);

                //Captured right after the FIRST assertion — this is the EARLY blob a stale restore replays.
                byte[] earlyBlob = store.GetStoredBytesCopy(RunId);

                uint signCountAfterSecondAssertion = await PerformAssertionAndGetSignCountAsync(
                    harness1.Transceive, pool, protocolId, Pin, RpId, credentialIdBytes, cancellationToken).ConfigureAwait(false);
                lastPreKillWireSignCount = await PerformAssertionAndGetSignCountAsync(
                    harness1.Transceive, pool, protocolId, Pin, RpId, credentialIdBytes, cancellationToken).ConfigureAwait(false);

                Assert.IsGreaterThan(signCountAfterFirstAssertion, signCountAfterSecondAssertion, "each successive assertion on instance 1 must strictly advance the wire signCount.");
                Assert.IsGreaterThan(signCountAfterSecondAssertion, lastPreKillWireSignCount, "each successive assertion on instance 1 must strictly advance the wire signCount.");

                //The stale restore, still on instance 1's own store — instance 2 will load exactly this.
                store.ReplaceStoredBytes(RunId, earlyBlob);
            }

            simulator1.Dispose();

            CtapAuthenticatorSimulator simulator2 = await CtapWave2AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, store), aaguid, signatureCounterCustody: counterCustody, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            using(CtapWave2TransportHarness harness2 = await CtapWave2TransportHarness.CreateAsync(simulator2, pool, cancellationToken).ConfigureAwait(false))
            {
                uint signCountAfterRehydrate = await PerformAssertionAndGetSignCountAsync(
                    harness2.Transceive, pool, protocolId, Pin, RpId, credentialIdBytes, cancellationToken).ConfigureAwait(false);

                Assert.IsGreaterThan(
                    lastPreKillWireSignCount, signCountAfterRehydrate,
                    "rehydrating from a STALE whole-snapshot blob must not roll the NV-backed signCount back below the last pre-kill wire value — " +
                    "the surviving chip's own NV Counter Index, never the stale cache, is authoritative.");
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
    /// Contract R-9, capstone 2 (continuity half): mint -&gt; assert -&gt; kill -&gt; rehydrate (from the
    /// LATEST, non-stale snapshot) -&gt; assert. The wire signCount strictly increases across the boundary —
    /// see <see cref="CustodyAbsentSignCountBehavesByteIdenticallyToPreWaveOverRealApduTransport"/> for the
    /// paired custody-absent control this capstone's own opt-in claim depends on.
    /// </summary>
    [TestMethod]
    public async Task NvBackedSignCountStrictlyIncreasesAcrossDeathAndRehydrationOverRealApduTransport()
    {
        const string RpId = "wavenv-continuity.example";
        const string Pin = "1234";
        const string RunId = "wavenv-continuity";
        const uint BaseNvIndexHandle = 0x0100_0710;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        Guid aaguid = Guid.NewGuid();
        byte[] sealAuth = "wavenv-continuity-seal-auth"u8.ToArray();
        byte[] counterAuth = "wavenv-continuity-counter-auth"u8.ToArray();

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("wavenv-continuity-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            var store = new DictionaryBackedTpmSealedSnapshotBlobStore();
            CtapSignatureCounterCustody counterCustody = TpmNvSignatureCounterCustody.Create(tpm, ReadOnlyMemory<byte>.Empty, counterAuth, BaseNvIndexHandle);

            byte[] credentialIdBytes;
            uint signCountBeforeDeath;

            CtapAuthenticatorSimulator simulator1 = await CtapWave2AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, store), aaguid, signatureCounterCustody: counterCustody, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            using(CtapWave2TransportHarness harness1 = await CtapWave2TransportHarness.CreateAsync(simulator1, pool, cancellationToken).ConfigureAwait(false))
            {
                await EstablishPinAsync(harness1.Transceive, pool, protocolId, Pin, cancellationToken).ConfigureAwait(false);
                credentialIdBytes = await RegisterDiscoverableCredentialAsync(
                    harness1.Transceive, pool, protocolId, Pin, RpId, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xF1), cancellationToken)
                    .ConfigureAwait(false);
                signCountBeforeDeath = await PerformAssertionAndGetSignCountAsync(
                    harness1.Transceive, pool, protocolId, Pin, RpId, credentialIdBytes, cancellationToken).ConfigureAwait(false);
            }

            simulator1.Dispose();

            CtapAuthenticatorSimulator simulator2 = await CtapWave2AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, store), aaguid, signatureCounterCustody: counterCustody, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            using(CtapWave2TransportHarness harness2 = await CtapWave2TransportHarness.CreateAsync(simulator2, pool, cancellationToken).ConfigureAwait(false))
            {
                uint signCountAfterRehydrate = await PerformAssertionAndGetSignCountAsync(
                    harness2.Transceive, pool, protocolId, Pin, RpId, credentialIdBytes, cancellationToken).ConfigureAwait(false);

                Assert.IsGreaterThan(
                    signCountBeforeDeath, signCountAfterRehydrate, "the NV-backed wire signCount must strictly increase across a kill/rehydrate boundary.");
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
    /// Contract R-9, capstone 2 (custody-absent control): with NO signature-counter custody composed at
    /// all, two assertions against a freshly minted credential must produce the EXACT pre-wave progression
    /// 0 -&gt; 1 -&gt; 2 — byte-identical to today's in-snapshot behavior, proving the mint/assert threading
    /// this wave introduced changes nothing when the new seam is absent (contract R-9's opt-in discipline).
    /// </summary>
    [TestMethod]
    public async Task CustodyAbsentSignCountBehavesByteIdenticallyToPreWaveOverRealApduTransport()
    {
        const string RpId = "wavenv-absent-control.example";
        const string Pin = "1234";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("wavenv-absent-control");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        await EstablishPinAsync(harness.Transceive, pool, protocolId, Pin, cancellationToken).ConfigureAwait(false);
        byte[] credentialIdBytes = await RegisterDiscoverableCredentialAsync(
            harness.Transceive, pool, protocolId, Pin, RpId, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xF2), cancellationToken).ConfigureAwait(false);

        uint signCountAfterFirstAssertion = await PerformAssertionAndGetSignCountAsync(
            harness.Transceive, pool, protocolId, Pin, RpId, credentialIdBytes, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(1u, signCountAfterFirstAssertion, "with no signature-counter custody composed, the first assertion must bump signCount from 0 to 1, exactly as before this wave.");

        uint signCountAfterSecondAssertion = await PerformAssertionAndGetSignCountAsync(
            harness.Transceive, pool, protocolId, Pin, RpId, credentialIdBytes, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(2u, signCountAfterSecondAssertion, "with no signature-counter custody composed, the second assertion must bump signCount from 1 to 2, exactly as before this wave.");
    }


    /// <summary>
    /// Contract R-9, capstone 3: retirement is observed for every credential that leaves the store, via the
    /// delegate's own context log (no closure capture) — both an explicit <c>deleteCredential</c> and an
    /// <c>authenticatorReset</c> factory wipe of the surviving resident credential. Because
    /// <c>authenticatorReset</c> restarts the mint-order sequence at zero, the post-reset credential's
    /// creation sequence COLLIDES with the very first credential's own — yet its first wire signCount is
    /// strictly ABOVE every signCount observed anywhere before the reset: the TPM phantom high-water mark
    /// (shared globally across every NV Counter Index on the chip) surfacing through CTAP.
    /// </summary>
    [TestMethod]
    public async Task FactoryResetAndDeleteCredentialRetireCountersAndPostResetMintSeedsAboveEveryPreResetValueOverRealApduTransport()
    {
        const string RpId = "wavenv-reset.example";
        const string Pin = "1234";
        const string RunId = "wavenv-reset";
        const uint BaseNvIndexHandle = 0x0100_0720;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        Guid aaguid = Guid.NewGuid();
        byte[] sealAuth = "wavenv-reset-seal-auth"u8.ToArray();
        byte[] counterAuth = "wavenv-reset-counter-auth"u8.ToArray();

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("wavenv-reset-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            var store = new DictionaryBackedTpmSealedSnapshotBlobStore();
            RecordingSignatureCounterCustodyHarness counterHarness = new RecordingSignatureCounterCustodyHarness(
                TpmNvSignatureCounterCustody.Create(tpm, ReadOnlyMemory<byte>.Empty, counterAuth, BaseNvIndexHandle)).Build();

            CtapAuthenticatorSimulator simulator = await CtapWave2AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, store), aaguid, signatureCounterCustody: counterHarness.Custody, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            uint maxPreResetObserved;
            uint signCountAfterPostResetMint;
            using(CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false))
            {
                await EstablishPinAsync(harness.Transceive, pool, protocolId, Pin, cancellationToken).ConfigureAwait(false);

                byte[] credentialAIdBytes = await RegisterDiscoverableCredentialAsync(
                    harness.Transceive, pool, protocolId, Pin, RpId, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xA0), cancellationToken)
                    .ConfigureAwait(false);
                uint signCountA = await PerformAssertionAndGetSignCountAsync(
                    harness.Transceive, pool, protocolId, Pin, RpId, credentialAIdBytes, cancellationToken).ConfigureAwait(false);

                byte[] credentialBIdBytes = await RegisterDiscoverableCredentialAsync(
                    harness.Transceive, pool, protocolId, Pin, RpId, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xB0), cancellationToken)
                    .ConfigureAwait(false);
                uint signCountB1 = await PerformAssertionAndGetSignCountAsync(
                    harness.Transceive, pool, protocolId, Pin, RpId, credentialBIdBytes, cancellationToken).ConfigureAwait(false);
                uint signCountB2 = await PerformAssertionAndGetSignCountAsync(
                    harness.Transceive, pool, protocolId, Pin, RpId, credentialBIdBytes, cancellationToken).ConfigureAwait(false);

                maxPreResetObserved = Math.Max(signCountA, Math.Max(signCountB1, signCountB2));

                await DeleteCredentialAsync(harness.Transceive, pool, protocolId, Pin, credentialAIdBytes, cancellationToken).ConfigureAwait(false);
                Assert.HasCount(1, counterHarness.RetiredCreationSequences, "deleteCredential must retire exactly one counter.");
                Assert.AreEqual(
                    CredentialACreationSequence, counterHarness.RetiredCreationSequences[0],
                    "deleteCredential must retire credential A's OWN counter - retiring any other sequence would destroy a live credential's rollback protection while this count still read one.");

                using PooledMemory resetResponse = await SendResetAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false);
                Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0], "authenticatorReset must succeed within the power-up window.");
                Assert.HasCount(2, counterHarness.RetiredCreationSequences, "authenticatorReset must additionally retire the surviving resident credential's counter.");
                Assert.AreEqual(
                    CredentialBCreationSequence, counterHarness.RetiredCreationSequences[1],
                    "authenticatorReset must retire the surviving credential B's OWN counter (deleteCredential's retirement of A above is untouched).");

                await EstablishPinAsync(harness.Transceive, pool, protocolId, Pin, cancellationToken).ConfigureAwait(false);
                byte[] credentialCIdBytes = await RegisterDiscoverableCredentialAsync(
                    harness.Transceive, pool, protocolId, Pin, RpId, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xC0), cancellationToken)
                    .ConfigureAwait(false);
                signCountAfterPostResetMint = await PerformAssertionAndGetSignCountAsync(
                    harness.Transceive, pool, protocolId, Pin, RpId, credentialCIdBytes, cancellationToken).ConfigureAwait(false);
            }

            simulator.Dispose();

            Assert.IsGreaterThan(
                maxPreResetObserved, signCountAfterPostResetMint,
                "a post-reset credential's counter (its creation sequence collides with a pre-reset one, since the mint-order sequence restarts at zero) " +
                "must seed strictly above every signCount observed anywhere before the reset — the TPM phantom high-water mark closing the rollback.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, cancellationToken).ConfigureAwait(false);
            tpm.Dispose();
        }
    }


    /// <summary>
    /// Contract R-9, capstone 4: a counter-custody increment failure fails the WHOLE assertion command —
    /// the wire never sees a response for that attempt at all, since the throw happens before any authData
    /// is framed or signed. A subsequent SUCCESSFUL assertion's wire signCount is then exactly one more than
    /// the last successful attempt's own — proving the failed attempt never touched the counter (this
    /// harness's fault injection throws before reaching the real TPM increment at all), so no signed
    /// response could ever have carried a count the custody did not itself produce.
    /// </summary>
    [TestMethod]
    public async Task FailedIncrementFailsAssertionOnWireAndSubsequentSuccessAdvancesOnlyByOneOverRealApduTransport()
    {
        const string RpId = "wavenv-failclosed.example";
        const string Pin = "1234";
        const string RunId = "wavenv-failclosed";
        const uint BaseNvIndexHandle = 0x0100_0730;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        Guid aaguid = Guid.NewGuid();
        byte[] sealAuth = "wavenv-failclosed-seal-auth"u8.ToArray();
        byte[] counterAuth = "wavenv-failclosed-counter-auth"u8.ToArray();

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("wavenv-failclosed-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            var store = new DictionaryBackedTpmSealedSnapshotBlobStore();
            RecordingSignatureCounterCustodyHarness counterHarness = new RecordingSignatureCounterCustodyHarness(
                TpmNvSignatureCounterCustody.Create(tpm, ReadOnlyMemory<byte>.Empty, counterAuth, BaseNvIndexHandle)).Build();

            CtapAuthenticatorSimulator simulator = await CtapWave2AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildStateCustody(tpm, parentHandle, sealAuth, store), aaguid, signatureCounterCustody: counterHarness.Custody, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            using(CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false))
            {
                await EstablishPinAsync(harness.Transceive, pool, protocolId, Pin, cancellationToken).ConfigureAwait(false);
                byte[] credentialIdBytes = await RegisterDiscoverableCredentialAsync(
                    harness.Transceive, pool, protocolId, Pin, RpId, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xF3), cancellationToken)
                    .ConfigureAwait(false);

                uint signCountAfterFirstAssertion = await PerformAssertionAndGetSignCountAsync(
                    harness.Transceive, pool, protocolId, Pin, RpId, credentialIdBytes, cancellationToken).ConfigureAwait(false);

                counterHarness.FailNextIncrement();
                _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                    PerformAssertionAndGetSignCountAsync(harness.Transceive, pool, protocolId, Pin, RpId, credentialIdBytes, cancellationToken));

                uint signCountAfterRetry = await PerformAssertionAndGetSignCountAsync(
                    harness.Transceive, pool, protocolId, Pin, RpId, credentialIdBytes, cancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    signCountAfterFirstAssertion + 1, signCountAfterRetry,
                    "the failed increment attempt must not have advanced the counter at all — the subsequent successful assertion's wire signCount " +
                    "is exactly one more than the last SUCCESSFUL attempt's own, never a count that skipped ahead or repeated.");
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
    /// Builds a <see cref="CtapStateCustody"/> bundle backed by <paramref name="tpm"/>'s already-loaded
    /// storage parent, <paramref name="sealAuth"/>, and <paramref name="store"/>'s three delegates —
    /// mirroring <see cref="CtapAuthenticatorTpmCustodyCapstoneTests"/>'s own identically named helper.
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
    /// the one long-lived TPM identity every capstone test method seals custody snapshots and per-credential
    /// signature counters under. Mirrors <see cref="CtapAuthenticatorTpmCustodyCapstoneTests"/>'s own
    /// identically named helper.
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
    /// Mirrors <see cref="CtapAuthenticatorTpmCustodyCapstoneTests"/>'s own identically named helper.
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
    /// Issues a permissions-scoped <c>pinUvAuthToken</c> via <c>getPinUvAuthTokenUsingPinWithPermissions</c>
    /// (<c>0x09</c>) over <paramref name="transceive"/>'s real transport, decrypting it from wire bytes only.
    /// </summary>
    private static async Task<byte[]> IssueTokenAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string pin, int permissions, string? rpId,
        CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(transceive, protocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync(pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)protocolId, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: permissions, RpId: rpId);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);

        return await session.DecryptTokenAsync(response.PinUvAuthToken!.Value, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Registers one discoverable (<c>rk</c>) credential for <paramref name="userId"/> under
    /// <paramref name="rpId"/>, driven by a freshly issued single-use <c>mc</c>-permissioned token over
    /// <paramref name="transceive"/>'s real transport.
    /// </summary>
    private static async Task<byte[]> RegisterDiscoverableCredentialAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string pin, string rpId, byte[] userId,
        CancellationToken cancellationToken)
    {
        byte[] token = await IssueTokenAsync(
            transceive, pool, protocolId, pin, WellKnownCtapPinUvAuthTokenPermissions.Mc, rpId, cancellationToken).ConfigureAwait(false);

        byte[] clientDataHashBytes = CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x10);
        byte[] pinUvAuthParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, clientDataHashBytes, pool, cancellationToken)
            .ConfigureAwait(false);

        CtapMakeCredentialRequest request = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: rpId, userId: userId, options: new CtapCommandOptions(ResidentKey: true),
            pinUvAuthParam: pinUvAuthParam, pinUvAuthProtocol: (int)protocolId);
        CtapMakeCredentialResponse response = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            transceive, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(request);

        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(response.AuthData, CredentialPublicKeyCborReader.Read, pool);

        return authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
    }


    /// <summary>
    /// Performs an allowList-scoped <c>ga</c> against <paramref name="credentialIdBytes"/> over
    /// <paramref name="transceive"/>'s real transport and returns the decoded assertion's <c>signCount</c>.
    /// </summary>
    private static async Task<uint> PerformAssertionAndGetSignCountAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string pin, string rpId, byte[] credentialIdBytes,
        CancellationToken cancellationToken)
    {
        byte[] token = await IssueTokenAsync(
            transceive, pool, protocolId, pin, WellKnownCtapPinUvAuthTokenPermissions.Ga, rpId, cancellationToken).ConfigureAwait(false);
        byte[] pinUvAuthParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(
            token, protocolId, CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x20), pool, cancellationToken).ConfigureAwait(false);

        CredentialId credentialId = CredentialId.Create(credentialIdBytes, pool);
        CtapGetAssertionRequest request = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(
            pool, rpId: rpId, allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = credentialId }],
            pinUvAuthParam: pinUvAuthParam, pinUvAuthProtocol: (int)protocolId);

        CtapGetAssertionResponse response = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            transceive, CtapGetAssertionRequestCborWriter.Write, request, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(request);

        uint signCount;
        using(AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(response.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            signCount = authenticatorData.SignCount;
        }

        response.Credential.Id.Dispose();
        response.User?.Id.Dispose();

        return signCount;
    }


    /// <summary>
    /// Deletes the credential identified by <paramref name="credentialIdBytes"/> via
    /// <c>authenticatorCredentialManagement</c>'s <c>deleteCredential</c> subcommand, driven by a freshly
    /// issued single-use <c>cm</c>-permissioned token over <paramref name="transceive"/>'s real transport.
    /// </summary>
    private static async Task DeleteCredentialAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string pin, byte[] credentialIdBytes,
        CancellationToken cancellationToken)
    {
        byte[] token = await IssueTokenAsync(
            transceive, pool, protocolId, pin, WellKnownCtapPinUvAuthTokenPermissions.Cm, rpId: null, cancellationToken).ConfigureAwait(false);

        using CredentialId deleteId = CredentialId.Create(credentialIdBytes, pool);
        var descriptor = new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = deleteId };
        byte[] subCommandParams = CtapWaveCmFixtures.BuildSubCommandParams(credentialId: descriptor);
        byte[] message = CtapWaveCmFixtures.BuildMessage(WellKnownCtapCredentialManagementSubCommands.DeleteCredential, subCommandParams);
        byte[] param = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, cancellationToken).ConfigureAwait(false);

        var request = new CtapCredentialManagementRequest(
            SubCommand: WellKnownCtapCredentialManagementSubCommands.DeleteCredential,
            CredentialId: descriptor,
            PinUvAuthProtocol: (int)protocolId,
            PinUvAuthParam: param);

        byte[] envelope = CtapWaveCmFixtures.BuildCredentialManagementEnvelope(request);
        using PooledMemory response = await transceive(envelope, pool, cancellationToken).ConfigureAwait(false);

        byte statusCode = response.AsReadOnlySpan()[0];
        if(!WellKnownCtapStatusCodes.IsOk(statusCode))
        {
            throw new CtapCommandException(statusCode);
        }
    }
}
