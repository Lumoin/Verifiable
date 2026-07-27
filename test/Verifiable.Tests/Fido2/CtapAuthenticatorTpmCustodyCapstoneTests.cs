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
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.Tpm;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Extensions.Seal;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The wavect capstones for the TPM-backed CTAP authenticator state-custody adapter
/// (<see cref="TpmSealedStateCustody"/>, contract rulings R-7/R-8): ONE in-house <see cref="TpmSimulator"/>
/// instance plays the durable chip and OUTLIVES every <see cref="CtapAuthenticatorSimulator"/> instance
/// built against it — the CTAP "process death" this suite models is disposing simulator instance 1 and
/// constructing instance 2 from the SAME chip, the same loaded storage parent, the same <c>sealAuth</c>,
/// and the same caller-side blob store, exactly as a real device restart would reconnect to the SAME
/// physical TPM. Every assertion reads a wire-visible fact over the real, unmodified APDU transport
/// (<see cref="CtapWave2TransportHarness"/>) — never internal simulator or TPM state — mirroring
/// <see cref="CtapAuthenticatorResetFlowTests"/>'s and <see cref="TpmSealExtensionsTests"/>'s own
/// firewalled composition.
/// </summary>
/// <remarks>
/// <para>
/// <b>Explicitly deferred (contract R-9), recorded here rather than silently omitted:</b>
/// </para>
/// <list type="bullet">
///   <item><description>
///   <b>TPM-enforced CTAP PIN throttle.</b> A <c>TPM_NT_PIN_FAIL</c> NV index gives CTAP's pinRetries
///   throttle "at-limit refuses even the correct PIN" semantics for free, but CTAP's real retry model is
///   TWO-TIER (a boot-scoped 3-consecutive-mismatch latch on top of the lifetime 8-attempt pinRetries
///   ceiling) and the simulator's PIN_FAIL model has exactly ONE counter/limit pair — no single NV index
///   captures both tiers. This adapter seals the WHOLE snapshot (pinRetries included) as opaque bytes
///   instead; a genuinely TPM-enforced (not merely TPM-custodied) PIN throttle needs its own design round.
///   </description></item>
///   <item><description>
///   <b>signCount as a TPM NV counter index — CLOSED (wavenv, contract R-9).</b> The gap this paragraph
///   used to describe (<c>TPM2_NV_Increment</c> unimplemented) is no longer true: NV-counter-backed
///   signature-counter custody now ships OPT-IN via <see cref="CtapSignatureCounterCustody"/>/
///   <see cref="TpmNvSignatureCounterCustody"/>, a SIBLING seam this adapter still knows nothing about — it
///   continues to custody signCount as part of the sealed whole-snapshot blob exactly as before, since the
///   two seams compose independently. See <see cref="CtapAuthenticatorNvSignCounterCapstoneTests"/> for the
///   NV-backed capstones, including the flagship proof that a stale whole-snapshot restore (this adapter's
///   OWN failure mode, left otherwise unclosed) cannot roll a composed NV counter back.
///   </description></item>
///   <item><description>
///   <b>Durable cross-TPM-instance custody.</b> <c>TPM2_Create</c>'s <c>outPrivate</c> is this simulator's
///   own plaintext encoding with no real parent-key wrap or integrity protection (roadmap W3) — sound for
///   an in-process custody backend (this simulator's own <c>TPM2_Load</c> always recovers its own
///   encoding correctly) but NOT a durable, cross-chip-instance secret container: a sealed blob persisted
///   by ONE chip instance is only ever unsealable by that SAME chip instance for as long as it lives. Every
///   capstone below models exactly that scope — one chip, surviving across CTAP simulator instances, never
///   across a chip instance itself.
///   </description></item>
/// </list>
/// </remarks>
[TestClass]
internal sealed class CtapAuthenticatorTpmCustodyCapstoneTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Capstone (a): rehydration continuity. A PIN, a resident credential, a live assertion, a config
    /// change (<c>forcePINChange</c>/raised <c>minPinLength</c>), and a wrong-PIN attempt (as the LAST
    /// wire operation before death, so its drop is exactly what the persisted snapshot carries -- a
    /// SUBSEQUENT correct-PIN token issuance would itself reset <c>pinRetries</c> back to maximum, CTAP
    /// 2.3's own "a correct PIN entry resets the counter" rule) are all driven through simulator instance 1
    /// over the real APDU transport; instance 1 is then killed and instance 2 is rehydrated from the SAME
    /// chip/parent/<c>sealAuth</c>/blob store. Every ruling in contract R-8 item 1 is asserted from
    /// wire-visible facts: a bare <c>authenticatorGetNextAssertion</c> as the FIRST command on instance 2
    /// rejects (no remembered sequence resurrects), <c>pinRetries</c> and <c>minPinLength</c> carried,
    /// key-agreement material fresh (differs), the credential locatable and usable with <c>signCount</c>
    /// strictly continuing (1 -&gt; 2, never reset), and the reset power-up window re-armed.
    /// </summary>
    [TestMethod]
    public async Task RehydrationContinuityPreservesCredentialPinAndConfigOverRealApduTransport()
    {
        const string RpId = "tpm-custody-capstone-a.example";
        const string Pin = "1234";
        const string RaisedPin = "654321";
        const string RunId = "tpm-custody-capstone-a";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        Guid aaguid = Guid.NewGuid();
        byte[] sealAuth = "tpm-custody-capstone-a-seal-auth"u8.ToArray();

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("tpm-custody-capstone-a-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            var store = new DictionaryBackedTpmSealedSnapshotBlobStore();

            byte[] credentialIdBytes;
            int pinRetriesAfterMismatch;
            CoseKey protocolOneKeyAgreementBeforeDeath;

            CtapAuthenticatorSimulator simulator1 = await CtapWave2AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildCustody(tpm, parentHandle, sealAuth, store), aaguid, cancellationToken: cancellationToken).ConfigureAwait(false);
            using(CtapWave2TransportHarness harness1 = await CtapWave2TransportHarness.CreateAsync(simulator1, pool, cancellationToken).ConfigureAwait(false))
            {
                await EstablishPinAsync(harness1.Transceive, pool, protocolId, Pin, cancellationToken).ConfigureAwait(false);

                credentialIdBytes = await RegisterDiscoverableCredentialAsync(
                    harness1.Transceive, pool, protocolId, Pin, RpId, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xD0), cancellationToken)
                    .ConfigureAwait(false);

                uint signCountAfterFirstAssertion = await PerformAssertionAndGetSignCountAsync(
                    harness1.Transceive, pool, protocolId, Pin, RpId, credentialIdBytes, cancellationToken).ConfigureAwait(false);
                Assert.AreEqual(1u, signCountAfterFirstAssertion, "the first assertion before death must bump signCount from 0 to 1.");

                byte[] acfgToken = await IssueTokenAsync(
                    harness1.Transceive, pool, protocolId, Pin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, cancellationToken)
                    .ConfigureAwait(false);
                await SendSetMinPinLengthAsync(harness1.Transceive, pool, protocolId, acfgToken, newMinPinLength: 6, forceChangePin: true, cancellationToken)
                    .ConfigureAwait(false);

                await ChangePinAsync(harness1.Transceive, pool, protocolId, Pin, RaisedPin, cancellationToken).ConfigureAwait(false);

                protocolOneKeyAgreementBeforeDeath = await GetKeyAgreementAsync(harness1.Transceive, CtapPinUvAuthProtocolId.One, pool, cancellationToken)
                    .ConfigureAwait(false);

                //LAST wire operation on instance 1 before death: nothing after this presents a correct PIN,
                //so its dropped pinRetries value is exactly what the persisted snapshot (and instance 2's
                //own rehydration) must carry -- a subsequent correct-PIN token issuance (needed to arm any
                //further stateful sequence) would itself reset pinRetries to maximum first, erasing the
                //very fact this step exists to prove.
                await AttemptWrongPinAsync(harness1.Transceive, pool, protocolId, cancellationToken).ConfigureAwait(false);
                pinRetriesAfterMismatch = await GetPinRetriesAsync(harness1.Transceive, pool, cancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    CtapAuthenticatorState.MaxPinRetries - 1, pinRetriesAfterMismatch,
                    "the wrong-PIN attempt must drop pinRetries by one before death, observed on the wire.");
            }

            simulator1.Dispose();

            Assert.IsTrue(store.HasSealedBlob(RunId), "instance 1's own commands must have persisted a TPM-sealed snapshot before it died.");

            CtapAuthenticatorSimulator simulator2 = await CtapWave2AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildCustody(tpm, parentHandle, sealAuth, store), aaguid, cancellationToken: cancellationToken).ConfigureAwait(false);
            using(CtapWave2TransportHarness harness2 = await CtapWave2TransportHarness.CreateAsync(simulator2, pool, cancellationToken).ConfigureAwait(false))
            {
                //FIRST wire command on instance 2: a remembered authenticatorGetAssertion sequence is
                //volatile (contract R-2 excludes it from the snapshot by construction, never even read by
                //the encoder) and so cannot resurrect after rehydration -- this is the wire-level regression
                //proof of that fact, checked before any other command could itself have discarded one.
                using(PooledMemory getNextAssertionResponse = await SendGetNextAssertionAsync(harness2.Transceive, pool, cancellationToken).ConfigureAwait(false))
                {
                    Assert.AreEqual(
                        WellKnownCtapStatusCodes.NotAllowed, getNextAssertionResponse.AsReadOnlySpan()[0],
                        "a remembered getAssertion sequence must never resurrect after TPM-backed rehydration, on the wire.");
                }

                int pinRetriesAfterRehydrate = await GetPinRetriesAsync(harness2.Transceive, pool, cancellationToken).ConfigureAwait(false);
                Assert.AreEqual(pinRetriesAfterMismatch, pinRetriesAfterRehydrate, "pinRetries must carry across TPM-backed rehydration.");

                CtapGetInfoResponse infoAfterRehydrate = await GetInfoAsync(harness2.Transceive, pool, cancellationToken).ConfigureAwait(false);
                Assert.AreEqual(6, infoAfterRehydrate.MinPinLength, "the raised minPinLength must carry across TPM-backed rehydration.");

                CoseKey protocolOneKeyAgreementAfterRehydrate = await GetKeyAgreementAsync(harness2.Transceive, CtapPinUvAuthProtocolId.One, pool, cancellationToken)
                    .ConfigureAwait(false);
                Assert.IsFalse(
                    protocolOneKeyAgreementBeforeDeath.X!.Value.Span.SequenceEqual(protocolOneKeyAgreementAfterRehydrate.X!.Value.Span),
                    "rehydration must mint fresh key-agreement material, never carry the dead instance's own pair forward.");

                uint signCountAfterRehydrate = await PerformAssertionAndGetSignCountAsync(
                    harness2.Transceive, pool, protocolId, RaisedPin, RpId, credentialIdBytes, cancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    2u, signCountAfterRehydrate,
                    "the credential minted by instance 1 must remain locatable and usable after TPM-backed rehydration, and signCount must strictly continue (1 -> 2), never reset.");

                using PooledMemory resetResponse = await SendResetAsync(harness2.Transceive, pool, cancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0],
                    "the reset power-up window must be re-armed immediately after TPM-backed rehydration, on the wire.");
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
    /// Capstone (b): <c>authenticatorReset</c> wipes TPM-backed custody. A successful reset must drive
    /// <see cref="WipeSnapshotAsyncDelegate"/> — observed directly on the blob-store double, the fact
    /// package A's own in-process reset test cannot observe — and the rehydrated instance 2 must be
    /// factory-fresh on the wire: birth-byte <c>getInfo</c> equality, the pre-reset credential unlocatable,
    /// <c>pinRetries</c> at maximum, and the PIN unset (a fresh <c>setPIN</c> succeeds).
    /// </summary>
    [TestMethod]
    public async Task AuthenticatorResetWipesTpmBackedCustodyOverRealApduTransport()
    {
        const string RpId = "tpm-custody-capstone-b.example";
        const string Pin = "1234";
        const string RunId = "tpm-custody-capstone-b";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        Guid aaguid = Guid.NewGuid();
        byte[] sealAuth = "tpm-custody-capstone-b-seal-auth"u8.ToArray();

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("tpm-custody-capstone-b-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            var store = new DictionaryBackedTpmSealedSnapshotBlobStore();

            byte[] birthGetInfoBytes;
            byte[] credentialIdBytes;

            CtapAuthenticatorSimulator simulator1 = await CtapWave2AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildCustody(tpm, parentHandle, sealAuth, store), aaguid, cancellationToken: cancellationToken).ConfigureAwait(false);
            using(CtapWave2TransportHarness harness1 = await CtapWave2TransportHarness.CreateAsync(simulator1, pool, cancellationToken).ConfigureAwait(false))
            {
                birthGetInfoBytes = await GetInfoBytesAsync(harness1.Transceive, pool, cancellationToken).ConfigureAwait(false);

                await EstablishPinAsync(harness1.Transceive, pool, protocolId, Pin, cancellationToken).ConfigureAwait(false);
                credentialIdBytes = await RegisterDiscoverableCredentialAsync(
                    harness1.Transceive, pool, protocolId, Pin, RpId, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xE0), cancellationToken)
                    .ConfigureAwait(false);

                Assert.IsTrue(store.HasSealedBlob(RunId), "the PIN establishment and mint must have persisted a TPM-sealed snapshot.");

                using PooledMemory resetResponse = await SendResetAsync(harness1.Transceive, pool, cancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0], "authenticatorReset must succeed within the power-up window.");

                Assert.IsFalse(
                    store.HasSealedBlob(RunId),
                    "a successful authenticatorReset must drive the custody wipe delegate -- the TPM-sealed blob store must observe the snapshot gone.");
            }

            simulator1.Dispose();

            CtapAuthenticatorSimulator simulator2 = await CtapWave2AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildCustody(tpm, parentHandle, sealAuth, store), aaguid, cancellationToken: cancellationToken).ConfigureAwait(false);
            using(CtapWave2TransportHarness harness2 = await CtapWave2TransportHarness.CreateAsync(simulator2, pool, cancellationToken).ConfigureAwait(false))
            {
                byte[] postResetGetInfoBytes = await GetInfoBytesAsync(harness2.Transceive, pool, cancellationToken).ConfigureAwait(false);
                Assert.AreSequenceEqual(
                    birthGetInfoBytes, postResetGetInfoBytes, "post-reset, post-rehydrate getInfo bytes must be byte-identical to the birth capture.");

                CtapGetAssertionRequest staleGaRequest = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(
                    pool, rpId: RpId,
                    allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(credentialIdBytes, pool) }]);
                CtapCommandException staleGaException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
                    CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
                        harness2.Transceive, CtapGetAssertionRequestCborWriter.Write, staleGaRequest, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken)
                        .AsTask());
                CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(staleGaRequest);
                Assert.AreEqual(
                    WellKnownCtapStatusCodes.NoCredentials, staleGaException.StatusCode,
                    "a pre-reset credential must not be locatable after a wiped-and-rehydrated instance, on the wire.");

                Assert.AreEqual(
                    CtapAuthenticatorState.MaxPinRetries, await GetPinRetriesAsync(harness2.Transceive, pool, cancellationToken).ConfigureAwait(false),
                    "pinRetries must be at maximum on a wiped-and-rehydrated instance.");

                //A fresh setPIN only succeeds when no PIN is currently set -- the wire proof that the PIN
                //was genuinely cleared, not merely inaccessible.
                await EstablishPinAsync(harness2.Transceive, pool, protocolId, "1234", cancellationToken).ConfigureAwait(false);
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
    /// Capstone (c): first boot (no snapshot ever stored) behaves identically to
    /// <see cref="CtapAuthenticatorState.Initial"/> — byte-identical <c>getInfo</c> against an ordinary,
    /// custody-free oracle simulator sharing the same personalization, <c>pinRetries</c> at maximum, and
    /// the blob store's own fetch was actually invoked (proving the adapter really asked) yet recorded
    /// zero hits (proving nothing was ever found), contract R-1's "no snapshot present ⇒ Initial."
    /// </summary>
    [TestMethod]
    public async Task FirstBootWithNoStoredSnapshotIsFactoryFreshAndObservesZeroFetchHits()
    {
        const string RunId = "tpm-custody-capstone-c";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        Guid aaguid = Guid.NewGuid();
        byte[] sealAuth = "tpm-custody-capstone-c-seal-auth"u8.ToArray();

        byte[] oracleGetInfoBytes;
        using(CtapAuthenticatorSimulator oracleSimulator = CtapWave2AuthenticatorFixtures.CreateSimulator(RunId + "-oracle", aaguid: aaguid))
        using(CtapWave2TransportHarness oracleHarness = await CtapWave2TransportHarness.CreateAsync(oracleSimulator, pool, cancellationToken).ConfigureAwait(false))
        {
            oracleGetInfoBytes = await GetInfoBytesAsync(oracleHarness.Transceive, pool, cancellationToken).ConfigureAwait(false);
        }

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("tpm-custody-capstone-c-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            var store = new DictionaryBackedTpmSealedSnapshotBlobStore();
            Assert.IsFalse(store.HasSealedBlob(RunId), "nothing must ever have been stored for a first-boot run id.");

            CtapAuthenticatorSimulator simulator = await CtapWave2AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildCustody(tpm, parentHandle, sealAuth, store), aaguid, cancellationToken: cancellationToken).ConfigureAwait(false);
            using(CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false))
            {
                byte[] firstBootGetInfoBytes = await GetInfoBytesAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false);
                Assert.AreSequenceEqual(
                    oracleGetInfoBytes, firstBootGetInfoBytes,
                    "a custody-composed first boot (no snapshot ever stored) must be byte-identical to an ordinary, custody-free Initial boot.");

                Assert.AreEqual(
                    CtapAuthenticatorState.MaxPinRetries, await GetPinRetriesAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false),
                    "pinRetries must be at maximum on a genuine first boot.");
            }

            simulator.Dispose();

            Assert.IsGreaterThanOrEqualTo(1, store.FetchCallCount, "the adapter must actually have asked the blob store whether a snapshot exists.");
            Assert.AreEqual(0, store.FetchHitCount, "a genuine first boot must observe zero fetch-hits -- nothing was ever found.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(parentHandle, cancellationToken).ConfigureAwait(false);
            tpm.Dispose();
        }
    }


    /// <summary>
    /// Capstone (d.1): a tampered sealed-blob byte sequence in the store fails rehydration closed. The
    /// TPM2B_PRIVATE length prefix (the first two wire bytes of the serialized sealed blob) is corrupted to
    /// declare far more octets than the buffer actually holds, so <see cref="TpmSealedBlob.Parse"/> itself
    /// rejects it (TPM 2.0 Library Part 2, Section 12.3.7's own framing check) -- <see cref="TpmSealedStateCustody"/>
    /// wraps that into a <see cref="TpmSealedStateCustodyException"/> rather than a partially restored
    /// snapshot. Restoring the original bytes afterward and proving a fresh <c>setPIN</c> against the
    /// recovered instance still fails (a PIN is already set) shows the failed attempt left the chip/store
    /// exactly as it was, with no partial state.
    /// </summary>
    [TestMethod]
    public async Task TamperedSealedBlobBytesFailCloseWithNoPartialState()
    {
        const string RunId = "tpm-custody-capstone-d1";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        Guid aaguid = Guid.NewGuid();
        byte[] sealAuth = "tpm-custody-capstone-d1-seal-auth"u8.ToArray();

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("tpm-custody-capstone-d1-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            var store = new DictionaryBackedTpmSealedSnapshotBlobStore();

            CtapAuthenticatorSimulator simulator1 = await CtapWave2AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildCustody(tpm, parentHandle, sealAuth, store), aaguid, cancellationToken: cancellationToken).ConfigureAwait(false);
            using(CtapWave2TransportHarness harness1 = await CtapWave2TransportHarness.CreateAsync(simulator1, pool, cancellationToken).ConfigureAwait(false))
            {
                await EstablishPinAsync(harness1.Transceive, pool, protocolId, "1234", cancellationToken).ConfigureAwait(false);
            }

            simulator1.Dispose();
            Assert.IsTrue(store.HasSealedBlob(RunId), "the PIN establishment must have persisted a TPM-sealed snapshot before death.");

            byte[] originalBytes = store.GetStoredBytesCopy(RunId);
            byte[] corrupted = (byte[])originalBytes.Clone();
            corrupted[0] = 0xFF;
            corrupted[1] = 0xFF;
            store.ReplaceStoredBytes(RunId, corrupted);

            TpmSealedStateCustodyException exception = await Assert.ThrowsExactlyAsync<TpmSealedStateCustodyException>(() =>
                CtapWave2AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                    RunId, BuildCustody(tpm, parentHandle, sealAuth, store), aaguid, cancellationToken: cancellationToken).AsTask());
            Assert.IsTrue(
                exception.Message.Contains("did not parse", StringComparison.OrdinalIgnoreCase),
                $"the exception message should name the parse failure; was: '{exception.Message}'.");

            //No partial state: restoring the original bytes still rehydrates cleanly, and the recovered
            //PIN is intact (a fresh setPIN against an ALREADY-set PIN fails) -- the failed tampered attempt
            //corrupted nothing else in the chip or the store.
            store.ReplaceStoredBytes(RunId, originalBytes);

            CtapAuthenticatorSimulator simulator2 = await CtapWave2AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildCustody(tpm, parentHandle, sealAuth, store), aaguid, cancellationToken: cancellationToken).ConfigureAwait(false);
            using(CtapWave2TransportHarness harness2 = await CtapWave2TransportHarness.CreateAsync(simulator2, pool, cancellationToken).ConfigureAwait(false))
            {
                CtapCommandException repeatSetPinException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
                    EstablishPinAsync(harness2.Transceive, pool, protocolId, "1234", cancellationToken));
                Assert.AreEqual(
                    WellKnownCtapStatusCodes.PinAuthInvalid, repeatSetPinException.StatusCode,
                    "the recovered instance must still have its original PIN set (setPIN against an already-set PIN fails) -- the tampered attempt left no partial state.");
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
    /// Capstone (d.2): the wrong <c>sealAuth</c> on the adapter fails rehydration closed identically. The
    /// TPM itself rejects the <c>TPM2_Unseal</c> (a non-success <see cref="TpmResult{T}"/>), which
    /// <see cref="TpmSealedStateCustody"/> surfaces as a <see cref="TpmSealedStateCustodyException"/>
    /// rather than an empty snapshot; the stored sealed blob is left untouched, and a subsequent rehydrate
    /// under the CORRECT <c>sealAuth</c> still recovers the original PIN intact.
    /// </summary>
    [TestMethod]
    public async Task WrongSealAuthFailsClosedWithNoPartialState()
    {
        const string RunId = "tpm-custody-capstone-d2";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;
        Guid aaguid = Guid.NewGuid();
        byte[] correctSealAuth = "tpm-custody-capstone-d2-correct-seal-auth"u8.ToArray();
        byte[] wrongSealAuth = "tpm-custody-capstone-d2-wrong-seal-auth"u8.ToArray();

        (TpmDevice tpm, uint parentHandle) = await CreateChipWithLoadedStorageParentAsync("tpm-custody-capstone-d2-chip", cancellationToken).ConfigureAwait(false);
        try
        {
            var store = new DictionaryBackedTpmSealedSnapshotBlobStore();

            CtapAuthenticatorSimulator simulator1 = await CtapWave2AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildCustody(tpm, parentHandle, correctSealAuth, store), aaguid, cancellationToken: cancellationToken).ConfigureAwait(false);
            using(CtapWave2TransportHarness harness1 = await CtapWave2TransportHarness.CreateAsync(simulator1, pool, cancellationToken).ConfigureAwait(false))
            {
                await EstablishPinAsync(harness1.Transceive, pool, protocolId, "1234", cancellationToken).ConfigureAwait(false);
            }

            simulator1.Dispose();
            Assert.IsTrue(store.HasSealedBlob(RunId), "the PIN establishment must have persisted a TPM-sealed snapshot before death.");

            TpmSealedStateCustodyException exception = await Assert.ThrowsExactlyAsync<TpmSealedStateCustodyException>(() =>
                CtapWave2AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                    RunId, BuildCustody(tpm, parentHandle, wrongSealAuth, store), aaguid, cancellationToken: cancellationToken).AsTask());
            Assert.IsTrue(
                exception.Message.Contains("Unsealing", StringComparison.Ordinal),
                $"the exception message should name the failed unseal; was: '{exception.Message}'.");

            Assert.IsTrue(store.HasSealedBlob(RunId), "a failed wrong-sealAuth rehydration attempt must not wipe or alter the stored sealed blob.");

            CtapAuthenticatorSimulator simulator2 = await CtapWave2AuthenticatorFixtures.CreateSimulatorWithCustodyAsync(
                RunId, BuildCustody(tpm, parentHandle, correctSealAuth, store), aaguid, cancellationToken: cancellationToken).ConfigureAwait(false);
            using(CtapWave2TransportHarness harness2 = await CtapWave2TransportHarness.CreateAsync(simulator2, pool, cancellationToken).ConfigureAwait(false))
            {
                CtapCommandException repeatSetPinException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
                    EstablishPinAsync(harness2.Transceive, pool, protocolId, "1234", cancellationToken));
                Assert.AreEqual(
                    WellKnownCtapStatusCodes.PinAuthInvalid, repeatSetPinException.StatusCode,
                    "the recovered instance (under the correct sealAuth) must still have its original PIN set -- the wrong-sealAuth attempt left no partial state.");
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
    /// Builds a <see cref="CtapStateCustody"/> bundle backed by <paramref name="tpm"/>'s already-loaded
    /// storage parent, <paramref name="sealAuth"/>, and <paramref name="store"/>'s three delegates --
    /// called fresh for every simulator construction, exactly as a real process reconnecting to the same
    /// chip would rebuild its own composition anew.
    /// </summary>
    /// <param name="tpm">The TPM device to seal to and unseal from.</param>
    /// <param name="parentHandle">The already-loaded storage parent's handle.</param>
    /// <param name="sealAuth">The authorization value every snapshot is sealed under.</param>
    /// <param name="store">The blob-store double this bundle's three delegates are bound to.</param>
    /// <returns>The composed seam-bundle record.</returns>
    private static CtapStateCustody BuildCustody(
        TpmDevice tpm, uint parentHandle, ReadOnlyMemory<byte> sealAuth, DictionaryBackedTpmSealedSnapshotBlobStore store) =>
        TpmSealedStateCustody.Create(
            tpm, parentHandle, ReadOnlyMemory<byte>.Empty, sealAuth,
            store.TryFetchSealedBlobAsync, store.StoreSealedBlobAsync, store.DeleteSealedBlobAsync);


    /// <summary>
    /// Brings up a fresh in-house simulated TPM ("the durable chip") and one loaded ECC storage parent --
    /// the one long-lived TPM identity every capstone test method seals custody snapshots under. The
    /// caller owns the returned <see cref="TpmDevice"/> and flushes <paramref name="chipRunId"/>'s
    /// parent/disposes the device once done with the chip; the underlying <see cref="TpmSimulator"/>
    /// itself needs no disposal (it is not <see cref="IDisposable"/>, mirroring every other TPM flow test
    /// in this suite).
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


    /// <summary>Sends a bare <c>authenticatorGetNextAssertion</c> request over <paramref name="transceive"/>, returning the raw response envelope.</summary>
    private static ValueTask<PooledMemory> SendGetNextAssertionAsync(Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] request = [WellKnownCtapCommands.GetNextAssertion];

        return transceive(request, pool, cancellationToken);
    }


    /// <summary>Sends a bare <c>authenticatorGetInfo</c> request over <paramref name="transceive"/> and returns the raw response bytes.</summary>
    private static async Task<byte[]> GetInfoBytesAsync(Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] request = [WellKnownCtapCommands.GetInfo];
        using PooledMemory response = await transceive(request, pool, cancellationToken).ConfigureAwait(false);

        return response.AsReadOnlySpan().ToArray();
    }


    /// <summary>Sends a bare <c>authenticatorGetInfo</c> request over <paramref name="transceive"/> and decodes the response.</summary>
    private static async Task<CtapGetInfoResponse> GetInfoAsync(Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] request = [WellKnownCtapCommands.GetInfo];
        using PooledMemory response = await transceive(request, pool, cancellationToken).ConfigureAwait(false);

        return CtapGetInfoResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
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
    /// Changes the authenticator's PIN from <paramref name="oldPin"/> to <paramref name="newPin"/> via
    /// <c>changePIN</c> over <paramref name="transceive"/>'s real transport.
    /// </summary>
    private static async Task ChangePinAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string oldPin, string newPin,
        CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(transceive, protocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        (byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam) =
            await session.BuildChangePinMessagesAsync(newPin, oldPin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.ChangePin, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc, PinHashEnc: pinHashEnc);

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
    /// Sends <c>setMinPINLength</c> with an already-issued <paramref name="token"/> over
    /// <paramref name="transceive"/>'s real transport, computing the platform-side <c>pinUvAuthParam</c>
    /// over the SAME <c>subCommandParams</c> bytes the request will carry.
    /// </summary>
    private static async Task SendSetMinPinLengthAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, byte[] token, int newMinPinLength, bool forceChangePin,
        CancellationToken cancellationToken)
    {
        byte[] subCommandParams = CtapWaveConfigFixtures.BuildSubCommandParams(newMinPinLength: newMinPinLength, forceChangePin: forceChangePin);
        byte[] message = CtapWaveConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength, subCommandParams);
        byte[] param = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, cancellationToken).ConfigureAwait(false);

        var request = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength, NewMinPinLength: newMinPinLength, ForceChangePin: forceChangePin,
            PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: param);

        byte[] envelope = CtapWaveConfigFixtures.BuildAuthenticatorConfigEnvelope(request);
        using PooledMemory response = await transceive(envelope, pool, cancellationToken).ConfigureAwait(false);

        byte statusCode = response.AsReadOnlySpan()[0];
        if(!WellKnownCtapStatusCodes.IsOk(statusCode))
        {
            throw new CtapCommandException(statusCode);
        }
    }


    /// <summary>Reads the current <c>pinRetries</c> value via <c>getPINRetries</c> over <paramref name="transceive"/>'s real transport.</summary>
    private static async Task<int> GetPinRetriesAsync(Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetPinRetries);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);

        return response.PinRetries!.Value;
    }


    /// <summary>Reads a protocol's current key-agreement public key via <c>getKeyAgreement</c> over <paramref name="transceive"/>'s real transport.</summary>
    private static async Task<CoseKey> GetKeyAgreementAsync(
        Ctap2TransceiveDelegate transceive, CtapPinUvAuthProtocolId protocolId, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetKeyAgreement, PinUvAuthProtocol: (int)protocolId);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);

        return response.KeyAgreement!;
    }


    /// <summary>
    /// Attempts <c>getPinToken</c> with a deliberately wrong <c>pinHashEnc</c> over
    /// <paramref name="transceive"/>'s real transport, asserting the call fails -- the mismatch drops
    /// <c>pinRetries</c> by one regardless of the outcome status.
    /// </summary>
    private static async Task AttemptWrongPinAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(transceive, protocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        byte[] wrongPinHashEnc = await session.BuildWrongPinHashEncAsync(cancellationToken).ConfigureAwait(false);
        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: wrongPinHashEnc);

        _ = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorClientPinClient.ClientPinAsync(
                transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).AsTask());
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
}
