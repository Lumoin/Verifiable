using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Pins <see cref="TransientKeyState.PublicPoint"/>'s ownership on persist: <c>TPM2_EvictControl()</c>'s persist
/// arm deep-copies the exported public point into a fresh pooled <see cref="EncodedEcPoint"/> rather than
/// aliasing the transient entry's own buffer, so flushing the transient copy (<c>TPM2_FlushContext()</c>, which
/// disposes and returns its pooled rental) leaves the persistent copy's point intact and usable.
/// </summary>
/// <remarks>
/// A persistent entry that merely aliased the transient's buffer would read released (and, under pool reuse,
/// overwritten) memory once the transient is flushed, which is why the persist arm copies the point.
/// <c>TPM2_StartAuthSession()</c>'s
/// ECC-salted arm is the load-bearing proof here — it is the one production path that reads a resolved object's
/// <see cref="TransientKeyState.PublicPoint"/> for a cryptographic computation (the TPM-side ECDH shared-secret
/// recovery, TPM 2.0 Library Part 1, clause 44.7.1) rather than merely re-exporting <c>PublicArea</c> (which
/// <c>TPM2_ReadPublic()</c> alone would exercise): a genuine <see cref="TpmSession"/> built from the SAME point
/// the client used at key creation only signs/verifies correctly if the simulator derived the identical session
/// key from the identical point octets, so a stale, zeroed, or reused buffer surfaces as either an outright
/// command failure or a session-key mismatch on the first encrypted command over it — never a silent pass.
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorEccPointCarrierTests
{
    /// <summary>The session hash algorithm the tests negotiate.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>Every ECC storage-parent-shaped template this simulator builds fixes nameAlg to SHA-256.</summary>
    private const TpmAlgIdConstants TpmKeyNameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The owner-hierarchy persistent handle (range 0x81000000-0x817FFFFF) used to persist the test key.</summary>
    private const uint PersistentHandle = 0x8100_0020;

    /// <summary>The persistent handle a persisted endorsement-key stand-in occupies for the credential-activation proof.</summary>
    private const uint PersistedEndorsementHandle = 0x8100_0201;

    /// <summary>The persistent handle the EvictControl persist-then-evict pool-balance proof occupies.</summary>
    private const uint EvictControlBalanceHandle = 0x8100_0202;

    /// <summary>The width of a P-256 coordinate, in octets.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The width of a SEC1 uncompressed P-256 point (<c>0x04 ‖ X ‖ Y</c>), in octets — the exact rental size <see cref="EncodedEcPoint.FromBytes"/> requests for a P-256 <see cref="TransientKeyState.PublicPoint"/>.</summary>
    private const int Sec1P256PointLength = 1 + (2 * P256ComponentSize);

    /// <summary>The secret a MakeCredential/ActivateCredential round trip wraps and recovers.</summary>
    private static byte[] CredentialSecret { get; } =
        [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF];

    /// <summary>The secret a sealed object exported and imported under a new ECC parent carries.</summary>
    private static byte[] MigratedSecretBytes { get; } = "Import me under a fresh ECC storage parent."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Persists an ECC decrypt key, flushes its transient handle, reads its public area back through the
    /// persistent handle (<c>TPM2_ReadPublic()</c> — proving the persist itself took effect), then starts a
    /// salted, unbound HMAC session against the SAME persistent handle and round-trips one encrypted
    /// <c>TPM2_GetRandom()</c> over it: the host derives the session key from the point it read off the
    /// CreatePrimary response, and the simulator derives it from <see cref="TransientKeyState.PublicPoint"/> on
    /// the resolved PERSISTENT record — a success proves that record's point carries the original octets, not a
    /// released or reused buffer left behind by the transient's flush.
    /// </summary>
    [TestMethod]
    public async Task PersistedEccKeysPublicPointSurvivesTheTransientsFlush()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        ReadOnlyMemory<byte> point = ExtractEccPoint(primary);
        uint transientHandle = primary.ObjectHandle.Value;

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, transientHandle, PersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        await FlushAsync(tpm, registry, pool, transientHandle).ConfigureAwait(false);

        TpmResult<ReadPublicResponse> readPublicResult = await ReadPublicAsync(tpm, registry, pool, PersistentHandle).ConfigureAwait(false);
        Assert.IsTrue(readPublicResult.IsSuccess, $"TPM2_ReadPublic() over the persistent handle failed after the transient's flush: '{readPublicResult.ResponseCode}'.");
        readPublicResult.Value.Dispose();

        TpmEccSigningBackend eccBackend = BouncyCastleTpmEccSigningBackend.Create();

        (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, int saltLength) = await StartAuthSessionInputExtensions.CreateSaltedHmacSession(
            PersistentHandle, point, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmKeyNameAlg, SessionAlg,
            eccBackend.GenerateKey, eccBackend.ComputeSharedSecret, TestEntropy.NewCounterStream(), pool, TestContext.CancellationToken,
            symmetric: TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)).ConfigureAwait(false);

        using(salt)
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess,
                $"StartAuthSession (salted, over the PERSISTENT handle) failed: '{startResult.ResponseCode}'. A failure here means the persisted record's PublicPoint did not survive the transient's flush.");
            StartAuthSessionResponse startResponse = startResult.Value;

            using TpmSession session = await TpmSession.CreateBoundAsync(
                new TpmHandle(startResponse.SessionHandle.Value), ReadOnlyMemory<byte>.Empty, startInput.NonceCaller, startResponse.NonceTPM,
                SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric: TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), salt: salt.Memory[..saltLength], cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

            try
            {
                var getRandomInput = new GetRandomInput(16);
                TpmResult<GetRandomResponse> randomResult = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    tpm, getRandomInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(randomResult.IsSuccess,
                    $"Encrypted GetRandom over the persisted key's salted session failed: '{randomResult.ResponseCode}'. A failure means the host (working from the client-side point) and the simulator (working from the persisted record's PublicPoint) derived different session keys — the alias defect's signature.");
                randomResult.Value.Dispose();
            }
            finally
            {
                var flush = FlushContextInput.ForHandle(startResponse.SessionHandle.Value);
                _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                    tpm, flush, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// A persisted ECC key MAKES a credential — <c>TPM2_MakeCredential()</c> reads only its public area — and
    /// then ACTIVATES it after its transient copy is flushed: <c>TPM2_ActivateCredential()</c>'s seed recovery
    /// reads the resolved credential key's <see cref="TransientKeyState.PublicPoint"/> for the KDFe shared-secret
    /// derivation (TPM 2.0 Library Part 1, clause 21), so a persisted record whose point did not survive the
    /// transient's flush would derive the wrong seed and fail the outer-HMAC integrity check rather than recover
    /// the wrapped secret.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.6</see>.
    /// </summary>
    [TestMethod]
    public async Task PersistedEndorsementKeyMakesAndActivatesACredentialAfterItsTransientIsFlushed()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse endorsement = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint transientHandle = endorsement.ObjectHandle.Value;

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, transientHandle, PersistedEndorsementHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");
        await FlushAsync(tpm, registry, pool, transientHandle).ConfigureAwait(false);

        using CreatePrimaryResponse attestKey = await CreateEccSigningKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            var persistedEndorsement = TpmiDhObject.FromValue(PersistedEndorsementHandle);
            using MakeCredentialInput makeInput = MakeCredentialInput.Create(persistedEndorsement, CredentialSecret, attestKey.Name.Span.ToArray(), pool);
            TpmResult<MakeCredentialResponse> makeResult = await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
                tpm, makeInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(makeResult.IsSuccess, $"TPM2_MakeCredential() over the PERSISTENT endorsement handle failed: '{makeResult.ResponseCode}'.");
            using MakeCredentialResponse made = makeResult.Value;

            using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                attestKey.ObjectHandle, persistedEndorsement, made.CredentialBlob.Span, made.Secret.Span, pool);
            using TpmPasswordSession activateAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(pool);
            TpmResult<ActivateCredentialResponse> activateResult = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                tpm, activateInput, [activateAuth, keyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                activateResult.IsSuccess,
                $"TPM2_ActivateCredential() over the PERSISTENT endorsement handle failed: '{activateResult.ResponseCode}'. A failure here means the persisted record's PublicPoint did not survive the transient's flush.");

            using ActivateCredentialResponse activated = activateResult.Value;
            Assert.IsTrue(
                activated.CertInfo.AsReadOnlySpan().SequenceEqual(CredentialSecret),
                "The recovered credential must equal the secret TPM2_MakeCredential wrapped against the persisted endorsement key's public point.");
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, attestKey.ObjectHandle.Value).ConfigureAwait(false);
            _ = await TpmEvictControlHarness.EvictControlAsync(
                tpm, registry, pool, PersistedEndorsementHandle, PersistedEndorsementHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "The encrypted data blob contains the data necessary to reconstruct the full object or session context in
    /// the TPM" (TPM 2.0 Library Part 1, clause 27.2.1) extended to the point: an ECC key restored at a NEW
    /// transient handle through <c>TPM2_ContextSave()</c>/<c>TPM2_ContextLoad()</c> starts a salted, unbound HMAC
    /// session over that reloaded handle and round-trips one encrypted <c>TPM2_GetRandom()</c> — the context
    /// load must have reconstructed the point byte-exact, or the host and the simulator derive different session
    /// keys and the encrypted round trip fails.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task EccKeyRestoredThroughAContextRoundTripStartsASaltedSessionAndDecryptsAnEncryptedGetRandom()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        ReadOnlyMemory<byte> point = ExtractEccPoint(primary);
        uint originalHandle = primary.ObjectHandle.Value;

        using ContextSaveResponse saveResponse = await SaveContextAsync(tpm, registry, pool, originalHandle).ConfigureAwait(false);
        uint restoredHandle = await LoadContextAsync(tpm, registry, pool, saveResponse.Context).ConfigureAwait(false);
        Assert.AreNotEqual(originalHandle, restoredHandle, "An object load draws a NEW transient handle (TPM 2.0 Library Part 1, clause 27.4).");
        await FlushAsync(tpm, registry, pool, originalHandle).ConfigureAwait(false);

        TpmEccSigningBackend eccBackend = BouncyCastleTpmEccSigningBackend.Create();
        (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, int saltLength) = await StartAuthSessionInputExtensions.CreateSaltedHmacSession(
            restoredHandle, point, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmKeyNameAlg, SessionAlg,
            eccBackend.GenerateKey, eccBackend.ComputeSharedSecret, TestEntropy.NewCounterStream(), pool, TestContext.CancellationToken,
            symmetric: TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)).ConfigureAwait(false);

        using(salt)
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (salted, over the RELOADED handle) failed: '{startResult.ResponseCode}'.");
            StartAuthSessionResponse startResponse = startResult.Value;

            using TpmSession session = await TpmSession.CreateBoundAsync(
                new TpmHandle(startResponse.SessionHandle.Value), ReadOnlyMemory<byte>.Empty, startInput.NonceCaller, startResponse.NonceTPM,
                SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric: TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB), salt: salt.Memory[..saltLength], cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
            try
            {
                var getRandomInput = new GetRandomInput(16);
                TpmResult<GetRandomResponse> randomResult = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    tpm, getRandomInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(
                    randomResult.IsSuccess,
                    $"Encrypted GetRandom over the RELOADED handle's salted session failed: '{randomResult.ResponseCode}'. A failure means the serializer did not reconstruct the point byte-exact.");
                randomResult.Value.Dispose();
            }
            finally
            {
                var flush = FlushContextInput.ForHandle(startResponse.SessionHandle.Value);
                _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                    tpm, flush, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }

        await FlushAsync(tpm, registry, pool, restoredHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_Import()</c>'s ECC arm reads its new parent's resolved <see cref="TransientKeyState.PublicPoint"/>
    /// X coordinate to derive the seed-transport KDFe input: importing a duplicated sealed object under a fresh
    /// ECC storage parent, then loading and unsealing it there, exercises that slice end to end — a wrong or
    /// stale parent point derives the wrong seed and the outer-HMAC integrity check refuses the import.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 13.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ImportUnderAFreshEccStorageParentConsumesTheParentsPointXSlice()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse sourceParent = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint objectHandle, byte[] objectName, byte[] publicOctets) = await CreateAndLoadDuplicableSealedObjectAsync(
            tpm, registry, pool, sourceParent.ObjectHandle.Value).ConfigureAwait(false);

        using CreatePrimaryResponse destinationParent = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint destinationHandle = destinationParent.ObjectHandle.Value;
        byte[] destinationName = destinationParent.Name.Span.ToArray();

        uint policySessionHandle = await StartRealPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] duplicate;
        byte[] outSymSeed;
        try
        {
            await AssertCommandCodeAsync(tpm, registry, pool, policySessionHandle, TpmCcConstants.TPM_CC_Duplicate).ConfigureAwait(false);

            var duplicateInput = new DuplicateInput(objectHandle, destinationHandle);
            using TpmPolicySession policySession = TpmPolicySession.ForSession(policySessionHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);
            TpmResult<DuplicateResponse> duplicateResult = await TpmCommandExecutor.ExecuteAsync<DuplicateResponse>(
                tpm, duplicateInput, [policySession], [objectName, destinationName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(duplicateResult.IsSuccess, $"TPM2_Duplicate() failed: '{duplicateResult.ResponseCode}'.");
            using DuplicateResponse duplicated = duplicateResult.Value;
            duplicate = duplicated.Duplicate.Span.ToArray();
            outSymSeed = duplicated.OutSymSeed.Span.ToArray();
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, policySessionHandle).ConfigureAwait(false);
        }

        using ImportInput importInput = ImportInput.Create(destinationHandle, publicOctets, duplicate, outSymSeed, pool);
        using TpmPasswordSession importParentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ImportResponse> importResult = await TpmCommandExecutor.ExecuteAsync<ImportResponse>(
            tpm, importInput, [importParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            importResult.IsSuccess,
            $"TPM2_Import() under the fresh ECC storage parent failed: '{importResult.ResponseCode}'. A failure here means the new parent's resolved PublicPoint X-slice did not derive the seed the exporter used.");
        using ImportResponse imported = importResult.Value;

        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(imported.OutPrivate.Span, pool);
        var publicReader = new TpmReader(publicOctets);
        using Tpm2bPublic inPublic = Tpm2bPublic.Parse(ref publicReader, pool);
        using LoadInput loadInput = new(destinationHandle, inPrivate, inPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"TPM2_Load() (imported object) failed: '{loadResult.ResponseCode}'.");
        using LoadResponse loaded = loadResult.Value;

        try
        {
            using TpmPasswordSession itemAuth = TpmPasswordSession.CreateEmpty(pool);
            UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [itemAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(unsealResult.IsSuccess, $"TPM2_Unseal() (imported object) failed: '{unsealResult.ResponseCode}'.");
            using UnsealResponse unsealed = unsealResult.Value;
            Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(MigratedSecretBytes), "The migrated secret must unseal under the fresh parent byte for byte.");
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, loaded.ObjectHandle.Value).ConfigureAwait(false);
            await FlushAsync(tpm, registry, pool, objectHandle).ConfigureAwait(false);
            await FlushAsync(tpm, registry, pool, destinationHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <see cref="TransientKeyState.PublicPoint"/>'s rental (adopted from the backend's own generated point) is
    /// returned once <c>TPM2_FlushContext()</c> releases the transient record — a pool-metered
    /// <c>TPM2_CreatePrimary()</c>/<c>TPM2_FlushContext()</c> pair over an ECC key leaves the pool exactly where
    /// it started.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.2</see>.
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryEccKeyPlusFlushContextBalancesThePool()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        using(CreatePrimaryResponse primary = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false))
        {
            await FlushAsync(tpm, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A CreatePrimary/FlushContext pair over an ECC key must leave the pool exactly where it started, the point rental included.");
    }

    /// <summary>
    /// <c>TPM2_EvictControl()</c>'s persist arm deep-copies the point into a SECOND pooled
    /// <see cref="EncodedEcPoint"/> rental (the alias defect's fix) — persisting an already-created key rents
    /// exactly one MORE SEC1-P-256-sized carrier than existed before it (the deep copy, beside the transient's
    /// own), and flushing the transient then evicting the persistent record releases BOTH, leaving the pool
    /// exactly where it started.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task EvictControlPersistAndEvictOfBothPointCopiesBalancesThePool()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        using(CreatePrimaryResponse primary = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false))
        {
            uint transientHandle = primary.ObjectHandle.Value;
            long pointRentalsBeforePersist = trackingPool.RentedCountOfSize(Sec1P256PointLength);

            TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
                tpm, registry, pool, transientHandle, EvictControlBalanceHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");
            Assert.AreEqual(
                pointRentalsBeforePersist + 1, trackingPool.RentedCountOfSize(Sec1P256PointLength),
                "Persisting must rent exactly one MORE SEC1-P-256-sized point carrier — the deep copy — on top of every rental CreatePrimary itself already took.");

            await FlushAsync(tpm, registry, pool, transientHandle).ConfigureAwait(false);

            TpmResult<EvictControlResponse> evictResult = await TpmEvictControlHarness.EvictControlAsync(
                tpm, registry, pool, EvictControlBalanceHandle, EvictControlBalanceHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(evictResult.IsSuccess, $"EvictControl (evict) failed: '{evictResult.ResponseCode}'.");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Flushing the transient and evicting the persistent record must release BOTH point rentals, alongside every other carrier.");
    }

    /// <summary>
    /// <c>TPM2_LoadExternal()</c>'s ECC arm adopts a pooled point projected from the parsed public area
    /// (<c>TpmsEccPoint.ToEncodedEcPoint</c>); a public-only load followed by <c>TPM2_FlushContext()</c> leaves
    /// the pool balanced.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task LoadExternalEccPublicOnlyPlusFlushBalancesThePool()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (byte[] x, byte[] y, byte[] _) = GenerateP256KeyMaterial();
        long baseline = trackingPool.OutstandingCount;

        using(Tpm2bPublic publicArea = BuildEccPublicArea(pool, x, y))
        using(var input = new LoadExternalInput(null, publicArea, TpmiRhHierarchy.Owner))
        {
            TpmResult<LoadExternalResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(
                tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(loadResult.IsSuccess, $"TPM2_LoadExternal() (public-only ECC) failed: '{loadResult.ResponseCode}'.");
            using LoadExternalResponse loaded = loadResult.Value;

            await FlushAsync(tpm, registry, pool, loaded.ObjectHandle.Value).ConfigureAwait(false);
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A public-only LoadExternal/FlushContext pair over an ECC key must leave the pool exactly where it started.");
    }

    /// <summary>
    /// "If nameAlg is not TPM_ALG_NULL, then the same consistency checks between inPublic and inPrivate are made
    /// as for TPM2_Load()" (TPM 2.0 Library Part 3, clause 12.3.1): an <c>inPrivate</c> scalar not matching
    /// <c>inPublic</c>'s point is refused bare <c>TPM_RC_BINDING</c> — the point rental the ECC arm of
    /// <c>TPM2_LoadExternal()</c> took to build the refused record's public area is released on the
    /// binding-mismatch refusal path, not orphaned.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task RefusedLoadExternalWithAMismatchedScalarReleasesThePointRental()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (byte[] x, byte[] y, byte[] _) = GenerateP256KeyMaterial();
        (byte[] _, byte[] _, byte[] otherScalar) = GenerateP256KeyMaterial();
        long baseline = trackingPool.OutstandingCount;

        using(Tpm2bPublic publicArea = BuildEccPublicArea(pool, x, y))
        using(TpmtSensitive sensitiveArea = BuildEccSensitive(pool, otherScalar))
        using(var input = new LoadExternalInput(sensitiveArea, publicArea, TpmiRhHierarchy.Null))
        {
            TpmResult<LoadExternalResponse> result = await TpmCommandExecutor.ExecuteAsync<LoadExternalResponse>(
                tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_BINDING, result.ResponseCode, "A scalar not matching the point must refuse TPM_RC_BINDING (Part 3, clause 12.3.1).");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The refused ECC arm's point rental must be released, not orphaned, on the binding-mismatch refusal path — this test's own request-side carriers (X, Y and the mismatched scalar) are released by the using blocks above before this check.");
    }

    /// <summary>Extracts an ECC primary's exported public point, SEC1 uncompressed (<c>0x04 ‖ X ‖ Y</c>).</summary>
    private static ReadOnlyMemory<byte> ExtractEccPoint(CreatePrimaryResponse primary)
    {
        TpmsEccPoint point = primary.OutPublic.PublicArea.Unique.Ecc!;

        return EllipticCurveUtilities.CombineToUncompressedPoint(point.X.AsReadOnlySpan(), point.Y.AsReadOnlySpan());
    }

    /// <summary>Creates an ECC storage-parent-shaped decrypt key (RESTRICTED+DECRYPT, SHA-256 nameAlg) under the owner hierarchy.</summary>
    private async Task<CreatePrimaryResponse> CreateEccDecryptKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccStorageParent(TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC decrypt key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Flushes a transient object handle.</summary>
    private async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        var flush = FlushContextInput.ForHandle(handle);
        TpmResult<FlushContextResponse> result = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flush, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"FlushContext (transient) failed: '{result.ResponseCode}'.");
    }

    /// <summary>Issues TPM2_ReadPublic for the given handle, returning the result for the caller to assert.</summary>
    private async Task<TpmResult<ReadPublicResponse>> ReadPublicAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        var input = ReadPublicInput.ForHandle(TpmiDhObject.FromValue(handle));

        return await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it operational.</summary>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-ecc-point-carrier", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator to move it into <see cref="TpmLifecyclePhase.Operational"/>.</summary>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed.");
        using TpmResponse response = result.Value;
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    /// <summary>Creates a response codec registry covering every command this class drives.</summary>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_EvictControl, TpmResponseCodec.EvictControl);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_ReadPublic, TpmResponseCodec.ReadPublic);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_MakeCredential, TpmResponseCodec.MakeCredential);
        _ = registry.Register(TpmCcConstants.TPM_CC_ActivateCredential, TpmResponseCodec.ActivateCredential);
        _ = registry.Register(TpmCcConstants.TPM_CC_ContextSave, TpmResponseCodec.ContextSave);
        _ = registry.Register(TpmCcConstants.TPM_CC_ContextLoad, TpmResponseCodec.ContextLoad);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyCommandCode, TpmResponseCodec.PolicyCommandCode);
        _ = registry.Register(TpmCcConstants.TPM_CC_Duplicate, TpmResponseCodec.Duplicate);
        _ = registry.Register(TpmCcConstants.TPM_CC_Import, TpmResponseCodec.Import);
        _ = registry.Register(TpmCcConstants.TPM_CC_LoadExternal, TpmResponseCodec.LoadExternal);

        return registry;
    }

    /// <summary>Creates a CreatePrimary'd, unrestricted ECC P-256 signing key under the owner hierarchy with an empty password — an attestation-key stand-in.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response; the caller disposes it.</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Saves a resource's context through <c>TPM2_ContextSave()</c> over the production executor and asserts success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle of the resource to save.</param>
    /// <returns>The response, owning the saved <see cref="TpmsContext"/>; the caller disposes it.</returns>
    private async Task<ContextSaveResponse> SaveContextAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        ContextSaveInput input = ContextSaveInput.ForHandle(handle);
        TpmResult<ContextSaveResponse> result = await TpmCommandExecutor.ExecuteAsync<ContextSaveResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ContextSave(0x{handle:X8}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Loads a saved context through <c>TPM2_ContextLoad()</c> over the production executor and asserts success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="context">The context to reload — borrowed; the caller retains and later disposes it.</param>
    /// <returns>The handle assigned to the reloaded resource.</returns>
    private async Task<uint> LoadContextAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmsContext context)
    {
        var input = new ContextLoadInput(context);
        TpmResult<ContextLoadResponse> result = await TpmCommandExecutor.ExecuteAsync<ContextLoadResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ContextLoad() failed: '{result.ResponseCode}'.");

        return result.Value.LoadedHandle.Value;
    }

    /// <summary>Seals <see cref="MigratedSecretBytes"/> into a DUPLICABLE object (authPolicy the <c>TPM2_PolicyCommandCode(TPM_CC_Duplicate)</c> digest) under the given parent and loads it.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The loaded parent's handle.</param>
    /// <returns>The loaded handle, its Name octets, and its marshaled public area.</returns>
    private async Task<(uint Handle, byte[] Name, byte[] PublicOctets)> CreateAndLoadDuplicableSealedObjectAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle)
    {
        byte[] duplicationPolicy = new byte[32];
        _ = TpmPolicyDigest.ExtendForCommandCode(new byte[32], TpmCcConstants.TPM_CC_Duplicate, SessionAlg, duplicationPolicy, pool);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(MigratedSecretBytes, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, duplicationPolicy, noDa: true, userWithAuth: true, isDuplicable: true);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_Create() (duplicable sealed object) failed: '{createResult.ResponseCode}'.");
        using CreateResponse sealedObject = createResult.Value;

        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
        int publicSize = sealedObject.OutPublic.GetSerializedSize();
        byte[] publicOctets = new byte[publicSize];
        var publicWriter = new TpmWriter(publicOctets);
        sealedObject.OutPublic.WriteTo(ref publicWriter);
        var publicReader = new TpmReader(publicOctets);
        using Tpm2bPublic inPublic = Tpm2bPublic.Parse(ref publicReader, pool);

        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"TPM2_Load() (duplicable sealed object) failed: '{loadResult.ResponseCode}'.");
        using LoadResponse loaded = loadResult.Value;

        return (loaded.ObjectHandle.Value, loaded.Name.Span.ToArray(), publicOctets);
    }

    /// <summary>Starts an unbound, unsalted REAL policy session and returns its handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The started session's handle.</returns>
    private async Task<uint> StartRealPolicySessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput input = StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> result = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"StartAuthSession (policy) failed: '{result.ResponseCode}'.");
        using StartAuthSessionResponse response = result.Value;

        return response.SessionHandle.Value;
    }

    /// <summary>Issues a <c>TPM2_PolicyCommandCode()</c> over the session and asserts it succeeded.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="policySession">The policy session's handle.</param>
    /// <param name="restrictedCommand">The command code to latch.</param>
    private async Task AssertCommandCodeAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint policySession, TpmCcConstants restrictedCommand)
    {
        PolicyCommandCodeInput input = PolicyCommandCodeInput.Create(policySession, restrictedCommand);
        TpmResult<PolicyCommandCodeResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyCommandCodeResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"PolicyCommandCode failed: '{result.ResponseCode}'.");
    }

    /// <summary>Mints a fresh P-256 key pair off the TPM and pads its coordinates and scalar to fixed width.</summary>
    /// <returns>The X coordinate, the Y coordinate, and the private scalar, each 32 octets.</returns>
    private static (byte[] X, byte[] Y, byte[] D) GenerateP256KeyMaterial()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters parameters = key.ExportParameters(includePrivateParameters: true);

        return (PadLeftToP256(parameters.Q.X!), PadLeftToP256(parameters.Q.Y!), PadLeftToP256(parameters.D!));
    }

    /// <summary>Left-pads a big-endian integer to the P-256 component width.</summary>
    /// <param name="value">The big-endian value.</param>
    /// <returns>A new 32-octet array.</returns>
    private static byte[] PadLeftToP256(byte[] value)
    {
        byte[] padded = new byte[P256ComponentSize];
        value.CopyTo(padded, P256ComponentSize - value.Length);

        return padded;
    }

    /// <summary>Builds an ECC P-256 ECDSA-SHA-256 signing public area carrying the given point (TPM 2.0 Library Part 2, clause 12.2.4, Table 235).</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="x">The point's X coordinate.</param>
    /// <param name="y">The point's Y coordinate.</param>
    /// <returns>The public area; the caller owns it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the point transfers to the returned public area, which its owner disposes.")]
    private static Tpm2bPublic BuildEccPublicArea(BaseMemoryPool pool, ReadOnlySpan<byte> x, ReadOnlySpan<byte> y) =>
        Tpm2bPublic.CreateEccSigningKey(
            TpmKeyNameAlg, TpmaObject.USER_WITH_AUTH | TpmaObject.SIGN_ENCRYPT | TpmaObject.NO_DA, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmKeyNameAlg), TpmsEccPoint.Create(x, y, pool), pool);

    /// <summary>Builds an ECC sensitive area (TPM 2.0 Library Part 2, clause 12.3.2, Table 240) around the given private scalar.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="scalar">The private scalar.</param>
    /// <returns>The sensitive area; the caller owns it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the three carriers transfers to the returned sensitive area, which its owner disposes.")]
    private static TpmtSensitive BuildEccSensitive(BaseMemoryPool pool, ReadOnlySpan<byte> scalar) =>
        new(Tpm2bAuth.CreateEmpty(pool), Tpm2bDigest.Empty, TpmuSensitiveComposite.FromEcc(Tpm2bEccParameter.Create(scalar, pool)));
}
