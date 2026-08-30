using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Foundation.Automata;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// The secure-memory lifecycle proofs for the in-house <see cref="TpmSimulator"/>: every durable secret
/// rides an owned pooled carrier, so eviction, rotation, every form of <c>TPM2_Startup()</c>, and simulator
/// teardown must genuinely RETURN those rentals to the pool — proven with real pool telemetry
/// (<see cref="MeteredHousePool"/>) over the real wire, never with internal hooks. The startup trio also
/// proves the normative session flush: "Session contexts in TPM RAM are flushed on any TPM2_Startup()"
/// (TPM 2.0 Library Part 1, clause 27.5) and "on TPM Resume or TPM Restart, authorization sessions in TPM
/// memory will be terminated" (clause 16.6.18).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorSecureMemoryLifecycleTests
{
    /// <summary>The session hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>Every ECC storage-parent-shaped template this simulator builds fixes nameAlg to SHA-256.</summary>
    private const TpmAlgIdConstants TpmKeyNameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The owner-hierarchy persistent handle used by the deep-copy proof.</summary>
    private const uint PersistentHandle = 0x8100_0020;

    /// <summary>The NV Index handle used by the carrier-accounting and stripped-form proofs.</summary>
    private const uint NvIndexHandle = 0x0100_0021;

    /// <summary>The declared data area size of every Index these tests define; <see cref="NvWriteData"/> fills it exactly.</summary>
    private const ushort NvDataSize = 8;

    /// <summary>The attribute set an ordinary caller-authorized, DA-exempt Index is defined with, unless a test elects more.</summary>
    private const TpmaNv DefaultIndexAttributes = TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>A caller-authorized, DA-exempt Counter Index carrying <c>TPMA_NV_ORDERLY</c> — the counter-exemption proof's shape.</summary>
    private const TpmaNv OrderlyCounterAttributes =
        DefaultIndexAttributes | TpmaNv.TPMA_NV_ORDERLY | (TpmaNv)((uint)TpmNt.TPM_NT_COUNTER << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>The authValue assigned to the teardown proof's Index, so its carrier rental is live at dispose time.</summary>
    private static byte[] TeardownIndexAuth { get; } = [0x51, 0x52, 0x53, 0x54];

    /// <summary>The octets the stripped-form proof writes, sized to fill the declared data area.</summary>
    private static byte[] NvWriteData { get; } = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    /// <summary>The stripped authValue the stripped-form proof authorizes with.</summary>
    private static byte[] StrippedAuthValue { get; } = [0x61, 0x62, 0x63];

    /// <summary>
    /// The wire form the stripped-form proof installs: <see cref="StrippedAuthValue"/> with two trailing zero
    /// octets appended — DERIVED from the stripped form, so the equivalence the test proves (TPM 2.0 Library
    /// Part 1, clause 16.6.4.3) is structural in the fixture rather than an eyeball match of two literals.
    /// </summary>
    private static byte[] PaddedAuthValue { get; } = [.. StrippedAuthValue, 0x00, 0x00];

    /// <summary>The first replacement ownerAuth in the rotation-balance proof.</summary>
    private static byte[] FirstRotationAuth { get; } = [0xA1, 0xA2, 0xA3, 0xA4];

    /// <summary>The second replacement ownerAuth in the rotation-balance proof, deliberately a different width than <see cref="FirstRotationAuth"/>.</summary>
    private static byte[] SecondRotationAuth { get; } = [0xB1, 0xB2, 0xB3, 0xB4, 0xB5];

    /// <summary>A deliberately wrong ownerAuth the HMAC-mismatch proof folds client-side, distinct from every installed value here.</summary>
    private static byte[] WrongSessionAuth { get; } = [0xC1, 0xC2, 0xC3, 0xC4];

    /// <summary>The secret the sealed-object proofs seal and recover.</summary>
    private static byte[] SealedSecret { get; } = [0x5E, 0xCA, 0x1E, 0xD5, 0xEC, 0x4E, 0x70, 0x01];

    /// <summary>The sealed item's authValue in the sealed-object proofs.</summary>
    private static byte[] SealAuth { get; } = [0x71, 0x72, 0x73, 0x74];

    /// <summary>
    /// How many pooled carriers a loaded sealed object owns: its Name, its recovered sealed data, its
    /// userAuth, its protection seed (the sensitive area's obfuscation value, TPM 2.0 Library Part 2,
    /// clause 12.3.2, Table 240), the raw storage of its retained public area plus the parsed <c>unique</c>
    /// that area carries (<c>H_nameAlg(seedValue ‖ data)</c>, Part 2, clause 12.2.3.1, equation (8); Part 1, clause 24.5.3.2, equation (48) — the
    /// caller's <c>inPublic</c>, which <c>TPM2_ReadPublic()</c> answers with, Part 3, clause 12.4.1; a
    /// policy-free sealed template parses no further carrier), and its Qualified Name (Part 1, clause 23.5).
    /// The Name is rented separately from the one <c>TPM2_Load()</c>'s response frames, because the two
    /// owners' lifetimes do not nest.
    /// </summary>
    private const int LoadedSealedObjectCarrierCount = 7;

    /// <summary>The real password the parent-authValue carrier-balance proofs create the storage parent with.</summary>
    private const string ParentPassword = "secmem-parent-auth-proof";

    /// <summary>The parent's authValue in wire form — the UTF-8 octets <see cref="ParentPassword"/> derives.</summary>
    private static byte[] ParentAuth { get; } = System.Text.Encoding.UTF8.GetBytes(ParentPassword);

    /// <summary>A wrong guess at the parent's password, distinct from <see cref="ParentAuth"/>.</summary>
    private static byte[] WrongParentAuth { get; } = [0x9A, 0x9B, 0x9C, 0x9D];

    /// <summary>
    /// The real password value the newly-verified command password slots (parent, hierarchy, key, sign, object,
    /// activate, index) install on whichever entity a given carrier-balance proof creates — reused across those
    /// proofs since each runs against its own isolated simulator and entity.
    /// </summary>
    private const string PasswordSlotAuth = "secmem-slot-auth-proof";

    /// <summary>The wire form of <see cref="PasswordSlotAuth"/>, for constructing the correct-password session.</summary>
    private static byte[] PasswordSlotAuthBytes { get; } = System.Text.Encoding.UTF8.GetBytes(PasswordSlotAuth);

    /// <summary>A wrong guess at <see cref="PasswordSlotAuth"/>, distinct from it, reused across the same proofs.</summary>
    private static byte[] WrongPasswordSlotAuthBytes { get; } = [0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6];

    /// <summary>The caller nonce (qualifyingData) the attestation-command carrier-balance proofs echo into the attestation.</summary>
    private static byte[] PasswordSlotNonce { get; } = "secmem-slot-nonce"u8.ToArray();

    /// <summary>The number of bytes a SHA-256 digest occupies — the fixed digest length the signing carrier-balance proofs sign.</summary>
    private const int Sha256DigestLength = 32;

    /// <summary>The fixed secret the credential-activation carrier-balance proofs wrap and recover.</summary>
    private static byte[] ActivateCredentialFixtureSecret { get; } =
        [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF];

    /// <summary>
    /// An authValue one octet wider than a SHA-256 Name algorithm's digest, DERIVED from the limit it
    /// violates (TPM 2.0 Library Part 1, clause 16.6.4.2) — the refused-seal balance proof's fixture. A
    /// non-zero fill keeps the wire length at 33 regardless of trailing-zero handling.
    /// </summary>
    private static byte[] OverWideSealAuth { get; } = CreateOverWideSealAuth();

    /// <summary>Builds <see cref="OverWideSealAuth"/>: one octet more than SHA-256's 32, filled with a non-zero value.</summary>
    /// <returns>The over-wide authValue.</returns>
    private static byte[] CreateOverWideSealAuth()
    {
        byte[] value = new byte[TpmPolicyDigest.Size(TpmAlgIdConstants.TPM_ALG_SHA256) + 1];
        Array.Fill(value, (byte)0x41);

        return value;
    }

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// TPM Resume terminates active sessions: a bound HMAC session started before
    /// <c>Shutdown(STATE)</c>/<c>Startup(STATE)</c> is gone afterwards — flushing its handle answers
    /// <c>TPM_RC_HANDLE</c>, exactly as a never-started handle does. TPM 2.0 Library Part 1, clause 27.5
    /// ("Session contexts in TPM RAM are flushed on any TPM2_Startup()") and clause 16.6.18 ("on TPM Resume
    /// or TPM Restart, authorization sessions in TPM memory will be terminated"); the reference's
    /// <c>SessionStartup()</c> clears the RAM slots unconditionally for every startup type.
    /// </summary>
    [TestMethod]
    public async Task StartupResumeTerminatesActiveSessions()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-secmem-resume-flush").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartBoundToOwnerSessionAsync(tpm, registry, pool).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, await SubmitSessionlessAsync(simulator, pool, new ShutdownInput(TpmSuConstants.TPM_SU_STATE)).ConfigureAwait(false));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, await SubmitSessionlessAsync(simulator, pool, new StartupInput(TpmSuConstants.TPM_SU_STATE)).ConfigureAwait(false));

        TpmResult<FlushContextResponse> flushResult = await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        Assert.IsTrue(
            flushResult.IsTpmError,
            "A TPM Resume terminates every session in TPM memory, so flushing the pre-resume session handle must be refused.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_HANDLE, flushResult.ResponseCode,
            "A TPM Resume terminates every session in TPM memory, so flushing the pre-resume session handle must answer TPM_RC_HANDLE.");
    }

    /// <summary>
    /// TPM Restart terminates active sessions: the same proof as
    /// <see cref="StartupResumeTerminatesActiveSessions"/> for the <c>Shutdown(STATE)</c>/<c>Startup(CLEAR)</c>
    /// sequence — clause 16.6.18 names Restart explicitly alongside Resume (TPM 2.0 Library Part 1, clauses
    /// 28.5 and 17.6.17).
    /// </summary>
    [TestMethod]
    public async Task StartupRestartTerminatesActiveSessions()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-secmem-restart-flush").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartBoundToOwnerSessionAsync(tpm, registry, pool).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, await SubmitSessionlessAsync(simulator, pool, new ShutdownInput(TpmSuConstants.TPM_SU_STATE)).ConfigureAwait(false));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, await SubmitSessionlessAsync(simulator, pool, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false));

        TpmResult<FlushContextResponse> flushResult = await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        Assert.IsTrue(
            flushResult.IsTpmError,
            "A TPM Restart terminates every session in TPM memory, so flushing the pre-restart session handle must be refused.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_HANDLE, flushResult.ResponseCode,
            "A TPM Restart terminates every session in TPM memory, so flushing the pre-restart session handle must answer TPM_RC_HANDLE.");
    }

    /// <summary>
    /// A TPM Reset's session flush genuinely RETURNS the flushed sessions' carrier rentals (session key and
    /// bound-entity value) to the pool: the pool's outstanding-rental count returns to its pre-session
    /// baseline once <c>Shutdown(CLEAR)</c>/<c>Startup(CLEAR)</c> completes. The flush itself is
    /// pre-existing behaviour; the accounting is what the owned carriers add (TPM 2.0 Library Part 1,
    /// clause 27.5).
    /// </summary>
    [TestMethod]
    public async Task StartupResetReturnsSessionCarrierRentalsToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-reset-pool").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;
        _ = await StartBoundToOwnerSessionAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        Assert.IsGreaterThan(
            baseline, trackingPool.OutstandingCount,
            "A bound session must hold live carrier rentals (session key, bound-entity value), or the balance assertion below is vacuous.");

        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, await SubmitSessionlessAsync(simulator, trackingPool.Pool, new ShutdownInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, await SubmitSessionlessAsync(simulator, trackingPool.Pool, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false));

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A TPM Reset's session flush must return every flushed session's carrier rentals to the pool.");
    }

    /// <summary>
    /// Disposing the simulator returns EVERY durable carrier rental to the pool: a scenario touching every
    /// owned carrier class — a primary key's retained private key, an NV Index's authorization value, and a
    /// bound session's key and bound-entity value — leaves outstanding rentals, and the teardown walk brings
    /// the pool back to exact balance. Real pool telemetry, no test hook in production code.
    /// </summary>
    [TestMethod]
    public async Task DisposeReturnsEveryDurableCarrierRentalToPool()
    {
        using var trackingPool = new MeteredHousePool();
        TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-teardown").ConfigureAwait(false);
        try
        {
            using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
            TpmResponseRegistry registry = CreateRegistry();

            using(CreatePrimaryResponse primary = await CreateEccDecryptKeyAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false))
            {
                Assert.AreNotEqual(0u, primary.ObjectHandle.Value, "The primary key must be created for the walk to have a private-key carrier to release.");
            }

            TpmResult<NvDefineSpaceResponse> defineResult = await DefineIndexAsync(
                tpm, registry, trackingPool.Pool, NvIndexHandle, TeardownIndexAuth).ConfigureAwait(false);
            Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");

            _ = await StartBoundToOwnerSessionAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

            Assert.IsGreaterThan(
                0L, trackingPool.OutstandingCount,
                "The scenario must leave live durable carrier rentals, or the balance assertion below is vacuous.");
        }
        finally
        {
            simulator.Dispose();
        }

        Assert.AreEqual(
            0L, trackingPool.OutstandingCount,
            "Tearing the simulator down must return every durable carrier rental — object keys, NV authValues, session keys, bound-entity values — to the pool.");
    }

    /// <summary>
    /// <c>TPM2_EvictControl()</c>'s persist arm installs a genuine deep COPY: after the transient original is
    /// flushed (disposing ITS private-key carrier), the persistent instance's own key still decrypts a salted
    /// <c>TPM2_StartAuthSession()</c>'s salt — proving the two instances never co-owned a buffer. The
    /// persistent copy is then evicted cleanly (TPM 2.0 Library Part 3, clause 28.5; Part 1, clause 16.6.13's
    /// salted-session seed recovery is what forces the simulator to USE the persistent key's bytes).
    /// </summary>
    [TestMethod]
    public async Task PersistedCopySurvivesFlushingTheTransientOriginal()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-secmem-persist-copy").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse tpmKey = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint transientHandle = tpmKey.ObjectHandle.Value;
        ReadOnlyMemory<byte> point = ExtractEccPoint(tpmKey);

        TpmResult<EvictControlResponse> persistResult = await EvictControlAsync(tpm, registry, pool, transientHandle, PersistentHandle).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        TpmResult<FlushContextResponse> flushResult = await FlushAsync(tpm, registry, pool, transientHandle).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext (transient original) failed: '{flushResult.ResponseCode}'.");

        //The salted start decrypts the salt with the PERSISTENT instance's private key: an aliased (and now
        //disposed) carrier could not serve it.
        TpmEccSigningBackend eccBackend = BouncyCastleTpmEccSigningBackend.Create();
        (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, _) = await StartAuthSessionInputExtensions.CreateSaltedHmacSession(
            PersistentHandle, point, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmKeyNameAlg, SessionAlg,
            eccBackend.GenerateKey, eccBackend.ComputeSharedSecret, pool, TestContext.CancellationToken).ConfigureAwait(false);

        uint saltedSessionHandle;
        using(salt)
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                startResult.IsSuccess,
                $"A salted session against the persistent copy must start after the transient original is flushed, but failed: '{startResult.ResponseCode}'.");
            saltedSessionHandle = startResult.Value.SessionHandle.Value;
        }

        TpmResult<FlushContextResponse> sessionFlush = await FlushAsync(tpm, registry, pool, saltedSessionHandle).ConfigureAwait(false);
        Assert.IsTrue(sessionFlush.IsSuccess, $"FlushContext (salted session) failed: '{sessionFlush.ResponseCode}'.");

        TpmResult<EvictControlResponse> evictResult = await EvictControlAsync(tpm, registry, pool, PersistentHandle, PersistentHandle).ConfigureAwait(false);
        Assert.IsTrue(evictResult.IsSuccess, $"EvictControl (evict persistent copy) failed: '{evictResult.ResponseCode}'.");
    }

    /// <summary>
    /// Rotating a hierarchy authorization value disposes the outgoing carrier as the replacement installs:
    /// across empty→A→B→empty rotations of ownerAuth the pool's outstanding-rental count moves exactly with
    /// the live value's width — one rental while a non-empty value is installed, back to baseline once the
    /// Empty Buffer returns (TPM 2.0 Library Part 3, clause 24.8).
    /// </summary>
    [TestMethod]
    public async Task HierarchyAuthRotationKeepsPoolBalanceExact()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-rotation").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        await RotateOwnerAuthAsync(tpm, registry, trackingPool.Pool, currentAuth: default, newAuth: FirstRotationAuth).ConfigureAwait(false);
        Assert.AreEqual(baseline + 1, trackingPool.OutstandingCount, "Installing a non-empty ownerAuth must hold exactly its one carrier rental.");

        await RotateOwnerAuthAsync(tpm, registry, trackingPool.Pool, currentAuth: FirstRotationAuth, newAuth: SecondRotationAuth).ConfigureAwait(false);
        Assert.AreEqual(baseline + 1, trackingPool.OutstandingCount, "Rotating ownerAuth must dispose the outgoing carrier as the replacement installs — the balance may not grow.");

        await RotateOwnerAuthAsync(tpm, registry, trackingPool.Pool, currentAuth: SecondRotationAuth, newAuth: default).ConfigureAwait(false);
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Rotating back to the Empty Buffer must return the last carrier rental to the pool.");
    }

    /// <summary>
    /// The trace stream's fail-loud contract: a retained <see cref="TraceEntry{TState, TInput}"/> snapshot
    /// stays structurally readable after the session it captured is flushed, but reading the flushed
    /// session's disposed key carrier throws <see cref="ObjectDisposedException"/> — never silently exposing
    /// recycled pool memory. An observer that needs a secret durably must copy it before the automaton
    /// moves on.
    /// </summary>
    [TestMethod]
    public async Task RetainedTraceSnapshotFailsLoudOnFlushedSessionKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-secmem-trace-loud").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        var observer = new TestObserver<TraceEntry<TpmSimulatorState, TpmSimulatorInput>>();
        using IDisposable subscription = simulator.Subscribe(observer);

        uint sessionHandle = await StartBoundToOwnerSessionAsync(tpm, registry, pool).ConfigureAwait(false);

        TraceEntry<TpmSimulatorState, TpmSimulatorInput>? sessionSnapshot = null;
        foreach(TraceEntry<TpmSimulatorState, TpmSimulatorInput> entry in observer.Received)
        {
            if(entry.StateAfter.HmacSessions.ContainsKey(TpmiShHmac.FromValue(sessionHandle)))
            {
                sessionSnapshot = entry;
                break;
            }
        }

        Assert.IsNotNull(sessionSnapshot, "A trace entry must have captured the started session's state.");

        TpmResult<FlushContextResponse> flushResult = await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext (session) failed: '{flushResult.ResponseCode}'.");

        _ = Assert.ThrowsExactly<ObjectDisposedException>(
            () => _ = sessionSnapshot.StateAfter.HmacSessions[TpmiShHmac.FromValue(sessionHandle)].SessionKey.AsReadOnlyMemory(),
            "Reading a flushed session's key from a retained snapshot must throw loudly, never read recycled pool memory.");
    }

    /// <summary>
    /// An authorization value installed WITH trailing zero octets authorizes in its stripped form: "Trailing
    /// octets of zero are to be removed from any string before it is used as an authValue" (TPM 2.0 Library
    /// Part 1, clause 16.6.4.3; the reference strips supplied session auths through
    /// <c>MemoryRemoveTrailingZeros</c> and every stored auth through <c>EntityGetAuthValue</c>). The stored
    /// carrier keeps the wire-exact octets; every compare takes stripped views of BOTH sides.
    /// </summary>
    [TestMethod]
    public async Task TrailingZeroPaddedNvAuthValueAuthorizesInStrippedForm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-secmem-strip-equiv").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //Defined with the zero-padded wire form; authorized below with the stripped form it derives from.
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineIndexAsync(
            tpm, registry, pool, NvIndexHandle, PaddedAuthValue).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");

        using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(NvWriteData, pool);
        var writeInput = new NvWriteInput(NvIndexHandle, NvIndexHandle, writeInputBuffer, Offset: 0);
        using TpmPasswordSession strippedAuth = TpmPasswordSession.Create(StrippedAuthValue, pool);

        TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, writeInput, [strippedAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            writeResult.IsSuccess,
            $"The stripped form of a trailing-zero-padded authValue must authorize (clause 16.6.4.3), but NV_Write failed: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// A REFUSED <c>TPM2_NV_DefineSpace()</c> returns the parse-rented authValue carrier to the pool: a
    /// definition claiming <c>TPMA_NV_PLATFORMCREATE</c> under Owner Authorization is refused with
    /// <c>TPM_RC_ATTRIBUTES</c> (TPM 2.0 Library Part 3, clause 31.3.1), and the refusal must release the
    /// pinned rental the parser took for the supplied Index authValue — every refusing arm disposes the
    /// in-flight input it received, never orphans it.
    /// </summary>
    [TestMethod]
    public async Task RefusedNvDefineSpaceReturnsTheParsedAuthCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-refused-define").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        TpmResult<NvDefineSpaceResponse> defineResult = await DefineIndexAsync(
            tpm, registry, trackingPool.Pool, NvIndexHandle, TeardownIndexAuth,
            DefaultIndexAttributes | TpmaNv.TPMA_NV_PLATFORMCREATE).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsTpmError, "An owner-authorized definition claiming TPMA_NV_PLATFORMCREATE must be refused.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, defineResult.ResponseCode);

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return the parse-rented Index authValue carrier to the pool.");
    }

    /// <summary>
    /// A REFUSED <c>TPM2_NV_ChangeAuth()</c> returns the parse-rented replacement-authValue carrier to the
    /// pool: the rotation's ADMIN role admits only a policy session, so a password authorization is refused
    /// with <c>TPM_RC_AUTH_TYPE</c> (TPM 2.0 Library Part 3, clause 31.15.1), and the refusal must release
    /// the pinned rental the parser took for <c>newAuth</c>.
    /// </summary>
    [TestMethod]
    public async Task RefusedNvChangeAuthReturnsTheParsedAuthCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-refused-rotation").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //Defined with an EMPTY authValue (the dispose-immune shared carrier), so the only rental the refused
        //rotation can involve is the parsed newAuth.
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineIndexAsync(
            tpm, registry, trackingPool.Pool, NvIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");

        long baseline = trackingPool.OutstandingCount;
        {
            using Tpm2bAuth newAuth = Tpm2bAuth.Create(FirstRotationAuth, trackingPool.Pool);
            using NvChangeAuthInput input = new(NvIndexHandle, newAuth);
            using TpmPasswordSession indexAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);

            TpmResult<NvChangeAuthResponse> result = await TpmCommandExecutor.ExecuteAsync<NvChangeAuthResponse>(
                tpm, input, [indexAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsTpmError, "A password session must never authorize an ADMIN-role NV command.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return the parse-rented newAuth carrier to the pool.");
    }

    /// <summary>
    /// A command-HMAC MISMATCH returns the queued request's parse-rented carrier to the pool: a
    /// <c>TPM2_HierarchyChangeAuth()</c> authorized over an HMAC session whose client folded a WRONG ownerAuth
    /// fails session verification (TPM 2.0 Library Part 1, clause 16.6; Part 3, clause 5.6, check 9), the
    /// rotation never installs, and the mismatch rejection must release the pinned rental the parser took for
    /// <c>newAuth</c> — the one reject path that runs after the request rode the verification queue.
    /// </summary>
    [TestMethod]
    public async Task HmacMismatchedRotationReturnsTheParsedAuthCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-hmac-mismatch").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //A real ownerAuth first, so the mismatch is a genuine wrong-secret disagreement rather than two empty folds.
        await RotateOwnerAuthAsync(tpm, registry, trackingPool.Pool, currentAuth: default, newAuth: FirstRotationAuth).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound) failed: '{startResult.ResponseCode}'.");
        using StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        //An unbound, unsalted session's HMAC keys on sessionKey (the Empty Buffer) ‖ the authorized entity's
        //authValue (Part 1, clause 16.6.9) — folding a wrong ownerAuth guarantees the mismatch. The client
        //session lives OUTSIDE the measured window: its constructor adopts the response's nonceTPM carrier,
        //so its own rentals would otherwise blur the one balance this test proves.
        using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, trackingPool.Pool);
        session.SetAuthValue(WrongSessionAuth, trackingPool.Pool);
        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        long baseline = trackingPool.OutstandingCount;
        {
            using Tpm2bAuth newAuth = Tpm2bAuth.Create(SecondRotationAuth, trackingPool.Pool);
            using var input = new HierarchyChangeAuthInput(TpmRh.TPM_RH_OWNER, newAuth);

            TpmResult<HierarchyChangeAuthResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyChangeAuthResponse>(
                tpm, input, [session], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsTpmError, "A session whose command HMAC does not verify must refuse the whole command.");
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_BAD_AUTH, result.BaseError,
                "TPM_RH_LOCKOUT is the sole permanent entity whose authValue is dictionary-attack protected (Part 1, clause 16.8.1), so a wrong ownerAuth is a plain session-encoded TPM_RC_BAD_AUTH.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The mismatch rejection must return the queued request's parse-rented newAuth carrier to the pool.");

        TpmResult<FlushContextResponse> sessionFlush = await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        Assert.IsTrue(sessionFlush.IsSuccess, $"FlushContext (session) failed: '{sessionFlush.ResponseCode}'.");
    }

    /// <summary>
    /// A REFUSED <c>TPM2_CreatePrimary()</c> returns the parse-rented userAuth carrier to the pool: an
    /// over-wide authValue (33 octets against a SHA-256 Name algorithm) is refused with <c>TPM_RC_SIZE</c>
    /// (TPM 2.0 Library Part 1, clause 16.6.4.2), and the refusing width-gate arm must release the pinned
    /// rental the parser took for <c>inSensitive.userAuth</c> — every refusing arm disposes the in-flight
    /// input it received, never orphans it.
    /// </summary>
    [TestMethod]
    public async Task RefusedCreatePrimaryReturnsTheParsedAuthCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-refused-primary").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;
        {
            using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
                TpmRh.TPM_RH_OWNER, new string('A', 33), TpmEccCurveConstants.TPM_ECC_NIST_P256, trackingPool.Pool, noDa: true);
            using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);

            TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
                tpm, input, [ownerAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsTpmError, "A 33-octet authValue against a SHA-256 Name algorithm must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, result.ResponseCode);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return the parse-rented userAuth carrier to the pool.");
    }

    /// <summary>
    /// A REFUSED plain-password <c>TPM2_Create()</c> seal returns BOTH parse-rented carriers (the secret and
    /// the userAuth) to the pool: an over-wide authValue against a SHA-256 Name algorithm is refused with
    /// <c>TPM_RC_SIZE</c> (TPM 2.0 Library Part 1, clause 16.6.4.2), and the refusal must release both
    /// pinned rentals through the request's own disposal.
    /// </summary>
    [TestMethod]
    public async Task RefusedSealCreateReturnsTheParsedSecretCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-refused-seal").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint parentHandle;
        using(CreatePrimaryResponse parent = await CreateEccDecryptKeyAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false))
        {
            parentHandle = parent.ObjectHandle.Value;
        }

        long baseline = trackingPool.OutstandingCount;
        {
            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, OverWideSealAuth, trackingPool.Pool);
            using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, trackingPool.Pool, authPolicy: default, noDa: true);
            using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);

            TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [parentAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsTpmError, "A 33-octet authValue against a SHA-256 Name algorithm must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, result.ResponseCode);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return the parse-rented secret and userAuth carriers to the pool.");
    }

    /// <summary>
    /// A SUCCESSFUL plain-password <c>TPM2_Create()</c> seal returns the parse-rented secret and userAuth
    /// carriers to the pool: <c>TPM2_Create()</c> installs no durable state — the created object exists only
    /// as the returned blob (TPM 2.0 Library Part 3, clause 12.1) — so the seal effect is the carriers'
    /// terminal owner and must release them once they are packed into the wrapped private blob.
    /// </summary>
    [TestMethod]
    public async Task SealedCreateReturnsTheSecretCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-sealed-balance").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint parentHandle;
        using(CreatePrimaryResponse parent = await CreateEccDecryptKeyAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false))
        {
            parentHandle = parent.ObjectHandle.Value;
        }

        long baseline = trackingPool.OutstandingCount;
        {
            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, SealAuth, trackingPool.Pool);
            using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, trackingPool.Pool, authPolicy: default, noDa: true);
            using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);

            TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [parentAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"Create (seal) failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The completed seal must return the parse-rented secret and userAuth carriers to the pool once they are packed into the blob.");
    }

    /// <summary>
    /// A REFUSED <c>TPM2_Create()</c> seal under a WRONG parent password returns every parse-rented request
    /// carrier to the pool: the secret, the sealed object's userAuth, AND the supplied parent password
    /// (compared against the parent's retained authValue at Auth Index 1, Auth Role USER — TPM 2.0 Library
    /// Part 3, clause 12.1) are all parse-rented for the duration of the parent-slot compare, and the refusing
    /// arm must dispose the whole in-flight request rather than orphan any one of them.
    /// </summary>
    [TestMethod]
    public async Task RefusedCreateWithWrongParentPasswordReturnsTheCarrierRentalsToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-refused-parent-auth").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint parentHandle;
        using(CreatePrimaryResponse parent = await CreatePasswordProtectedStorageParentAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false))
        {
            parentHandle = parent.ObjectHandle.Value;
        }

        long baseline = trackingPool.OutstandingCount;
        {
            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, SealAuth, trackingPool.Pool);
            using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, trackingPool.Pool, authPolicy: default, noDa: false);
            using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            using TpmPasswordSession wrongParentAuth = TpmPasswordSession.Create(WrongParentAuth, trackingPool.Pool);

            TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [wrongParentAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsTpmError, "A wrong parent password must be refused.");
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_FAIL, result.BaseError,
                "A wrong password against a DA-protected parent must fail with the session-index-encoded TPM_RC_AUTH_FAIL.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return the parse-rented secret, userAuth, and supplied parent password carriers to the pool.");
    }

    /// <summary>
    /// A SUCCESSFUL <c>TPM2_Create()</c> seal under a REAL parent password returns the parse-rented secret,
    /// userAuth, AND supplied parent password carriers to the pool: the parent-slot compare (TPM 2.0 Library
    /// Part 3, clause 12.1) is the supplied password carrier's terminal use, and the seal effect packs and
    /// releases the remaining two once the wrapped private blob is built.
    /// </summary>
    [TestMethod]
    public async Task SealedCreateWithParentPasswordReturnsTheCarrierRentalsToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-sealed-parent-auth").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint parentHandle;
        using(CreatePrimaryResponse parent = await CreatePasswordProtectedStorageParentAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false))
        {
            parentHandle = parent.ObjectHandle.Value;
        }

        long baseline = trackingPool.OutstandingCount;
        {
            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, SealAuth, trackingPool.Pool);
            using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, trackingPool.Pool, authPolicy: default, noDa: false);
            using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            using TpmPasswordSession correctParentAuth = TpmPasswordSession.Create(ParentAuth, trackingPool.Pool);

            TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [correctParentAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"Create (seal, real parent password) failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The completed seal must return the parse-rented secret, userAuth, and supplied parent password carriers to the pool.");
    }

    /// <summary>
    /// A REFUSED <c>TPM2_Load()</c> under a WRONG parent password returns every carrier this window rented —
    /// the cloned inPrivate/inPublic blob and the supplied parent password — to the pool: TPM2_Load()'s
    /// parent slot (Auth Index 1, Auth Role USER — TPM 2.0 Library Part 3, clause 12.2) now compares the
    /// supplied password against the parent's retained authValue, and the disposing session-encoded refusal
    /// must release the whole in-flight request rather than orphan any one carrier.
    /// </summary>
    [TestMethod]
    public async Task RefusedLoadWithWrongParentPasswordReturnsTheSuppliedPasswordCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-refused-load").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint parentHandle;
        using(CreatePrimaryResponse parent = await CreatePasswordProtectedStorageParentAsync(
            tpm, registry, trackingPool.Pool).ConfigureAwait(false))
        {
            parentHandle = parent.ObjectHandle.Value;
        }

        long baseline = trackingPool.OutstandingCount;
        {
            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, SealAuth, trackingPool.Pool);
            using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, trackingPool.Pool, authPolicy: default, noDa: true);
            using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            using TpmPasswordSession createParentAuth = TpmPasswordSession.Create(ParentAuth, trackingPool.Pool);

            TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [createParentAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(createResult.IsSuccess, $"Create (seal under password-protected parent) failed: '{createResult.ResponseCode}'.");

            using CreateResponse sealedObject = createResult.Value;
            using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, trackingPool.Pool);
            using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, trackingPool.Pool);

            using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
            using TpmPasswordSession wrongParentAuth = TpmPasswordSession.Create(WrongParentAuth, trackingPool.Pool);

            TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
                tpm, loadInput, [wrongParentAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(loadResult.IsTpmError, "A wrong parent password must be refused.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), loadResult.ResponseCode,
                "A wrong parent password over TPM2_Load's plain TPM_RS_PW session names the parent slot (index 0), session-index-encoded.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return the cloned inPrivate/inPublic blob and the supplied parent password carrier to the pool.");
    }

    /// <summary>
    /// A SUCCESSFUL <c>TPM2_Load()</c> under the parent's REAL password, once the loaded object is flushed,
    /// returns every carrier this window rented to the pool: the parent-slot compare (TPM 2.0 Library Part 3,
    /// clause 12.2) is the supplied password carrier's terminal use.
    /// </summary>
    [TestMethod]
    public async Task SuccessfulLoadWithParentPasswordReturnsTheSuppliedPasswordCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-success-load").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint parentHandle;
        using(CreatePrimaryResponse parent = await CreatePasswordProtectedStorageParentAsync(
            tpm, registry, trackingPool.Pool).ConfigureAwait(false))
        {
            parentHandle = parent.ObjectHandle.Value;
        }

        long baseline = trackingPool.OutstandingCount;
        {
            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, SealAuth, trackingPool.Pool);
            using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, trackingPool.Pool, authPolicy: default, noDa: true);
            using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            using TpmPasswordSession createParentAuth = TpmPasswordSession.Create(ParentAuth, trackingPool.Pool);

            TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [createParentAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(createResult.IsSuccess, $"Create (seal under password-protected parent) failed: '{createResult.ResponseCode}'.");

            using CreateResponse sealedObject = createResult.Value;
            using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, trackingPool.Pool);
            using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, trackingPool.Pool);

            using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
            using TpmPasswordSession correctParentAuth = TpmPasswordSession.Create(ParentAuth, trackingPool.Pool);

            TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
                tpm, loadInput, [correctParentAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(loadResult.IsSuccess, $"Load with the parent's correct password must succeed, but failed: '{loadResult.ResponseCode}'.");

            uint itemHandle;
            using(LoadResponse loaded = loadResult.Value)
            {
                itemHandle = loaded.ObjectHandle.Value;
            }

            TpmResult<FlushContextResponse> flushResult = await FlushAsync(tpm, registry, trackingPool.Pool, itemHandle).ConfigureAwait(false);
            Assert.IsTrue(flushResult.IsSuccess, $"FlushContext (loaded item) failed: '{flushResult.ResponseCode}'.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A successful Load, once its loaded object is flushed, must return every carrier this window rented — the supplied parent password included.");
    }

    /// <summary>
    /// A REFUSED <c>TPM2_EvictControl()</c> under a WRONG owner password returns the supplied owner password
    /// carrier to the pool: the owner-hierarchy auth slot (TPM 2.0 Library Part 3, clause 28.5) is DA-exempt
    /// (Part 1, clause 16.8.1), so the refusal is a bare, uncharged <c>TPM_RC_BAD_AUTH</c> whose disposing
    /// arm must still release the parse-rented carrier.
    /// </summary>
    [TestMethod]
    public async Task RefusedEvictControlWithWrongOwnerPasswordReturnsTheSuppliedPasswordCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-refused-evict").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //The primary is minted BEFORE the owner rotation: TPM2_CreatePrimary's own hierarchy slot verifies the
        //owner password too, and the fixture helper authorizes with an empty session.
        uint transientHandle;
        using(CreatePrimaryResponse primary = await CreateEccDecryptKeyAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false))
        {
            transientHandle = primary.ObjectHandle.Value;
        }

        await RotateHierarchyAuthAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, currentAuth: default, newAuth: PasswordSlotAuthBytes).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            TpmResult<EvictControlResponse> result = await EvictControlWithAuthAsync(
                tpm, registry, trackingPool.Pool, transientHandle, PersistentHandle, WrongPasswordSlotAuthBytes).ConfigureAwait(false);
            Assert.IsTrue(result.IsTpmError, "A wrong owner password must be refused.");
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_BAD_AUTH, result.ResponseCode,
                "A wrong owner password is a bare, uncharged TPM_RC_BAD_AUTH — the owner hierarchy is DA-exempt.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return the supplied owner password carrier to the pool.");
    }

    /// <summary>
    /// A SUCCESSFUL persist/evict cycle under the owner's REAL password returns every carrier this window
    /// rented to the pool — the supplied owner password on each call, and the persisted copy's own carrier
    /// once it is evicted again (TPM 2.0 Library Part 3, clause 28.5).
    /// </summary>
    [TestMethod]
    public async Task SuccessfulEvictControlWithOwnerPasswordReturnsTheSuppliedPasswordCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-success-evict").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //The primary is minted BEFORE the owner rotation: TPM2_CreatePrimary's own hierarchy slot verifies the
        //owner password too, and the fixture helper authorizes with an empty session.
        uint transientHandle;
        using(CreatePrimaryResponse primary = await CreateEccDecryptKeyAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false))
        {
            transientHandle = primary.ObjectHandle.Value;
        }

        await RotateHierarchyAuthAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, currentAuth: default, newAuth: PasswordSlotAuthBytes).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            TpmResult<EvictControlResponse> persistResult = await EvictControlWithAuthAsync(
                tpm, registry, trackingPool.Pool, transientHandle, PersistentHandle, PasswordSlotAuthBytes).ConfigureAwait(false);
            Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

            TpmResult<EvictControlResponse> evictResult = await EvictControlWithAuthAsync(
                tpm, registry, trackingPool.Pool, PersistentHandle, PersistentHandle, PasswordSlotAuthBytes).ConfigureAwait(false);
            Assert.IsTrue(evictResult.IsSuccess, $"EvictControl (evict) failed: '{evictResult.ResponseCode}'.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The persist/evict cycle must return every supplied owner password carrier and the persisted copy's own carrier to the pool.");
    }

    /// <summary>
    /// A REFUSED <c>TPM2_CreatePrimary()</c> under a WRONG owner-hierarchy password returns the supplied
    /// hierarchy password carrier to the pool: the owner-hierarchy auth slot (TPM 2.0 Library Part 3, clause
    /// 24.1) is DA-exempt (Part 1, clause 16.8.1), so the refusal is a bare, uncharged
    /// <c>TPM_RC_BAD_AUTH</c>.
    /// </summary>
    [TestMethod]
    public async Task RefusedCreatePrimaryWithWrongHierarchyPasswordReturnsTheSuppliedPasswordCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-refused-primary-hierarchy").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await RotateHierarchyAuthAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, currentAuth: default, newAuth: PasswordSlotAuthBytes).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
                TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
                TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), trackingPool.Pool, noDa: true);
            using TpmPasswordSession wrongHierarchyAuth = TpmPasswordSession.Create(WrongPasswordSlotAuthBytes, trackingPool.Pool);

            TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
                tpm, input, [wrongHierarchyAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsTpmError, "A wrong owner-hierarchy password must be refused.");
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_BAD_AUTH, result.ResponseCode,
                "A wrong owner-hierarchy password is a bare, uncharged TPM_RC_BAD_AUTH.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return the supplied hierarchy password carrier to the pool.");
    }

    /// <summary>
    /// A SUCCESSFUL <c>TPM2_CreatePrimary()</c> under the owner hierarchy's REAL password, once the created
    /// object is flushed, returns every carrier this window rented to the pool (TPM 2.0 Library Part 3,
    /// clause 24.1).
    /// </summary>
    [TestMethod]
    public async Task SuccessfulCreatePrimaryWithHierarchyPasswordReturnsTheSuppliedPasswordCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-success-primary-hierarchy").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await RotateHierarchyAuthAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, currentAuth: default, newAuth: PasswordSlotAuthBytes).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
                TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
                TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), trackingPool.Pool, noDa: true);
            using TpmPasswordSession correctHierarchyAuth = TpmPasswordSession.Create(PasswordSlotAuthBytes, trackingPool.Pool);

            TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
                tpm, input, [correctHierarchyAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"CreatePrimary with the owner hierarchy's correct password must succeed, but failed: '{result.ResponseCode}'.");

            uint objectHandle;
            using(CreatePrimaryResponse primary = result.Value)
            {
                objectHandle = primary.ObjectHandle.Value;
            }

            TpmResult<FlushContextResponse> flushResult = await FlushAsync(tpm, registry, trackingPool.Pool, objectHandle).ConfigureAwait(false);
            Assert.IsTrue(flushResult.IsSuccess, $"FlushContext (primary) failed: '{flushResult.ResponseCode}'.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The flushed object must return the supplied hierarchy password carrier and the retained private key to the pool.");
    }

    /// <summary>
    /// A REFUSED <c>TPM2_Sign()</c> under a WRONG key password returns the supplied key password carrier to
    /// the pool: the signing key's slot (Auth Index 1, Auth Role USER — TPM 2.0 Library Part 3, clause 20.5)
    /// now compares the supplied password against the key's retained authValue.
    /// </summary>
    [TestMethod]
    public async Task RefusedSignWithWrongKeyPasswordReturnsTheSuppliedPasswordCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-refused-sign").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningKeyWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, PasswordSlotAuth, noDa: false).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(PasswordSlotNonce, trackingPool.Pool, TestContext.CancellationToken).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using SignInput signInput = SignInput.ForEcdsa(key.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);
            using TpmPasswordSession wrongKeyAuth = TpmPasswordSession.Create(WrongPasswordSlotAuthBytes, trackingPool.Pool);

            TpmResult<SignResponse> result = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signInput, [wrongKeyAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsTpmError, "A wrong key password must be refused.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode,
                "A wrong key password over TPM2_Sign's plain TPM_RS_PW session names the key slot (index 0), session-index-encoded.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return the supplied key password carrier to the pool.");
    }

    /// <summary>
    /// A SUCCESSFUL <c>TPM2_Sign()</c> under the key's REAL password returns the supplied key password
    /// carrier to the pool: the key-slot compare (TPM 2.0 Library Part 3, clause 20.5) is the supplied
    /// password carrier's terminal use.
    /// </summary>
    [TestMethod]
    public async Task SuccessfulSignWithKeyPasswordReturnsTheSuppliedPasswordCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-success-sign").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEccSigningKeyWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, PasswordSlotAuth, noDa: false).ConfigureAwait(false);
        byte[] digest = await ComputeSha256Async(PasswordSlotNonce, trackingPool.Pool, TestContext.CancellationToken).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using SignInput signInput = SignInput.ForEcdsa(key.ObjectHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);
            using TpmPasswordSession correctKeyAuth = TpmPasswordSession.Create(PasswordSlotAuthBytes, trackingPool.Pool);

            TpmResult<SignResponse> result = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signInput, [correctKeyAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"Sign with the key's correct password must succeed, but failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The completed signature must return the supplied key password carrier to the pool.");
    }

    /// <summary>
    /// A REFUSED <c>TPM2_CertifyCreation()</c> under a WRONG sign password returns the supplied sign
    /// password carrier to the pool: the signing key's slot (Auth Index 1, Auth Role USER — TPM 2.0 Library
    /// Part 3, clause 18.3, Table 99) now compares the supplied password against the key's retained
    /// authValue.
    /// </summary>
    [TestMethod]
    public async Task RefusedCertifyCreationWithWrongSignPasswordReturnsTheSuppliedPasswordCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-refused-certifycreation").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateEccSigningKeyWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, password: null, noDa: true).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateEccSigningKeyWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, PasswordSlotAuth, noDa: false).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
                ak.ObjectHandle, subject.ObjectHandle, PasswordSlotNonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket,
                TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);
            using TpmPasswordSession wrongSignAuth = TpmPasswordSession.Create(WrongPasswordSlotAuthBytes, trackingPool.Pool);

            TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                tpm, certifyCreationInput, [wrongSignAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsTpmError, "A wrong sign password must be refused.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode,
                "A wrong sign password over TPM2_CertifyCreation's plain TPM_RS_PW session names the sign slot (index 0), session-index-encoded.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return the supplied sign password carrier to the pool.");
    }

    /// <summary>
    /// A SUCCESSFUL <c>TPM2_CertifyCreation()</c> under the sign key's REAL password returns the supplied
    /// sign password carrier to the pool (TPM 2.0 Library Part 3, clause 18.3, Table 99).
    /// </summary>
    [TestMethod]
    public async Task SuccessfulCertifyCreationWithSignPasswordReturnsTheSuppliedPasswordCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-success-certifycreation").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateEccSigningKeyWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, password: null, noDa: true).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateEccSigningKeyWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, PasswordSlotAuth, noDa: false).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
                ak.ObjectHandle, subject.ObjectHandle, PasswordSlotNonce, subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket,
                TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);
            using TpmPasswordSession correctSignAuth = TpmPasswordSession.Create(PasswordSlotAuthBytes, trackingPool.Pool);

            TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                tpm, certifyCreationInput, [correctSignAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"CertifyCreation with the sign key's correct password must succeed, but failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The completed certification must return the supplied sign password carrier to the pool.");
    }

    /// <summary>
    /// A REFUSED <c>TPM2_Quote()</c> under a WRONG sign password returns the supplied sign password carrier
    /// to the pool: the signing key's slot (Auth Index 1, Auth Role USER — TPM 2.0 Library Part 3, clause
    /// 18.4) now compares the supplied password against the key's retained authValue.
    /// </summary>
    [TestMethod]
    public async Task RefusedQuoteWithWrongSignPasswordReturnsTheSuppliedPasswordCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-refused-quote").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateEccSigningKeyWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, PasswordSlotAuth, noDa: false).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using QuoteInput quoteInput = QuoteInput.ForEcdsa(
                ak.ObjectHandle, PasswordSlotNonce, TpmAlgIdConstants.TPM_ALG_SHA256, TpmlPcrSelection.Empty, trackingPool.Pool);
            using TpmPasswordSession wrongSignAuth = TpmPasswordSession.Create(WrongPasswordSlotAuthBytes, trackingPool.Pool);

            TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                tpm, quoteInput, [wrongSignAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsTpmError, "A wrong sign password must be refused.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode,
                "A wrong sign password over TPM2_Quote's plain TPM_RS_PW session names the sign slot (index 0), session-index-encoded.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return the supplied sign password carrier to the pool.");
    }

    /// <summary>
    /// A SUCCESSFUL <c>TPM2_Quote()</c> under the sign key's REAL password returns the supplied sign
    /// password carrier to the pool (TPM 2.0 Library Part 3, clause 18.4).
    /// </summary>
    [TestMethod]
    public async Task SuccessfulQuoteWithSignPasswordReturnsTheSuppliedPasswordCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-success-quote").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateEccSigningKeyWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, PasswordSlotAuth, noDa: false).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using QuoteInput quoteInput = QuoteInput.ForEcdsa(
                ak.ObjectHandle, PasswordSlotNonce, TpmAlgIdConstants.TPM_ALG_SHA256, TpmlPcrSelection.Empty, trackingPool.Pool);
            using TpmPasswordSession correctSignAuth = TpmPasswordSession.Create(PasswordSlotAuthBytes, trackingPool.Pool);

            TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                tpm, quoteInput, [correctSignAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"Quote with the sign key's correct password must succeed, but failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The completed quote must return the supplied sign password carrier to the pool.");
    }

    /// <summary>
    /// A REFUSED <c>TPM2_Certify()</c> under a WRONG password at the certified object's slot (index 0)
    /// returns both supplied password carriers to the pool: the object slot (Auth Index 1, Auth Role ADMIN —
    /// TPM 2.0 Library Part 3, clause 18.2) now compares the supplied password against the object's retained
    /// authValue, ahead of the signer slot's own standing.
    /// </summary>
    [TestMethod]
    public async Task RefusedCertifyWithWrongObjectPasswordReturnsTheSuppliedPasswordCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-refused-certify").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subjectObject = await CreateEccSigningKeyWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, PasswordSlotAuth, noDa: false).ConfigureAwait(false);
        using CreatePrimaryResponse signKey = await CreateEccSigningKeyWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, PasswordSlotAuth, noDa: false).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using CertifyInput certifyInput = CertifyInput.ForEcdsa(
                subjectObject.ObjectHandle, signKey.ObjectHandle, PasswordSlotNonce, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);
            using TpmPasswordSession wrongObjectAuth = TpmPasswordSession.Create(WrongPasswordSlotAuthBytes, trackingPool.Pool);
            using TpmPasswordSession correctSignAuth = TpmPasswordSession.Create(PasswordSlotAuthBytes, trackingPool.Pool);

            TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                tpm, certifyInput, [wrongObjectAuth, correctSignAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsTpmError, "A wrong object password must be refused.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode,
                "A wrong object password over TPM2_Certify's slot 0 names the object slot (index 0), session-index-encoded.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return both supplied password carriers to the pool.");
    }

    /// <summary>
    /// A SUCCESSFUL <c>TPM2_Certify()</c> under BOTH slots' REAL passwords returns both supplied password
    /// carriers to the pool (TPM 2.0 Library Part 3, clause 18.2).
    /// </summary>
    [TestMethod]
    public async Task SuccessfulCertifyWithBothSlotPasswordsReturnsTheSuppliedPasswordCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-success-certify").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subjectObject = await CreateEccSigningKeyWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, PasswordSlotAuth, noDa: false).ConfigureAwait(false);
        using CreatePrimaryResponse signKey = await CreateEccSigningKeyWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, PasswordSlotAuth, noDa: false).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using CertifyInput certifyInput = CertifyInput.ForEcdsa(
                subjectObject.ObjectHandle, signKey.ObjectHandle, PasswordSlotNonce, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);
            using TpmPasswordSession correctObjectAuth = TpmPasswordSession.Create(PasswordSlotAuthBytes, trackingPool.Pool);
            using TpmPasswordSession correctSignAuth = TpmPasswordSession.Create(PasswordSlotAuthBytes, trackingPool.Pool);

            TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                tpm, certifyInput, [correctObjectAuth, correctSignAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"Certify with both slots' correct passwords must succeed, but failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The completed certification must return both supplied password carriers to the pool.");
    }

    /// <summary>
    /// A REFUSED <c>TPM2_GetTime()</c> under a WRONG password at the signing key's slot (index 1) returns
    /// both supplied password carriers to the pool: the sign slot (Auth Index 2, Auth Role USER — TPM 2.0
    /// Library Part 3, clause 18.7, Table 107) now compares the supplied password against the key's retained
    /// authValue, session-index-encoded at its own slot regardless of the privacy-administrator slot's
    /// standing.
    /// </summary>
    [TestMethod]
    public async Task RefusedGetTimeWithWrongSignPasswordReturnsTheSuppliedPasswordCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-refused-gettime").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await RotateHierarchyAuthAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, currentAuth: default, newAuth: PasswordSlotAuthBytes).ConfigureAwait(false);
        using CreatePrimaryResponse signKey = await CreateEccSigningKeyWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, PasswordSlotAuth, noDa: false).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(
                signKey.ObjectHandle, PasswordSlotNonce, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);
            using TpmPasswordSession correctEndorsementAuth = TpmPasswordSession.Create(PasswordSlotAuthBytes, trackingPool.Pool);
            using TpmPasswordSession wrongSignAuth = TpmPasswordSession.Create(WrongPasswordSlotAuthBytes, trackingPool.Pool);

            TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                tpm, getTimeInput, [correctEndorsementAuth, wrongSignAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsTpmError, "A wrong sign password must be refused.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 1), result.ResponseCode,
                "A wrong sign password over TPM2_GetTime's slot 1 names the sign slot (index 1), session-index-encoded.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return both supplied password carriers to the pool.");
    }

    /// <summary>
    /// A SUCCESSFUL <c>TPM2_GetTime()</c> under BOTH slots' REAL passwords — the rotated Endorsement
    /// hierarchy at slot 0 and the signing key at slot 1 — returns both supplied password carriers to the
    /// pool (TPM 2.0 Library Part 3, clause 18.7, Table 107).
    /// </summary>
    [TestMethod]
    public async Task SuccessfulGetTimeWithBothSlotPasswordsReturnsTheSuppliedPasswordCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-success-gettime").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await RotateHierarchyAuthAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, currentAuth: default, newAuth: PasswordSlotAuthBytes).ConfigureAwait(false);
        using CreatePrimaryResponse signKey = await CreateEccSigningKeyWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, PasswordSlotAuth, noDa: false).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using GetTimeInput getTimeInput = GetTimeInput.ForEcdsa(
                signKey.ObjectHandle, PasswordSlotNonce, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);
            using TpmPasswordSession correctEndorsementAuth = TpmPasswordSession.Create(PasswordSlotAuthBytes, trackingPool.Pool);
            using TpmPasswordSession correctSignAuth = TpmPasswordSession.Create(PasswordSlotAuthBytes, trackingPool.Pool);

            TpmResult<GetTimeResponse> result = await TpmCommandExecutor.ExecuteAsync<GetTimeResponse>(
                tpm, getTimeInput, [correctEndorsementAuth, correctSignAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"GetTime with both slots' correct passwords must succeed, but failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The completed attestation must return both supplied password carriers to the pool.");
    }

    /// <summary>
    /// A REFUSED all-password <c>TPM2_NV_Certify()</c> against an nvIndex handle that was never defined
    /// returns the parse-rented sign password carrier to the pool: the Index lookup (TPM 2.0 Library Part
    /// 3, clause 31.16) fails before either authorization slot's credential is compared, and the disposing
    /// reject arm releases <c>TpmNvCertifyRequested</c>'s owned SuppliedSignPassword exactly as every other
    /// refusing arm does — including the USER-role gate at clause 5.6, check 7.1 — so no refusal orphans
    /// the parser's rental. The supplied sign password is deliberately NON-empty: an empty one would parse
    /// to the dispose-immune <see cref="Tpm2bAuth.Empty"/> sentinel, which rents nothing and would make this
    /// balance vacuous — only a genuinely rented carrier can prove the refusing arm returns it.
    /// </summary>
    [TestMethod]
    public async Task RefusedNvCertifyOfUndefinedIndexReturnsTheSuppliedSignPasswordCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-refused-nvcertify").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateEccSigningKeyWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, password: null, noDa: true).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
                ak.ObjectHandle, NvIndexHandle, NvIndexHandle, PasswordSlotNonce, TpmAlgIdConstants.TPM_ALG_SHA256, NvDataSize, offset: 0, trackingPool.Pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.Create(WrongPasswordSlotAuthBytes, trackingPool.Pool);
            using TpmPasswordSession indexAuth = TpmPasswordSession.Create(WrongPasswordSlotAuthBytes, trackingPool.Pool);

            TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, nvCertifyInput, [signAuth, indexAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsTpmError, "An nvIndex handle that was never defined must be refused.");
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_HANDLE, result.ResponseCode,
                "An undefined nvIndex handle is a bare TPM_RC_HANDLE, refused before either slot's credential is compared (TPM 2.0 Library Part 3, clause 31.16).");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return the parse-rented sign password carrier to the pool.");
    }

    /// <summary>
    /// A SUCCESSFUL all-password <c>TPM2_NV_Certify()</c> returns the parse-rented sign password carrier to
    /// the pool once the response is disposed: the sign slot's own credential compare (TPM 2.0 Library Part
    /// 3, clause 5.6, checks 9/10; clause 31.16's <c>@signHandle</c>) is <c>TpmNvCertifyRequested</c>'s
    /// SuppliedSignPassword carrier's terminal use, and the transition disposes it there rather than
    /// holding it for the remainder of the command. The signing key carries a NON-empty authValue and the
    /// matching non-empty password is supplied: an empty one would parse to the dispose-immune
    /// <see cref="Tpm2bAuth.Empty"/> sentinel, which rents nothing and would make this balance vacuous —
    /// only a genuinely rented carrier can prove the transition's terminal dispose returns it.
    /// </summary>
    [TestMethod]
    public async Task SuccessfulNvCertifyReturnsTheSuppliedSignPasswordCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-success-nvcertify").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<NvDefineSpaceResponse> defineResult = await DefineIndexAsync(
            tpm, registry, trackingPool.Pool, NvIndexHandle, PasswordSlotAuthBytes).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");

        using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(NvWriteData, trackingPool.Pool);
        var writeInput = new NvWriteInput(NvIndexHandle, NvIndexHandle, writeInputBuffer, Offset: 0);
        using(TpmPasswordSession writeAuth = TpmPasswordSession.Create(PasswordSlotAuthBytes, trackingPool.Pool))
        {
            TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
                tpm, writeInput, [writeAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(writeResult.IsSuccess, $"NV_Write failed: '{writeResult.ResponseCode}'.");
        }

        const string SignKeyPassword = "nv-certify-sign-carrier";
        using CreatePrimaryResponse ak = await CreateEccSigningKeyWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, password: SignKeyPassword, noDa: true).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
                ak.ObjectHandle, NvIndexHandle, NvIndexHandle, PasswordSlotNonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)NvWriteData.Length, offset: 0, trackingPool.Pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.Create(SignKeyPassword, trackingPool.Pool);
            using TpmPasswordSession indexAuth = TpmPasswordSession.Create(PasswordSlotAuthBytes, trackingPool.Pool);

            TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, nvCertifyInput, [signAuth, indexAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"NV_Certify with the sign key's correct password must succeed, but failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The completed certification must return the supplied sign password carrier to the pool.");
    }

    /// <summary>
    /// A REFUSED <c>TPM2_PolicyNV()</c> under a WRONG password at the authorizing Index itself returns the
    /// supplied index password carrier to the pool: the index arm (TPM 2.0 Library Part 3, clause 23.9) of a
    /// DA-protected Index refuses with a bare (never session-encoded) <c>TPM_RC_AUTH_FAIL</c>, matching every
    /// other NV command's authorization family.
    /// </summary>
    [TestMethod]
    public async Task RefusedPolicyNvWithWrongIndexPasswordReturnsTheSuppliedPasswordCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-refused-policynv").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<NvDefineSpaceResponse> defineResult = await DefineIndexAsync(
            tpm, registry, trackingPool.Pool, NvIndexHandle, PasswordSlotAuthBytes, TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
            SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");
        using StartAuthSessionResponse policyStarted = startResult.Value;
        uint policySessionHandle = policyStarted.SessionHandle.Value;

        long baseline = trackingPool.OutstandingCount;
        {
            var policyNvInput = new PolicyNvInput(NvIndexHandle, NvIndexHandle, policySessionHandle, new byte[] { 0x01 }, 0, TpmEoConstants.TPM_EO_EQ);
            using TpmPasswordSession wrongIndexAuth = TpmPasswordSession.Create(WrongPasswordSlotAuthBytes, trackingPool.Pool);

            TpmResult<PolicyNvResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyNvResponse>(
                tpm, policyNvInput, [wrongIndexAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsTpmError, "A wrong index password must be refused.");
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_FAIL, result.ResponseCode,
                "A wrong password against a DA-protected Index is a bare TPM_RC_AUTH_FAIL — the NV family never session-encodes.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return the supplied index password carrier to the pool.");

        _ = await tpm.FlushContextAsync(policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// A SUCCESSFUL <c>TPM2_PolicyNV()</c> under the authorizing Index's REAL password returns the supplied
    /// index password carrier to the pool (TPM 2.0 Library Part 3, clause 23.9). A succeeding assertion also
    /// advances the session's policyDigest, which the session then owns until it is evicted, so the balance is
    /// measured across the flush — where the supplied password's return is the only outcome left to prove.
    /// </summary>
    [TestMethod]
    public async Task SuccessfulPolicyNvWithIndexPasswordReturnsTheSuppliedPasswordCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-success-policynv").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<NvDefineSpaceResponse> defineResult = await DefineIndexAsync(
            tpm, registry, trackingPool.Pool, NvIndexHandle, PasswordSlotAuthBytes, TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
            SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");
        using StartAuthSessionResponse policyStarted = startResult.Value;
        uint policySessionHandle = policyStarted.SessionHandle.Value;

        long baseline = trackingPool.OutstandingCount;
        {
            var policyNvInput = new PolicyNvInput(NvIndexHandle, NvIndexHandle, policySessionHandle, new byte[] { 0x01 }, 0, TpmEoConstants.TPM_EO_EQ);
            using TpmPasswordSession correctIndexAuth = TpmPasswordSession.Create(PasswordSlotAuthBytes, trackingPool.Pool);

            TpmResult<PolicyNvResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyNvResponse>(
                tpm, policyNvInput, [correctIndexAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"PolicyNV with the Index's correct password must succeed, but failed: '{result.ResponseCode}'.");
        }

        Assert.AreEqual(
            baseline + 1, trackingPool.OutstandingCount,
            "The completed authorization must return the supplied index password carrier and leave exactly the advanced policyDigest the session now owns.");

        _ = await tpm.FlushContextAsync(policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Evicting the session must return its policyDigest too, leaving nothing the assertion rented outstanding.");
    }

    /// <summary>
    /// A REFUSED plain-password <c>TPM2_ActivateCredential()</c> under a WRONG password at the activate
    /// object's slot (index 0) returns both supplied password carriers to the pool: the activate slot (Auth
    /// Index 1, Auth Role ADMIN — TPM 2.0 Library Part 3, clause 12.5) now compares the supplied password
    /// against the retained authValue, session-index-encoded at its own slot regardless of the key slot's
    /// own standing.
    /// </summary>
    [TestMethod]
    public async Task RefusedActivateCredentialWithWrongActivatePasswordReturnsTheSuppliedPasswordCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-refused-activate").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateEccStorageParentWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, PasswordSlotAuth, noDa: false).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateEccSigningKeyWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, PasswordSlotAuth, noDa: false).ConfigureAwait(false);

        (byte[] credentialBlob, byte[] secret) = await MakeCredentialBytesAsync(
            tpm, registry, trackingPool.Pool, ek.ObjectHandle, ak.Name.Span.ToArray()).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                ak.ObjectHandle, ek.ObjectHandle, credentialBlob, secret, trackingPool.Pool);
            using TpmPasswordSession wrongActivateAuth = TpmPasswordSession.Create(WrongPasswordSlotAuthBytes, trackingPool.Pool);
            using TpmPasswordSession correctKeyAuth = TpmPasswordSession.Create(PasswordSlotAuthBytes, trackingPool.Pool);

            TpmResult<ActivateCredentialResponse> result = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                tpm, activateInput, [wrongActivateAuth, correctKeyAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsTpmError, "A wrong activate password must be refused.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode,
                "A wrong activate password over TPM2_ActivateCredential's slot 0 names the activate slot (index 0), session-index-encoded.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return both supplied password carriers to the pool.");
    }

    /// <summary>
    /// A SUCCESSFUL plain-password <c>TPM2_ActivateCredential()</c> under BOTH slots' REAL passwords returns
    /// both supplied password carriers to the pool (TPM 2.0 Library Part 3, clause 12.5).
    /// </summary>
    [TestMethod]
    public async Task SuccessfulActivateCredentialWithBothSlotPasswordsReturnsTheSuppliedPasswordCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-success-activate").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateEccStorageParentWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, PasswordSlotAuth, noDa: false).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateEccSigningKeyWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, PasswordSlotAuth, noDa: false).ConfigureAwait(false);

        (byte[] credentialBlob, byte[] secret) = await MakeCredentialBytesAsync(
            tpm, registry, trackingPool.Pool, ek.ObjectHandle, ak.Name.Span.ToArray()).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                ak.ObjectHandle, ek.ObjectHandle, credentialBlob, secret, trackingPool.Pool);
            using TpmPasswordSession correctActivateAuth = TpmPasswordSession.Create(PasswordSlotAuthBytes, trackingPool.Pool);
            using TpmPasswordSession correctKeyAuth = TpmPasswordSession.Create(PasswordSlotAuthBytes, trackingPool.Pool);

            TpmResult<ActivateCredentialResponse> result = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                tpm, activateInput, [correctActivateAuth, correctKeyAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"ActivateCredential with both slots' correct passwords must succeed, but failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The completed activation must return both supplied password carriers to the pool.");
    }

    /// <summary>
    /// A REFUSED over-session <c>TPM2_ActivateCredential()</c> under a WRONG password at the activate
    /// object's slot (index 0) returns the supplied activate password carrier to the pool: slot 1 carries a
    /// real (non-<c>TPM_RS_PW</c>) HMAC session folding the key's CORRECT password, which routes the parse
    /// to the over-session form (<c>OnActivateCredentialOverSessions</c>) — proving the activate-slot compare
    /// (TPM 2.0 Library Part 3, clause 12.5) is inserted identically ahead of that form's own policy checks.
    /// </summary>
    [TestMethod]
    public async Task RefusedActivateCredentialOverSessionWithWrongActivatePasswordReturnsTheSuppliedPasswordCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-refused-activate-oversession").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ek = await CreateEccStorageParentWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, PasswordSlotAuth, noDa: false).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateEccSigningKeyWithPasswordAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, PasswordSlotAuth, noDa: false).ConfigureAwait(false);

        (byte[] credentialBlob, byte[] secret) = await MakeCredentialBytesAsync(
            tpm, registry, trackingPool.Pool, ek.ObjectHandle, ak.Name.Span.ToArray()).ConfigureAwait(false);

        StartAuthSessionInput keyStartInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg);
        TpmResult<StartAuthSessionResponse> keyStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, keyStartInput, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(keyStartResult.IsSuccess, $"StartAuthSession (key slot) failed: '{keyStartResult.ResponseCode}'.");
        StartAuthSessionResponse keyStarted = keyStartResult.Value;
        uint keySessionHandle = keyStarted.SessionHandle.Value;

        try
        {
            using TpmSession keySession = new(new TpmHandle(keySessionHandle), keyStarted.NonceTPM, SessionAlg, trackingPool.Pool);
            keySession.SetAuthValue(PasswordSlotAuthBytes, trackingPool.Pool);
            keySession.SessionAttributes = TpmaSession.CONTINUE_SESSION;

            long baseline = trackingPool.OutstandingCount;
            {
                using ActivateCredentialInput activateInput = ActivateCredentialInput.Create(
                    ak.ObjectHandle, ek.ObjectHandle, credentialBlob, secret, trackingPool.Pool);
                using TpmPasswordSession wrongActivateAuth = TpmPasswordSession.Create(WrongPasswordSlotAuthBytes, trackingPool.Pool);
                ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), ek.Name.Span.ToArray()];

                TpmResult<ActivateCredentialResponse> result = await TpmCommandExecutor.ExecuteAsync<ActivateCredentialResponse>(
                    tpm, activateInput, [wrongActivateAuth, keySession], handleNames, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsTpmError, "A wrong activate password must be refused.");
                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode,
                    "A wrong activate password over the over-session form's slot 0 names the activate slot (index 0), session-index-encoded.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The refusal must return the supplied activate password carrier to the pool.");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(keySessionHandle), [], null, trackingPool.Pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A flushed <c>TPM2_CreatePrimary()</c> object with a non-empty authValue returns every carrier rental
    /// to the pool: the parse-rented userAuth rides the request and the create action into the effect, is
    /// installed on the durable key state without a copy, and <c>TPM2_FlushContext()</c>'s eviction disposal
    /// releases it together with the retained private key — the whole transfer chain leaks nothing and
    /// double-disposes nothing.
    /// </summary>
    [TestMethod]
    public async Task FlushedPrimaryWithAuthReturnsItsCarrierRentalsToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-flushed-primary").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;
        {
            using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
                TpmRh.TPM_RH_OWNER, "parent-auth-proof", TpmEccCurveConstants.TPM_ECC_NIST_P256, trackingPool.Pool, noDa: true);
            using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);

            TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
                tpm, input, [ownerAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"CreatePrimary (with authValue) failed: '{result.ResponseCode}'.");

            uint objectHandle;
            using(CreatePrimaryResponse primary = result.Value)
            {
                objectHandle = primary.ObjectHandle.Value;
            }

            TpmResult<FlushContextResponse> flushResult = await FlushAsync(tpm, registry, trackingPool.Pool, objectHandle).ConfigureAwait(false);
            Assert.IsTrue(flushResult.IsSuccess, $"FlushContext (primary) failed: '{flushResult.ResponseCode}'.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The flushed object must return the transferred userAuth carrier and the retained private key to the pool.");
    }

    /// <summary>
    /// A <c>TPM2_Create()</c> frame truncated INSIDE <c>inSensitive</c> — the authValue half present, the
    /// sensitive-data half missing — is answered on the wire with <c>TPM_RC_INSUFFICIENT</c> (TPM 2.0 Library
    /// Part 3, clause 5.8.2, Table 2), and the refusal must still return the already-rented authValue carrier
    /// to the pool: the structure parser rents the auth half first, so a failing data read is the one window
    /// in which that rental has no other owner.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.8.2, Table 2</see>.
    /// </summary>
    [TestMethod]
    public async Task TruncatedSealCreateParseReturnsTheAuthRentalToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-truncated-create").ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        byte[] command = BuildSealCreateFrameTruncatedAfterAuth();
        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(command, trackingPool.Pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The truncated frame must reach the simulator and be answered, never thrown out of it.");
        using(TpmResponse response = submitResult.Value)
        {
            var reader = new TpmReader(response.AsReadOnlySpan());
            TpmHeader responseHeader = TpmHeader.Parse(ref reader);
            Assert.AreEqual(TpmRcConstants.TPM_RC_INSUFFICIENT, (TpmRcConstants)responseHeader.Code, "A frame truncated inside inSensitive must be refused with TPM_RC_INSUFFICIENT.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The truncated-frame refusal must return the parse-rented authValue carrier to the pool.");
    }

    /// <summary>
    /// Frames a plain-password <c>TPM2_Create()</c> whose <c>inSensitive</c> declares an authValue and a
    /// sensitive-data half but ends right after the authValue octets — the data half's size prefix is
    /// missing, so its read runs off the end of the frame.
    /// </summary>
    /// <returns>The malformed command frame.</returns>
    private static byte[] BuildSealCreateFrameTruncatedAfterAuth()
    {
        const int AuthValueLength = 32;
        const int SessionLength = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);
        const int InSensitiveLength = sizeof(ushort) + sizeof(ushort) + AuthValueLength;
        const int TotalLength = TpmHeader.HeaderSize + sizeof(uint) + sizeof(uint) + SessionLength + InSensitiveLength;

        Span<byte> authValue = stackalloc byte[AuthValueLength];
        authValue.Fill(0x41);

        byte[] frame = new byte[TotalLength];
        var writer = new TpmWriter(frame);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, TotalLength, (uint)TpmCcConstants.TPM_CC_Create);
        header.WriteTo(ref writer);
        writer.WriteUInt32(TpmSimulatorState.TransientHandleBase);

        //Authorization area: one TPM_RS_PW session (handle, empty nonce, attributes, empty hmac).
        writer.WriteUInt32(SessionLength);
        writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
        writer.WriteUInt16(0);
        writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
        writer.WriteUInt16(0);

        //inSensitive: the outer size declares the auth half ONLY; the frame then ends, so the
        //sensitive-data half's own size prefix is missing.
        writer.WriteUInt16(InSensitiveLength - sizeof(ushort));
        writer.WriteTpm2b(authValue);

        return frame;
    }

    /// <summary>
    /// A TPM Resume flushes loaded objects: "An object context is only removed from TPM memory with
    /// TPM2_FlushContext(), deletion of the associated hierarchy seed, or TPM2_Startup()" (TPM 2.0 Library
    /// Part 1, clause 27.4) — the object half of the rule the session trio above proves, realized as the
    /// reference's unconditional <c>ObjectStartup()</c> slot clear. A transient key loaded before
    /// <c>Shutdown(STATE)</c>/<c>Startup(STATE)</c> is gone afterwards: flushing its handle answers
    /// <c>TPM_RC_HANDLE</c>, exactly as a never-loaded handle does.
    /// </summary>
    [TestMethod]
    public async Task StartupResumeFlushesLoadedObjects()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-secmem-resume-objects").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint transientHandle;
        using(CreatePrimaryResponse primary = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false))
        {
            transientHandle = primary.ObjectHandle.Value;
        }

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE, TpmSuConstants.TPM_SU_STATE).ConfigureAwait(false);

        TpmResult<FlushContextResponse> flushResult = await FlushAsync(tpm, registry, pool, transientHandle).ConfigureAwait(false);
        Assert.IsTrue(
            flushResult.IsTpmError,
            "A TPM Resume removes every object context from TPM memory, so flushing the pre-resume transient handle must be refused.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_HANDLE, flushResult.ResponseCode,
            "A TPM Resume removes every object context from TPM memory, so flushing the pre-resume transient handle must answer TPM_RC_HANDLE.");

        //With every RAM slot free again, transient handle assignment restarts where a fresh TPM's does: the
        //first post-resume object receives the same handle the first pre-resume object did.
        using CreatePrimaryResponse reloaded = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.AreEqual(
            transientHandle, reloaded.ObjectHandle.Value,
            "The startup flush must return the transient handle counter to its range base, as a real TPM's first-free-slot assignment does after a reboot.");
    }

    /// <summary>
    /// A TPM Reset's object flush genuinely RETURNS the flushed objects' carrier rentals to the pool: a
    /// transient storage parent's retained private key and a loaded sealed object's data and authValue all
    /// ride owned carriers, and the pool's outstanding-rental count returns to its pre-scenario baseline once
    /// <c>Shutdown(CLEAR)</c>/<c>Startup(CLEAR)</c> completes (TPM 2.0 Library Part 1, clause 27.4).
    /// </summary>
    [TestMethod]
    public async Task StartupResetReturnsObjectCarrierRentalsToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-reset-objects").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        uint parentHandle;
        using(CreatePrimaryResponse primary = await CreateEccDecryptKeyAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false))
        {
            parentHandle = primary.ObjectHandle.Value;
        }

        using(LoadResponse loaded = await SealAndLoadSealedItemAsync(tpm, registry, trackingPool.Pool, parentHandle).ConfigureAwait(false))
        {
            Assert.AreNotEqual(0u, loaded.ObjectHandle.Value, "The sealed item must be loaded for the flush to have a sealed-object carrier to release.");
        }

        Assert.IsGreaterThan(
            baseline, trackingPool.OutstandingCount,
            "The loaded objects must hold live durable carrier rentals, or the balance assertion below is vacuous.");

        await PowerCycleAsync(simulator, trackingPool.Pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A TPM Reset's object flush must return every flushed object's carrier rentals — private keys, sealed data, sealed authValues — to the pool.");
    }

    /// <summary>
    /// A persistent object SURVIVES a TPM Resume while every RAM object context is flushed: clause 27.4's
    /// removal rule names object contexts in TPM memory, and a persisted copy is NV-resident (TPM 2.0 Library
    /// Part 1, clause 27.4; Part 3, clause 28.5). After persisting a key, flushing the transient original, and
    /// resuming, a salted <c>TPM2_StartAuthSession()</c> against the persistent handle still recovers its salt
    /// with the persisted private key — the same wire proof the deep-copy test uses, now across a power cycle.
    /// </summary>
    [TestMethod]
    public async Task PersistentObjectSurvivesStartupResume()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-secmem-persist-resume").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse tpmKey = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint transientHandle = tpmKey.ObjectHandle.Value;
        ReadOnlyMemory<byte> point = ExtractEccPoint(tpmKey);

        TpmResult<EvictControlResponse> persistResult = await EvictControlAsync(tpm, registry, pool, transientHandle, PersistentHandle).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        TpmResult<FlushContextResponse> flushResult = await FlushAsync(tpm, registry, pool, transientHandle).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext (transient original) failed: '{flushResult.ResponseCode}'.");

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE, TpmSuConstants.TPM_SU_STATE).ConfigureAwait(false);

        TpmEccSigningBackend eccBackend = BouncyCastleTpmEccSigningBackend.Create();
        (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, _) = await StartAuthSessionInputExtensions.CreateSaltedHmacSession(
            PersistentHandle, point, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmKeyNameAlg, SessionAlg,
            eccBackend.GenerateKey, eccBackend.ComputeSharedSecret, pool, TestContext.CancellationToken).ConfigureAwait(false);

        uint saltedSessionHandle;
        using(salt)
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                startResult.IsSuccess,
                $"A salted session against the NV-resident persistent copy must start after a TPM Resume, but failed: '{startResult.ResponseCode}'.");
            saltedSessionHandle = startResult.Value.SessionHandle.Value;
        }

        TpmResult<FlushContextResponse> sessionFlush = await FlushAsync(tpm, registry, pool, saltedSessionHandle).ConfigureAwait(false);
        Assert.IsTrue(sessionFlush.IsSuccess, $"FlushContext (salted session) failed: '{sessionFlush.ResponseCode}'.");

        TpmResult<EvictControlResponse> evictResult = await EvictControlAsync(tpm, registry, pool, PersistentHandle, PersistentHandle).ConfigureAwait(false);
        Assert.IsTrue(evictResult.IsSuccess, $"EvictControl (evict persistent copy) failed: '{evictResult.ResponseCode}'.");
    }

    /// <summary>
    /// <c>TPMA_NV_CLEAR_STCLEAR</c> on a TPM Reset: "TPMA_NV_WRITTEN for the Index is CLEAR by TPM Reset or
    /// TPM Restart" (TPM 2.0 Library Part 2, clause 13.4, bit 27; the reference's
    /// <c>NvSetStartupAttributes</c>). An ordinary Index defined with the bit, written, and carried through
    /// <c>Shutdown(CLEAR)</c>/<c>Startup(CLEAR)</c> answers <c>TPM_RC_NV_UNINITIALIZED</c> to a read again.
    /// </summary>
    [TestMethod]
    public async Task ClearStClearIndexLosesWrittenOnReset()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-secmem-stclear-reset").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineWriteAndVerifyIndexAsync(tpm, registry, pool, DefaultIndexAttributes | TpmaNv.TPMA_NV_CLEAR_STCLEAR).ConfigureAwait(false);
        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmResult<NvReadResponse> afterResult = await ReadIndexAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(afterResult.IsTpmError, "A TPM Reset must CLEAR TPMA_NV_WRITTEN on a CLEAR_STCLEAR Index, so the read must be refused.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_UNINITIALIZED, afterResult.ResponseCode,
            "An unwritten Index answers TPM_RC_NV_UNINITIALIZED, exactly as before its first write.");
    }

    /// <summary>
    /// <c>TPMA_NV_CLEAR_STCLEAR</c> on a TPM Restart: the same clearing as
    /// <see cref="ClearStClearIndexLosesWrittenOnReset"/> for the <c>Shutdown(STATE)</c>/<c>Startup(CLEAR)</c>
    /// sequence — clause 13.4's bit 27 names Reset and Restart alike (TPM 2.0 Library Part 2, clause 13.4).
    /// </summary>
    [TestMethod]
    public async Task ClearStClearIndexLosesWrittenOnRestart()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-secmem-stclear-restart").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineWriteAndVerifyIndexAsync(tpm, registry, pool, DefaultIndexAttributes | TpmaNv.TPMA_NV_CLEAR_STCLEAR).ConfigureAwait(false);
        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmResult<NvReadResponse> afterResult = await ReadIndexAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(afterResult.IsTpmError, "A TPM Restart must CLEAR TPMA_NV_WRITTEN on a CLEAR_STCLEAR Index, so the read must be refused.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_UNINITIALIZED, afterResult.ResponseCode,
            "An unwritten Index answers TPM_RC_NV_UNINITIALIZED, exactly as before its first write.");
    }

    /// <summary>
    /// <c>TPMA_NV_CLEAR_STCLEAR</c> across a TPM Resume: the bit clears written-ness on Reset and Restart
    /// only — the reference's <c>NvEntityStartup</c> returns early for <c>SU_RESUME</c> — so the written data
    /// reads back byte-exact after <c>Shutdown(STATE)</c>/<c>Startup(STATE)</c> (TPM 2.0 Library Part 2,
    /// clause 13.4, bit 27).
    /// </summary>
    [TestMethod]
    public async Task ClearStClearIndexKeepsWrittenOnResume()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-secmem-stclear-resume").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineWriteAndVerifyIndexAsync(tpm, registry, pool, DefaultIndexAttributes | TpmaNv.TPMA_NV_CLEAR_STCLEAR).ConfigureAwait(false);
        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE, TpmSuConstants.TPM_SU_STATE).ConfigureAwait(false);

        TpmResult<NvReadResponse> afterResult = await ReadIndexAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(afterResult.IsSuccess, $"A TPM Resume leaves TPMA_NV_WRITTEN as it was, but the read failed: '{afterResult.ResponseCode}'.");

        using NvReadResponse response = afterResult.Value;
        Assert.IsTrue(
            response.Data.SequenceEqual(NvWriteData),
            "The written data must survive a TPM Resume byte-exact.");
    }

    /// <summary>
    /// <c>TPMA_NV_ORDERLY</c> on a TPM Reset: the reference's <c>NvSetStartupAttributes</c> clears
    /// <c>TPMA_NV_WRITTEN</c> for a non-counter orderly Index on <c>SU_RESET</c> — orderly data is only
    /// saved to NV on an orderly shutdown, so a Reset means the RAM image is gone (TPM 2.0 Library Part 2,
    /// clause 13.4, bit 26). A written ordinary orderly Index answers <c>TPM_RC_NV_UNINITIALIZED</c> after
    /// <c>Shutdown(CLEAR)</c>/<c>Startup(CLEAR)</c>.
    /// </summary>
    [TestMethod]
    public async Task OrderlyIndexLosesWrittenOnReset()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-secmem-orderly-reset").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineWriteAndVerifyIndexAsync(tpm, registry, pool, DefaultIndexAttributes | TpmaNv.TPMA_NV_ORDERLY).ConfigureAwait(false);
        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmResult<NvReadResponse> afterResult = await ReadIndexAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(afterResult.IsTpmError, "A TPM Reset must CLEAR TPMA_NV_WRITTEN on a non-counter ORDERLY Index, so the read must be refused.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_UNINITIALIZED, afterResult.ResponseCode,
            "An unwritten Index answers TPM_RC_NV_UNINITIALIZED, exactly as before its first write.");
    }

    /// <summary>
    /// <c>TPMA_NV_ORDERLY</c> across a TPM Restart: unlike <c>TPMA_NV_CLEAR_STCLEAR</c>, the orderly bit's
    /// clearing is scoped to <c>SU_RESET</c> alone — a Restart follows an orderly <c>Shutdown(STATE)</c>,
    /// so the orderly data WAS saved and survives (TPM 2.0 Library Part 2, clause 13.4, bit 26; the
    /// reference's <c>NvSetStartupAttributes</c> tests <c>type == SU_RESET</c> for this term). The written
    /// data reads back byte-exact after <c>Shutdown(STATE)</c>/<c>Startup(CLEAR)</c>.
    /// </summary>
    [TestMethod]
    public async Task OrderlyIndexKeepsWrittenOnRestart()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-secmem-orderly-restart").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineWriteAndVerifyIndexAsync(tpm, registry, pool, DefaultIndexAttributes | TpmaNv.TPMA_NV_ORDERLY).ConfigureAwait(false);
        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmResult<NvReadResponse> afterResult = await ReadIndexAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(afterResult.IsSuccess, $"A TPM Restart leaves an ORDERLY Index's TPMA_NV_WRITTEN as it was, but the read failed: '{afterResult.ResponseCode}'.");

        using NvReadResponse response = afterResult.Value;
        Assert.IsTrue(
            response.Data.SequenceEqual(NvWriteData),
            "The orderly Index's written data must survive a TPM Restart byte-exact.");
    }

    /// <summary>
    /// A COUNTER Index is exempt from the startup <c>TPMA_NV_WRITTEN</c> pass even when it carries
    /// <c>TPMA_NV_ORDERLY</c>: a counter is restored or advanced across a startup, never cleared (TPM 2.0
    /// Library Part 1, clause 34.2.4.2; the reference's <c>NvSetStartupAttributes</c> guards the whole pass
    /// with <c>IsNvCounterIndex</c>). An incremented orderly counter still reads its value after a TPM
    /// Reset — the exemption arm <c>TPMA_NV_CLEAR_STCLEAR</c> can never exercise, since that bit is refused
    /// on a counter at definition.
    /// </summary>
    [TestMethod]
    public async Task OrderlyCounterKeepsWrittenOnReset()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-secmem-orderly-counter").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<NvDefineSpaceResponse> defineResult = await DefineIndexAsync(
            tpm, registry, pool, NvIndexHandle, ReadOnlyMemory<byte>.Empty, OrderlyCounterAttributes).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace (orderly counter) failed: '{defineResult.ResponseCode}'.");

        var incrementInput = new NvIncrementInput(NvIndexHandle, NvIndexHandle);
        using TpmPasswordSession incrementAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<NvIncrementResponse> incrementResult = await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
            tpm, incrementInput, [incrementAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(incrementResult.IsSuccess, $"NV_Increment failed: '{incrementResult.ResponseCode}'.");

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmResult<NvReadResponse> afterResult = await ReadIndexAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(afterResult.IsSuccess, $"A counter must keep TPMA_NV_WRITTEN across every startup form, but the read failed: '{afterResult.ResponseCode}'.");

        using NvReadResponse response = afterResult.Value;
        Assert.AreEqual(
            1ul, BinaryPrimitives.ReadUInt64BigEndian(response.Data),
            "The counter's single increment must read back across the TPM Reset.");
    }

    /// <summary>
    /// The trace stream's fail-loud contract holds for a bind-entity borrow: the session-start action a
    /// snapshot captures carries the bind entity's authValue as a borrowed carrier reference, so once a later
    /// <c>TPM2_HierarchyChangeAuth()</c> rotates that entity's authValue (disposing the outgoing carrier),
    /// reading the retained snapshot's bind value throws <see cref="ObjectDisposedException"/> — never
    /// silently exposing recycled pool memory.
    /// </summary>
    [TestMethod]
    public async Task RetainedTraceSnapshotFailsLoudOnRotatedBindAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-secmem-bind-loud").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //A real ownerAuth first, so the bind borrow references a disposable carrier rather than the
        //dispose-immune shared empty one.
        await RotateOwnerAuthAsync(tpm, registry, pool, currentAuth: default, newAuth: FirstRotationAuth).ConfigureAwait(false);

        var observer = new TestObserver<TraceEntry<TpmSimulatorState, TpmSimulatorInput>>();
        using IDisposable subscription = simulator.Subscribe(observer);

        _ = await StartBoundToOwnerSessionAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmStartHmacSessionAction? capturedAction = null;
        foreach(TraceEntry<TpmSimulatorState, TpmSimulatorInput> entry in observer.Received)
        {
            if(entry.StateAfter.NextAction is TpmStartHmacSessionAction startAction)
            {
                capturedAction = startAction;
                break;
            }
        }

        Assert.IsNotNull(capturedAction, "A trace entry must have captured the declared session-start action.");

        await RotateOwnerAuthAsync(tpm, registry, pool, currentAuth: FirstRotationAuth, newAuth: SecondRotationAuth).ConfigureAwait(false);

        _ = Assert.ThrowsExactly<ObjectDisposedException>(
            () => _ = capturedAction.BindAuthValue.AsReadOnlyMemory(),
            "Reading a rotated bind entity's authValue from a retained snapshot must throw loudly, never read recycled pool memory.");
    }

    /// <summary>
    /// The trace stream's fail-loud contract holds for the unseal response payload: the
    /// <c>TPM2_Unseal()</c> response intent a snapshot captures carries the recovered data as a borrowed
    /// carrier reference to the loaded sealed object's own storage, so once <c>TPM2_FlushContext()</c>
    /// releases that object, reading the retained snapshot's payload throws
    /// <see cref="ObjectDisposedException"/> — never silently exposing recycled pool memory.
    /// </summary>
    [TestMethod]
    public async Task RetainedUnsealSnapshotFailsLoudOnFlushedSealedObject()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-secmem-unseal-loud").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);

        var observer = new TestObserver<TraceEntry<TpmSimulatorState, TpmSimulatorInput>>();
        using IDisposable subscription = simulator.Subscribe(observer);

        uint itemHandle;
        using(LoadResponse loaded = await SealAndLoadSealedItemAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false))
        {
            itemHandle = loaded.ObjectHandle.Value;

            UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
            using TpmPasswordSession itemAuth = TpmPasswordSession.Create(SealAuth, pool);
            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [itemAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(unsealResult.IsSuccess, $"Unseal failed: '{unsealResult.ResponseCode}'.");
            unsealResult.Value.Dispose();
        }

        TpmUnsealResponse? capturedIntent = null;
        foreach(TraceEntry<TpmSimulatorState, TpmSimulatorInput> entry in observer.Received)
        {
            if(entry.StateAfter.ResponseIntent is TpmUnsealResponse unsealIntent)
            {
                capturedIntent = unsealIntent;
                break;
            }
        }

        Assert.IsNotNull(capturedIntent, "A trace entry must have captured the unseal response intent.");

        TpmResult<FlushContextResponse> flushResult = await FlushAsync(tpm, registry, pool, itemHandle).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext (sealed item) failed: '{flushResult.ResponseCode}'.");

        _ = Assert.ThrowsExactly<ObjectDisposedException>(
            () => _ = capturedIntent.OutData.AsReadOnlyMemory(),
            "Reading a flushed sealed object's data from a retained snapshot must throw loudly, never read recycled pool memory.");
    }

    /// <summary>
    /// A loaded sealed object's Name (<c>nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c>, TPM 2.0 Library Part 1, clause 13, Table 9)
    /// is an owned pooled <c>TPM2B_NAME</c> carrier the object holds for as long as it is loaded, rented by the
    /// <c>TPM2_Load()</c> effect SEPARATELY from the one the response frames — so <c>TPM2_FlushContext()</c>
    /// (Part 3, clause 28.4) must return it along with the object's other carriers. The exact residue is
    /// asserted, not merely its return: a loaded object holds exactly <see cref="LoadedSealedObjectCarrierCount"/>
    /// rentals — Name, sealed data, userAuth, protection seed, the public area's raw storage and its parsed
    /// <c>unique</c>, and Qualified Name — so a Name that
    /// was aliased from the framed response instead of separately rented would show as one fewer, and a Name
    /// left out of the object's disposal would show as one still outstanding after the flush.
    /// </summary>
    [TestMethod]
    public async Task FlushedSealedObjectReturnsTheNameCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool, "tpm-secmem-sealed-name").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateEccDecryptKeyAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        uint itemHandle;
        using(LoadResponse loaded = await SealAndLoadSealedItemAsync(tpm, registry, trackingPool.Pool, parent.ObjectHandle.Value).ConfigureAwait(false))
        {
            itemHandle = loaded.ObjectHandle.Value;
        }

        Assert.AreEqual(
            baseline + LoadedSealedObjectCarrierCount, trackingPool.OutstandingCount,
            "A loaded sealed object must hold exactly its Name, sealed-data, userAuth, protection-seed, public-area (raw storage plus its parsed unique), and Qualified Name rentals once every client-side and response-side carrier has been released.");

        TpmResult<FlushContextResponse> flushResult = await FlushAsync(tpm, registry, trackingPool.Pool, itemHandle).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext (sealed item) failed: '{flushResult.ResponseCode}'.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Flushing the sealed object must return its Name carrier to the pool along with its data and authValue carriers.");
    }

    /// <summary>
    /// The trace stream's fail-loud contract covers the loaded sealed object's Name too: a snapshot that retains
    /// the object's state reads its Name through the aliasing accessor built for a borrowing consumer such as a
    /// cpHash handle-Name area, so once <c>TPM2_FlushContext()</c> (TPM 2.0 Library Part 3, clause 28.4) releases
    /// the object, reading that Name throws <see cref="ObjectDisposedException"/> rather than exposing recycled
    /// pool memory. The borrow is taken while the object is still loaded — the exact aliasing a cpHash term
    /// takes — so the throw proves the carrier, not a copy, is what the borrower held.
    /// </summary>
    [TestMethod]
    public async Task RetainedSealedObjectNameFailsLoudOnFlush()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-secmem-sealed-name-loud").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);

        var observer = new TestObserver<TraceEntry<TpmSimulatorState, TpmSimulatorInput>>();
        using IDisposable subscription = simulator.Subscribe(observer);

        uint itemHandle;
        using(LoadResponse loaded = await SealAndLoadSealedItemAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false))
        {
            itemHandle = loaded.ObjectHandle.Value;
        }

        KeyedHashObjectState? capturedObject = null;
        foreach(TraceEntry<TpmSimulatorState, TpmSimulatorInput> entry in observer.Received)
        {
            if(entry.StateAfter.LoadedKeyedHashObjects.TryGetValue(TpmiDhObject.FromValue(itemHandle), out KeyedHashObjectState? loadedState))
            {
                capturedObject = loadedState;
                break;
            }
        }

        Assert.IsNotNull(capturedObject, "A trace entry must have captured the loaded sealed object's retained state.");

        ReadOnlyMemory<byte> borrowedName = capturedObject.Name.AsReadOnlyMemory();
        Assert.IsFalse(borrowedName.IsEmpty, "The retained Name must be a genuine rental, or the disposal proof below is vacuous.");

        TpmResult<FlushContextResponse> flushResult = await FlushAsync(tpm, registry, pool, itemHandle).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext (sealed item) failed: '{flushResult.ResponseCode}'.");

        _ = Assert.ThrowsExactly<ObjectDisposedException>(
            () => _ = capturedObject.Name.AsReadOnlyMemory(),
            "Reading a flushed sealed object's Name from a retained snapshot must throw loudly, never read recycled pool memory.");
    }

    /// <summary>Starts a bound, unsalted HMAC session bound to the owner hierarchy (empty ownerAuth) and returns its handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The started session's handle.</returns>
    private async Task<uint> StartBoundToOwnerSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession((uint)TpmRh.TPM_RH_OWNER, SessionAlg);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound to owner) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse startResponse = startResult.Value;

        return startResponse.SessionHandle.Value;
    }

    /// <summary>Rotates ownerAuth through the password arm of <c>TPM2_HierarchyChangeAuth()</c>, authorized by the current value.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="currentAuth">The current ownerAuth authorizing the rotation; default for the Empty Buffer.</param>
    /// <param name="newAuth">The replacement ownerAuth; default for the Empty Buffer.</param>
    private async Task RotateOwnerAuthAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, ReadOnlyMemory<byte> currentAuth, ReadOnlyMemory<byte> newAuth)
    {
        //The input adopts the carrier and disposes it; the using here is a belt-and-braces idempotent second
        //release that also keeps the analyzer's ownership view closed.
        using Tpm2bAuth newAuthValue = Tpm2bAuth.Create(newAuth.Span, pool);
        using var input = new HierarchyChangeAuthInput(TpmRh.TPM_RH_OWNER, newAuthValue);
        using TpmPasswordSession authorizingSession = currentAuth.IsEmpty
            ? TpmPasswordSession.CreateEmpty(pool)
            : TpmPasswordSession.Create(currentAuth.Span, pool);

        TpmResult<HierarchyChangeAuthResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyChangeAuthResponse>(
            tpm, input, [authorizingSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"HierarchyChangeAuth failed: '{result.ResponseCode}'.");
    }

    /// <summary>Defines a small NV Index with the given authValue and attributes.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The NV Index handle to define.</param>
    /// <param name="indexAuth">The wire-exact authorization value to assign.</param>
    /// <param name="attributes">The Index attributes; the DA-exempt caller-authorized default unless a test elects more.</param>
    /// <returns>The NV_DefineSpace result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineIndexAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex, ReadOnlyMemory<byte> indexAuth,
        TpmaNv attributes = DefaultIndexAttributes)
    {
        using Tpm2bAuth auth = Tpm2bAuth.Create(indexAuth.Span, pool);
        using var publicInfo = new TpmsNvPublic(
            nvIndex,
            TpmAlgIdConstants.TPM_ALG_SHA256,
            attributes,
            Tpm2bDigest.Empty,
            NvDataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Defines an empty-auth ordinary Index with the given startup-relevant attributes, writes
    /// <see cref="NvWriteData"/>, and verifies the write reads back — the shared front half of the
    /// startup-attribute proofs, so each proves only its own startup form's effect on the written state.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="attributes">The Index attributes under proof.</param>
    private async Task DefineWriteAndVerifyIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmaNv attributes)
    {
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineIndexAsync(
            tpm, registry, pool, NvIndexHandle, ReadOnlyMemory<byte>.Empty, attributes).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace ({attributes}) failed: '{defineResult.ResponseCode}'.");

        using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(NvWriteData, pool);
        var writeInput = new NvWriteInput(NvIndexHandle, NvIndexHandle, writeInputBuffer, Offset: 0);
        using TpmPasswordSession writeAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, writeInput, [writeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"NV_Write failed: '{writeResult.ResponseCode}'.");

        TpmResult<NvReadResponse> beforeResult = await ReadIndexAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(beforeResult.IsSuccess, $"The written Index must read back before the power cycle: '{beforeResult.ResponseCode}'.");
        beforeResult.Value.Dispose();
    }

    /// <summary>Reads the full data area of an empty-auth Index under its own authorization.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The NV Index handle to read.</param>
    /// <returns>The NV_Read result.</returns>
    private async Task<TpmResult<NvReadResponse>> ReadIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex)
    {
        var readInput = new NvReadInput(AuthHandle: nvIndex, NvIndex: nvIndex, Size: NvDataSize, Offset: 0);
        using TpmPasswordSession readAuth = TpmPasswordSession.CreateEmpty(pool);

        return await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            tpm, readInput, [readAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Seals <see cref="SealedSecret"/> under <see cref="SealAuth"/> beneath the given parent through the real
    /// <c>TPM2_Create()</c>/<c>TPM2_Load()</c> wire pair and returns the loaded object's response.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <returns>The loaded object's response (the caller owns it).</returns>
    private async Task<LoadResponse> SealAndLoadSealedItemAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, SealAuth, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (seal) failed: '{createResult.ResponseCode}'.");

        using CreateResponse sealedObject = createResult.Value;
        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
        using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, pool);
        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed item) failed: '{loadResult.ResponseCode}'.");

        return loadResult.Value;
    }

    /// <summary>Reserializes a public area into a fresh <see cref="Tpm2bPublic"/> (a disk-persisted round trip).</summary>
    /// <param name="source">The public area to clone.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The cloned public area.</returns>
    private static Tpm2bPublic ClonePublic(Tpm2bPublic source, BaseMemoryPool pool)
    {
        int size = source.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        source.WriteTo(ref writer);

        var reader = new TpmReader(owner.Memory.Span[..size]);

        return Tpm2bPublic.Parse(ref reader, pool);
    }

    /// <summary>Completes an orderly shutdown, powers the simulator back on, and completes the startup, asserting each wire step.</summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="shutdownType">The orderly shutdown type.</param>
    /// <param name="startupType">The startup type completing the cycle.</param>
    private async Task PowerCycleAsync(TpmSimulator simulator, BaseMemoryPool pool, TpmSuConstants shutdownType, TpmSuConstants startupType)
    {
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, await SubmitSessionlessAsync(simulator, pool, new ShutdownInput(shutdownType)).ConfigureAwait(false));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, await SubmitSessionlessAsync(simulator, pool, new StartupInput(startupType)).ConfigureAwait(false));
    }

    /// <summary>Creates a primary ECC P-256 storage parent (a decrypt key a salted session can target) under the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateEccDecryptKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC storage parent) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a DA-protected ECC storage parent under the owner hierarchy with a real, non-empty password
    /// (<see cref="ParentPassword"/>) — the fixture the parent-authValue carrier-balance proofs need, in
    /// contrast to <see cref="CreateEccDecryptKeyAsync"/>'s empty-password parent.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response for the storage parent (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreatePasswordProtectedStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, ParentPassword, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: false);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (password-protected ECC storage parent) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates an ECC storage parent under the given hierarchy with a real, non-empty password — the
    /// generalized (hierarchy- and password-parameterized) counterpart of
    /// <see cref="CreatePasswordProtectedStorageParentAsync(TpmDevice, TpmResponseRegistry, BaseMemoryPool)"/>
    /// the credential-activation carrier-balance proofs need for a password-protected EK stand-in.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <param name="password">The key's password.</param>
    /// <param name="noDa">Whether the key is dictionary-attack exempt (<c>TPMA_OBJECT.NO_DA</c>).</param>
    /// <returns>The CreatePrimary response for the storage parent (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateEccStorageParentWithPasswordAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy, string password, bool noDa)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(hierarchy, password, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC storage parent, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates an ECC P-256 signing key under the given hierarchy, optionally with a real, non-empty
    /// password — the fixture the newly-verified command password slots' carrier-balance proofs need to
    /// exercise a signing key's own USER-role or ADMIN-role authorization against a genuine retained
    /// authValue.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <param name="password">The key's password, or <see langword="null"/> for the Empty Buffer.</param>
    /// <param name="noDa">Whether the key is dictionary-attack exempt (<c>TPMA_OBJECT.NO_DA</c>).</param>
    /// <returns>The CreatePrimary response for the signing key (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningKeyWithPasswordAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy, string? password, bool noDa)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy, password, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC signing key, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Rotates a hierarchy's authorization value through the password arm of
    /// <c>TPM2_HierarchyChangeAuth()</c> (TPM 2.0 Library Part 3, clause 24.8), authorized by the current
    /// value — the generalized (hierarchy-parameterized) counterpart of
    /// <see cref="RotateOwnerAuthAsync(TpmDevice, TpmResponseRegistry, BaseMemoryPool, ReadOnlyMemory{byte}, ReadOnlyMemory{byte})"/>
    /// the Endorsement-hierarchy carrier-balance proofs need.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy whose authorization value is rotated.</param>
    /// <param name="currentAuth">The current authorization value; default for the Empty Buffer.</param>
    /// <param name="newAuth">The replacement authorization value; default for the Empty Buffer.</param>
    private async Task RotateHierarchyAuthAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy, ReadOnlyMemory<byte> currentAuth, ReadOnlyMemory<byte> newAuth)
    {
        using Tpm2bAuth newAuthValue = Tpm2bAuth.Create(newAuth.Span, pool);
        using var input = new HierarchyChangeAuthInput(hierarchy, newAuthValue);
        using TpmPasswordSession authorizingSession = currentAuth.IsEmpty
            ? TpmPasswordSession.CreateEmpty(pool)
            : TpmPasswordSession.Create(currentAuth.Span, pool);

        TpmResult<HierarchyChangeAuthResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyChangeAuthResponse>(
            tpm, input, [authorizingSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"HierarchyChangeAuth ({hierarchy}) failed: '{result.ResponseCode}'.");
    }

    /// <summary>Issues TPM2_EvictControl for the given object and persistent handles under a supplied owner password, returning the result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="objectHandle">The transient object to persist, or the persistent handle to evict.</param>
    /// <param name="persistentHandle">The persistent handle to assign or evict.</param>
    /// <param name="ownerAuth">The supplied owner-hierarchy password.</param>
    /// <returns>The EvictControl result.</returns>
    private async Task<TpmResult<EvictControlResponse>> EvictControlWithAuthAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint objectHandle, uint persistentHandle, ReadOnlyMemory<byte> ownerAuth)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.Create(ownerAuth.Span, pool);
        var input = new EvictControlInput(TpmRh.TPM_RH_OWNER, objectHandle, persistentHandle);

        return await TpmCommandExecutor.ExecuteAsync<EvictControlResponse>(
            tpm, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Computes a SHA-256 digest through the registered digest seam (not a direct framework hash) — the
    /// fixture the signing-command carrier-balance proofs sign.
    /// </summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The 32-byte digest.</returns>
    private static async Task<byte[]> ComputeSha256Async(ReadOnlyMemory<byte> message, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        Tag tag = Tag.Create(HashAlgorithmName.SHA256)
            .With(Purpose.Digest)
            .With(EncodingScheme.Raw)
            .With(MaterialSemantics.Direct);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlySequence<byte>(message), outputByteLength: Sha256DigestLength, tag: tag, pool: pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Wraps a fixed credential secret to <paramref name="keyHandle"/>'s public area, bound to
    /// <paramref name="objectName"/>, and copies the resulting credential blob and secret to plain byte
    /// arrays so <c>TPM2_MakeCredential()</c>'s own response carrier rentals close before a caller's balance
    /// measurement window opens.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The credential key whose public area protects the seed.</param>
    /// <param name="objectName">The Name of the object the credential is bound to.</param>
    /// <returns>The credential blob and encrypted secret, as independent byte arrays.</returns>
    private async Task<(byte[] CredentialBlob, byte[] Secret)> MakeCredentialBytesAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] objectName)
    {
        using MakeCredentialInput input = MakeCredentialInput.Create(keyHandle, ActivateCredentialFixtureSecret, objectName, pool);

        TpmResult<MakeCredentialResponse> result = await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_MakeCredential failed: '{result.ResponseCode}'.");

        using MakeCredentialResponse made = result.Value;

        return (made.CredentialBlob.Span.ToArray(), made.Secret.Span.ToArray());
    }

    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): rc + TPM_RC_S +
    /// TPM_RC_n(0x100·(sessionIndex+1)) — a local mirror of the production session-index encoding,
    /// transcribed independently here since the production helper is private.
    /// </summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>Issues TPM2_EvictControl for the given object and persistent handles, returning the result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="objectHandle">The transient object to persist, or the persistent handle to evict.</param>
    /// <param name="persistentHandle">The persistent handle to assign or evict.</param>
    /// <returns>The EvictControl result.</returns>
    private async Task<TpmResult<EvictControlResponse>> EvictControlAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint objectHandle, uint persistentHandle)
    {
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        var input = new EvictControlInput(TpmRh.TPM_RH_OWNER, objectHandle, persistentHandle);

        return await TpmCommandExecutor.ExecuteAsync<EvictControlResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Flushes the given handle, returning the result for the caller to assert.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The transient object or session handle to flush.</param>
    /// <returns>The FlushContext result.</returns>
    private async Task<TpmResult<FlushContextResponse>> FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        var input = FlushContextInput.ForHandle(handle);

        return await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Extracts the ECC public point in SEC1 uncompressed form from a CreatePrimary response.</summary>
    /// <param name="primary">The CreatePrimary response carrying the public area.</param>
    /// <returns>The SEC1 uncompressed point.</returns>
    private static ReadOnlyMemory<byte> ExtractEccPoint(CreatePrimaryResponse primary)
    {
        TpmsEccPoint point = primary.OutPublic.PublicArea.Unique.Ecc!;

        return EllipticCurveUtilities.CombineToUncompressedPoint(point.X.AsReadOnlySpan(), point.Y.AsReadOnlySpan());
    }

    /// <summary>Creates a simulator with an ECC signing backend, powers it on, and brings it operational.</summary>
    /// <param name="pool">The memory pool every command runs against.</param>
    /// <param name="tpmId">The simulated TPM's run identifier.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool, string tpmId)
    {
        var simulator = new TpmSimulator(tpmId, signingBackend: BouncyCastleTpmEccSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, await SubmitSessionlessAsync(simulator, pool, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false));
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);

        return simulator;
    }

    /// <summary>Frames and submits a sessionless command directly against the simulator, returning its response code.</summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="input">The sessionless command input.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSessionlessAsync(TpmSimulator simulator, BaseMemoryPool pool, ITpmCommandInput input)
    {
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        if(result.IsSuccess)
        {
            result.Value.Dispose();

            return TpmRcConstants.TPM_RC_SUCCESS;
        }

        return result.ResponseCode;
    }

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_EvictControl, TpmResponseCodec.EvictControl);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Increment, TpmResponseCodec.NvIncrement);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmResponseCodec.NvChangeAuth);
        _ = registry.Register(TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmResponseCodec.HierarchyChangeAuth);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);
        _ = registry.Register(TpmCcConstants.TPM_CC_CertifyCreation, TpmResponseCodec.CertifyCreation);
        _ = registry.Register(TpmCcConstants.TPM_CC_Quote, TpmResponseCodec.Quote);
        _ = registry.Register(TpmCcConstants.TPM_CC_Certify, TpmResponseCodec.Certify);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetTime, TpmResponseCodec.GetTime);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyNV, TpmResponseCodec.PolicyNv);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Certify, TpmResponseCodec.NvCertify);
        _ = registry.Register(TpmCcConstants.TPM_CC_MakeCredential, TpmResponseCodec.MakeCredential);
        _ = registry.Register(TpmCcConstants.TPM_CC_ActivateCredential, TpmResponseCodec.ActivateCredential);

        return registry;
    }
}
