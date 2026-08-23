using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// The wire-shape and pool-accounting proofs for the composite response payloads an object creation returns —
/// the <c>creationData</c>, <c>creationHash</c>, <c>creationTicket</c> and (for <c>TPM2_CreatePrimary()</c>)
/// <c>name</c> trailer of TPM 2.0 Library Part 3, clauses 24.1 and 12.1 — together with the carriers
/// <c>TPM2_Load()</c>, <c>TPM2_PolicyNV()</c>, <c>TPM2_PolicyCounterTimer()</c> and an RSA storage parent hold.
/// Every proof drives the real wire through the production command path and reads real pool telemetry
/// (<see cref="MeteredHousePool"/>), never an internal hook.
/// </summary>
/// <remarks>
/// The framing proofs walk the response octets field by field with a <see cref="TpmReader"/> and check every
/// boundary the specification fixes, so a dropped, reordered, or resized member moves the offsets and fails the
/// walk. The creation hash is checked against the project's own digest seam over the creation-data octets the
/// same response carried, which is the relation clauses 24.1 and 12.1 define rather than a value copied out of
/// the implementation.
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorCompositeCarrierTests
{
    /// <summary>The Name and session hash algorithm every command here uses.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The digest width of <see cref="SessionAlg"/>.</summary>
    private const int DigestSize = 32;

    /// <summary>A SHA-256 Name is its two-octet algorithm identifier followed by the digest.</summary>
    private const int Sha256NameSize = sizeof(ushort) + DigestSize;

    /// <summary>The octets a seal stores in the created object.</summary>
    private static byte[] SealedSecret { get; } = [0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68];

    /// <summary>A parent password no object here was created with, so a load quoting it is refused.</summary>
    private static byte[] WrongParentPassword { get; } = [0x77, 0x72, 0x6F, 0x6E, 0x67];

    /// <summary>An NV Index handle the operand-bound proof names but never has to define.</summary>
    private const uint NvIndexHandle = 0x0100_00A1;

    /// <summary>The persistent handle the modulus proof persists an object to.</summary>
    private const uint PersistentHandle = 0x8100_00A1;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// <c>TPM2_CreatePrimary()</c> frames its creation by-products as the four separate structures Part 3,
    /// clause 24.1's response table names — <c>creationData</c> (a <c>TPM2B_CREATION_DATA</c>, Part 2, clause
    /// 15.2, Table 247), <c>creationHash</c> (a <c>TPM2B_DIGEST</c>, clause 10.4.2, Table 92),
    /// <c>creationTicket</c> (a <c>TPMT_TK_CREATION</c>, clause 10.7.3, Table 109) and <c>name</c> (a
    /// <c>TPM2B_NAME</c>) — one after another with no padding and nothing left over. Each field boundary is
    /// walked explicitly, and the creation hash is recomputed from the creation-data octets the same response
    /// carried, so a dropped, reordered, or resized member fails the walk rather than merely changing a length.
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryFramesItsCreationByProductsAsFourSpecStructures()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-composite-primaryframing").ConfigureAwait(false);

        byte[] response;
        using(CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true))
        {
            response = await SubmitPasswordAuthorizedAsync(simulator, pool, input).ConfigureAwait(false);
        }

        (byte[] creationData, byte[] creationHash, byte[] name) =
            WalkCreationResponse(response, "TPM2_CreatePrimary()", hasObjectHandle: true, hasPrivateBlob: false, expectName: true, TpmiRhHierarchy.Owner);

        byte[] expectedCreationHash = await ComputeSha256Async(creationData, pool).ConfigureAwait(false);
        Assert.AreSequenceEqual(
            expectedCreationHash, creationHash,
            "Part 3, clause 24.1 defines creationHash as the Name-algorithm digest of the creationData the same response carries.");

        Assert.HasCount(Sha256NameSize, name, "TPM2_CreatePrimary() returns the object Name as nameAlg followed by its digest (Part 1, clause 14, Table 6).");
        Assert.AreEqual(
            (ushort)SessionAlg, BinaryPrimitives.ReadUInt16BigEndian(name),
            "The Name's leading algorithm identifier is the object's own nameAlg.");
    }

    /// <summary>
    /// <c>TPM2_Create()</c> frames the same three by-product structures Part 3, clause 12.1's response table
    /// names and NO trailing Name — clause 12.1 returns <c>outPrivate</c>, <c>outPublic</c>,
    /// <c>creationData</c>, <c>creationHash</c> and <c>creationTicket</c>, and no <c>name</c>, because the
    /// created object is not loaded. The walk pins that absence: a Name appended here would leave octets over.
    /// </summary>
    [TestMethod]
    public async Task CreateFramesItsCreationByProductsAsThreeSpecStructuresWithNoName()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-composite-createframing").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint parentHandle = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        byte[] response;
        using(Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, ReadOnlySpan<byte>.Empty, pool))
        using(Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true))
        using(CreateInput input = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty))
        {
            response = await SubmitPasswordAuthorizedAsync(simulator, pool, input).ConfigureAwait(false);
        }

        (byte[] creationData, byte[] creationHash, byte[] name) =
            WalkCreationResponse(response, "TPM2_Create()", hasObjectHandle: false, hasPrivateBlob: true, expectName: false, TpmiRhHierarchy.Owner);

        byte[] expectedCreationHash = await ComputeSha256Async(creationData, pool).ConfigureAwait(false);
        Assert.AreSequenceEqual(
            expectedCreationHash, creationHash,
            "Part 3, clause 12.1 defines creationHash as the Name-algorithm digest of the creationData the same response carries.");
        Assert.IsEmpty(name, "TPM2_Create() returns no Name, so the creation ticket is the last response parameter.");
    }

    /// <summary>
    /// <c>TPM2_Create()</c>'s creation ticket names the HIERARCHY the created object belongs to, never the
    /// parent object's transient handle. Part 2, clause 10.7.3, Table 109 types the ticket's <c>hierarchy</c>
    /// field <c>TPMI_RH_HIERARCHY+</c> and describes it as "the hierarchy containing name", so its only legal
    /// values are the four selectors of clause 9.13, Table 60; a transient object handle is not among them. The
    /// proof creates the parent under the PLATFORM hierarchy, so the ticket's field can be neither the parent's
    /// handle nor the storage hierarchy the sibling proofs use.
    /// </summary>
    [TestMethod]
    public async Task CreateTicketNamesTheParentsHierarchyRatherThanItsHandle()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-composite-tickethierarchy").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint parentHandle = await CreateStorageParentAsync(tpm, registry, pool, TpmRh.TPM_RH_PLATFORM).ConfigureAwait(false);
        Assert.AreEqual(TpmHt.TPM_HT_TRANSIENT, (TpmHt)(parentHandle >> 24), "Test setup: the parent must be a transient object.");

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, ReadOnlySpan<byte>.Empty, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
        using CreateInput input = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, input, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"Create (seal) failed: '{result.ResponseCode}'.");

        using CreateResponse created = result.Value;
        Assert.AreEqual(
            TpmiRhHierarchy.Platform, created.CreationTicket.Hierarchy,
            "The ticket must name the hierarchy containing the created object, which is the parent's hierarchy.");
        Assert.AreEqual(
            TpmStConstants.TPM_ST_CREATION, created.CreationTicket.Tag,
            "The ticket tag is TPM_ST_CREATION whatever the hierarchy.");
        Assert.IsFalse(created.CreationTicket.IsNull, "A real creation produces a real ticket, not the NULL Creation Ticket.");
    }

    /// <summary>
    /// A completed <c>TPM2_CreatePrimary()</c> returns every by-product carrier to the pool once its response is
    /// framed and released: the creation data, the creation hash, the creation ticket and the Name are framed
    /// from carriers the response intent owns, so disposing the response must leave the pool exactly where the
    /// command found it apart from the durable state the created object keeps.
    /// </summary>
    [TestMethod]
    public async Task CompletedCreatePrimaryReturnsTheByProductCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-composite-primarybalance").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //The first creation warms every lazily-rented durable slot, so the measured window covers the
        //by-products alone rather than the first object's own state.
        uint firstHandle = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.AreNotEqual(0u, firstHandle, "Test setup: the warming primary must be created.");

        long baseline = trackingPool.OutstandingCount;

        uint secondHandle = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        long afterCreate = trackingPool.OutstandingCount;
        Assert.IsGreaterThan(
            baseline, afterCreate,
            "A created object retains durable carriers of its own, so the pool must hold more after the creation than before it.");

        _ = await tpm.FlushContextAsync(secondHandle, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Flushing the created object releases its durable carriers, and the by-products were already released when the response was framed.");
    }

    /// <summary>
    /// A completed <c>TPM2_Create()</c> returns every by-product carrier to the pool: unlike
    /// <c>TPM2_CreatePrimary()</c> the command installs no durable object (Part 3, clause 12.1 — the created
    /// object exists only as the returned blob), so the pool must return to its exact starting point once the
    /// response is disposed.
    /// </summary>
    [TestMethod]
    public async Task CompletedCreateReturnsEveryByProductCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-composite-createbalance").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint parentHandle = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        using(Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, ReadOnlySpan<byte>.Empty, pool))
        using(Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true))
        using(CreateInput input = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty))
        using(TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool))
        {
            TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, input, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"Create (seal) failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "TPM2_Create() installs no durable object, so every by-product carrier it framed must be back in the pool.");
    }

    /// <summary>
    /// A <c>TPM2_PolicyCounterTimer()</c> whose <c>operandB</c> declares more octets than a
    /// <c>TPM2B_OPERAND</c> can hold is refused at the wire read with <c>TPM_RC_SIZE</c>. Part 2, clause 10.4.6,
    /// Table 96 defines <c>TPM2B_OPERAND</c> with the digest structure's own bound —
    /// <c>buffer[size]{:sizeof(TPMU_HA)}</c>, 64 octets — so a wider parameter never reaches the command body at
    /// all, and its refusal is the marshalling one rather than the offset/size range rule clause 23.10 states
    /// for a well-formed operand. All three rungs are proved on one session so the ORDER is pinned as well: an
    /// operand spanning the whole <c>TPMS_TIME_INFO</c> is admitted, one octet more is <c>TPM_RC_RANGE</c> from
    /// the command body, and one past the buffer bound is <c>TPM_RC_SIZE</c> from the wire read. The last rung
    /// is submitted as a hand-built frame: <see cref="PolicyCounterTimerInput"/> refuses the same bound at
    /// construction, so the wire form is the only way to reach the parser's own refusal.
    /// </summary>
    [TestMethod]
    public async Task PolicyCounterTimerRefusesAnOperandWiderThanTheOperandBound()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-composite-operandbound").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            long baseline = trackingPool.OutstandingCount;

            //A whole TPMS_TIME_INFO's worth of operand at offset zero: inside the buffer bound and inside the
            //structure, so the trial session folds it.
            byte[] atStructureWidth = new byte[TpmsTimeInfo.SerializedSize];
            TpmResult<PolicyCounterTimerResponse> admitted = await tpm.PolicyCounterTimerAsync(
                sessionHandle, atStructureWidth, offset: 0, TpmEoConstants.TPM_EO_EQ, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(admitted.IsSuccess, $"An operand spanning the whole TPMS_TIME_INFO must be admitted: '{admitted.ResponseCode}'.");

            //One octet past the structure but still inside the buffer bound: the command body's own range rule.
            byte[] pastStructure = new byte[TpmsTimeInfo.SerializedSize + 1];
            TpmResult<PolicyCounterTimerResponse> ranged = await tpm.PolicyCounterTimerAsync(
                sessionHandle, pastStructure, offset: 0, TpmEoConstants.TPM_EO_EQ, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(ranged.IsTpmError, "An operand past the compared structure must be refused.");
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_RANGE, ranged.ResponseCode,
                "A well-formed operand whose window leaves the structure is the command body's TPM_RC_RANGE (Part 3, clause 23.10).");

            //One octet past the buffer bound: refused at the wire read, ahead of the range rule. The frame is
            //built by hand, because the typed input refuses the same bound at construction and no production
            //caller can express it.
            var oversizeBody = new List<byte>();
            AppendUInt32(oversizeBody, sessionHandle);
            AppendUInt16(oversizeBody, Tpm2bOperand.MaxSize + 1);
            oversizeBody.AddRange(new byte[Tpm2bOperand.MaxSize + 1]);
            AppendUInt16(oversizeBody, 0);
            AppendUInt16(oversizeBody, (ushort)TpmEoConstants.TPM_EO_EQ);

            TpmRcConstants oversize = await SubmitFramedAsync(
                simulator, pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PolicyCounterTimer, [.. oversizeBody]).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_SIZE, oversize,
                "A parameter wider than Table 96's bound is a marshalling refusal, answered before the command body runs.");

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The bound is answered ahead of the rental, so a refused parse rents nothing, and an admitted assertion replaces the session digest rather than accumulating carriers.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_PolicyNV()</c>'s <c>operandB</c> carries the same <c>TPM2B_OPERAND</c> bound (Part 2, clause
    /// 10.4.6, Table 96), enforced at the same wire read: the refusal precedes every gate the command body runs,
    /// so it needs no defined Index and no authorization to observe, and it rents nothing. The frame is built by
    /// hand, because <see cref="PolicyNvInput"/> refuses the same bound at construction.
    /// </summary>
    [TestMethod]
    public async Task PolicyNvRefusesAnOperandWiderThanTheOperandBound()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-composite-nvoperandbound").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            long baseline = trackingPool.OutstandingCount;

            //The frame is built by hand, because the typed input refuses the same bound at construction and no
            //production caller can express it.
            var oversizeBody = new List<byte>();
            AppendUInt32(oversizeBody, (uint)TpmRh.TPM_RH_OWNER);
            AppendUInt32(oversizeBody, NvIndexHandle);
            AppendUInt32(oversizeBody, sessionHandle);
            AppendPasswordAuthorizationArea(oversizeBody);
            AppendUInt16(oversizeBody, Tpm2bOperand.MaxSize + 1);
            oversizeBody.AddRange(new byte[Tpm2bOperand.MaxSize + 1]);
            AppendUInt16(oversizeBody, 0);
            AppendUInt16(oversizeBody, (ushort)TpmEoConstants.TPM_EO_EQ);

            TpmRcConstants oversize = await SubmitFramedAsync(
                simulator, pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_PolicyNV, [.. oversizeBody]).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_SIZE, oversize,
                "A parameter wider than Table 96's bound is a marshalling refusal, answered before the Index is even resolved.");
            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The bound is answered ahead of the rentals, so a refused parse rents neither the operand nor the supplied password.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An RSA storage parent's retained public modulus is an owned pooled <c>TPM2B_PUBLIC_KEY_RSA</c> carrier
    /// (Part 2, clause 11.2.4.5, Table 193) on the same lifecycle as the object's other durable carriers:
    /// persisting the object deep-copies it, so the transient and persistent entries hold separate rentals, and
    /// evicting each entry releases its own.
    /// </summary>
    [TestMethod]
    public async Task RsaStorageParentModulusIsDeepCopiedOnPersistAndReleasedOnEviction()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateRsaOperationalAsync(pool, "tpm-composite-modulus").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        uint transientHandle;
        using(CreatePrimaryInput input = CreatePrimaryInput.ForRsaEndorsementKey(TpmRh.TPM_RH_OWNER, pool))
        using(TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool))
        {
            TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
                tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA endorsement key) failed: '{result.ResponseCode}'.");

            using CreatePrimaryResponse created = result.Value;
            transientHandle = created.ObjectHandle.Value;
        }

        long afterCreate = trackingPool.OutstandingCount;
        Assert.IsGreaterThan(baseline, afterCreate, "The created RSA parent retains durable carriers, the public modulus among them.");

        await EvictControlAsync(tpm, registry, pool, transientHandle, PersistentHandle).ConfigureAwait(false);
        long afterPersist = trackingPool.OutstandingCount;
        Assert.IsGreaterThan(
            afterCreate, afterPersist,
            "Persisting deep-copies every durable carrier, so the persistent entry holds rentals of its own rather than sharing the transient entry's.");

        //Evicting the persistent copy releases ITS carriers alone; the transient object still holds its own.
        await EvictControlAsync(tpm, registry, pool, PersistentHandle, PersistentHandle).ConfigureAwait(false);
        Assert.AreEqual(afterCreate, trackingPool.OutstandingCount, "Evicting the persistent copy releases exactly the carriers it deep-copied.");

        _ = await tpm.FlushContextAsync(transientHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Flushing the transient object releases the rest.");
    }

    /// <summary>
    /// <c>TPM2_Load()</c>'s <c>inPublic</c> rides an owned <c>TPM2B_PUBLIC</c> carrier from the parse to the
    /// effect that hashes its marshaled <c>TPMT_PUBLIC</c> into the object Name (Part 3, clause 12.2; Part 1,
    /// clause 14, Table 6), so the public area never leaves pooled memory. Both outcomes are proved on one pool: a
    /// refused load returns every parse rental, and a successful one leaves only the loaded object's own durable
    /// carriers behind, which the flush then releases.
    /// </summary>
    [TestMethod]
    public async Task LoadReturnsThePublicAreaCarrierOnBothTheRefusedAndTheSuccessfulPath()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-composite-loadcarrier").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint parentHandle = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        byte[] privateBlob;
        byte[] publicArea;
        using(Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, ReadOnlySpan<byte>.Empty, pool))
        using(Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true))
        using(CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty))
        using(TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool))
        {
            TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"Create (seal) failed: '{result.ResponseCode}'.");

            using CreateResponse created = result.Value;
            privateBlob = created.OutPrivate.Span.ToArray();
            publicArea = created.OutPublic.GetRawBytes().ToArray();
        }

        long baseline = trackingPool.OutstandingCount;

        //A wrong parent password is refused inside the command body, after the parse has already rented the
        //public area, the policy digest and the password.
        {
            using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(privateBlob, pool);
            using Tpm2bPublic inPublic = ParsePublicArea(publicArea, pool);
            using var refusedInput = new LoadInput(parentHandle, inPrivate, inPublic);
            using TpmPasswordSession wrongAuth = TpmPasswordSession.Create(WrongParentPassword, pool);

            TpmResult<LoadResponse> refused = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
                tpm, refusedInput, [wrongAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(refused.IsTpmError, "A wrong parent password must be refused.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return the parse-rented public area, policy digest and password carriers.");

        uint loadedHandle;
        {
            using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(privateBlob, pool);
            using Tpm2bPublic inPublic = ParsePublicArea(publicArea, pool);
            using var loadInput = new LoadInput(parentHandle, inPrivate, inPublic);
            using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<LoadResponse> loaded = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
                tpm, loadInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(loaded.IsSuccess, $"Load failed: '{loaded.ResponseCode}'.");

            using LoadResponse response = loaded.Value;
            loadedHandle = response.ObjectHandle.Value;
        }

        Assert.IsGreaterThan(
            baseline, trackingPool.OutstandingCount,
            "A loaded object retains durable carriers of its own, so the pool holds more than before the load.");

        _ = await tpm.FlushContextAsync(loadedHandle, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Flushing the loaded object releases its durable carriers, and the public area was released by the effect that hashed it.");
    }

    /// <summary>
    /// Walks a creation response frame field by field and returns the by-product octets the caller's own oracle
    /// checks. Every boundary the response tables fix is asserted here — the handle area, the sized structures
    /// that precede the by-products, the three by-product structures themselves, the presence or absence of the
    /// trailing Name, and that nothing is left over — so a member dropped, reordered, or written at the wrong
    /// width shifts the offsets and fails the walk.
    /// </summary>
    /// <param name="response">The complete response frame.</param>
    /// <param name="commandName">The command's own name, quoted in the failure messages.</param>
    /// <param name="hasObjectHandle">Whether the response opens with a handle area (<c>TPM2_CreatePrimary()</c> does; <c>TPM2_Create()</c> does not).</param>
    /// <param name="hasPrivateBlob">Whether an <c>outPrivate</c> precedes <c>outPublic</c> (<c>TPM2_Create()</c> only).</param>
    /// <param name="expectName">Whether a <c>TPM2B_NAME</c> trails the creation ticket (<c>TPM2_CreatePrimary()</c> only).</param>
    /// <param name="expectedHierarchy">The hierarchy the creation ticket must name.</param>
    /// <returns>The creation data, the creation hash, and the trailing Name (empty when none is expected).</returns>
    private static (byte[] CreationData, byte[] CreationHash, byte[] Name) WalkCreationResponse(
        byte[] response, string commandName, bool hasObjectHandle, bool hasPrivateBlob, bool expectName, TpmiRhHierarchy expectedHierarchy)
    {
        var reader = new TpmReader(response);
        TpmHeader header = TpmHeader.Parse(ref reader);
        Assert.AreEqual(0u, header.Code, $"{commandName} must succeed.");

        if(hasObjectHandle)
        {
            uint objectHandle = reader.ReadUInt32();
            Assert.AreEqual(TpmHt.TPM_HT_TRANSIENT, (TpmHt)(objectHandle >> 24), "A created object is addressed by a transient handle.");
        }

        if(hasPrivateBlob)
        {
            //outPrivate (TPM2B_PRIVATE): sized, and not a by-product.
            _ = ReadSizedField(ref reader, "outPrivate");
        }

        //outPublic (TPM2B_PUBLIC), whose own size field carries the whole TPMT_PUBLIC the by-products follow.
        ushort publicSize = reader.ReadUInt16();
        Assert.IsLessThanOrEqualTo(reader.Remaining, publicSize, "The declared size of 'outPublic' must fit the octets that follow it.");
        _ = reader.ReadBytes(publicSize);

        byte[] creationData = ReadSizedField(ref reader, "creationData");
        byte[] creationHash = ReadSizedField(ref reader, "creationHash");
        Assert.HasCount(DigestSize, creationHash, "creationHash is a TPM2B_DIGEST at the object's own Name-algorithm width.");

        AssertCreationTicket(ref reader, expectedHierarchy);

        byte[] name = expectName
            ? ReadSizedField(ref reader, "name")
            : [];

        Assert.AreEqual(0, reader.Remaining, $"The by-products are {commandName}'s last response parameter, so nothing may follow them.");

        return (creationData, creationHash, name);
    }

    /// <summary>Walks a <c>TPMT_TK_CREATION</c> at the reader's position and checks every field Table 109 fixes.</summary>
    /// <param name="reader">The reader positioned at the ticket's tag.</param>
    /// <param name="expectedHierarchy">The hierarchy the ticket must name.</param>
    private static void AssertCreationTicket(ref TpmReader reader, TpmiRhHierarchy expectedHierarchy)
    {
        ushort ticketTag = reader.ReadUInt16();
        Assert.AreEqual(
            (ushort)TpmStConstants.TPM_ST_CREATION, ticketTag,
            "A creation ticket's structure tag is TPM_ST_CREATION (Part 2, clause 10.7.3, Table 109).");

        uint ticketHierarchy = reader.ReadUInt32();
        Assert.AreEqual(
            expectedHierarchy.Value, ticketHierarchy,
            "The ticket's hierarchy field is a TPMI_RH_HIERARCHY selector naming the hierarchy containing the object.");
        Assert.IsTrue(
            TpmiRhHierarchy.IsHierarchy(ticketHierarchy),
            "Table 109 types the field TPMI_RH_HIERARCHY+, whose admitted set is Table 60's four selectors.");

        ushort ticketDigestSize = reader.ReadUInt16();
        Assert.AreEqual(DigestSize, ticketDigestSize, "A real ticket carries a full-width HMAC, so its TPM2B_DIGEST is the context digest width.");
        _ = reader.ReadBytes(ticketDigestSize);
    }

    /// <summary>Reads one <c>UINT16</c>-sized wire field and returns its octets.</summary>
    /// <param name="reader">The reader positioned at the field's size prefix.</param>
    /// <param name="fieldName">The field's own name, quoted in the failure message.</param>
    /// <returns>The field's octets.</returns>
    private static byte[] ReadSizedField(ref TpmReader reader, string fieldName)
    {
        ushort size = reader.ReadUInt16();
        Assert.IsLessThanOrEqualTo(reader.Remaining, size, $"The declared size of '{fieldName}' must fit the octets that follow it.");

        return reader.ReadBytes(size).ToArray();
    }

    /// <summary>
    /// Hashes a message through the project's own registered SHA-256 seam, so no proof here reaches past the
    /// library for its oracle.
    /// </summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The digest octets.</returns>
    private async Task<byte[]> ComputeSha256Async(byte[] message, BaseMemoryPool pool)
    {
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            message, DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Frames a command with one empty-password authorization slot, submits it straight to the simulator, and
    /// returns the whole response frame — the only way a proof can walk the response octets exactly as they go
    /// on the wire, rather than through a codec that has already interpreted them.
    /// </summary>
    /// <param name="simulator">The simulator to submit to.</param>
    /// <param name="pool">The memory pool the command and response are framed from.</param>
    /// <param name="input">The command whose handle and parameter areas are framed.</param>
    /// <returns>The complete response frame.</returns>
    private async Task<byte[]> SubmitPasswordAuthorizedAsync(TpmSimulator simulator, BaseMemoryPool pool, ITpmCommandInput input)
    {
        var authorizationArea = new List<byte>();
        AppendUInt32(authorizationArea, (uint)TpmRh.TPM_RH_PW);
        AppendUInt16(authorizationArea, 0);
        authorizationArea.Add((byte)TpmaSession.CONTINUE_SESSION);
        AppendUInt16(authorizationArea, 0);

        int length = TpmHeader.HeaderSize + input.GetSerializedSize() + sizeof(uint) + authorizationArea.Count;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        writer.WriteUInt32((uint)authorizationArea.Count);
        writer.WriteBytes([.. authorizationArea]);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer with a framed response.");

        using TpmResponse response = result.Value;

        return response.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Appends a one-slot authorization area naming <c>TPM_RS_PW</c> with an empty nonce and an empty password —
    /// the password form of <c>TPMS_AUTH_COMMAND</c> (TPM 2.0 Library Part 1, clause 17.6.4.1) — which is enough
    /// for a parse-time proof, since the parse never evaluates the credential.
    /// </summary>
    /// <param name="body">The body being built.</param>
    private static void AppendPasswordAuthorizationArea(List<byte> body)
    {
        var area = new List<byte>();
        AppendUInt32(area, (uint)TpmRh.TPM_RH_PW);
        AppendUInt16(area, 0);
        area.Add((byte)TpmaSession.CONTINUE_SESSION);
        AppendUInt16(area, 0);

        AppendUInt32(body, (uint)area.Count);
        body.AddRange(area);
    }

    /// <summary>Submits a hand-framed command body and returns the response code alone.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool the command and response are framed from.</param>
    /// <param name="tag">The command tag.</param>
    /// <param name="commandCode">The command code.</param>
    /// <param name="body">Everything after the header.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitFramedAsync(
        TpmSimulator simulator, BaseMemoryPool pool, TpmStConstants tag, TpmCcConstants commandCode, byte[] body)
    {
        int length = TpmHeader.HeaderSize + body.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)tag, (uint)length, (uint)commandCode);
        header.WriteTo(ref writer);
        writer.WriteBytes(body);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer a malformed command rather than fault.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>Appends a big-endian <c>UINT32</c> to a command area under construction.</summary>
    /// <param name="area">The area being built.</param>
    /// <param name="value">The value to append.</param>
    private static void AppendUInt32(List<byte> area, uint value)
    {
        Span<byte> octets = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(octets, value);
        area.AddRange(octets);
    }

    /// <summary>Appends a big-endian <c>UINT16</c> to a command area under construction.</summary>
    /// <param name="area">The area being built.</param>
    /// <param name="value">The value to append.</param>
    private static void AppendUInt16(List<byte> area, int value)
    {
        Span<byte> octets = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(octets, (ushort)value);
        area.AddRange(octets);
    }

    /// <summary>Creates an empty-auth ECC P-256 restricted storage parent and returns its transient handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy to create the parent under.</param>
    /// <returns>The parent's transient handle.</returns>
    private async Task<uint> CreateStorageParentAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy = TpmRh.TPM_RH_OWNER)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            hierarchy, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (storage parent) failed: '{result.ResponseCode}'.");

        using CreatePrimaryResponse created = result.Value;

        return created.ObjectHandle.Value;
    }

    /// <summary>Creates the response codec registry these proofs drive commands through.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_EvictControl, TpmResponseCodec.EvictControl);

        return registry;
    }

    /// <summary>Runs <c>TPM2_EvictControl()</c> under empty owner authorization and asserts it succeeded.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="objectHandle">The transient or persistent object the command acts on.</param>
    /// <param name="persistentHandle">The persistent handle to install at or evict.</param>
    private async Task EvictControlAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint objectHandle, uint persistentHandle)
    {
        var input = new EvictControlInput(TpmRh.TPM_RH_OWNER, objectHandle, persistentHandle);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<EvictControlResponse> result = await TpmCommandExecutor.ExecuteAsync<EvictControlResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"EvictControl failed: '{result.ResponseCode}'.");
    }

    /// <summary>Creates a simulator with an RSA signing backend, powers it on, and brings it operational.</summary>
    /// <param name="pool">The memory pool every command runs against.</param>
    /// <param name="tpmId">The simulated TPM's run identifier, unique per test so no meter is shared.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateRsaOperationalAsync(BaseMemoryPool pool, string tpmId)
    {
        var simulator = new TpmSimulator(tpmId, rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Creates a simulator with an ECC signing backend, powers it on, and brings it operational.</summary>
    /// <param name="pool">The memory pool every command runs against.</param>
    /// <param name="tpmId">The simulated TPM's run identifier, unique per test so no meter is shared.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool, string tpmId)
    {
        var simulator = new TpmSimulator(tpmId, signingBackend: BouncyCastleTpmEccSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Frames a <c>TPM2B_PUBLIC</c> around already-marshaled public-area octets and parses it back.</summary>
    /// <param name="publicArea">The marshaled <c>TPMT_PUBLIC</c> octets.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The parsed public area; the caller owns and disposes it.</returns>
    private static Tpm2bPublic ParsePublicArea(byte[] publicArea, BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> framing = pool.Rent(sizeof(ushort) + publicArea.Length);
        var writer = new TpmWriter(framing.Memory.Span[..(sizeof(ushort) + publicArea.Length)]);
        writer.WriteUInt16((ushort)publicArea.Length);
        writer.WriteBytes(publicArea);

        var reader = new TpmReader(framing.Memory.Span[..(sizeof(ushort) + publicArea.Length)]);

        return Tpm2bPublic.Parse(ref reader, pool);
    }

    /// <summary>Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator to move it into the operational phase.</summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
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
        var reader = new TpmReader(response.AsReadOnlySpan());
        Assert.AreEqual(0u, TpmHeader.Parse(ref reader).Code, "TPM2_Startup(CLEAR) must answer TPM_RC_SUCCESS.");
    }
}
