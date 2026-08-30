using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// The pool-accounting, borrow-lifetime, and buffer-bound proofs for a defined NV Index's data area — the
/// pooled <see cref="TpmNvIndexData"/> carrier reserved at the Index's declared <c>dataSize</c>
/// (<c>TPMS_NV_PUBLIC.dataSize</c>, TPM 2.0 Library Part 2, clause 13.6, Table 251) and merged into by every
/// store (Part 3, clause 31.7.1) — together with the <c>MAX_NV_BUFFER_SIZE</c> bound the NV data parameters
/// carry (Part 2, clause 10.3.9, Table 97) and the capability property that reports it (Part 2, clause 6.13,
/// Table 28). Every proof drives the real wire through the production command path and reads real pool
/// telemetry (<see cref="MeteredHousePool"/>), never an internal hook.
/// </summary>
/// <remarks>
/// Three properties are separable and each is proved on its own here: the area is reserved once, at definition,
/// so a written Index holds exactly one data rental however many times it is written; every eviction path
/// releases it; and a read frames a BORROW of that carrier, so the Index still owns a readable area after a
/// read has been framed — the property that would break the moment the read intent joined the serializer's
/// blanket release.
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorNvDataCarrierTests
{
    /// <summary>The session and Name hash algorithm every command here uses.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The ordinary owner-authorized Index the balance and borrow proofs use.</summary>
    private const uint OwnerIndexHandle = 0x0100_0091;

    /// <summary>A second ordinary owner-authorized Index, so the clear proof has more than one to release.</summary>
    private const uint SecondOwnerIndexHandle = 0x0100_0092;

    /// <summary>The counter Index the increment proof advances.</summary>
    private const uint CounterIndexHandle = 0x0100_0093;

    /// <summary>The Index whose declared data area is one octet wider than a <c>TPM2B_MAX_NV_BUFFER</c> can carry.</summary>
    private const uint OversizeIndexHandle = 0x0100_0094;

    /// <summary>The declared data area width of the ordinary Indexes these proofs define.</summary>
    private const ushort IndexDataSize = 8;

    /// <summary>A Counter, PIN Fail, or PIN Pass Index's data area is always eight octets (Part 2, clause 13.2).</summary>
    private const ushort CounterDataSize = 8;

    /// <summary>The declared data area width of <see cref="OversizeIndexHandle"/>: one octet past the buffer bound.</summary>
    private const ushort OversizeIndexDataSize = Tpm2bMaxNvBuffer.MaxSize + 1;

    /// <summary>An owner-authorized, dictionary-attack-exempt ordinary Index.</summary>
    private const TpmaNv OwnerAuthorizedAttributes = TpmaNv.TPMA_NV_OWNERREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>A caller-authorized, dictionary-attack-exempt ordinary Index: its own authValue reads and writes it, which is the arm <c>TPM2_NV_Certify()</c> models.</summary>
    private const TpmaNv SelfAuthorizedAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>An owner-authorized, dictionary-attack-exempt Counter Index (<c>TPM_NT_COUNTER</c>, Part 2, clause 13.2).</summary>
    private static TpmaNv CounterAttributes { get; } =
        TpmaNv.TPMA_NV_OWNERREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_NO_DA
        | (TpmaNv)((uint)TpmNt.TPM_NT_COUNTER << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>The octets the balance proofs first store in an Index's data area.</summary>
    private static byte[] FirstWrite { get; } = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];

    /// <summary>The octets the balance proofs store over <see cref="FirstWrite"/>, so a second write is observable.</summary>
    private static byte[] SecondWrite { get; } = [0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28];

    /// <summary>The caller nonce the certify proofs echo into the attestation.</summary>
    private static byte[] QualifyingData { get; } = [0x31, 0x32, 0x33, 0x34];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A defined NV Index holds exactly ONE data-area rental for its whole life: the area is reserved at
    /// <c>TPM2_NV_DefineSpace()</c> at the declared <c>dataSize</c> and every later store merges into it
    /// (TPM 2.0 Library Part 3, clause 31.7.1), so a define takes one rental, a write takes none, a read takes
    /// none, and <c>TPM2_NV_UndefineSpace()</c> (clause 31.4) returns it. The Index authValue is deliberately
    /// EMPTY here so the shared dispose-immune sentinel accounts for it and the delta this proof reads is the
    /// data area alone.
    /// </summary>
    [TestMethod]
    public async Task DefinedIndexHoldsExactlyOneDataAreaRentalUntilItIsUndefined()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nvdata-lifecycle").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        await DefineIndexAsync(tpm, registry, pool, OwnerIndexHandle, OwnerAuthorizedAttributes, IndexDataSize).ConfigureAwait(false);
        Assert.AreEqual(
            baseline + 1, trackingPool.OutstandingCount,
            "A definition reserves the Index's data area at its declared dataSize and transfers that one rental into durable state.");

        await WriteAsync(tpm, registry, pool, OwnerIndexHandle, FirstWrite, offset: 0).ConfigureAwait(false);
        Assert.AreEqual(
            baseline + 1, trackingPool.OutstandingCount,
            "A write merges into the reserved area, so it must leave the Index holding the same single rental.");

        byte[] readBack = await ReadAsync(tpm, registry, pool, OwnerIndexHandle, (ushort)FirstWrite.Length, offset: 0).ConfigureAwait(false);
        Assert.AreSequenceEqual(FirstWrite, readBack, "The read must answer the octets the write stored.");
        Assert.AreEqual(
            baseline + 1, trackingPool.OutstandingCount,
            "A read frames a borrow of the Index's area, so it must neither rent nor release one.");

        await UndefineAsync(tpm, registry, pool, OwnerIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Undefining the Index is its data area's ownership-end boundary and must return the rental (Part 3, clause 31.4).");
    }

    /// <summary>
    /// Writing the same Index twice leaves the pool flat: the second store merges into the very area the first
    /// stored into (TPM 2.0 Library Part 3, clause 31.7.1's "merge the data.size octets of data.buffer value
    /// into the nvIndex→data starting at nvIndex→data[offset]"), so no second area is ever reserved and no
    /// first area is ever superseded. The parsed <c>TPM2B_MAX_NV_BUFFER</c> each command carries is returned by
    /// the storing transition, which is its terminal owner.
    /// </summary>
    [TestMethod]
    public async Task WritingAnIndexTwiceLeavesThePoolFlat()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nvdata-writetwice").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineIndexAsync(tpm, registry, pool, OwnerIndexHandle, OwnerAuthorizedAttributes, IndexDataSize).ConfigureAwait(false);
        await WriteAsync(tpm, registry, pool, OwnerIndexHandle, FirstWrite, offset: 0).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        await WriteAsync(tpm, registry, pool, OwnerIndexHandle, SecondWrite, offset: 0).ConfigureAwait(false);
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A second write must not grow the balance: it merges into the reserved area and returns its own parsed data carrier.");

        await WriteAsync(tpm, registry, pool, OwnerIndexHandle, FirstWrite, offset: 0).ConfigureAwait(false);
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A third write must leave the balance flat for the same reason.");

        byte[] readBack = await ReadAsync(tpm, registry, pool, OwnerIndexHandle, (ushort)FirstWrite.Length, offset: 0).ConfigureAwait(false);
        Assert.AreSequenceEqual(FirstWrite, readBack, "The last write's octets must be what the Index answers with.");
    }

    /// <summary>
    /// A store at a non-zero offset advances the Index's written extent over the reserved octets below that
    /// offset, and those octets read as zeros: the area is reserved at <c>TPM2_NV_DefineSpace()</c> at the
    /// declared <c>dataSize</c> and a write merges only its own octets into it, "starting at
    /// <c>nvIndex→data[offset]</c>" (TPM 2.0 Library Part 3, clause 31.7.1), so nothing the write did not carry
    /// is ever what a later <c>TPM2_NV_Read()</c> of the whole area answers with.
    /// </summary>
    [TestMethod]
    public async Task AStoreAtAnOffsetLeavesTheOctetsBelowItReadingAsZeros()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nvdata-offsetstore").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineIndexAsync(tpm, registry, pool, OwnerIndexHandle, OwnerAuthorizedAttributes, IndexDataSize).ConfigureAwait(false);

        //A store of the upper half alone, so the lower half is octets the Index has reserved but no store has
        //ever reached, and every octet stored is non-zero — a zero anywhere in the read-back is then the
        //reserved area's own content and not the write's.
        byte[] upperHalf = [0x71, 0x72, 0x73, 0x74];
        await WriteAsync(tpm, registry, pool, OwnerIndexHandle, upperHalf, offset: IndexDataSize - upperHalf.Length).ConfigureAwait(false);

        byte[] whole = await ReadAsync(tpm, registry, pool, OwnerIndexHandle, IndexDataSize, offset: 0).ConfigureAwait(false);

        Assert.AreSequenceEqual(
            new byte[IndexDataSize - upperHalf.Length], whole[..(IndexDataSize - upperHalf.Length)],
            "The octets below the store's offset were reserved and never written, so they must read as zeros.");
        Assert.AreSequenceEqual(
            upperHalf, whole[(IndexDataSize - upperHalf.Length)..],
            "The octets at and above the store's offset must be exactly what the write carried.");
    }

    /// <summary>
    /// Advancing a Counter Index with <c>TPM2_NV_Increment()</c> (TPM 2.0 Library Part 3, clause 31.8) stores
    /// the new 8-octet value through the same reserved area, so repeated increments leave the pool flat.
    /// </summary>
    [TestMethod]
    public async Task IncrementingACounterIndexLeavesThePoolFlat()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nvdata-increment").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineIndexAsync(tpm, registry, pool, CounterIndexHandle, CounterAttributes, CounterDataSize).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        await IncrementAsync(tpm, registry, pool, CounterIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The first increment writes the counter's seed into the reserved area and must not grow the balance.");

        await IncrementAsync(tpm, registry, pool, CounterIndexHandle).ConfigureAwait(false);
        await IncrementAsync(tpm, registry, pool, CounterIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Further increments store through the same area, so the balance must stay flat.");
    }

    /// <summary>
    /// <c>TPM2_Clear()</c> deletes every NV Index with <c>TPMA_NV_PLATFORMCREATE</c> CLEAR (TPM 2.0 Library
    /// Part 3, clause 24.6.1) and its owner-NV walk releases each deleted Index's data area along with its
    /// authValue. The one rental the command leaves outstanding is the fresh storage-proof seed the clear
    /// installs, so a successful clear of two written Indexes lands at the pre-definition baseline plus that
    /// single seed.
    /// </summary>
    [TestMethod]
    public async Task ClearReleasesEveryOwnerCreatedIndexDataArea()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nvdata-clear").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        await DefineIndexAsync(tpm, registry, pool, OwnerIndexHandle, OwnerAuthorizedAttributes, IndexDataSize).ConfigureAwait(false);
        await DefineIndexAsync(tpm, registry, pool, SecondOwnerIndexHandle, OwnerAuthorizedAttributes, IndexDataSize).ConfigureAwait(false);
        await WriteAsync(tpm, registry, pool, OwnerIndexHandle, FirstWrite, offset: 0).ConfigureAwait(false);
        await WriteAsync(tpm, registry, pool, SecondOwnerIndexHandle, SecondWrite, offset: 0).ConfigureAwait(false);

        Assert.AreEqual(
            baseline + 2, trackingPool.OutstandingCount,
            "Two definitions reserve two data areas; their empty authValues and policies are shared sentinels.");

        {
            var input = new ClearInput(TpmRh.TPM_RH_LOCKOUT);
            using TpmPasswordSession lockoutAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<ClearResponse> result = await TpmCommandExecutor.ExecuteAsync<ClearResponse>(
                tpm, input, [lockoutAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_Clear failed: '{result.ResponseCode}'.");
        }

        Assert.AreEqual(
            baseline + 1, trackingPool.OutstandingCount,
            "The clear must release both Indexes' data areas; the one remaining rental is the fresh storage-proof seed it installs.");
    }

    /// <summary>
    /// <c>TPM2_NV_Read()</c> frames a BORROW of the Index's data area, never a rental of the response intent's:
    /// the Index outlives the command and stays the carrier's single owner, so a read may be followed by a write
    /// and another read against the same Index. Framing the borrow through the serializer's blanket release
    /// instead would leave the still-live Index holding a returned buffer, and the very next command against it
    /// would fault rather than answer.
    /// </summary>
    [TestMethod]
    public async Task ReadingAnIndexLeavesItsDataAreaUsableForALaterWriteAndRead()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nvdata-borrow").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineIndexAsync(tpm, registry, pool, OwnerIndexHandle, OwnerAuthorizedAttributes, IndexDataSize).ConfigureAwait(false);
        await WriteAsync(tpm, registry, pool, OwnerIndexHandle, FirstWrite, offset: 0).ConfigureAwait(false);

        byte[] first = await ReadAsync(tpm, registry, pool, OwnerIndexHandle, (ushort)FirstWrite.Length, offset: 0).ConfigureAwait(false);
        Assert.AreSequenceEqual(FirstWrite, first, "The first read must answer the stored octets.");

        await WriteAsync(tpm, registry, pool, OwnerIndexHandle, SecondWrite, offset: 0).ConfigureAwait(false);

        byte[] second = await ReadAsync(tpm, registry, pool, OwnerIndexHandle, (ushort)SecondWrite.Length, offset: 0).ConfigureAwait(false);
        Assert.AreSequenceEqual(
            SecondWrite, second,
            "The Index's area must still be owned and writable after a read has framed a borrow of it.");
    }

    /// <summary>
    /// A session-authorized <c>TPM2_NV_Read()</c> builds its <c>TPM2B_MAX_NV_BUFFER</c> response parameter area
    /// inside the framing effect — the step that holds a memory pool — and the response intent adopts that
    /// rental, which the serializer releases after framing (TPM 2.0 Library Part 1, clause 15.6.1). The command
    /// therefore leaves the pool exactly where it found it while still answering the stored octets.
    /// </summary>
    [TestMethod]
    public async Task NvReadOverSessionReturnsItsFramedResponseArea()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nvdata-oversession").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineIndexAsync(tpm, registry, pool, OwnerIndexHandle, OwnerAuthorizedAttributes, IndexDataSize).ConfigureAwait(false);
        await WriteAsync(tpm, registry, pool, OwnerIndexHandle, FirstWrite, offset: 0).ConfigureAwait(false);

        byte[] ownerName = HandleFormName((uint)TpmRh.TPM_RH_OWNER);
        byte[] indexName = await ReadIndexNameAsync(tpm, registry, pool, OwnerIndexHandle).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            long baseline = trackingPool.OutstandingCount;

            {
                var input = new NvReadInput((uint)TpmRh.TPM_RH_OWNER, OwnerIndexHandle, (ushort)FirstWrite.Length, Offset: 0);
                TpmResult<NvReadResponse> result = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                    tpm, input, [session], [ownerName, indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Read over an HMAC session failed: '{result.ResponseCode}'.");

                using NvReadResponse read = result.Value;
                Assert.AreSequenceEqual(FirstWrite, read.Data.ToArray(), "The session-authorized read must answer the stored octets.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The framed response parameter area is adopted by the response intent and released by the serializer after framing.");
        }

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// A <c>TPM2_NV_Read()</c> asking for more octets than a <c>TPM2B_MAX_NV_BUFFER</c> can carry is refused
    /// with <c>TPM_RC_VALUE</c>, and refused there BEFORE the within-the-Index range check: the reference's own
    /// <c>TPM2_NV_Read</c> orders "Make sure the data will fit the return buffer" (<c>in-&gt;size &gt;
    /// MAX_NV_BUFFER_SIZE</c>) ahead of both the offset check and the range check, and clause 31.13.1 names no
    /// buffer rule of its own — the bound is Table 264's response parameter being a <c>TPM2B_MAX_NV_BUFFER</c>,
    /// which TPM 2.0 Library Part 2, clause 10.3.9, Table 97 limits to <c>MAX_NV_BUFFER_SIZE</c>. The request
    /// here is BOTH over the bound and past the Index's 8 written octets, so the code proves the order and not
    /// merely the check.
    /// </summary>
    [TestMethod]
    public async Task NvReadRefusesASizeWiderThanTheBufferBoundBeforeTheRangeCheck()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nvdata-readbound").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineIndexAsync(tpm, registry, pool, OwnerIndexHandle, OwnerAuthorizedAttributes, IndexDataSize).ConfigureAwait(false);
        await WriteAsync(tpm, registry, pool, OwnerIndexHandle, FirstWrite, offset: 0).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        {
            var input = new NvReadInput((uint)TpmRh.TPM_RH_OWNER, OwnerIndexHandle, Size: Tpm2bMaxNvBuffer.MaxSize + 1, Offset: 0);
            using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<NvReadResponse> result = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsTpmError, "A read wider than the NV buffer bound must be refused.");
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_VALUE, result.ResponseCode,
                "A requested size past MAX_NV_BUFFER_SIZE is TPM_RC_VALUE, answered ahead of the within-the-Index range check.");
        }

        {
            var input = new NvReadInput((uint)TpmRh.TPM_RH_OWNER, OwnerIndexHandle, Size: IndexDataSize + 1, Offset: 0);
            using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<NvReadResponse> result = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_NV_RANGE, result.ResponseCode,
                "A size within the buffer bound but past the Index's written extent stays TPM_RC_NV_RANGE (Part 3, clause 31.13.1).");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Neither refusal may leave a rental outstanding.");
    }

    /// <summary>
    /// The buffer bound is enforced on the session-authorized arm of <c>TPM2_NV_Read()</c> too, through the same
    /// shared window validation both arms run, and the refusal is framed bare exactly as the arm's other
    /// business-logic refusals are.
    /// </summary>
    [TestMethod]
    public async Task NvReadOverSessionRefusesASizeWiderThanTheBufferBound()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nvdata-readboundsession").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineIndexAsync(tpm, registry, pool, OwnerIndexHandle, OwnerAuthorizedAttributes, IndexDataSize).ConfigureAwait(false);
        await WriteAsync(tpm, registry, pool, OwnerIndexHandle, FirstWrite, offset: 0).ConfigureAwait(false);

        byte[] ownerName = HandleFormName((uint)TpmRh.TPM_RH_OWNER);
        byte[] indexName = await ReadIndexNameAsync(tpm, registry, pool, OwnerIndexHandle).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            long baseline = trackingPool.OutstandingCount;

            var input = new NvReadInput((uint)TpmRh.TPM_RH_OWNER, OwnerIndexHandle, Size: Tpm2bMaxNvBuffer.MaxSize + 1, Offset: 0);
            TpmResult<NvReadResponse> result = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                tpm, input, [session], [ownerName, indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsTpmError, "A session-authorized read wider than the NV buffer bound must be refused.");
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_VALUE, result.ResponseCode,
                "The bound answers TPM_RC_VALUE on the session arm as well, bare rather than session-encoded.");
            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The refusal must release the parse-rented parameter area and the transferred Index Name.");
        }

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// A <c>TPM2_NV_Write()</c> whose <c>data</c> parameter declares more octets than a
    /// <c>TPM2B_MAX_NV_BUFFER</c> can hold is refused at the wire read with <c>TPM_RC_SIZE</c> — the
    /// marshalling refusal Part 2, clause 10.3.9, Table 97's <c>buffer[size]{:MAX_NV_BUFFER_SIZE}</c> bound
    /// produces, and the one the reference's own <c>TPM2B_MAX_NV_BUFFER</c> unmarshal answers. Clause 31.7.1
    /// states no size rule of its own precisely because such a parameter never reaches the command body. The
    /// frame is built by hand: the typed input's carrier refuses the same bound client-side, so no production
    /// caller can express it.
    /// </summary>
    [TestMethod]
    public async Task NvWriteRefusesDataWiderThanTheBufferBoundAtTheWireRead()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nvdata-writebound").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineIndexAsync(tpm, registry, pool, OversizeIndexHandle, SelfAuthorizedAttributes, OversizeIndexDataSize).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        //Handle area, a password authorization area, then data ‖ offset with a data field one octet past the bound.
        var body = new List<byte>();
        AppendUInt32(body, OversizeIndexHandle);
        AppendUInt32(body, OversizeIndexHandle);
        AppendPasswordAuthorizationArea(body);
        AppendUInt16(body, Tpm2bMaxNvBuffer.MaxSize + 1);
        body.AddRange(new byte[Tpm2bMaxNvBuffer.MaxSize + 1]);
        AppendUInt16(body, 0);

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_NV_Write, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, code,
            "A data parameter past MAX_NV_BUFFER_SIZE is refused at the wire read with TPM_RC_SIZE.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The bound is answered ahead of the rental, so a refused parse must rent nothing.");

        //A write exactly AT the bound is admitted, so the refusal above pins the bound and not merely a size.
        byte[] atBound = new byte[Tpm2bMaxNvBuffer.MaxSize];
        atBound[0] = 0x41;
        await WriteAsync(tpm, registry, pool, OversizeIndexHandle, atBound, offset: 0, authHandle: OversizeIndexHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// A <c>TPM2_NV_Certify()</c> asking to certify more octets than a <c>TPM2B_MAX_NV_BUFFER</c> can carry is
    /// refused with <c>TPM_RC_VALUE</c>, and refused there AFTER the within-the-Index range check: clause
    /// 31.16.1 states the range rule as a "shall" ("If offset and size add to a value that is greater than the
    /// dataSize field of the NV Index referenced by nvIndex, the TPM shall return an error (TPM_RC_NV_RANGE)")
    /// and the buffer rule as the additional check that follows it ("The implementation may return an error
    /// (TPM_RC_VALUE) if it performs an additional check and determines that offset is greater than the dataSize
    /// field of the NV Index, or if size is greater than MAX_NV_BUFFER_SIZE"), which is also the order the
    /// reference's own <c>TPM2_NV_Certify</c> runs them in — the OPPOSITE of <c>TPM2_NV_Read</c>'s. Both halves
    /// are proved: an in-range request past the bound is <c>TPM_RC_VALUE</c>, an out-of-range one is
    /// <c>TPM_RC_NV_RANGE</c> even though it is also past the bound.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyRefusesASizeWiderThanTheBufferBoundAfterTheRangeCheck()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nvdata-certifybound").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        await DefineIndexAsync(tpm, registry, pool, OversizeIndexHandle, SelfAuthorizedAttributes, OversizeIndexDataSize).ConfigureAwait(false);

        //The written extent has to reach the whole declared area, which takes two writes because a single one
        //may carry at most MAX_NV_BUFFER_SIZE octets.
        byte[] head = new byte[Tpm2bMaxNvBuffer.MaxSize];
        head[0] = 0x51;
        await WriteAsync(tpm, registry, pool, OversizeIndexHandle, head, offset: 0, authHandle: OversizeIndexHandle).ConfigureAwait(false);
        await WriteAsync(tpm, registry, pool, OversizeIndexHandle, [0x52], offset: Tpm2bMaxNvBuffer.MaxSize, authHandle: OversizeIndexHandle).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        {
            using NvCertifyInput input = NvCertifyInput.ForEcdsa(
                signer.ObjectHandle, OversizeIndexHandle, OversizeIndexHandle, QualifyingData, SessionAlg,
                size: OversizeIndexDataSize, offset: 0, pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession indexAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, input, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsTpmError, "Certifying more octets than the NV buffer bound admits must be refused.");
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_VALUE, result.ResponseCode,
                "An in-range request past MAX_NV_BUFFER_SIZE is TPM_RC_VALUE (Part 3, clause 31.16.1's additional check).");
        }

        {
            using NvCertifyInput input = NvCertifyInput.ForEcdsa(
                signer.ObjectHandle, OversizeIndexHandle, OversizeIndexHandle, QualifyingData, SessionAlg,
                size: OversizeIndexDataSize, offset: 1, pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession indexAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, input, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_NV_RANGE, result.ResponseCode,
                "A request that is out of range as well as past the bound answers the range code, which clause 31.16.1 states first.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Neither refusal may leave a rental outstanding.");
    }

    /// <summary>
    /// The bound the NV data parameters enforce is the one the TPM reports: <c>TPM_PT_NV_BUFFER_MAX</c> is "the
    /// maximum data size in one NV write, NV read, NV extend, or NV certify command" (TPM 2.0 Library Part 2,
    /// clause 6.13, Table 28), so a caller that reads the property and sizes its transfers by it is never
    /// refused for exceeding it — one fact, reported and enforced from the same value.
    /// </summary>
    [TestMethod]
    public async Task NvBufferMaxIsReportedAsTheBoundTheNvCommandsEnforce()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-nvdata-property").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        var input = GetCapabilityInput.ForTpmProperties(TpmPtConstants.TPM_PT_NV_BUFFER_MAX, count: 1);
        TpmResult<GetCapabilityResponse> result = await TpmCommandExecutor.ExecuteAsync<GetCapabilityResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_GetCapability failed: '{result.ResponseCode}'.");

        using GetCapabilityResponse response = result.Value;
        var properties = response.CapabilityData.TpmProperties;
        Assert.IsNotNull(properties);
        Assert.HasCount(1, properties);
        Assert.AreEqual(TpmPtConstants.TPM_PT_NV_BUFFER_MAX, properties[0].Property, "The window must start at the requested property.");
        Assert.AreEqual(
            (uint)Tpm2bMaxNvBuffer.MaxSize, properties[0].Value,
            "The reported maximum must be the very bound the NV read, write, and certify parameters refuse above.");
    }

    /// <summary>Renders a permanent entity's Name: its 4-octet big-endian handle value (Part 1, clause 13, Table 9).</summary>
    /// <param name="handle">The entity's handle.</param>
    /// <returns>The handle-form Name.</returns>
    private static byte[] HandleFormName(uint handle)
    {
        byte[] name = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(name, handle);

        return name;
    }

    /// <summary>Appends a big-endian <c>UINT32</c> to a command body under construction.</summary>
    /// <param name="body">The body being built.</param>
    /// <param name="value">The value to append.</param>
    private static void AppendUInt32(List<byte> body, uint value)
    {
        Span<byte> octets = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(octets, value);
        body.AddRange(octets);
    }

    /// <summary>Appends a big-endian <c>UINT16</c> to a command body under construction.</summary>
    /// <param name="body">The body being built.</param>
    /// <param name="value">The value to append.</param>
    private static void AppendUInt16(List<byte> body, int value)
    {
        Span<byte> octets = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(octets, (ushort)value);
        body.AddRange(octets);
    }

    /// <summary>
    /// Appends a one-slot authorization area naming <c>TPM_RS_PW</c> with an empty nonce and an empty password —
    /// the password form of <c>TPMS_AUTH_COMMAND</c> (TPM 2.0 Library Part 1, clause 16.6.4.1) — which is enough
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
    /// <param name="pool">The memory pool.</param>
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

    /// <summary>Defines an Index with empty owner authorization and an empty access policy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index attributes.</param>
    /// <param name="dataSize">The declared data area width.</param>
    private async Task DefineIndexAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex, TpmaNv attributes, ushort dataSize)
    {
        using Tpm2bDigest policyDigest = Tpm2bDigest.Create(ReadOnlySpan<byte>.Empty, pool);
        using TpmsNvPublic publicInfo = new(nvIndex, SessionAlg, attributes, policyDigest, dataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, Tpm2bAuth.Empty, publicInfo);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_DefineSpace failed: '{result.ResponseCode}'.");
    }

    /// <summary>Writes octets into an Index under empty owner authorization.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index to write.</param>
    /// <param name="data">The octets to store.</param>
    /// <param name="offset">The octet offset at which to store them.</param>
    /// <param name="authHandle">The authorization handle, or <see langword="null"/> for the owner hierarchy.</param>
    private async Task WriteAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex, byte[] data, int offset, uint? authHandle = null)
    {
        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(data, pool);
        var input = new NvWriteInput(authHandle ?? (uint)TpmRh.TPM_RH_OWNER, nvIndex, buffer, (ushort)offset);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<NvWriteResponse> result = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Write failed: '{result.ResponseCode}'.");
    }

    /// <summary>Reads a window of an Index under empty owner authorization.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index to read.</param>
    /// <param name="size">The number of octets to read.</param>
    /// <param name="offset">The octet offset to read from.</param>
    /// <returns>The octets read.</returns>
    private async Task<byte[]> ReadAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex, ushort size, ushort offset)
    {
        var input = new NvReadInput((uint)TpmRh.TPM_RH_OWNER, nvIndex, size, offset);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<NvReadResponse> result = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Read failed: '{result.ResponseCode}'.");

        using NvReadResponse read = result.Value;

        return read.Data.ToArray();
    }

    /// <summary>Advances a Counter Index by one under empty owner authorization.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Counter Index to advance.</param>
    private async Task IncrementAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex)
    {
        var input = new NvIncrementInput((uint)TpmRh.TPM_RH_OWNER, nvIndex);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<NvIncrementResponse> result = await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Increment failed: '{result.ResponseCode}'.");
    }

    /// <summary>Removes an Index under empty owner authorization.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index to remove.</param>
    private async Task UndefineAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex)
    {
        var input = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, nvIndex);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<NvUndefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_UndefineSpace failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Reads an Index's Name back from the TPM, which is where a session-authorized command's cpHash Name2 term
    /// comes from — <c>TPMA_NV_WRITTEN</c> is part of the public area the Name digests, so a Name taken before
    /// the first write would no longer name the Index (TPM 2.0 Library Part 1, clause 13, Table 9).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index whose Name is wanted.</param>
    /// <returns>The Index's Name.</returns>
    private async Task<byte[]> ReadIndexNameAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex)
    {
        var input = new NvReadPublicInput(nvIndex);
        TpmResult<NvReadPublicResponse> result = await TpmCommandExecutor.ExecuteAsync<NvReadPublicResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_ReadPublic failed: '{result.ResponseCode}'.");

        using NvReadPublicResponse publicArea = result.Value;

        return publicArea.NvName.Span.ToArray();
    }

    /// <summary>Creates an empty-auth ECC P-256 signing primary in the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256 signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Starts an unbound, unsalted HMAC session and returns its handle and client-side wrapper.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session handle and the caller-side session.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartUnboundSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, pool)
        {
            SessionAttributes = TpmaSession.CONTINUE_SESSION
        };

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Flushes a transient object or session handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush.</param>
    private async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        var input = FlushContextInput.ForHandle(handle);
        TpmResult<FlushContextResponse> result = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_FlushContext failed: '{result.ResponseCode}'.");
    }

    /// <summary>Builds the response codec registry these proofs drive the executor with.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_ReadPublic, TpmResponseCodec.NvReadPublic);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Increment, TpmResponseCodec.NvIncrement);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Certify, TpmResponseCodec.NvCertify);
        _ = registry.Register(TpmCcConstants.TPM_CC_Clear, TpmResponseCodec.Clear);

        return registry;
    }

    /// <summary>Creates a simulator with an ECC signing backend, powers it on, and brings it operational.</summary>
    /// <param name="pool">The memory pool every command runs against.</param>
    /// <param name="tpmId">The simulated TPM's run identifier, unique per test so no meter is shared.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool, string tpmId)
    {
        var simulator = new TpmSimulator(tpmId, signingBackend: BouncyCastleTpmEccSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

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

        return simulator;
    }
}
