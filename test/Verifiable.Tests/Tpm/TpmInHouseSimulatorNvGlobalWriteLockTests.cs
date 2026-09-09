using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Nv;
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
/// Drives <c>TPM2_NV_GlobalWriteLock()</c>'s EFFECT over the owner arm on the password form — "The command will
/// SET TPMA_NV_WRITELOCKED for all indexes that have their TPMA_NV_GLOBALLOCK attribute SET" — across the Index
/// shapes the effect must reach and must not reach, the Name movement each lock causes, the write family's
/// <c>TPM_RC_NV_LOCKED</c> gates the lock makes reachable, and the <c>TPM2_Startup()</c> pass that CLEARs such a
/// lock on a TPM Reset or TPM Restart unless <c>TPMA_NV_WRITEDEFINE</c> and <c>TPMA_NV_WRITTEN</c> are both SET —
/// against the in-house behavioural <see cref="TpmSimulator"/>, entirely in-process with no external assets,
/// through the same production command path the production code uses (<see cref="TpmCommandExecutor"/> and the
/// real command/response codecs). TPM 2.0 Library Part 3, clauses 31.12, 31.8.1, 31.9.1, 31.10 and 9.3; Part 2,
/// clause 13.4; Part 1, clauses 13 and 34.2.6.1.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorNvGlobalWriteLockTests
{
    /// <summary>The declared data size of every Ordinary Index this file defines.</summary>
    private const ushort OrdinaryDataSize = 16;

    /// <summary>The declared data size clause 31.3.1's eight-octet rule fixes for a Counter and a Bit Field Index.</summary>
    private const ushort EightOctetDataSize = 8;

    /// <summary>The declared data size of the SHA-256 Extend Index — its nameAlg's digest width (clause 31.3.1).</summary>
    private const ushort Sha256DigestSize = 32;

    /// <summary>The Ordinary Index carrying <c>TPMA_NV_GLOBALLOCK</c> alone, the elected shape.</summary>
    private const uint GlobalLockIndexHandle = 0x0100_0080;

    /// <summary>The Ordinary Index carrying no <c>TPMA_NV_GLOBALLOCK</c>, the shape the command must not touch.</summary>
    private const uint PlainIndexHandle = 0x0100_0081;

    /// <summary>The Ordinary Index carrying <c>TPMA_NV_GLOBALLOCK</c> together with <c>TPMA_NV_ORDERLY</c>.</summary>
    private const uint OrderlyGlobalLockIndexHandle = 0x0100_0082;

    /// <summary>The Ordinary Index carrying <c>TPMA_NV_GLOBALLOCK</c> together with <c>TPMA_NV_WRITEDEFINE</c>.</summary>
    private const uint WriteDefineGlobalLockIndexHandle = 0x0100_0083;

    /// <summary>The Ordinary Index defined only AFTER a global lock has already been executed.</summary>
    private const uint LateGlobalLockIndexHandle = 0x0100_0084;

    /// <summary>The Counter Index used to prove <c>TPM2_NV_Increment()</c>'s lock gate.</summary>
    private const uint CounterIndexHandle = 0x0100_0085;

    /// <summary>The Extend Index used to prove <c>TPM2_NV_Extend()</c>'s lock gate.</summary>
    private const uint ExtendIndexHandle = 0x0100_0086;

    /// <summary>The Bit Field Index used to prove <c>TPM2_NV_SetBits()</c>'s lock gate.</summary>
    private const uint BitsIndexHandle = 0x0100_0087;

    /// <summary>
    /// Ordinary Index attributes carrying no <c>TPMA_NV_GLOBALLOCK</c>: readable and writable with the Index
    /// authValue, writable with owner authorization.
    /// </summary>
    private const TpmaNv PlainAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE;

    /// <summary>Ordinary Index attributes electing <c>TPMA_NV_GLOBALLOCK</c> and neither lockability attribute.</summary>
    private const TpmaNv GlobalLockOnlyAttributes = PlainAttributes | TpmaNv.TPMA_NV_GLOBALLOCK;

    /// <summary>
    /// Ordinary Index attributes electing <c>TPMA_NV_GLOBALLOCK</c> together with <c>TPMA_NV_ORDERLY</c> — the
    /// Index shape Part 4's <c>NvSetGlobalLock</c> reaches through its second, RAM-resident loop.
    /// </summary>
    private const TpmaNv OrderlyGlobalLockAttributes = GlobalLockOnlyAttributes | TpmaNv.TPMA_NV_ORDERLY;

    /// <summary>Ordinary Index attributes electing <c>TPMA_NV_GLOBALLOCK</c> together with <c>TPMA_NV_WRITEDEFINE</c>, the permanent lock.</summary>
    private const TpmaNv WriteDefineGlobalLockAttributes = GlobalLockOnlyAttributes | TpmaNv.TPMA_NV_WRITEDEFINE;

    /// <summary>Counter Index attributes electing <c>TPMA_NV_GLOBALLOCK</c> (the type rides bits 7:4 of TPMA_NV).</summary>
    private const TpmaNv CounterGlobalLockAttributes =
        GlobalLockOnlyAttributes | (TpmaNv)((uint)TpmNt.TPM_NT_COUNTER << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>Extend Index attributes electing <c>TPMA_NV_GLOBALLOCK</c>.</summary>
    private const TpmaNv ExtendGlobalLockAttributes =
        GlobalLockOnlyAttributes | (TpmaNv)((uint)TpmNt.TPM_NT_EXTEND << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>Bit Field Index attributes electing <c>TPMA_NV_GLOBALLOCK</c>.</summary>
    private const TpmaNv BitsGlobalLockAttributes =
        GlobalLockOnlyAttributes | (TpmaNv)((uint)TpmNt.TPM_NT_BITS << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>The <c>bits</c> value the pre-lock <c>TPM2_NV_SetBits()</c> call ORs in, which the Bit Field Index must accept.</summary>
    private const ulong AcceptedBits = 0x8000_0000_0000_0001ul;

    /// <summary>The <c>bits</c> value the post-lock <c>TPM2_NV_SetBits()</c> attempt would OR in, which the lock must refuse.</summary>
    private const ulong RefusedBits = 0x0000_0000_0000_0002ul;

    /// <summary>The Index authorization value used throughout.</summary>
    private static byte[] CorrectAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>The sixteen octets an Ordinary Index is populated with before it is globally locked.</summary>
    private static byte[] IndexData { get; } =
        [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];

    /// <summary>A second sixteen-octet payload, written after a lock has been cleared by a startup.</summary>
    private static byte[] SecondIndexData { get; } =
        [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F];

    /// <summary>
    /// A single-octet payload for a write attempt that a lock must refuse; its content is immaterial since the
    /// write never reaches the Index's stored data.
    /// </summary>
    private static byte[] RefusedWriteAttempt { get; } = [0x00];

    /// <summary>Thirty-two octets of <c>data</c> for a <c>TPM2_NV_Extend()</c> the Index accepts before the lock.</summary>
    private static byte[] AcceptedExtendAttempt { get; } = new byte[Sha256DigestSize];

    /// <summary>Thirty-two octets of <c>data</c> for the <c>TPM2_NV_Extend()</c> attempt a lock must refuse.</summary>
    private static byte[] RefusedExtendAttempt { get; } = new byte[Sha256DigestSize];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// "The command will SET TPMA_NV_WRITELOCKED for all indexes that have their TPMA_NV_GLOBALLOCK attribute
    /// SET" — read back two ways on an Ordinary Index carrying <c>TPMA_NV_GLOBALLOCK</c>: the attribute word
    /// <c>TPM2_NV_ReadPublic()</c> returns carries <c>TPMA_NV_WRITELOCKED</c>, and the next <c>TPM2_NV_Write()</c>
    /// is refused with <c>TPM_RC_NV_LOCKED</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.12.1 and 31.7.1; Part 2, clause 13.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOfGlobalLockIndexSetsWritelockedAndRefusesTheNextWrite()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockOnlyAttributes).ConfigureAwait(false);

        TpmResult<NvWriteResponse> firstWrite = await WriteIndexAsync(
            device, pool, registry, GlobalLockIndexHandle, CorrectAuth, IndexData).ConfigureAwait(false);
        Assert.IsTrue(firstWrite.IsSuccess, $"The Index must be writable before the global lock: '{firstWrite.ResponseCode}'.");

        TpmResult<NvGlobalWriteLockResponse> lockResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{lockResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "Clause 31.12.1 SETs TPMA_NV_WRITELOCKED on every Index whose TPMA_NV_GLOBALLOCK is SET.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, GlobalLockIndexHandle, CorrectAuth, RefusedWriteAttempt).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_LOCKED, writeResult.ResponseCode,
            "Clause 31.7.1 refuses TPM2_NV_Write() on a write-locked Index with TPM_RC_NV_LOCKED.");
    }

    /// <summary>
    /// "CLEAR (0): TPM2_NV_GlobalWriteLock() has no effect on the writing of the data at this Index" — an Index
    /// whose <c>TPMA_NV_GLOBALLOCK</c> is CLEAR is untouched: it keeps <c>TPMA_NV_WRITELOCKED</c> CLEAR, its Name
    /// does not move (Part 1, clause 13: only a locked Index's Name changes) and it is still writable.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 13.4; Part 3, clause 31.12.1; Part 1, clause 13</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockLeavesAnIndexWithoutGlobalLockWritableWithItsNameUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PlainIndexHandle, PlainAttributes).ConfigureAwait(false);
        byte[] nameBefore = await ReadIndexNameAsync(device, PlainIndexHandle).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> lockResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{lockResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, PlainIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "TPMA_NV_GLOBALLOCK CLEAR means the command has no effect on this Index.");

        byte[] nameAfter = await ReadIndexNameAsync(device, PlainIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(
            nameBefore.AsSpan().SequenceEqual(nameAfter),
            "An untouched Index's attribute word is unchanged, so the Name it digests is unchanged too.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, PlainIndexHandle, CorrectAuth, IndexData).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"An Index the global lock does not elect must stay writable: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// The election is <c>TPMA_NV_GLOBALLOCK</c> alone: Part 4's <c>NvSetGlobalLock</c> walks the non-orderly
    /// Indexes and the orderly ones in two loops and SETs <c>TPMA_NV_WRITELOCKED</c> in both, so an Index
    /// carrying <c>TPMA_NV_ORDERLY</c> beside <c>TPMA_NV_GLOBALLOCK</c> locks exactly as a non-orderly one does.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.12.1; Part 2, clause 13.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOfOrderlyGlobalLockIndexSetsWritelockedAndRefusesTheNextWrite()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, OrderlyGlobalLockIndexHandle, OrderlyGlobalLockAttributes).ConfigureAwait(false);

        TpmResult<NvWriteResponse> firstWrite = await WriteIndexAsync(
            device, pool, registry, OrderlyGlobalLockIndexHandle, CorrectAuth, IndexData).ConfigureAwait(false);
        Assert.IsTrue(firstWrite.IsSuccess, $"The Index must be writable before the global lock: '{firstWrite.ResponseCode}'.");

        TpmResult<NvGlobalWriteLockResponse> lockResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{lockResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, OrderlyGlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "An orderly Index carrying TPMA_NV_GLOBALLOCK is locked by the same command.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, OrderlyGlobalLockIndexHandle, CorrectAuth, RefusedWriteAttempt).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_LOCKED, writeResult.ResponseCode,
            "A globally locked orderly Index refuses TPM2_NV_Write() with TPM_RC_NV_LOCKED.");
    }

    /// <summary>
    /// The election tests no other attribute: clause 31.12.1 conditions the lock on <c>TPMA_NV_GLOBALLOCK</c>
    /// alone and never on <c>TPMA_NV_WRITTEN</c>, so an Index that has never been written locks too and is
    /// refused its FIRST write with <c>TPM_RC_NV_LOCKED</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.12.1 and 31.7.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOfUnwrittenGlobalLockIndexLocksAndRefusesItsFirstWrite()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockOnlyAttributes).ConfigureAwait(false);

        TpmaNv beforeLock = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), beforeLock & TpmaNv.TPMA_NV_WRITTEN, "The Index has never been written.");

        TpmResult<NvGlobalWriteLockResponse> lockResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{lockResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "Clause 31.12.1's election reads TPMA_NV_GLOBALLOCK only, so an unwritten Index locks as well.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, GlobalLockIndexHandle, CorrectAuth, IndexData).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_LOCKED, writeResult.ResponseCode,
            "The lock refuses the Index's first write exactly as it refuses a later one.");
    }

    /// <summary>
    /// The command's reach and its restraint in one position: with a <c>TPMA_NV_GLOBALLOCK</c> Index, a
    /// <c>TPMA_NV_GLOBALLOCK</c> + <c>TPMA_NV_ORDERLY</c> Index and an Index carrying neither defined side by
    /// side, "all indexes that have their TPMA_NV_GLOBALLOCK attribute SET" locks the first two and leaves the
    /// third writable.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.12.1; Part 2, clause 13.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOfThreeIndexesLocksTheTwoElectedAndLeavesTheThirdWritable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockOnlyAttributes).ConfigureAwait(false);
        await DefineIndexAsync(device, pool, registry, OrderlyGlobalLockIndexHandle, OrderlyGlobalLockAttributes).ConfigureAwait(false);
        await DefineIndexAsync(device, pool, registry, PlainIndexHandle, PlainAttributes).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> lockResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{lockResult.ResponseCode}'.");

        TpmaNv globalLockAttributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        TpmaNv orderlyAttributes = await ReadIndexAttributesAsync(device, OrderlyGlobalLockIndexHandle).ConfigureAwait(false);
        TpmaNv plainAttributes = await ReadIndexAttributesAsync(device, PlainIndexHandle).ConfigureAwait(false);

        Assert.AreEqual(TpmaNv.TPMA_NV_WRITELOCKED, globalLockAttributes & TpmaNv.TPMA_NV_WRITELOCKED, "The elected Ordinary Index locks.");
        Assert.AreEqual(TpmaNv.TPMA_NV_WRITELOCKED, orderlyAttributes & TpmaNv.TPMA_NV_WRITELOCKED, "The elected orderly Index locks as well.");
        Assert.AreEqual(default(TpmaNv), plainAttributes & TpmaNv.TPMA_NV_WRITELOCKED, "The Index carrying no TPMA_NV_GLOBALLOCK is untouched.");

        TpmResult<NvWriteResponse> globalLockWrite = await WriteIndexAsync(
            device, pool, registry, GlobalLockIndexHandle, CorrectAuth, RefusedWriteAttempt).ConfigureAwait(false);
        TpmResult<NvWriteResponse> orderlyWrite = await WriteIndexAsync(
            device, pool, registry, OrderlyGlobalLockIndexHandle, CorrectAuth, RefusedWriteAttempt).ConfigureAwait(false);
        TpmResult<NvWriteResponse> plainWrite = await WriteIndexAsync(
            device, pool, registry, PlainIndexHandle, CorrectAuth, IndexData).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, globalLockWrite.ResponseCode, "The elected Ordinary Index refuses a write.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, orderlyWrite.ResponseCode, "The elected orderly Index refuses a write.");
        Assert.IsTrue(plainWrite.IsSuccess, $"The unelected Index must remain writable: '{plainWrite.ResponseCode}'.");
    }

    /// <summary>
    /// Part 4's <c>NvSetGlobalLock</c> walks whatever Indexes exist and returns <c>TPM_RC_SUCCESS</c>
    /// unconditionally, so a TPM with no Index defined at all answers the command successfully — zero matches is
    /// not an error.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockWithNoIndexDefinedReturnsSuccess()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);

        Assert.IsTrue(
            result.IsSuccess,
            $"Clause 31.12.1 names no error for an empty NV space, so zero elected Indexes is TPM_RC_SUCCESS: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// "If an Index is defined with TPMA_NV_GLOBALLOCK SET, then the global lock does not apply until the next
    /// time this command is executed" — an Index defined after a global lock is writable, and the NEXT
    /// <c>TPM2_NV_GlobalWriteLock()</c> is what locks it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockDoesNotApplyToAnIndexDefinedAfterwardsUntilTheNextExecution()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockOnlyAttributes).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> firstLock = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(firstLock.IsSuccess, $"The first TPM2_NV_GlobalWriteLock() failed: '{firstLock.ResponseCode}'.");

        await DefineIndexAsync(device, pool, registry, LateGlobalLockIndexHandle, GlobalLockOnlyAttributes).ConfigureAwait(false);

        TpmaNv afterDefinition = await ReadIndexAttributesAsync(device, LateGlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            default(TpmaNv), afterDefinition & TpmaNv.TPMA_NV_WRITELOCKED,
            "The earlier global lock does not reach an Index that did not yet exist.");

        TpmResult<NvWriteResponse> writeBeforeSecondLock = await WriteIndexAsync(
            device, pool, registry, LateGlobalLockIndexHandle, CorrectAuth, IndexData).ConfigureAwait(false);
        Assert.IsTrue(writeBeforeSecondLock.IsSuccess, $"The later Index must be writable until the next execution: '{writeBeforeSecondLock.ResponseCode}'.");

        TpmResult<NvGlobalWriteLockResponse> secondLock = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(secondLock.IsSuccess, $"The second TPM2_NV_GlobalWriteLock() failed: '{secondLock.ResponseCode}'.");

        TpmaNv afterSecondLock = await ReadIndexAttributesAsync(device, LateGlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, afterSecondLock & TpmaNv.TPMA_NV_WRITELOCKED,
            "The next execution of the command is what applies the global lock to the later Index.");

        TpmResult<NvWriteResponse> writeAfterSecondLock = await WriteIndexAsync(
            device, pool, registry, LateGlobalLockIndexHandle, CorrectAuth, SecondIndexData).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, writeAfterSecondLock.ResponseCode, "The later Index is write-locked once the second execution has run.");
    }

    /// <summary>
    /// The effect is idempotent: Part 4's <c>NvSetGlobalLock</c> SETs a bit that is already SET and returns
    /// <c>TPM_RC_SUCCESS</c>, which the Names prove — the Name digests the attribute word (Part 1, clause 13),
    /// so an unchanged Name on the locked Index and on the untouched one is an unchanged public area on both.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.12.1; Part 1, clause 13</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockRepeatedReturnsSuccessWithEveryNameUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockOnlyAttributes).ConfigureAwait(false);
        await DefineIndexAsync(device, pool, registry, PlainIndexHandle, PlainAttributes).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> firstLock = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(firstLock.IsSuccess, $"The first TPM2_NV_GlobalWriteLock() failed: '{firstLock.ResponseCode}'.");

        byte[] globalLockNameAfterFirst = await ReadIndexNameAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        byte[] plainNameAfterFirst = await ReadIndexNameAsync(device, PlainIndexHandle).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> secondLock = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(
            secondLock.IsSuccess,
            $"A repeated global lock is TPM_RC_SUCCESS: clause 31.12.1 names no already-locked refusal, yet the answer was '{secondLock.ResponseCode}'.");

        byte[] globalLockNameAfterSecond = await ReadIndexNameAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        byte[] plainNameAfterSecond = await ReadIndexNameAsync(device, PlainIndexHandle).ConfigureAwait(false);

        Assert.IsTrue(
            globalLockNameAfterFirst.AsSpan().SequenceEqual(globalLockNameAfterSecond),
            "The repeat changes no attribute on the already-locked Index, so its Name is unchanged.");
        Assert.IsTrue(
            plainNameAfterFirst.AsSpan().SequenceEqual(plainNameAfterSecond),
            "The repeat changes no attribute on the unelected Index either.");
    }

    /// <summary>
    /// "When an NV Index becomes locked (TPMA_NV_WRITELOCKED or TPMA_NV_READLOCKED is SET), the Name of the NV
    /// Index changes" — the Name digests the public area's attribute word, so each Index this command locks has a
    /// different Name afterwards while the Index it leaves alone keeps its own.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 13; Part 3, clause 31.12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockChangesTheNameOfEachLockedIndexAndNotTheUntouchedOne()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockOnlyAttributes).ConfigureAwait(false);
        await DefineIndexAsync(device, pool, registry, OrderlyGlobalLockIndexHandle, OrderlyGlobalLockAttributes).ConfigureAwait(false);
        await DefineIndexAsync(device, pool, registry, PlainIndexHandle, PlainAttributes).ConfigureAwait(false);

        byte[] globalLockNameBefore = await ReadIndexNameAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        byte[] orderlyNameBefore = await ReadIndexNameAsync(device, OrderlyGlobalLockIndexHandle).ConfigureAwait(false);
        byte[] plainNameBefore = await ReadIndexNameAsync(device, PlainIndexHandle).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> lockResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{lockResult.ResponseCode}'.");

        byte[] globalLockNameAfter = await ReadIndexNameAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        byte[] orderlyNameAfter = await ReadIndexNameAsync(device, OrderlyGlobalLockIndexHandle).ConfigureAwait(false);
        byte[] plainNameAfter = await ReadIndexNameAsync(device, PlainIndexHandle).ConfigureAwait(false);

        Assert.IsFalse(globalLockNameBefore.AsSpan().SequenceEqual(globalLockNameAfter), "Becoming locked moves the elected Ordinary Index's Name.");
        Assert.IsFalse(orderlyNameBefore.AsSpan().SequenceEqual(orderlyNameAfter), "Becoming locked moves the elected orderly Index's Name.");
        Assert.IsTrue(plainNameBefore.AsSpan().SequenceEqual(plainNameAfter), "An Index that does not become locked keeps its Name.");
    }

    /// <summary>
    /// "If TPMA_NV_WRITEDEFINE is CLEAR, the TPMA_NV_WRITELOCKED attribute can be SET using ...
    /// TPM2_NV_GlobalWriteLock() if TPMA_NV_GLOBALLOCK is SET. In this case, TPMA_NV_WRITELOCKED will be CLEAR on
    /// the next TPM Reset or TPM Restart" — a written <c>TPMA_NV_GLOBALLOCK</c>-only Index locked by this command
    /// has its lock cleared by a TPM Reset and is writable again.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.1; Part 3, clauses 9.3 and 31.12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOfWrittenGlobalLockOnlyIndexClearsOnATpmReset()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineWriteAndGlobalLockAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockOnlyAttributes).ConfigureAwait(false);

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "A TPM Reset must CLEAR a globally set TPMA_NV_WRITELOCKED on an Index whose TPMA_NV_WRITEDEFINE is CLEAR.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, GlobalLockIndexHandle, CorrectAuth, SecondIndexData).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"The Index must be writable once the lock has cleared: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// Clause 9.3 lists the same bullet under TPM Restart — "For each NV index with TPMA_NV_WRITEDEFINE CLEAR or
    /// TPMA_NV_WRITTEN CLEAR, TPMA_NV_WRITELOCKED shall be CLEAR" — so a
    /// <c>Shutdown(TPM_SU_STATE)</c>/<c>Startup(TPM_SU_CLEAR)</c> cycle clears a global lock on a
    /// <c>TPMA_NV_GLOBALLOCK</c>-only Index exactly as a Reset does.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 9.3 and 31.12.1; Part 1, clause 34.2.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOfWrittenGlobalLockOnlyIndexClearsOnATpmRestart()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineWriteAndGlobalLockAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockOnlyAttributes).ConfigureAwait(false);

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "A TPM Restart must CLEAR a globally set TPMA_NV_WRITELOCKED on an Index whose TPMA_NV_WRITEDEFINE is CLEAR.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, GlobalLockIndexHandle, CorrectAuth, SecondIndexData).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"The Index must be writable once the lock has cleared: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// The unlock is a TPM Reset and TPM Restart act only: "TPMA_NV_WRITELOCKED will be CLEAR on the next TPM
    /// Reset or TPM Restart" names neither a Resume, and clause 9.3 lists the bullet under neither the Resume
    /// heading nor the every-Startup rules — so after a <c>Shutdown(TPM_SU_STATE)</c>/<c>Startup(TPM_SU_STATE)</c>
    /// cycle a global lock stands and a write is still <c>TPM_RC_NV_LOCKED</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.1; Part 3, clauses 9.3, 31.12.1 and 31.7.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOfWrittenGlobalLockOnlyIndexSurvivesATpmResume()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineWriteAndGlobalLockAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockOnlyAttributes).ConfigureAwait(false);

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE, TpmSuConstants.TPM_SU_STATE).ConfigureAwait(false);

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "A TPM Resume runs no NV startup pass, so the global lock must stand.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, GlobalLockIndexHandle, CorrectAuth, SecondIndexData).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, writeResult.ResponseCode, "The Index is still globally write-locked after a TPM Resume.");
    }

    /// <summary>
    /// "If an Index has both TPMA_NV_GLOBALLOCK and TPMA_NV_WRITEDEFINE SET, then this command will permanently
    /// lock the NV Index for writing unless TPMA_NV_WRITTEN is CLEAR" — with <c>TPMA_NV_WRITTEN</c> SET, clause
    /// 9.3's unlock bullet does not apply, so the lock survives a TPM Reset AND a TPM Restart.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.12.1 and 9.3; Part 1, clause 34.2.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOfWrittenWriteDefineIndexSurvivesATpmResetAndATpmRestart()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineWriteAndGlobalLockAsync(device, pool, registry, WriteDefineGlobalLockIndexHandle, WriteDefineGlobalLockAttributes).ConfigureAwait(false);

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmaNv afterReset = await ReadIndexAttributesAsync(device, WriteDefineGlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, afterReset & TpmaNv.TPMA_NV_WRITELOCKED,
            "A written TPMA_NV_WRITEDEFINE Index keeps a globally set lock across a TPM Reset.");

        TpmResult<NvWriteResponse> afterResetWrite = await WriteIndexAsync(
            device, pool, registry, WriteDefineGlobalLockIndexHandle, CorrectAuth, SecondIndexData).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, afterResetWrite.ResponseCode, "The permanent lock still refuses a write after a TPM Reset.");

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmaNv afterRestart = await ReadIndexAttributesAsync(device, WriteDefineGlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, afterRestart & TpmaNv.TPMA_NV_WRITELOCKED,
            "A written TPMA_NV_WRITEDEFINE Index keeps a globally set lock across a TPM Restart too.");

        TpmResult<NvWriteResponse> afterRestartWrite = await WriteIndexAsync(
            device, pool, registry, WriteDefineGlobalLockIndexHandle, CorrectAuth, SecondIndexData).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, afterRestartWrite.ResponseCode, "The permanent lock still refuses a write after a TPM Restart.");
    }

    /// <summary>
    /// The permanent lock's only exit is deletion: <c>TPM2_NV_UndefineSpace()</c> carries no lock gate at all, so
    /// the owner arm deletes a globally and permanently locked Index, and a redefinition at the same handle
    /// begins with <c>TPMA_NV_WRITELOCKED</c> CLEAR ("When the Index is created ... TPMA_NV_WRITELOCKED,
    /// TPMA_NV_READLOCKED, and TPMA_NV_WRITTEN shall all be CLEAR") and is writable.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.4, 31.3.1 and 31.12.1; Part 2, clause 13.4; Part 1, clause 34.2.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceOfGloballyLockedWriteDefineIndexAllowsAWritableRedefinition()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineWriteAndGlobalLockAsync(device, pool, registry, WriteDefineGlobalLockIndexHandle, WriteDefineGlobalLockAttributes).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> undefineResult = await UndefineIndexAsync(device, pool, registry, WriteDefineGlobalLockIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(undefineResult.IsSuccess, $"TPM2_NV_UndefineSpace() of a permanently locked Index must succeed: '{undefineResult.ResponseCode}'.");

        TpmResult<NvDefineSpaceResponse> redefineResult = await DefineIndexAsync(
            device, pool, registry, WriteDefineGlobalLockIndexHandle, WriteDefineGlobalLockAttributes).ConfigureAwait(false);
        Assert.IsTrue(redefineResult.IsSuccess, $"The redefinition must succeed: '{redefineResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, WriteDefineGlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED, "A newly defined Index carries TPMA_NV_WRITELOCKED CLEAR.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, WriteDefineGlobalLockIndexHandle, CorrectAuth, IndexData).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"The redefined Index must be writable: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// The "unless TPMA_NV_WRITTEN is CLEAR" half of clause 31.12.1's permanence sentence, which Part 1 states as
    /// "If TPMA_NV_WRITELOCKED is SET, but TPMA_NV_WRITTEN is CLEAR, then TPMA_NV_WRITELOCKED is CLEAR by TPM
    /// Reset or TPM Restart. This is true even if the TPMA_NV_WRITEDEFINE attribute is set. It prevents an NV
    /// Index from being defined that can never be written" — an UNWRITTEN
    /// <c>TPMA_NV_GLOBALLOCK</c> + <c>TPMA_NV_WRITEDEFINE</c> Index locks here, is unlocked by a TPM Reset, and
    /// then accepts its first write.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.1; Part 3, clauses 31.12.1 and 9.3</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOfUnwrittenWriteDefineIndexClearsOnATpmResetAndTheIndexAcceptsItsFirstWrite()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteDefineGlobalLockIndexHandle, WriteDefineGlobalLockAttributes).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> lockResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{lockResult.ResponseCode}'.");

        TpmaNv afterLock = await ReadIndexAttributesAsync(device, WriteDefineGlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, afterLock & TpmaNv.TPMA_NV_WRITELOCKED,
            "An unwritten Index carrying TPMA_NV_GLOBALLOCK is locked by this command like any other.");

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmaNv afterReset = await ReadIndexAttributesAsync(device, WriteDefineGlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            default(TpmaNv), afterReset & TpmaNv.TPMA_NV_WRITELOCKED,
            "TPMA_NV_WRITTEN CLEAR unlocks the Index even under TPMA_NV_WRITEDEFINE, so no Index is defined that can never be written.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, WriteDefineGlobalLockIndexHandle, CorrectAuth, IndexData).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"The Index must accept its first write once the lock has cleared: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// The lock this command sets reaches every update command's gate: "If TPMA_NV_WRITELOCKED is SET, the TPM
    /// shall return TPM_RC_NV_LOCKED" for <c>TPM2_NV_Increment()</c> — a Counter Index carrying
    /// <c>TPMA_NV_GLOBALLOCK</c> increments before the global lock and is refused afterwards.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.8.1 and 31.12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOfGloballyLockedCounterIndexReturnsNvLocked()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterGlobalLockAttributes, EightOctetDataSize).ConfigureAwait(false);

        TpmResult<NvIncrementResponse> firstIncrement = await IncrementAsync(device, pool, registry, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(firstIncrement.IsSuccess, $"The Counter Index must increment before the global lock: '{firstIncrement.ResponseCode}'.");

        TpmResult<NvGlobalWriteLockResponse> lockResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{lockResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, CounterIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED, "A Counter Index carrying TPMA_NV_GLOBALLOCK locks like any other.");

        TpmResult<NvIncrementResponse> result = await IncrementAsync(device, pool, registry, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, result.ResponseCode, "Clause 31.8.1 refuses an increment on a write-locked Index.");
    }

    /// <summary>
    /// The same gate on <c>TPM2_NV_Extend()</c>: "If the TPMA_NV_WRITELOCKED attribute of the NV Index is SET,
    /// then the TPM shall return TPM_RC_NV_LOCKED" — an Extend Index carrying <c>TPMA_NV_GLOBALLOCK</c> extends
    /// before the global lock and is refused afterwards.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.9.1 and 31.12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOfGloballyLockedExtendIndexReturnsNvLocked()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendGlobalLockAttributes, Sha256DigestSize).ConfigureAwait(false);

        TpmResult<NvExtendResponse> firstExtend = await ExtendAsync(device, pool, registry, ExtendIndexHandle, CorrectAuth, AcceptedExtendAttempt).ConfigureAwait(false);
        Assert.IsTrue(firstExtend.IsSuccess, $"The Extend Index must extend before the global lock: '{firstExtend.ResponseCode}'.");

        TpmResult<NvGlobalWriteLockResponse> lockResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{lockResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, ExtendIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED, "An Extend Index carrying TPMA_NV_GLOBALLOCK locks like any other.");

        TpmResult<NvExtendResponse> result = await ExtendAsync(device, pool, registry, ExtendIndexHandle, CorrectAuth, RefusedExtendAttempt).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, result.ResponseCode, "Clause 31.9.1 refuses an extend on a write-locked Index.");
    }

    /// <summary>
    /// The fourth update command answers the same gate: "If the TPMA_NV_WRITELOCKED attribute is SET when an
    /// attempt is made to modify the Index, the TPM returns TPM_RC_NV_LOCKED" — a Bit Field Index carrying
    /// <c>TPMA_NV_GLOBALLOCK</c> accepts <c>TPM2_NV_SetBits()</c> before the global lock and is refused
    /// afterwards.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.1; Part 3, clauses 31.10 and 31.12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOfGloballyLockedBitsIndexReturnsNvLocked()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsGlobalLockAttributes, EightOctetDataSize).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> firstSetBits = await SetBitsAsync(device, pool, registry, BitsIndexHandle, CorrectAuth, AcceptedBits).ConfigureAwait(false);
        Assert.IsTrue(firstSetBits.IsSuccess, $"The Bit Field Index must accept bits before the global lock: '{firstSetBits.ResponseCode}'.");

        TpmResult<NvGlobalWriteLockResponse> lockResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{lockResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, BitsIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED, "A Bit Field Index carrying TPMA_NV_GLOBALLOCK locks like any other.");

        TpmResult<NvSetBitsResponse> result = await SetBitsAsync(device, pool, registry, BitsIndexHandle, CorrectAuth, RefusedBits).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, result.ResponseCode, "Clause 31.10 refuses a bit-set on a write-locked Index.");
    }

    /// <summary>
    /// Defines <paramref name="nvIndex"/>, populates it with <see cref="IndexData"/> and executes
    /// <c>TPM2_NV_GlobalWriteLock()</c>, asserting each step — the starting position of every startup-pass proof,
    /// which needs both <c>TPMA_NV_WRITTEN</c> and a globally set <c>TPMA_NV_WRITELOCKED</c>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define and write.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes; they must carry TPMA_NV_GLOBALLOCK for the lock to reach it.</param>
    private async Task DefineWriteAndGlobalLockAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, TpmaNv attributes)
    {
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineIndexAsync(device, pool, registry, nvIndex, attributes).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"TPM2_NV_DefineSpace() failed: '{defineResult.ResponseCode}'.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(device, pool, registry, nvIndex, CorrectAuth, IndexData).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"TPM2_NV_Write() failed: '{writeResult.ResponseCode}'.");

        TpmResult<NvGlobalWriteLockResponse> lockResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{lockResult.ResponseCode}'.");

        TpmaNv locked = await ReadIndexAttributesAsync(device, nvIndex).ConfigureAwait(false);
        Assert.AreEqual(TpmaNv.TPMA_NV_WRITELOCKED, locked & TpmaNv.TPMA_NV_WRITELOCKED, "The Index must be write-locked before the startup cycle under test.");
    }

    /// <summary>
    /// Issues the owner arm of <c>TPM2_NV_GlobalWriteLock()</c> over a password authorization carrying the
    /// factory-empty <c>ownerAuth</c> — "This command requires either platformAuth/platformPolicy or
    /// ownerAuth/ownerPolicy" (TPM 2.0 Library Part 3, clause 31.12.1), and the authorizing handle plays no part
    /// in which Indexes lock.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <returns>The global write-lock result.</returns>
    private async Task<TpmResult<NvGlobalWriteLockResponse>> GlobalWriteLockAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        var input = new NvGlobalWriteLockInput(TpmRh.TPM_RH_OWNER);

        return await TpmCommandExecutor.ExecuteAsync<NvGlobalWriteLockResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates a response codec registry for the NV commands these tests drive.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateNvRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite)
            .Register(TpmCcConstants.TPM_CC_NV_Increment, TpmResponseCodec.NvIncrement)
            .Register(TpmCcConstants.TPM_CC_NV_Extend, TpmResponseCodec.NvExtend)
            .Register(TpmCcConstants.TPM_CC_NV_SetBits, TpmResponseCodec.NvSetBits)
            .Register(TpmCcConstants.TPM_CC_NV_GlobalWriteLock, TpmResponseCodec.NvGlobalWriteLock);

    /// <summary>
    /// Issues <c>TPM2_NV_DefineSpace()</c> for <paramref name="nvIndex"/> with <see cref="CorrectAuth"/> as the
    /// Index authValue, authorized by the (empty) owner authValue.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    /// <param name="dataSize">The declared data area size; defaults to the Ordinary Index width this file uses.</param>
    /// <returns>The define-space result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, TpmaNv attributes, ushort dataSize = OrdinaryDataSize)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);

        //The input takes ownership of the auth value and public area and disposes them; the redundant using
        //locals satisfy CA2000 and are safe because both types have idempotent disposal.
        using var auth = Tpm2bAuth.Create(CorrectAuth, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, attributes, Tpm2bDigest.Empty, dataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues an owner-authorized <c>TPM2_NV_UndefineSpace()</c> for <paramref name="nvIndex"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to delete.</param>
    /// <returns>The undefine-space result.</returns>
    private async Task<TpmResult<NvUndefineSpaceResponse>> UndefineIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        var input = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues an Index-arm <c>TPM2_NV_Write()</c> against <paramref name="nvIndex"/> at offset zero, authorized by the Index authValue.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to write.</param>
    /// <param name="suppliedAuth">The authorization value supplied for the Index.</param>
    /// <param name="data">The octets to store.</param>
    /// <returns>The write result.</returns>
    private async Task<TpmResult<NvWriteResponse>> WriteIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ReadOnlyMemory<byte> data)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(data.Span, pool);
        var input = new NvWriteInput(nvIndex, nvIndex, buffer, Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues an Index-arm <c>TPM2_NV_Increment()</c> against <paramref name="nvIndex"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Counter Index to increment.</param>
    /// <param name="suppliedAuth">The authorization value supplied for the Index.</param>
    /// <returns>The increment result.</returns>
    private async Task<TpmResult<NvIncrementResponse>> IncrementAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var input = new NvIncrementInput(nvIndex, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues an Index-arm <c>TPM2_NV_Extend()</c> against <paramref name="nvIndex"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Extend Index to extend.</param>
    /// <param name="suppliedAuth">The authorization value supplied for the Index.</param>
    /// <param name="data">The octets to fold in.</param>
    /// <returns>The extend result.</returns>
    private async Task<TpmResult<NvExtendResponse>> ExtendAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ReadOnlyMemory<byte> data)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(data.Span, pool);
        var input = new NvExtendInput(nvIndex, nvIndex, buffer);

        return await TpmCommandExecutor.ExecuteAsync<NvExtendResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues an Index-arm <c>TPM2_NV_SetBits()</c> against <paramref name="nvIndex"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Bit Field Index whose bits are SET.</param>
    /// <param name="suppliedAuth">The authorization value supplied for the Index.</param>
    /// <param name="bits">The value ORed into the Index's current contents.</param>
    /// <returns>The set-bits result.</returns>
    private async Task<TpmResult<NvSetBitsResponse>> SetBitsAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ulong bits)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var input = new NvSetBitsInput(nvIndex, nvIndex, bits);

        return await TpmCommandExecutor.ExecuteAsync<NvSetBitsResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads an Index's Name back from the TPM through <c>TPM2_NV_ReadPublic()</c> — the authoritative view of a
    /// lock's effect on identity, since the attribute word a lock changes is part of the public area the Name
    /// digests (TPM 2.0 Library Part 1, clause 13).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Index whose Name is wanted.</param>
    /// <returns>The Index's Name.</returns>
    private async Task<byte[]> ReadIndexNameAsync(TpmDevice device, uint nvIndex)
    {
        TpmResult<NvReadPublicResponse> nameResult = await device.NvReadPublicAsync(nvIndex, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(nameResult.IsSuccess, $"NvReadPublicAsync failed: '{nameResult.ResponseCode}'.");

        using NvReadPublicResponse namePublic = nameResult.Value;

        return namePublic.NvName.Span.ToArray();
    }

    /// <summary>
    /// Reads an Index's <c>TPMA_NV</c> attribute word back through <c>TPM2_NV_ReadPublic()</c>, which is how the
    /// TPM-maintained lock bits are observable from outside (TPM 2.0 Library Part 3, clause 31.6).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Index whose public area is wanted.</param>
    /// <returns>The Index's attribute word.</returns>
    private async Task<TpmaNv> ReadIndexAttributesAsync(TpmDevice device, uint nvIndex)
    {
        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(nvIndex, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(publicResult.IsSuccess, $"NvReadPublicAsync failed: '{publicResult.ResponseCode}'.");

        using NvReadPublicResponse indexPublic = publicResult.Value;

        return indexPublic.NvPublic.Attributes;
    }

    /// <summary>Completes an orderly shutdown, powers the simulator back on, and completes the startup, asserting each wire step.</summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="shutdownType">The orderly shutdown type.</param>
    /// <param name="startupType">The startup type completing the cycle.</param>
    private async Task PowerCycleAsync(TpmSimulator simulator, BaseMemoryPool pool, TpmSuConstants shutdownType, TpmSuConstants startupType)
    {
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, await SubmitSessionlessAsync(simulator, pool, new ShutdownInput(shutdownType)).ConfigureAwait(false), "TPM2_Shutdown() must succeed.");
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, await SubmitSessionlessAsync(simulator, pool, new StartupInput(startupType)).ConfigureAwait(false), "TPM2_Startup() must succeed.");
    }

    /// <summary>Frames a sessionless command directly to the simulator and returns its response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="input">The command input.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSessionlessAsync(TpmSimulator simulator, BaseMemoryPool pool, ITpmCommandInput input)
    {
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The transport itself must succeed.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>Creates a simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.</summary>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync()
    {
        var simulator = new TpmSimulator("tpm-in-house-nv-globalwritelock", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitSessionlessAsync(simulator, BaseMemoryPool.Shared, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false),
            "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
