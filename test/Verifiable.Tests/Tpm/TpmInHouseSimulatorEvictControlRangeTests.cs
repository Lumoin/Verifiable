using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_EvictControl()</c>'s hierarchy and range gates against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same production
/// command path the production code uses (<see cref="TpmCommandExecutor"/> with the real
/// <see cref="EvictControlInput"/> and response codecs): clause 28.5.1's items 2 (<c>TPM_RC_HIERARCHY</c>), 3
/// and 8 (<c>TPM_RC_RANGE</c>), and 4 (<c>TPM_RC_NV_DEFINED</c>)
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3, clause 28.5.1).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorEvictControlRangeTests
{
    /// <summary>A platform-range persistent handle (0x81800000-0x81FFFFFF) used by the range-mismatch tests.</summary>
    private const uint PlatformRangeHandle = 0x8180_0400;

    /// <summary>An owner-range persistent handle used by the hierarchy-mismatch test.</summary>
    private const uint OwnerRangeHandleForHierarchyTest = 0x8100_0410;

    /// <summary>The owner-range persistent handle the NV_DEFINED collision test persists to twice.</summary>
    private const uint CollisionHandle = 0x8100_0420;

    /// <summary>The owner-range persistent handle the item-9 mismatch test evicts under.</summary>
    private const uint HandleMismatchPersistentHandle = 0x8100_0430;

    /// <summary>A distinct owner-range handle, never the same as <see cref="HandleMismatchPersistentHandle"/>, supplied as the mismatched <c>objectHandle</c>.</summary>
    private const uint HandleMismatchObjectHandle = 0x8100_0431;

    /// <summary>An owner-range persistent handle persisted under <c>TPM_RH_OWNER</c>, then evicted under <c>TPM_RH_PLATFORM</c>.</summary>
    private const uint PlatformEvictOfOwnerObjectHandle = 0x8100_0440;

    /// <summary>A persistentHandle value above Table 51's persistent-object range ({PERSISTENT_FIRST:PERSISTENT_LAST}, ceiling 0x81FFFFFF).</summary>
    private const uint AboveTable51Range = 0x9000_0000;

    /// <summary>A persistentHandle value below Table 51's persistent-object range (floor 0x81000000).</summary>
    private const uint BelowTable51Range = 0x0100_0000;

    /// <summary>An arbitrary objectHandle placeholder for the parse-level tests, never read: <c>persistentHandle</c> is a parameter parsed after the handle area, so a malformed value is refused before objectHandle is ever resolved.</summary>
    private const uint ParseTestObjectHandlePlaceholder = 0;

    /// <summary>An owner-range persistent handle a platform-hierarchy object is refused persisting to under <c>TPM_RH_PLATFORM</c> auth (item 3.2's converse cell).</summary>
    private const uint PlatformPersistIntoOwnerRangeHandle = 0x8100_0450;

    /// <summary>The owner-range persistent handle the different-object NV_DEFINED collision test persists two distinct objects to.</summary>
    private const uint DifferentObjectCollisionHandle = 0x8100_0460;

    /// <summary>A platform-range persistent handle a platform-hierarchy object is persisted to, then re-attempted under <c>TPM_RH_OWNER</c> auth (both wrong-hierarchy and out-of-range at once).</summary>
    private const uint BothWrongHierarchyAndRangeHandle = 0x8180_0470;

    /// <summary>An owner-range persistent handle an Endorsement-hierarchy object persists to under <c>TPM_RH_OWNER</c> auth successfully (item 2.2).</summary>
    private const uint EndorsementUnderOwnerSuccessHandle = 0x8100_0480;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// "3. The TPM shall return TPM_RC_RANGE if persistentHandle is not in the proper range as determined by
    /// auth. 1. If auth is TPM_RH_OWNER, then persistentHandle shall be in the inclusive range of 81 00 00
    /// 00₁₆ to 81 7F FF FF₁₆" (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3, clause 28.5.1, item 3.1): persisting an owner-hierarchy object
    /// under <c>TPM_RH_OWNER</c> to a platform-range handle is refused <c>TPM_RC_RANGE</c>.
    /// </summary>
    [TestMethod]
    public async Task PersistUnderOwnerToAPlatformRangeHandleAnswersRange()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateOwnerStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<EvictControlResponse> result = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, key.ObjectHandle.Value, PlatformRangeHandle, authHandle: TpmRh.TPM_RH_OWNER, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_RANGE, 0), result.ResponseCode,
            "A TPM_RH_OWNER persist to a platform-range persistentHandle must be refused TPM_RC_RANGE (clause 28.5.1, item 3.1).");
    }

    /// <summary>
    /// "2. The TPM shall return TPM_RC_HIERARCHY if the object is not in the proper hierarchy as determined by
    /// auth. 1. If auth is TPM_RH_PLATFORM, the proper hierarchy is the Platform hierarchy"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 28.5.1, item 2.1): persisting an owner-hierarchy object under
    /// <c>TPM_RH_PLATFORM</c> authorization is refused <c>TPM_RC_HIERARCHY</c>.
    /// </summary>
    [TestMethod]
    public async Task PersistAnOwnerHierarchyObjectUnderPlatformAuthAnswersHierarchy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateOwnerStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<EvictControlResponse> result = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, key.ObjectHandle.Value, OwnerRangeHandleForHierarchyTest, authHandle: TpmRh.TPM_RH_PLATFORM, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 1), result.ResponseCode,
            "TPM_RH_PLATFORM may persist only a Platform-hierarchy object; an owner-hierarchy object must be refused TPM_RC_HIERARCHY (clause 28.5.1, item 2.1).");
    }

    /// <summary>
    /// "4. The TPM shall return TPM_RC_NV_DEFINED if a persistent object exists with the same handle as
    /// persistentHandle" (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3, clause 28.5.1, item 4): persisting a second object to an
    /// already-occupied persistentHandle is refused <c>TPM_RC_NV_DEFINED</c> rather than replacing the occupant.
    /// </summary>
    [TestMethod]
    public async Task PersistToAnAlreadyOccupiedHandleAnswersNvDefinedOnTheSecondCall()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateOwnerStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<EvictControlResponse> firstResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, key.ObjectHandle.Value, CollisionHandle, authHandle: TpmRh.TPM_RH_OWNER, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(firstResult.IsSuccess, $"The first persist to the handle must succeed: '{firstResult.ResponseCode}'.");

        //Persisting is a genuine copy — the transient stays loaded — so the same objectHandle names a live
        //transient object again for the second, colliding call.
        TpmResult<EvictControlResponse> secondResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, key.ObjectHandle.Value, CollisionHandle, authHandle: TpmRh.TPM_RH_OWNER, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_DEFINED, secondResult.ResponseCode,
            "Persisting a second object to an already-occupied persistentHandle must be refused TPM_RC_NV_DEFINED (clause 28.5.1, item 4), not silently overwrite it.");
    }

    /// <summary>
    /// "8. The TPM shall return TPM_RC_RANGE if objectHandle is not in the proper range as determined by auth.
    /// If auth is TPM_RC_OWNER, objectHandle shall be in the inclusive range of 81 00 00 00₁₆ to 81 7F FF FF₁₆"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 28.5.1, item 8): a platform-hierarchy object persisted under
    /// <c>TPM_RH_PLATFORM</c> at a platform-range handle, then evicted under <c>TPM_RH_OWNER</c>, is refused
    /// <c>TPM_RC_RANGE</c>: the evict arm's own range gate (item 8) is item 3's exact counterpart on the evict side.
    /// </summary>
    [TestMethod]
    public async Task EvictUnderOwnerOfAPlatformRangeHandlePersistedUnderPlatformAnswersRange()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreatePlatformStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, key.ObjectHandle.Value, PlatformRangeHandle, authHandle: TpmRh.TPM_RH_PLATFORM, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"Persisting the platform-hierarchy object under TPM_RH_PLATFORM must succeed: '{persistResult.ResponseCode}'.");

        TpmResult<EvictControlResponse> evictResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, PlatformRangeHandle, PlatformRangeHandle, authHandle: TpmRh.TPM_RH_OWNER, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_RANGE, 0), evictResult.ResponseCode,
            "TPM_RH_OWNER may evict only a handle in the owner range; a platform-range handle must be refused TPM_RC_RANGE (clause 28.5.1, item 8), not TPM_RC_SUCCESS.");
    }

    /// <summary>
    /// "9. If objectHandle is not the same value as persistentHandle, return TPM_RC_HANDLE"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 28.5.1, item 9): <see cref="EvictControlInput"/> carries
    /// <c>ObjectHandle</c> and <c>PersistentHandle</c> as two genuinely distinct fields (<c>persistentHandle</c> is
    /// read as its own wire parameter on every call, Table 230), so the evict arm's own mismatch gate is
    /// reachable: evicting with an <c>objectHandle</c> that
    /// names a real persistent object but differs from the supplied <c>persistentHandle</c> answers
    /// <c>TPM_RC_HANDLE</c> handle-encoded at objectHandle, handle 2 of Table 230.
    /// </summary>
    [TestMethod]
    public async Task EvictWithAMismatchedObjectHandleAndPersistentHandleAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateOwnerStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, key.ObjectHandle.Value, HandleMismatchPersistentHandle, authHandle: TpmRh.TPM_RH_OWNER, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"Persisting the object must succeed: '{persistResult.ResponseCode}'.");

        //objectHandle carries the REAL persistent handle (so the handle-area presence probe resolves and the
        //evict arm is reached), while persistentHandle carries a distinct value nothing names — item 9 compares
        //the two request fields directly, so this reaches its own gate rather than the earlier presence probe.
        TpmResult<EvictControlResponse> evictResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, HandleMismatchPersistentHandle, HandleMismatchObjectHandle, authHandle: TpmRh.TPM_RH_OWNER, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), evictResult.ResponseCode,
            "objectHandle naming a real persistent object that differs from the supplied persistentHandle designates objectHandle, handle 2 of TPM2_EvictControl's own command table (clause 28.5.1, item 9).");
    }

    /// <summary>
    /// "If auth is TPM_RC_PLATFORM, objectHandle may be any valid persistent object handle"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 28.5.1, item 8): evicting an owner-hierarchy persistent object under
    /// <c>TPM_RH_PLATFORM</c> succeeds — clause 28.5.1's evict arm (items 8-10, "If objectHandle references a
    /// persistent object") carries no hierarchy item at all, unlike the persist arm's item 2, so a
    /// platform-authorized evict is gated by range alone and reaches any persistent handle regardless of the
    /// object's own recorded hierarchy. The evicted handle then names nothing, so <c>TPM2_ReadPublic()</c>
    /// answers <c>TPM_RC_HANDLE</c> handle-encoded at objectHandle, its sole handle.
    /// </summary>
    [TestMethod]
    public async Task EvictUnderPlatformOfAnOwnerHierarchyPersistentObjectAnswersSuccessThenReadPublicAnswersHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateOwnerStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, key.ObjectHandle.Value, PlatformEvictOfOwnerObjectHandle, authHandle: TpmRh.TPM_RH_OWNER, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"Persisting the owner-hierarchy object under TPM_RH_OWNER must succeed: '{persistResult.ResponseCode}'.");

        TpmResult<EvictControlResponse> evictResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, PlatformEvictOfOwnerObjectHandle, PlatformEvictOfOwnerObjectHandle, authHandle: TpmRh.TPM_RH_PLATFORM, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            evictResult.IsSuccess,
            $"TPM_RH_PLATFORM may evict any valid persistent object handle regardless of the object's own recorded hierarchy (clause 28.5.1, item 8): '{(evictResult.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : evictResult.ResponseCode)}'.");

        TpmResult<ReadPublicResponse> readAfterEvict = await ReadPublicAsync(tpm, registry, pool, PlatformEvictOfOwnerObjectHandle).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), readAfterEvict.ResponseCode,
            "The evicted handle must name nothing: TPM2_ReadPublic() at it answers TPM_RC_HANDLE.");
    }

    /// <summary>
    /// "{PERSISTENT_FIRST:PERSISTENT_LAST} allowed range for persistent objects" / "#TPM_RC_VALUE"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2, clause 9.5, Table 51): a persistentHandle outside the persistent-object
    /// range is refused <c>TPM_RC_VALUE</c> by <see cref="Verifiable.Tpm.Spec.Handles.TpmiDhPersistent.Parse"/>
    /// at parse — before the handle area is ever resolved and before Part 3, clause 28.5.1's own item 3/item 8 range
    /// gates could run — regardless of which provisioning hierarchy authorizes the command.
    /// </summary>
    [TestMethod]
    public async Task PersistentHandleOutsideTable51RangeAnswersValueAtParse()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<EvictControlResponse> abovePlatformRange = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, ParseTestObjectHandlePlaceholder, AboveTable51Range, authHandle: TpmRh.TPM_RH_PLATFORM, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, parameterIndex: 0), abovePlatformRange.ResponseCode,
            "Table 230: persistentHandle is TPM2_EvictControl()'s sole parameter (index 0); 0x90000000 lies above Table 51's persistent-object range and must be refused TPM_RC_VALUE at parse, even under TPM_RH_PLATFORM auth.");

        TpmResult<EvictControlResponse> belowOwnerRange = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, ParseTestObjectHandlePlaceholder, BelowTable51Range, authHandle: TpmRh.TPM_RH_OWNER, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, parameterIndex: 0), belowOwnerRange.ResponseCode,
            "Table 230: persistentHandle is TPM2_EvictControl()'s sole parameter (index 0); 0x01000000 lies below Table 51's persistent-object range and must be refused TPM_RC_VALUE at parse, even under TPM_RH_OWNER auth.");
    }

    /// <summary>
    /// "2. If auth is TPM_RH_PLATFORM, then persistentHandle shall be in the inclusive range of 81 80 00 00₁₆
    /// to 81 FF FF FF₁₆" (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3, clause 28.5.1, item 3.2): persisting a platform-hierarchy
    /// object under <c>TPM_RH_PLATFORM</c> to an owner-range handle is refused <c>TPM_RC_RANGE</c> — the
    /// converse cell of <see cref="PersistUnderOwnerToAPlatformRangeHandleAnswersRange"/>'s item 3.1.
    /// </summary>
    [TestMethod]
    public async Task PersistUnderPlatformToAnOwnerRangeHandleAnswersRange()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreatePlatformStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<EvictControlResponse> result = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, key.ObjectHandle.Value, PlatformPersistIntoOwnerRangeHandle, authHandle: TpmRh.TPM_RH_PLATFORM, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_RANGE, 0), result.ResponseCode,
            "A TPM_RH_PLATFORM persist to an owner-range persistentHandle must be refused TPM_RC_RANGE (clause 28.5.1, item 3.2).");
    }

    /// <summary>
    /// "4. The TPM shall return TPM_RC_NV_DEFINED if a persistent object exists with the same handle as
    /// persistentHandle" (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 3, clause 28.5.1, item 4), for a genuinely DIFFERENT object than
    /// the one already occupying the handle: the second persist is refused, and the ORIGINAL object stays
    /// reachable and unmodified through its handle — item 4's refusal must not disturb the occupant.
    /// </summary>
    [TestMethod]
    public async Task PersistToAnAlreadyOccupiedHandleWithADifferentObjectAnswersNvDefinedAndTheOriginalStaysUsable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse original = await CreateOwnerStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreatePrimaryResponse other = await CreateOwnerStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<EvictControlResponse> firstResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, original.ObjectHandle.Value, DifferentObjectCollisionHandle, authHandle: TpmRh.TPM_RH_OWNER, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(firstResult.IsSuccess, $"The first persist to the handle must succeed: '{firstResult.ResponseCode}'.");

        TpmResult<EvictControlResponse> secondResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, other.ObjectHandle.Value, DifferentObjectCollisionHandle, authHandle: TpmRh.TPM_RH_OWNER, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_DEFINED, secondResult.ResponseCode,
            "Persisting a DIFFERENT object to an already-occupied persistentHandle must be refused TPM_RC_NV_DEFINED (clause 28.5.1, item 4).");

        TpmResult<ReadPublicResponse> readAfterRefusal = await ReadPublicAsync(tpm, registry, pool, DifferentObjectCollisionHandle).ConfigureAwait(false);
        Assert.IsTrue(
            readAfterRefusal.IsSuccess,
            $"The original occupant must still be reachable through its handle after the refused collision: '{(readAfterRefusal.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : readAfterRefusal.ResponseCode)}'.");
        using ReadPublicResponse readResponse = readAfterRefusal.Value;
        Assert.IsTrue(
            readResponse.Name.Span.SequenceEqual(original.Name.Span),
            "The handle must still name the ORIGINAL object, not the refused second one, after the collision.");
    }

    /// <summary>
    /// The persist arm's gate order: an object that is BOTH in the wrong hierarchy for <c>auth</c> AND
    /// targeting a persistentHandle outside <c>auth</c>'s range is refused <c>TPM_RC_HIERARCHY</c>, item 2
    /// running before item 3
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 28.5.1): a platform-hierarchy object persisted under
    /// <c>TPM_RH_OWNER</c> to a platform-range handle fails BOTH item 2 (a platform-hierarchy object is
    /// improper for owner auth) and item 3 (a platform-range handle is improper for owner auth) at once, and
    /// item 2's <c>TPM_RC_HIERARCHY</c> is the one the TPM returns.
    /// </summary>
    [TestMethod]
    public async Task PersistAnObjectThatIsBothWrongHierarchyAndOutOfRangeAnswersHierarchy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreatePlatformStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<EvictControlResponse> result = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, key.ObjectHandle.Value, BothWrongHierarchyAndRangeHandle, authHandle: TpmRh.TPM_RH_OWNER, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 1), result.ResponseCode,
            "An object failing both item 2 (hierarchy) and item 3 (range) at once must answer TPM_RC_HIERARCHY, item 2 running first (clause 28.5.1).");
    }

    /// <summary>
    /// "2. If auth is TPM_RH_OWNER, the proper hierarchy is either the Storage or the Endorsement hierarchy"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3, clause 28.5.1, item 2.2): persisting an Endorsement-hierarchy object under
    /// <c>TPM_RH_OWNER</c> authorization to an owner-range handle succeeds — owner authorization admits EITHER
    /// hierarchy, not Storage alone.
    /// </summary>
    [TestMethod]
    public async Task PersistAnEndorsementHierarchyObjectUnderOwnerAuthSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateEndorsementStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<EvictControlResponse> result = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, key.ObjectHandle.Value, EndorsementUnderOwnerSuccessHandle, authHandle: TpmRh.TPM_RH_OWNER, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            result.IsSuccess,
            $"TPM_RH_OWNER authorization must admit an Endorsement-hierarchy object (clause 28.5.1, item 2.2): '{(result.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : result.ResponseCode)}'.");
    }

    /// <summary>Issues a sessionless <c>TPM2_ReadPublic()</c> for the given handle, returning the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="objectHandle">The handle to read.</param>
    /// <returns>The ReadPublic result.</returns>
    private async Task<TpmResult<ReadPublicResponse>> ReadPublicAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint objectHandle)
    {
        ReadPublicInput input = ReadPublicInput.ForHandle(TpmiDhObject.FromValue(objectHandle));

        return await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates a restricted-decrypt ECC storage primary under the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateOwnerStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (owner storage parent) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates a restricted-decrypt ECC storage primary under the platform hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreatePlatformStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_PLATFORM, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession platformAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [platformAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (platform storage parent) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates a restricted-decrypt ECC storage primary under the endorsement hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateEndorsementStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_ENDORSEMENT, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession endorsementAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [endorsementAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (endorsement storage parent) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates a powered-on simulator brought to the Operational phase with <c>TPM2_Startup(CLEAR)</c>.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The simulator (the caller owns it).</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-evictcontrol-range", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator to move it into <see cref="TpmLifecyclePhase.Operational"/>.</summary>
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
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_EvictControl, TpmResponseCodec.EvictControl);
        _ = registry.Register(TpmCcConstants.TPM_CC_ReadPublic, TpmResponseCodec.ReadPublic);

        return registry;
    }
}
