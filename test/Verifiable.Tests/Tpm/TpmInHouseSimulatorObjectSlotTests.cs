using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// The in-house behavioural <see cref="TpmSimulator"/>'s object-slot bound: every command that loads a transient
/// object — <c>TPM2_CreatePrimary()</c>, <c>TPM2_Load()</c>, <c>TPM2_SignSequenceStart()</c>,
/// <c>TPM2_VerifySequenceStart()</c> — takes one of <see cref="TpmSimulatorState.MaxLoadedObjects"/> RAM slots and,
/// once they are exhausted, answers <c>TPM_RC_OBJECT_MEMORY</c> until a flush, a hierarchy sweep, or a completing command frees one
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 1: Architecture, clauses 24.9, 27.4, 29.4.6, and 36.3.2; Part 2: Structures, clause
/// 6.13, Table 28; Part 3: Commands, clause 6.2, Table 3). Driven through the production command path (<see cref="TpmCommandExecutor"/> with the real inputs and
/// response codecs), in-process, with no external assets.
/// </summary>
/// <remarks>
/// The unauthorized allocators matter most here: both sequence-start commands have Auth Index None on
/// <c>keyHandle</c> (Part 3, clauses 17.5 and 17.6), so the slot bound is the only thing between a caller who
/// knows a public key handle and unbounded allocation.
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorObjectSlotTests
{
    /// <summary>A transient handle value naming no loaded object in a freshly-brought-operational simulator.</summary>
    private const uint ArbitraryUnknownHandle = 0x8000_0999;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// With one signing key loaded, <c>TPM2_SignSequenceStart()</c> — which needs no authorization at all — opens
    /// exactly <see cref="TpmSimulatorState.MaxLoadedObjects"/> − 1 sequences and the next Start is refused with
    /// <c>TPM_RC_OBJECT_MEMORY</c>: "When the TPM is out of object slots, it returns TPM_RC_OBJECT_MEMORY"
    /// (Part 1, clause 36.3.2).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceStartBeyondTheObjectSlotsReturnsObjectMemory()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        List<TpmiDhObject> sequences = await FillRemainingSlotsWithSequencesAsync(tpm, registry, pool, primary.ObjectHandle).ConfigureAwait(false);
        Assert.HasCount(TpmSimulatorState.MaxLoadedObjects - 1, sequences, "Every slot but the key's own must open a sequence.");

        TpmResult<SignSequenceStartResponse> overflow = await SubmitStartAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_OBJECT_MEMORY, overflow.ResponseCode, "The Start that would need a ninth slot must be refused with TPM_RC_OBJECT_MEMORY.");
    }

    /// <summary>
    /// <c>TPM2_FlushContext()</c> on one open sequence frees exactly one slot: the next Start succeeds and the
    /// one after it is refused again — "an object must be flushed from TPM memory" before the command can
    /// complete (Part 1, clause 27.4).
    /// </summary>
    [TestMethod]
    public async Task FlushingASequenceFreesExactlyOneSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        List<TpmiDhObject> sequences = await FillRemainingSlotsWithSequencesAsync(tpm, registry, pool, primary.ObjectHandle).ConfigureAwait(false);

        await FlushAsync(tpm, registry, pool, sequences[0].Value).ConfigureAwait(false);

        TpmResult<SignSequenceStartResponse> refilled = await SubmitStartAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        Assert.IsTrue(refilled.IsSuccess, $"The slot the flush freed must admit the next Start: '{refilled.ResponseCode}'.");

        TpmResult<SignSequenceStartResponse> overflow = await SubmitStartAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_OBJECT_MEMORY, overflow.ResponseCode, "One flush frees one slot, not more.");
    }

    /// <summary>
    /// <c>TPM2_VerifySequenceStart()</c> draws from the same slots as every other transient object: with the
    /// slots filled by signing sequences it is refused with <c>TPM_RC_OBJECT_MEMORY</c> (Part 1, clause 36.3.2;
    /// Part 3, clause 17.6).
    /// </summary>
    [TestMethod]
    public async Task VerifySequenceStartBeyondTheObjectSlotsReturnsObjectMemory()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        _ = await FillRemainingSlotsWithSequencesAsync(tpm, registry, pool, primary.ObjectHandle).ConfigureAwait(false);

        using VerifySequenceStartInput input = VerifySequenceStartInput.Create(primary.ObjectHandle, [], pool);
        TpmResult<VerifySequenceStartResponse> overflow = await TpmCommandExecutor.ExecuteAsync<VerifySequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_OBJECT_MEMORY, overflow.ResponseCode, "A verification sequence needs a slot exactly as a signing sequence does.");
    }

    /// <summary>
    /// <c>TPM2_CreatePrimary()</c> — the authorized allocator — is refused with <c>TPM_RC_OBJECT_MEMORY</c> once
    /// unauthorized sequences hold every slot: "When a Primary Object is created, it is also loaded in a TPM
    /// object slot ... If no free object slot is available, the TPM will return TPM_RC_OBJECT_MEMORY" (Part 1,
    /// clause 24.9).
    /// </summary>
    [TestMethod]
    public async Task CreatePrimaryBeyondTheObjectSlotsReturnsObjectMemory()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        _ = await FillRemainingSlotsWithSequencesAsync(tpm, registry, pool, primary.ObjectHandle).ConfigureAwait(false);

        TpmResult<CreatePrimaryResponse> overflow = await SubmitCreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_OBJECT_MEMORY, overflow.ResponseCode, "A primary needs a slot to be loaded into.");
    }

    /// <summary>
    /// <c>TPM2_Create()</c> takes no slot (the object is returned, not loaded) while <c>TPM2_Load()</c> takes one:
    /// with the slots full the load is refused with <c>TPM_RC_OBJECT_MEMORY</c>, and once a sequence is flushed the
    /// same blob loads — and the loaded sealed object then holds the slot it took, so the next Start is refused
    /// (Part 1, clauses 27.4 and 36.3.2; Part 3, clauses 12.1 and 12.2).
    /// </summary>
    [TestMethod]
    public async Task LoadBeyondTheObjectSlotsReturnsObjectMemoryAndALoadedObjectHoldsItsSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreatePrimaryResponse signer = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreateResponse sealedObject = await CreateSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle).ConfigureAwait(false);
        List<TpmiDhObject> sequences = await FillRemainingSlotsWithSequencesAsync(tpm, registry, pool, signer.ObjectHandle).ConfigureAwait(false);
        Assert.HasCount(TpmSimulatorState.MaxLoadedObjects - 2, sequences, "TPM2_Create() must not have taken a slot: only the two primaries did.");

        TpmResult<LoadResponse> refused = await SubmitLoadAsync(tpm, registry, pool, parent.ObjectHandle, sealedObject).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_OBJECT_MEMORY, refused.ResponseCode, "TPM2_Load() needs a slot for the loaded object.");

        await FlushAsync(tpm, registry, pool, sequences[0].Value).ConfigureAwait(false);

        TpmResult<LoadResponse> loaded = await SubmitLoadAsync(tpm, registry, pool, parent.ObjectHandle, sealedObject).ConfigureAwait(false);
        Assert.IsTrue(loaded.IsSuccess, $"The same blob must load once a slot is free: '{loaded.ResponseCode}'.");
        loaded.Value.Dispose();

        TpmResult<SignSequenceStartResponse> overflow = await SubmitStartAsync(tpm, registry, pool, signer.ObjectHandle, []).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_OBJECT_MEMORY, overflow.ResponseCode, "The loaded sealed object occupies the slot the flush freed.");
    }

    /// <summary>
    /// The slot is the LAST thing an allocating command claims — a real TPM allocates it inside the command's
    /// own actions, after every handle and parameter check — so with the slots full an unloaded transient-range
    /// <c>keyHandle</c> still answers <c>TPM_RC_REFERENCE_H0</c> and a non-signing key still answers
    /// <c>TPM_RC_KEY</c>, never <c>TPM_RC_OBJECT_MEMORY</c> (Part 3, clause 5.4, step 2.1; clause 17.5).
    /// </summary>
    [TestMethod]
    public async Task TheSlotGateIsDecidedAfterEveryOtherRefusal()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreatePrimaryResponse signer = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        _ = await FillRemainingSlotsWithSequencesAsync(tpm, registry, pool, signer.ObjectHandle).ConfigureAwait(false);

        TpmResult<SignSequenceStartResponse> unknown = await SubmitStartAsync(tpm, registry, pool, TpmiDhObject.FromValue(ArbitraryUnknownHandle), []).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H0, unknown.ResponseCode, "Handle resolution precedes the slot gate.");

        TpmResult<SignSequenceStartResponse> nonSigning = await SubmitStartAsync(tpm, registry, pool, parent.ObjectHandle, []).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_KEY, 0), nonSigning.ResponseCode, "The key-attribute gate precedes the slot gate.");

        TpmResult<SignSequenceStartResponse> full = await SubmitStartAsync(tpm, registry, pool, signer.ObjectHandle, []).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_OBJECT_MEMORY, full.ResponseCode, "Only a Start that passes every other gate reaches the slot gate.");
    }

    /// <summary>
    /// A TPM Reset (<c>TPM2_Shutdown(CLEAR)</c>, <c>_TPM_Init</c>, <c>TPM2_Startup(CLEAR)</c>) empties every
    /// slot: the sequences and the key are gone, and a fresh primary loads — "An object context is only removed
    /// from TPM memory with TPM2_FlushContext(), deletion of the associated hierarchy seed, or TPM2_Startup()"
    /// (Part 1, clause 27.4).
    /// </summary>
    [TestMethod]
    public async Task ATpmResetFreesEverySlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        _ = await FillRemainingSlotsWithSequencesAsync(tpm, registry, pool, primary.ObjectHandle).ConfigureAwait(false);

        await IssueShutdownClearAsync(simulator, pool).ConfigureAwait(false);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        using CreatePrimaryResponse afterReset = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        List<TpmiDhObject> sequences = await FillRemainingSlotsWithSequencesAsync(tpm, registry, pool, afterReset.ObjectHandle).ConfigureAwait(false);
        Assert.HasCount(TpmSimulatorState.MaxLoadedObjects - 1, sequences, "Every slot must be free again after the Reset.");
    }

    /// <summary>
    /// A <c>TPM2_SignSequenceStart()</c> refused for want of a slot returns its parsed, non-empty <c>auth</c>
    /// carrier to the pool: the refusal is decided after the parse rented it, so the balance must come back to
    /// exactly where it stood before the attempt (Part 3, clause 17.5).
    /// </summary>
    [TestMethod]
    public async Task SignSequenceStartRefusedForWantOfASlotReturnsTheParsedCarriersToPool()
    {
        using var housePool = new MeteredHousePool();
        BaseMemoryPool pool = housePool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        _ = await FillRemainingSlotsWithSequencesAsync(tpm, registry, pool, primary.ObjectHandle).ConfigureAwait(false);
        long baseline = housePool.OutstandingCount;
        long rentedBefore = housePool.RentedCount;

        TpmResult<SignSequenceStartResponse> overflow = await SubmitStartAsync(tpm, registry, pool, primary.ObjectHandle, "slot-refused-sequence-auth"u8.ToArray()).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_OBJECT_MEMORY, overflow.ResponseCode, "The Start must be refused for want of a slot.");

        Assert.IsGreaterThan(rentedBefore, housePool.RentedCount, "The refused command must have rented its auth carrier at parse — otherwise the balance below proves nothing.");
        Assert.AreEqual(baseline, housePool.OutstandingCount, "A slot-refused TPM2_SignSequenceStart() must return its parsed auth carrier to the pool.");
    }

    /// <summary>
    /// A successful <c>TPM2_SignSequenceComplete()</c> flushes its sequence (<c>{F}</c>, Part 3, clause 20.6;
    /// Part 1, clause 29.4.6: "the sequence context is flushed from the TPM") and so frees exactly its slot: with
    /// the slots full, completing one sequence admits one more Start and no more.
    /// </summary>
    [TestMethod]
    public async Task ASuccessfulSignSequenceCompleteFreesExactlyItsSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        List<TpmiDhObject> sequences = await FillRemainingSlotsWithSequencesAsync(tpm, registry, pool, primary.ObjectHandle).ConfigureAwait(false);

        using SignSequenceCompleteInput completeInput = SignSequenceCompleteInput.Create(sequences[0], primary.ObjectHandle, "the whole message"u8.ToArray(), pool);
        using TpmPasswordSession sequenceSession = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession keySession = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<SignSequenceCompleteResponse> completed = await TpmCommandExecutor.ExecuteAsync<SignSequenceCompleteResponse>(
            tpm, completeInput, [sequenceSession, keySession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(completed.IsSuccess, $"TPM2_SignSequenceComplete() failed: '{completed.ResponseCode}'.");
        completed.Value.Dispose();

        TpmResult<SignSequenceStartResponse> refilled = await SubmitStartAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        Assert.IsTrue(refilled.IsSuccess, $"The slot the completed sequence released must admit the next Start: '{refilled.ResponseCode}'.");

        TpmResult<SignSequenceStartResponse> overflow = await SubmitStartAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_OBJECT_MEMORY, overflow.ResponseCode, "A completion frees one slot, not more.");
    }

    /// <summary>
    /// <c>TPM2_Clear()</c> flushes the storage hierarchy's transient key and frees its slot, while the open
    /// sequences — NULL-hierarchy objects (Part 1, clause 27.2.4) — keep theirs: after the clear exactly one
    /// slot is free, taken by a fresh primary, and the Start after that is refused (Part 1, clause 27.4: "all
    /// objects associated with that hierarchy are flushed from TPM memory"; Part 3, clause 24.6).
    /// </summary>
    [TestMethod]
    public async Task ClearFreesTheStorageHierarchyKeySlotAndLeavesTheSequencesInPlace()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        _ = await FillRemainingSlotsWithSequencesAsync(tpm, registry, pool, primary.ObjectHandle).ConfigureAwait(false);

        await ClearAsync(tpm, registry, pool).ConfigureAwait(false);

        using CreatePrimaryResponse afterClear = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<SignSequenceStartResponse> overflow = await SubmitStartAsync(tpm, registry, pool, afterClear.ObjectHandle, []).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_OBJECT_MEMORY, overflow.ResponseCode, "The clear freed the key's slot only: the NULL-hierarchy sequences survive it and still hold theirs.");
    }

    /// <summary>
    /// A loaded sealed data object belongs to the hierarchy of the Storage Parent it was loaded under — "the
    /// ancestors of an object are the parent keys that connect the object to a TPM Primary Seed" (Part 1, clause
    /// 20.2) — so <c>TPM2_Clear()</c>, which flushes "resident objects (persistent and volatile) in the Storage and
    /// Endorsement hierarchies" (Part 3, clause 24.6.1), evicts it beside the parent and the signing key: exactly
    /// the three owner-hierarchy slots come free, the sealed handle no longer names anything, and the
    /// NULL-hierarchy sequences keep theirs (Part 1, clauses 27.2.4 and 27.4).
    /// </summary>
    [TestMethod]
    public async Task ClearFreesALoadedSealedObjectsSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreatePrimaryResponse signer = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreateResponse sealedObject = await CreateSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle).ConfigureAwait(false);
        TpmiDhObject sealedHandle = await LoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle, sealedObject).ConfigureAwait(false);
        _ = await FillRemainingSlotsWithSequencesAsync(tpm, registry, pool, signer.ObjectHandle).ConfigureAwait(false);
        Assert.AreEqual(0u, await ReadPropertyAsync(tpm, registry, pool, TpmPtConstants.TPM_PT_HR_TRANSIENT_AVAIL).ConfigureAwait(false), "Premise: no slot is free before the clear.");

        await ClearAsync(tpm, registry, pool).ConfigureAwait(false);

        Assert.AreEqual(3u, await ReadPropertyAsync(tpm, registry, pool, TpmPtConstants.TPM_PT_HR_TRANSIENT_AVAIL).ConfigureAwait(false), "The clear frees the parent's, the signer's, and the sealed object's slots — and only those three.");
        TpmResult<FlushContextResponse> flushed = await SubmitFlushAsync(tpm, registry, pool, sealedHandle.Value).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), flushed.ResponseCode, "The sealed object's handle names nothing after the clear.");
    }

    /// <summary>
    /// <c>TPM2_HierarchyControl()</c> disabling the storage hierarchy "will flush any transient objects associated
    /// with the disabled hierarchy" (Part 3, clause 24.2.1), and a loaded sealed data object is associated with its
    /// Storage Parent's hierarchy (Part 1, clause 20.2): exactly the three owner-hierarchy slots come free and the
    /// sealed handle no longer names anything, while the NULL-hierarchy sequences — which no enable governs —
    /// keep theirs (Part 1, clause 27.2.4).
    /// </summary>
    [TestMethod]
    public async Task DisablingTheStorageHierarchyFreesALoadedSealedObjectsSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreatePrimaryResponse signer = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreateResponse sealedObject = await CreateSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle).ConfigureAwait(false);
        TpmiDhObject sealedHandle = await LoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle, sealedObject).ConfigureAwait(false);
        _ = await FillRemainingSlotsWithSequencesAsync(tpm, registry, pool, signer.ObjectHandle).ConfigureAwait(false);
        Assert.AreEqual(0u, await ReadPropertyAsync(tpm, registry, pool, TpmPtConstants.TPM_PT_HR_TRANSIENT_AVAIL).ConfigureAwait(false), "Premise: no slot is free before the hierarchy is disabled.");

        await DisableHierarchyAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        Assert.AreEqual(3u, await ReadPropertyAsync(tpm, registry, pool, TpmPtConstants.TPM_PT_HR_TRANSIENT_AVAIL).ConfigureAwait(false), "Disabling the storage hierarchy frees the parent's, the signer's, and the sealed object's slots — and only those three.");
        TpmResult<FlushContextResponse> flushed = await SubmitFlushAsync(tpm, registry, pool, sealedHandle.Value).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), flushed.ResponseCode, "The sealed object's handle names nothing once its hierarchy is disabled.");
    }

    /// <summary>
    /// The sweep is by hierarchy, not blanket: disabling the endorsement hierarchy leaves an owner-hierarchy
    /// sealed object loaded — no slot comes free, and the object still flushes by handle — because only
    /// "transient objects associated with the disabled hierarchy" are flushed (Part 3, clause 24.2.1).
    /// </summary>
    [TestMethod]
    public async Task DisablingAnotherHierarchyLeavesTheLoadedSealedObjectInPlace()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreatePrimaryResponse signer = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreateResponse sealedObject = await CreateSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle).ConfigureAwait(false);
        TpmiDhObject sealedHandle = await LoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle, sealedObject).ConfigureAwait(false);
        _ = await FillRemainingSlotsWithSequencesAsync(tpm, registry, pool, signer.ObjectHandle).ConfigureAwait(false);

        await DisableHierarchyAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        Assert.AreEqual(0u, await ReadPropertyAsync(tpm, registry, pool, TpmPtConstants.TPM_PT_HR_TRANSIENT_AVAIL).ConfigureAwait(false), "Disabling the endorsement hierarchy touches no owner-hierarchy object.");
        await FlushAsync(tpm, registry, pool, sealedHandle.Value).ConfigureAwait(false);
        Assert.AreEqual(1u, await ReadPropertyAsync(tpm, registry, pool, TpmPtConstants.TPM_PT_HR_TRANSIENT_AVAIL).ConfigureAwait(false), "The sealed object held its slot until flushed by handle.");
    }

    /// <summary>
    /// <c>TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES)</c> reports the bound and the headroom: <c>TPM_PT_HR_TRANSIENT_MIN</c>
    /// is the slot count ("the minimum number of transient objects that can be held in TPM RAM") and
    /// <c>TPM_PT_HR_TRANSIENT_AVAIL</c> the free slots ("If this value is at least 1, then at least one object of
    /// any type may be loaded"), falling to zero exactly when the next Start is refused (Part 2, clause 6.13, Table 28).
    /// </summary>
    [TestMethod]
    public async Task GetCapabilityReportsTheSlotBoundAndTheFreeSlots()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        Assert.AreEqual((uint)TpmSimulatorState.MaxLoadedObjects, await ReadPropertyAsync(tpm, registry, pool, TpmPtConstants.TPM_PT_HR_TRANSIENT_MIN).ConfigureAwait(false), "TPM_PT_HR_TRANSIENT_MIN is the slot count.");
        Assert.AreEqual((uint)TpmSimulatorState.MaxLoadedObjects, await ReadPropertyAsync(tpm, registry, pool, TpmPtConstants.TPM_PT_HR_TRANSIENT_AVAIL).ConfigureAwait(false), "An empty TPM has every slot free.");

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.AreEqual((uint)(TpmSimulatorState.MaxLoadedObjects - 1), await ReadPropertyAsync(tpm, registry, pool, TpmPtConstants.TPM_PT_HR_TRANSIENT_AVAIL).ConfigureAwait(false), "The primary took one slot.");

        _ = await FillRemainingSlotsWithSequencesAsync(tpm, registry, pool, primary.ObjectHandle).ConfigureAwait(false);
        Assert.AreEqual(0u, await ReadPropertyAsync(tpm, registry, pool, TpmPtConstants.TPM_PT_HR_TRANSIENT_AVAIL).ConfigureAwait(false), "No slot is free once the Starts are refused.");

        TpmResult<SignSequenceStartResponse> overflow = await SubmitStartAsync(tpm, registry, pool, primary.ObjectHandle, []).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_OBJECT_MEMORY, overflow.ResponseCode, "Zero free slots reported means the next allocating command is refused.");
    }

    /// <summary>
    /// Opens signing sequences under <paramref name="keyHandle"/> until the slots are full, returning every
    /// handle opened, asserting each Start up to the bound succeeds.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The signing key to start the sequences under.</param>
    /// <returns>The handles of the sequences opened, in order.</returns>
    private async Task<List<TpmiDhObject>> FillRemainingSlotsWithSequencesAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle)
    {
        var sequences = new List<TpmiDhObject>();
        for(int i = 0; i < TpmSimulatorState.MaxLoadedObjects; i++)
        {
            TpmResult<SignSequenceStartResponse> result = await SubmitStartAsync(tpm, registry, pool, keyHandle, []).ConfigureAwait(false);
            if(!result.IsSuccess && result.ResponseCode == TpmRcConstants.TPM_RC_OBJECT_MEMORY)
            {
                break;
            }

            Assert.IsTrue(result.IsSuccess, $"TPM2_SignSequenceStart() number {i + 1} failed: '{result.ResponseCode}'.");
            SignSequenceStartResponse started = result.Value;
            sequences.Add(started.SequenceHandle);
        }

        return sequences;
    }

    /// <summary>
    /// Submits <see cref="SignSequenceStartInput.Create"/> with no session (Auth Index None) and returns the raw result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The candidate signing key handle.</param>
    /// <param name="sequenceAuth">The sequence's own authValue.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<SignSequenceStartResponse>> SubmitStartAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] sequenceAuth)
    {
        using SignSequenceStartInput input = SignSequenceStartInput.Create(keyHandle, sequenceAuth, pool);

        return await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads one <c>TPM_CAP_TPM_PROPERTIES</c> property's value via <c>TPM2_GetCapability()</c>, asserting the window starts at it.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="property">The property to read.</param>
    /// <returns>The property's value.</returns>
    private async Task<uint> ReadPropertyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint property)
    {
        TpmResult<GetCapabilityResponse> result = await TpmCommandExecutor.ExecuteAsync<GetCapabilityResponse>(
            tpm, GetCapabilityInput.ForTpmProperties(property, count: 1), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_GetCapability() failed: '{result.ResponseCode}'.");

        using GetCapabilityResponse response = result.Value;
        var properties = response.CapabilityData.TpmProperties;
        Assert.IsNotNull(properties);
        Assert.HasCount(1, properties);
        Assert.AreEqual(property, properties[0].Property, "The window must start at the requested property.");

        return properties[0].Value;
    }

    /// <summary>Flushes <paramref name="handle"/> via <c>TPM2_FlushContext()</c>, asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The transient handle to flush.</param>
    private async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        TpmResult<FlushContextResponse> result = await SubmitFlushAsync(tpm, registry, pool, handle).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_FlushContext() failed: '{result.ResponseCode}'.");
    }

    /// <summary>Submits <c>TPM2_FlushContext()</c> for <paramref name="handle"/> and returns the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The transient handle to flush.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<FlushContextResponse>> SubmitFlushAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        FlushContextInput flushInput = FlushContextInput.ForHandle(handle);

        return await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flushInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues <c>TPM2_Clear()</c> under the empty-password lockout authorization, asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task ClearAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        var clearInput = new ClearInput(TpmRh.TPM_RH_LOCKOUT);
        using TpmPasswordSession lockoutAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ClearResponse> result = await TpmCommandExecutor.ExecuteAsync<ClearResponse>(
            tpm, clearInput, [lockoutAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_Clear() failed: '{result.ResponseCode}'.");
    }

    /// <summary>CLEARs <paramref name="enable"/> via <c>TPM2_HierarchyControl()</c> under the empty-password platform authorization, asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="enable">The hierarchy enable to CLEAR.</param>
    private async Task DisableHierarchyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh enable)
    {
        var input = new HierarchyControlInput(TpmRh.TPM_RH_PLATFORM, enable, TpmiYesNo.No);
        using TpmPasswordSession platformAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<HierarchyControlResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyControlResponse>(
            tpm, input, [platformAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HierarchyControl() failed: '{result.ResponseCode}'.");
    }

    /// <summary>Submits an unrestricted, empty-password ECC P-256 signing primary under the owner hierarchy and returns the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<CreatePrimaryResponse>> SubmitCreateEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        return await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates an unrestricted, empty-password ECC P-256 signing primary under the owner hierarchy, asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        TpmResult<CreatePrimaryResponse> result = await SubmitCreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates an empty-password ECC storage parent under the owner hierarchy, asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary storage parent failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Seals a small datum under <paramref name="parentHandle"/> via <c>TPM2_Create()</c> — returned, not loaded — asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent.</param>
    /// <returns>The Create response (the caller owns it).</returns>
    private async Task<CreateResponse> CreateSealedObjectAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject parentHandle)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData("slot-bound sealed datum"u8.ToArray(), pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true);
        using CreateInput createInput = new(parentHandle.Value, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"Create (seal) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Submits <c>TPM2_Load()</c> of <paramref name="sealedObject"/> under <paramref name="parentHandle"/> and returns the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent.</param>
    /// <param name="sealedObject">The Create response carrying the blob to load.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<LoadResponse>> SubmitLoadAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject parentHandle, CreateResponse sealedObject)
    {
        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
        using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, pool);
        using LoadInput loadInput = new(parentHandle.Value, inPrivate, inPublic);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);

        return await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Loads <paramref name="sealedObject"/> under <paramref name="parentHandle"/> via <c>TPM2_Load()</c>, asserting success, and returns the loaded object's transient handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent.</param>
    /// <param name="sealedObject">The Create response carrying the blob to load.</param>
    /// <returns>The loaded object's handle.</returns>
    private async Task<TpmiDhObject> LoadSealedObjectAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject parentHandle, CreateResponse sealedObject)
    {
        TpmResult<LoadResponse> result = await SubmitLoadAsync(tpm, registry, pool, parentHandle, sealedObject).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_Load() failed: '{result.ResponseCode}'.");
        using LoadResponse loaded = result.Value;

        return loaded.ObjectHandle;
    }

    /// <summary>
    /// Persist-then-reload a public area through wire bytes only — the disk round-trip a real deployment
    /// performs — yielding an independently-owned copy rather than aliasing <paramref name="source"/>'s own storage.
    /// </summary>
    /// <param name="source">The public area to clone.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The cloned public area; the caller owns and disposes it.</returns>
    private static Tpm2bPublic ClonePublic(Tpm2bPublic source, BaseMemoryPool pool)
    {
        int size = source.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        source.WriteTo(ref writer);

        var reader = new TpmReader(owner.Memory.Span[..size]);

        return Tpm2bPublic.Parse(ref reader, pool);
    }

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySequenceStart, TpmResponseCodec.VerifySequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceComplete, TpmResponseCodec.SignSequenceComplete);
        _ = registry.Register(TpmCcConstants.TPM_CC_Clear, TpmResponseCodec.Clear);
        _ = registry.Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);

        return registry;
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-object-slots", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        await SubmitUnauthorizedAsync(simulator, pool, input, "TPM2_Startup(CLEAR)").ConfigureAwait(false);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    /// <summary>Issues <c>TPM2_Shutdown(CLEAR)</c> directly against the simulator, asserting success.</summary>
    /// <param name="simulator">The simulator to shut down.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task IssueShutdownClearAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new ShutdownInput(TpmSuConstants.TPM_SU_CLEAR);
        await SubmitUnauthorizedAsync(simulator, pool, input, "TPM2_Shutdown(CLEAR)").ConfigureAwait(false);
    }

    /// <summary>Frames an unauthorized (<c>TPM_ST_NO_SESSIONS</c>) command straight to the simulator and asserts <c>TPM_RC_SUCCESS</c>.</summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="input">The command input to frame.</param>
    /// <param name="commandName">The command's name for the assertion message.</param>
    private async Task SubmitUnauthorizedAsync(TpmSimulator simulator, BaseMemoryPool pool, ITpmCommandInput input, string commandName)
    {
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"{commandName} must succeed at the transport level.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, $"{commandName} must succeed.");
    }
}
