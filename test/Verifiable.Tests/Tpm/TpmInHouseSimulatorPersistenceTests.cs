using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Hierarchy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the object/NV provisioning teardown lifecycle against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the production command
/// path (<see cref="TpmCommandExecutor"/> with the real inputs and response codecs): persisting and evicting a
/// key with <c>TPM2_EvictControl</c>, and defining then removing an NV Index with <c>TPM2_NV_UndefineSpace</c>.
/// These are the persistence and reclamation operations a real EK/AK provisioning flow uses.
/// </summary>
/// <remarks>
/// Because the in-house simulator starts from a clean, deterministic state on every run (no persistent external
/// process), each test additionally asserts the negative outcome — re-evicting or undefining a now-absent handle
/// returns <c>TPM_RC_HANDLE</c> — which a persistent external simulator could only pre-clean and ignore.
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorPersistenceTests
{
    /// <summary>The owner-hierarchy persistent handle (range 0x81000000-0x817FFFFF) used to persist the test key.</summary>
    private const uint PersistentHandle = 0x8100_0010;

    /// <summary>The NV Index handle used by the undefine test (MSO 0x01 = TPM_HT_NV_INDEX).</summary>
    private const uint NvIndexHandle = 0x0100_0011;

    /// <summary>The owner hierarchy's authorization value after the auth-verification tests rotate it away from the Empty Buffer.</summary>
    private static byte[] OwnerAuthBytes { get; } = [0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F];

    /// <summary>A value that never authorizes the owner hierarchy in this file, distinct from <see cref="OwnerAuthBytes"/>.</summary>
    private static byte[] WrongOwnerAuthBytes { get; } = [0xF1, 0xE2, 0xD3, 0xC4];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task EvictControlPersistsAndEvictsAKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        //Persist the transient key to the fixed persistent handle.
        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, primary.ObjectHandle.Value, PersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        //Evict it. A successful eviction proves a persistent object existed at the handle — i.e. the persist took
        //effect.
        TpmResult<EvictControlResponse> evictResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, PersistentHandle, PersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(evictResult.IsSuccess, $"EvictControl (evict) failed: '{evictResult.ResponseCode}'.");

        //Evicting the now-absent persistent handle must fail with TPM_RC_HANDLE.
        TpmResult<EvictControlResponse> reEvictResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, PersistentHandle, PersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), reEvictResult.ResponseCode, "Evicting an already-evicted handle must fail with TPM_RC_HANDLE at objectHandle, handle 2 of the EvictControl command table.");
    }

    /// <summary>
    /// <c>TPM2_EvictControl</c>'s @auth slot (<c>TPMI_RH_PROVISION</c>, Auth Role USER; TPM 2.0 Library Part
    /// 3, clause 4.2.10) is verified against the named provisioning hierarchy's own authorization value through
    /// the house hierarchy-authorization ladder: after <c>TPM2_HierarchyChangeAuth</c> installs a real owner
    /// password, a WRONG password is refused with <c>TPM_RC_BAD_AUTH</c> at the authorizing session, session 1
    /// of <c>TPM2_EvictControl</c>'s own command table (Part 2, clause 6.6.2, Table 15) - never a
    /// dictionary-attack strike, because the owner hierarchy carries no such protection (Part 1, clause
    /// 16.8.1) - while the CORRECT password persists the transient key, and a second correctly-authorized call
    /// evicts it.
    /// </summary>
    [TestMethod]
    public async Task EvictControlVerifiesTheOwnerAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        //CreatePrimary is itself resolved under TPM_RH_OWNER (TPM 2.0 Library Part 3, clause 5.6), so the
        //primary is minted while ownerAuth is still the Empty Buffer, and only then rotated away from it -
        //otherwise CreateSigningPrimaryAsync's own empty-password session would no longer authorize.
        using CreatePrimaryResponse primary = await CreateSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<HierarchyChangeAuthResponse> rotation = await tpm.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, OwnerAuthBytes, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(rotation.IsSuccess, $"Rotating the owner authorization value away from the Empty Buffer failed: '{rotation.ResponseCode}'.");

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmResult<EvictControlResponse> wrongAuthResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, primary.ObjectHandle.Value, PersistentHandle, auth: WrongOwnerAuthBytes, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(wrongAuthResult.IsSuccess, "A wrong owner password must not persist the object.");
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), wrongAuthResult.ResponseCode,
            "The owner hierarchy is a dictionary-attack-exempt permanent entity, so a wrong password fails the owner authorization, session 1 of TPM2_EvictControl's own command table.");

        TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter, afterWrong.Value.LockoutCounter,
            "A wrong owner password must never charge the dictionary-attack counter (TPM 2.0 Library Part 1, clause 16.8.1 exempts permanent entities).");

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, primary.ObjectHandle.Value, PersistentHandle, auth: OwnerAuthBytes, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) with the correct owner password failed: '{persistResult.ResponseCode}'.");

        TpmResult<EvictControlResponse> evictResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, PersistentHandle, PersistentHandle, auth: OwnerAuthBytes, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(evictResult.IsSuccess, $"EvictControl (evict) with the correct owner password failed: '{evictResult.ResponseCode}'.");
    }

    /// <summary>
    /// <c>TPM2_EvictControl</c>'s @auth slot is typed <c>TPMI_RH_PROVISION</c> (TPM 2.0 Library Part 2,
    /// clause 9.21), which admits only the owner and platform hierarchies. A handle outside that interface -
    /// the endorsement hierarchy, still carrying its factory-state Empty Buffer authorization value - never
    /// reaches the hierarchy-authorization ladder at all and is refused with <c>TPM_RC_VALUE</c> at the
    /// handle-typing gate, before any object handle or password is examined.
    /// </summary>
    [TestMethod]
    public async Task EvictControlRejectsANonProvisionAuthHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<EvictControlResponse> result = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, PersistentHandle, PersistentHandle, authHandle: TpmRh.TPM_RH_ENDORSEMENT, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A non-provision auth handle must not be admitted.");
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), result.ResponseCode,
            "TPMI_RH_PROVISION admits only the owner and platform hierarchies (TPM 2.0 Library Part 2, clause 9.21); the endorsement hierarchy is refused with TPM_RC_VALUE ahead of the authorization ladder.");
    }

    /// <summary>
    /// <c>TPM2_EvictControl</c> validates the presence of <c>objectHandle</c> before checking the supplied
    /// authorization (TPM 2.0 Library Part 3, clauses 5.4 and 5.6): with a real owner password installed, a
    /// request naming an object handle nothing is loaded or persisted at answers <c>TPM_RC_HANDLE</c> even
    /// though the supplied owner password is wrong — the handle-area refusal, not <c>TPM_RC_BAD_AUTH</c>.
    /// </summary>
    [TestMethod]
    public async Task EvictControlResolvesTheObjectHandleBeforeTheOwnerAuthCompare()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<HierarchyChangeAuthResponse> rotation = await tpm.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, OwnerAuthBytes, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(rotation.IsSuccess, $"Rotating the owner authorization value away from the Empty Buffer failed: '{rotation.ResponseCode}'.");

        TpmResult<EvictControlResponse> result = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, PersistentHandle, PersistentHandle, auth: WrongOwnerAuthBytes, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), result.ResponseCode,
            "An object handle with nothing loaded or persisted at it is refused at objectHandle, handle 2 of the EvictControl command table (TPM 2.0 Library Part 3, clause 5.4), ahead of the authorization compare.");
    }

    /// <summary>
    /// The authorizing hierarchy's availability is resolved as a handle-area outcome on @auth, ahead of the
    /// next handle's presence (TPM 2.0 Library Part 3, clause 5.4): with the owner hierarchy disabled — which
    /// also flushes its transient objects — a request naming an absent object handle answers
    /// <c>TPM_RC_HIERARCHY</c> (a disabled hierarchy's authValue can authorize nothing, Part 1, clause 10.2),
    /// not the <c>TPM_RC_HANDLE</c> the presence probe would give.
    /// </summary>
    [TestMethod]
    public async Task EvictControlUnderADisabledOwnerHierarchyAnswersHierarchy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<HierarchyControlResponse> disableResult = await tpm.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_OWNER, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(disableResult.IsSuccess, $"Disabling the owner hierarchy failed: '{disableResult.ResponseCode}'.");

        TpmResult<EvictControlResponse> result = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, PersistentHandle, PersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), result.ResponseCode,
            "A disabled authorizing hierarchy is refused as a handle-area availability outcome (TPM 2.0 Library Part 3, clause 5.4), ahead of the object handle's presence probe.");
    }

    [TestMethod]
    public async Task NvUndefineSpaceFreesTheIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<NvDefineSpaceResponse> defineResult = await DefineIndexAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");

        TpmResult<NvUndefineSpaceResponse> undefineResult = await UndefineAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(undefineResult.IsSuccess, $"NV_UndefineSpace failed: '{undefineResult.ResponseCode}'.");

        //Re-defining the same handle proves the previous definition was removed and the handle freed.
        TpmResult<NvDefineSpaceResponse> redefineResult = await DefineIndexAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(redefineResult.IsSuccess, $"NV_DefineSpace after undefine failed: '{redefineResult.ResponseCode}'.");

        //Undefining a handle that was never defined must fail with TPM_RC_HANDLE.
        TpmResult<NvUndefineSpaceResponse> undefineUnknown = await UndefineAsync(tpm, registry, pool, NvIndexHandle + 1).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), undefineUnknown.ResponseCode, "Undefining an unknown NV Index must fail with TPM_RC_HANDLE.");
    }

    /// <summary>
    /// The same handle-order convention <see cref="EvictControlUnderADisabledOwnerHierarchyAnswersHierarchy"/>
    /// pins for <c>TPM2_EvictControl()</c> now governs <c>TPM2_NV_UndefineSpace()</c> too: Part 3, clause 5.4
    /// permits handle checks in any order, and the simulator resolves the authorizing hierarchy's own
    /// handle-area outcomes — admit, then enable — before probing the next handle's presence, the same
    /// convention <c>TPM2_EvictControl()</c> holds. With the owner hierarchy disabled, a request naming an
    /// unknown NV Index handle answers <c>TPM_RC_HIERARCHY</c> (a disabled hierarchy's authValue can authorize
    /// nothing, Part 1, clause 10.2), not the <c>TPM_RC_HANDLE</c> the Index presence probe alone would give.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceUnderADisabledOwnerHierarchyAnswersHierarchy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<HierarchyControlResponse> disableResult = await tpm.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_OWNER, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(disableResult.IsSuccess, $"Disabling the owner hierarchy failed: '{disableResult.ResponseCode}'.");

        TpmResult<NvUndefineSpaceResponse> result = await UndefineAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), result.ResponseCode,
            "A disabled authorizing hierarchy is refused as a handle-area availability outcome (TPM 2.0 Library Part 3, clause 5.4), ahead of the NV Index handle's presence probe.");
    }

    /// <summary>
    /// <see cref="NvUndefineSpaceUnderADisabledOwnerHierarchyAnswersHierarchy"/>'s handle-order pin replayed
    /// over an HMAC session rather than a password session: the session form resolves the
    /// identical handle-area ladder — @authHandle's admit, then enable, then the Index handle's presence —
    /// ahead of the session area and its authorization checks (Part 3, clause 5.4 requires the handle area
    /// before the authorization checks, and permits any order within it), and so before it ever declares the
    /// Name-computation action a genuine command HMAC needs. With the owner hierarchy disabled, an unknown
    /// Index handle therefore answers <c>TPM_RC_HIERARCHY</c> without ever reaching the point where the
    /// Index's real Name — and so the command HMAC's own correctness — would matter. The session is started,
    /// and bound, while the owner hierarchy is still enabled; disabling a hierarchy flushes only its transient
    /// objects (never a session already bound to it), so the started session remains a live authorizer for the
    /// command under test.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceOverHmacUnderADisabledOwnerHierarchyAnswersHierarchy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistryWithSessionSupport();

        (uint sessionHandle, TpmSession session) = await StartOwnerBoundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            using(session)
            {
                TpmResult<HierarchyControlResponse> disableResult = await tpm.DisableHierarchyWithPasswordAsync(
                    TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_OWNER, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(disableResult.IsSuccess, $"Disabling the owner hierarchy failed: '{disableResult.ResponseCode}'.");

                //The rejection below is decided before the Index's Name is ever computed, so this placeholder
                //never has to carry the Index's genuine Name (TPM 2.0 Library Part 1, clause 15.7) - it only
                //has to be non-empty, satisfying the executor's requirement that a named handle supply one.
                ReadOnlyMemory<byte>[] handleNames = [ReadOnlyMemory<byte>.Empty, new byte[] { 0x00 }];
                var input = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, NvIndexHandle);

                TpmResult<NvUndefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
                    tpm, input, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), result.ResponseCode,
                    "The HMAC-session arm resolves the disabled authorizing hierarchy ahead of the NV Index handle's presence, exactly as the password arm does (TPM 2.0 Library Part 3, clause 5.4).");
            }
        }
        finally
        {
            await FlushSessionAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// TPM2_NV_UndefineSpace()'s session form resolves the whole handle area before any session work at all
    /// (TPM 2.0 Library Part 3, clause 5.4: handle-area validation is required before the authorization
    /// checks): a request naming an unknown NV Index handle over a session handle the simulator has never
    /// issued answers the Index handle's <c>TPM_RC_HANDLE</c>, not a session-area outcome — the presence
    /// probe fires before the authorizing session is even looked up.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the fabricated nonceTPM transfers to the TpmSession constructor, which the using-disposed session disposes.")]
    public async Task NvUndefineSpaceOverHmacResolvesTheHandleAreaBeforeTheSessionArea()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistryWithSessionSupport();

        //An HMAC-session-ranged handle (MSO 0x02) the simulator has never issued.
        const uint UnknownSessionHandle = 0x0200_00EE;
        using TpmSession unknownSession = new(new TpmHandle(UnknownSessionHandle), Tpm2bNonce.CreateRandom(16, TestEntropy.NewCounterStream(), pool), TpmAlgIdConstants.TPM_ALG_SHA256, TestEntropy.NewCounterStream(), pool);
        unknownSession.SetAuthValue([0x01], pool);

        //The rejection is decided at the handle area, so the placeholder never has to carry the Index's
        //genuine Name - it only has to be non-empty, satisfying the executor's requirement that a named
        //handle supply one.
        ReadOnlyMemory<byte>[] handleNames = [ReadOnlyMemory<byte>.Empty, new byte[] { 0x00 }];
        var input = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, NvIndexHandle);

        TpmResult<NvUndefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            tpm, input, [unknownSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), result.ResponseCode,
            "The unknown Index handle's presence probe is a handle-area outcome, resolved before the authorizing session is looked up at all (TPM 2.0 Library Part 3, clause 5.4).");
    }

    /// <summary>
    /// <c>TPM2_Clear</c> reclaims the owner's provisioning wholesale: it will "flush resident objects (persistent
    /// and volatile) in the Storage and Endorsement hierarchies" and "delete any NV Index with
    /// TPMA_NV_PLATFORMCREATE == CLEAR" - every Index defined under Owner Authorization, which is every Index
    /// this simulator can define (TPM 2.0 Library Part 3, clause 24.6.1). Observed through the two teardown
    /// commands this file already covers: after the clear, evicting the persistent handle and undefining the
    /// Index both answer <c>TPM_RC_HANDLE</c> because neither exists any more, and the freed handles accept
    /// fresh definitions - so the deletion released the handle rather than merely hiding the entry.
    /// </summary>
    [TestMethod]
    public async Task ClearFlushesOwnerPersistentObjectsAndDeletesOwnerCreatedNvIndexes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<EvictControlResponse> persistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, primary.ObjectHandle.Value, PersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        TpmResult<NvDefineSpaceResponse> defineResult = await DefineIndexAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");

        TpmResult<ClearResponse> clearResult = await tpm.ClearAsync(ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(clearResult.IsSuccess, $"TPM2_Clear failed: '{clearResult.ResponseCode}'.");

        TpmResult<EvictControlResponse> evictAfterClear = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, PersistentHandle, PersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), evictAfterClear.ResponseCode,
            "A clear flushes owner-hierarchy persistent objects, so nothing remains at objectHandle, handle 2 of the EvictControl command table, to evict.");

        TpmResult<NvUndefineSpaceResponse> undefineAfterClear = await UndefineAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), undefineAfterClear.ResponseCode,
            "A clear deletes every owner-created NV Index, so nothing remains at the Index handle to undefine.");

        //The handles were released, not merely emptied: both accept a fresh definition of the same kind.
        TpmResult<NvDefineSpaceResponse> redefineResult = await DefineIndexAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(redefineResult.IsSuccess, $"NV_DefineSpace after the clear failed: '{redefineResult.ResponseCode}'.");

        using CreatePrimaryResponse replacementPrimary = await CreateSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmResult<EvictControlResponse> repersistResult = await TpmEvictControlHarness.EvictControlAsync(
            tpm, registry, pool, replacementPrimary.ObjectHandle.Value, PersistentHandle, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(repersistResult.IsSuccess, $"EvictControl (re-persist) after the clear failed: '{repersistResult.ResponseCode}'.");
    }

    /// <summary>Defines a small DA-exempt NV Index authorized by its own auth value.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The NV Index handle to define.</param>
    /// <returns>The NV_DefineSpace result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex)
    {
        using Tpm2bAuth indexAuth = Tpm2bAuth.CreateEmpty(pool);
        using var publicInfo = new TpmsNvPublic(
            nvIndex,
            TpmAlgIdConstants.TPM_ALG_SHA256,
            TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_NO_DA,
            Tpm2bDigest.Empty,
            dataSize: 8);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, indexAuth, publicInfo);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Undefines (removes) the given NV Index, returning the result for the caller to assert.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The NV Index handle to undefine.</param>
    /// <returns>The NV_UndefineSpace result.</returns>
    private async Task<TpmResult<NvUndefineSpaceResponse>> UndefineAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex)
    {
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        var input = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Starts an HMAC session bound to the owner hierarchy through the production
    /// <c>TPM2_StartAuthSession()</c> path (TPM 2.0 Library Part 1, clause 16.6.10, equation 20), deriving the
    /// session key from the owner's Empty Buffer authValue - this file never rotates it away before calling
    /// this helper.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry; must already carry the StartAuthSession codec.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The started session handle and its client-side wrapper (the caller disposes the wrapper and flushes the handle).</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartOwnerBoundHmacSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession((uint)TpmRh.TPM_RH_OWNER, TpmAlgIdConstants.TPM_ALG_SHA256, TestEntropy.NewCounterStream(), pool);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound to the owner hierarchy) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse startResponse = startResult.Value;
        TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(startResponse.SessionHandle.Value), ReadOnlyMemory<byte>.Empty, startInput.NonceCaller,
            startResponse.NonceTPM, TpmAlgIdConstants.TPM_ALG_SHA256, TestEntropy.NewCounterStream(), pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        return (startResponse.SessionHandle.Value, session);
    }

    /// <summary>Flushes a started session's simulator-side context via <c>TPM2_FlushContext()</c>.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry; must already carry the FlushContext codec.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sessionHandle">The session handle to flush.</param>
    private async Task FlushSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint sessionHandle)
    {
        var flush = FlushContextInput.ForHandle(sessionHandle);
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flush, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates a primary ECC P-256 signing key under the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates a simulator with an ECC signing backend, powers it on, and brings it operational.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-persistence", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator to move it into
    /// <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
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
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);

        return registry;
    }

    /// <summary>
    /// Creates a response codec registry covering <c>TPM2_NV_UndefineSpace()</c> plus the session bracket
    /// (<c>TPM2_StartAuthSession()</c>, <c>TPM2_FlushContext()</c>) the HMAC-session undefine test issues.
    /// </summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistryWithSessionSupport()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }
}
