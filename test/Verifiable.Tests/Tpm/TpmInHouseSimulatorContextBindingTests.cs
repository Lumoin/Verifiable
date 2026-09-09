using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
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
/// The in-house behavioural <see cref="TpmSimulator"/>'s <c>TPM2_ContextSave()</c>/<c>TPM2_ContextLoad()</c>
/// security invariants: a saved context is bound to the TPM that saved it and to its Reset epoch, and its
/// content is invalidated by the events that rotate the proof or seed it was protected under — "A saved
/// context is cryptographically bound to a specific TPM so that it may not be loaded on a different TPM"
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
/// clause 27.1</see>). Driven through the production command path
/// (<see cref="Verifiable.Tpm.Infrastructure.TpmCommandExecutor"/> with <see cref="ContextSaveInput"/>/<see
/// cref="ContextLoadInput"/> and the real response codecs), in-process, with no external assets. This class
/// consumes no NV Index: none of its cases bind a session to a DA-protected entity, so the handle block
/// <c>0x0100_0230</c>-<c>0x0100_023F</c> reserved for this class goes unused.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorContextBindingTests
{
    /// <summary>The session/name hash algorithm every HMAC session in this class uses.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A blob saved on one simulated TPM does not load on another: two instances with distinct identifiers
    /// derive distinct proofs from them, so the recomputed integrity HMAC never matches
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Part 1, clause 27.1</see>: "This binding is provided by using a statistically unique proof value in
    /// the generation of the protection values for a context").
    /// </summary>
    [TestMethod]
    public async Task ObjectContextBlobFailsIntegrityOnAnotherSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulatorA = await CreateOperationalAsync(pool, "tpm-in-house-context-binding-cross-a").ConfigureAwait(false);
        using TpmDevice tpmA = TpmDevice.Create(simulatorA.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpmA, registry, pool).ConfigureAwait(false);
        using ContextSaveResponse saved = await SaveContextAsync(tpmA, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);

        using TpmSimulator simulatorB = await CreateOperationalAsync(pool, "tpm-in-house-context-binding-cross-b").ConfigureAwait(false);
        using TpmDevice tpmB = TpmDevice.Create(simulatorB.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        //B's own object counter starts at zero; the clause 14.6.1 range gate would otherwise fire (VALUE)
        //before the crypto binding this test actually proves is ever consulted.
        await WarmUpObjectCounterAsync(tpmB, registry, pool, saved.Context.Sequence).ConfigureAwait(false);

        TpmResult<ContextLoadResponse> result = await SubmitContextLoadAsync(tpmB, registry, pool, saved.Context).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INTEGRITY, 0), CodeOf(result),
            "An object blob saved on one simulator must fail integrity on a differently-seeded one, at context, parameter 1 of Part 3's Table 226.");
    }

    /// <summary>
    /// A session blob saved on one simulated TPM does not load on another, for the identical proof-binding
    /// reason an object blob does not
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Part 1, clause 27.1</see>).
    /// </summary>
    [TestMethod]
    public async Task SessionContextBlobFailsIntegrityOnAnotherSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulatorA = await CreateOperationalAsync(pool, "tpm-in-house-context-binding-cross-session-a").ConfigureAwait(false);
        using TpmDevice tpmA = TpmDevice.Create(simulatorA.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse bindObject = await CreateEccSigningPrimaryAsync(tpmA, registry, pool).ConfigureAwait(false);
        (uint handle, TpmSession session) = await StartBoundHmacSessionAsync(tpmA, registry, pool, bindObject.ObjectHandle.Value).ConfigureAwait(false);
        using ContextSaveResponse saved = await SaveContextAsync(tpmA, registry, pool, handle).ConfigureAwait(false);
        session.Dispose();

        using TpmSimulator simulatorB = await CreateOperationalAsync(pool, "tpm-in-house-context-binding-cross-session-b").ConfigureAwait(false);
        using TpmDevice tpmB = TpmDevice.Create(simulatorB.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        //B's own session counter starts at zero; the clause 14.6.1 range gate would otherwise fire (VALUE)
        //before the crypto binding this test actually proves is ever consulted.
        await WarmUpSessionCounterAsync(tpmB, registry, pool, saved.Context.Sequence).ConfigureAwait(false);

        TpmResult<ContextLoadResponse> result = await SubmitContextLoadAsync(tpmB, registry, pool, saved.Context).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INTEGRITY, 0), CodeOf(result),
            "A session blob saved on one simulator must fail integrity on a differently-seeded one, at context, parameter 1 of Part 3's Table 226.");
    }

    /// <summary>
    /// An owner-hierarchy object's blob is refused after <c>TPM2_Clear()</c>: the clear "change[s] the
    /// storage primary seed (SPS) to a new value from the TPM's random number generator (RNG)"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Part 3, clause 24.6.1</see>), which is exactly the seed the owner hierarchy's proof — and so the
    /// blob's integrity HMAC key — derives from.
    /// </summary>
    [TestMethod]
    public async Task OwnerHierarchyObjectBlobFailsIntegrityAfterClear()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-in-house-context-binding-clear-owner").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using ContextSaveResponse saved = await SaveContextAsync(tpm, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);

        await ClearAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<ContextLoadResponse> result = await SubmitContextLoadAsync(tpm, registry, pool, saved.Context).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INTEGRITY, 0), CodeOf(result),
            "The storage-hierarchy seed TPM2_Clear() rotates is exactly what an owner-hierarchy object's saved context is bound to, at context, parameter 1 of Part 3's Table 226.");
    }

    /// <summary>
    /// A platform-hierarchy object's blob still loads after <c>TPM2_Clear()</c>: the command "flush[es]
    /// resident objects (persistent and volatile) in the Storage and Endorsement hierarchies" and rotates
    /// only the storage primary seed
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Part 3, clause 24.6.1</see>) — the platform hierarchy's proof, untouched by either change, still
    /// matches.
    /// </summary>
    [TestMethod]
    public async Task PlatformHierarchyObjectBlobStillLoadsAfterClear()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-in-house-context-binding-clear-platform").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_PLATFORM).ConfigureAwait(false);
        using ContextSaveResponse saved = await SaveContextAsync(tpm, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);

        await ClearAsync(tpm, registry, pool).ConfigureAwait(false);

        ContextLoadResponse loaded = await LoadContextAsync(tpm, registry, pool, saved.Context).ConfigureAwait(false);

        await AssertLoadsAndReadsAsync(tpm, registry, pool, loaded.LoadedHandle.Value, "The platform object's reloaded copy").ConfigureAwait(false);
    }

    /// <summary>
    /// A saved session's tracking entry is gone after <c>TPM2_Clear()</c>: "Previously saved sessions shall
    /// not be loadable after the SPS changes"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Part 2, clause 14.7.1</see>), realized here as the load-once tracking table being emptied outright —
    /// unlike an owner-hierarchy object, a session's own proof falls back to the construction-fixed seed
    /// <c>TPM2_Clear()</c> never rotates, so the crypto binding itself still passes and the tracking check is
    /// what actually refuses the reload.
    /// </summary>
    [TestMethod]
    public async Task SavedSessionFailsWithHandleAfterClear()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-in-house-context-binding-clear-session").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse bindObject = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint handle, TpmSession session) = await StartBoundHmacSessionAsync(tpm, registry, pool, bindObject.ObjectHandle.Value).ConfigureAwait(false);
        using ContextSaveResponse saved = await SaveContextAsync(tpm, registry, pool, handle).ConfigureAwait(false);
        session.Dispose();

        await ClearAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<ContextLoadResponse> result = await SubmitContextLoadAsync(tpm, registry, pool, saved.Context).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), CodeOf(result),
            "TPM2_Clear() empties the saved-session tracking table while leaving the session's own crypto binding intact, so the load-once check is what refuses the reload.");
    }

    /// <summary>
    /// An owner-hierarchy object's blob fails integrity after a TPM Reset, once the sequence-range gate that
    /// would otherwise fire first (<see cref="SessionBlobFailsAfterReset"/>'s own subject) is satisfied by a
    /// fresh post-Reset save: "a new context encryption key shall be generated"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Part 3, clause 9.3</see>) invalidates the pre-Reset blob's HMAC.
    /// </summary>
    [TestMethod]
    public async Task OwnerHierarchyObjectBlobFailsIntegrityAfterReset() =>
        await AssertObjectBlobFailsIntegrityAfterResetAsync(isNullHierarchySequence: false, "tpm-in-house-context-binding-reset-owner").ConfigureAwait(false);

    /// <summary>
    /// A NULL-hierarchy sequence object's blob fails integrity after a TPM Reset for the identical reason an
    /// owner-hierarchy object's does — the Reset-epoch fold in the context encryption key derivation is
    /// hierarchy-agnostic
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Part 3, clause 9.3</see>).
    /// </summary>
    [TestMethod]
    public async Task NullHierarchySequenceBlobFailsIntegrityAfterReset() =>
        await AssertObjectBlobFailsIntegrityAfterResetAsync(isNullHierarchySequence: true, "tpm-in-house-context-binding-reset-null").ConfigureAwait(false);

    /// <summary>
    /// A session's blob fails <c>TPM_RC_VALUE</c>, not <c>TPM_RC_HANDLE</c>, on the ordinary post-Reset reload
    /// attempt: "If an input value for sequence is larger than the value used in any saved context, the TPM
    /// shall return an error (TPM_RC_VALUE) and do no additional processing of the context"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Part 2, clause 14.6.1</see>). A TPM Reset re-zeroes <c>SessionContextCounter</c> ("contextCounter is
    /// saved by Shutdown(STATE) and reset on TPM Reset"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Part 1, clause 27.5</see>)), so the pre-Reset sequence is now larger than the counter and this
    /// pre-effect gate fires before the crypto binding or the (also-cleared) load-once tracking table —
    /// "tracking data for saved session contexts shall be set to its initial value"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Part 3, clause 9.3</see>) — is ever consulted; the load-once refusal this same tracking clear produces
    /// is observable directly only via <c>TPM2_Clear()</c>, which leaves the counter untouched (see <see
    /// cref="SavedSessionFailsWithHandleAfterClear"/>).
    /// </summary>
    [TestMethod]
    public async Task SessionBlobFailsAfterReset()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-in-house-context-binding-reset-session").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse bindObject = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint handle, TpmSession session) = await StartBoundHmacSessionAsync(tpm, registry, pool, bindObject.ObjectHandle.Value).ConfigureAwait(false);
        using ContextSaveResponse saved = await SaveContextAsync(tpm, registry, pool, handle).ConfigureAwait(false);
        session.Dispose();

        await IssueShutdownAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmResult<ContextLoadResponse> result = await SubmitContextLoadAsync(tpm, registry, pool, saved.Context).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), CodeOf(result),
            "A TPM Reset re-zeroes SessionContextCounter, so the pre-Reset sequence now exceeds it and the clause 14.6.1 range gate fires before any tracking or crypto check runs.");
    }

    /// <summary>
    /// An ordinary object's blob loads after a TPM Restart (<c>Shutdown(STATE)</c> then <c>Startup(CLEAR)</c>):
    /// unlike an <c>stClear</c> object's, its saved context carries no <c>clearCount</c> fold, so the
    /// Restart's <c>ClearCount</c> bump does not disturb its integrity HMAC
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Part 2, clause 14.5</see>).
    /// </summary>
    [TestMethod]
    public async Task OrdinaryObjectBlobLoadsAfterRestart() =>
        await AssertOrdinaryObjectBlobLoadsAsync(TpmSuConstants.TPM_SU_CLEAR, "tpm-in-house-context-binding-restart-object").ConfigureAwait(false);

    /// <summary>
    /// An ordinary object's blob loads after a TPM Resume (<c>Shutdown(STATE)</c> then <c>Startup(STATE)</c>):
    /// neither the Reset epoch nor <c>ClearCount</c> advances across a Resume
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Part 3, clause 9.3</see>'s Resume bullets name neither), so a pre-Resume blob's integrity HMAC still
    /// matches.
    /// </summary>
    [TestMethod]
    public async Task OrdinaryObjectBlobLoadsAfterResume() =>
        await AssertOrdinaryObjectBlobLoadsAsync(TpmSuConstants.TPM_SU_STATE, "tpm-in-house-context-binding-resume-object").ConfigureAwait(false);

    /// <summary>
    /// A saved HMAC session reloads at its own handle and still authorizes a following command after a TPM
    /// Restart: "Saved session contexts are not invalidated and may be reloaded after a TPM Restart or TPM
    /// Resume"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Part 1, clause 27.5</see>).
    /// </summary>
    [TestMethod]
    public async Task SessionBlobStillWorksAfterRestart() =>
        await AssertSessionBlobStillWorksAsync(TpmSuConstants.TPM_SU_CLEAR, "tpm-in-house-context-binding-restart-session").ConfigureAwait(false);

    /// <summary>
    /// A saved HMAC session reloads at its own handle and still authorizes a following command after a TPM
    /// Resume, for the same reason it survives a Restart
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Part 1, clause 27.5</see>).
    /// </summary>
    [TestMethod]
    public async Task SessionBlobStillWorksAfterResume() =>
        await AssertSessionBlobStillWorksAsync(TpmSuConstants.TPM_SU_STATE, "tpm-in-house-context-binding-resume-session").ConfigureAwait(false);

    /// <summary>
    /// An <c>stClear</c> object's blob fails integrity after a TPM Restart: "When an object has the stClear
    /// attribute, it shall not be possible to reload the context or any descendant object after a TPM Reset
    /// or TPM Restart"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Part 2, clause 14.5</see>), realized here as the Restart's <c>ClearCount</c> bump breaking the
    /// <c>clearCount</c>-folded integrity HMAC only <c>stClear</c> objects carry.
    /// </summary>
    [TestMethod]
    public async Task StClearObjectBlobFailsIntegrityAfterRestart() =>
        await AssertStClearObjectBlobAsync(TpmSuConstants.TPM_SU_CLEAR, isExpectedToLoad: false, "tpm-in-house-context-binding-restart-stclear").ConfigureAwait(false);

    /// <summary>
    /// An <c>stClear</c> object's blob still loads after a TPM Resume — clause 14.5's Restart/Reset-only rule
    /// does not name Resume, and Resume advances neither the Reset epoch nor <c>ClearCount</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Part 3, clause 9.3</see>), so the <c>clearCount</c>-folded integrity HMAC still matches.
    /// </summary>
    [TestMethod]
    public async Task StClearObjectBlobLoadsAfterResume() =>
        await AssertStClearObjectBlobAsync(TpmSuConstants.TPM_SU_STATE, isExpectedToLoad: true, "tpm-in-house-context-binding-resume-stclear").ConfigureAwait(false);

    /// <summary>
    /// A saved session's vacated slot admits a new <c>TPM2_StartAuthSession()</c>, and once that new session
    /// is flushed the reloaded original still authorizes a command — "A saved session context may be reloaded
    /// into the TPM" and "the handle associated with a session does not change as long as the session is
    /// active"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Part 1, clause 27.5</see>).
    /// </summary>
    [TestMethod]
    public async Task SavedSessionSlotAdmitsNewSessionAndReloadedSessionStillWorks()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-in-house-context-binding-slot-reuse").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse bindObject = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint handleA, TpmSession sessionA) = await StartBoundHmacSessionAsync(tpm, registry, pool, bindObject.ObjectHandle.Value).ConfigureAwait(false);
        using(sessionA)
        {
            using ContextSaveResponse savedA = await SaveContextAsync(tpm, registry, pool, handleA).ConfigureAwait(false);

            (uint handleB, TpmSession sessionB) = await StartBoundHmacSessionAsync(tpm, registry, pool, bindObject.ObjectHandle.Value).ConfigureAwait(false);
            using(sessionB)
            {
                Assert.AreNotEqual(handleA, handleB, "The new session must occupy a distinct slot beside the saved one.");
                await AssertSessionStillWorksAsync(tpm, registry, pool, sessionB, "The new session").ConfigureAwait(false);
                await FlushAsync(tpm, registry, pool, handleB).ConfigureAwait(false);
            }

            ContextLoadResponse loadedA = await LoadContextAsync(tpm, registry, pool, savedA.Context).ConfigureAwait(false);
            Assert.AreEqual(handleA, loadedA.LoadedHandle.Value, "A session installs at its own saved handle — no new handle is drawn.");
            await AssertSessionStillWorksAsync(tpm, registry, pool, sessionA, "The reloaded session").ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES)</c> reports the six context-management rows: "the
    /// algorithm used for the integrity HMAC on saved contexts" (<c>TPM_PT_CONTEXT_HASH</c>), "the algorithm
    /// used for encryption of saved contexts" and its key size (<c>TPM_PT_CONTEXT_SYM</c>/<c>_SYM_SIZE</c>),
    /// "the maximum allowed difference... between the contextID values of two saved session contexts"
    /// (<c>TPM_PT_CONTEXT_GAP_MAX</c>), and the two <c>TPM_PT_MAX_*_CONTEXT</c> ceilings
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Part 2, clause 6.13, Table 28</see>).
    /// </summary>
    [TestMethod]
    public async Task GetCapabilityReportsContextManagementProperties()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-in-house-context-binding-capability").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        Assert.AreEqual((uint)TpmAlgIdConstants.TPM_ALG_SHA256, await ReadPropertyAsync(tpm, registry, pool, TpmPtConstants.TPM_PT_CONTEXT_HASH).ConfigureAwait(false), "TPM_PT_CONTEXT_HASH must name the integrity HMAC's algorithm.");
        Assert.AreEqual((uint)TpmAlgIdConstants.TPM_ALG_AES, await ReadPropertyAsync(tpm, registry, pool, TpmPtConstants.TPM_PT_CONTEXT_SYM).ConfigureAwait(false), "TPM_PT_CONTEXT_SYM must name the confidentiality algorithm.");
        Assert.AreEqual(256u, await ReadPropertyAsync(tpm, registry, pool, TpmPtConstants.TPM_PT_CONTEXT_SYM_SIZE).ConfigureAwait(false), "TPM_PT_CONTEXT_SYM_SIZE must report the key size in bits.");
        Assert.AreEqual(65535u, await ReadPropertyAsync(tpm, registry, pool, TpmPtConstants.TPM_PT_CONTEXT_GAP_MAX).ConfigureAwait(false), "TPM_PT_CONTEXT_GAP_MAX must report 2^16 - 1.");
        Assert.AreEqual(65535u, await ReadPropertyAsync(tpm, registry, pool, TpmPtConstants.TPM_PT_MAX_OBJECT_CONTEXT).ConfigureAwait(false), "TPM_PT_MAX_OBJECT_CONTEXT must report the UINT16 ceiling.");
        Assert.AreEqual(65535u, await ReadPropertyAsync(tpm, registry, pool, TpmPtConstants.TPM_PT_MAX_SESSION_CONTEXT).ConfigureAwait(false), "TPM_PT_MAX_SESSION_CONTEXT must report the UINT16 ceiling.");
    }

    /// <summary>
    /// The metered house pool balances across three distinct <c>TPM2_ContextLoad()</c> refusal shapes — an
    /// integrity refusal, a hierarchy refusal, and a cross-instance integrity refusal — proving every carrier
    /// each refused parse and effect rented is returned
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Part 3, clause 28.3.1</see>).
    /// </summary>
    [TestMethod]
    public async Task MeteredPoolBalancedAcrossIntegrityHierarchyAndCrossInstanceRefusals()
    {
        using var housePool = new MeteredHousePool();
        BaseMemoryPool pool = housePool.Pool;

        using TpmSimulator simulatorA = await CreateOperationalAsync(pool, "tpm-in-house-context-binding-pool-a").ConfigureAwait(false);
        using TpmDevice tpmA = TpmDevice.Create(simulatorA.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse integrityVictim = await CreateEccSigningPrimaryAsync(tpmA, registry, pool).ConfigureAwait(false);
        using ContextSaveResponse integritySaved = await SaveContextAsync(tpmA, registry, pool, integrityVictim.ObjectHandle.Value).ConfigureAwait(false);

        //The clear rotates the storage seed, so the hierarchy- and cross-instance-refusal victims below must
        //be saved AFTER it — otherwise the clear would break their integrity too, and the wrong gate would
        //fire when each is tested for its own, distinct refusal.
        await ClearAsync(tpmA, registry, pool).ConfigureAwait(false);

        using CreatePrimaryResponse hierarchyVictim = await CreateEccSigningPrimaryAsync(tpmA, registry, pool).ConfigureAwait(false);
        using ContextSaveResponse hierarchySaved = await SaveContextAsync(tpmA, registry, pool, hierarchyVictim.ObjectHandle.Value).ConfigureAwait(false);

        using CreatePrimaryResponse crossVictim = await CreateEccSigningPrimaryAsync(tpmA, registry, pool).ConfigureAwait(false);
        using ContextSaveResponse crossSaved = await SaveContextAsync(tpmA, registry, pool, crossVictim.ObjectHandle.Value).ConfigureAwait(false);

        await DisableOwnerHierarchyAsync(tpmA, registry, pool).ConfigureAwait(false);

        using TpmSimulator simulatorB = await CreateOperationalAsync(pool, "tpm-in-house-context-binding-pool-b").ConfigureAwait(false);
        using TpmDevice tpmB = TpmDevice.Create(simulatorB.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        await WarmUpObjectCounterAsync(tpmB, registry, pool, crossSaved.Context.Sequence).ConfigureAwait(false);

        long baseline = housePool.OutstandingCount;
        TpmResult<ContextLoadResponse> integrityResult = await SubmitContextLoadAsync(tpmA, registry, pool, integritySaved.Context).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INTEGRITY, 0), CodeOf(integrityResult), "Premise: the clear must have actually broken this blob's integrity, at context, parameter 1 of Part 3's Table 226.");
        Assert.AreEqual(baseline, housePool.OutstandingCount, "An integrity-refused ContextLoad must return every carrier it rented.");

        baseline = housePool.OutstandingCount;
        TpmResult<ContextLoadResponse> hierarchyResult = await SubmitContextLoadAsync(tpmA, registry, pool, hierarchySaved.Context).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), CodeOf(hierarchyResult), "Premise: the disabled owner hierarchy must actually refuse this blob.");
        Assert.AreEqual(baseline, housePool.OutstandingCount, "A hierarchy-refused ContextLoad must return every carrier it rented.");

        baseline = housePool.OutstandingCount;
        TpmResult<ContextLoadResponse> crossResult = await SubmitContextLoadAsync(tpmB, registry, pool, crossSaved.Context).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INTEGRITY, 0), CodeOf(crossResult), "Premise: the foreign instance must actually refuse this blob, at context, parameter 1 of Part 3's Table 226.");
        Assert.AreEqual(baseline, housePool.OutstandingCount, "A cross-instance-refused ContextLoad must return every carrier it rented.");
    }

    /// <summary>
    /// Shared implementation for <see cref="OwnerHierarchyObjectBlobFailsIntegrityAfterReset"/> and <see
    /// cref="NullHierarchySequenceBlobFailsIntegrityAfterReset"/>: saves an object (or, when <paramref
    /// name="isNullHierarchySequence"/>, a NULL-hierarchy sequence), Resets the TPM, advances the relevant
    /// counter past the pre-Reset sequence with a fresh post-Reset save so the clause 14.6.1 range gate is
    /// satisfied, then asserts the pre-Reset blob fails integrity.
    /// </summary>
    /// <param name="isNullHierarchySequence">Whether to save an open sign sequence (NULL hierarchy) instead of the signing key itself (owner hierarchy).</param>
    /// <param name="identifier">The simulator's own identifier.</param>
    private async Task AssertObjectBlobFailsIntegrityAfterResetAsync(bool isNullHierarchySequence, string identifier)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, identifier).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse signer = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        uint handle = isNullHierarchySequence
            ? await StartSignSequenceAsync(tpm, registry, pool, signer.ObjectHandle.Value).ConfigureAwait(false)
            : signer.ObjectHandle.Value;
        using ContextSaveResponse saved = await SaveContextAsync(tpm, registry, pool, handle).ConfigureAwait(false);

        await IssueShutdownAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        //The object-context sequence counter re-zeroes on a TPM Reset (Part 3, clause 9.3), so a bare reload
        //of the pre-Reset blob would trip the clause 14.6.1 sequence-range gate before the crypto binding is
        //ever consulted. A fresh post-Reset save advances the counter past the old sequence so this test
        //actually reaches, and proves, the binding itself.
        using CreatePrimaryResponse signerAfter = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        uint handleAfter = isNullHierarchySequence
            ? await StartSignSequenceAsync(tpm, registry, pool, signerAfter.ObjectHandle.Value).ConfigureAwait(false)
            : signerAfter.ObjectHandle.Value;
        using ContextSaveResponse advancing = await SaveContextAsync(tpm, registry, pool, handleAfter).ConfigureAwait(false);
        Assert.IsGreaterThanOrEqualTo(saved.Context.Sequence, advancing.Context.Sequence, "Premise: the post-Reset save must have re-reached at least the pre-Reset blob's own sequence number.");

        TpmResult<ContextLoadResponse> result = await SubmitContextLoadAsync(tpm, registry, pool, saved.Context).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INTEGRITY, 0), CodeOf(result),
            "Part 1, clause 27.1: 'Saved contexts for all objects and sessions are invalidated on a TPM Reset.' A new context encryption key is generated on Reset (clause 9.3), so a pre-Reset blob's HMAC fails to match even once the sequence range gate is satisfied, at context, parameter 1 of Part 3's Table 226.");
    }

    /// <summary>
    /// Shared implementation for <see cref="OrdinaryObjectBlobLoadsAfterRestart"/> and <see
    /// cref="OrdinaryObjectBlobLoadsAfterResume"/>: saves a signing key's context, shuts down with
    /// <c>Shutdown(STATE)</c>, restarts with <paramref name="startupAfterShutdown"/>, then asserts the blob
    /// still loads and the reloaded copy still answers <c>TPM2_ReadPublic()</c>.
    /// </summary>
    /// <param name="startupAfterShutdown">The Startup type following the STATE shutdown — CLEAR for a Restart, STATE for a Resume.</param>
    /// <param name="identifier">The simulator's own identifier.</param>
    private async Task AssertOrdinaryObjectBlobLoadsAsync(TpmSuConstants startupAfterShutdown, string identifier)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, identifier).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using ContextSaveResponse saved = await SaveContextAsync(tpm, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);

        await IssueShutdownAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE).ConfigureAwait(false);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool, startupAfterShutdown).ConfigureAwait(false);

        ContextLoadResponse loaded = await LoadContextAsync(tpm, registry, pool, saved.Context).ConfigureAwait(false);

        await AssertLoadsAndReadsAsync(tpm, registry, pool, loaded.LoadedHandle.Value, "An ordinary object's reloaded copy").ConfigureAwait(false);
    }

    /// <summary>
    /// Shared implementation for <see cref="SessionBlobStillWorksAfterRestart"/> and <see
    /// cref="SessionBlobStillWorksAfterResume"/>: saves a bound HMAC session's context, shuts down with
    /// <c>Shutdown(STATE)</c>, restarts with <paramref name="startupAfterShutdown"/>, then asserts the
    /// session reloads at its own handle and still authorizes a command.
    /// </summary>
    /// <param name="startupAfterShutdown">The Startup type following the STATE shutdown — CLEAR for a Restart, STATE for a Resume.</param>
    /// <param name="identifier">The simulator's own identifier.</param>
    private async Task AssertSessionBlobStillWorksAsync(TpmSuConstants startupAfterShutdown, string identifier)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, identifier).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse bindObject = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint handle, TpmSession session) = await StartBoundHmacSessionAsync(tpm, registry, pool, bindObject.ObjectHandle.Value).ConfigureAwait(false);
        using(session)
        {
            using ContextSaveResponse saved = await SaveContextAsync(tpm, registry, pool, handle).ConfigureAwait(false);

            await IssueShutdownAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE).ConfigureAwait(false);
            await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
            await BringOperationalAsync(simulator, pool, startupAfterShutdown).ConfigureAwait(false);

            ContextLoadResponse loaded = await LoadContextAsync(tpm, registry, pool, saved.Context).ConfigureAwait(false);
            Assert.AreEqual(handle, loaded.LoadedHandle.Value, "A session installs at its own saved handle — no new handle is drawn.");
            await AssertSessionStillWorksAsync(tpm, registry, pool, session, "The reloaded session").ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Shared implementation for <see cref="StClearObjectBlobFailsIntegrityAfterRestart"/> and <see
    /// cref="StClearObjectBlobLoadsAfterResume"/>: saves an <c>stClear</c> key's context, shuts down with
    /// <c>Shutdown(STATE)</c>, restarts with <paramref name="startupAfterShutdown"/>, then asserts either the
    /// blob loads or it fails integrity, per <paramref name="isExpectedToLoad"/>.
    /// </summary>
    /// <param name="startupAfterShutdown">The Startup type following the STATE shutdown — CLEAR for a Restart, STATE for a Resume.</param>
    /// <param name="isExpectedToLoad">Whether the reload is expected to succeed (Resume) or fail integrity (Restart).</param>
    /// <param name="identifier">The simulator's own identifier.</param>
    private async Task AssertStClearObjectBlobAsync(TpmSuConstants startupAfterShutdown, bool isExpectedToLoad, string identifier)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, identifier).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateStClearEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        using ContextSaveResponse saved = await SaveContextAsync(tpm, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        Assert.AreEqual(TpmiDhSaved.StClearTransientObject, saved.Context.SavedHandle.Value, "Premise: an ST_CLEAR object must stamp Table 58's stClear saved handle.");

        await IssueShutdownAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE).ConfigureAwait(false);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool, startupAfterShutdown).ConfigureAwait(false);

        if(isExpectedToLoad)
        {
            ContextLoadResponse loaded = await LoadContextAsync(tpm, registry, pool, saved.Context).ConfigureAwait(false);

            await AssertLoadsAndReadsAsync(tpm, registry, pool, loaded.LoadedHandle.Value, "The stClear object's reloaded copy").ConfigureAwait(false);
        }
        else
        {
            TpmResult<ContextLoadResponse> result = await SubmitContextLoadAsync(tpm, registry, pool, saved.Context).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INTEGRITY, 0), CodeOf(result),
                "Part 2, clause 14.5: 'When an object has the stClear attribute, it shall not be possible to reload the context or any descendant object after a TPM Reset or TPM Restart.' at context, parameter 1 of Part 3's Table 226.");
        }
    }

    /// <summary>Reads a command result's response code without touching <see cref="TpmResult{T}.ResponseCode"/> on a success, which throws.</summary>
    /// <typeparam name="T">The response type.</typeparam>
    /// <param name="result">The command result.</param>
    /// <returns><see cref="TpmRcConstants.TPM_RC_SUCCESS"/> when successful, else the result's own response code.</returns>
    private static TpmRcConstants CodeOf<T>(TpmResult<T> result) =>
        result.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : result.ResponseCode;

    /// <summary>Submits <see cref="ContextSaveInput"/> for <paramref name="handle"/>, asserting success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The resource handle to save.</param>
    /// <returns>The response; the caller disposes it.</returns>
    private async Task<ContextSaveResponse> SaveContextAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        TpmResult<ContextSaveResponse> result = await TpmCommandExecutor.ExecuteAsync<ContextSaveResponse>(
            tpm, ContextSaveInput.ForHandle(handle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ContextSave() failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Submits <see cref="ContextLoadInput"/> for <paramref name="context"/> and returns the raw result.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="context">The saved context to reload. Borrowed — not disposed here.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<ContextLoadResponse>> SubmitContextLoadAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmsContext context)
    {
        var input = new ContextLoadInput(context);

        return await TpmCommandExecutor.ExecuteAsync<ContextLoadResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Submits <see cref="ContextLoadInput"/> for <paramref name="context"/>, asserting success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="context">The saved context to reload. Borrowed — not disposed here.</param>
    /// <returns>The response.</returns>
    private async Task<ContextLoadResponse> LoadContextAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmsContext context)
    {
        TpmResult<ContextLoadResponse> result = await SubmitContextLoadAsync(tpm, registry, pool, context).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ContextLoad() failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Issues <c>TPM2_ReadPublic()</c> against <paramref name="handle"/>, asserting success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The transient object handle.</param>
    /// <param name="because">A label for the assertion message.</param>
    private async Task AssertLoadsAndReadsAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle, string because)
    {
        TpmResult<ReadPublicResponse> result = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
            tpm, ReadPublicInput.ForHandle(TpmiDhObject.FromValue(handle)), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"{because}: TPM2_ReadPublic() failed: '{result.ResponseCode}'.");

        result.Value.Dispose();
    }

    /// <summary>Issues <c>TPM2_Clear()</c> under the empty-password lockout authorization, asserting success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task ClearAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        var clearInput = new ClearInput(TpmRh.TPM_RH_LOCKOUT);
        using TpmPasswordSession lockoutAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ClearResponse> result = await TpmCommandExecutor.ExecuteAsync<ClearResponse>(
            tpm, clearInput, [lockoutAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_Clear() failed: '{result.ResponseCode}'.");
    }

    /// <summary>Disables the owner hierarchy via <c>TPM2_HierarchyControl(shEnable, NO)</c> under platform authorization, asserting success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task DisableOwnerHierarchyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        var input = new HierarchyControlInput(TpmRh.TPM_RH_PLATFORM, TpmRh.TPM_RH_OWNER, TpmiYesNo.No);
        using TpmPasswordSession platformAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<HierarchyControlResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyControlResponse>(
            tpm, input, [platformAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HierarchyControl(OWNER, NO) failed: '{result.ResponseCode}'.");
    }

    /// <summary>Submits an unrestricted, empty-password ECC P-256 signing primary and returns the response, asserting success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy to create under. Defaults to the owner hierarchy.</param>
    /// <returns>The response; the caller disposes it.</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy = TpmRh.TPM_RH_OWNER)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession auth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [auth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC signing, hierarchy 0x{(uint)hierarchy:X8}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Submits an unrestricted, empty-password, owner-hierarchy ECC P-256 signing primary with
    /// <c>TPMA_OBJECT.stClear</c> SET, asserting success — no existing recipe in this suite builds this
    /// template, so it is built here directly over <see cref="TpmtPublic.CreateEccSigningTemplate"/>.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "inPublic and inSensitive's ownership transfers to the constructed CreatePrimaryInput, which the using block disposes; the analyzer cannot see the transfer through the constructor's positional parameters.")]
    private async Task<CreatePrimaryResponse> CreateStClearEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        TpmaObject objectAttributes =
            TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH | TpmaObject.SIGN_ENCRYPT | TpmaObject.ST_CLEAR | TpmaObject.NO_DA;
        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256, objectAttributes, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));
        Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.CreateEmpty(pool);
        using CreatePrimaryInput input = new(TpmRh.TPM_RH_OWNER, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession auth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [auth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC signing, ST_CLEAR) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Opens a signing sequence under <paramref name="keyHandle"/> via <c>TPM2_SignSequenceStart()</c>, asserting success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The signing key to open the sequence under.</param>
    /// <returns>The sequence's own transient handle value.</returns>
    private async Task<uint> StartSignSequenceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint keyHandle)
    {
        using SignSequenceStartInput input = SignSequenceStartInput.Create(TpmiDhObject.FromValue(keyHandle), [], pool);
        TpmResult<SignSequenceStartResponse> result = await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SignSequenceStart() failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle.Value;
    }

    /// <summary>Starts a bound, unsalted HMAC session against <paramref name="bindHandle"/> and wraps it as a <see cref="TpmSession"/>.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="bindHandle">The entity the session binds to.</param>
    /// <returns>The session's handle and the client-side session wrapper; the caller disposes the session.</returns>
    private async Task<(uint Handle, TpmSession Session)> StartBoundHmacSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint bindHandle)
    {
        TpmtSymDef symmetric = TpmtSymDef.Xor(SessionAlg);
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(bindHandle, SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"TPM2_StartAuthSession() failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse startResponse = startResult.Value;
        using Tpm2bAuth bindAuth = Tpm2bAuth.CreateEmpty(pool);
        TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(startResponse.SessionHandle.Value), bindAuth.AsReadOnlyMemory(), startInput.NonceCaller,
            startResponse.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric: symmetric, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        //GetRandom authorizes no entity (no @-handle), so its lone session MUST set at least one of
        //decrypt/encrypt/audit (Part 3, clause 5.5) or the session area itself is rejected before the
        //binding round trip this class actually tests is ever reached; ENCRYPT needs a negotiated symmetric
        //algorithm, hence Xor rather than Null.
        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

        return (startResponse.SessionHandle.Value, session);
    }

    /// <summary>Proves <paramref name="session"/> still authorizes commands by submitting <c>TPM2_GetRandom()</c> over it, asserting success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="session">The session to submit over.</param>
    /// <param name="because">A label for the assertion message.</param>
    private async Task AssertSessionStillWorksAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmSession session, string because)
    {
        var input = new GetRandomInput(16);
        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            tpm, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"{because}: TPM2_GetRandom() over the session failed: '{result.ResponseCode}'.");

        result.Value.Dispose();
    }

    /// <summary>Flushes <paramref name="handle"/> via <c>TPM2_FlushContext()</c>, asserting success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush.</param>
    private async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        TpmResult<FlushContextResponse> result = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(handle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_FlushContext() failed: '{result.ResponseCode}'.");
    }

    /// <summary>Reads one <c>TPM_CAP_TPM_PROPERTIES</c> property's value via <c>TPM2_GetCapability()</c>, asserting the window starts at it.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
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

    /// <summary>Frames an unauthorized (<c>TPM_ST_NO_SESSIONS</c>) command straight to the simulator, asserting <c>TPM_RC_SUCCESS</c>.</summary>
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

    /// <summary>Issues <c>TPM2_Shutdown(<paramref name="type"/>)</c> directly against the simulator, asserting success.</summary>
    /// <param name="simulator">The simulator to shut down.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="type">The shutdown type.</param>
    private async Task IssueShutdownAsync(TpmSimulator simulator, BaseMemoryPool pool, TpmSuConstants type) =>
        await SubmitUnauthorizedAsync(simulator, pool, new ShutdownInput(type), $"TPM2_Shutdown({type})").ConfigureAwait(false);

    /// <summary>Issues <c>TPM2_Startup(<paramref name="type"/>)</c> directly against the simulator, asserting success.</summary>
    /// <param name="simulator">The simulator to start up.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="type">The startup type.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool, TpmSuConstants type) =>
        await SubmitUnauthorizedAsync(simulator, pool, new StartupInput(type), $"TPM2_Startup({type})").ConfigureAwait(false);

    /// <summary>Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it operational with <c>Startup(CLEAR)</c>.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="identifier">The simulator's own identifier — a distinct identifier derives a distinct proof.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool, string identifier)
    {
        var simulator = new TpmSimulator(identifier, signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Advances a simulator's own object-context sequence counter to at least <paramref name="atLeast"/> by
    /// saving fresh throwaway primaries, so a later <c>TPM2_ContextLoad()</c> of a foreign blob at that
    /// sequence clears the clause 14.6.1 pre-effect range gate and reaches the crypto binding this class
    /// actually tests.
    /// </summary>
    /// <param name="tpm">The device whose counter to advance.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="atLeast">The sequence number the counter must reach or exceed.</param>
    private async Task WarmUpObjectCounterAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, ulong atLeast)
    {
        ulong reached = 0ul;
        while(reached < atLeast)
        {
            using CreatePrimaryResponse warm = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
            using ContextSaveResponse saved = await SaveContextAsync(tpm, registry, pool, warm.ObjectHandle.Value).ConfigureAwait(false);
            reached = saved.Context.Sequence;
        }
    }

    /// <summary>
    /// Advances a simulator's own session-context counter to at least <paramref name="atLeast"/> by starting
    /// and saving fresh throwaway sessions, for the same reason <see cref="WarmUpObjectCounterAsync"/>
    /// advances the object counter.
    /// </summary>
    /// <param name="tpm">The device whose counter to advance.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="atLeast">The sequence number the counter must reach or exceed.</param>
    private async Task WarmUpSessionCounterAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, ulong atLeast)
    {
        ulong reached = 0ul;
        while(reached < atLeast)
        {
            using CreatePrimaryResponse bindObject = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
            (uint handle, TpmSession session) = await StartBoundHmacSessionAsync(tpm, registry, pool, bindObject.ObjectHandle.Value).ConfigureAwait(false);
            session.Dispose();
            using ContextSaveResponse saved = await SaveContextAsync(tpm, registry, pool, handle).ConfigureAwait(false);
            reached = saved.Context.Sequence;
        }
    }

    /// <summary>Creates a response codec registry covering the commands this class issues.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_ContextSave, TpmResponseCodec.ContextSave);
        _ = registry.Register(TpmCcConstants.TPM_CC_ContextLoad, TpmResponseCodec.ContextLoad);
        _ = registry.Register(TpmCcConstants.TPM_CC_ReadPublic, TpmResponseCodec.ReadPublic);
        _ = registry.Register(TpmCcConstants.TPM_CC_Clear, TpmResponseCodec.Clear);
        _ = registry.Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart);

        return registry;
    }
}
