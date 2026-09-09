using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_ContextLoad()</c> against the in-house behavioural <see cref="TpmSimulator"/> through the
/// production command path (<see cref="TpmCommandExecutor"/> with <see cref="ContextLoadInput"/> and
/// <see cref="TpmResponseCodec.ContextLoad"/>), and the <c>TPM2_FlushContext()</c> arm a saved session takes:
/// "This command is used to reload a context that has been saved by TPM2_ContextSave()."
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.3.1</see>.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorContextLoadTests
{
    /// <summary>The Name algorithm every key and session in this class uses.</summary>
    private const TpmAlgIdConstants NameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The RSA modulus width every decrypt key in this class uses.</summary>
    private const ushort RsaKeyBits = 2048;

    /// <summary>The octet width of a blob's leading <c>TPM2B_DIGEST</c> integrity field: a 2-octet size prefix plus a 32-octet SHA-256 digest.</summary>
    private const int IntegrityFieldSize = 2 + 32;

    /// <summary>The octet width of the fingerprint the effect prepends to the encrypted region, immediately after the integrity field.</summary>
    private const int FingerprintFieldSize = sizeof(ulong);

    /// <summary>The smallest a valid blob can be: the integrity field plus the fingerprint, with an empty serialized resource beyond it.</summary>
    private const int MinimumBlobLength = IntegrityFieldSize + FingerprintFieldSize;

    /// <summary>A blob length narrower than <see cref="MinimumBlobLength"/>, used to drive the truncated-blob case.</summary>
    private const int TruncatedBlobLength = 30;

    /// <summary>A leading declared digest width that is neither zero nor the genuine 32 octets, used to drive the wrong-integrity-width case.</summary>
    private const ushort WrongIntegrityWidth = 20;

    /// <summary>A <c>savedHandle</c> value one past the three fixed object arms Table 58 admits.</summary>
    private const uint SavedHandleOneAboveTheFixedArms = TpmiDhSaved.StClearTransientObject + 1;

    /// <summary>A <c>savedHandle</c> value drawn from the NV Index range — outside every one of Table 58's five arms.</summary>
    private const uint SavedHandleInTheNvIndexRange = 0x0100_0210;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// "If the TPM has sufficient memory available, it will load the object and assign a handle. ... it is
    /// likely that a different handle will be assigned to the object.": a saved RSA key loads at a NEW transient
    /// handle, the original stays loaded at its own handle, and <c>TPM2_ReadPublic()</c> at both handles answers
    /// the identical Name.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.4</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadObjectAssignsNewHandleOriginalStaysLoadedBothAnswerSameName()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextLoadObjectAssignsNewHandleOriginalStaysLoadedBothAnswerSameName), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint originalHandle = key.ObjectHandle.Value;

        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, originalHandle).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse savedResponse = saved.Value;

        TpmResult<ContextLoadResponse> loaded = await LoadAsync(tpm, registry, pool, savedResponse.Context).ConfigureAwait(false);
        Assert.IsTrue(loaded.IsSuccess, $"TPM2_ContextLoad() must succeed: '{loaded.ResponseCode}'.");
        uint newHandle = loaded.Value.LoadedHandle.Value;
        Assert.AreNotEqual(originalHandle, newHandle, "A reloaded object is likely to be assigned a different handle (Part 1, clause 27.4).");

        using ReadPublicResponse originalReadBack = await ReadPublicAsync(tpm, registry, pool, originalHandle).ConfigureAwait(false);
        using ReadPublicResponse reloadedReadBack = await ReadPublicAsync(tpm, registry, pool, newHandle).ConfigureAwait(false);
        Assert.IsTrue(originalReadBack.Name.Span.SequenceEqual(reloadedReadBack.Name.Span), "The original and the reloaded copy must answer the identical Name.");
    }

    /// <summary>
    /// "Unlike a session context (see Clause 27.5), a saved sequence object does not include replay protection.":
    /// the same object blob loaded TWICE yields two independent new handles, neither refused.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.8</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadSameObjectBlobTwiceYieldsTwoNewHandles()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextLoadSameObjectBlobTwiceYieldsTwoNewHandles), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, key.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse savedResponse = saved.Value;

        TpmResult<ContextLoadResponse> firstLoad = await LoadAsync(tpm, registry, pool, savedResponse.Context).ConfigureAwait(false);
        Assert.IsTrue(firstLoad.IsSuccess, $"The first load must succeed: '{firstLoad.ResponseCode}'.");

        TpmResult<ContextLoadResponse> secondLoad = await LoadAsync(tpm, registry, pool, savedResponse.Context).ConfigureAwait(false);
        Assert.IsTrue(secondLoad.IsSuccess, $"An object blob carries no replay protection, so a second load must also succeed: '{secondLoad.ResponseCode}'.");
        Assert.AreNotEqual(firstLoad.Value.LoadedHandle.Value, secondLoad.Value.LoadedHandle.Value, "Two loads of the same object blob must be assigned two different handles.");
    }

    /// <summary>
    /// A saved hash-sequence context reloads at a new handle, accepts one further <c>TPM2_SequenceUpdate()</c>,
    /// and completes: the encrypted blob "contains the data necessary to reconstruct the full object or session
    /// context in the TPM."
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadHashSequenceRestoresAndCompletes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextLoadHashSequenceRestoresAndCompletes), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sequenceHandle = await StartHashSequenceHandleAsync(tpm, registry, pool).ConfigureAwait(false);
        await UpdateSequenceAsync(tpm, registry, pool, sequenceHandle, "first block "u8.ToArray()).ConfigureAwait(false);

        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, sequenceHandle).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() of an open sequence must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse savedResponse = saved.Value;
        Assert.AreEqual(TpmiDhSaved.SequenceObject, savedResponse.Context.SavedHandle.Value, "A sequence object saves under Table 58's fixed sequence-object value.");

        TpmResult<ContextLoadResponse> loaded = await LoadAsync(tpm, registry, pool, savedResponse.Context).ConfigureAwait(false);
        Assert.IsTrue(loaded.IsSuccess, $"TPM2_ContextLoad() of the sequence must succeed: '{loaded.ResponseCode}'.");
        uint reloadedHandle = loaded.Value.LoadedHandle.Value;

        await UpdateSequenceAsync(tpm, registry, pool, reloadedHandle, "second block"u8.ToArray()).ConfigureAwait(false);
        using SequenceCompleteInput completeInput = SequenceCompleteInput.Create(TpmiDhObject.FromValue(reloadedHandle), ReadOnlySpan<byte>.Empty, TpmiRhHierarchy.Owner, pool);
        using TpmPasswordSession completeAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<SequenceCompleteResponse> completed = await TpmCommandExecutor.ExecuteAsync<SequenceCompleteResponse>(
            tpm, completeInput, [completeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(completed.IsSuccess, $"TPM2_SequenceComplete() over the reloaded sequence must succeed: '{completed.ResponseCode}'.");
        completed.Value.Dispose();
    }

    /// <summary>
    /// "The handle associated with a session does not change as long as the session is active.": a saved,
    /// then reloaded HMAC session answers the SAME handle it was saved from, and a following unauthenticated
    /// command over it still succeeds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.5</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadHmacSessionRestoresAtSameHandleAndUsable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextLoadHmacSessionRestoresAtSameHandleAndUsable), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
            Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() of the session must succeed: '{saved.ResponseCode}'.");
            using ContextSaveResponse savedResponse = saved.Value;
            Assert.AreEqual(sessionHandle, savedResponse.Context.SavedHandle.Value, "A session's savedHandle is the session's own handle (Table 58).");
            Assert.AreEqual((uint)TpmRh.TPM_RH_NULL, savedResponse.Context.Hierarchy.Value, "A session context belongs to the NULL hierarchy (Part 2, clause 14.6.3).");

            TpmResult<ContextLoadResponse> loaded = await LoadAsync(tpm, registry, pool, savedResponse.Context).ConfigureAwait(false);
            Assert.IsTrue(loaded.IsSuccess, $"TPM2_ContextLoad() of the session must succeed: '{loaded.ResponseCode}'.");
            Assert.AreEqual(sessionHandle, loaded.Value.LoadedHandle.Value, "A reloaded session must be reinstalled at the SAME handle it was saved from.");

            TpmResult<NvGlobalWriteLockResponse> lockResult = await IssueGlobalWriteLockOverSessionAsync(tpm, registry, pool, session).ConfigureAwait(false);
            Assert.IsTrue(lockResult.IsSuccess, $"A following command authorized by the reloaded session must succeed: '{lockResult.ResponseCode}'.");
        }
    }

    /// <summary>
    /// A saved, then reloaded policy session likewise answers the SAME handle, and <c>TPM2_PolicyGetDigest()</c>
    /// over it still succeeds — proof the session is genuinely reinstalled rather than merely accepted.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.5</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadPolicySessionRestoresAtSameHandleAndUsable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextLoadPolicySessionRestoresAtSameHandleAndUsable), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartUnboundPolicySessionHandleAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() of the policy session must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse savedResponse = saved.Value;

        TpmResult<ContextLoadResponse> loaded = await LoadAsync(tpm, registry, pool, savedResponse.Context).ConfigureAwait(false);
        Assert.IsTrue(loaded.IsSuccess, $"TPM2_ContextLoad() of the policy session must succeed: '{loaded.ResponseCode}'.");
        Assert.AreEqual(sessionHandle, loaded.Value.LoadedHandle.Value, "A reloaded policy session must be reinstalled at the SAME handle it was saved from.");

        TpmResult<PolicyGetDigestResponse> digest = await TpmCommandExecutor.ExecuteAsync<PolicyGetDigestResponse>(
            tpm, PolicyGetDigestInput.ForSession(sessionHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(digest.IsSuccess, $"TPM2_PolicyGetDigest() over the reloaded session must succeed: '{digest.ResponseCode}'.");
        digest.Value.Dispose();
    }

    /// <summary>
    /// "If an input value for sequence is larger than the value used in any saved context, the TPM shall return
    /// an error (TPM_RC_VALUE)": a blob whose <c>sequence</c> field is rewritten one past the counter it was
    /// saved under is refused, for both an object blob and a session blob.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 14.6.1</see>.
    /// </summary>
    /// <param name="isSession">Whether the tampered blob is a session's (versus an object's).</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task ContextLoadSequenceAboveTheCounterIsRefusedWithValue(bool isSession)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(ContextLoadSequenceAboveTheCounterIsRefusedWithValue)}-{isSession}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint handle;
        if(isSession)
        {
            (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
            using(session)
            {
                handle = sessionHandle;
            }
        }
        else
        {
            using CreatePrimaryResponse key = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
            handle = key.ObjectHandle.Value;
        }

        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, handle).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse savedResponse = saved.Value;

        using TpmsContext tampered = WithMetadata(savedResponse.Context, pool, savedResponse.Context.Sequence + 1, savedResponse.Context.SavedHandle.Value, savedResponse.Context.Hierarchy.Value);
        TpmResult<ContextLoadResponse> loaded = await LoadAsync(tpm, registry, pool, tampered).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), loaded.ResponseCode, "A sequence one past the counter it was saved under must be TPM_RC_VALUE (Part 2, clause 14.6.1).");
    }

    /// <summary>
    /// The near side of clause 14.6.1's session-sequence inequality — "if the input value for sequence is less
    /// than the current value of contextID minus the maximum range for sessions" — proved from the direction
    /// that is cheap to reach. Table 28 sizes that maximum range: "TPM_PT_CONTEXT_GAP_MAX ... the maximum
    /// allowed difference (unsigned) between the contextID values of two saved session contexts ... This value
    /// shall be 2 - 1, where n is at least 16." (TPM 2.0 Library Part 2, clause 6.13, Table 28) — this TPM's
    /// maximum range is 65 536, so the property it derives from reports 65 535 (2^16 minus one). The far side
    /// of the inequality — a session blob more than 65 536 saves old — is refused with TPM_RC_VALUE (clause
    /// 14.6.1) but needs 65 537 session saves to reach, so no test here drives it; this proves only the near
    /// side: a saved session blob still loads once the session counter has advanced by a few further session
    /// saves, nowhere near the boundary.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 14.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadSessionBlobStillLoadsAfterThreeFurtherSessionSaves()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextLoadSessionBlobStillLoadsAfterThreeFurtherSessionSaves), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint firstHandle, TpmSession firstSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        ContextSaveResponse firstSaved;
        using(firstSession)
        {
            TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, firstHandle).ConfigureAwait(false);
            Assert.IsTrue(saved.IsSuccess, $"The first session's save must succeed: '{saved.ResponseCode}'.");
            firstSaved = saved.Value;
        }

        for(int i = 0; i < 3; i++)
        {
            (uint otherHandle, TpmSession otherSession) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
            using(otherSession)
            {
                TpmResult<ContextSaveResponse> otherSaved = await SaveAsync(tpm, registry, pool, otherHandle).ConfigureAwait(false);
                Assert.IsTrue(otherSaved.IsSuccess, $"Advancing save {i} must succeed: '{otherSaved.ResponseCode}'.");
                otherSaved.Value.Dispose();
            }
        }

        using(firstSaved)
        {
            TpmResult<ContextLoadResponse> loaded = await LoadAsync(tpm, registry, pool, firstSaved.Context).ConfigureAwait(false);
            Assert.IsTrue(loaded.IsSuccess, $"The first session's blob must still load after three further session saves, far below the 65 536-wide range: '{loaded.ResponseCode}'.");
            Assert.AreEqual(firstHandle, loaded.Value.LoadedHandle.Value, "The reloaded handle must be the first session's own.");
        }
    }

    /// <summary>
    /// "If an input value for handle is outside of the range of values used by the TPM, the TPM shall return an
    /// error (TPM_RC_VALUE)": a <c>savedHandle</c> outside Table 58's five admitted arms is refused at parse.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 14.6.2</see>.
    /// </summary>
    /// <param name="badSavedHandle">The unadmitted <c>savedHandle</c> value.</param>
    [TestMethod]
    [DataRow(SavedHandleOneAboveTheFixedArms)]
    [DataRow(SavedHandleInTheNvIndexRange)]
    public async Task ContextLoadSavedHandleOutsideTable58IsRefusedWithValue(uint badSavedHandle)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(ContextLoadSavedHandleOutsideTable58IsRefusedWithValue)}-{badSavedHandle:X8}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, key.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse savedResponse = saved.Value;

        using TpmsContext tampered = WithMetadata(savedResponse.Context, pool, savedResponse.Context.Sequence, badSavedHandle, savedResponse.Context.Hierarchy.Value);
        TpmResult<ContextLoadResponse> loaded = await LoadAsync(tpm, registry, pool, tampered).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, parameterIndex: 0), loaded.ResponseCode,
            $"Table 226: context is TPM2_ContextLoad()'s sole parameter (index 0); savedHandle 0x{badSavedHandle:X8} is outside Table 58's five admitted arms.");
    }

    /// <summary>
    /// "If the savedHandle value in the context is changed by software, the context will not load.": an
    /// ordinary object's blob re-presented with its metadata <c>savedHandle</c> rewritten to another Table 58
    /// arm — still admitted at parse, since both rewritten values name one of Table 58's five arms — fails the
    /// recomputed HMAC: equation 52's <c>data = resetValue { clearCount } sequence handle encContext</c> folds
    /// <c>handle</c> (the <c>savedHandle</c> the context carries) into the integrity computation (Part 1,
    /// clause 27.3.2).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.2.3</see>.
    /// </summary>
    /// <param name="rewrittenSavedHandle">The admitted-but-wrong Part 2 Table 58 arm presented in place of the genuine <see cref="TpmiDhSaved.OrdinaryTransientObject"/> value.</param>
    [TestMethod]
    [DataRow(TpmiDhSaved.SequenceObject)]
    [DataRow(TpmiDhSaved.StClearTransientObject)]
    public async Task ContextLoadSavedHandleRewrittenToAnotherAdmittedArmIsRefusedWithIntegrity(uint rewrittenSavedHandle)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(ContextLoadSavedHandleRewrittenToAnotherAdmittedArmIsRefusedWithIntegrity)}-{rewrittenSavedHandle:X8}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, key.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse savedResponse = saved.Value;
        Assert.AreEqual(TpmiDhSaved.OrdinaryTransientObject, savedResponse.Context.SavedHandle.Value, "An ordinary object saves under Table 58's OrdinaryTransientObject value.");

        using TpmsContext tampered = WithMetadata(savedResponse.Context, pool, savedResponse.Context.Sequence, rewrittenSavedHandle, savedResponse.Context.Hierarchy.Value);
        TpmResult<ContextLoadResponse> loaded = await LoadAsync(tpm, registry, pool, tampered).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INTEGRITY, 0), loaded.ResponseCode, $"savedHandle rewritten from 0x{TpmiDhSaved.OrdinaryTransientObject:X8} to the admitted 0x{rewrittenSavedHandle:X8} must fail the recomputed HMAC at context, parameter 1 of Table 226.");
    }

    /// <summary>
    /// Table 59's admitted set is <c>TPM_RH_OWNER</c>, <c>TPM_RH_PLATFORM</c>, <c>TPM_RH_ENDORSEMENT</c> and
    /// <c>TPM_RH_NULL</c> alone: a <c>hierarchy</c> field rewritten to <c>TPM_RH_LOCKOUT</c> is refused at parse,
    /// before the effect ever derives a proof.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.13, Table 59</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadHierarchyOutsideTable59IsRefusedWithValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextLoadHierarchyOutsideTable59IsRefusedWithValue), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, key.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse savedResponse = saved.Value;

        using TpmsContext tampered = WithMetadata(savedResponse.Context, pool, savedResponse.Context.Sequence, savedResponse.Context.SavedHandle.Value, (uint)TpmRh.TPM_RH_LOCKOUT);
        TpmResult<ContextLoadResponse> loaded = await LoadAsync(tpm, registry, pool, tampered).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, parameterIndex: 0), loaded.ResponseCode,
            "Table 226: context is TPM2_ContextLoad()'s sole parameter (index 0); TPM_RH_LOCKOUT is outside Table 59's four admitted hierarchy selectors.");
    }

    /// <summary>
    /// A blob shorter than the fingerprint that must follow the integrity field, and a blob whose leading
    /// declared digest width is not the genuine 32 octets, are both refused: "context.savedHandle does not
    /// reference a saved session" is not this gate — the size check runs first, before the HMAC is even
    /// recomputed.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.3.1</see>.
    /// </summary>
    /// <param name="isTruncated">Whether the blob is cut short (versus keeping its length but lying about the digest width).</param>
    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task ContextLoadTruncatedOrWrongIntegrityWidthIsRefusedWithSize(bool isTruncated)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync($"{nameof(ContextLoadTruncatedOrWrongIntegrityWidthIsRefusedWithSize)}-{isTruncated}", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, key.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse savedResponse = saved.Value;

        byte[] malformed = isTruncated
            ? savedResponse.Context.ContextBlob.Span[..TruncatedBlobLength].ToArray()
            : WithLeadingDigestWidth(savedResponse.Context.ContextBlob.Span, WrongIntegrityWidth);

        using TpmsContext tampered = WithBlob(savedResponse.Context, pool, malformed);
        TpmResult<ContextLoadResponse> loaded = await LoadAsync(tpm, registry, pool, tampered).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), loaded.ResponseCode, isTruncated ? "A blob shorter than the fingerprint must be TPM_RC_SIZE at context, parameter 1 of Table 226." : "A blob whose leading declared digest width is not 32 must be TPM_RC_SIZE at context, parameter 1 of Table 226.");
    }

    /// <summary>
    /// "If the integrity HMAC of the saved context is not valid, the TPM shall return TPM_RC_INTEGRITY.": one
    /// octet flipped inside the encrypted region (past the leading integrity field) invalidates the recomputed
    /// HMAC.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadTamperedEncryptedRegionIsRefusedWithIntegrity()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextLoadTamperedEncryptedRegionIsRefusedWithIntegrity), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, key.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse savedResponse = saved.Value;

        byte[] flipped = FlipOctet(savedResponse.Context.ContextBlob.Span, IntegrityFieldSize);
        using TpmsContext tampered = WithBlob(savedResponse.Context, pool, flipped);
        TpmResult<ContextLoadResponse> loaded = await LoadAsync(tpm, registry, pool, tampered).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INTEGRITY, 0), loaded.ResponseCode, "A flipped octet inside the encrypted region must invalidate the recomputed HMAC at context, parameter 1 of Table 226.");
    }

    /// <summary>
    /// The mirror case: one octet flipped inside the leading integrity digest itself (not the ciphertext it
    /// protects) equally invalidates the fixed-time comparison against the recomputed HMAC.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadTamperedIntegrityDigestIsRefusedWithIntegrity()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextLoadTamperedIntegrityDigestIsRefusedWithIntegrity), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, key.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse savedResponse = saved.Value;

        byte[] flipped = FlipOctet(savedResponse.Context.ContextBlob.Span, sizeof(ushort));
        using TpmsContext tampered = WithBlob(savedResponse.Context, pool, flipped);
        TpmResult<ContextLoadResponse> loaded = await LoadAsync(tpm, registry, pool, tampered).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INTEGRITY, 0), loaded.ResponseCode, "A flipped octet inside the integrity digest itself must fail the fixed-time comparison at context, parameter 1 of Table 226.");
    }

    /// <summary>
    /// "the sequence value of the decrypted context does not match the value in the sequence parameter": the
    /// SAVED-BLOB's own metadata <c>sequence</c> rewritten to an earlier, still-in-range value (rather than the
    /// value the HMAC was actually computed over) fails integrity — proved by saving two objects and presenting
    /// the second blob together with the first blob's sequence number.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 14.5</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadMetadataSequenceRewrittenSmallerButWithinRangeIsRefusedWithIntegrity()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextLoadMetadataSequenceRewrittenSmallerButWithinRangeIsRefusedWithIntegrity), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse firstKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmResult<ContextSaveResponse> firstSaved = await SaveAsync(tpm, registry, pool, firstKey.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(firstSaved.IsSuccess, $"The first save must succeed: '{firstSaved.ResponseCode}'.");
        using ContextSaveResponse firstSavedResponse = firstSaved.Value;

        using CreatePrimaryResponse secondKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmResult<ContextSaveResponse> secondSaved = await SaveAsync(tpm, registry, pool, secondKey.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(secondSaved.IsSuccess, $"The second save must succeed: '{secondSaved.ResponseCode}'.");
        using ContextSaveResponse secondSavedResponse = secondSaved.Value;
        Assert.IsGreaterThan(firstSavedResponse.Context.Sequence, secondSavedResponse.Context.Sequence, "The second object's sequence must be strictly greater than the first's (the shared object counter).");

        using TpmsContext tampered = WithMetadata(secondSavedResponse.Context, pool, firstSavedResponse.Context.Sequence, secondSavedResponse.Context.SavedHandle.Value, secondSavedResponse.Context.Hierarchy.Value);
        TpmResult<ContextLoadResponse> loaded = await LoadAsync(tpm, registry, pool, tampered).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INTEGRITY, 0), loaded.ResponseCode, "A smaller-but-in-range sequence still fails integrity: the HMAC was computed over the ORIGINAL sequence, not the presented one, at context, parameter 1 of Table 226.");
    }

    /// <summary>
    /// The HMAC message folds <c>savedHandle</c> — a <c>hierarchy</c> field rewritten from the object's true
    /// hierarchy to another ADMITTED-but-wrong one selects a different proof, failing the recomputed HMAC even
    /// though both hierarchies remain enabled.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.3.2, equation 52</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadHierarchyRewrittenToAnotherEnabledHierarchyIsRefusedWithIntegrity()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextLoadHierarchyRewrittenToAnotherEnabledHierarchyIsRefusedWithIntegrity), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, key.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse savedResponse = saved.Value;
        Assert.AreEqual((uint)TpmRh.TPM_RH_OWNER, savedResponse.Context.Hierarchy.Value, "The decrypt key is created under the owner hierarchy.");

        using TpmsContext tampered = WithMetadata(savedResponse.Context, pool, savedResponse.Context.Sequence, savedResponse.Context.SavedHandle.Value, (uint)TpmRh.TPM_RH_ENDORSEMENT);
        TpmResult<ContextLoadResponse> loaded = await LoadAsync(tpm, registry, pool, tampered).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INTEGRITY, 0), loaded.ResponseCode, "The endorsement proof does not match the HMAC computed under the owner proof, even with the endorsement hierarchy enabled, at context, parameter 1 of Table 226.");
    }

    /// <summary>
    /// "The TPM will return TPM_RC_HIERARCHY if the context is associated with a hierarchy that is disabled.":
    /// an object saved under the owner hierarchy, whose hierarchy is disabled AFTER the save, is refused at
    /// load — judged after integrity passes.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadObjectHierarchyDisabledAfterSaveIsRefusedWithHierarchy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextLoadObjectHierarchyDisabledAfterSaveIsRefusedWithHierarchy), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, key.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse savedResponse = saved.Value;

        await DisableOwnerHierarchyAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<ContextLoadResponse> loaded = await LoadAsync(tpm, registry, pool, savedResponse.Context).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), loaded.ResponseCode, "A saved context whose hierarchy is now disabled must be TPM_RC_HIERARCHY.");
    }

    /// <summary>
    /// "a saved session context may only be loaded once. These limitations on the session context are intended
    /// to prevent possible attacks based on replay of authorizations.": a session blob loaded once, then
    /// presented again, is refused the second time.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.5</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadReplayedSessionBlobIsRefusedWithHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextLoadReplayedSessionBlobIsRefusedWithHandle), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        session.Dispose();

        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() of the session must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse savedResponse = saved.Value;

        TpmResult<ContextLoadResponse> firstLoad = await LoadAsync(tpm, registry, pool, savedResponse.Context).ConfigureAwait(false);
        Assert.IsTrue(firstLoad.IsSuccess, $"The first load must succeed: '{firstLoad.ResponseCode}'.");

        TpmResult<ContextLoadResponse> replayedLoad = await LoadAsync(tpm, registry, pool, savedResponse.Context).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), replayedLoad.ResponseCode, "The tracking entry is consumed on the first load; a replayed session blob must be TPM_RC_HANDLE.");
    }

    /// <summary>
    /// "a saved session context may only be loaded once.": a session saved, reloaded, and saved again names a
    /// tracking entry against its NEWER blob's sequence alone. The OLDER blob (loaded once already, so not
    /// itself a replay of anything unconsumed) is refused because the tracked sequence disagrees with the one
    /// it carries — the entry stays present, naming the newer blob, until that newer blob consumes it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.5</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadOlderBlobAfterResaveIsRefusedWithHandleThenNewerBlobSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextLoadOlderBlobAfterResaveIsRefusedWithHandleThenNewerBlobSucceeds), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        session.Dispose();

        TpmResult<ContextSaveResponse> olderSaved = await SaveAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        Assert.IsTrue(olderSaved.IsSuccess, $"The first save must succeed: '{olderSaved.ResponseCode}'.");
        using ContextSaveResponse olderSavedResponse = olderSaved.Value;

        TpmResult<ContextLoadResponse> firstLoad = await LoadAsync(tpm, registry, pool, olderSavedResponse.Context).ConfigureAwait(false);
        Assert.IsTrue(firstLoad.IsSuccess, $"Loading the first blob must succeed: '{firstLoad.ResponseCode}'.");

        TpmResult<ContextSaveResponse> newerSaved = await SaveAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        Assert.IsTrue(newerSaved.IsSuccess, $"Saving the session again must succeed: '{newerSaved.ResponseCode}'.");
        using ContextSaveResponse newerSavedResponse = newerSaved.Value;
        Assert.IsGreaterThan(olderSavedResponse.Context.Sequence, newerSavedResponse.Context.Sequence, "The second save's sequence must be strictly greater than the first's (the shared session counter).");

        TpmResult<ContextLoadResponse> olderLoad = await LoadAsync(tpm, registry, pool, olderSavedResponse.Context).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), olderLoad.ResponseCode, "The tracking entry now names the newer blob's sequence, not the older blob's; presenting the older blob must be TPM_RC_HANDLE.");

        TpmResult<ContextLoadResponse> newerLoad = await LoadAsync(tpm, registry, pool, newerSavedResponse.Context).ConfigureAwait(false);
        Assert.IsTrue(newerLoad.IsSuccess, $"The newer blob's sequence matches the tracking entry it left behind, so it must succeed: '{newerLoad.ResponseCode}'.");
    }

    /// <summary>
    /// "A session does not have to be loaded in TPM memory to have its context flushed. The saved session
    /// context associated with the indicated handle is invalidated.": flushing a SAVED (not loaded) session's
    /// handle succeeds, a load of the blob is refused afterward, and flushing the same handle again also
    /// fails — the tracking entry, once consumed, names nothing.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadSavedSessionFlushedThenLoadedIsRefusedWithHandleAndFlushedAgainIsAlsoHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextLoadSavedSessionFlushedThenLoadedIsRefusedWithHandleAndFlushedAgainIsAlsoHandle), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        session.Dispose();

        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() of the session must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse savedResponse = saved.Value;

        TpmResult<FlushContextResponse> firstFlush = await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        Assert.IsTrue(firstFlush.IsSuccess, $"Flushing the SAVED session's own handle must succeed (Part 3, clause 28.4.1): '{firstFlush.ResponseCode}'.");

        TpmResult<ContextLoadResponse> loaded = await LoadAsync(tpm, registry, pool, savedResponse.Context).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), loaded.ResponseCode, "The flush invalidated the saved session context; loading it afterward must be TPM_RC_HANDLE.");

        TpmResult<FlushContextResponse> secondFlush = await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), secondFlush.ResponseCode, "The tracking entry was already consumed by the first flush; the handle now names nothing.");
    }

    /// <summary>
    /// The object slot gate is judged LAST, after the hierarchy gate: an object blob loaded once every one of
    /// <see cref="TpmSimulatorState.MaxLoadedObjects"/> transient slots is occupied is
    /// <c>TPM_RC_OBJECT_MEMORY</c>; the SAME blob, once its own
    /// hierarchy is subsequently disabled, is instead <c>TPM_RC_HIERARCHY</c> — the earlier gate fires even
    /// though the slot condition still holds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadObjectMemoryFullIsObjectMemoryThenHierarchyGateFiresFirstOnceDisabled()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextLoadObjectMemoryFullIsObjectMemoryThenHierarchyGateFiresFirstOnceDisabled), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subjectKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, subjectKey.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse savedResponse = saved.Value;

        for(int i = 0; i < TpmSimulatorState.MaxLoadedObjects - 1; i++)
        {
            using CreatePrimaryResponse fillerKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        }

        TpmResult<ContextLoadResponse> loadedWhileFull = await LoadAsync(tpm, registry, pool, savedResponse.Context).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_OBJECT_MEMORY, loadedWhileFull.ResponseCode, $"All {TpmSimulatorState.MaxLoadedObjects} transient slots are occupied; the slot gate must refuse the load.");

        await DisableOwnerHierarchyAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<ContextLoadResponse> loadedWhileFullAndDisabled = await LoadAsync(tpm, registry, pool, savedResponse.Context).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), loadedWhileFullAndDisabled.ResponseCode, "With the hierarchy ALSO disabled, the hierarchy gate must fire first — the slot gate is judged last.");
    }

    /// <summary>
    /// "No authorization sessions of any type are allowed with this command and tag is required to be
    /// TPM_ST_NO_SESSIONS": <c>TPM_ST_SESSIONS</c> is refused with <c>TPM_RC_BAD_TAG</c>, before the parameter
    /// area is even read.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadSessionsTagIsRefusedWithBadTag()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = CreatePoweredOff(nameof(ContextLoadSessionsTagIsRefusedWithBadTag));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateOnDeviceRsaDecryptKeyAsync(simulator, registry, pool).ConfigureAwait(false);
        TpmResult<ContextSaveResponse> saved = await SaveOnDeviceAsync(simulator, registry, pool, key.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse savedResponse = saved.Value;

        TpmRcConstants responseCode = await SubmitContextLoadFramedAsync(simulator, pool, savedResponse.Context, (ushort)TpmStConstants.TPM_ST_SESSIONS, []).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_TAG, responseCode, "TPM_ST_SESSIONS on TPM2_ContextLoad() must be TPM_RC_BAD_TAG.");
    }

    /// <summary>
    /// An octet trailing an otherwise well-formed <c>TPMS_CONTEXT</c> parameter area is <c>TPM_RC_SIZE</c>
    /// (clause 5.2's own framing discipline, exercised through this command's parameter-only body).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.3</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadTrailingOctetIsRefusedWithSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = CreatePoweredOff(nameof(ContextLoadTrailingOctetIsRefusedWithSize));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse key = await CreateOnDeviceRsaDecryptKeyAsync(simulator, registry, pool).ConfigureAwait(false);
        TpmResult<ContextSaveResponse> saved = await SaveOnDeviceAsync(simulator, registry, pool, key.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse savedResponse = saved.Value;

        TpmRcConstants responseCode = await SubmitContextLoadFramedAsync(simulator, pool, savedResponse.Context, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS, [0xA5]).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, responseCode, "A trailing octet after a well-formed TPMS_CONTEXT parameter area must be TPM_RC_SIZE.");
    }

    /// <summary>
    /// "TPM_RC_INITIALIZE": a command submitted before <c>TPM2_Startup()</c> is refused before any of
    /// <c>TPM2_ContextLoad()</c>'s own rules run.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 12.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadPreStartupIsRefusedWithInitialize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = CreatePoweredOff(nameof(ContextLoadPreStartupIsRefusedWithInitialize));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmsContext placeholder = PlaceholderContext(pool);
        TpmResult<ContextLoadResponse> loaded = await LoadAsync(tpm, registry, pool, placeholder).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_INITIALIZE, loaded.ResponseCode, "Before TPM2_Startup() every command is TPM_RC_INITIALIZE (Part 1, clause 12.2).");
    }

    /// <summary>
    /// "TPM_RC_FAILURE": once a failed self-test has entered Failure Mode, <c>TPM2_ContextLoad()</c> is refused
    /// before its own rules run, exactly like every other command Failure Mode does not specifically admit.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 12.3</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadFailureModeIsRefusedWithFailure()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = new TpmSimulator(
            $"tpm-in-house-context-load-{nameof(ContextLoadFailureModeIsRefusedWithFailure)}",selfTest: TpmSelfTestBehavior.Fails, rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);
        TpmRcConstants selfTestCode = await SubmitSelfTestAsync(simulator, pool).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, selfTestCode, "A failing self-test enters Failure Mode.");

        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmsContext placeholder = PlaceholderContext(pool);
        TpmResult<ContextLoadResponse> loaded = await LoadAsync(tpm, registry, pool, placeholder).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, loaded.ResponseCode, "In Failure Mode TPM2_ContextLoad() is TPM_RC_FAILURE (Part 1, clause 12.3).");
    }

    /// <summary>
    /// Pool hygiene across every refusal category and a success: a parse refusal (a bad savedHandle), a range
    /// refusal (a sequence above the counter), an integrity refusal (a flipped octet), a feedback refusal (a
    /// replayed session blob), and a success each leave the pool with exactly the carriers outstanding before
    /// them.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.3</see>.
    /// </summary>
    [TestMethod]
    public async Task ContextLoadPoolBalanceAcrossEveryRefusalCategoryAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(nameof(ContextLoadPoolBalanceAcrossEveryRefusalCategoryAndASuccess), pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        session.Dispose();
        TpmResult<ContextSaveResponse> saved = await SaveAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        Assert.IsTrue(saved.IsSuccess, $"TPM2_ContextSave() must succeed: '{saved.ResponseCode}'.");
        using ContextSaveResponse savedResponse = saved.Value;
        long baseline = trackingPool.OutstandingCount;

        using(TpmsContext badSavedHandle = WithMetadata(savedResponse.Context, pool, savedResponse.Context.Sequence, SavedHandleOneAboveTheFixedArms, savedResponse.Context.Hierarchy.Value))
        {
            TpmResult<ContextLoadResponse> parseRefusal = await LoadAsync(tpm, registry, pool, badSavedHandle).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, parameterIndex: 0), parseRefusal.ResponseCode,
                "Table 226: context is TPM2_ContextLoad()'s sole parameter (index 0); a bad savedHandle is refused at parse there.");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A parse refusal returns every carrier it rented.");

        using(TpmsContext aboveCounter = WithMetadata(savedResponse.Context, pool, savedResponse.Context.Sequence + 1, savedResponse.Context.SavedHandle.Value, savedResponse.Context.Hierarchy.Value))
        {
            TpmResult<ContextLoadResponse> rangeRefusal = await LoadAsync(tpm, registry, pool, aboveCounter).ConfigureAwait(false);
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), rangeRefusal.ResponseCode, "A sequence above the counter is refused at the transition.");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A range refusal returns every carrier it rented.");

        byte[] flipped = FlipOctet(savedResponse.Context.ContextBlob.Span, IntegrityFieldSize);
        using(TpmsContext tampered = WithBlob(savedResponse.Context, pool, flipped))
        {
            TpmResult<ContextLoadResponse> integrityRefusal = await LoadAsync(tpm, registry, pool, tampered).ConfigureAwait(false);
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INTEGRITY, 0), integrityRefusal.ResponseCode, "A flipped octet is refused at context, parameter 1 of Table 226.");
        }

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "An integrity refusal returns every carrier it rented.");

        TpmResult<ContextLoadResponse> success = await LoadAsync(tpm, registry, pool, savedResponse.Context).ConfigureAwait(false);
        Assert.IsTrue(success.IsSuccess, $"The genuine session blob must load: '{success.ResponseCode}'.");
        long afterSuccess = trackingPool.OutstandingCount;

        TpmResult<ContextLoadResponse> feedbackRefusal = await LoadAsync(tpm, registry, pool, savedResponse.Context).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), feedbackRefusal.ResponseCode, "The session blob's tracking entry is consumed by the success above; a replay must be TPM_RC_HANDLE.");
        Assert.AreEqual(afterSuccess, trackingPool.OutstandingCount, "The success installs the session's own carriers, which stay outstanding until the session is flushed; the following feedback refusal must not change that count.");
    }

    /// <summary>Creates a not-yet-started simulator identified by <paramref name="name"/> for lifecycle-boundary tests that manage <c>TPM2_Startup()</c> themselves.</summary>
    /// <param name="name">The per-test simulator identifier suffix.</param>
    /// <returns>The powered-off simulator.</returns>
    private static TpmSimulator CreatePoweredOff(string name) =>
        new($"tpm-in-house-context-load-{name}", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch), rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create());

    /// <summary>Creates an operational simulator (powered on and started) with the RSA backend wired.</summary>
    /// <param name="name">The per-test simulator identifier suffix.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(string name, BaseMemoryPool pool)
    {
        TpmSimulator simulator = CreatePoweredOff(name);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an unauthorized command on the wire.</summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed at the transport level.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)TpmHeader.Parse(ref reader).Code, "TPM2_Startup(CLEAR) must succeed.");
    }

    /// <summary>Issues <c>TPM2_SelfTest(NO)</c> directly against the simulator and returns its response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSelfTestAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new SelfTestInput(IsFullTest: false);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer TPM2_SelfTest() rather than fault.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>Builds the codec registry covering every command this class issues.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_ReadPublic, TpmResponseCodec.ReadPublic)
            .Register(TpmCcConstants.TPM_CC_ContextSave, TpmResponseCodec.ContextSave)
            .Register(TpmCcConstants.TPM_CC_ContextLoad, TpmResponseCodec.ContextLoad)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext)
            .Register(TpmCcConstants.TPM_CC_HashSequenceStart, TpmResponseCodec.HashSequenceStart)
            .Register(TpmCcConstants.TPM_CC_SequenceUpdate, TpmResponseCodec.SequenceUpdate)
            .Register(TpmCcConstants.TPM_CC_SequenceComplete, TpmResponseCodec.SequenceComplete)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl)
            .Register(TpmCcConstants.TPM_CC_NV_GlobalWriteLock, TpmResponseCodec.NvGlobalWriteLock)
            .Register(TpmCcConstants.TPM_CC_PolicyGetDigest, TpmResponseCodec.PolicyGetDigest);

    /// <summary>Creates an unrestricted RSA decrypt primary under the owner hierarchy, empty password, dictionary-attack exempt.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaDecryptKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaDecryptKey(TpmRh.TPM_RH_OWNER, password: null, RsaKeyBits, TpmtRsaScheme.Null, pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA decrypt key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Same as <see cref="CreateRsaDecryptKeyAsync"/> but driven straight against a simulator with no long-lived <see cref="TpmDevice"/> in front of it — the lifecycle-boundary framing tests build and dispose their own device around each call.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateOnDeviceRsaDecryptKeyAsync(TpmSimulator simulator, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        return await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
    }

    /// <summary>Issues <c>TPM2_ContextSave()</c> straight against a simulator with no long-lived <see cref="TpmDevice"/> in front of it.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to save.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    private async Task<TpmResult<ContextSaveResponse>> SaveOnDeviceAsync(TpmSimulator simulator, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        return await SaveAsync(tpm, registry, pool, handle).ConfigureAwait(false);
    }

    /// <summary>Issues <c>TPM2_ContextSave()</c> through the production executor.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to save.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    private async Task<TpmResult<ContextSaveResponse>> SaveAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle) =>
        await TpmCommandExecutor.ExecuteAsync<ContextSaveResponse>(
            tpm, ContextSaveInput.ForHandle(handle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

    /// <summary>Issues <c>TPM2_ContextLoad()</c> through the production executor over a BORROWED context.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="context">The context to reload; not owned or disposed by this call.</param>
    /// <returns>The raw result; the caller disposes the value on success.</returns>
    private async Task<TpmResult<ContextLoadResponse>> LoadAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmsContext context) =>
        await TpmCommandExecutor.ExecuteAsync<ContextLoadResponse>(
            tpm, new ContextLoadInput(context), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

    /// <summary>Issues <c>TPM2_FlushContext()</c> through the production executor.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush.</param>
    /// <returns>The raw result.</returns>
    private async Task<TpmResult<FlushContextResponse>> FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle) =>
        await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(handle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

    /// <summary>Issues <c>TPM2_ReadPublic()</c> and asserts it succeeded.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The object handle.</param>
    /// <returns>The response; the caller disposes it.</returns>
    private async Task<ReadPublicResponse> ReadPublicAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        TpmResult<ReadPublicResponse> result = await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
            tpm, ReadPublicInput.ForHandle(TpmiDhObject.FromValue(handle)), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ReadPublic() failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Disables the owner hierarchy through <c>TPM2_HierarchyControl(shEnable, NO)</c> under platform authorization.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task DisableOwnerHierarchyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using TpmPasswordSession platformAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<HierarchyControlResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyControlResponse>(
            tpm, new HierarchyControlInput(TpmRh.TPM_RH_PLATFORM, TpmRh.TPM_RH_OWNER, TpmiYesNo.No), [platformAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HierarchyControl(OWNER, NO) failed: '{result.ResponseCode}'.");
    }

    /// <summary>Opens a SHA-256 hash sequence context with an empty authValue and returns its handle.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The sequence handle.</returns>
    private async Task<uint> StartHashSequenceHandleAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using HashSequenceStartInput input = HashSequenceStartInput.Create([], TpmiAlgHash.FromValue(NameAlg), pool);
        TpmResult<HashSequenceStartResponse> result = await TpmCommandExecutor.ExecuteAsync<HashSequenceStartResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HashSequenceStart() failed: '{result.ResponseCode}'.");

        return result.Value.SequenceHandle.Value;
    }

    /// <summary>Submits <c>TPM2_SequenceUpdate()</c> with the sequence's (empty) password and asserts success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequenceHandle">The open sequence's handle.</param>
    /// <param name="buffer">The block to append.</param>
    private async Task UpdateSequenceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint sequenceHandle, byte[] buffer)
    {
        using TpmPasswordSession sequenceAuth = TpmPasswordSession.CreateEmpty(pool);
        using SequenceUpdateInput input = SequenceUpdateInput.Create(TpmiDhObject.FromValue(sequenceHandle), buffer, pool);
        TpmResult<SequenceUpdateResponse> result = await TpmCommandExecutor.ExecuteAsync<SequenceUpdateResponse>(
            tpm, input, [sequenceAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_SequenceUpdate() failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Starts an unbound, unsalted HMAC session (TPM 2.0 Library Part 1, clause 16.6.9) with an empty authValue,
    /// composing the host session over its response.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session handle and the composed, caller-owned session.</returns>
    private async Task<(uint Handle, TpmSession Session)> StartUnboundHmacSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(NameAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (HMAC) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, NameAlg, TestEntropy.NewCounterStream(), pool);
        session.SetAuthValue(ReadOnlySpan<byte>.Empty, pool);

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Starts an unbound, unsalted policy session and returns its handle alone — no client-side session wrapper is needed since this class only issues the auth-free <c>TPM2_PolicyGetDigest()</c> over it.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The started policy session's handle.</returns>
    private async Task<uint> StartUnboundPolicySessionHandleAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(NameAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse started = startResult.Value;

        return started.SessionHandle.Value;
    }

    /// <summary>Issues <c>TPM2_NV_GlobalWriteLock()</c> under the owner hierarchy over a caller-owned unbound session — a following command that carries no other precondition, over the reloaded session.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="session">The authorizing session.</param>
    /// <returns>The raw result.</returns>
    private async Task<TpmResult<NvGlobalWriteLockResponse>> IssueGlobalWriteLockOverSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmSession session) =>
        await TpmCommandExecutor.ExecuteAsync<NvGlobalWriteLockResponse>(
            tpm, new NvGlobalWriteLockInput(TpmRh.TPM_RH_OWNER), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

    /// <summary>Builds a copy of <paramref name="source"/> with its metadata fields overridden but the SAME blob octets — the vehicle for every metadata-tampering case.</summary>
    /// <param name="source">The genuine, saved context.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sequence">The <c>sequence</c> field to present.</param>
    /// <param name="savedHandle">The raw <c>savedHandle</c> value to present.</param>
    /// <param name="hierarchy">The raw <c>hierarchy</c> value to present.</param>
    /// <returns>The tampered context; the caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented blob transfers to the constructed TpmsContext, which the caller disposes.")]
    private static TpmsContext WithMetadata(TpmsContext source, BaseMemoryPool pool, ulong sequence, uint savedHandle, uint hierarchy)
    {
        Tpm2bContextData blob = Tpm2bContextData.Create(source.ContextBlob.Span, pool);

        return new TpmsContext(sequence, TpmiDhSaved.FromValue(savedHandle), TpmiRhHierarchy.FromValue(hierarchy), blob);
    }

    /// <summary>Builds a copy of <paramref name="source"/> with the SAME metadata but different blob octets — the vehicle for every blob-tampering case.</summary>
    /// <param name="source">The genuine, saved context.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="blobOctets">The replacement blob octets.</param>
    /// <returns>The tampered context; the caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented blob transfers to the constructed TpmsContext, which the caller disposes.")]
    private static TpmsContext WithBlob(TpmsContext source, BaseMemoryPool pool, ReadOnlySpan<byte> blobOctets)
    {
        Tpm2bContextData blob = Tpm2bContextData.Create(blobOctets, pool);

        return new TpmsContext(source.Sequence, source.SavedHandle, source.Hierarchy, blob);
    }

    /// <summary>A syntactically well-formed but semantically arbitrary context — sufficient to reach a lifecycle precondition gate that fires before any of this command's own content is inspected.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The placeholder context; the caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented blob transfers to the constructed TpmsContext, which the caller disposes.")]
    private static TpmsContext PlaceholderContext(BaseMemoryPool pool)
    {
        byte[] blobOctets = new byte[MinimumBlobLength];
        BinaryPrimitives.WriteUInt16BigEndian(blobOctets, 32);
        Tpm2bContextData blob = Tpm2bContextData.Create(blobOctets, pool);

        return new TpmsContext(1, TpmiDhSaved.FromValue(TpmiDhSaved.OrdinaryTransientObject), TpmiRhHierarchy.Null, blob);
    }

    /// <summary>Copies <paramref name="original"/> with the leading <c>UINT16</c> declared digest width overwritten.</summary>
    /// <param name="original">The genuine blob octets.</param>
    /// <param name="width">The declared width to present.</param>
    /// <returns>The malformed copy.</returns>
    private static byte[] WithLeadingDigestWidth(ReadOnlySpan<byte> original, ushort width)
    {
        byte[] copy = original.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(copy, width);

        return copy;
    }

    /// <summary>Copies <paramref name="original"/> with the octet at <paramref name="offset"/> flipped by XOR against <c>0xFF</c>.</summary>
    /// <param name="original">The genuine blob octets.</param>
    /// <param name="offset">The octet offset to flip.</param>
    /// <returns>The tampered copy.</returns>
    private static byte[] FlipOctet(ReadOnlySpan<byte> original, int offset)
    {
        byte[] copy = original.ToArray();
        copy[offset] ^= 0xFF;

        return copy;
    }

    /// <summary>Hand-frames a <c>TPM2_ContextLoad()</c> command with a caller-chosen tag and trailing octets, and returns the response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="context">The context to frame as the parameter area.</param>
    /// <param name="tag">The command tag.</param>
    /// <param name="trailing">Octets appended after the parameter area.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitContextLoadFramedAsync(TpmSimulator simulator, BaseMemoryPool pool, TpmsContext context, ushort tag, byte[] trailing)
    {
        var input = new ContextLoadInput(context);
        int baseLength = TpmHeader.HeaderSize + input.GetSerializedSize();
        int length = baseLength + trailing.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader(tag, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);
        writer.WriteBytes(trailing);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer rather than fault.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }
}
