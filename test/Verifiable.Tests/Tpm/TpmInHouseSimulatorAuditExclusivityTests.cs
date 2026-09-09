using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
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
/// The TPM-wide exclusive-audit-session invariants across the command family, the context-save/load family and
/// the lifecycle arms, and the response-octet law an audited command's session area carries: "The TPM keeps
/// track of the current exclusive session. At most, one active session can have the auditExclusive status."
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1,
/// clause 17.2</see>). Every case is driven through the production wire path
/// (<see cref="TpmCommandExecutor"/> for the ordinary, session-authorized calls; hand-framed submission through
/// <see cref="TpmSimulator.SubmitAsync"/> only where a test needs to set the session-attributes octet itself or
/// read the response's own session entry back) against the in-house behavioural <see cref="TpmSimulator"/>,
/// entirely in-process. Exclusivity is read back through <c>TPM2_GetSessionAuditDigest()</c> with the NULL
/// signer (TPM 2.0 Library Part 3, clause 18.1) — an oracle independent of the simulator's session table, since
/// it reports only what the wire attests; because that very read is itself a session-admitting command that
/// carries no audit session of its own, it clears the TPM-wide exclusive session as a side effect the instant it
/// runs (the same clause 17.2 rule this file proves), so every test performs at most one such read per
/// checkpoint and never reads a session's status as a mid-test premise it still depends on afterward. This class
/// consumes one NV Index, from the handle block <c>0x0100_0260</c>-<c>0x0100_026F</c> reserved for it, to bind a
/// session to a DA-protected entity for the response-octet-law case.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorAuditExclusivityTests
{
    /// <summary>The session/name hash algorithm every session in this class negotiates.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The SHA-256 digest width, in octets — the width of every audit digest and cpHash/rpHash term this class computes.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The octet count every audited <c>TPM2_GetRandom()</c> call in this class requests.</summary>
    private const ushort RandomDrawLength = 16;

    /// <summary>The DA-protected NV Index this class binds a session to, from its assigned handle block.</summary>
    private const uint BoundNvIndexHandle = 0x0100_0260;

    /// <summary>The declared data size of <see cref="BoundNvIndexHandle"/>.</summary>
    private const ushort NvIndexDataSize = 16;

    /// <summary>The non-empty authValue bound to <see cref="BoundNvIndexHandle"/>.</summary>
    private static byte[] NvIndexAuthValueBytes { get; } = [0x51, 0x22, 0x33, 0x44, 0x55, 0x66];

    /// <summary>The octets an authorized <c>TPM2_NV_Write()</c> stores at <see cref="BoundNvIndexHandle"/> ahead of the response-octet-law case.</summary>
    private static byte[] NvWriteDataBytes { get; } = [0x0A, 0x0B, 0x0C, 0x0D];

    /// <summary>The Zero Digest (TPM 2.0 Library Part 1, clause 17.1: "the TPM will initialize the audit hash ... to a Zero Digest"), SHA-256-wide, an audit digest chain starts from on a first use or an auditReset.</summary>
    private static byte[] ZeroDigest { get; } = new byte[Sha256DigestSize];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// "A session becomes the current exclusive audit session when it is first used as an audit session,
    /// regardless of the setting of auditReset. ... The session is no longer the current exclusive audit
    /// session if it is flushed (TPM2_FlushContext()) or if an auditable command is executed that does not use
    /// the current exclusive audit session." (TPM 2.0 Library Part 1, clause 17.2) — session A's first audited
    /// use makes it exclusive; session B's first audited use displaces it; A's own digest is untouched by the
    /// displacement. "If the auditExclusive attribute of an audit session is SET in the command, then the TPM
    /// will return TPM_RC_EXCLUSIVE if the audit session is not the current exclusive audit session." (clause
    /// 17.3) — A's displaced claim of auditExclusive is refused, bare, and leaves A's digest unchanged
    /// ("As with other error returns, no change is made to the state of the session and it remains active.",
    /// ibid.).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.2; clause 17.3</see>.
    /// </summary>
    [TestMethod]
    public async Task SecondAuditSessionUsedTransfersExclusivityAndAFormerExclusiveClaimIsRefused()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "audit-exclusivity-handoff").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint handleA, TpmSession sessionA) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(sessionA)
        {
            (uint handleB, TpmSession sessionB) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
            using(sessionB)
            {
                var inputA = new GetRandomInput(RandomDrawLength);
                sessionA.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                TpmResult<GetRandomResponse> resultA = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    tpm, inputA, [sessionA], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(resultA.IsSuccess, $"A's first audited use must succeed: '{resultA.ResponseCode}'.");
                byte[] expectedDigestA;
                using(GetRandomResponse responseA = resultA.Value)
                {
                    expectedDigestA = await ComputeExpectedAuditDigestAsync(
                        ZeroDigest, inputA, responseA, pool, TestContext.CancellationToken).ConfigureAwait(false);
                }

                await AssertExclusiveAsync(tpm, registry, pool, handleA, expected: true, "A's first audited use must make it the exclusive session.").ConfigureAwait(false);

                sessionB.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                TpmResult<GetRandomResponse> resultB = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    tpm, new GetRandomInput(RandomDrawLength), [sessionB], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(resultB.IsSuccess, $"B's first audited use must succeed: '{resultB.ResponseCode}'.");
                resultB.Value.Dispose();

                await AssertExclusiveAsync(tpm, registry, pool, handleB, expected: true, "B's first audited use must make it the exclusive session.").ConfigureAwait(false);
                await AssertExclusiveAsync(tpm, registry, pool, handleA, expected: false, "A must no longer be the exclusive session once B has been used.").ConfigureAwait(false);

                sessionA.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE;
                TpmResult<GetRandomResponse> refused = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    tpm, new GetRandomInput(RandomDrawLength), [sessionA], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsFalse(refused.IsSuccess, "A displaced session's auditExclusive claim must be refused.");
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_EXCLUSIVE, refused.ResponseCode,
                    "A displaced session's auditExclusive claim must answer the bare TPM_RC_EXCLUSIVE (Part 1, clause 17.3).");

                TpmResult<GetSessionAuditDigestResponse> finalRead = await ReadSessionAuditStatusAsync(tpm, registry, pool, handleA).ConfigureAwait(false);
                Assert.IsTrue(finalRead.IsSuccess, $"TPM2_GetSessionAuditDigest() on A must succeed: '{finalRead.ResponseCode}'.");
                using GetSessionAuditDigestResponse finalStatus = finalRead.Value;
                Assert.IsTrue(
                    expectedDigestA.AsSpan().SequenceEqual(finalStatus.SessionAudit.SessionDigest.AsReadOnlySpan()),
                    "The refused auditExclusive claim must leave A's digest exactly as its first use produced it.");
            }

            await FlushAsync(tpm, registry, pool, handleB).ConfigureAwait(false);
        }

        await FlushAsync(tpm, registry, pool, handleA).ConfigureAwait(false);
    }

    /// <summary>
    /// "This attribute allows the caller to restart an audit sequence with a session that has previously been
    /// used for audit. If the associated command completes successfully, the TPM will initialize the session
    /// audit hash with 0...0 before Extending the cpHash and the rpHash. The response will have the exclusive
    /// attribute SET." (TPM 2.0 Library Part 1, clause 15.6.4, Table 15, the <c>auditReset</c> row) — a session
    /// already established as audit but displaced by another session's use reclaims exclusivity and re-zeroes
    /// its digest, rather than chaining onward from the digest it carried before the reset, the moment it is
    /// used with <c>auditReset</c> SET.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.6.4, Table 15</see>.
    /// </summary>
    [TestMethod]
    public async Task AuditResetOnADisplacedSessionReclaimsExclusivityAndRezeroesTheDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "audit-exclusivity-reset").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint handleA, TpmSession sessionA) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(sessionA)
        {
            (uint handleB, TpmSession sessionB) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
            using(sessionB)
            {
                sessionA.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                TpmResult<GetRandomResponse> firstUseA = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    tpm, new GetRandomInput(RandomDrawLength), [sessionA], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(firstUseA.IsSuccess, $"A's first audited use must succeed: '{firstUseA.ResponseCode}'.");
                firstUseA.Value.Dispose();

                sessionB.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
                TpmResult<GetRandomResponse> useB = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    tpm, new GetRandomInput(RandomDrawLength), [sessionB], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(useB.IsSuccess, $"B's use must succeed and displace A: '{useB.ResponseCode}'.");
                useB.Value.Dispose();

                var resetInput = new GetRandomInput(RandomDrawLength);
                sessionA.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_RESET;
                TpmResult<GetRandomResponse> resetUse = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    tpm, resetInput, [sessionA], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(resetUse.IsSuccess, $"A's auditReset-claiming use must succeed: '{resetUse.ResponseCode}'.");
                byte[] expectedDigest;
                using(GetRandomResponse resetResponse = resetUse.Value)
                {
                    expectedDigest = await ComputeExpectedAuditDigestAsync(
                        ZeroDigest, resetInput, resetResponse, pool, TestContext.CancellationToken).ConfigureAwait(false);
                }

                TpmResult<GetSessionAuditDigestResponse> read = await ReadSessionAuditStatusAsync(tpm, registry, pool, handleA).ConfigureAwait(false);
                Assert.IsTrue(read.IsSuccess, $"TPM2_GetSessionAuditDigest() on A must succeed: '{read.ResponseCode}'.");
                using GetSessionAuditDigestResponse status = read.Value;
                Assert.IsTrue(status.SessionAudit.ExclusiveSession.IsYes, "auditReset must reclaim exclusivity for A (Part 1, clause 17.2).");
                Assert.IsTrue(
                    expectedDigest.AsSpan().SequenceEqual(status.SessionAudit.SessionDigest.AsReadOnlySpan()),
                    "auditReset must re-zero A's digest before extending it, not chain onward from the pre-reset value.");
            }

            await FlushAsync(tpm, registry, pool, handleB).ConfigureAwait(false);
        }

        await FlushAsync(tpm, registry, pool, handleA).ConfigureAwait(false);
    }

    /// <summary>
    /// "A command that is not allowed to have any sessions will not change the current exclusive audit session.
    /// Those commands include the context management commands (TPM2_ContextSave(), TPM2_ContextLoad(), and
    /// TPM2_Flush())..." (TPM 2.0 Library Part 1, clause 17.2) — saving and reloading the exclusive session
    /// itself leaves its own exclusivity untouched.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ExclusiveSessionSurvivesItsOwnContextSaveAndReload()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "audit-exclusivity-self-save").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint handle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            TpmResult<GetRandomResponse> use = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                tpm, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(use.IsSuccess, $"The audited use must succeed: '{use.ResponseCode}'.");
            use.Value.Dispose();

            using ContextSaveResponse saved = await SaveContextAsync(tpm, registry, pool, handle).ConfigureAwait(false);
            TpmResult<ContextLoadResponse> loaded = await SubmitContextLoadAsync(tpm, registry, pool, saved.Context).ConfigureAwait(false);
            Assert.IsTrue(loaded.IsSuccess, $"Reloading the exclusive session's own saved blob must succeed: '{loaded.ResponseCode}'.");
            Assert.AreEqual(handle, loaded.Value.LoadedHandle.Value, "A saved session context loads at the SAME handle it was saved from.");

            await AssertExclusiveAsync(tpm, registry, pool, handle, expected: true, "TPM2_ContextSave()/TPM2_ContextLoad() of the exclusive session must not clear its own exclusivity.").ConfigureAwait(false);
        }

        await FlushAsync(tpm, registry, pool, handle).ConfigureAwait(false);
    }

    /// <summary>
    /// "A command that is not allowed to have any sessions will not change the current exclusive audit session.
    /// Those commands include the context management commands (TPM2_ContextSave(), TPM2_ContextLoad(), and
    /// TPM2_Flush())..." (TPM 2.0 Library Part 1, clause 17.2) — saving and reloading an UNRELATED object leaves
    /// the exclusive audit session's status untouched.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ExclusiveSessionSurvivesContextSaveAndReloadOfAnUnrelatedObject()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "audit-exclusivity-object-save").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        //The object is created BEFORE the audit session is used, so its own password-authorized CreatePrimary()
        //(itself a successful session-admitting command without an audit session) cannot displace an
        //exclusivity this test has not established yet.
        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        (uint handle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            TpmResult<GetRandomResponse> use = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                tpm, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(use.IsSuccess, $"The audited use must succeed: '{use.ResponseCode}'.");
            use.Value.Dispose();

            using ContextSaveResponse saved = await SaveContextAsync(tpm, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
            TpmResult<ContextLoadResponse> loaded = await SubmitContextLoadAsync(tpm, registry, pool, saved.Context).ConfigureAwait(false);
            Assert.IsTrue(loaded.IsSuccess, $"Reloading the unrelated object must succeed: '{loaded.ResponseCode}'.");
            await FlushAsync(tpm, registry, pool, loaded.Value.LoadedHandle.Value).ConfigureAwait(false);

            await AssertExclusiveAsync(tpm, registry, pool, handle, expected: true, "TPM2_ContextSave()/TPM2_ContextLoad() of an unrelated object must not clear the exclusive audit session.").ConfigureAwait(false);
        }

        await FlushAsync(tpm, registry, pool, handle).ConfigureAwait(false);
    }

    /// <summary>
    /// "The session is no longer the current exclusive audit session if it is flushed (TPM2_FlushContext())..."
    /// (TPM 2.0 Library Part 1, clause 17.2) — flushing the loaded, exclusive session releases its tracking
    /// entirely: a freshly started session has never been designated for audit ("A session does not become an
    /// audit session until the successful completion of the command in which the session is first used as an
    /// audit session.", Part 3, clause 18.5.1, note), and its own first audited use is admitted and becomes
    /// exclusive cleanly, with nothing left over from the flushed session to interfere.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.2</see>.
    /// </summary>
    [TestMethod]
    public async Task FlushOfTheLoadedExclusiveSessionReleasesItAndAFreshSessionStartsClean()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "audit-exclusivity-flush-loaded").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint handleA, TpmSession sessionA) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        sessionA.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
        TpmResult<GetRandomResponse> use = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            tpm, new GetRandomInput(RandomDrawLength), [sessionA], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(use.IsSuccess, $"A's audited use must succeed: '{use.ResponseCode}'.");
        use.Value.Dispose();
        sessionA.Dispose();

        await FlushAsync(tpm, registry, pool, handleA).ConfigureAwait(false);

        TpmResult<GetSessionAuditDigestResponse> onA = await ReadSessionAuditStatusAsync(tpm, registry, pool, handleA).ConfigureAwait(false);
        Assert.IsFalse(onA.IsSuccess, "A's flushed handle must no longer be loaded.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_REFERENCE_H2, onA.ResponseCode, "TPM2_GetSessionAuditDigest()'s sessionHandle is the 3rd handle in the handle area (index 2); an unloaded session answers TPM_RC_REFERENCE_H2 (TPM 2.0 Library Part 3, clause 5.4, step 2.4).");

        (uint handleC, TpmSession sessionC) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(sessionC)
        {
            TpmResult<GetSessionAuditDigestResponse> beforeUse = await ReadSessionAuditStatusAsync(tpm, registry, pool, handleC).ConfigureAwait(false);
            Assert.IsFalse(beforeUse.IsSuccess, "A never-audited session must not answer as an audit session.");
            Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_TYPE, 2), beforeUse.ResponseCode, "A loaded session that has never been used for audit is refused at sessionHandle, handle 3 of Table 103.");

            sessionC.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            TpmResult<GetRandomResponse> useC = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                tpm, new GetRandomInput(RandomDrawLength), [sessionC], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(useC.IsSuccess, $"C's first audited use must succeed: '{useC.ResponseCode}'.");
            useC.Value.Dispose();

            await AssertExclusiveAsync(tpm, registry, pool, handleC, expected: true, "A freshly started session's own first audited use must become exclusive cleanly.").ConfigureAwait(false);
        }

        await FlushAsync(tpm, registry, pool, handleC).ConfigureAwait(false);
    }

    /// <summary>
    /// "A session does not have to be loaded in TPM memory to have its context flushed. The saved session
    /// context associated with the indicated handle is invalidated." (TPM 2.0 Library Part 3, clause 28.4.1) —
    /// flushing a SAVED (not currently loaded) exclusive session invalidates its blob for reload and releases
    /// its exclusivity tracking, after which another session's later use becomes exclusive without interference.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.4.1</see>.
    /// </summary>
    [TestMethod]
    public async Task FlushOfASavedExclusiveSessionInvalidatesItsBlobAndReleasesExclusivity()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "audit-exclusivity-flush-saved").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint handleA, TpmSession sessionA) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        sessionA.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
        TpmResult<GetRandomResponse> use = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            tpm, new GetRandomInput(RandomDrawLength), [sessionA], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(use.IsSuccess, $"A's audited use must succeed: '{use.ResponseCode}'.");
        use.Value.Dispose();
        sessionA.Dispose();

        using ContextSaveResponse saved = await SaveContextAsync(tpm, registry, pool, handleA).ConfigureAwait(false);
        await FlushAsync(tpm, registry, pool, handleA).ConfigureAwait(false);

        TpmResult<ContextLoadResponse> reload = await SubmitContextLoadAsync(tpm, registry, pool, saved.Context).ConfigureAwait(false);
        Assert.IsFalse(reload.IsSuccess, "The flushed saved blob must no longer be loadable.");
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), reload.ResponseCode, "A flushed saved-session handle answers TPM_RC_HANDLE.");

        (uint handleB, TpmSession sessionB) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(sessionB)
        {
            sessionB.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            TpmResult<GetRandomResponse> useB = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                tpm, new GetRandomInput(RandomDrawLength), [sessionB], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(useB.IsSuccess, $"B's first audited use must succeed: '{useB.ResponseCode}'.");
            useB.Value.Dispose();

            await AssertExclusiveAsync(tpm, registry, pool, handleB, expected: true, "B's use after A's saved blob was flushed must become exclusive cleanly.").ConfigureAwait(false);
        }

        await FlushAsync(tpm, registry, pool, handleB).ConfigureAwait(false);
    }

    /// <summary>
    /// "Session contexts in TPM RAM are flushed on any TPM2_Startup(). Saved session contexts are not
    /// invalidated and may be reloaded after a TPM Restart or TPM Resume." (TPM 2.0 Library Part 1, clause
    /// 27.5) — a Restart (<c>Shutdown(STATE)</c> then <c>Startup(CLEAR)</c>) clears the exclusive-session
    /// tracking, but a session saved before the Restart reloads at its own handle afterward still designated
    /// for audit, with its digest unchanged, now reporting NO for exclusivity.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.5</see>.
    /// </summary>
    [TestMethod]
    public async Task RestartClearsExclusivityButASavedSessionsAuditStatusAndDigestSurvive()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "audit-exclusivity-restart").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint handle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        var input = new GetRandomInput(RandomDrawLength);
        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
        TpmResult<GetRandomResponse> use = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            tpm, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(use.IsSuccess, $"The audited use must succeed: '{use.ResponseCode}'.");
        byte[] expectedDigest;
        using(GetRandomResponse response = use.Value)
        {
            expectedDigest = await ComputeExpectedAuditDigestAsync(
                ZeroDigest, input, response, pool, TestContext.CancellationToken).ConfigureAwait(false);
        }

        session.Dispose();
        using ContextSaveResponse saved = await SaveContextAsync(tpm, registry, pool, handle).ConfigureAwait(false);

        await IssueShutdownAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE).ConfigureAwait(false);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmResult<ContextLoadResponse> loaded = await SubmitContextLoadAsync(tpm, registry, pool, saved.Context).ConfigureAwait(false);
        Assert.IsTrue(loaded.IsSuccess, $"The saved session must reload after a Restart: '{loaded.ResponseCode}'.");
        Assert.AreEqual(handle, loaded.Value.LoadedHandle.Value, "A saved session context loads at the SAME handle it was saved from.");

        TpmResult<GetSessionAuditDigestResponse> read = await ReadSessionAuditStatusAsync(tpm, registry, pool, handle).ConfigureAwait(false);
        Assert.IsTrue(read.IsSuccess, $"The reloaded session must still be designated for audit, not TYPE: '{read.ResponseCode}'.");
        using GetSessionAuditDigestResponse status = read.Value;
        Assert.IsFalse(status.SessionAudit.ExclusiveSession.IsYes, "A Restart must clear the exclusive-session tracking (Part 1, clause 27.5).");
        Assert.IsTrue(
            expectedDigest.AsSpan().SequenceEqual(status.SessionAudit.SessionDigest.AsReadOnlySpan()),
            "The reloaded session's digest must equal what its pre-Restart use produced.");

        await FlushAsync(tpm, registry, pool, handle).ConfigureAwait(false);
    }

    /// <summary>
    /// "Session contexts in TPM RAM are flushed on any TPM2_Startup(). Saved session contexts are not
    /// invalidated and may be reloaded after a TPM Restart or TPM Resume." (TPM 2.0 Library Part 1, clause
    /// 27.5) — a Resume (<c>Shutdown(STATE)</c> then <c>Startup(STATE)</c>) clears the exclusive-session
    /// tracking exactly as a Restart does, for the identical reason: every <c>TPM2_Startup()</c> flushes RAM
    /// session contexts regardless of the Startup type.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.5</see>.
    /// </summary>
    [TestMethod]
    public async Task ResumeClearsExclusivityTheSameWayARestartDoes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "audit-exclusivity-resume").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint handle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
        TpmResult<GetRandomResponse> use = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            tpm, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(use.IsSuccess, $"The audited use must succeed: '{use.ResponseCode}'.");
        use.Value.Dispose();
        session.Dispose();

        using ContextSaveResponse saved = await SaveContextAsync(tpm, registry, pool, handle).ConfigureAwait(false);

        await IssueShutdownAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE).ConfigureAwait(false);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE).ConfigureAwait(false);

        TpmResult<ContextLoadResponse> loaded = await SubmitContextLoadAsync(tpm, registry, pool, saved.Context).ConfigureAwait(false);
        Assert.IsTrue(loaded.IsSuccess, $"The saved session must reload after a Resume: '{loaded.ResponseCode}'.");

        TpmResult<GetSessionAuditDigestResponse> read = await ReadSessionAuditStatusAsync(tpm, registry, pool, handle).ConfigureAwait(false);
        Assert.IsTrue(read.IsSuccess, $"The reloaded session must still be designated for audit: '{read.ResponseCode}'.");
        using GetSessionAuditDigestResponse status = read.Value;
        Assert.IsFalse(status.SessionAudit.ExclusiveSession.IsYes, "A Resume must clear the exclusive-session tracking (Part 1, clause 27.5).");

        await FlushAsync(tpm, registry, pool, handle).ConfigureAwait(false);
    }

    /// <summary>
    /// "Saved session contexts are ... invalidated on a TPM Reset." (TPM 2.0 Library Part 1, clause 27.5) — a
    /// Reset (<c>Shutdown(TPM_SU_CLEAR)</c> then <c>Startup(TPM_SU_CLEAR)</c>) leaves the exclusive session's
    /// own saved blob unreloadable, so its audit status is unreachable through any read-back; a fresh session
    /// started after the Reset carries no residual state and becomes exclusive on its own first use.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 27.5</see>.
    /// </summary>
    [TestMethod]
    public async Task ResetInvalidatesTheSavedBlobBeforeAnyAuditStateCanBeRead()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "audit-exclusivity-reset-blob").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint handle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
        TpmResult<GetRandomResponse> use = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            tpm, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(use.IsSuccess, $"The audited use must succeed: '{use.ResponseCode}'.");
        use.Value.Dispose();
        session.Dispose();

        using ContextSaveResponse saved = await SaveContextAsync(tpm, registry, pool, handle).ConfigureAwait(false);

        await IssueShutdownAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmResult<ContextLoadResponse> reload = await SubmitContextLoadAsync(tpm, registry, pool, saved.Context).ConfigureAwait(false);
        Assert.IsFalse(reload.IsSuccess, "A Reset must invalidate the saved session blob.");
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), reload.ResponseCode,
            "A TPM Reset re-zeroes the session-context counter, so the pre-Reset sequence exceeds it and the clause 14.6.1 range gate refuses the reload before any tracking or audit state is consulted.");

        (uint handleC, TpmSession sessionC) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(sessionC)
        {
            sessionC.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            TpmResult<GetRandomResponse> useC = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                tpm, new GetRandomInput(RandomDrawLength), [sessionC], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(useC.IsSuccess, $"A fresh post-Reset session's first audited use must succeed: '{useC.ResponseCode}'.");
            useC.Value.Dispose();

            await AssertExclusiveAsync(tpm, registry, pool, handleC, expected: true, "A fresh post-Reset session's first use must become exclusive cleanly.").ConfigureAwait(false);
        }

        await FlushAsync(tpm, registry, pool, handleC).ConfigureAwait(false);
    }

    /// <summary>
    /// "If a command fails, then the exclusive status of sessions does not change. A session that was exclusive
    /// before the command failure is exclusive after the command failure." (TPM 2.0 Library Part 1, clause
    /// 17.5) — a wire-corrupted command HMAC over an UNRELATED session fails outright, and A's exclusivity and
    /// digest are exactly what its own single audited use produced, unaffected by the failure of a sibling
    /// session's command. The sibling session is started BEFORE A's audited use, since
    /// <c>TPM2_StartAuthSession()</c> admits sessions and would itself clear the exclusive session were it to run
    /// afterwards (clause 17.2).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.5</see>.
    /// </summary>
    [TestMethod]
    public async Task FailedCommandOverAnotherSessionLeavesExclusivityAndDigestUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "audit-exclusivity-failed-sibling").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint handleA, TpmSession sessionA) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(sessionA)
        {
            (uint handleC, TpmSession sessionC) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);

            var inputA = new GetRandomInput(RandomDrawLength);
            sessionA.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            TpmResult<GetRandomResponse> useA = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                tpm, inputA, [sessionA], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(useA.IsSuccess, $"A's audited use must succeed: '{useA.ResponseCode}'.");
            byte[] expectedDigest;
            using(GetRandomResponse responseA = useA.Value)
            {
                expectedDigest = await ComputeExpectedAuditDigestAsync(
                    ZeroDigest, inputA, responseA, pool, TestContext.CancellationToken).ConfigureAwait(false);
            }

            using(sessionC)
            {
                sessionC.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;
                byte[] parameters = ParameterAreaFor(new GetRandomInput(RandomDrawLength));
                byte[] authArea = await BuildZeroHandleAuthAreaAsync(sessionC, TpmCcConstants.TPM_CC_GetRandom, parameters, pool).ConfigureAwait(false);
                TamperLastHmacOctet(authArea);
                TpmRcConstants failedCode = await SubmitZeroHandleRawAsync(simulator, pool, TpmCcConstants.TPM_CC_GetRandom, authArea, parameters).ConfigureAwait(false);
                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), failedCode,
                    "A wire-corrupted command HMAC over an unbound session with no dictionary-attack protection is the session-index-encoded TPM_RC_BAD_AUTH.");
            }

            await FlushAsync(tpm, registry, pool, handleC).ConfigureAwait(false);

            TpmResult<GetSessionAuditDigestResponse> read = await ReadSessionAuditStatusAsync(tpm, registry, pool, handleA).ConfigureAwait(false);
            Assert.IsTrue(read.IsSuccess, $"TPM2_GetSessionAuditDigest() on A must succeed: '{read.ResponseCode}'.");
            using GetSessionAuditDigestResponse status = read.Value;
            Assert.IsTrue(status.SessionAudit.ExclusiveSession.IsYes, "A's exclusivity must be unchanged by the sibling session's failed command (Part 1, clause 17.5).");
            Assert.IsTrue(
                expectedDigest.AsSpan().SequenceEqual(status.SessionAudit.SessionDigest.AsReadOnlySpan()),
                "A's digest must be unchanged by the sibling session's failed command.");
        }

        await FlushAsync(tpm, registry, pool, handleA).ConfigureAwait(false);
    }

    /// <summary>
    /// "A command that is not allowed to have any sessions will not change the current exclusive audit session.
    /// Those commands include the context management commands ..., TPM2_Startup(), and TPM2_ReadClock()." (TPM
    /// 2.0 Library Part 1, clause 17.2) names <c>TPM2_ReadClock()</c> among the commands that do NOT clear
    /// exclusivity, diverging from this simulator's own model: <c>TPM2_ReadClock()</c> admits an audit session
    /// in its own Part 3 command table (Table 232) and is not one of the four commands Part 3/Part 4 fix to
    /// <c>TPM_ST_NO_SESSIONS</c>, so a successful <c>TPM2_ReadClock()</c> over no audit session of its own
    /// clears the exclusive session the same way any other session-admitting command without an audit
    /// participant does.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.2</see>.
    /// </summary>
    [TestMethod]
    public async Task SuccessfulReadClockClearsTheExclusiveSession()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "audit-exclusivity-readclock").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint handle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            TpmResult<GetRandomResponse> use = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                tpm, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(use.IsSuccess, $"The audited use must succeed: '{use.ResponseCode}'.");
            use.Value.Dispose();

            TpmRcConstants readClockCode = await SubmitUnauthorizedAsync(simulator, pool, new ReadClockInput()).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, readClockCode, "TPM2_ReadClock() must itself succeed for this case to be decisive.");

            await AssertExclusiveAsync(tpm, registry, pool, handle, expected: false, "A successful TPM2_ReadClock() without an audit session must clear the exclusive session.").ConfigureAwait(false);
        }

        await FlushAsync(tpm, registry, pool, handle).ConfigureAwait(false);
    }

    /// <summary>
    /// "The session is no longer the current exclusive audit session if it is flushed (TPM2_FlushContext())..."
    /// (TPM 2.0 Library Part 1, clause 17.2) is a per-handle rule: flushing an UNRELATED session's handle must
    /// not clear A's exclusivity.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.2</see>.
    /// </summary>
    [TestMethod]
    public async Task FlushContextOfAnotherSessionDoesNotClearExclusivity()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "audit-exclusivity-flush-unrelated").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint handleA, TpmSession sessionA) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(sessionA)
        {
            (uint handleD, TpmSession sessionD) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
            sessionD.Dispose();

            sessionA.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
            TpmResult<GetRandomResponse> useA = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                tpm, new GetRandomInput(RandomDrawLength), [sessionA], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(useA.IsSuccess, $"A's audited use must succeed: '{useA.ResponseCode}'.");
            useA.Value.Dispose();

            await FlushAsync(tpm, registry, pool, handleD).ConfigureAwait(false);

            await AssertExclusiveAsync(tpm, registry, pool, handleA, expected: true, "Flushing an unrelated session's handle must not clear A's exclusivity.").ConfigureAwait(false);
        }

        await FlushAsync(tpm, registry, pool, handleA).ConfigureAwait(false);
    }

    /// <summary>
    /// The response-attributes octet law (TPM 2.0 Library Part 2, clause 8.4, Table 38) on a session that is
    /// BOTH the authorizing session and the audit session over one command: "audit" is echoed SET ("If SET in
    /// the command, then this attribute will be SET in the response."), "auditExclusive" reflects the
    /// end-of-command exclusive status ("In a response, it indicates that the session is exclusive."),
    /// "auditReset" is CLEAR in the response even though it was SET in the command ("This bit is always CLEAR
    /// in a response."), and the response HMAC verifies over exactly that rewritten octet — proven here by
    /// recomputing rpHash independently from the wire and handing it to the session's own production response
    /// verification, which folds the octet actually read back rather than the one sent.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.4, Table 38</see>.
    /// </summary>
    [TestMethod]
    public async Task ResponseOctetOnASessionThatIsBothAuthorizingAndAuditFoldsExclusivityAndClearsAuditReset()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "audit-exclusivity-response-octet").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteBoundNvIndexAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmResult<NvReadPublicResponse> nameResult = await tpm.NvReadPublicAsync(BoundNvIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(nameResult.IsSuccess, $"TPM2_NV_ReadPublic() failed: '{nameResult.ResponseCode}'.");
        byte[] indexName;
        using(NvReadPublicResponse namePublic = nameResult.Value)
        {
            indexName = namePublic.NvName.Span.ToArray();
        }

        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(
            tpm, registry, pool, BoundNvIndexHandle, NvIndexAuthValueBytes, TpmtSymDef.Null,
            isBoundToAuthorizedEntity: true, TestContext.CancellationToken).ConfigureAwait(false);
        using(session)
        {
            var readInput = new NvReadInput(BoundNvIndexHandle, BoundNvIndexHandle, (ushort)NvWriteDataBytes.Length, Offset: 0);
            TpmaSession sentAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_RESET;
            session.SessionAttributes = sentAttributes;

            byte[] parameters = new byte[sizeof(ushort) * 2];
            var parameterWriter = new TpmWriter(parameters);
            parameterWriter.WriteUInt16(readInput.Size);
            parameterWriter.WriteUInt16(readInput.Offset);

            byte[] nameTerms = [.. indexName, .. indexName];
            byte[] authArea = await BuildAuthAreaAsync(session, TpmCcConstants.TPM_CC_NV_Read, nameTerms, parameters, pool).ConfigureAwait(false);

            using TpmResponse rawResponse = await SubmitWithHandlesAsync(
                simulator, pool, TpmCcConstants.TPM_CC_NV_Read, [BoundNvIndexHandle, BoundNvIndexHandle], authArea, parameters).ConfigureAwait(false);

            var reader = new TpmReader(rawResponse.AsReadOnlySpan());
            TpmHeader header = TpmHeader.Parse(ref reader);
            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)header.Code, "TPM2_NV_Read() over the bound audit session must succeed.");

            uint responseParameterLength = reader.ReadUInt32();
            byte[] responseParameters = rawResponse.AsReadOnlySpan().Slice(reader.Consumed, (int)responseParameterLength).ToArray();
            reader.Skip((int)responseParameterLength);

            using TpmsAuthResponse authResponse = TpmsAuthResponse.Parse(ref reader, pool);
            TpmaSession responseAttributes = authResponse.SessionAttributes;

            Assert.AreEqual(TpmaSession.AUDIT, responseAttributes & TpmaSession.AUDIT, "The response octet must echo audit SET (Part 2, clause 8.4, Table 38).");
            Assert.AreEqual(TpmaSession.AUDIT_EXCLUSIVE, responseAttributes & TpmaSession.AUDIT_EXCLUSIVE, "auditExclusive in the response must reflect the end-of-command exclusive status — SET on this first use.");
            Assert.AreEqual((TpmaSession)0, responseAttributes & TpmaSession.AUDIT_RESET, "auditReset must be CLEAR in the response even though it was SET in the command.");

            byte[] rpHashInput = BuildRpHashInput(TpmCcConstants.TPM_CC_NV_Read, responseParameters);
            using DigestValue rpHash = await CryptographicKeyEvents.ComputeDigestAsync(
                rpHashInput, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            bool verified = await session.VerifyAndUpdateAsync(authResponse, rpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(verified, "The response HMAC must verify over the RESPONSE octet actually read back, not the octet the command sent.");
        }

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// The <see cref="MeteredHousePool"/> balances across a full start/audit/save/load/flush cycle of one audit
    /// session, proving every carrier the session's start, its audited use, the save, the load and the flush rent
    /// is returned once the cycle ends. The baseline is taken BEFORE the session exists: a session save is
    /// destructive — "the data describing the session's state may be either on the TPM or saved off the TPM, but
    /// not both" (TPM 2.0 Library Part 1, clause 27.5) — so the save releases the live record's own carriers as it
    /// rents the blob, and the load rents them back, which is why only the whole cycle balances
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part
    /// 1, clause 27.5; Part 3, clause 28.3.1</see>).
    /// </summary>
    [TestMethod]
    public async Task MeteredPoolBalancedAcrossTheAuditSessionSaveLoadFlushCycle()
    {
        using var housePool = new MeteredHousePool();
        BaseMemoryPool pool = housePool.Pool;

        using TpmSimulator simulator = await CreateOperationalAsync(pool, "audit-exclusivity-pool").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = housePool.OutstandingCount;

        (uint handle, TpmSession session) = await StartUnboundHmacSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;
        TpmResult<GetRandomResponse> use = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            tpm, new GetRandomInput(RandomDrawLength), [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(use.IsSuccess, $"The audited use must succeed: '{use.ResponseCode}'.");
        use.Value.Dispose();
        session.Dispose();

        using(ContextSaveResponse saved = await SaveContextAsync(tpm, registry, pool, handle).ConfigureAwait(false))
        {
            TpmResult<ContextLoadResponse> loaded = await SubmitContextLoadAsync(tpm, registry, pool, saved.Context).ConfigureAwait(false);
            Assert.IsTrue(loaded.IsSuccess, $"TPM2_ContextLoad() must succeed: '{loaded.ResponseCode}'.");
            Assert.AreEqual(handle, loaded.Value.LoadedHandle.Value, "A saved session reloads at its own handle (TPM 2.0 Library Part 1, clause 27.5).");
        }

        await FlushAsync(tpm, registry, pool, handle).ConfigureAwait(false);
        Assert.AreEqual(baseline, housePool.OutstandingCount, "Every carrier the audit session's start, audited use, save, load and flush rented must be returned once the cycle ends.");
    }

    /// <summary>Reads <paramref name="sessionHandle"/>'s current audit status through <c>TPM2_GetSessionAuditDigest()</c> with the NULL signer over two empty-password authorization slots, and disposes a successful response after asserting <paramref name="expected"/>.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sessionHandle">The audit session's handle.</param>
    /// <param name="expected">The expected <c>exclusiveSession</c> value.</param>
    /// <param name="because">The assertion message.</param>
    private async Task AssertExclusiveAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint sessionHandle, bool expected, string because)
    {
        TpmResult<GetSessionAuditDigestResponse> result = await ReadSessionAuditStatusAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_GetSessionAuditDigest() failed: '{result.ResponseCode}'.");
        using GetSessionAuditDigestResponse status = result.Value;
        Assert.AreEqual(expected, status.SessionAudit.ExclusiveSession.IsYes, because);
    }

    /// <summary>
    /// Runs <c>TPM2_GetSessionAuditDigest()</c> with the NULL signer (TPM 2.0 Library Part 3, clause 18.1:
    /// "the attestation block is 'signed' with the NULL Signature") over two empty-password authorization
    /// slots — an empty password for <c>TPM_RH_ENDORSEMENT</c>'s default authValue, and an empty password for
    /// <c>TPM_RH_NULL</c>'s Empty Buffer authValue — an oracle independent of the
    /// simulator's own session table, since it reports only what the wire attests. Note that this very call is
    /// itself a session-admitting command without an audit session of its own, so it clears the TPM-wide
    /// exclusive session as a side effect the instant it completes (Part 1, clause 17.2) — callers must not
    /// treat its result as a premise a later step still depends on.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sessionHandle">The audit session's handle.</param>
    /// <returns>The raw command result; the caller disposes a successful value.</returns>
    private async Task<TpmResult<GetSessionAuditDigestResponse>> ReadSessionAuditStatusAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint sessionHandle)
    {
        using TpmPasswordSession privacyAdminAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForNullSigner(
            TpmiShHmac.FromValue(sessionHandle), ReadOnlySpan<byte>.Empty, pool);

        return await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
            tpm, input, [privacyAdminAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Computes the audit digest TPM 2.0 Library Part 1, clause 17.1, eq. (30) predicts for one successful
    /// audited <c>TPM2_GetRandom()</c> command, entirely from the octets the test itself sent and read back —
    /// never from <see cref="TpmSession"/> or the simulator's own state: "auditDigest_new =
    /// H_auditAlg(auditDigest_old || cpHash || rpHash)" with cpHash per clause 15.7, eq. (15) (<c>commandCode
    /// || parameters</c>, GetRandom carrying no handle whose Name could enter it) and rpHash per clause 15.8,
    /// eq. (16) (<c>TPM_RC_SUCCESS || commandCode || parameters</c>).
    /// </summary>
    /// <param name="oldDigest">The digest before this command — the Zero Digest on a first use or an auditReset.</param>
    /// <param name="commandInput">The exact <see cref="GetRandomInput"/> sent.</param>
    /// <param name="response">The response received.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A token observed across the digest computations.</param>
    /// <returns>The expected post-extend digest.</returns>
    private static async Task<byte[]> ComputeExpectedAuditDigestAsync(
        ReadOnlyMemory<byte> oldDigest, GetRandomInput commandInput, GetRandomResponse response, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        byte[] commandParameters = ParameterAreaFor(commandInput);

        int cpHashInputLength = sizeof(uint) + commandParameters.Length;
        using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
        Memory<byte> cpHashInput = cpHashInputOwner.Memory[..cpHashInputLength];
        var cpWriter = new TpmWriter(cpHashInput.Span);
        cpWriter.WriteUInt32((uint)TpmCcConstants.TPM_CC_GetRandom);
        cpWriter.WriteBytes(commandParameters);

        using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
            cpHashInput, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        byte[] responseParameters = new byte[sizeof(ushort) + response.RandomBytes.Size];
        var responseWriter = new TpmWriter(responseParameters);
        responseWriter.WriteUInt16((ushort)response.RandomBytes.Size);
        responseWriter.WriteBytes(response.RandomBytes.AsReadOnlySpan());

        byte[] rpHashInput = BuildRpHashInput(TpmCcConstants.TPM_CC_GetRandom, responseParameters);
        using DigestValue rpHash = await CryptographicKeyEvents.ComputeDigestAsync(
            rpHashInput, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        int extendInputLength = oldDigest.Length + Sha256DigestSize + Sha256DigestSize;
        using IMemoryOwner<byte> extendInputOwner = pool.Rent(extendInputLength);
        Memory<byte> extendInput = extendInputOwner.Memory[..extendInputLength];
        oldDigest.Span.CopyTo(extendInput.Span);
        cpHash.AsReadOnlySpan().CopyTo(extendInput.Span[oldDigest.Length..]);
        rpHash.AsReadOnlySpan().CopyTo(extendInput.Span[(oldDigest.Length + Sha256DigestSize)..]);

        using DigestValue extended = await CryptographicKeyEvents.ComputeDigestAsync(
            extendInput, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return extended.AsReadOnlySpan().ToArray();
    }

    /// <summary>Builds the rpHash input <c>TPM_RC_SUCCESS || commandCode || parameters</c> (TPM 2.0 Library Part 1, clause 15.8, eq. (16)).</summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="responseParameters">The response parameter area octets.</param>
    /// <returns>The concatenated input.</returns>
    private static byte[] BuildRpHashInput(TpmCcConstants commandCode, ReadOnlySpan<byte> responseParameters)
    {
        byte[] input = new byte[sizeof(uint) + sizeof(uint) + responseParameters.Length];
        var writer = new TpmWriter(input);
        writer.WriteUInt32((uint)TpmRcConstants.TPM_RC_SUCCESS);
        writer.WriteUInt32((uint)commandCode);
        writer.WriteBytes(responseParameters);

        return input;
    }

    /// <summary>Serializes a zero-handle command's parameter area through its own production input type.</summary>
    /// <param name="input">The command input.</param>
    /// <returns>The parameter area's octets.</returns>
    private static byte[] ParameterAreaFor(GetRandomInput input)
    {
        byte[] parameters = new byte[input.GetSerializedSize()];
        var writer = new TpmWriter(parameters);
        input.WriteParameters(ref writer);

        return parameters;
    }

    /// <summary>Builds one <c>TPMS_AUTH_COMMAND</c> block over <paramref name="session"/> for a zero-handle command, whose cpHash carries no Name term.</summary>
    /// <param name="session">The authorizing session, whose caller nonce this rolls.</param>
    /// <param name="commandCode">The command the HMAC commits to.</param>
    /// <param name="parameters">The parameter area the HMAC commits to.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The block's octets, without the authorizationSize field that precedes them.</returns>
    private async Task<byte[]> BuildZeroHandleAuthAreaAsync(TpmSession session, TpmCcConstants commandCode, byte[] parameters, BaseMemoryPool pool) =>
        await BuildAuthAreaAsync(session, commandCode, [], parameters, pool).ConfigureAwait(false);

    /// <summary>Builds one <c>TPMS_AUTH_COMMAND</c> block over <paramref name="session"/>, its command HMAC computed on <c>commandCode || nameTerms || parameters</c> (TPM 2.0 Library Part 1, clause 15.7, eq. (15)).</summary>
    /// <param name="session">The authorizing session, whose caller nonce this rolls.</param>
    /// <param name="commandCode">The command the HMAC commits to.</param>
    /// <param name="nameTerms">The concatenated entity Names of every handle in the command, in handle order.</param>
    /// <param name="parameters">The parameter area the HMAC commits to.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The block's octets, without the authorizationSize field that precedes them.</returns>
    private async Task<byte[]> BuildAuthAreaAsync(TpmSession session, TpmCcConstants commandCode, byte[] nameTerms, byte[] parameters, BaseMemoryPool pool)
    {
        int cpHashInputLength = sizeof(uint) + nameTerms.Length + parameters.Length;
        using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
        Memory<byte> cpHashInput = cpHashInputOwner.Memory[..cpHashInputLength];
        var cpHashWriter = new TpmWriter(cpHashInput.Span);
        cpHashWriter.WriteUInt32((uint)commandCode);
        cpHashWriter.WriteBytes(nameTerms);
        cpHashWriter.WriteBytes(parameters);

        using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
            cpHashInput, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.RollNonceCaller(pool);
        using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(
            cpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        int blockSize = session.GetAuthCommandSize();
        using IMemoryOwner<byte> blockOwner = pool.Rent(blockSize);
        Memory<byte> block = blockOwner.Memory[..blockSize];
        var writer = new TpmWriter(block.Span);
        session.WriteAuthCommand(ref writer, hmac);

        return block.Span.ToArray();
    }

    /// <summary>Flips every bit of the LAST octet of a one-slot authorization block's <c>hmac</c> field.</summary>
    /// <param name="authArea">The authorization block, mutated in place.</param>
    private static void TamperLastHmacOctet(byte[] authArea)
    {
        var reader = new TpmReader(authArea);
        _ = reader.ReadUInt32();
        ushort nonceSize = reader.ReadUInt16();
        reader.Skip(nonceSize);
        _ = reader.ReadByte();
        ushort hmacSize = reader.ReadUInt16();
        Assert.IsGreaterThan(0, hmacSize, "The arrangement must carry a non-empty hmac for the tamper to change one.");

        authArea[reader.Consumed + hmacSize - 1] ^= 0xFF;
    }

    /// <summary>Frames a <c>TPM_ST_SESSIONS</c> command with no handle area and submits it straight to the simulator, bypassing <see cref="TpmCommandExecutor"/>.</summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="commandCode">The command code written into the header.</param>
    /// <param name="authArea">The authorization block.</param>
    /// <param name="parameters">The parameter area.</param>
    /// <returns>The response code, still carrying any session-index encoding.</returns>
    private async Task<TpmRcConstants> SubmitZeroHandleRawAsync(
        TpmSimulator simulator, BaseMemoryPool pool, TpmCcConstants commandCode, byte[] authArea, byte[] parameters)
    {
        int length = TpmHeader.HeaderSize + sizeof(uint) + authArea.Length + parameters.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Memory<byte> command = owner.Memory[..length];

        var writer = new TpmWriter(command.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)commandCode);
        header.WriteTo(ref writer);
        writer.WriteUInt32((uint)authArea.Length);
        writer.WriteBytes(authArea);
        writer.WriteBytes(parameters);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer a refused command rather than fault.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>Frames a <c>TPM_ST_SESSIONS</c> command carrying <paramref name="handles"/> and submits it straight to the simulator, bypassing <see cref="TpmCommandExecutor"/> so the raw response can be read back.</summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="commandCode">The command code written into the header.</param>
    /// <param name="handles">The handle values, in wire order.</param>
    /// <param name="authArea">The authorization block.</param>
    /// <param name="parameters">The parameter area.</param>
    /// <returns>The raw response; the caller disposes it.</returns>
    private async Task<TpmResponse> SubmitWithHandlesAsync(
        TpmSimulator simulator, BaseMemoryPool pool, TpmCcConstants commandCode, uint[] handles, byte[] authArea, byte[] parameters)
    {
        int handleAreaSize = handles.Length * sizeof(uint);
        int length = TpmHeader.HeaderSize + handleAreaSize + sizeof(uint) + authArea.Length + parameters.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        Memory<byte> command = owner.Memory[..length];

        var writer = new TpmWriter(command.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)commandCode);
        header.WriteTo(ref writer);
        foreach(uint handle in handles)
        {
            writer.WriteUInt32(handle);
        }

        writer.WriteUInt32((uint)authArea.Length);
        writer.WriteBytes(authArea);
        writer.WriteBytes(parameters);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer rather than fault.");

        return result.Value;
    }

    /// <summary>The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S + TPM_RC_n(0x100·(index+1)).</summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>Submits an unauthorized (<c>TPM_ST_NO_SESSIONS</c>) command straight to the simulator.</summary>
    /// <param name="simulator">The simulator to submit against.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="input">The command input to frame.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitUnauthorizedAsync(TpmSimulator simulator, BaseMemoryPool pool, ITpmCommandInput input)
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

    /// <summary>Issues <c>TPM2_Shutdown(<paramref name="type"/>)</c> directly against the simulator, asserting success.</summary>
    /// <param name="simulator">The simulator to shut down.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="type">The shutdown type.</param>
    private async Task IssueShutdownAsync(TpmSimulator simulator, BaseMemoryPool pool, TpmSuConstants type)
    {
        TpmRcConstants code = await SubmitUnauthorizedAsync(simulator, pool, new ShutdownInput(type)).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, $"TPM2_Shutdown({type}) must succeed.");
    }

    /// <summary>Issues <c>TPM2_Startup(<paramref name="type"/>)</c> directly against the simulator, asserting success.</summary>
    /// <param name="simulator">The simulator to start up.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="type">The startup type.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool, TpmSuConstants type)
    {
        TpmRcConstants code = await SubmitUnauthorizedAsync(simulator, pool, new StartupInput(type)).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, code, $"TPM2_Startup({type}) must succeed.");
    }

    /// <summary>
    /// Starts an unbound, unsalted HMAC session, negotiating XOR obfuscation, and builds the host-side
    /// <see cref="TpmSession"/> over it, with an empty authValue. <c>TPM2_GetRandom()</c> routes its response
    /// through the session's negotiated symmetric definition whenever a session participates at all, regardless
    /// of whether THIS call claims <c>encrypt</c> — so every session this class starts negotiates a REAL
    /// algorithm rather than <c>TPM_ALG_NULL</c>, mirroring the house pattern's own zero-handle recipe.
    /// </summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session handle and the host session; the caller disposes the session and flushes the handle.</returns>
    private async Task<(uint Handle, TpmSession Session)> StartUnboundHmacSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        TpmtSymDef symmetric = TpmtSymDef.Xor(SessionAlg);
        StartAuthSessionInput startInput = StartAuthSessionInputExtensions.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"TPM2_StartAuthSession() failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric: symmetric);

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Saves a resource's context through <c>TPM2_ContextSave()</c> over the production executor, asserting success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle of the resource to save.</param>
    /// <returns>The response, owning the saved <see cref="TpmsContext"/>; the caller disposes it.</returns>
    private async Task<ContextSaveResponse> SaveContextAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        TpmResult<ContextSaveResponse> result = await TpmCommandExecutor.ExecuteAsync<ContextSaveResponse>(
            tpm, ContextSaveInput.ForHandle(handle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ContextSave(0x{handle:X8}) failed: '{result.ResponseCode}'.");

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

    /// <summary>Flushes <paramref name="handle"/> via <c>TPM2_FlushContext()</c>, asserting success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush.</param>
    private async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        TpmResult<FlushContextResponse> result = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(handle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_FlushContext(0x{handle:X8}) failed: '{result.ResponseCode}'.");
    }

    /// <summary>Submits an unrestricted, empty-password ECC P-256 signing primary under the owner hierarchy, asserting success.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response; the caller disposes it.</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession auth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [auth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC signing) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Defines <see cref="BoundNvIndexHandle"/> under the owner hierarchy with <see cref="NvIndexAuthValueBytes"/> as its authValue, then writes <see cref="NvWriteDataBytes"/> to it under the Index's own authorization, asserting success at each step.</summary>
    /// <param name="tpm">The device.</param>
    /// <param name="registry">The codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task DefineAndWriteBoundNvIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth auth = Tpm2bAuth.Create(NvIndexAuthValueBytes, pool);
        TpmaNv attributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE;
        using var publicInfo = new TpmsNvPublic(BoundNvIndexHandle, TpmAlgIdConstants.TPM_ALG_SHA256, attributes, Tpm2bDigest.Empty, NvIndexDataSize);
        using var defineInput = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);
        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, defineInput, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"TPM2_NV_DefineSpace(0x{BoundNvIndexHandle:X8}) failed: '{defineResult.ResponseCode}'.");

        using TpmPasswordSession writeAuth = TpmPasswordSession.Create(NvIndexAuthValueBytes, pool);
        using Tpm2bMaxNvBuffer writeBuffer = Tpm2bMaxNvBuffer.Create(NvWriteDataBytes, pool);
        var writeInput = new NvWriteInput(BoundNvIndexHandle, BoundNvIndexHandle, writeBuffer, Offset: 0);
        TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, writeInput, [writeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"TPM2_NV_Write(0x{BoundNvIndexHandle:X8}) failed: '{writeResult.ResponseCode}'.");
    }

    /// <summary>Builds the digest <see cref="Tag"/> for every SHA-256 cpHash/rpHash/extend computation this class performs — the same shape the production executor's own cpHash computation uses.</summary>
    /// <returns>The digest tag.</returns>
    private static Tag DigestTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

    /// <summary>Creates the response codec registry covering every command this class issues.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_ContextSave, TpmResponseCodec.ContextSave);
        _ = registry.Register(TpmCcConstants.TPM_CC_ContextLoad, TpmResponseCodec.ContextLoad);
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);

        return registry;
    }

    /// <summary>Creates a simulator with the ECC (BouncyCastle) signing backend wired — needed for <c>TPM2_GetSessionAuditDigest()</c>'s parse-time backend gate, even on the NULL-signer path this class always takes — powers it on, and brings it operational with <c>Startup(CLEAR)</c>.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="identifier">The simulator's own identifier.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool, string identifier)
    {
        var simulator = new TpmSimulator(identifier, signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        return simulator;
    }
}
