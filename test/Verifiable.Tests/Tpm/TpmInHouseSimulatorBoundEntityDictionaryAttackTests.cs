using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Nv;
using Verifiable.Tpm.Extensions.Policy;
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
/// Drives the bound-entity dictionary-attack (DA) state a session's context records at
/// <c>TPM2_StartAuthSession()</c> time (TPM 2.0 Library Part 1, clause 16.6.10: "The noDA attribute of the bind
/// entity is recorded in the session context") against the in-house behavioural <see cref="TpmSimulator"/> —
/// entirely in-process, with no external assets — through the same production command path production code uses
/// (<see cref="TpmCommandExecutor"/>, <see cref="TpmSession"/>, and the real command/response codecs).
/// </summary>
/// <remarks>
/// <para>
/// The governing rule is Part 1, clause 16.8.7: "the authorization failure counter (failedTries) is incremented
/// if either the entity being authorized is subject to DA protection or if the session is bound to an entity that
/// has DA protection" — an explicit OR, independently restated at Part 3, clause 11.1.1 ("use of the session is
/// subject to DA regardless of the DA status of the entity being authorized"). A session bound to a DA-protected
/// entity and then used to authorize a NON-DA-protected entity is, absent this rule, an unthrottled online
/// guessing oracle against the bound entity's own authValue (clause 16.8.7's own worked attack scenario) — the
/// case every test below authorized-vs-bound mismatch isolates.
/// </para>
/// <para>
/// Every negative case is proven non-vacuous against the matching positive shape elsewhere in this file (case 10
/// mirrors case 1's bind/target pair with a correct authValue), and every counter assertion reads the live
/// <c>failedTries</c> value through <see cref="TpmDictionaryAttackExtensions.GetDictionaryAttackParametersAsync"/>
/// — the same observation surface the sibling dictionary-attack tests use.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorBoundEntityDictionaryAttackTests
{
    /// <summary>The session/policy hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The digest width, in octets, of <see cref="SessionAlg"/>.</summary>
    private const int DigestSize = 32;

    /// <summary>
    /// An ordinary NV Index used as a bind target: USER-role authorization via its own authValue, dictionary-attack
    /// protected (<c>TPMA_NV_NO_DA</c> CLEAR, TPM 2.0 Library Part 2, clause 13.4).
    /// </summary>
    private const uint BindIndexHandle = 0x0100_0011;

    /// <summary>An ordinary NV Index used as the entity a bound session authorizes.</summary>
    private const uint TargetIndexHandle = 0x0100_0021;

    /// <summary>Index attributes granting USER-role authorization via authValue, with <c>TPMA_NV_NO_DA</c> CLEAR (DA-protected).</summary>
    private const TpmaNv DaProtectedAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE;

    /// <summary>The same authorization shape as <see cref="DaProtectedAttributes"/>, with <c>TPMA_NV_NO_DA</c> additionally SET (exempt).</summary>
    private const TpmaNv NoDaAttributes = DaProtectedAttributes | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>The correct authValue installed on every Index this file defines, unless noted otherwise.</summary>
    private static byte[] CorrectAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong authValue, distinct from <see cref="CorrectAuth"/>.</summary>
    private static byte[] WrongAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>The single-octet payload every <c>TPM2_NV_Write()</c> in this file sends.</summary>
    private static byte[] WriteData { get; } = [0x2A];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The oracle-closure case: a session bound to a DA-protected NV Index, used to authorize a DIFFERENT NO_DA
    /// Index with a wrong authValue, must charge <c>failedTries</c> — TPM 2.0 Library Part 1, clause 16.8.7's
    /// explicit OR ("...or if the session is bound to an entity that has DA protection"), restated at Part 3,
    /// clause 11.1.1 ("use of the session is subject to DA regardless of the DA status of the entity being
    /// authorized"). Without this OR the target's own <c>TPMA_NV_NO_DA</c> SET would make it, incorrectly, an
    /// unthrottled oracle against the bind entity's authValue — clause 16.8.7's own worked attack.
    /// </summary>
    [TestMethod]
    public async Task SessionBoundToDaProtectedIndexAuthorizingADifferentNoDaIndexWithWrongAuthCountsAuthFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineNvIndexAsync(tpm, pool, registry, BindIndexHandle, DaProtectedAttributes, CorrectAuth).ConfigureAwait(false);
        await DefineNvIndexAsync(tpm, pool, registry, TargetIndexHandle, NoDaAttributes, CorrectAuth).ConfigureAwait(false);
        //An NV Index's Name is nameAlg ‖ H(TPMS_NV_PUBLIC) (TPM 2.0 Library Part 1, clause 13, Table 9), and
        //the first write SETs the public-area TPMA_NV_WRITTEN attribute, changing that Name — so the Name the
        //session's cpHash folds must be read AFTER the provisioning write.
        await ProvisionTargetIndexAsync(tpm, pool, registry, TargetIndexHandle, CorrectAuth).ConfigureAwait(false);
        byte[] targetName = await ReadIndexNameAsync(tpm, TargetIndexHandle).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(before.IsSuccess);

        uint sessionHandle = 0;
        try
        {
            TpmSession session;
            (sessionHandle, session) = await StartBoundHmacSessionAsync(tpm, registry, pool, BindIndexHandle, CorrectAuth).ConfigureAwait(false);
            using(session)
            {
                TpmResult<NvReadResponse> result = await ReadTargetIndexOverSessionAsync(
                    tpm, registry, pool, session, TargetIndexHandle, targetName, WrongAuth).ConfigureAwait(false);

                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode,
                    "A wrong authValue on a NO_DA target, authorized over a session bound to a DA-protected entity, must charge the session-encoded TPM_RC_AUTH_FAIL.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
        }

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter + 1, after.Value.LockoutCounter, "failedTries must move by exactly 1.");
    }

    /// <summary>
    /// The negative-space counterpart of case 1: a session bound to a NON-DA-protected Index (<c>TPMA_NV_NO_DA</c>
    /// SET) contributes nothing to the OR (TPM 2.0 Library Part 1, clause 16.8.1: "The authValue for an NV Index
    /// receives DA protection unless the TPMA_NV_NO_DA attribute of the Index is SET"), so a wrong authValue on a
    /// DIFFERENT NO_DA target is the plain, uncounted <c>TPM_RC_BAD_AUTH</c> — both disjuncts of clause 16.8.7's
    /// OR are false.
    /// </summary>
    [TestMethod]
    public async Task SessionBoundToNoDaIndexAuthorizingADifferentNoDaIndexWithWrongAuthIsBadAuthWithoutCounting()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineNvIndexAsync(tpm, pool, registry, BindIndexHandle, NoDaAttributes, CorrectAuth).ConfigureAwait(false);
        await DefineNvIndexAsync(tpm, pool, registry, TargetIndexHandle, NoDaAttributes, CorrectAuth).ConfigureAwait(false);
        //An NV Index's Name is nameAlg ‖ H(TPMS_NV_PUBLIC) (TPM 2.0 Library Part 1, clause 13, Table 9), and
        //the first write SETs the public-area TPMA_NV_WRITTEN attribute, changing that Name — so the Name the
        //session's cpHash folds must be read AFTER the provisioning write.
        await ProvisionTargetIndexAsync(tpm, pool, registry, TargetIndexHandle, CorrectAuth).ConfigureAwait(false);
        byte[] targetName = await ReadIndexNameAsync(tpm, TargetIndexHandle).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            TpmSession session;
            (sessionHandle, session) = await StartBoundHmacSessionAsync(tpm, registry, pool, BindIndexHandle, CorrectAuth).ConfigureAwait(false);
            using(session)
            {
                TpmResult<NvReadResponse> result = await ReadTargetIndexOverSessionAsync(
                    tpm, registry, pool, session, TargetIndexHandle, targetName, WrongAuth).ConfigureAwait(false);

                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
                    "Neither the bind entity nor the target is DA-protected, so a wrong authValue must be the plain session-encoded TPM_RC_BAD_AUTH.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
        }

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "failedTries must not move.");
    }

    /// <summary>
    /// A session bound to <c>TPM_RH_OWNER</c> — a permanent entity other than <c>TPM_RH_LOCKOUT</c> — contributes
    /// nothing to the OR: TPM 2.0 Library Part 1, clause 16.8.7's closing sentence, "If a session is bound to a
    /// permanent entity other than TPM_RH_LOCKOUT, then the session is not bound to an entity that has DA
    /// protection," and clause 16.8.1, "The authValue associated with a permanent entity, other than
    /// TPM_RH_LOCKOUT, does not receive DA protection." A wrong authValue on a NO_DA target is therefore the
    /// plain, uncounted <c>TPM_RC_BAD_AUTH</c>.
    /// </summary>
    [TestMethod]
    public async Task SessionBoundToOwnerAuthorizingANoDaIndexWithWrongAuthIsBadAuthWithoutCounting()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineNvIndexAsync(tpm, pool, registry, TargetIndexHandle, NoDaAttributes, CorrectAuth).ConfigureAwait(false);
        //An NV Index's Name is nameAlg ‖ H(TPMS_NV_PUBLIC) (TPM 2.0 Library Part 1, clause 13, Table 9), and
        //the first write SETs the public-area TPMA_NV_WRITTEN attribute, changing that Name — so the Name the
        //session's cpHash folds must be read AFTER the provisioning write.
        await ProvisionTargetIndexAsync(tpm, pool, registry, TargetIndexHandle, CorrectAuth).ConfigureAwait(false);
        byte[] targetName = await ReadIndexNameAsync(tpm, TargetIndexHandle).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            TpmSession session;
            (sessionHandle, session) = await StartBoundHmacSessionAsync(tpm, registry, pool, (uint)TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            using(session)
            {
                TpmResult<NvReadResponse> result = await ReadTargetIndexOverSessionAsync(
                    tpm, registry, pool, session, TargetIndexHandle, targetName, WrongAuth).ConfigureAwait(false);

                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
                    "TPM_RH_OWNER is DA-exempt as a bind entity, so a wrong authValue on a NO_DA target must be the plain session-encoded TPM_RC_BAD_AUTH.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
        }

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "failedTries must not move.");
    }

    /// <summary>
    /// The one-strike collision: a session bound to <c>TPM_RH_LOCKOUT</c> — DA-protected despite being a
    /// permanent entity (TPM 2.0 Library Part 1, clause 16.8.1: "lockoutAuth is DA protected even though it is a
    /// permanent entity") — authorizing a DIFFERENT, NO_DA-exempt entity with a wrong authValue must spend the
    /// clause 16.8.5 one-strike lockoutAuth-disable, never the ordinary <c>failedTries</c> counter: "An
    /// authorization failure associated with lockoutAuth causes the TPM to enter this special lockout state
    /// regardless of the setting of failedTries and maxTries." This is precisely clause 16.8.7's attack scenario
    /// with entity A = TPM_RH_LOCKOUT: absent the bind-DA OR, a NO_DA target would make lockoutAuth an
    /// unthrottled oracle.
    /// </summary>
    [TestMethod]
    public async Task SessionBoundToLockoutAuthorizingAnotherEntityWithWrongAuthSpendsTheOneStrike()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineNvIndexAsync(tpm, pool, registry, TargetIndexHandle, NoDaAttributes, CorrectAuth).ConfigureAwait(false);
        //An NV Index's Name is nameAlg ‖ H(TPMS_NV_PUBLIC) (TPM 2.0 Library Part 1, clause 13, Table 9), and
        //the first write SETs the public-area TPMA_NV_WRITTEN attribute, changing that Name — so the Name the
        //session's cpHash folds must be read AFTER the provisioning write.
        await ProvisionTargetIndexAsync(tpm, pool, registry, TargetIndexHandle, CorrectAuth).ConfigureAwait(false);
        byte[] targetName = await ReadIndexNameAsync(tpm, TargetIndexHandle).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            TpmSession session;
            (sessionHandle, session) = await StartBoundHmacSessionAsync(tpm, registry, pool, (uint)TpmRh.TPM_RH_LOCKOUT, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            using(session)
            {
                TpmResult<NvReadResponse> result = await ReadTargetIndexOverSessionAsync(
                    tpm, registry, pool, session, TargetIndexHandle, targetName, WrongAuth).ConfigureAwait(false);

                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode,
                    "A session bound to TPM_RH_LOCKOUT, authorizing a different entity, must charge the session-encoded TPM_RC_AUTH_FAIL on a wrong authValue.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
        }

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "The one-strike lockoutAuth-disable and the ordinary failedTries counter are exclusive: failedTries must not move.");

        TpmResult<DictionaryAttackLockResetResponse> subsequentCorrectLockoutAuth = await tpm.DictionaryAttackLockResetAsync(
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, subsequentCorrectLockoutAuth.ResponseCode,
            "The one-strike state bars EVEN a subsequent CORRECT lockoutAuth use, proving LockoutAuthEnabled was actually disabled by the mismatch above.");
    }

    /// <summary>
    /// The use-time lockout gate: TPM 2.0 Library Part 1, clause 16.8.3, "While in Lockout mode, any use of a
    /// DA-protected authValue will return TPM_RC_LOCKOUT," composed with clause 16.8.7's bind-DA grant. Once
    /// <c>failedTries == maxTries</c>, a session bound to a DA-protected entity used to authorize a NO_DA target
    /// must be refused with the BARE <c>TPM_RC_LOCKOUT</c> (Part 3, clause 6.2's Table 3 entry — a
    /// command-independent, non-session-encoded code), with no <c>failedTries</c> movement and, proven by
    /// supplying a WRONG target authValue and still observing the bare code, no authValue evaluation at all.
    /// </summary>
    [TestMethod]
    public async Task BoundToDaSessionUsedInLockoutModeIsBareLockoutWithNoAuthEvaluation()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DriveIntoLockoutAsync(tpm, pool, registry).ConfigureAwait(false);
        await DefineNvIndexAsync(tpm, pool, registry, TargetIndexHandle, NoDaAttributes, CorrectAuth).ConfigureAwait(false);
        //An NV Index's Name is nameAlg ‖ H(TPMS_NV_PUBLIC) (TPM 2.0 Library Part 1, clause 13, Table 9), and
        //the first write SETs the public-area TPMA_NV_WRITTEN attribute, changing that Name — so the Name the
        //session's cpHash folds must be read AFTER the provisioning write.
        await ProvisionTargetIndexAsync(tpm, pool, registry, TargetIndexHandle, CorrectAuth).ConfigureAwait(false);
        byte[] targetName = await ReadIndexNameAsync(tpm, TargetIndexHandle).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(before.Value.IsLockedOut, "Test setup: the TPM must already be in Lockout mode.");

        uint sessionHandle = 0;
        try
        {
            TpmSession session;
            (sessionHandle, session) = await StartBoundHmacSessionAsync(tpm, registry, pool, BindIndexHandle, CorrectAuth).ConfigureAwait(false);
            using(session)
            {
                TpmResult<NvReadResponse> result = await ReadTargetIndexOverSessionAsync(
                    tpm, registry, pool, session, TargetIndexHandle, targetName, WrongAuth).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_LOCKOUT, result.ResponseCode,
                    "While in Lockout mode, a session bound to a DA-protected entity must be refused with the bare TPM_RC_LOCKOUT before any authValue is evaluated (a wrong authValue would otherwise session-encode AUTH_FAIL/BAD_AUTH).");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
        }

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "A LOCKOUT rejection must never move failedTries further.");
    }

    /// <summary>
    /// The exercised-and-declined half of the use-time gate: TPM 2.0 Library Part 3, clause 11.1.1, "No
    /// authorization is required for tpmKey or bind" — starting a session bound to a DA-protected entity SUCCEEDS
    /// even while the TPM is in Lockout mode. The refusal (case 5) surfaces only at USE, never at
    /// <c>TPM2_StartAuthSession()</c> itself, and clause 11.1.1's own error enumeration for the command names no
    /// lockout-related code at all.
    /// </summary>
    [TestMethod]
    public async Task StartAuthSessionBindingToADaProtectedEntitySucceedsWhileInLockoutMode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DriveIntoLockoutAsync(tpm, pool, registry).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> lockedOut = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lockedOut.Value.IsLockedOut, "Test setup: the TPM must already be in Lockout mode.");

        uint sessionHandle = 0;
        try
        {
            TpmSession session;
            (sessionHandle, session) = await StartBoundHmacSessionAsync(tpm, registry, pool, BindIndexHandle, CorrectAuth).ConfigureAwait(false);
            session.Dispose();
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
        }

        Assert.AreNotEqual(0u, sessionHandle, "TPM2_StartAuthSession() binding to a DA-protected entity must succeed and allocate a real session handle even while the TPM is in Lockout mode.");
    }

    /// <summary>
    /// A companion session that authorizes no entity still owes a genuine command HMAC, and its own bind DA state
    /// enters the OR exactly as an authorizing session's does: TPM 2.0 Library Part 1, clause 16.8.1's three-uses
    /// enumeration names "the authValue parameter in the computation of sessionKey for a bound session" (use 3)
    /// as itself a DA-protected use, and "All uses of a DA protected authValue receive DA protection." A decrypt/
    /// encrypt-only companion session bound to a DA-protected entity, riding a command whose PRIMARY session
    /// authorizes an unrelated (correctly-supplied) entity, must charge failedTries on its own HMAC mismatch —
    /// proving the companion is not exempt from clause 16.8.7's OR merely because it authorizes nothing itself.
    /// </summary>
    /// <remarks>
    /// This command is <c>TPM2_Unseal()</c>, whose primary (index 0) session must resolve as a genuine HMAC or
    /// policy session — a bare <c>TPM_RS_PW</c> password in that slot is refused before any companion is
    /// considered, as it is for <c>TPM2_NV_ChangeAuth()</c>'s and <c>TPM2_HierarchyChangeAuth()</c>'s session
    /// arms. The primary here is an UNBOUND HMAC session whose command-HMAC key reduces to the correctly-supplied
    /// item authValue alone, so nothing it authorizes can be the source of a dictionary-attack charge; the sole
    /// bind-DA standing in the area belongs to the genuine encrypt-only companion, which is what makes the charge
    /// unambiguously attributable to it. (Not every companion-bearing command refuses a password primary —
    /// <c>TPM2_Create()</c>'s sealed-object arm admits a <c>TPM_RS_PW</c> parent paired with a decrypt companion —
    /// so Unseal is chosen here for the clean single-source attribution, not because a password primary is
    /// universally unreachable.)
    /// </remarks>
    [TestMethod]
    public async Task DecryptCompanionSessionBoundToADaProtectedEntityWithHmacMismatchCountsAuthFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineNvIndexAsync(tpm, pool, registry, BindIndexHandle, DaProtectedAttributes, CorrectAuth).ConfigureAwait(false);

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint primarySessionHandle = 0;
        uint companionSessionHandle = 0;

        try
        {
            using LoadResponse loaded = await SealAndLoadAsync(tpm, registry, pool, parentHandle, CorrectAuth, noDa: true).ConfigureAwait(false);
            itemHandle = loaded.ObjectHandle.Value;

            TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

            StartAuthSessionInput primaryStart = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool);
            TpmResult<StartAuthSessionResponse> primaryStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                tpm, primaryStart, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(primaryStartResult.IsSuccess, $"StartAuthSession (unbound primary) failed: '{primaryStartResult.ResponseCode}'.");
            primarySessionHandle = primaryStartResult.Value.SessionHandle.Value;
            using TpmSession primarySession = new(new TpmHandle(primarySessionHandle), primaryStartResult.Value.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);
            primarySession.SetAuthValue(CorrectAuth, pool);

            TpmSession companionSession;
            (companionSessionHandle, companionSession) = await StartBoundHmacSessionAsync(
                tpm, registry, pool, BindIndexHandle, WrongAuth, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
            using(companionSession)
            {
                companionSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
                TpmResult<UnsealResponse> result = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                    tpm, unsealInput, [primarySession, companionSession], [loaded.Name.Span.ToArray()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 1), result.ResponseCode,
                    "The companion session's own HMAC mismatch (its believed bind authValue is wrong) must charge the session-encoded TPM_RC_AUTH_FAIL at ITS OWN session index (1), because it is bound to a DA-protected entity.");
            }

            TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(before.Value.LockoutCounter + 1, after.Value.LockoutCounter, "failedTries must move by exactly 1, attributable to the companion's own bind-DA charge alone (the item is NO_DA-exempt and the primary session is correctly authorized).");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, primarySessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, companionSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, parentHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The bind-DA state applies uniformly across session types: TPM 2.0 Library Part 1, clause 16.6.10, "For all
    /// session types, this command will cause initialization of the sessionKey and may establish binding between
    /// the session and an entity," and clause 16.8.1's "All uses of a DA protected authValue receive DA
    /// protection" names no session-type exception. A POLICY session started bound to a DA-protected entity,
    /// whose accumulated policy otherwise legitimately authorizes <c>TPM2_NV_ChangeAuth()</c>'s ADMIN role
    /// (<c>TPM2_PolicyAuthValue()</c> then <c>TPM2_PolicyCommandCode(TPM_CC_NV_ChangeAuth)</c>, Part 3, clause
    /// 31.15.1) against a NO_DA-exempt target with a WRONG target authValue, must still charge failedTries on the
    /// resulting command-HMAC mismatch, purely from its own bind state.
    /// </summary>
    [TestMethod]
    public async Task PolicySessionBoundToADaProtectedEntityWithAuthFailureCountsAuthFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineNvIndexAsync(tpm, pool, registry, BindIndexHandle, DaProtectedAttributes, CorrectAuth).ConfigureAwait(false);

        TpmPolicy rotationPolicy = new TpmPolicyBuilder().WithAuthValue().WithCommandCode(TpmCcConstants.TPM_CC_NV_ChangeAuth).Build();
        byte[] rotationAuthPolicy = new byte[DigestSize];
        int written = rotationPolicy.ComputeDigest(SessionAlg, rotationAuthPolicy, pool);
        Assert.AreEqual(DigestSize, written, "A SHA-256 policy digest is the hash's full width.");

        await DefineNvIndexAsync(tpm, pool, registry, TargetIndexHandle, NoDaAttributes, CorrectAuth, rotationAuthPolicy).ConfigureAwait(false);
        byte[] targetName = await ReadIndexNameAsync(tpm, TargetIndexHandle).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            TpmSession session;
            (sessionHandle, session) = await StartBoundPolicySessionAsync(tpm, registry, pool, BindIndexHandle, CorrectAuth).ConfigureAwait(false);
            using(session)
            {
                TpmResult<uint> replay = await rotationPolicy.ExecuteAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(replay.IsSuccess, $"Replaying the rotation policy on the bound session failed: '{replay.ResponseCode}'.");

                session.SetAuthValue(WrongAuth, pool);

                using Tpm2bAuth newAuth = Tpm2bAuth.Create(CorrectAuth, pool);
                using NvChangeAuthInput input = new(TargetIndexHandle, newAuth);

                TpmResult<NvChangeAuthResponse> result = await TpmCommandExecutor.ExecuteAsync<NvChangeAuthResponse>(
                    tpm, input, [session], [targetName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode,
                    "A wrong target authValue over a POLICY session bound to a DA-protected entity must charge the session-encoded TPM_RC_AUTH_FAIL.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
        }

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter + 1, after.Value.LockoutCounter, "failedTries must move by exactly 1.");
    }

    /// <summary>
    /// The bind derivation reaches ordinary loaded objects, not only NV Indexes and permanent handles: TPM 2.0
    /// Library Part 1, clause 16.8.1, "The authValue for an object receives DA protection unless the object's
    /// noDA attribute is SET," applies identically whether the object is the entity being authorized or merely
    /// the bind entity a session's sessionKey was derived from (clause 16.8.7's OR draws no distinction). A
    /// session bound to an ordinary loaded key with <c>noDA</c> CLEAR, authorizing a DIFFERENT NO_DA Index with a
    /// wrong authValue, must charge failedTries.
    /// </summary>
    [TestMethod]
    public async Task SessionBoundToAnOrdinaryNoDaClearKeyAuthorizingANoDaIndexWithWrongAuthCountsAuthFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse bindKey = await CreateOrdinaryBindKeyAsync(tpm, registry, pool, isDaProtected: true).ConfigureAwait(false);
        uint bindKeyHandle = bindKey.ObjectHandle.Value;

        await DefineNvIndexAsync(tpm, pool, registry, TargetIndexHandle, NoDaAttributes, CorrectAuth).ConfigureAwait(false);
        //An NV Index's Name is nameAlg ‖ H(TPMS_NV_PUBLIC) (TPM 2.0 Library Part 1, clause 13, Table 9), and
        //the first write SETs the public-area TPMA_NV_WRITTEN attribute, changing that Name — so the Name the
        //session's cpHash folds must be read AFTER the provisioning write.
        await ProvisionTargetIndexAsync(tpm, pool, registry, TargetIndexHandle, CorrectAuth).ConfigureAwait(false);
        byte[] targetName = await ReadIndexNameAsync(tpm, TargetIndexHandle).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            TpmSession session;
            (sessionHandle, session) = await StartBoundHmacSessionAsync(tpm, registry, pool, bindKeyHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            using(session)
            {
                TpmResult<NvReadResponse> result = await ReadTargetIndexOverSessionAsync(
                    tpm, registry, pool, session, TargetIndexHandle, targetName, WrongAuth).ConfigureAwait(false);

                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode,
                    "A session bound to an ordinary noDA-CLEAR key, authorizing a NO_DA target with a wrong authValue, must charge the session-encoded TPM_RC_AUTH_FAIL.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, bindKeyHandle).ConfigureAwait(false);
        }

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter + 1, after.Value.LockoutCounter, "failedTries must move by exactly 1.");
    }

    /// <summary>
    /// The success invariant: TPM 2.0 Library Part 1, clause 16.8.7's OR governs a FAILED authorization only — it
    /// is a disjunction over which conditions cause a charge, not a rule that a DA-protected bind entity by
    /// itself blocks or throttles a CORRECT authorization. A session bound to a DA-protected Index, used to
    /// authorize a NO_DA target with the CORRECT authValue, must succeed and must not move failedTries.
    /// </summary>
    [TestMethod]
    public async Task BoundToDaSessionWithCorrectAuthOnANoDaIndexSucceedsWithoutCounting()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DefineNvIndexAsync(tpm, pool, registry, BindIndexHandle, DaProtectedAttributes, CorrectAuth).ConfigureAwait(false);
        await DefineNvIndexAsync(tpm, pool, registry, TargetIndexHandle, NoDaAttributes, CorrectAuth).ConfigureAwait(false);
        //An NV Index's Name is nameAlg ‖ H(TPMS_NV_PUBLIC) (TPM 2.0 Library Part 1, clause 13, Table 9), and
        //the first write SETs the public-area TPMA_NV_WRITTEN attribute, changing that Name — so the Name the
        //session's cpHash folds must be read AFTER the provisioning write.
        await ProvisionTargetIndexAsync(tpm, pool, registry, TargetIndexHandle, CorrectAuth).ConfigureAwait(false);
        byte[] targetName = await ReadIndexNameAsync(tpm, TargetIndexHandle).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            TpmSession session;
            (sessionHandle, session) = await StartBoundHmacSessionAsync(tpm, registry, pool, BindIndexHandle, CorrectAuth).ConfigureAwait(false);
            using(session)
            {
                TpmResult<NvReadResponse> result = await ReadTargetIndexOverSessionAsync(
                    tpm, registry, pool, session, TargetIndexHandle, targetName, CorrectAuth).ConfigureAwait(false);

                Assert.IsTrue(result.IsSuccess, $"A correct authValue on a NO_DA target, over a session bound to a DA-protected entity, must succeed: '{result.ResponseCode}'.");

                using NvReadResponse response = result.Value;
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
        }

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.Value.LockoutCounter, after.Value.LockoutCounter, "A successful authorization must never move failedTries.");
    }

    /// <summary>
    /// Defines an NV Index at <paramref name="nvIndex"/> with <paramref name="attributes"/>, USER-role
    /// authorization via <paramref name="authValue"/>, and an optional ADMIN-role <paramref name="authPolicy"/>,
    /// authorized by the (empty) owner authValue.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    /// <param name="authValue">The Index authValue (TPM 2.0 Library Part 1, clause 16.8.1's USER-role authorization).</param>
    /// <param name="authPolicy">The Index's ADMIN-role access policy digest, or empty for none.</param>
    private async Task DefineNvIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, TpmaNv attributes, ReadOnlyMemory<byte> authValue, ReadOnlyMemory<byte> authPolicy = default)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth auth = Tpm2bAuth.Create(authValue.Span, pool);
        using Tpm2bDigest policyDigest = Tpm2bDigest.Create(authPolicy.Span, pool);
        using TpmsNvPublic publicInfo = new(nvIndex, SessionAlg, attributes, policyDigest, dataSize: 8);
        using NvDefineSpaceInput input = new(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"NV_DefineSpace(0x{nvIndex:X8}) failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Reads an NV Index's current Name over <c>TPM2_NV_ReadPublic()</c> — the authoritative source an
    /// HMAC/policy-session-authorized command's cpHash needs (TPM 2.0 Library Part 1, clause 15.7, equation 15).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The NV Index handle.</param>
    /// <returns>The Index's current Name.</returns>
    private async Task<byte[]> ReadIndexNameAsync(TpmDevice device, uint nvIndex)
    {
        TpmResult<NvReadPublicResponse> result = await device.NvReadPublicAsync(nvIndex, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"NvReadPublicAsync(0x{nvIndex:X8}) failed: '{result.ResponseCode}'.");

        using NvReadPublicResponse response = result.Value;

        return response.NvName.Span.ToArray();
    }

    /// <summary>
    /// Starts a bound, unsalted HMAC session against <paramref name="bindHandle"/> through the production
    /// <c>TPM2_StartAuthSession()</c> path, deriving the client-side session key from
    /// <paramref name="bindAuthValue"/> — the caller's belief of the bind entity's real authValue (TPM 2.0
    /// Library Part 1, clause 16.6.10, equation 20).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="bindHandle">The entity to bind to.</param>
    /// <param name="bindAuthValue">The believed bind authValue fed into the session-key KDFa.</param>
    /// <param name="symmetric">
    /// The symmetric algorithm to negotiate for parameter encryption, or <see langword="null"/> for none
    /// (<c>TPM_ALG_NULL</c>). A companion session that sets <c>decrypt</c>/<c>encrypt</c> needs a real
    /// negotiated algorithm here — an unnegotiated session answers a client-side rejection instead of ever
    /// reaching the TPM (TPM 2.0 Library Part 3, clause 5.5).
    /// </param>
    /// <returns>The started session handle and its client-side wrapper.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartBoundHmacSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint bindHandle, ReadOnlyMemory<byte> bindAuthValue, TpmtSymDef? symmetric = null)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(bindHandle, SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound to 0x{bindHandle:X8}) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse startResponse = startResult.Value;
        TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(startResponse.SessionHandle.Value), bindAuthValue, startInput.NonceCaller,
            startResponse.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool, symmetric: symmetric, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        return (startResponse.SessionHandle.Value, session);
    }

    /// <summary>
    /// Starts a bound, unsalted POLICY session against <paramref name="bindHandle"/>, mirroring
    /// <see cref="StartBoundHmacSessionAsync"/> but with <c>sessionType = TPM_SE_POLICY</c> (TPM 2.0 Library Part
    /// 3, clause 11.1.1: session-key derivation and the bind mechanism are identical across session types).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="bindHandle">The entity to bind to.</param>
    /// <param name="bindAuthValue">The believed bind authValue fed into the session-key KDFa.</param>
    /// <returns>The started session handle and its client-side wrapper.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartBoundPolicySessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint bindHandle, ReadOnlyMemory<byte> bindAuthValue)
    {
        byte[] nonceCaller = new byte[DigestSize];
        RandomNumberGenerator.Fill(nonceCaller);

        var startInput = new StartAuthSessionInput
        {
            TpmKey = (uint)TpmRh.TPM_RH_NULL,
            Bind = bindHandle,
            NonceCaller = nonceCaller,
            EncryptedSalt = ReadOnlyMemory<byte>.Empty,
            SessionType = TpmSeConstants.TPM_SE_POLICY,
            AuthHash = SessionAlg,
            Symmetric = TpmtSymDef.Null
        };

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy, bound to 0x{bindHandle:X8}) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse startResponse = startResult.Value;
        TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(startResponse.SessionHandle.Value), bindAuthValue, startInput.NonceCaller,
            startResponse.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        return (startResponse.SessionHandle.Value, session);
    }

    /// <summary>
    /// Issues <c>TPM2_NV_Read()</c> against <paramref name="targetIndex"/> under Index authorization, folding
    /// <paramref name="suppliedAuth"/> as the target entity's authValue term on <paramref name="session"/> (TPM
    /// 2.0 Library Part 1, clause 16.6.10, equation 21 — the session is not bound to the entity being authorized;
    /// TPM 2.0 Library Part 3, clause 31.13 for the command itself). The simulator's HMAC-session arm of
    /// <c>TPM2_NV_Write()</c> only models the owner arm — an ordinary Index answers <c>TPM_RC_AUTH_TYPE</c> for
    /// Index-authValue authorization over an HMAC session — so every case in this file that needs a session-
    /// authorized Index-authValue arm drives it through <c>TPM2_NV_Read()</c> instead, whose HMAC-session arm
    /// does model Index authorization (<paramref name="session"/>'s <c>authHandle</c> equal to
    /// <paramref name="targetIndex"/>).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="session">The authorizing session.</param>
    /// <param name="targetIndex">The NV Index to read.</param>
    /// <param name="targetIndexName">The target Index's current Name (cpHash Name term, both handle positions).</param>
    /// <param name="suppliedAuth">The authValue supplied for the target Index.</param>
    /// <returns>The read result; on success, the caller owns and must dispose <see cref="TpmResult{T}.Value"/>.</returns>
    private async Task<TpmResult<NvReadResponse>> ReadTargetIndexOverSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmSession session, uint targetIndex, byte[] targetIndexName, ReadOnlyMemory<byte> suppliedAuth)
    {
        session.SetAuthValue(suppliedAuth.Span, pool);

        var readInput = new NvReadInput(targetIndex, targetIndex, Size: (ushort)WriteData.Length, Offset: 0);
        ReadOnlyMemory<byte>[] handleNames = [targetIndexName, targetIndexName];

        return await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            tpm, readInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Provisions <paramref name="targetIndex"/> for a subsequent session-authorized <c>TPM2_NV_Read()</c>: writes
    /// it once, over its own authValue via a password (<c>TPM_RS_PW</c>) session (TPM 2.0 Library Part 3, clause
    /// 31.7), so the Index carries <c>TPMA_NV_WRITTEN</c> before the case under test reads it. An unwritten Index
    /// answers <c>TPM_RC_NV_UNINITIALIZED</c> regardless of authorization outcome (Part 3, clause 31.13), which
    /// would obscure the DA-composition result this file's cases prove.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="targetIndex">The NV Index to provision.</param>
    /// <param name="authValue">The Index's correct authValue.</param>
    private async Task ProvisionTargetIndexAsync(TpmDevice tpm, BaseMemoryPool pool, TpmResponseRegistry registry, uint targetIndex, ReadOnlyMemory<byte> authValue)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(authValue.Span, pool);
        using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(WriteData, pool);
        var writeInput = new NvWriteInput(targetIndex, targetIndex, writeInputBuffer, Offset: 0);

        TpmResult<NvWriteResponse> result = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, writeInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Provisioning write for NV Index 0x{targetIndex:X8} failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Lowers <c>maxTries</c> to 1 and drives the TPM into Lockout mode with a single wrong-password write against
    /// a freshly defined DA-protected Index (<see cref="BindIndexHandle"/>), which the caller subsequently reuses
    /// as a bind target.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    private async Task DriveIntoLockoutAsync(TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry)
    {
        const uint LoweredMaxTries = 1;

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        await DefineNvIndexAsync(device, pool, registry, BindIndexHandle, DaProtectedAttributes, CorrectAuth).ConfigureAwait(false);

        using TpmPasswordSession wrongPasswordSession = TpmPasswordSession.Create(WrongAuth, pool);
        using Tpm2bMaxNvBuffer wrongWriteBuffer = Tpm2bMaxNvBuffer.Create(WriteData, pool);
        var wrongWrite = new NvWriteInput(BindIndexHandle, BindIndexHandle, wrongWriteBuffer, Offset: 0);
        TpmResult<NvWriteResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, wrongWrite, [wrongPasswordSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        //Arrange machinery, not the normative case under proof: the password arm answers the
        //session-index-encoded TPM_RC_AUTH_FAIL for this rejection. Lockout engagement itself is proven
        //by each caller's own normative assertion against the state this priming produces.
        Assert.IsFalse(wrongResult.IsSuccess, "The priming write must fail.");
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode,
            "The priming failure must count and, with maxTries lowered to 1, engage Lockout mode immediately.");
    }

    /// <summary>Creates the deterministic ECC storage parent under the owner hierarchy, DA-exempt.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary storage parent failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a transient ECC signing key under the owner hierarchy, with its <c>noDA</c> attribute controlled
    /// by <paramref name="isDaProtected"/> — the bind-entity derivation case for an ordinary loaded object (TPM
    /// 2.0 Library Part 1, clause 16.8.1: "The authValue for an object receives DA protection unless the object's
    /// noDA attribute is SET").
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="isDaProtected">Whether the created key's <c>noDA</c> attribute is CLEAR (DA-protected).</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateOrdinaryBindKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, bool isDaProtected)
    {
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: !isDaProtected);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (bind key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Seals a fixed secret under <paramref name="userAuth"/> beneath <paramref name="parentHandle"/>,
    /// persists-and-reloads it through wire bytes only, and returns the loaded object's response.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <param name="userAuth">The sealed item's authValue.</param>
    /// <param name="noDa">Whether the sealed item's <c>noDA</c> attribute is SET (DA-exempt).</param>
    /// <returns>The loaded object's response.</returns>
    private async Task<LoadResponse> SealAndLoadAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, byte[] userAuth, bool noDa)
    {
        byte[] secretBytes = "Bound-entity DA companion secret."u8.ToArray();

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(secretBytes, userAuth, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: noDa);
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
        Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");

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

    /// <summary>Flushes a transient object or session handle when one is present (non-zero), ignoring the result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="handle">The handle to flush, or 0 for none.</param>
    private async Task FlushIfPresentAsync(TpmDevice tpm, TpmResponseRegistry registry, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        var flush = FlushContextInput.ForHandle(handle);
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flush, [], null, BaseMemoryPool.Shared, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S +
    /// TPM_RC_n(0x100·(index+1)) — a local mirror of the production session-index encoding, transcribed
    /// independently here since the production helper is private.
    /// </summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>Creates a response codec registry covering every command this file drives directly.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite)
            .Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead)
            .Register(TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmResponseCodec.NvChangeAuth)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext)
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject)
            .Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load)
            .Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-bound-entity-da", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await IssueStartupClearAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire.
    /// </summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task IssueStartupClearAsync(TpmSimulator simulator, BaseMemoryPool pool)
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
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code);
    }
}
