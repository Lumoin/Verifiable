using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Hierarchy;
using Verifiable.Tpm.Extensions.Nv;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the LIFECYCLE of a session's binding — how it ends — against the in-house behavioural
/// <see cref="TpmSimulator"/>, entirely in-process through the production command path
/// (<see cref="TpmCommandExecutor"/>, <see cref="TpmSession"/>, and the real codecs). The governing mechanism is
/// TPM 2.0 Library Part 1, clause 16.6.10's bound-entity record: the bind entity's Name COMBINED with its
/// authValue ("In the Reference Code, the authorization value is combined with the Name and stored in the
/// SESSION boundEntity member"), recomputed from the entity's LIVE authValue at every bind-omission decision
/// (Part 4, <c>IsSessionBindEntity()</c>). A Name-only record would keep a session bound across the very events
/// clause 16.6.10 requires to end it: an authValue rotation ("sessions bound to the old authorization should no
/// longer be valid") and the clause's own NV Index "squatting" attack.
/// </summary>
/// <remarks>
/// Every negative case in this file is bracketed by positive controls over the same session — the omission form
/// authorizes BEFORE the binding-ending event, and the explicit-authValue form authorizes AFTER it (clause
/// 17.6.10's own Note: "The session can continue to be used, but it, in effect, is no longer bound") — so a
/// rejection can only come from the binding decision under test, never from a broken session or harness.
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorBoundEntityBindingLifecycleTests
{
    /// <summary>The session hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>An ordinary NV Index used as the bind-and-squat target: USER-role authorization via its own authValue, dictionary-attack protected (<c>TPMA_NV_NO_DA</c> CLEAR).</summary>
    private const uint SquatIndexHandle = 0x0100_0031;

    /// <summary>Index attributes granting USER-role authorization via authValue, with <c>TPMA_NV_NO_DA</c> CLEAR (DA-protected).</summary>
    private const TpmaNv DaProtectedAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE;

    /// <summary>The first owner authorization value installed before a session binds to the owner hierarchy.</summary>
    private static byte[] FirstOwnerAuth { get; } = [0x11, 0x12, 0x13, 0x14];

    /// <summary>The replacement owner authorization value a rotation installs.</summary>
    private static byte[] SecondOwnerAuth { get; } = [0x21, 0x22, 0x23, 0x24];

    /// <summary>A third owner authorization value, distinct from both others.</summary>
    private static byte[] ThirdOwnerAuth { get; } = [0x31, 0x32, 0x33, 0x34];

    /// <summary>The squat Index's original authValue, folded into the bound session's key at start.</summary>
    private static byte[] OriginalIndexAuth { get; } = [0x41, 0x42, 0x43, 0x44];

    /// <summary>The authValue the squatter installs on the recreated, identically-Named Index.</summary>
    private static byte[] SquatterIndexAuth { get; } = [0x51, 0x52, 0x53, 0x54];

    /// <summary>The single-octet payload every provisioning <c>TPM2_NV_Write()</c> in this file sends.</summary>
    private static byte[] WriteData { get; } = [0x2A];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The same-command rotation arc: <c>TPM2_HierarchyChangeAuth()</c> authorized BY a session bound to the very
    /// hierarchy it rotates. The command HMAC omits the authValue (the binding is valid when the command arrives,
    /// TPM 2.0 Library Part 1, clause 16.6.10 equation 22), and the RESPONSE HMAC must omit it too — clause
    /// 17.6.10: "The TPM will record the fact that the authValue was not used in the HMAC computation of the
    /// authorization and not include it in the HMAC computation on the response" (the reference's recorded
    /// <c>includeAuth</c> session attribute) — NOT re-derive the decision against the just-rotated value, which
    /// would key the response on the new secret and fail the honest caller's verification. The executor verifies
    /// the response HMAC with the session key alone here, so the rotation's success proves both halves at once.
    /// The rotation then ENDS the binding: the session's next omission-form use fails, and its explicit-authValue
    /// form with the NEW value succeeds (Part 3, clause 24.9 for <c>TPM2_SetPrimaryPolicy()</c> as the follow-on
    /// owner-authorized command).
    /// </summary>
    [TestMethod]
    public async Task RotatingTheBoundHierarchyThroughItsOwnBoundSessionMirrorsTheOmissionOnTheResponseAndEndsTheBinding()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<HierarchyChangeAuthResponse> install = await tpm.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, FirstOwnerAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(install.IsSuccess, $"Installing the first ownerAuth failed: '{install.ResponseCode}'.");

        (uint sessionHandle, TpmSession session) = await StartBoundHmacSessionAsync(
            tpm, registry, pool, (uint)TpmRh.TPM_RH_OWNER, FirstOwnerAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                //The bound session rotates the very hierarchy it is bound to, omitting the authValue on both the
                //command and (mirrored) the response HMAC. A response keyed on the new value instead would fail
                //the executor's verification and surface here as a failed result.
                TpmResult<HierarchyChangeAuthResponse> boundRotation = await ChangeOwnerAuthOverSessionAsync(
                    tpm, registry, pool, session, suppliedAuth: ReadOnlyMemory<byte>.Empty, newAuth: SecondOwnerAuth).ConfigureAwait(false);
                Assert.IsTrue(
                    boundRotation.IsSuccess,
                    $"The bound session's own rotation must succeed with the authValue omitted on BOTH HMAC legs (clause 16.6.10's record-and-mirror rule); got '{boundRotation.ResponseCode}'.");

                //The rotation ended the binding: the recomputed bound-entity value now folds the NEW ownerAuth
                //and no longer equals the recorded one, so the omission form stops authorizing. Owner is
                //dictionary-attack exempt and the session was bound to owner, so the rejection is the
                //non-charging TPM_RC_BAD_AUTH.
                TpmResult<HierarchyChangeAuthResponse> staleOmission = await ChangeOwnerAuthOverSessionAsync(
                    tpm, registry, pool, session, suppliedAuth: ReadOnlyMemory<byte>.Empty, newAuth: ThirdOwnerAuth).ConfigureAwait(false);
                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), staleOmission.ResponseCode,
                    "After the rotation the session is no longer bound, so an omission-form use must fail its command HMAC.");

                //The session itself stays usable (clause 16.6.10's Note): folding the CURRENT ownerAuth
                //authorizes an owner command whose response reuses the same key (TPM2_SetPrimaryPolicy changes
                //no authValue, so both HMAC legs agree client-side).
                TpmResult<SetPrimaryPolicyResponse> unboundUse = await SetEmptyOwnerPolicyOverSessionAsync(
                    tpm, registry, pool, session, suppliedAuth: SecondOwnerAuth).ConfigureAwait(false);
                Assert.IsTrue(
                    unboundUse.IsSuccess,
                    $"The unbound session folding the new ownerAuth must still authorize (clause 16.6.10's Note); got '{unboundUse.ResponseCode}'.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The cross-path rotation rider (TPM 2.0 Library Part 1, clause 16.6.10: "If the administrator for a
    /// persistent object changes the authorization, sessions bound to the old authorization should no longer be
    /// valid"): a session bound to the owner hierarchy, whose authValue is then rotated by a DIFFERENT
    /// authorization path (a password session), must stop applying the bind-omission — the recomputed
    /// bound-entity value folds the live authValue (Part 4, <c>IsSessionBindEntity()</c>), so the rotation
    /// changes it and the comparison fails. The same session bracketed by positive controls: the omission form
    /// authorizes before the rotation, and the explicit new-authValue form authorizes after it.
    /// </summary>
    [TestMethod]
    public async Task RotatingTheBoundHierarchysAuthValueByAnotherPathEndsTheBinding()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<HierarchyChangeAuthResponse> install = await tpm.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, FirstOwnerAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(install.IsSuccess, $"Installing the first ownerAuth failed: '{install.ResponseCode}'.");

        (uint sessionHandle, TpmSession session) = await StartBoundHmacSessionAsync(
            tpm, registry, pool, (uint)TpmRh.TPM_RH_OWNER, FirstOwnerAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                //Positive control: while the binding holds, the omission form authorizes (equation 22).
                TpmResult<SetPrimaryPolicyResponse> boundUse = await SetEmptyOwnerPolicyOverSessionAsync(
                    tpm, registry, pool, session, suppliedAuth: ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
                Assert.IsTrue(boundUse.IsSuccess, $"The bound omission form must authorize before the rotation; got '{boundUse.ResponseCode}'.");

                //The rotation rides a password session — a path entirely outside the bound session.
                TpmResult<HierarchyChangeAuthResponse> rotation = await tpm.ChangeHierarchyAuthWithPasswordAsync(
                    TpmRh.TPM_RH_OWNER, FirstOwnerAuth, SecondOwnerAuth, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(rotation.IsSuccess, $"The password-path rotation failed: '{rotation.ResponseCode}'.");

                //The binding ended with the rotation: the omission form must now fail. Owner is DA-exempt and
                //the session was bound to owner, so the rejection is the non-charging TPM_RC_BAD_AUTH.
                TpmResult<SetPrimaryPolicyResponse> staleOmission = await SetEmptyOwnerPolicyOverSessionAsync(
                    tpm, registry, pool, session, suppliedAuth: ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), staleOmission.ResponseCode,
                    "A session bound to the OLD ownerAuth must no longer authorize with the omission after the rotation (clause 16.6.10).");

                //Positive control: the session folding the NEW ownerAuth authorizes — unbound but alive.
                TpmResult<SetPrimaryPolicyResponse> unboundUse = await SetEmptyOwnerPolicyOverSessionAsync(
                    tpm, registry, pool, session, suppliedAuth: SecondOwnerAuth).ConfigureAwait(false);
                Assert.IsTrue(unboundUse.IsSuccess, $"The unbound session folding the new ownerAuth must still authorize; got '{unboundUse.ResponseCode}'.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// TPM 2.0 Library Part 1, clause 16.6.10's own NV Index "squatting" attack, verbatim: "The attacker would
    /// then start an authorization session bound to the NV Index and delete the NV Index. When the NV Index to be
    /// attacked is created, the attacker would have an authorization session bound to an Index with the same Name
    /// and could [have] access to the NV Index even though the actual authorization value is unknown" — the
    /// attack that "Recording of the NV Index authorization is required to prevent." A session bound to an Index
    /// survives the Index's undefine-then-recreate with an identical public area (identical Name) ONLY as a stale
    /// handle: the recomputed bound-entity value folds the recreated Index's DIFFERENT authValue, the comparison
    /// fails, and the omission form is refused — charging <c>failedTries</c>, since the recreated Index is
    /// dictionary-attack protected (clause 16.8.7).
    /// </summary>
    [TestMethod]
    public async Task ASessionBoundToAnUndefinedIndexMustNotAuthorizeAnIdenticallyNamedSquatterIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineNvIndexAsync(tpm, pool, registry, SquatIndexHandle, DaProtectedAttributes, OriginalIndexAuth).ConfigureAwait(false);
        await ProvisionIndexAsync(tpm, pool, registry, SquatIndexHandle, OriginalIndexAuth).ConfigureAwait(false);
        byte[] indexName = await ReadIndexNameAsync(tpm, SquatIndexHandle).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartBoundHmacSessionAsync(
            tpm, registry, pool, SquatIndexHandle, OriginalIndexAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                //Positive control: bound to the Index it authorizes, the omission form reads it (equation 22).
                TpmResult<NvReadResponse> boundRead = await ReadIndexOverSessionAsync(
                    tpm, registry, pool, session, SquatIndexHandle, indexName, suppliedAuth: ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
                Assert.IsTrue(boundRead.IsSuccess, $"The bound omission-form read must succeed before the squat; got '{boundRead.ResponseCode}'.");
                boundRead.Value.Dispose();

                //The squat: undefine the Index, then recreate it with an IDENTICAL public area — hence an
                //identical Name — under an authValue the original binding never proved.
                await UndefineIndexAsync(tpm, pool, registry, SquatIndexHandle).ConfigureAwait(false);
                await DefineNvIndexAsync(tpm, pool, registry, SquatIndexHandle, DaProtectedAttributes, SquatterIndexAuth).ConfigureAwait(false);
                await ProvisionIndexAsync(tpm, pool, registry, SquatIndexHandle, SquatterIndexAuth).ConfigureAwait(false);
                byte[] squatterName = await ReadIndexNameAsync(tpm, SquatIndexHandle).ConfigureAwait(false);
                Assert.AreSequenceEqual(indexName, squatterName, "Test setup: the squatter Index must carry the identical Name, or the case proves nothing.");

                TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(before.IsSuccess);

                //The recomputed bound-entity value folds the squatter's authValue and no longer matches the
                //recorded one, so the omission form fails its command HMAC — and charges failedTries, because
                //the squatter Index is DA-protected (clause 16.8.7).
                TpmResult<NvReadResponse> squattedRead = await ReadIndexOverSessionAsync(
                    tpm, registry, pool, session, SquatIndexHandle, squatterName, suppliedAuth: ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), squattedRead.ResponseCode,
                    "The session bound to the deleted Index must NOT authorize the identically-Named squatter with the omission (clause 16.6.10's squatting attack).");

                TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(after.IsSuccess);
                Assert.AreEqual(before.Value.LockoutCounter + 1, after.Value.LockoutCounter, "The refused omission must charge failedTries by exactly 1.");

                //Positive control: folding the squatter's own authValue authorizes — the session is alive, the
                //BINDING is what ended (clause 16.6.10's Note), so the refusal above can only have come from the
                //bound-entity comparison.
                TpmResult<NvReadResponse> explicitRead = await ReadIndexOverSessionAsync(
                    tpm, registry, pool, session, SquatIndexHandle, squatterName, suppliedAuth: SquatterIndexAuth).ConfigureAwait(false);
                Assert.IsTrue(explicitRead.IsSuccess, $"The unbound session folding the squatter's authValue must authorize; got '{explicitRead.ResponseCode}'.");
                explicitRead.Value.Dispose();
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "The size of auth is limited to be no larger than the size of the digest produced by the NV Index's
    /// nameAlg (TPM_RC_SIZE)" — TPM 2.0 Library Part 3, clause 31.3.1: a <c>TPM2_NV_DefineSpace()</c> whose
    /// <c>auth</c> exceeds the SHA-256 nameAlg's 32-octet digest is refused with <c>TPM_RC_SIZE</c>, while an
    /// exactly-digest-width <c>auth</c> is accepted. This is the definition-time bound that keeps every stored
    /// NV authValue inside the bound-entity fold's fixed width — the invariant the fold's own guards restate.
    /// </summary>
    [TestMethod]
    public async Task DefiningAnNvIndexWithAnAuthValueWiderThanItsNameAlgDigestIsRefusedWithSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //33 octets against SHA-256's 32, the last octet non-zero so trailing-zero stripping cannot narrow it.
        byte[] overWideAuth = new byte[33];
        overWideAuth.AsSpan().Fill(0x5A);

        TpmResult<NvDefineSpaceResponse> refused = await DefineNvIndexExpectingAsync(
            tpm, pool, registry, SquatIndexHandle, DaProtectedAttributes, overWideAuth).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, refused.ResponseCode, "An auth wider than the nameAlg digest must be refused with TPM_RC_SIZE (Part 3, clause 31.3.1).");

        byte[] digestWidthAuth = new byte[32];
        digestWidthAuth.AsSpan().Fill(0x5A);

        TpmResult<NvDefineSpaceResponse> accepted = await DefineNvIndexExpectingAsync(
            tpm, pool, registry, SquatIndexHandle, DaProtectedAttributes, digestWidthAuth).ConfigureAwait(false);
        Assert.IsTrue(accepted.IsSuccess, $"An exactly-digest-width auth must be accepted; got '{accepted.ResponseCode}'.");
    }

    /// <summary>
    /// An authValue "should not be larger than the digest size of the algorithm used to compute the Name of the
    /// object" (TPM 2.0 Library Part 1, clause 16.6.4.2, enforced by the reference's <c>TPM2_Create()</c> with
    /// <c>TPM_RC_SIZE</c>): sealing under a 33-octet <c>userAuth</c> against a SHA-256 nameAlg template is
    /// refused, while an exactly-digest-width <c>userAuth</c> seals — the creation-time bound that keeps every
    /// sealed object's authValue inside the bound-entity fold's fixed width.
    /// </summary>
    [TestMethod]
    public async Task SealingWithAUserAuthWiderThanTheNameAlgDigestIsRefusedWithSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary storage parent failed: '{parentResult.ResponseCode}'.");
        using CreatePrimaryResponse parent = parentResult.Value;

        byte[] overWideAuth = new byte[33];
        overWideAuth.AsSpan().Fill(0x5A);

        TpmResult<CreateResponse> refused = await SealExpectingAsync(tpm, registry, pool, parent.ObjectHandle.Value, overWideAuth).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, refused.ResponseCode, "A userAuth wider than the nameAlg digest must be refused with TPM_RC_SIZE (Part 1, clause 16.6.4.2).");

        byte[] digestWidthAuth = new byte[32];
        digestWidthAuth.AsSpan().Fill(0x5A);

        TpmResult<CreateResponse> accepted = await SealExpectingAsync(tpm, registry, pool, parent.ObjectHandle.Value, digestWidthAuth).ConfigureAwait(false);
        Assert.IsTrue(accepted.IsSuccess, $"An exactly-digest-width userAuth must seal; got '{accepted.ResponseCode}'.");
        accepted.Value.Dispose();
    }

    /// <summary>
    /// The same Part 3, clause 31.3.1 auth-size bound over the SESSION arm: a <c>TPM2_NV_DefineSpace()</c>
    /// authorized by a real owner-bound HMAC session, whose plaintext <c>auth</c> parameter exceeds the SHA-256
    /// nameAlg's 32-octet digest, is refused with <c>TPM_RC_SIZE</c> after its command HMAC verifies — the
    /// session-tail gate, distinct from the password arm's.
    /// </summary>
    [TestMethod]
    public async Task DefiningAnNvIndexOverASessionWithAnOverWideAuthIsRefusedWithSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        byte[] overWideAuth = new byte[33];
        overWideAuth.AsSpan().Fill(0x5A);

        (uint sessionHandle, TpmSession session) = await StartBoundHmacSessionAsync(
            tpm, registry, pool, (uint)TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(session)
            {
                //Bound to the owner it authorizes: the bind-omission composes the command HMAC on the session
                //key alone, so the refusal below can only come from the auth-size gate.
                session.SetAuthValue(ReadOnlySpan<byte>.Empty, pool);

                TpmResult<NvDefineSpaceResponse> refused = await DefineNvIndexOverSessionExpectingAsync(
                    tpm, pool, registry, session, SquatIndexHandle, overWideAuth).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_SIZE, refused.ResponseCode,
                    "An auth wider than the nameAlg digest must be refused with TPM_RC_SIZE on the session arm too (Part 3, clause 31.3.1).");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The same Part 3, clause 31.3.1 auth-size bound over the DECRYPTED arm: a <c>TPM2_NV_DefineSpace()</c>
    /// whose over-wide <c>auth</c> parameter travels XOR-encrypted under the authorizing session's own
    /// <c>decrypt</c> attribute is refused with <c>TPM_RC_SIZE</c> on the RAW recovered size, before
    /// trailing-zero stripping — the pre-strip gate, distinct from both plaintext gates.
    /// </summary>
    [TestMethod]
    public async Task DefiningAnNvIndexWithAnEncryptedOverWideAuthIsRefusedWithSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        byte[] overWideAuth = new byte[33];
        overWideAuth.AsSpan().Fill(0x5A);

        (uint sessionHandle, TpmSession session) = await StartBoundHmacSessionAsync(
            tpm, registry, pool, (uint)TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmtSymDef.Xor(SessionAlg)).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;
                session.SetAuthValue(ReadOnlySpan<byte>.Empty, pool);

                TpmResult<NvDefineSpaceResponse> refused = await DefineNvIndexOverSessionExpectingAsync(
                    tpm, pool, registry, session, SquatIndexHandle, overWideAuth).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_SIZE, refused.ResponseCode,
                    "A decrypted auth wider than the nameAlg digest must be refused with TPM_RC_SIZE (Part 3, clause 31.3.1).");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Issues <c>TPM2_NV_DefineSpace()</c> under owner authorization over <paramref name="session"/> and returns
    /// the raw result, asserting nothing — the session-arm counterpart of <see cref="DefineNvIndexExpectingAsync"/>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="session">The authorizing session.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="authValue">The Index's authValue.</param>
    /// <returns>The define result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineNvIndexOverSessionExpectingAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmSession session, uint nvIndex, ReadOnlyMemory<byte> authValue)
    {
        using Tpm2bAuth auth = Tpm2bAuth.Create(authValue.Span, pool);
        using Tpm2bDigest policyDigest = Tpm2bDigest.Create(ReadOnlySpan<byte>.Empty, pool);
        using TpmsNvPublic publicInfo = new(nvIndex, SessionAlg, DaProtectedAttributes, policyDigest, dataSize: 8);
        using NvDefineSpaceInput input = new(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues <c>TPM2_NV_DefineSpace()</c> under owner authorization with a <c>TPM_RS_PW</c> session and returns
    /// the raw result, asserting nothing — the negative-case counterpart of <see cref="DefineNvIndexAsync"/>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index attributes.</param>
    /// <param name="authValue">The Index's authValue.</param>
    /// <returns>The define result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineNvIndexExpectingAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, TpmaNv attributes, ReadOnlyMemory<byte> authValue)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth auth = Tpm2bAuth.Create(authValue.Span, pool);
        using Tpm2bDigest policyDigest = Tpm2bDigest.Create(ReadOnlySpan<byte>.Empty, pool);
        using TpmsNvPublic publicInfo = new(nvIndex, SessionAlg, attributes, policyDigest, dataSize: 8);
        using NvDefineSpaceInput input = new(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Seals a fixed secret under <paramref name="userAuth"/> beneath <paramref name="parentHandle"/> and
    /// returns the raw result, asserting nothing — on success, the caller owns and must dispose
    /// <see cref="TpmResult{T}.Value"/>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <param name="userAuth">The sealed item's authValue.</param>
    /// <returns>The create result.</returns>
    private async Task<TpmResult<CreateResponse>> SealExpectingAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle, byte[] userAuth)
    {
        byte[] secretBytes = "Binding-lifecycle sealed secret."u8.ToArray();

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(secretBytes, userAuth, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);

        return await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues <c>TPM2_HierarchyChangeAuth()</c> for the owner hierarchy over <paramref name="session"/>, folding
    /// <paramref name="suppliedAuth"/> as the entity authValue term (empty composes the bind-omission form,
    /// TPM 2.0 Library Part 1, clause 16.6.10 equation 22).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="session">The authorizing session.</param>
    /// <param name="suppliedAuth">The authValue term to fold, or empty for the omission form.</param>
    /// <param name="newAuth">The replacement owner authorization value.</param>
    /// <returns>The rotation result.</returns>
    private async Task<TpmResult<HierarchyChangeAuthResponse>> ChangeOwnerAuthOverSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmSession session, ReadOnlyMemory<byte> suppliedAuth, ReadOnlyMemory<byte> newAuth)
    {
        session.SetAuthValue(suppliedAuth.Span, pool);

        using Tpm2bAuth replacementAuth = Tpm2bAuth.Create(newAuth.Span, pool);
        using HierarchyChangeAuthInput input = new(TpmRh.TPM_RH_OWNER, replacementAuth);

        return await TpmCommandExecutor.ExecuteAsync<HierarchyChangeAuthResponse>(
            tpm, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues <c>TPM2_SetPrimaryPolicy()</c> clearing the owner hierarchy's policy (an Empty policy with
    /// <c>TPM_ALG_NULL</c>, TPM 2.0 Library Part 3, clause 24.9) over <paramref name="session"/> — a
    /// non-rotating owner-authorized command whose response HMAC reuses the command's key, folding
    /// <paramref name="suppliedAuth"/> as the entity authValue term (empty composes the bind-omission form).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="session">The authorizing session.</param>
    /// <param name="suppliedAuth">The authValue term to fold, or empty for the omission form.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<SetPrimaryPolicyResponse>> SetEmptyOwnerPolicyOverSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmSession session, ReadOnlyMemory<byte> suppliedAuth)
    {
        session.SetAuthValue(suppliedAuth.Span, pool);

        using Tpm2bDigest emptyPolicy = Tpm2bDigest.Create(ReadOnlySpan<byte>.Empty, pool);
        using SetPrimaryPolicyInput input = new(TpmRh.TPM_RH_OWNER, emptyPolicy, TpmAlgIdConstants.TPM_ALG_NULL);

        return await TpmCommandExecutor.ExecuteAsync<SetPrimaryPolicyResponse>(
            tpm, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues <c>TPM2_NV_Read()</c> against <paramref name="nvIndex"/> under Index authorization over
    /// <paramref name="session"/>, folding <paramref name="suppliedAuth"/> as the entity authValue term (empty
    /// composes the bind-omission form).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="session">The authorizing session.</param>
    /// <param name="nvIndex">The NV Index to read under its own authorization.</param>
    /// <param name="indexName">The Index's current Name (the cpHash Name term, both handle positions).</param>
    /// <param name="suppliedAuth">The authValue term to fold, or empty for the omission form.</param>
    /// <returns>The read result; on success, the caller owns and must dispose <see cref="TpmResult{T}.Value"/>.</returns>
    private async Task<TpmResult<NvReadResponse>> ReadIndexOverSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmSession session, uint nvIndex, byte[] indexName, ReadOnlyMemory<byte> suppliedAuth)
    {
        session.SetAuthValue(suppliedAuth.Span, pool);

        var readInput = new NvReadInput(nvIndex, nvIndex, Size: (ushort)WriteData.Length, Offset: 0);
        ReadOnlyMemory<byte>[] handleNames = [indexName, indexName];

        return await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            tpm, readInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Defines an ordinary NV Index under owner authorization with a <c>TPM_RS_PW</c> session (TPM 2.0 Library
    /// Part 3, clause 31.3).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index attributes.</param>
    /// <param name="authValue">The Index's authValue.</param>
    private async Task DefineNvIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, TpmaNv attributes, ReadOnlyMemory<byte> authValue)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth auth = Tpm2bAuth.Create(authValue.Span, pool);
        using Tpm2bDigest policyDigest = Tpm2bDigest.Create(ReadOnlySpan<byte>.Empty, pool);
        using TpmsNvPublic publicInfo = new(nvIndex, SessionAlg, attributes, policyDigest, dataSize: 8);
        using NvDefineSpaceInput input = new(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"NV_DefineSpace(0x{nvIndex:X8}) failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Undefines <paramref name="nvIndex"/> under owner authorization with a <c>TPM_RS_PW</c> session (TPM 2.0
    /// Library Part 3, clause 31.4) — the deletion step of clause 16.6.10's squatting attack.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to undefine.</param>
    private async Task UndefineIndexAsync(TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        var undefineInput = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, nvIndex);

        TpmResult<NvUndefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            device, undefineInput, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"NV_UndefineSpace(0x{nvIndex:X8}) failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Writes <paramref name="nvIndex"/> once over its own authValue via a <c>TPM_RS_PW</c> session so the Index
    /// carries <c>TPMA_NV_WRITTEN</c> — an unwritten Index answers <c>TPM_RC_NV_UNINITIALIZED</c> on a read
    /// regardless of authorization outcome (TPM 2.0 Library Part 3, clause 31.13), which would obscure the
    /// binding decision under test.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The NV Index to provision.</param>
    /// <param name="authValue">The Index's correct authValue.</param>
    private async Task ProvisionIndexAsync(TpmDevice tpm, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> authValue)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(authValue.Span, pool);
        using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(WriteData, pool);
        var writeInput = new NvWriteInput(nvIndex, nvIndex, writeInputBuffer, Offset: 0);

        TpmResult<NvWriteResponse> result = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, writeInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Provisioning write for NV Index 0x{nvIndex:X8} failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Reads an NV Index's current Name over <c>TPM2_NV_ReadPublic()</c> — the cpHash Name term a
    /// session-authorized NV command needs (TPM 2.0 Library Part 1, clause 15.7, equation 15).
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
    /// <paramref name="bindAuthValue"/> (TPM 2.0 Library Part 1, clause 16.6.10, equation 20).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="bindHandle">The entity to bind to.</param>
    /// <param name="bindAuthValue">The bind entity's authValue fed into the session-key KDFa.</param>
    /// <param name="symmetric">The symmetric algorithm to negotiate for parameter encryption, or <see langword="null"/> for none.</param>
    /// <returns>The started session handle and its client-side wrapper.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartBoundHmacSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint bindHandle, ReadOnlyMemory<byte> bindAuthValue, TpmtSymDef? symmetric = null)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(bindHandle, SessionAlg, symmetric);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound to 0x{bindHandle:X8}) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse startResponse = startResult.Value;
        TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(startResponse.SessionHandle.Value), bindAuthValue, startInput.NonceCaller,
            startResponse.NonceTPM, SessionAlg, pool, symmetric: symmetric, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        return (startResponse.SessionHandle.Value, session);
    }

    /// <summary>
    /// Flushes <paramref name="handle"/> if it names a started session, releasing the simulator-side context.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="handle">The session handle, or zero when no session was started.</param>
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
            .Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite)
            .Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext)
            .Register(TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmResponseCodec.HierarchyChangeAuth)
            .Register(TpmCcConstants.TPM_CC_SetPrimaryPolicy, TpmResponseCodec.SetPrimaryPolicy)
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);

    /// <summary>
    /// Creates a simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational
    /// phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-bound-entity-lifecycle", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
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
