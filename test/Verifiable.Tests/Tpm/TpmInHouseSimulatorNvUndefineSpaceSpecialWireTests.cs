using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Hierarchy;
using Verifiable.Tpm.Extensions.Nv;
using Verifiable.Tpm.Extensions.Pin;
using Verifiable.Tpm.Extensions.Policy;
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
/// Drives the <c>@platform</c> authorization slot of <c>TPM2_NV_UndefineSpaceSpecial()</c> and the wire the
/// command travels on - the USER-role slot as a password and as an HMAC session (unbound, bound to the platform
/// hierarchy, bound to a dictionary-attack-protected NV Index), the wire order in which the two slots are judged,
/// the slot-1 resolution table, the framing refusals Table 249 fixes, the fail-closed
/// <c>decrypt</c>/<c>encrypt</c>/<c>audit</c> answers a parameterless command owes, and the cpHash whose Name
/// terms are the Index's own Name and the platform handle's four octets - against the in-house behavioural
/// <see cref="TpmSimulator"/>, entirely in-process with no external assets, through the same production command
/// path the production code uses (<see cref="TpmCommandExecutor"/> and the real command/response codecs).
/// TPM 2.0 Library Part 3, clauses 31.5, 5.5, 5.6 and 5.7; Part 2, clauses 9.18 and 6.6.2; Part 1, clauses 13,
/// 15.7, 16.6 and 16.8.1.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorNvUndefineSpaceSpecialWireTests
{
    /// <summary>The hash algorithm for every session and every policy digest these tests compose.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The SHA-256 digest width, in octets - the policy-digest and cpHash width used here.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The declared data size of every Ordinary Index this file defines.</summary>
    private const ushort OrdinaryDataSize = 16;

    /// <summary>The declared data size of a <c>TPM_NT_PIN_FAIL</c> Index: the whole 8-octet <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c>.</summary>
    private const ushort PinCounterParametersSize = 8;

    /// <summary>
    /// The smallest well-formed authorization block: a session handle, an empty nonce, the
    /// <c>sessionAttributes</c> octet and an empty hmac (TPM 2.0 Library Part 3, clause 5.5, step 3.1).
    /// </summary>
    private const int MinimumAuthorizationBlockSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);

    /// <summary>The dictionary-attack-exempt platform-created Index carrying <c>TPMA_NV_POLICY_DELETE</c>.</summary>
    private const uint PolicyDeleteIndexHandle = 0x0100_0065;

    /// <summary>A second Index of the same shape, for the case that needs a deletion after the first is gone.</summary>
    private const uint SecondPolicyDeleteIndexHandle = 0x0100_0066;

    /// <summary>The dictionary-attack-PROTECTED policy-delete Index, whose authValue a folding policy charges on a mismatch.</summary>
    private const uint DaProtectedPolicyDeleteIndexHandle = 0x0100_0067;

    /// <summary>A dictionary-attack-protected ordinary Index used as a bind target and as the lockout driver.</summary>
    private const uint BindIndexHandle = 0x0100_0068;

    /// <summary>The <c>TPM_NT_PIN_FAIL</c> policy-delete Index whose attempt counter a folding policy moves.</summary>
    private const uint PinPolicyDeleteIndexHandle = 0x0100_0069;

    /// <summary>A handle in the transient-object range, which the authorization slot admits no more than any other non-session handle.</summary>
    private const uint TransientRangeHandle = 0x8000_0000;

    /// <summary>
    /// The attributes of the platform-created, policy-delete Index this file deletes: readable and writable with
    /// the Index authValue, <c>TPMA_NV_PLATFORMCREATE</c> as Platform Authorization requires, and
    /// <c>TPMA_NV_POLICY_DELETE</c>, "Index may not be deleted unless the authPolicy is satisfied using
    /// TPM2_NV_UndefineSpaceSpecial()". Dictionary-attack exempt, so a refusal elsewhere in a case never moves
    /// <c>failedTries</c>.
    /// </summary>
    private const TpmaNv PolicyDeleteAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_NO_DA
        | TpmaNv.TPMA_NV_PLATFORMCREATE | TpmaNv.TPMA_NV_POLICY_DELETE;

    /// <summary>The same Index shape, dictionary-attack PROTECTED (<c>TPMA_NV_NO_DA</c> CLEAR).</summary>
    private const TpmaNv DaProtectedPolicyDeleteAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE
        | TpmaNv.TPMA_NV_PLATFORMCREATE | TpmaNv.TPMA_NV_POLICY_DELETE;

    /// <summary>Dictionary-attack-protected, owner-created Ordinary Index attributes, for the bind target and the lockout driver.</summary>
    private const TpmaNv DaProtectedOwnerAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE;

    /// <summary>
    /// The attributes a <c>TPM_NT_PIN_FAIL</c> policy-delete Index is DEFINED with: the spec-mandated
    /// <c>TPMA_NV_NO_DA</c>, Index-authValue reads, owner-hierarchy provisioning and reporting of the counter
    /// window, and the platform-created/policy-delete pair this command demands.
    /// </summary>
    private const TpmaNv PinPolicyDeleteAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_OWNERREAD | TpmaNv.TPMA_NV_NO_DA
        | TpmaNv.TPMA_NV_PLATFORMCREATE | TpmaNv.TPMA_NV_POLICY_DELETE
        | (TpmaNv)((uint)TpmNt.TPM_NT_PIN_FAIL << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>The Index authorization value every Index here is defined with.</summary>
    private static byte[] IndexAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong authorization value, distinct from every correct one this file installs.</summary>
    private static byte[] WrongAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>The platformAuth value installed over the factory-empty one, so a command HMAC is keyed on a genuine secret.</summary>
    private static byte[] InstalledPlatformAuth { get; } = [0x19, 0x28, 0x37, 0x46, 0x55, 0x64, 0x73, 0x82];

    /// <summary>A single-octet payload for the priming write that drives the TPM into Lockout mode.</summary>
    private static byte[] PrimingWriteData { get; } = [0x2A];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Table 249's <c>@platform</c> row is "TPM_RH_PLATFORM+{PP}, Auth Index: 2, Auth Role: USER", so the slot
    /// takes an ordinary USER-role authorization: an unbound, unsalted HMAC session proving platformAuth. The
    /// command HMAC verifies against a cpHash whose Name terms are the Index's own Name and the platform
    /// handle's own four octets - "If the Name is a handle, the Name is only the handle value" (Part 1, clause
    /// 13, Table 9) - and the executor's own verification of BOTH response authorization entries is what makes the returned success
    /// meaningful. "This command allows removal of a platform-created NV Index that has TPMA_NV_POLICY_DELETE
    /// SET": the Index is gone afterwards.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.5.2, Table 249; Part 1, clause 15.7, equation 15</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialOverAnUnboundPlatformHmacSessionDeletesTheIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        (uint platformHandle, TpmSession platformSession) = await StartUnboundSessionAsync(device, pool, registry, InstalledPlatformAuth).ConfigureAwait(false);
        try
        {
            using(policySession)
            using(platformSession)
            {
                TpmResult<NvUndefineSpaceSpecialResponse> result = await DeleteOverSessionsAsync(
                    device, pool, registry, PolicyDeleteIndexHandle, policySession, platformSession).ConfigureAwait(false);

                Assert.IsTrue(result.IsSuccess, $"The USER-role platform slot over an HMAC session must authorize the deletion and its response authorization must verify on the host: '{result.ResponseCode}'.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(device, registry, pool, platformHandle).ConfigureAwait(false);
        }

        await AssertIndexIsGoneAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// "If the authorization is for the entity to which the session is bound, the HMAC key is the session's
    /// sessionKey" - a session bound to <c>TPM_RH_PLATFORM</c> authorizes the <c>@platform</c> slot with the authValue term
    /// OMITTED, because it was already folded into the session key at <c>TPM2_StartAuthSession()</c>. The
    /// deletion succeeds with an empty authValue term supplied on the host side, which no unbound session could
    /// achieve against a non-empty platformAuth.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.10, equations 20 and 22; Part 3, clause 31.5, Table 249</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialOverASessionBoundToThePlatformHierarchyDeletesTheIndexWithTheAuthValueOmitted()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        (uint platformHandle, TpmSession platformSession) = await StartBoundHmacSessionAsync(
            device, registry, pool, (uint)TpmRh.TPM_RH_PLATFORM, InstalledPlatformAuth).ConfigureAwait(false);
        try
        {
            using(policySession)
            using(platformSession)
            {
                platformSession.SetAuthValue(ReadOnlySpan<byte>.Empty, pool);

                TpmResult<NvUndefineSpaceSpecialResponse> result = await DeleteOverSessionsAsync(
                    device, pool, registry, PolicyDeleteIndexHandle, policySession, platformSession).ConfigureAwait(false);

                Assert.IsTrue(result.IsSuccess, $"A session bound to TPM_RH_PLATFORM omits the authValue term from the HMAC key, so an empty term must still authorize: '{result.ResponseCode}'.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(device, registry, pool, platformHandle).ConfigureAwait(false);
        }

        await AssertIndexIsGoneAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// "If the entity is authorized in a bind session, it receives DA protection if the bind entity receives DA
    /// protection" - a session BOUND to a dictionary-attack-protected NV Index carries that protection into the
    /// otherwise-exempt platform slot, so a WRONG platformAuth over it is the charging, session-encoded
    /// <c>TPM_RC_AUTH_FAIL</c> naming slot 1 rather than the exempt entity's non-charging
    /// <c>TPM_RC_BAD_AUTH</c>, and <c>failedTries</c> moves exactly once.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialOverAPlatformSessionBoundToADaProtectedIndexWithAWrongHmacReturnsAuthFailAndChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        await DefineOwnerIndexAsync(device, pool, registry, BindIndexHandle, DaProtectedOwnerAttributes).ConfigureAwait(false);
        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        (uint platformHandle, TpmSession platformSession) = await StartBoundHmacSessionAsync(device, registry, pool, BindIndexHandle, IndexAuth).ConfigureAwait(false);
        try
        {
            using(policySession)
            using(platformSession)
            {
                platformSession.SetAuthValue(WrongAuth, pool);

                TpmResult<NvUndefineSpaceSpecialResponse> result = await DeleteOverSessionsAsync(
                    device, pool, registry, PolicyDeleteIndexHandle, policySession, platformSession).ConfigureAwait(false);

                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 1), result.ResponseCode,
                    "A DA-protected bind entity turns the platform slot's TPM_RC_BAD_AUTH into the charging TPM_RC_AUTH_FAIL, blamed on slot 1.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(device, registry, pool, platformHandle).ConfigureAwait(false);
        }

        Assert.AreEqual(
            counterBefore + 1u, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "An authorization that receives DA protection through its bind entity charges failedTries exactly once on a mismatch.");
        await AssertIndexIsStillDefinedAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// The Lockout-mode half of the same bind sentence: "The authValue associated with a permanent entity, other
    /// than TPM_RH_LOCKOUT, does not receive DA protection", so the platform slot is exempt - but a session bound
    /// to a dictionary-attack-protected NV Index lends its protection to the command and, while the TPM is in
    /// Lockout mode, that command is refused with the bare <c>TPM_RC_LOCKOUT</c> before any credential is
    /// evaluated. A <c>TPM_RS_PW</c> platform slot on the same locked-out TPM deletes the Index, which is what
    /// makes the refusal a property of the BIND rather than of the platform hierarchy.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.8.1 and 16.8.3; Part 3, clause 31.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialOverAPlatformSessionBoundToADaProtectedIndexInLockoutModeReturnsLockoutWhileThePasswordSlotDeletes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        await DriveIntoLockoutAsync(device, pool, registry).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> lockedOut = await device.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lockedOut.IsSuccess, $"Reading the dictionary-attack parameters failed: '{lockedOut.ResponseCode}'.");
        Assert.IsTrue(lockedOut.Value.IsLockedOut, "The arrangement must leave the TPM in Lockout mode, or the case proves nothing.");

        (uint boundPolicyHandle, TpmSession boundPolicySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        (uint platformHandle, TpmSession platformSession) = await StartBoundHmacSessionAsync(device, registry, pool, BindIndexHandle, IndexAuth).ConfigureAwait(false);
        try
        {
            using(boundPolicySession)
            using(platformSession)
            {
                platformSession.SetAuthValue(ReadOnlySpan<byte>.Empty, pool);

                TpmResult<NvUndefineSpaceSpecialResponse> refused = await DeleteOverSessionsAsync(
                    device, pool, registry, PolicyDeleteIndexHandle, boundPolicySession, platformSession).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_LOCKOUT, refused.ResponseCode,
                    "A bind entity that receives DA protection lends it to the command, which Lockout mode refuses with the bare TPM_RC_LOCKOUT.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, boundPolicyHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(device, registry, pool, platformHandle).ConfigureAwait(false);
        }

        await AssertIndexIsStillDefinedAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        (uint passwordPolicyHandle, TpmSession passwordPolicySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(passwordPolicySession)
            {
                using TpmPasswordSession platformPassword = TpmPasswordSession.CreateEmpty(pool);

                TpmResult<NvUndefineSpaceSpecialResponse> accepted = await DeleteOverSessionsAsync(
                    device, pool, registry, PolicyDeleteIndexHandle, passwordPolicySession, platformPassword).ConfigureAwait(false);

                Assert.IsTrue(accepted.IsSuccess, $"The platform hierarchy's own authValue is dictionary-attack exempt, so Lockout mode never gates it: '{accepted.ResponseCode}'.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, passwordPolicyHandle).ConfigureAwait(false);
        }

        await AssertIndexIsGoneAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// "The authValue associated with a permanent entity, other than TPM_RH_LOCKOUT, does not receive DA
    /// protection" - a wrong platformAuth at the <c>@platform</c> slot is therefore the non-charging
    /// <c>TPM_RC_BAD_AUTH</c>, session-encoded to slot 1 because the failure names which authorization was not
    /// satisfied, and <c>failedTries</c> stands still. Proven on both forms the USER-role slot admits: a
    /// <c>TPM_RS_PW</c> password block and a real HMAC session.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 2, clause 6.6.2; Part 3, clause 31.5, Table 249</see>.
    /// </summary>
    /// <param name="isPlatformSlotAnHmacSession">Whether the platform slot is a real HMAC session rather than a <c>TPM_RS_PW</c> password block.</param>
    [TestMethod]
    [DataRow(false, DisplayName = "a TPM_RS_PW platform slot carrying the wrong platformAuth")]
    [DataRow(true, DisplayName = "an HMAC platform session keyed on the wrong platformAuth")]
    public async Task NvUndefineSpaceSpecialWithAWrongPlatformAuthReturnsSessionEncodedBadAuthUncharged(bool isPlatformSlotAnHmacSession)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        uint platformHandle = 0;
        TpmSession? platformSession = null;
        try
        {
            using(policySession)
            {
                TpmSessionBase platformSlot;
                if(isPlatformSlotAnHmacSession)
                {
                    (platformHandle, platformSession) = await StartUnboundSessionAsync(device, pool, registry, WrongAuth).ConfigureAwait(false);
                    platformSlot = platformSession;
                }
                else
                {
                    platformSlot = TpmPasswordSession.Create(WrongAuth, pool);
                }

                using(platformSlot as IDisposable)
                {
                    TpmResult<NvUndefineSpaceSpecialResponse> result = await DeleteOverSessionsAsync(
                        device, pool, registry, PolicyDeleteIndexHandle, policySession, platformSlot).ConfigureAwait(false);

                    Assert.AreEqual(
                        SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 1), result.ResponseCode,
                        "A wrong platformAuth is the exempt permanent entity's non-charging TPM_RC_BAD_AUTH, blamed on the slot that carried it.");
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(device, registry, pool, platformHandle).ConfigureAwait(false);
        }

        Assert.AreEqual(
            counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "The platform hierarchy's authValue is dictionary-attack exempt, so the mismatch never charges failedTries.");
        await AssertIndexIsStillDefinedAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// "After unmarshaling and validating the handles and the consistency of the authorization sessions, the
    /// authorizations shall be checked" - one authorization at a time, in the order the sessions appear. A
    /// request whose ADMIN slot cannot verify (a policy folding the Index authValue, keyed on a WRONG one) AND
    /// whose platform password is also wrong answers the SLOT-0 failure: the dictionary-attack charge follows
    /// slot 0's own rules (the Index is DA-protected and its authValue was folded, so <c>failedTries</c> moves
    /// once), and the platform compare is never reached, which the answer's session index alone reveals.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.6; Part 1, clauses 16.6.5 and 16.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialWithAFailingPolicyHmacAndAWrongPlatformPasswordAnswersTheSlotZeroFailure()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeAuthValueDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(
            device, pool, registry, DaProtectedPolicyDeleteIndexHandle, DaProtectedPolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: true, WrongAuth).ConfigureAwait(false);
        try
        {
            using(policySession)
            {
                using TpmPasswordSession platformSlot = TpmPasswordSession.Create(WrongAuth, pool);

                TpmResult<NvUndefineSpaceSpecialResponse> result = await DeleteOverSessionsAsync(
                    device, pool, registry, DaProtectedPolicyDeleteIndexHandle, policySession, platformSlot).ConfigureAwait(false);

                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode,
                    "The first authorization in wire order decides the answer, so a failing ADMIN slot is reported before the platform password is ever compared.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }

        Assert.AreEqual(
            counterBefore + 1u, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "The charge follows slot 0's own rules: a policy folding a DA-protected Index's authValue charges failedTries once on a mismatch.");
        await AssertIndexIsStillDefinedAsync(device, DaProtectedPolicyDeleteIndexHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// The PIN half of the same wire-order rule: a <c>TPM_NT_PIN_FAIL</c> Index whose deletion policy asserts
    /// <c>TPM2_PolicyAuthValue()</c> spends an attempt on a slot-0 mismatch - "If the authorization fails,
    /// pinCount is incremented for a PIN Fail Index and left unchanged for a PIN Pass Index" - while the wrong
    /// platform password behind it is never compared. The Index carries <c>TPMA_NV_NO_DA</c>, so the refusal is
    /// the non-charging <c>TPM_RC_BAD_AUTH</c> at slot 0 and the lockout counter stands still, which is exactly
    /// slot 0's own rule rather than slot 1's.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.6; Part 3, clause 5.6; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialWithAFailingPolicyHmacSpendsThePinAttemptWhileThePlatformPasswordIsNeverCompared()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeAuthValueDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(
            device, pool, registry, PinPolicyDeleteIndexHandle, PinPolicyDeleteAttributes, deletionPolicy, PinCounterParametersSize).ConfigureAwait(false);
        await WritePinCounterParametersAsync(device, pool, registry, PinPolicyDeleteIndexHandle, pinCount: 0, pinLimit: 3).ConfigureAwait(false);
        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: true, WrongAuth).ConfigureAwait(false);
        try
        {
            using(policySession)
            {
                using TpmPasswordSession platformSlot = TpmPasswordSession.Create(WrongAuth, pool);

                TpmResult<NvUndefineSpaceSpecialResponse> result = await DeleteOverSessionsAsync(
                    device, pool, registry, PinPolicyDeleteIndexHandle, policySession, platformSlot).ConfigureAwait(false);

                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
                    "A TPMA_NV_NO_DA Index's mismatch is the non-charging TPM_RC_BAD_AUTH, still blamed on the ADMIN slot that failed.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }

        await AssertPinCountIsAsync(device, PinPolicyDeleteIndexHandle, expectedPinCount: 1).ConfigureAwait(false);
        Assert.AreEqual(
            counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "A TPMA_NV_NO_DA Index's authValue receives no dictionary-attack protection, so the attempt is charged to pinCount alone.");
    }

    /// <summary>
    /// The <c>@platform</c> slot is a USER-role slot, so clause 5.5 step 4's resolution admits an HMAC session or
    /// <c>TPM_RS_PW</c>; a LOADED POLICY session there names ownerPolicy/platformPolicy, a kind of authorization
    /// this simulator does not implement, and is refused with the bare <c>TPM_RC_AUTH_TYPE</c> naming no slot -
    /// the same answer the hierarchy family's own provisioning slot gives.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4; clause 31.5, Table 249</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialOverALoadedPolicySessionAtThePlatformSlotReturnsAuthType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        TpmResult<StartAuthSessionResponse> platformStart = await device.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(platformStart.IsSuccess, $"StartPolicySessionAsync failed: '{platformStart.ResponseCode}'.");

        using StartAuthSessionResponse platformStarted = platformStart.Value;
        uint platformHandle = platformStarted.SessionHandle.Value;
        try
        {
            using(policySession)
            {
                using TpmPolicySession platformSlot = TpmPolicySession.ForSession(platformHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);

                TpmResult<NvUndefineSpaceSpecialResponse> result = await DeleteOverSessionsAsync(
                    device, pool, registry, PolicyDeleteIndexHandle, policySession, platformSlot).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode,
                    "A genuine POLICY session at the USER-role platform slot must be refused with the bare TPM_RC_AUTH_TYPE.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(device, registry, pool, platformHandle).ConfigureAwait(false);
        }

        await AssertIndexIsStillDefinedAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// A session handle in the <c>0x02000000</c> range that names no loaded session is blamed on the offending
    /// slot INDEX: the platform slot is the second authorization, so "TPM_RC_REFERENCE_S1 ... the 2nd session
    /// handle references a session that is not loaded" - distinct from the bare <c>TPM_RC_AUTH_TYPE</c> a
    /// LOADED policy session earns there.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.6.2; Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialOverAnUnloadedPlatformSessionHandleReturnsReferenceMissAtSlotOne()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        (uint platformHandle, TpmSession platformSession) = await StartUnboundSessionAsync(device, pool, registry, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(policySession)
            using(platformSession)
            {
                await FlushIfPresentAsync(device, registry, pool, platformHandle).ConfigureAwait(false);

                TpmResult<NvUndefineSpaceSpecialResponse> result = await DeleteOverSessionsAsync(
                    device, pool, registry, PolicyDeleteIndexHandle, policySession, platformSession).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_REFERENCE_S1, result.ResponseCode,
                    "A session handle naming no loaded session must be blamed on the offending slot index, which for @platform is the second.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }

        await AssertIndexIsStillDefinedAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// The third row of the platform slot's own resolution: "If the session handle is not a handle for an HMAC
    /// session, a handle for a policy session, or, TPM_RS_PW then the TPM shall return TPM_RC_HANDLE" - a
    /// NON-SESSION handle framed into the slot (a transient-object handle, or a defined NV Index handle) is
    /// refused before any credential is evaluated, session-index-encoded to slot 1.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4.1; Part 2, clause 6.6.2</see>.
    /// </summary>
    /// <param name="slotHandle">The non-session value framed into the platform slot's session handle field.</param>
    [TestMethod]
    [DataRow(TransientRangeHandle, DisplayName = "a transient-object handle is not a session")]
    [DataRow(PolicyDeleteIndexHandle, DisplayName = "a defined NV Index handle is not a session")]
    public async Task NvUndefineSpaceSpecialWithANonSessionHandleAtThePlatformSlotReturnsSessionEncodedHandle(uint slotHandle)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadIndexNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(policySession)
            {
                (TpmRcConstants rawCode, _) = await SubmitHandFramedDeletionAsync(
                    device, pool, PolicyDeleteIndexHandle, indexName, policySession, platformSession: null, ReadOnlyMemory<byte>.Empty,
                    policySlotAttribute: default, platformSlotAttribute: default, platformSlotHandleOverride: slotHandle, hasCompanionBlock: false).ConfigureAwait(false);

                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 1), rawCode,
                    "A non-session handle at the platform slot is refused with the session-index-encoded TPM_RC_HANDLE, ahead of any credential evaluation.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }

        await AssertIndexIsStillDefinedAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>@platform</c> is a <c>TPMI_RH_PLATFORM</c>, whose table lists the single value "TPM_RH_PLATFORM
    /// Platform hierarchy" and the unmarshalling answer "#TPM_RC_VALUE response code returned when the
    /// unmarshaling of this type fails" - so any other hierarchy handle in that position, including the two that
    /// authorize the sibling deletion command, is the <c>TPM_RC_VALUE</c>, handle-encoded to the same index the interface type itself
    /// defines, decided at parse before any authorization is looked at.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.18, Table 64; Part 3, clause 31.5, Table 249</see>.
    /// </summary>
    /// <param name="platformSlotHandle">The handle framed where <c>TPMI_RH_PLATFORM</c> belongs.</param>
    [TestMethod]
    [DataRow((uint)TpmRh.TPM_RH_OWNER, DisplayName = "TPM_RH_OWNER is not TPMI_RH_PLATFORM")]
    [DataRow((uint)TpmRh.TPM_RH_ENDORSEMENT, DisplayName = "TPM_RH_ENDORSEMENT is not TPMI_RH_PLATFORM")]
    public async Task NvUndefineSpaceSpecialWithANonPlatformHandleReturnsValue(uint platformSlotHandle)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadIndexNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(policySession)
            {
                using TpmPasswordSession platformSlot = TpmPasswordSession.CreateEmpty(pool);
                var input = new NvUndefineSpaceSpecialInput(PolicyDeleteIndexHandle, (TpmRh)platformSlotHandle);

                TpmResult<NvUndefineSpaceSpecialResponse> result = await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceSpecialResponse>(
                    device, input, [policySession, platformSlot], [indexName, ReadOnlyMemory<byte>.Empty], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, handleIndex: 1), result.ResponseCode,
                    "Table 249: @platform is TPM2_NV_UndefineSpaceSpecial()'s second handle (index 1); a handle outside TPMI_RH_PLATFORM is that interface type's own unmarshalling failure there.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }

        await AssertIndexIsStillDefinedAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>@nvIndex</c> is <c>TPMI_RH_NV_DEFINED_INDEX</c>, whose admitted set is the ordinary and external NV
    /// Index ranges: "#TPM_RC_VALUE error returned if the handle is out of range". A PCR-range handle and the
    /// first permanent-range handle both fall outside every NV Index range, so each is that interface type's
    /// own unmarshalling failure, decided at parse before the authorization area is even read.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.26, Table 72; Part 3, clause 31.5, Table 249</see>.
    /// </summary>
    /// <param name="malformedNvIndex">The out-of-range handle framed where <c>@nvIndex</c> belongs.</param>
    [TestMethod]
    [DataRow(0x0000_0000u, DisplayName = "a PCR-range handle is outside every NV Index range")]
    [DataRow(0x4000_0000u, DisplayName = "the first permanent-range handle is outside every NV Index range")]
    public async Task NvUndefineSpaceSpecialWithAnOutOfRangeNvIndexReturnsValue(uint malformedNvIndex)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadIndexNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(policySession)
            {
                (TpmRcConstants rawCode, _) = await SubmitHandFramedDeletionAsync(
                    device, pool, malformedNvIndex, indexName, policySession, platformSession: null, ReadOnlyMemory<byte>.Empty,
                    policySlotAttribute: default, platformSlotAttribute: default, platformSlotHandleOverride: null, hasCompanionBlock: false).ConfigureAwait(false);

                Assert.AreEqual(
                    HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, handleIndex: 0), rawCode,
                    "Table 249: @nvIndex is TPM2_NV_UndefineSpaceSpecial()'s first handle (index 0); Table 72's #TPM_RC_VALUE fires there for an @nvIndex outside every NV Index range, decided at parse.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }

        await AssertIndexIsStillDefinedAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// Table 249 fixes the tag at <c>TPM_ST_SESSIONS</c> and marks BOTH handles with the '@' decoration: "An
    /// authorization session is present for each of the handles with the '@' decoration (TPM_RC_AUTH_MISSING)".
    /// A <c>TPM_ST_NO_SESSIONS</c> frame carries no authorization area at all, so neither authorization the
    /// command owes is supplied.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 5; clause 31.5, Table 249</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialWithoutAnAuthorizationAreaReturnsAuthMissing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        //The handle area alone: the frame declares no sessions and carries no authorization area.
        var body = new List<byte>();
        AppendUInt32(body, PolicyDeleteIndexHandle);
        AppendUInt32(body, (uint)TpmRh.TPM_RH_PLATFORM);

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_NO_SESSIONS, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_MISSING, code, "A command owing two authorizations and sent without an authorization area is TPM_RC_AUTH_MISSING.");
    }

    /// <summary>
    /// The same rule counted rather than merely present: with two '@'-decorated handles the area owes TWO whole
    /// blocks, so an area holding exactly ONE well-formed block leaves the second authorization missing and is
    /// <c>TPM_RC_AUTH_MISSING</c> - answered bare, ahead of any per-slot resolution.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 5; clause 31.5, Table 249</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialWithASingleAuthorizationBlockReturnsAuthMissing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        //Handle area, then an authorization area carrying one well-formed password block where two are owed.
        var body = new List<byte>();
        AppendUInt32(body, PolicyDeleteIndexHandle);
        AppendUInt32(body, (uint)TpmRh.TPM_RH_PLATFORM);
        AppendPasswordAuthorizationArea(body, blockCount: 1);

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_SESSIONS, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_MISSING, code, "One block for two '@'-decorated handles is one authorization short, which is TPM_RC_AUTH_MISSING.");
    }

    /// <summary>
    /// "If a session is not being used for authorization, at least one of decrypt, encrypt, or audit must be SET.
    /// (TPM_RC_ATTRIBUTES)" - Table 249 lists no parameters at all and this simulator models no audit trail, so
    /// nothing exists for a THIRD block to claim: it authorizes no handle (the command has only two) and may
    /// hold none of the three attributes that would justify its presence, so it is refused session-encoded to
    /// index 2.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4.4.2; clause 5.7; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialWithAThirdAuthorizationBlockReturnsSessionEncodedAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadIndexNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(policySession)
            {
                (TpmRcConstants rawCode, _) = await SubmitHandFramedDeletionAsync(
                    device, pool, PolicyDeleteIndexHandle, indexName, policySession, platformSession: null, ReadOnlyMemory<byte>.Empty,
                    policySlotAttribute: default, platformSlotAttribute: default, platformSlotHandleOverride: null, hasCompanionBlock: true).ConfigureAwait(false);

                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 2), rawCode,
                    "A companion block on a parameterless, non-auditable command claims nothing it may hold and is refused at its own index.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }

        await AssertIndexIsStillDefinedAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// The handle area is two four-octet handles, @nvIndex then @platform (TPM 2.0 Library Part 3, clause 31.5,
    /// Table 249): a frame carrying the full four octets of @nvIndex (top octet <c>TPM_HT_NV_INDEX</c>, so its
    /// own range check passes) and only three of @platform's runs out of buffer on @platform's own read, which
    /// Table 2's unmarshalling-error row answers - "the input buffer did not contain enough octets to allow
    /// unmarshaling of the expected data type" - handle-encoded <c>TPM_RC_INSUFFICIENT</c> at index 1, the field
    /// whose own read failed, not @nvIndex's index 0.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.5, Table 249; clause 5.8.2, Table 2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialWithATruncatedHandleAreaReturnsInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        //A full four-octet @nvIndex (TPM_HT_NV_INDEX top octet) then only three of @platform's four octets.
        byte[] body = [0x01, 0x00, 0x00, 0x65, 0x40, 0x00, 0x00];

        TpmRcConstants code = await SubmitFramedAsync(simulator, pool, TpmStConstants.TPM_ST_SESSIONS, body).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, handleIndex: 1), code,
            "Table 249: @nvIndex (index 0) reads cleanly and passes its own range check; @platform (index 1) is the field whose own read fails on a seven-octet handle area, so the refusal is handle-encoded TPM_RC_INSUFFICIENT at index 1.");
    }

    /// <summary>
    /// Table 249 defines no command parameters, so nothing may follow the authorization area: one trailing octet
    /// is unmarshaled as if it began a further structure the command never declares, which Table 2's
    /// unmarshalling-error row answers - "the value of a size parameter is larger or smaller than allowed" - the
    /// bare <c>TPM_RC_SIZE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.5, Table 249; clause 5.8.2, Table 2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialWithATrailingOctetAfterTheAuthorizationAreaReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        //Handle area, a well-formed two-block password authorization area, then one octet too many.
        var body = new List<byte>();
        AppendUInt32(body, PolicyDeleteIndexHandle);
        AppendUInt32(body, (uint)TpmRh.TPM_RH_PLATFORM);
        AppendPasswordAuthorizationArea(body, blockCount: 2);
        body.Add(0x00);

        TpmRcConstants code = await SubmitFramedAsync(simulator, pool, TpmStConstants.TPM_ST_SESSIONS, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "No octet may follow the authorization area of a command that declares no parameters.");
    }

    /// <summary>
    /// The smallest well-formed authorization block is nine octets - a session handle, an empty nonce, the
    /// <c>sessionAttributes</c> octet and an empty hmac - so a declared <c>authorizationSize</c> below that is
    /// "the value of authorizationSize is out of range or the number of octets in the Authorization Area is
    /// greater than required", the bare <c>TPM_RC_AUTHSIZE</c>, refused before the area is ever walked and so
    /// before the missing second block could be noticed.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 3.1; Part 2, Table 18</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialWithAnUndersizedAuthorizationAreaReturnsAuthsize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        //Handle area, then an authorization area declaring eight octets and framing exactly eight - one short of
        //the nine-octet minimum, so the size itself is what is refused rather than the buffer running out.
        var body = new List<byte>();
        AppendUInt32(body, PolicyDeleteIndexHandle);
        AppendUInt32(body, (uint)TpmRh.TPM_RH_PLATFORM);
        AppendUInt32(body, 8u);
        AppendUInt32(body, (uint)TpmRh.TPM_RH_PW);
        AppendUInt16(body, 0);
        body.Add((byte)TpmaSession.CONTINUE_SESSION);
        body.Add(0x00);

        TpmRcConstants code = await SubmitFramedAsync(simulator, pool, TpmStConstants.TPM_ST_SESSIONS, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTHSIZE, code, "An authorizationSize below the nine-octet minimum is TPM_RC_AUTHSIZE.");
    }

    /// <summary>
    /// "If an authorization session has the TPMA_SESSION.decrypt attribute SET, and the command does not allow a
    /// command parameter to be encrypted, then the TPM will return TPM_RC_ATTRIBUTES" - and its response twin,
    /// since Table 250 is the header alone. Table 249 declares no parameter in either direction, so EITHER
    /// authorizing slot claiming <c>decrypt</c> or <c>encrypt</c> fails closed, blamed on the slot that claimed
    /// it. Proven hand-framed, because the executor's own client-side guard refuses the composition before any
    /// octet reaches the wire.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.7; Part 1, clause 18.1; Part 2, clause 6.6.2</see>.
    /// </summary>
    /// <param name="isClaimedByThePlatformSlot">Whether the platform slot rather than the ADMIN slot carries the attribute.</param>
    /// <param name="isEncryptRatherThanDecrypt">Whether the attribute under test is <c>encrypt</c> rather than <c>decrypt</c>.</param>
    [TestMethod]
    [DataRow(false, false, DisplayName = "the ADMIN slot claims decrypt")]
    [DataRow(false, true, DisplayName = "the ADMIN slot claims encrypt")]
    [DataRow(true, false, DisplayName = "the platform slot claims decrypt")]
    [DataRow(true, true, DisplayName = "the platform slot claims encrypt")]
    public async Task NvUndefineSpaceSpecialWithAParameterEncryptionAttributeReturnsSessionEncodedAttributesAtTheClaimingSlot(
        bool isClaimedByThePlatformSlot, bool isEncryptRatherThanDecrypt)
    {
        TpmaSession attribute = isEncryptRatherThanDecrypt ? TpmaSession.ENCRYPT : TpmaSession.DECRYPT;

        await AssertSessionAttributeIsRefusedAtItsSlotAsync(attribute, isClaimedByThePlatformSlot).ConfigureAwait(false);
    }

    /// <summary>
    /// The <c>audit</c> attribute on the ADMIN slot fails closed with <c>TPM_RC_ATTRIBUTES</c> naming that slot:
    /// the ADMIN slot is a policy session, and <c>audit</c> "is not allowed to be SET in a policy or trial policy
    /// session" (TPM 2.0 Library Part 1, Table 15, the audit row) — the claim is refused as an ATTRIBUTES
    /// violation of the session's own kind, not because audit is unsupported.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, Table 15</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialWithAnAuditAttributeOnTheAdminSlotIsRefusedWithAttributes()
    {
        await AssertSessionAttributeIsRefusedAtItsSlotAsync(TpmaSession.AUDIT, isClaimedByThePlatformSlot: false).ConfigureAwait(false);
    }

    /// <summary>
    /// The <c>audit</c> attribute on the platform slot — a real HMAC session, unlike the ADMIN slot's policy
    /// session — is admitted (TPM 2.0 Library Part 1, clause 17.1) and the deletion succeeds, extending the
    /// platform session's audit digest to <c>H(0…0 ‖ cpHash ‖ rpHash)</c> on its first use (equation 30) with
    /// the response echoing <c>audit</c> SET, <c>auditExclusive</c> SET and <c>auditReset</c> CLEAR (TPM 2.0
    /// Library Part 2, clause 8.4, Table 38) — proved by chaining cpHash/rpHash from the octets this test itself
    /// sent and read, then reading the platform session's digest back through
    /// <c>TPM2_GetSessionAuditDigest()</c> with the NULL signer even though the Index it deleted is GONE
    /// afterward; the platform slot's session, not the deleted Index, is what carries the digest.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1; Part 2, clause 8.4, Table 38</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialWithAnAuditAttributeOnThePlatformSlotSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        byte[] deletionPolicy = ComputeCommandCodeOnlyDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadIndexNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        (uint platformHandle, TpmSession platformSession) = await StartUnboundSessionAsync(device, pool, registry, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(policySession)
            using(platformSession)
            {
                (byte[] response, byte[] cpHash) = await SubmitHandFramedDeletionForAuditAsync(
                    device, pool, PolicyDeleteIndexHandle, indexName, policySession, platformSession).ConfigureAwait(false);

                var responseReader = new TpmReader(response);
                TpmRcConstants rawCode = (TpmRcConstants)TpmHeader.Parse(ref responseReader).Code;
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_SUCCESS, rawCode,
                    "The platform slot's audit claim is admitted and the deletion succeeds (TPM 2.0 Library Part 1, clause 17.1).");

                byte auditedAttributes = ReadResponseSessionAttributes(response, outHandleCount: 0, sessionIndex: 1);
                Assert.AreEqual(
                    (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE), auditedAttributes,
                    "The platform slot's response echoes audit SET and auditExclusive SET (the session's first use as an audit session), with auditReset CLEAR (TPM 2.0 Library Part 2, clause 8.4, Table 38).");

                byte[] responseParameters = ReadResponseParameters(response, outHandleCount: 0);
                byte[] rpHash = await ComputeRpHashAsync(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, responseParameters, pool).ConfigureAwait(false);
                byte[] expectedDigest = await ExtendAuditDigestAsync(priorDigest: null, cpHash, rpHash, pool).ConfigureAwait(false);

                using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(platformHandle), ReadOnlySpan<byte>.Empty, pool);
                using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
                using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);

                TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                    device, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                using GetSessionAuditDigestResponse? auditDigestResponse = digestResult.IsSuccess ? digestResult.Value : null;

                Assert.IsTrue(
                    digestResult.IsSuccess,
                    $"TPM2_GetSessionAuditDigest() over the platform slot must succeed even though the deleted Index is gone: '{digestResult.ResponseCode}'.");
                Assert.IsTrue(auditDigestResponse!.SessionAudit.ExclusiveSession.IsYes, "The platform slot became the exclusive audit session on its first use (TPM 2.0 Library Part 1, clause 17.2).");
                Assert.IsTrue(
                    expectedDigest.AsSpan().SequenceEqual(auditDigestResponse.SessionAudit.SessionDigest.AsReadOnlySpan()),
                    "The platform slot's audit digest must equal H(0…0 ‖ cpHash ‖ rpHash) chained from the deletion exchange's own wire octets (TPM 2.0 Library Part 1, clause 17.1, equation 30).");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(device, registry, pool, platformHandle).ConfigureAwait(false);
        }

        await AssertIndexIsGoneAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// The client-side half of the same rule: "only the first parameter in the parameter area of a request or
    /// response can be encrypted" and Table 249/250 declare none, so the executor refuses to compose a command
    /// whose session claims <c>decrypt</c> or <c>encrypt</c> with an <see cref="ArgumentException"/> before any
    /// octet reaches the wire.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 31.5, Tables 249 and 250</see>.
    /// </summary>
    /// <param name="isEncryptRatherThanDecrypt">Whether the attribute under test is <c>encrypt</c> rather than <c>decrypt</c>.</param>
    [TestMethod]
    [DataRow(false, DisplayName = "decrypt has no encryptable command parameter to act on")]
    [DataRow(true, DisplayName = "encrypt has no encryptable response parameter to act on")]
    public async Task NvUndefineSpaceSpecialWithAParameterEncryptionAttributeIsRefusedByTheExecutorBeforeTheWire(bool isEncryptRatherThanDecrypt)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadIndexNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(policySession)
            {
                using TpmPasswordSession platformSlot = TpmPasswordSession.CreateEmpty(pool);
                policySession.SessionAttributes |= isEncryptRatherThanDecrypt ? TpmaSession.ENCRYPT : TpmaSession.DECRYPT;
                var input = new NvUndefineSpaceSpecialInput(PolicyDeleteIndexHandle);

                _ = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
                    await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceSpecialResponse>(
                        device, input, [policySession, platformSlot], [indexName, ReadOnlyMemory<byte>.Empty], pool, registry,
                        TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The accepting half of the raw command-HMAC proof: a hand-framed composition whose cpHash is computed
    /// independently - the command code, then the Index's own Name, then the platform handle's four octets, with
    /// an EMPTY parameters term because Table 249 declares no parameters - is accepted, which makes that
    /// independently computed digest the thing the TPM's own command-HMAC verification agrees with. The ADMIN
    /// slot rides a <c>TPM2_PolicyCommandCode()</c>-only policy, whose HMAC key is therefore the empty session
    /// key alone, and the platform slot is a <c>TPM_RS_PW</c> block.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.7, equation 15, and clause 13, Table 9; Part 3, clause 31.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialHandFramedWithTheCorrectCpHashDeletesTheIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        await InstallPlatformAuthAsync(device).ConfigureAwait(false);
        byte[] indexName = await ReadIndexNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(policySession)
            {
                (TpmRcConstants rawCode, _) = await SubmitHandFramedDeletionAsync(
                    device, pool, PolicyDeleteIndexHandle, indexName, policySession, platformSession: null, InstalledPlatformAuth,
                    policySlotAttribute: default, platformSlotAttribute: default, platformSlotHandleOverride: null, hasCompanionBlock: false).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, rawCode, $"A cpHash independently computed the production way must verify: '{rawCode}'.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }

        await AssertIndexIsGoneAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// The negative twin: the same composition, but cpHash folds the Index's STALE pre-write Name while the wire
    /// still names the Index as it now stands. "The caller should use its copy of the NV public area and
    /// calculate the Name before using it in an HMAC authorization calculation" - a command HMAC keyed on the
    /// wrong Name term cannot verify against the octets the TPM actually received, so it is the session-encoded
    /// <c>TPM_RC_BAD_AUTH</c> at the ADMIN slot and the Index survives.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 13 and 15.7, equation 15; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialHandFramedWithTheStaleIndexNameReturnsSessionEncodedBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] staleName = await ReadIndexNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, IndexAuth, PrimingWriteData).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"TPM2_NV_Write() failed: '{writeResult.ResponseCode}'.");

        byte[] freshName = await ReadIndexNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
        Assert.IsFalse(staleName.AsSpan().SequenceEqual(freshName), "SETting TPMA_NV_WRITTEN moves the Name the Index's public area digests.");

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(policySession)
            {
                (TpmRcConstants rawCode, _) = await SubmitHandFramedDeletionAsync(
                    device, pool, PolicyDeleteIndexHandle, staleName, policySession, platformSession: null, ReadOnlyMemory<byte>.Empty,
                    policySlotAttribute: default, platformSlotAttribute: default, platformSlotHandleOverride: null, hasCompanionBlock: false).ConfigureAwait(false);

                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), rawCode,
                    "cpHash folding the stale Name cannot key a command HMAC that verifies against the octets actually on the wire.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }

        await AssertIndexIsStillDefinedAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// A literal replay of a captured, previously successful deletion is refused, and the session it rode is not
    /// simply reusable: "Since the index is deleted, the Empty Buffer is used as the authValue when generating
    /// the response HMAC" - the success rolled <c>nonceTPM</c> and RESET the policy session's context, so a
    /// second deletion on the same session needs its assertions made afresh. The replayed octets name an Index
    /// that no longer exists (<c>TPM_RC_HANDLE</c>); the same session reused against a second Index without
    /// re-asserting is <c>TPM_RC_POLICY_FAIL</c>, its accumulated <c>policyDigest</c> having gone back to its
    /// starting value; and re-asserting <c>TPM2_PolicyCommandCode()</c> on that same session deletes the second
    /// Index, which only correctly rolled nonces on both sides allow.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.5.1; Part 1, clauses 16.6.3 and 16.7</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialReplayOfACapturedSuccessIsRefusedAndTheSessionNeedsFreshAssertions()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        var capturedCommands = new List<byte[]>();
        using TpmDevice device = CreateCapturingDevice(simulator, capturedCommands);
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        await DefinePolicyDeleteIndexAsync(device, pool, registry, SecondPolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(policySession)
            {
                using TpmPasswordSession platformSlot = TpmPasswordSession.CreateEmpty(pool);

                capturedCommands.Clear();
                TpmResult<NvUndefineSpaceSpecialResponse> first = await DeleteOverSessionsAsync(
                    device, pool, registry, PolicyDeleteIndexHandle, policySession, platformSlot).ConfigureAwait(false);
                Assert.IsTrue(first.IsSuccess, $"The captured deletion must succeed the first time: '{first.ResponseCode}'.");
                Assert.IsNotEmpty(capturedCommands, "The capturing device must have recorded the framed command this replay test needs.");

                byte[] framedCommand = capturedCommands[^1];
                using IMemoryOwner<byte> replayOwner = pool.Rent(framedCommand.Length);
                Memory<byte> replay = replayOwner.Memory[..framedCommand.Length];
                framedCommand.CopyTo(replay);

                TpmResult<TpmResponse> replayResult = await simulator.SubmitAsync(replay, pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(replayResult.IsSuccess, "The transport itself must succeed even when the TPM refuses the replay.");

                using(TpmResponse replayResponse = replayResult.Value)
                {
                    var replayReader = new TpmReader(replayResponse.AsReadOnlySpan());

                    Assert.AreEqual(
                        HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), (TpmRcConstants)TpmHeader.Parse(ref replayReader).Code,
                        "A successful deletion can never repeat: the replayed octets name an Index the first submission removed.");
                }

                TpmResult<NvUndefineSpaceSpecialResponse> withoutFreshAssertions = await DeleteOverSessionsAsync(
                    device, pool, registry, SecondPolicyDeleteIndexHandle, policySession, platformSlot).ConfigureAwait(false);
                Assert.AreEqual(
                    HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_POLICY_FAIL, 0), withoutFreshAssertions.ResponseCode,
                    "The success reset the policy session's context, so its policyDigest no longer matches the Index authPolicy.");

                TpmResult<PolicyCommandCodeResponse> reasserted = await device.PolicyCommandCodeAsync(
                    policyHandle, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(reasserted.IsSuccess, $"PolicyCommandCodeAsync failed: '{reasserted.ResponseCode}'.");

                TpmResult<NvUndefineSpaceSpecialResponse> second = await DeleteOverSessionsAsync(
                    device, pool, registry, SecondPolicyDeleteIndexHandle, policySession, platformSlot).ConfigureAwait(false);
                Assert.IsTrue(second.IsSuccess, $"A freshly asserted policy on the same session must delete the second Index: '{second.ResponseCode}'.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }

        await AssertIndexIsGoneAsync(device, SecondPolicyDeleteIndexHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// "For a response, the TPM uses the last nonceCaller and a newly generated nonceTPM in the HMAC" - and an
    /// error answer is the header alone, which carries no response authorization and therefore rolls nothing and
    /// resets nothing: a deletion refused at the platform slot leaves the ADMIN session's nonce and its
    /// accumulated assertions exactly as they were, so the very next attempt on that same session, with the
    /// right platformAuth, succeeds without re-asserting anything.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.3; Part 3, clause 31.5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialLeavesTheAdminSessionUsableAfterARefusalAndRollsOnlyOnSuccess()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(policySession)
            {
                using(TpmPasswordSession wrongPlatformSlot = TpmPasswordSession.Create(WrongAuth, pool))
                {
                    TpmResult<NvUndefineSpaceSpecialResponse> refused = await DeleteOverSessionsAsync(
                        device, pool, registry, PolicyDeleteIndexHandle, policySession, wrongPlatformSlot).ConfigureAwait(false);

                    Assert.AreEqual(
                        SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 1), refused.ResponseCode,
                        "A wrong platformAuth is the exempt permanent entity's non-charging TPM_RC_BAD_AUTH at slot 1.");
                }

                using TpmPasswordSession correctPlatformSlot = TpmPasswordSession.Create(InstalledPlatformAuth, pool);
                TpmResult<NvUndefineSpaceSpecialResponse> accepted = await DeleteOverSessionsAsync(
                    device, pool, registry, PolicyDeleteIndexHandle, policySession, correctPlatformSlot).ConfigureAwait(false);

                Assert.IsTrue(
                    accepted.IsSuccess,
                    $"A header-only refusal rolls no nonceTPM and resets no policy context, so the next command on the same session must still verify: '{accepted.ResponseCode}'.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
        }

        await AssertIndexIsGoneAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// The two-slot form returns every carrier its parse rented - the always-empty raw parameter area, both
    /// slots' nonces and credentials, and the Index Name the cpHash computation produced - across a refusal at
    /// the platform slot and a success. A refusal leaves the meter exactly where it found it; a success leaves it
    /// lower by precisely the footprint the deleted Index itself retained from its definition, because "this
    /// command allows removal of a platform-created NV Index" and removal is that Index's ownership-end
    /// boundary. Both sessions are brought to their steady state by an earlier deletion first, so what the two
    /// measured commands move is the command's own renting alone.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.5.1; Part 1, clause 15.7</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceSpecialReturnsItsCarriersAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);

        long beforeDefinition = trackingPool.OutstandingCount;
        await DefinePolicyDeleteIndexAsync(device, pool, registry, SecondPolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        long indexFootprint = trackingPool.OutstandingCount - beforeDefinition;
        Assert.IsGreaterThan(0, indexFootprint, "A defined Index retains carriers of its own, or the deletion's release would be unobservable.");

        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        (uint platformHandle, TpmSession platformSession) = await StartUnboundSessionAsync(device, pool, registry, InstalledPlatformAuth).ConfigureAwait(false);
        try
        {
            using(policySession)
            using(platformSession)
            {
                TpmResult<NvUndefineSpaceSpecialResponse> warmUp = await DeleteOverSessionsAsync(
                    device, pool, registry, PolicyDeleteIndexHandle, policySession, platformSession).ConfigureAwait(false);
                Assert.IsTrue(warmUp.IsSuccess, $"The first deletion, which brings both sessions to their steady state, failed: '{warmUp.ResponseCode}'.");

                TpmResult<PolicyCommandCodeResponse> reasserted = await device.PolicyCommandCodeAsync(
                    policyHandle, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(reasserted.IsSuccess, $"PolicyCommandCodeAsync failed: '{reasserted.ResponseCode}'.");

                long baseline = trackingPool.OutstandingCount;

                platformSession.SetAuthValue(WrongAuth, pool);
                TpmResult<NvUndefineSpaceSpecialResponse> refused = await DeleteOverSessionsAsync(
                    device, pool, registry, SecondPolicyDeleteIndexHandle, policySession, platformSession).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_BAD_AUTH, refused.BaseError,
                    "The platform hierarchy's DA exemption (clause 16.8.1) makes a wrong platformAuth the plain, non-charging TPM_RC_BAD_AUTH.");
                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A command refused at a command HMAC releases every carrier its parse rented and keeps the Index's own.");

                platformSession.SetAuthValue(InstalledPlatformAuth, pool);
                TpmResult<NvUndefineSpaceSpecialResponse> accepted = await DeleteOverSessionsAsync(
                    device, pool, registry, SecondPolicyDeleteIndexHandle, policySession, platformSession).ConfigureAwait(false);
                Assert.IsTrue(accepted.IsSuccess, $"TPM2_NV_UndefineSpaceSpecial() over two sessions failed: '{accepted.ResponseCode}'.");
                Assert.AreEqual(
                    baseline - indexFootprint, trackingPool.OutstandingCount,
                    "The completing tail and the response framing between them release every carrier the command rented, and the deletion releases the Index's own retained ones.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(device, registry, pool, platformHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Hand-frames a deletion whose ADMIN slot or platform slot carries <paramref name="attribute"/> and asserts
    /// the refusal is <c>TPM_RC_ATTRIBUTES</c> session-encoded to whichever slot claimed it, and that the Index
    /// survives. Both slots ride real sessions so the refusal is the parameterless command's own
    /// nothing-to-act-on rule rather than a password slot's separate attribute restriction.
    /// </summary>
    /// <param name="attribute">The <c>TPMA_SESSION</c> bit under test.</param>
    /// <param name="isClaimedByThePlatformSlot">Whether the platform slot rather than the ADMIN slot carries it.</param>
    private async Task AssertSessionAttributeIsRefusedAtItsSlotAsync(TpmaSession attribute, bool isClaimedByThePlatformSlot)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateDeletionRegistry();

        byte[] deletionPolicy = ComputeCommandCodeOnlyDeletionPolicy();
        await DefinePolicyDeleteIndexAsync(device, pool, registry, PolicyDeleteIndexHandle, PolicyDeleteAttributes, deletionPolicy, OrdinaryDataSize).ConfigureAwait(false);
        byte[] indexName = await ReadIndexNameAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);

        (uint policyHandle, TpmSession policySession) = await StartDeletionPolicySessionAsync(device, pool, foldsAuthValue: false, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        (uint platformHandle, TpmSession platformSession) = await StartUnboundSessionAsync(device, pool, registry, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(policySession)
            using(platformSession)
            {
                (TpmRcConstants rawCode, _) = await SubmitHandFramedDeletionAsync(
                    device, pool, PolicyDeleteIndexHandle, indexName, policySession, platformSession, ReadOnlyMemory<byte>.Empty,
                    policySlotAttribute: isClaimedByThePlatformSlot ? default : attribute,
                    platformSlotAttribute: isClaimedByThePlatformSlot ? attribute : default,
                    platformSlotHandleOverride: null, hasCompanionBlock: false).ConfigureAwait(false);

                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: isClaimedByThePlatformSlot ? 1 : 0), rawCode,
                    "A parameterless, non-auditable command has nothing for the attribute to act on, so the claiming slot is named in the refusal.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policyHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(device, registry, pool, platformHandle).ConfigureAwait(false);
        }

        await AssertIndexIsStillDefinedAsync(device, PolicyDeleteIndexHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues <c>TPM2_NV_UndefineSpaceSpecial()</c> through the production executor with the ADMIN slot at index
    /// 0 and the platform slot at index 1. The Index's Name must be supplied for cpHash; the platform handle is
    /// permanent, so its Name term is left for the host to derive from the handle's own four octets.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to delete.</param>
    /// <param name="policySession">The ADMIN-role policy session.</param>
    /// <param name="platformSlot">The <c>@platform</c> slot: a password block or an HMAC session.</param>
    /// <returns>The deletion result.</returns>
    private async Task<TpmResult<NvUndefineSpaceSpecialResponse>> DeleteOverSessionsAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, TpmSession policySession, TpmSessionBase platformSlot)
    {
        byte[] indexName = await ReadIndexNameAsync(device, nvIndex).ConfigureAwait(false);
        var input = new NvUndefineSpaceSpecialInput(nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceSpecialResponse>(
            device, input, [policySession, platformSlot], [indexName, ReadOnlyMemory<byte>.Empty], pool, registry,
            TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The SIMULATOR-side proof for the session-attribute fail-closed gate, the platform slot's own resolution,
    /// the companion-block refusal and the raw command-HMAC verification: hand-frames a raw
    /// <c>TPM2_NV_UndefineSpaceSpecial()</c> and submits it straight to the transport, bypassing
    /// <see cref="TpmCommandExecutor"/>, whose own client-side guard would refuse a bad attribute before any
    /// octet reaches the wire. Both slots' HMACs fold the SAME independently computed cpHash: the command code,
    /// <paramref name="foldedIndexName"/>, the platform handle's four octets, and an EMPTY parameters term.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index handle written into the wire's handle area.</param>
    /// <param name="foldedIndexName">The Name term cpHash folds, supplied by the caller so a stale Name can be proven.</param>
    /// <param name="policySession">The ADMIN slot's policy session.</param>
    /// <param name="platformSession">The platform slot's HMAC session, or <see langword="null"/> for a <c>TPM_RS_PW</c> block.</param>
    /// <param name="platformPassword">The password framed into a <c>TPM_RS_PW</c> platform slot; ignored when <paramref name="platformSession"/> is supplied.</param>
    /// <param name="policySlotAttribute">An extra <c>TPMA_SESSION</c> bit for the ADMIN slot.</param>
    /// <param name="platformSlotAttribute">An extra <c>TPMA_SESSION</c> bit for the platform slot.</param>
    /// <param name="platformSlotHandleOverride">A wire-only substitute for the platform slot's session handle field, or <see langword="null"/> to leave the genuine one in place.</param>
    /// <param name="hasCompanionBlock">Whether a third, password-shaped block follows the two authorizing blocks.</param>
    /// <returns>The raw wire response code (still carrying any session-index encoding) and the exact octets submitted.</returns>
    private async Task<(TpmRcConstants ResponseCode, byte[] FramedCommand)> SubmitHandFramedDeletionAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        uint nvIndex,
        ReadOnlyMemory<byte> foldedIndexName,
        TpmSession policySession,
        TpmSession? platformSession,
        ReadOnlyMemory<byte> platformPassword,
        TpmaSession policySlotAttribute,
        TpmaSession platformSlotAttribute,
        uint? platformSlotHandleOverride,
        bool hasCompanionBlock)
    {
        byte[] cpHash = ComputeDeletionCpHash(foldedIndexName.Span);

        policySession.SessionAttributes |= policySlotAttribute;
        policySession.RollNonceCaller(pool);
        using Tpm2bAuth? policyHmac = await policySession.PrepareAuthHmacAsync(cpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Tpm2bAuth? platformHmac = null;
        if(platformSession is not null)
        {
            platformSession.SessionAttributes |= platformSlotAttribute;
            platformSession.RollNonceCaller(pool);
            platformHmac = await platformSession.PrepareAuthHmacAsync(cpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);
        }

        try
        {
            int policyBlockSize = policySession.GetAuthCommandSize();
            int platformBlockSize = platformSession is not null
                ? platformSession.GetAuthCommandSize()
                : MinimumAuthorizationBlockSize + platformPassword.Length;
            int companionBlockSize = hasCompanionBlock ? MinimumAuthorizationBlockSize : 0;
            int authorizationSize = policyBlockSize + platformBlockSize + companionBlockSize;
            int handlesSize = 2 * sizeof(uint);
            int totalSize = TpmHeader.HeaderSize + handlesSize + sizeof(uint) + authorizationSize;

            using IMemoryOwner<byte> commandOwner = pool.Rent(totalSize);
            Memory<byte> command = commandOwner.Memory[..totalSize];
            var writer = new TpmWriter(command.Span);
            writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_SESSIONS);
            writer.WriteUInt32((uint)totalSize);
            writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
            writer.WriteUInt32(nvIndex);
            writer.WriteUInt32((uint)TpmRh.TPM_RH_PLATFORM);
            writer.WriteUInt32((uint)authorizationSize);
            policySession.WriteAuthCommand(ref writer, policyHmac);

            if(platformSession is not null)
            {
                platformSession.WriteAuthCommand(ref writer, platformHmac);
            }
            else
            {
                writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
                writer.WriteUInt16(0);
                writer.WriteByte((byte)(TpmaSession.CONTINUE_SESSION | platformSlotAttribute));
                writer.WriteUInt16((ushort)platformPassword.Length);
                writer.WriteBytes(platformPassword.Span);
            }

            if(hasCompanionBlock)
            {
                writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
                writer.WriteUInt16(0);
                writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
                writer.WriteUInt16(0);
            }

            if(platformSlotHandleOverride is uint overrideHandle)
            {
                int slotHandleOffset = TpmHeader.HeaderSize + handlesSize + sizeof(uint) + policyBlockSize;
                BinaryPrimitives.WriteUInt32BigEndian(command.Span.Slice(slotHandleOffset, sizeof(uint)), overrideHandle);
            }

            byte[] framedCommand = command.Span.ToArray();

            TpmResult<TpmResponse> transportResult = await device.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(transportResult.IsSuccess, "The transport itself must succeed even when the TPM refuses the command.");

            using TpmResponse response = transportResult.Value;
            var responseReader = new TpmReader(response.AsReadOnlySpan());

            return ((TpmRcConstants)TpmHeader.Parse(ref responseReader).Code, framedCommand);
        }
        finally
        {
            platformHmac?.Dispose();
        }
    }

    /// <summary>
    /// The audit twin of <see cref="SubmitHandFramedDeletionAsync"/>: hand-frames a raw
    /// <c>TPM2_NV_UndefineSpaceSpecial()</c> whose platform slot carries <c>audit ‖ continueSession</c>, submits
    /// it directly to the transport, and returns the raw response octets and the independently computed cpHash —
    /// neither slot's session is flushed here, so the caller can read the platform slot's audit digest back
    /// through <c>TPM2_GetSessionAuditDigest()</c> even after the deletion removes the Index itself.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index handle written into the wire's handle area.</param>
    /// <param name="foldedIndexName">The Name term cpHash folds.</param>
    /// <param name="policySession">The ADMIN slot's policy session.</param>
    /// <param name="platformSession">The platform slot's HMAC session, claiming <c>audit</c> here.</param>
    /// <returns>The raw response octets and cpHash.</returns>
    private async Task<(byte[] Response, byte[] CpHash)> SubmitHandFramedDeletionForAuditAsync(
        TpmDevice device, BaseMemoryPool pool, uint nvIndex, ReadOnlyMemory<byte> foldedIndexName, TpmSession policySession, TpmSession platformSession)
    {
        byte[] cpHash = ComputeDeletionCpHash(foldedIndexName.Span);

        policySession.RollNonceCaller(pool);
        using Tpm2bAuth? policyHmac = await policySession.PrepareAuthHmacAsync(cpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);

        platformSession.SessionAttributes |= TpmaSession.AUDIT;
        platformSession.RollNonceCaller(pool);
        using Tpm2bAuth? platformHmac = await platformSession.PrepareAuthHmacAsync(cpHash, pool, TestContext.CancellationToken).ConfigureAwait(false);

        int policyBlockSize = policySession.GetAuthCommandSize();
        int platformBlockSize = platformSession.GetAuthCommandSize();
        int authorizationSize = policyBlockSize + platformBlockSize;
        int handlesSize = 2 * sizeof(uint);
        int totalSize = TpmHeader.HeaderSize + handlesSize + sizeof(uint) + authorizationSize;

        using IMemoryOwner<byte> commandOwner = pool.Rent(totalSize);
        Memory<byte> command = commandOwner.Memory[..totalSize];
        var writer = new TpmWriter(command.Span);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_SESSIONS);
        writer.WriteUInt32((uint)totalSize);
        writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        writer.WriteUInt32(nvIndex);
        writer.WriteUInt32((uint)TpmRh.TPM_RH_PLATFORM);
        writer.WriteUInt32((uint)authorizationSize);
        policySession.WriteAuthCommand(ref writer, policyHmac);
        platformSession.WriteAuthCommand(ref writer, platformHmac);

        TpmResult<TpmResponse> transportResult = await device.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(transportResult.IsSuccess, "The transport itself must succeed even when the TPM refuses the command.");

        using TpmResponse response = transportResult.Value;

        return (response.AsReadOnlySpan().ToArray(), cpHash);
    }

    /// <summary>
    /// Reads the response parameter area out of a captured raw response's octets — the bytes rpHash (TPM 2.0
    /// Library Part 1, clause 15.8, equation 16) is computed over, as actually returned on the wire, independent
    /// of whatever the codec parsed them into.
    /// </summary>
    /// <param name="responseBytes">The raw response octets, tagged <c>TPM_ST_SESSIONS</c>.</param>
    /// <param name="outHandleCount">The number of output handles the response carries before its parameter area.</param>
    /// <returns>The response parameter octets.</returns>
    private static byte[] ReadResponseParameters(byte[] responseBytes, int outHandleCount)
    {
        var reader = new TpmReader(responseBytes);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < outHandleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint parameterSize = reader.ReadUInt32();

        return reader.ReadBytes((int)parameterSize).ToArray();
    }

    /// <summary>
    /// Reads one entry's <c>sessionAttributes</c> octet out of a captured raw response's authorization area — the
    /// octet Table 38's <c>audit</c>/<c>auditExclusive</c>/<c>auditReset</c> echo lands in and the response HMAC
    /// is computed over, walked directly off the wire rather than through any parsed session state.
    /// </summary>
    /// <param name="responseBytes">The raw response octets.</param>
    /// <param name="outHandleCount">The number of output handles preceding the parameter area.</param>
    /// <param name="sessionIndex">The zero-based position, in request order, of the session entry to read.</param>
    /// <returns>The entry's raw <c>sessionAttributes</c> octet.</returns>
    private static byte ReadResponseSessionAttributes(byte[] responseBytes, int outHandleCount, int sessionIndex)
    {
        var reader = new TpmReader(responseBytes);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < outHandleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint parameterSize = reader.ReadUInt32();
        _ = reader.ReadBytes((int)parameterSize);

        byte attributes = 0;
        for(int i = 0; i <= sessionIndex; i++)
        {
            ushort nonceLength = reader.ReadUInt16();
            _ = reader.ReadBytes(nonceLength);
            attributes = reader.ReadByte();
            ushort hmacLength = reader.ReadUInt16();
            _ = reader.ReadBytes(hmacLength);
        }

        return attributes;
    }

    /// <summary>
    /// Computes <c>rpHash = H_sessionAlg(TPM_RC_SUCCESS ‖ commandCode ‖ parameters)</c> (TPM 2.0 Library Part 1,
    /// clause 15.8, equation 16) over the response parameter octets as actually read off the wire.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="responseParameters">The response parameter area as read.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The rpHash octets.</returns>
    private async Task<byte[]> ComputeRpHashAsync(TpmCcConstants commandCode, ReadOnlyMemory<byte> responseParameters, BaseMemoryPool pool)
    {
        byte[] input = new byte[sizeof(uint) + sizeof(uint) + responseParameters.Length];
        BinaryPrimitives.WriteUInt32BigEndian(input, (uint)TpmRcConstants.TPM_RC_SUCCESS);
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(sizeof(uint)), (uint)commandCode);
        responseParameters.Span.CopyTo(input.AsSpan(2 * sizeof(uint)));

        return await HashSha256Async(input, pool).ConfigureAwait(false);
    }

    /// <summary>
    /// Extends an audit session digest by one round: <c>H(old ‖ cpHash ‖ rpHash)</c>, with the Zero Digest of the
    /// session's hash width standing in for <paramref name="priorDigest"/> on the session's first use as an audit
    /// session (TPM 2.0 Library Part 1, clause 17.1, equation 30).
    /// </summary>
    /// <param name="priorDigest">The digest before this extend, or <see langword="null"/> on first use.</param>
    /// <param name="cpHash">The audited command's cpHash.</param>
    /// <param name="rpHash">The audited command's rpHash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The extended digest.</returns>
    private async Task<byte[]> ExtendAuditDigestAsync(byte[]? priorDigest, byte[] cpHash, byte[] rpHash, BaseMemoryPool pool)
    {
        byte[] old = priorDigest ?? new byte[Sha256DigestSize];
        byte[] input = new byte[old.Length + cpHash.Length + rpHash.Length];
        old.CopyTo(input, 0);
        cpHash.CopyTo(input, old.Length);
        rpHash.CopyTo(input, old.Length + cpHash.Length);

        return await HashSha256Async(input, pool).ConfigureAwait(false);
    }

    /// <summary>Computes a raw SHA-256 digest over <paramref name="input"/> through the project's own digest primitive.</summary>
    /// <param name="input">The octets to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The digest octets.</returns>
    private async Task<byte[]> HashSha256Async(ReadOnlyMemory<byte> input, BaseMemoryPool pool)
    {
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            input, Sha256DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Transcribes this command's cpHash independently of the production computation:
    /// <c>H(TPM_CC_NV_UndefineSpaceSpecial ‖ Name(nvIndex) ‖ TPM_RH_PLATFORM)</c> with an EMPTY parameters term,
    /// since Table 249 declares no parameters and a permanent entity's Name is its own four octets (TPM 2.0
    /// Library Part 1, clause 15.7, equation 15, and clause 13, Table 9).
    /// </summary>
    /// <param name="indexName">The Index's Name, the first handle's cpHash term.</param>
    /// <returns>The transcribed cpHash.</returns>
    private static byte[] ComputeDeletionCpHash(ReadOnlySpan<byte> indexName)
    {
        byte[] input = new byte[sizeof(uint) + indexName.Length + sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(input, (uint)TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        indexName.CopyTo(input.AsSpan(sizeof(uint)));
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(sizeof(uint) + indexName.Length), (uint)TpmRh.TPM_RH_PLATFORM);

        return SHA256.HashData(input);
    }

    /// <summary>
    /// Transcribes the MINIMAL deletion <c>authPolicy</c> - the one assertion clause 31.5.1 demands, "the policy
    /// must contain a command that sets the policy command code to TPM_CC_NV_UndefineSpaceSpecial" - from its
    /// single extend formula, <c>policyDigest = H(policyDigest ‖ TPM_CC_PolicyCommandCode ‖
    /// TPM_CC_NV_UndefineSpaceSpecial)</c> folded over the all-zero starting digest a fresh policy session
    /// carries. Written out with <see cref="BinaryPrimitives"/> and the framework hash directly, never through
    /// the policy builder the implementation folds its own copy with.
    /// </summary>
    /// <returns>The transcribed policy digest.</returns>
    private static byte[] ComputeCommandCodeOnlyDeletionPolicy()
    {
        byte[] commandCodeInput = new byte[Sha256DigestSize + sizeof(uint) + sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(commandCodeInput.AsSpan(Sha256DigestSize), (uint)TpmCcConstants.TPM_CC_PolicyCommandCode);
        BinaryPrimitives.WriteUInt32BigEndian(commandCodeInput.AsSpan(Sha256DigestSize + sizeof(uint)), (uint)TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);

        return SHA256.HashData(commandCodeInput);
    }

    /// <summary>
    /// Transcribes the deletion <c>authPolicy</c> that ALSO folds the Index's own authValue into the command
    /// HMAC, from the two extend formulas: <c>policyDigest = H(zeroes ‖ TPM_CC_PolicyAuthValue)</c>, then
    /// <c>policyDigest = H(policyDigest ‖ TPM_CC_PolicyCommandCode ‖ TPM_CC_NV_UndefineSpaceSpecial)</c>. It is
    /// the shape under which "the authValue is not included in the HMAC calculation unless the policy session
    /// include TPM2_PolicyAuthValue()" resolves in the affirmative.
    /// </summary>
    /// <returns>The transcribed policy digest.</returns>
    private static byte[] ComputeAuthValueDeletionPolicy()
    {
        byte[] authValueInput = new byte[Sha256DigestSize + sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(authValueInput.AsSpan(Sha256DigestSize), (uint)TpmCcConstants.TPM_CC_PolicyAuthValue);
        byte[] afterAuthValue = SHA256.HashData(authValueInput);

        byte[] commandCodeInput = new byte[Sha256DigestSize + sizeof(uint) + sizeof(uint)];
        afterAuthValue.CopyTo(commandCodeInput, 0);
        BinaryPrimitives.WriteUInt32BigEndian(commandCodeInput.AsSpan(Sha256DigestSize), (uint)TpmCcConstants.TPM_CC_PolicyCommandCode);
        BinaryPrimitives.WriteUInt32BigEndian(commandCodeInput.AsSpan(Sha256DigestSize + sizeof(uint)), (uint)TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);

        return SHA256.HashData(commandCodeInput);
    }

    /// <summary>
    /// Starts a policy session and asserts the deletion policy on it: <c>TPM2_PolicyCommandCode()</c> naming
    /// this command always, preceded by <c>TPM2_PolicyAuthValue()</c> when the Index's own authValue is meant to
    /// key the command HMAC as well.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="foldsAuthValue">Whether the session also asserts <c>TPM2_PolicyAuthValue()</c>.</param>
    /// <param name="indexAuth">The authValue term folded when <paramref name="foldsAuthValue"/> is set.</param>
    /// <returns>The session handle (to flush) and the composed session (to dispose).</returns>
    private async Task<(uint Handle, TpmSession Session)> StartDeletionPolicySessionAsync(
        TpmDevice device, BaseMemoryPool pool, bool foldsAuthValue, ReadOnlyMemory<byte> indexAuth)
    {
        TpmResult<StartAuthSessionResponse> startResult = await device.StartPolicySessionAsync(SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartPolicySessionAsync failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;
        var session = new TpmSession(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);

        if(foldsAuthValue)
        {
            TpmResult<PolicyAuthValueResponse> authValueResult = await device.PolicyAuthValueAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValueAsync failed: '{authValueResult.ResponseCode}'.");
        }

        TpmResult<PolicyCommandCodeResponse> commandCodeResult = await device.PolicyCommandCodeAsync(
            sessionHandle, TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCodeAsync failed: '{commandCodeResult.ResponseCode}'.");

        if(foldsAuthValue)
        {
            session.SetAuthValue(indexAuth.Span, pool);
        }

        return (sessionHandle, session);
    }

    /// <summary>
    /// Starts an unbound, unsalted HMAC session (TPM 2.0 Library Part 1, clause 16.6.9) and composes the host
    /// session over it with <paramref name="authValue"/> as its authValue term.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authValue">The authValue the session proves.</param>
    /// <returns>The session handle (to flush) and the composed session (to dispose).</returns>
    private async Task<(uint Handle, TpmSession Session)> StartUnboundSessionAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, ReadOnlyMemory<byte> authValue)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);
        session.SetAuthValue(authValue.Span, pool);

        return (started.SessionHandle.Value, session);
    }

    /// <summary>
    /// Starts a bound, unsalted HMAC session against <paramref name="bindHandle"/> through the production
    /// <c>TPM2_StartAuthSession()</c> path, deriving the client-side session key from
    /// <paramref name="bindAuthValue"/> (TPM 2.0 Library Part 1, clause 16.6.10, equation 20).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="bindHandle">The entity to bind to.</param>
    /// <param name="bindAuthValue">The bind entity's authValue fed into the session-key KDFa.</param>
    /// <returns>The started session handle and its client-side wrapper.</returns>
    private async Task<(uint Handle, TpmSession Session)> StartBoundHmacSessionAsync(
        TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, uint bindHandle, ReadOnlyMemory<byte> bindAuthValue)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(bindHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound to 0x{bindHandle:X8}) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse startResponse = startResult.Value;
        TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(startResponse.SessionHandle.Value), bindAuthValue, startInput.NonceCaller,
            startResponse.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        return (startResponse.SessionHandle.Value, session);
    }

    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S +
    /// TPM_RC_n(0x100·(index+1)) - a local mirror of the production session-index encoding, transcribed
    /// independently here since the production helper is private.
    /// </summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>Creates a response codec registry for the commands these tests drive directly.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateDeletionRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite)
            .Register(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, TpmResponseCodec.NvUndefineSpaceSpecial)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext)
            .Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);

    /// <summary>
    /// Defines a platform-created Index carrying <paramref name="authPolicy"/> as its deletion policy, under
    /// Platform Authorization with the factory-empty platformAuth - the only authority
    /// <c>TPMA_NV_POLICY_DELETE</c> may be installed with (TPM 2.0 Library Part 3, clause 31.3.1).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    /// <param name="authPolicy">The deletion policy digest to define with.</param>
    /// <param name="dataSize">The declared data area size.</param>
    private async Task DefinePolicyDeleteIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, TpmaNv attributes, ReadOnlyMemory<byte> authPolicy, ushort dataSize)
    {
        using TpmPasswordSession platformSession = TpmPasswordSession.CreateEmpty(pool);

        //The input takes ownership of the auth value and public area and disposes them; the redundant using
        //locals satisfy CA2000 and are safe because the types have idempotent disposal.
        using var auth = Tpm2bAuth.Create(IndexAuth, pool);
        using var policyDigest = Tpm2bDigest.Create(authPolicy.Span, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, attributes, policyDigest, dataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_PLATFORM, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [platformSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_DefineSpace(0x{nvIndex:X8}) under Platform Authorization failed: '{result.ResponseCode}'.");
    }

    /// <summary>Defines an owner-created Ordinary Index with no access policy, for use as a bind target or a lockout driver.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    private async Task DefineOwnerIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, TpmaNv attributes)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);

        //The input takes ownership of the auth value and public area and disposes them; the redundant using
        //locals satisfy CA2000 and are safe because both types have idempotent disposal.
        using var auth = Tpm2bAuth.Create(IndexAuth, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, attributes, Tpm2bDigest.Empty, OrdinaryDataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_DefineSpace(0x{nvIndex:X8}) failed: '{result.ResponseCode}'.");
    }

    /// <summary>Issues an Index-arm <c>TPM2_NV_Write()</c> at offset zero over a password session.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to write, which also authorizes the write.</param>
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

    /// <summary>
    /// Writes a PIN Index's whole <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> window over the owner-authorized
    /// <c>TPM2_NV_Write()</c> arm - the only write path a PIN Index has - so a test can establish an exact
    /// counter state without producing any authorization outcome of its own.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The PIN Index to provision.</param>
    /// <param name="pinCount">The attempt count to store.</param>
    /// <param name="pinLimit">The attempt threshold to store.</param>
    private async Task WritePinCounterParametersAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, uint pinCount, uint pinLimit)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using IMemoryOwner<byte> blobOwner = pool.Rent(PinCounterParametersSize);
        Memory<byte> blob = blobOwner.Memory[..PinCounterParametersSize];
        BinaryPrimitives.WriteUInt32BigEndian(blob.Span, pinCount);
        BinaryPrimitives.WriteUInt32BigEndian(blob.Span[sizeof(uint)..], pinLimit);

        using Tpm2bMaxNvBuffer inputBuffer = Tpm2bMaxNvBuffer.Create(blob.Span, pool);
        var input = new NvWriteInput((uint)TpmRh.TPM_RH_OWNER, nvIndex, inputBuffer, Offset: 0);

        TpmResult<NvWriteResponse> result = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The owner-authorized counter write failed: '{result.ResponseCode}'.");
    }

    /// <summary>Reads a PIN Index's counter window back over the owner-authorized path and requires an exact attempt count.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The PIN Index to read.</param>
    /// <param name="expectedPinCount">The attempt count the counter must carry.</param>
    private async Task AssertPinCountIsAsync(TpmDevice device, uint nvIndex, uint expectedPinCount)
    {
        TpmResult<TpmPinCounterParameters> counters = await device.ReadPinCountersAsync(
            ReadOnlyMemory<byte>.Empty, nvIndex, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(counters.IsSuccess, $"ReadPinCountersAsync failed: '{counters.ResponseCode}'.");
        Assert.AreEqual(expectedPinCount, counters.Value.PinCount, "A deletion refused at the ADMIN slot spends exactly one PIN attempt.");
    }

    /// <summary>Installs <see cref="InstalledPlatformAuth"/> as <c>platformAuth</c> over the factory-empty value.</summary>
    /// <param name="device">The TPM device.</param>
    private async Task InstallPlatformAuthAsync(TpmDevice device)
    {
        TpmResult<HierarchyChangeAuthResponse> result = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, InstalledPlatformAuth, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Installing platformAuth failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Lowers <c>maxTries</c> to one and drives the TPM into Lockout mode with a single wrong-password write
    /// against a freshly defined dictionary-attack-protected Index (<see cref="BindIndexHandle"/>), which the
    /// caller subsequently reuses as a bind target.
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

        await DefineOwnerIndexAsync(device, pool, registry, BindIndexHandle, DaProtectedOwnerAttributes).ConfigureAwait(false);

        TpmResult<NvWriteResponse> wrongResult = await WriteIndexAsync(device, pool, registry, BindIndexHandle, WrongAuth, PrimingWriteData).ConfigureAwait(false);

        //Arrangement machinery, not the normative case under proof: the password arm answers the
        //session-index-encoded TPM_RC_AUTH_FAIL for this rejection, and with maxTries lowered to one it
        //engages Lockout mode at once.
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode,
            "The priming write must fail and count, taking the TPM into Lockout mode.");
    }

    /// <summary>
    /// Reads an Index's Name back from the TPM through <c>TPM2_NV_ReadPublic()</c> - the authoritative source of
    /// a session-authorized command's cpHash Name term (TPM 2.0 Library Part 1, clause 13).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Index whose Name is wanted.</param>
    /// <returns>The Index's Name.</returns>
    private async Task<byte[]> ReadIndexNameAsync(TpmDevice device, uint nvIndex)
    {
        TpmResult<NvReadPublicResponse> nameResult = await device.NvReadPublicAsync(nvIndex, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(nameResult.IsSuccess, $"NvReadPublicAsync(0x{nvIndex:X8}) failed: '{nameResult.ResponseCode}'.");

        using NvReadPublicResponse namePublic = nameResult.Value;

        return namePublic.NvName.Span.ToArray();
    }

    /// <summary>
    /// Asserts the Index has left the TPM's NV state: "If nvIndex is not defined, the TPM shall return
    /// TPM_RC_HANDLE", which <c>TPM2_NV_ReadPublic()</c> answers for a handle no Index occupies.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Index handle expected to be free.</param>
    private async Task AssertIndexIsGoneAsync(TpmDevice device, uint nvIndex)
    {
        TpmResult<NvReadPublicResponse> result = await device.NvReadPublicAsync(nvIndex, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 0), result.ResponseCode,
            "A deleted Index occupies its handle no longer, so its public area cannot be read back.");
    }

    /// <summary>Asserts the Index is still defined, which is what makes a refusal a refusal rather than a silent deletion.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Index handle expected to be occupied.</param>
    private async Task AssertIndexIsStillDefinedAsync(TpmDevice device, uint nvIndex)
    {
        TpmResult<NvReadPublicResponse> result = await device.NvReadPublicAsync(nvIndex, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A refused deletion must leave the Index defined: '{result.ResponseCode}'.");

        result.Value.Dispose();
    }

    /// <summary>Reads <c>TPM_PT_LOCKOUT_COUNTER</c>, the live <c>failedTries</c> value, back over <c>TPM2_GetCapability()</c>.</summary>
    /// <param name="device">The device the capability is read through.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The reported counter value.</returns>
    private async Task<uint> ReadLockoutCounterAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        TpmResult<GetCapabilityResponse> result = await TpmCommandExecutor.ExecuteAsync<GetCapabilityResponse>(
            device, GetCapabilityInput.ForTpmProperties(TpmPtConstants.TPM_PT_LOCKOUT_COUNTER, count: 1), [], null, pool, registry,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"GetCapability(TPM_PT_LOCKOUT_COUNTER) failed: '{result.ResponseCode}'.");

        using GetCapabilityResponse properties = result.Value;
        var reported = properties.CapabilityData.TpmProperties;
        Assert.IsNotNull(reported);
        Assert.IsNotEmpty(reported);
        Assert.AreEqual(TpmPtConstants.TPM_PT_LOCKOUT_COUNTER, reported[0].Property);

        return reported[0].Value;
    }

    /// <summary>Flushes <paramref name="handle"/> if it names a started session, releasing the simulator-side context.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The session handle, or zero when no session was started.</param>
    private static async Task FlushIfPresentAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            device, FlushContextInput.ForHandle(handle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
    }

    /// <summary>Wraps a device whose transport appends every command it forwards to <paramref name="capturedCommands"/>, in submission order.</summary>
    /// <param name="simulator">The simulator the capturing transport forwards to.</param>
    /// <param name="capturedCommands">The list each observed command is appended to.</param>
    /// <returns>A device the caller disposes; its transport captures as a side effect of forwarding.</returns>
    private static TpmDevice CreateCapturingDevice(TpmSimulator simulator, List<byte[]> capturedCommands)
    {
        async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
        {
            capturedCommands.Add(command.ToArray());

            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        return TpmDevice.Create(CaptureAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
    /// Appends an authorization area of <paramref name="blockCount"/> blocks, each naming <c>TPM_RS_PW</c> with
    /// an empty nonce and an empty password - the password form of <c>TPMS_AUTH_COMMAND</c> (TPM 2.0 Library
    /// Part 1, clause 16.6.4.1) - which is enough for a parse-time proof, since the parse never evaluates a
    /// credential.
    /// </summary>
    /// <param name="body">The body being built.</param>
    /// <param name="blockCount">How many password blocks the area holds.</param>
    private static void AppendPasswordAuthorizationArea(List<byte> body, int blockCount)
    {
        var area = new List<byte>();
        for(int block = 0; block < blockCount; block++)
        {
            AppendUInt32(area, (uint)TpmRh.TPM_RH_PW);
            AppendUInt16(area, 0);
            area.Add((byte)TpmaSession.CONTINUE_SESSION);
            AppendUInt16(area, 0);
        }

        AppendUInt32(body, (uint)area.Count);
        body.AddRange(area);
    }

    /// <summary>Frames a <c>TPM2_NV_UndefineSpaceSpecial()</c> header around <paramref name="body"/> and submits it straight to the simulator.</summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag.</param>
    /// <param name="body">The handle area, authorization area and parameter area, already laid out.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitFramedAsync(TpmSimulator simulator, BaseMemoryPool pool, TpmStConstants tag, byte[] body)
    {
        int length = TpmHeader.HeaderSize + body.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)tag, (uint)length, (uint)TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial);
        header.WriteTo(ref writer);
        writer.WriteBytes(body);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer a malformed command rather than fault.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>Frames <c>TPM2_Startup()</c> directly to the simulator, sessionless, and returns its response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="input">The startup command input.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitStartupAsync(TpmSimulator simulator, BaseMemoryPool pool, StartupInput input)
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

    /// <summary>
    /// Creates a simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational
    /// phase - the precondition <c>TPM2_NV_UndefineSpaceSpecial()</c> carries.
    /// </summary>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync()
    {
        var simulator = new TpmSimulator("tpm-in-house-nv-undefinespacespecial-wire", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitStartupAsync(simulator, BaseMemoryPool.Shared, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false),
            "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
