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
/// Drives <c>TPM2_NV_GlobalWriteLock()</c> over authorization SESSIONS and over the raw wire — the owner and the
/// platform arm proven by a command HMAC whose cpHash folds the permanent handle's own four octets and an empty
/// parameters term, the bind omission a session bound to <c>TPM_RH_OWNER</c> earns, the dictionary-attack posture
/// a permanent entity and a dictionary-attack-protected bind entity each impose, the authorization slot's
/// refusals, the fail-closed <c>decrypt</c>/<c>encrypt</c>/<c>audit</c> answers a parameterless command owes, and
/// the framing refusals Table 263 fixes — against the in-house behavioural <see cref="TpmSimulator"/>, entirely
/// in-process with no external assets, through the same production command path the production code uses
/// (<see cref="TpmCommandExecutor"/> and the real command/response codecs). TPM 2.0 Library Part 3, clauses 31.12,
/// 5.4, 5.6 and 5.7; Part 2, clauses 9.21 and 6.6.2; Part 1, clauses 13, 15.7, 16.6, 16.8.1 and 18.1.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorNvGlobalWriteLockOverSessionTests
{
    /// <summary>The declared data size of every Ordinary Index this file defines.</summary>
    private const ushort OrdinaryDataSize = 16;

    /// <summary>The SHA-256 digest width, in octets — the cpHash width and the session nonce width used here.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The dictionary-attack-exempt Ordinary Index carrying <c>TPMA_NV_GLOBALLOCK</c>.</summary>
    private const uint GlobalLockIndexHandle = 0x0100_00B0;

    /// <summary>The dictionary-attack-PROTECTED Ordinary Index carrying <c>TPMA_NV_GLOBALLOCK</c>, for the Name-movement proof.</summary>
    private const uint DaProtectedGlobalLockIndexHandle = 0x0100_00B1;

    /// <summary>The dictionary-attack-protected Ordinary Index used as a bind target and as the lockout driver.</summary>
    private const uint BindIndexHandle = 0x0100_00B2;

    /// <summary>A handle in the transient-object range, which the authorization slot admits no more than a session handle a non-session type would.</summary>
    private const uint TransientRangeHandle = 0x8000_0000;

    /// <summary>The hash algorithm for every session these tests compose.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// Ordinary Index attributes electing <c>TPMA_NV_GLOBALLOCK</c> — the bit Part 2, Table 249 defines as "SET
    /// (1): If TPM2_NV_GlobalWriteLock() is successful, TPMA_NV_WRITELOCKED is set" — opted out of
    /// dictionary-attack protection so a refusal elsewhere in a case never moves <c>failedTries</c>.
    /// </summary>
    private const TpmaNv GlobalLockAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_GLOBALLOCK | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>The same <c>TPMA_NV_GLOBALLOCK</c> Index, dictionary-attack protected (<c>TPMA_NV_NO_DA</c> CLEAR).</summary>
    private const TpmaNv DaProtectedGlobalLockAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_GLOBALLOCK;

    /// <summary>Dictionary-attack-protected Ordinary Index attributes carrying no lock attribute at all.</summary>
    private const TpmaNv DaProtectedAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE;

    /// <summary>The Index authorization value used throughout.</summary>
    private static byte[] CorrectAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong authorization value, distinct from every correct one this file installs.</summary>
    private static byte[] WrongAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>The owner authorization value installed before the owner arm is proven, so the HMAC key is not the empty buffer.</summary>
    private static byte[] InstalledOwnerAuth { get; } = [0x51, 0x62, 0x73, 0x84, 0x95, 0xA6, 0xB7, 0xC8];

    /// <summary>The platform authorization value installed before the platform arm is proven.</summary>
    private static byte[] InstalledPlatformAuth { get; } = [0x19, 0x28, 0x37, 0x46, 0x55, 0x64, 0x73, 0x82];

    /// <summary>The sixteen octets an Ordinary Index is populated with before it is globally locked.</summary>
    private static byte[] IndexData { get; } =
        [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];

    /// <summary>A single-octet payload for the priming write that drives the TPM into Lockout mode.</summary>
    private static byte[] PrimingWriteData { get; } = [0x2A];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The owner arm over an unbound, unsalted HMAC session: "This command requires either
    /// platformAuth/platformPolicy or ownerAuth/ownerPolicy", and "The command will SET TPMA_NV_WRITELOCKED for
    /// all indexes that have their TPMA_NV_GLOBALLOCK attribute SET". The command HMAC verifies against a cpHash
    /// whose sole Name term is the permanent handle's own four octets — "the Name of a permanent entity is the
    /// handle" (Part 1, Table 9), which the host derives without a supplied Name — and an EMPTY parameters term,
    /// since Part 3's Table 263 defines no command parameters. A non-empty <c>ownerAuth</c> is installed first so the HMAC
    /// key is genuinely secret-keyed, and the executor's own verification of the response authorization is what
    /// makes the returned success meaningful.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.12.1; Part 1, clause 15.7, equation 15, and clause 13, Table 9</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverHmacSessionAtTheOwnerArmLocks()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);
        await InstallOwnerAuthAsync(device).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, InstalledOwnerAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"Clause 31.12.1's owner arm over an HMAC session must succeed and its response authorization must verify on the host: '{result.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "Clause 31.12.1: every Index whose TPMA_NV_GLOBALLOCK is SET must carry TPMA_NV_WRITELOCKED after the command.");
    }

    /// <summary>
    /// The platform arm of the same sentence — Table 263's <c>@authHandle</c> is <c>TPMI_RH_PROVISION</c>, whose
    /// two admitted values are <c>TPM_RH_OWNER</c> and <c>TPM_RH_PLATFORM</c> — proven over a session against an
    /// installed <c>platformAuth</c>, and on an Index the OWNER hierarchy defined: "The Index will be locked
    /// whether the index was defined using Owner Authorization or Platform Authorization."
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.12.2, Table 263; Part 2, clause 9.21, Table 67</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverHmacSessionAtThePlatformArmLocks()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);
        await InstallPlatformAuthAsync(device).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, InstalledPlatformAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"Clause 31.12.1's platform arm over an HMAC session must succeed: '{result.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "Clause 31.12.1's Note: an owner-defined Index locks under Platform Authorization exactly as under Owner Authorization.");
    }

    /// <summary>
    /// "The authValue associated with a permanent entity, other than TPM_RH_LOCKOUT, does not receive DA
    /// protection" — a wrong <c>ownerAuth</c> proven over an unbound HMAC session is the non-charging
    /// <c>TPM_RC_BAD_AUTH</c>, named on the offending session by Part 2, clause 6.6.2's session-index encoding,
    /// with <c>TPM_PT_LOCKOUT_COUNTER</c> unmoved.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 2, clause 6.6.2; Part 3, clause 31.12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverHmacSessionWithWrongOwnerAuthReturnsSessionEncodedBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);
        await InstallOwnerAuthAsync(device).ConfigureAwait(false);

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
            "A permanent entity other than TPM_RH_LOCKOUT is dictionary-attack exempt, so its command-HMAC mismatch is the session-encoded TPM_RC_BAD_AUTH.");
        Assert.AreEqual(
            counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "Clause 16.8.1: a dictionary-attack-exempt authValue must never charge failedTries.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "A refused command applies none of clause 31.12.1's effect.");
    }

    /// <summary>
    /// "If the authorization is for the entity to which the session is bound, the HMAC key is the session's
    /// sessionKey" — a session BOUND to <c>TPM_RH_OWNER</c> authorizes the owner arm with the authValue term
    /// omitted, and the TPM mirrors the omission on the response authorization, which the executor verifies with
    /// the session key alone. The installed non-empty <c>ownerAuth</c> is what makes the omission observable: a
    /// TPM that folded it anyway would key the command HMAC differently and refuse.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.10, equation 22; Part 3, clause 31.12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverASessionBoundToTheOwnerHierarchyLocksWithTheAuthValueOmitted()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);
        await InstallOwnerAuthAsync(device).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartBoundHmacSessionAsync(
            device, registry, pool, (uint)TpmRh.TPM_RH_OWNER, InstalledOwnerAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockOverSessionAsync(
                    device, pool, registry, session, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
                Assert.IsTrue(
                    result.IsSuccess,
                    $"The bind omission must authorize the owner arm and be mirrored on the response authorization: '{result.ResponseCode}'.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "A bind-authorized command applies clause 31.12.1's effect exactly as an explicitly authorized one does.");
    }

    /// <summary>
    /// "If the handle references a primary seed for a hierarchy (TPM_RH_ENDORSEMENT, TPM_RH_OWNER, or
    /// TPM_RH_PLATFORM) then the enable for the hierarchy is SET (TPM_RC_HIERARCHY)" — with <c>shEnable</c>
    /// CLEARed under Platform Authorization the owner arm over a session answers <c>TPM_RC_HIERARCHY</c> naming
    /// authHandle, handle 1 of Table 263, refused before any authorization is judged, while the platform arm over
    /// a session still locks the very same owner-defined Index.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.4, check 5; clause 24.2; clause 31.12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverHmacSessionWithADisabledOwnerHierarchyReturnsHierarchyWhileThePlatformArmLocks()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);

        TpmResult<HierarchyControlResponse> disableResult = await device.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_OWNER, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(disableResult.IsSuccess, $"CLEARing shEnable under Platform Authorization failed: '{disableResult.ResponseCode}'.");

        TpmResult<NvGlobalWriteLockResponse> ownerResult = await GlobalWriteLockOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), ownerResult.ResponseCode,
            "Clause 5.4's check 5 refuses a disabled hierarchy at authHandle, handle 1 of Table 263, ahead of clause 5.6's authorization.");

        TpmaNv afterRefusal = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), afterRefusal & TpmaNv.TPMA_NV_WRITELOCKED, "A hierarchy refusal applies none of clause 31.12.1's effect.");

        TpmResult<NvGlobalWriteLockResponse> platformResult = await GlobalWriteLockOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(platformResult.IsSuccess, $"The platform arm is gated by phEnable alone and must still succeed: '{platformResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "Clause 31.12.1's Note: the authorizing hierarchy plays no part in which Indexes lock.");
    }

    /// <summary>
    /// The converse of the shEnable case, on the session form: "If the handle references a primary seed for a
    /// hierarchy (TPM_RH_ENDORSEMENT, TPM_RH_OWNER, or TPM_RH_PLATFORM) then the enable for the hierarchy is SET
    /// (TPM_RC_HIERARCHY)" — with <c>phEnable</c> CLEARed under Platform Authorization the platform arm over a
    /// session answers <c>TPM_RC_HIERARCHY</c> naming authHandle, handle 1 of Table 263, refused before any
    /// authorization is judged, while the owner arm over a session still locks the same Index.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.4, check 5; clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverHmacSessionWithADisabledPlatformHierarchyReturnsHierarchyWhileTheOwnerArmLocks()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);

        TpmResult<HierarchyControlResponse> disableResult = await device.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_PLATFORM, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(disableResult.IsSuccess, $"CLEARing phEnable under Platform Authorization failed: '{disableResult.ResponseCode}'.");

        TpmResult<NvGlobalWriteLockResponse> platformResult = await GlobalWriteLockOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), platformResult.ResponseCode,
            "Clause 5.4's check 5 refuses a disabled hierarchy at authHandle, handle 1 of Table 263, ahead of clause 5.6's authorization, and the enable gate precedes the HMAC verification the session form adds.");

        TpmaNv afterRefusal = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), afterRefusal & TpmaNv.TPMA_NV_WRITELOCKED, "A hierarchy refusal applies none of clause 31.12.1's effect.");

        TpmResult<NvGlobalWriteLockResponse> ownerResult = await GlobalWriteLockOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(ownerResult.IsSuccess, $"The owner arm is gated by shEnable alone and must still succeed: '{ownerResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "Clause 31.12.1's Note: the authorizing hierarchy plays no part in which Indexes lock.");
    }

    /// <summary>
    /// The order between the two refusals, on the session form: clause 5.4's handle checks run ahead of clause
    /// 5.6's authorization checks — the enable gate precedes the command-HMAC verification a session adds — so a
    /// WRONG ownerAuth proven over a session while shEnable is CLEAR answers <c>TPM_RC_HIERARCHY</c> naming
    /// authHandle, handle 1 of Table 263, by the availability gate, and never reaches the HMAC compare that would
    /// have answered the session-encoded <c>TPM_RC_BAD_AUTH</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.4, check 5; clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverHmacSessionWithWrongOwnerAuthUnderADisabledOwnerHierarchyReturnsHierarchyNotSessionEncodedBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);

        TpmResult<HierarchyControlResponse> disableResult = await device.DisableHierarchyWithPasswordAsync(
            TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, TpmRh.TPM_RH_OWNER, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(disableResult.IsSuccess, $"CLEARing shEnable under Platform Authorization failed: '{disableResult.ResponseCode}'.");

        TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), result.ResponseCode, "The enable is judged before the command HMAC, so the disabled hierarchy answers first.");
        Assert.AreNotEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
            "No HMAC compare happens at all once the handle resolves to no usable entity.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED, "A hierarchy refusal applies none of clause 31.12.1's effect.");
    }

    /// <summary>
    /// <c>TPMI_RH_PROVISION</c> admits <c>TPM_RH_OWNER</c> and <c>TPM_RH_PLATFORM</c> and nothing else, with
    /// "#TPM_RC_VALUE" as the unmarshalling error for any other value — so <c>TPM_RH_ENDORSEMENT</c> at
    /// <c>@authHandle</c> answers <c>TPM_RC_VALUE</c> naming authHandle, handle 1 of Table 263, answered at the
    /// head of the transition before the hierarchy-enable check and before any authorization is judged.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.21, Table 67; Part 3, clause 31.12, Table 263</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverHmacSessionWithANonProvisionHandleReturnsValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), result.ResponseCode,
            "A handle outside TPMI_RH_PROVISION designates authHandle, handle 1 of Table 263, at unmarshalling.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED, "A handle refusal applies none of clause 31.12.1's effect.");
    }

    /// <summary>
    /// Clause 5.5, step 4 fixes the RESOLUTION ORDER at the authorization slot: a handle's kind (HMAC session,
    /// policy session, or <c>TPM_RS_PW</c>) is settled before its loadedness. A loaded POLICY session clears that
    /// order and reaches clause 31.12.1, which admits ownerPolicy/platformPolicy alongside ownerAuth/platformAuth
    /// — a kind of authorization this simulator does not implement — so it is answered with the unimplemented-
    /// authorization-kind <c>TPM_RC_AUTH_TYPE</c>, naming no slot.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4; clause 31.12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverALoadedPolicySessionReturnsAuthType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);

        TpmResult<StartAuthSessionResponse> policyStartResult = await device.StartPolicySessionAsync(HmacSessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStartResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyStartResult.ResponseCode}'.");

        using StartAuthSessionResponse policyStarted = policyStartResult.Value;
        uint policySessionHandle = policyStarted.SessionHandle.Value;
        try
        {
            using TpmPolicySession policySlot = TpmPolicySession.ForSession(policySessionHandle, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
            var input = new NvGlobalWriteLockInput(TpmRh.TPM_RH_OWNER);

            TpmResult<NvGlobalWriteLockResponse> result = await TpmCommandExecutor.ExecuteAsync<NvGlobalWriteLockResponse>(
                device, input, [policySlot], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode,
                "A genuine POLICY session at the sole authorization slot must be refused with the unimplemented-authorization-kind TPM_RC_AUTH_TYPE.");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, policySessionHandle).ConfigureAwait(false);
        }

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED, "A slot refusal applies none of clause 31.12.1's effect.");
    }

    /// <summary>
    /// A session handle in the <c>0x02000000</c> range that names no loaded session is blamed on the offending
    /// slot index: "TPM_RC_REFERENCE_S0 ... the 1st session handle references a session that is not loaded",
    /// distinct from the unimplemented-authorization-kind <c>TPM_RC_AUTH_TYPE</c> a LOADED policy session earns.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.6.2; Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverAnUnloadedSessionHandleReturnsReferenceMiss()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;
        using TpmSession unloadedSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);

        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext failed: '{flushResult.ResponseCode}'.");

        var input = new NvGlobalWriteLockInput(TpmRh.TPM_RH_OWNER);
        TpmResult<NvGlobalWriteLockResponse> result = await TpmCommandExecutor.ExecuteAsync<NvGlobalWriteLockResponse>(
            device, input, [unloadedSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_REFERENCE_S0, result.ResponseCode,
            "A session handle naming no loaded session must be blamed on the offending slot index.");
    }

    /// <summary>
    /// "For a response, the TPM uses the last nonceCaller and a newly generated nonceTPM in the HMAC." — and an
    /// error answer is the header alone, which carries no response authorization and therefore rolls nothing
    /// (Part 1, clause 16.6): a second command on the same session succeeds after a success, proving both sides
    /// rolled together, and a third succeeds after a REFUSAL with the caller's freshly rolled nonce against an
    /// unmoved <c>nonceTPM</c>, proving the refusal rolled nothing on the TPM side.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.3; Part 3, clause 31.12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverHmacSessionRollsTheNonceOnSuccessAndNotOnARefusal()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);
        await InstallOwnerAuthAsync(device).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, InstalledOwnerAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                TpmResult<NvGlobalWriteLockResponse> first = await GlobalWriteLockOverSessionAsync(
                    device, pool, registry, session, TpmRh.TPM_RH_OWNER, InstalledOwnerAuth).ConfigureAwait(false);
                Assert.IsTrue(first.IsSuccess, $"The first command over the session failed: '{first.ResponseCode}'.");

                TpmResult<NvGlobalWriteLockResponse> second = await GlobalWriteLockOverSessionAsync(
                    device, pool, registry, session, TpmRh.TPM_RH_OWNER, InstalledOwnerAuth).ConfigureAwait(false);
                Assert.IsTrue(
                    second.IsSuccess,
                    $"A second command on the same session must succeed, which only a nonce rolled on BOTH sides of the first success allows: '{second.ResponseCode}'.");

                TpmResult<NvGlobalWriteLockResponse> refused = await GlobalWriteLockOverSessionAsync(
                    device, pool, registry, session, TpmRh.TPM_RH_OWNER, WrongAuth).ConfigureAwait(false);
                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), refused.ResponseCode,
                    "A wrong ownerAuth over a session is the session-encoded, non-charging TPM_RC_BAD_AUTH.");

                TpmResult<NvGlobalWriteLockResponse> afterRefusal = await GlobalWriteLockOverSessionAsync(
                    device, pool, registry, session, TpmRh.TPM_RH_OWNER, InstalledOwnerAuth).ConfigureAwait(false);
                Assert.IsTrue(
                    afterRefusal.IsSuccess,
                    $"A header-only refusal carries no response authorization and rolls no nonceTPM, so the next command must still verify: '{afterRefusal.ResponseCode}'.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "While in Lockout mode, any use of a DA-protected authValue will return TPM_RC_LOCKOUT" is a rule about
    /// DA-PROTECTED authValues only, and "the authValue associated with a permanent entity, other than
    /// TPM_RH_LOCKOUT, does not receive DA protection" — so with the TPM already in Lockout mode the owner arm
    /// over an UNBOUND session is untouched by the gate and still locks every <c>TPMA_NV_GLOBALLOCK</c> Index.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.8.1 and 16.8.3; Part 3, clause 31.12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverAnUnboundHmacSessionInLockoutModeStillLocks()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);
        await DriveIntoLockoutAsync(device, pool, registry).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> lockedOut = await device.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lockedOut.IsSuccess, $"Reading the dictionary-attack parameters failed: '{lockedOut.ResponseCode}'.");
        Assert.IsTrue(lockedOut.Value.IsLockedOut, "The arrangement must leave the TPM in Lockout mode, or the case proves nothing.");

        TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A dictionary-attack-exempt permanent entity is not gated by Lockout mode: '{result.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "Clause 31.12.1's effect applies unchanged while the TPM is in Lockout mode.");
    }

    /// <summary>
    /// "If the entity is authorized in a bind session, it receives DA protection if the bind entity receives DA
    /// protection" — a session BOUND to a dictionary-attack-protected NV Index carries that protection into
    /// every command it authorizes, including the otherwise-exempt owner arm, so while the TPM is in Lockout
    /// mode it is refused with the format-zero <c>TPM_RC_LOCKOUT</c> before any authValue is evaluated and no
    /// Index locks.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.8.1 and 16.8.3; Part 3, clause 31.12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverASessionBoundToADaProtectedIndexInLockoutModeReturnsLockout()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);
        await DriveIntoLockoutAsync(device, pool, registry).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> before = await device.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(before.IsSuccess, $"Reading the dictionary-attack parameters failed: '{before.ResponseCode}'.");
        Assert.IsTrue(before.Value.IsLockedOut, "The arrangement must leave the TPM in Lockout mode, or the case proves nothing.");

        (uint sessionHandle, TpmSession session) = await StartBoundHmacSessionAsync(
            device, registry, pool, BindIndexHandle, CorrectAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockOverSessionAsync(
                    device, pool, registry, session, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_LOCKOUT, result.ResponseCode,
                    "A bind entity that receives DA protection lends it to the command, which Lockout mode then refuses with the format-zero TPM_RC_LOCKOUT.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED, "A lockout refusal applies none of clause 31.12.1's effect.");
    }

    /// <summary>
    /// The charging half of the same bind sentence: outside Lockout mode, a session bound to a
    /// dictionary-attack-protected NV Index and used to authorize the owner arm with a WRONG <c>ownerAuth</c> is
    /// refused with the session-encoded <c>TPM_RC_AUTH_FAIL</c> — not the exempt entity's non-charging
    /// <c>TPM_RC_BAD_AUTH</c> — and charges <c>failedTries</c> exactly once.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.8.1 and 16.8.3; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverASessionBoundToADaProtectedIndexWithAWrongHmacReturnsAuthFailAndChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);
        await DefineIndexAsync(device, pool, registry, BindIndexHandle, DaProtectedAttributes).ConfigureAwait(false);
        await InstallOwnerAuthAsync(device).ConfigureAwait(false);

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartBoundHmacSessionAsync(
            device, registry, pool, BindIndexHandle, CorrectAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockOverSessionAsync(
                    device, pool, registry, session, TpmRh.TPM_RH_OWNER, WrongAuth).ConfigureAwait(false);

                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), result.ResponseCode,
                    "A DA-protected bind entity turns the exempt entity's TPM_RC_BAD_AUTH into the charging TPM_RC_AUTH_FAIL.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }

        Assert.AreEqual(
            counterBefore + 1u, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "A command that receives DA protection through its bind entity charges failedTries exactly once on a mismatch.");
    }

    /// <summary>
    /// "When an NV Index becomes locked (TPMA_NV_WRITELOCKED or TPMA_NV_READLOCKED is SET), the Name of the NV
    /// Index changes. This has two implications: ... The caller should use its copy of the NV public area and
    /// calculate the Name before using it in an HMAC authorization calculation. Otherwise, an invalid
    /// authorization can trigger the dictionary attack protection depending on TPMA_NV_NO_DA" — end to end on
    /// THIS command's effect: after a global write lock, a
    /// <c>TPM2_NV_Read()</c> over an HMAC session folding the STALE pre-lock Name of the
    /// dictionary-attack-protected Index is refused with a session-encoded <c>TPM_RC_AUTH_FAIL</c> and charges
    /// <c>failedTries</c>, while the same read folding the fresh Name succeeds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 13 and 15.7; Part 3, clauses 31.12.1 and 31.13</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadOverHmacSessionFoldingTheStaleNameAfterAGlobalWriteLockReturnsAuthFailWhileTheFreshNameSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, DaProtectedGlobalLockIndexHandle, DaProtectedGlobalLockAttributes).ConfigureAwait(false);

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, DaProtectedGlobalLockIndexHandle, CorrectAuth, IndexData).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"TPM2_NV_Write() failed: '{writeResult.ResponseCode}'.");

        byte[] staleName = await ReadIndexNameAsync(device, DaProtectedGlobalLockIndexHandle).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> lockResult = await GlobalWriteLockOverHmacAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{lockResult.ResponseCode}'.");

        byte[] freshName = await ReadIndexNameAsync(device, DaProtectedGlobalLockIndexHandle).ConfigureAwait(false);
        Assert.IsFalse(staleName.AsSpan().SequenceEqual(freshName), "SETting TPMA_NV_WRITELOCKED moves the Name the Index's public area digests.");

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvReadResponse> staleResult = await ReadIndexOverHmacWithNamesAsync(
            device, pool, registry, DaProtectedGlobalLockIndexHandle, CorrectAuth, OrdinaryDataSize, [staleName, staleName]).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_FAIL, staleResult.BaseError,
            "A cpHash folding the pre-lock Name cannot match the one the TPM computes over the globally locked Index.");
        Assert.AreEqual(
            counterBefore + 1u, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "Clause 13's warning: the stale-Name authorization is an ordinary authorization failure and charges failedTries.");

        TpmResult<NvReadResponse> freshResult = await ReadIndexOverHmacWithNamesAsync(
            device, pool, registry, DaProtectedGlobalLockIndexHandle, CorrectAuth, OrdinaryDataSize, [freshName, freshName]).ConfigureAwait(false);
        Assert.IsTrue(freshResult.IsSuccess, $"The same read folding the fresh Name must succeed: '{freshResult.ResponseCode}'.");

        using NvReadResponse read = freshResult.Value;
        Assert.IsTrue(IndexData.AsSpan().SequenceEqual(read.Data), "A write lock never blocks a read, so the Index still returns the octets it holds.");
    }

    /// <summary>
    /// "If session-based encryption is allowed, only the first parameter in the parameter area of a request or
    /// response can be encrypted. That parameter must have an explicit size field." — Table 263 defines no
    /// command parameter at all, so nothing with a size field exists for a <c>decrypt</c>-attributed authorizing
    /// session to act on, and the TPM fails closed with <c>TPM_RC_ATTRIBUTES</c> naming the session. Proven
    /// hand-framed, because the executor's
    /// own client-side guard refuses the composition with an <see cref="ArgumentException"/> before any octet
    /// reaches the wire — the second assertion below.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clauses 5.7 and 31.12</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverSessionWithDecryptAttributeReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        (TpmRcConstants rawCode, _, _) = await GlobalWriteLockOverHmacHandFramedAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmaSession.DECRYPT).ConfigureAwait(false);
        TpmResult<NvGlobalWriteLockResponse> result = TpmResult<NvGlobalWriteLockResponse>.TpmError(rawCode);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.BaseError, "A parameterless command has nothing to decrypt, so a decrypt-attributed session must fail closed.");
        Assert.AreNotEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode, "The refusal names the offending session, so the raw wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        await AssertExecutorRefusesAttributeAsync(device, pool, registry, TpmaSession.DECRYPT).ConfigureAwait(false);
    }

    /// <summary>
    /// The response side of the same rule: Table 264 is the header alone, so there is no first response
    /// parameter to encrypt and an <c>encrypt</c>-attributed authorizing session fails closed with
    /// <c>TPM_RC_ATTRIBUTES</c> naming the session, the executor again refusing the composition client-side.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clauses 5.7 and 31.12</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverSessionWithEncryptAttributeReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        (TpmRcConstants rawCode, _, _) = await GlobalWriteLockOverHmacHandFramedAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmaSession.ENCRYPT).ConfigureAwait(false);
        TpmResult<NvGlobalWriteLockResponse> result = TpmResult<NvGlobalWriteLockResponse>.TpmError(rawCode);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.BaseError, "A header-only response has nothing to encrypt, so an encrypt-attributed session must fail closed.");
        Assert.AreNotEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode, "The refusal names the offending session, so the raw wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        await AssertExecutorRefusesAttributeAsync(device, pool, registry, TpmaSession.ENCRYPT).ConfigureAwait(false);
    }

    /// <summary>
    /// The <c>audit</c> attribute on the authorizing session is admitted (TPM 2.0 Library Part 1, clause 17.1)
    /// and the command succeeds, extending the session's audit digest to <c>H(0…0 ‖ cpHash ‖ rpHash)</c> on its
    /// first use (equation 30) with the response echoing <c>audit</c> SET, <c>auditExclusive</c> SET and
    /// <c>auditReset</c> CLEAR (TPM 2.0 Library Part 2, clause 8.4, Table 38) — proved by chaining cpHash/rpHash
    /// from the octets this test itself sent and read, then reading the session's digest back through
    /// <c>TPM2_GetSessionAuditDigest()</c> with the NULL signer.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1; Part 2, clause 8.4, Table 38</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverSessionWithAuditAttributeSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        (byte[] response, uint sessionHandle, byte[] cpHash) = await GlobalWriteLockOverHmacHandFramedForAuditAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            var responseReader = new TpmReader(response);
            TpmRcConstants rawCode = (TpmRcConstants)TpmHeader.Parse(ref responseReader).Code;
            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, rawCode, "An audit-claiming session over an audited command succeeds (TPM 2.0 Library Part 1, clause 17.1).");

            byte auditedAttributes = ReadResponseSessionAttributes(response, outHandleCount: 0, sessionIndex: 0);
            Assert.AreEqual(
                (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE), auditedAttributes,
                "The response echoes audit SET and auditExclusive SET (the session's first use as an audit session), with auditReset CLEAR (TPM 2.0 Library Part 2, clause 8.4, Table 38).");

            byte[] responseParameters = ReadResponseParameters(response, outHandleCount: 0);
            byte[] rpHash = await ComputeRpHashAsync(TpmCcConstants.TPM_CC_NV_GlobalWriteLock, responseParameters, pool).ConfigureAwait(false);
            byte[] expectedDigest = await ExtendAuditDigestAsync(priorDigest: null, cpHash, rpHash, pool).ConfigureAwait(false);

            using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(sessionHandle), ReadOnlySpan<byte>.Empty, pool);
            using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                device, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            using GetSessionAuditDigestResponse? auditDigestResponse = digestResult.IsSuccess ? digestResult.Value : null;

            Assert.IsTrue(digestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() over the freshly audited session must succeed: '{digestResult.ResponseCode}'.");
            Assert.IsTrue(auditDigestResponse!.SessionAudit.ExclusiveSession.IsYes, "The session became the exclusive audit session on its first use (TPM 2.0 Library Part 1, clause 17.2).");
            Assert.IsTrue(
                expectedDigest.AsSpan().SequenceEqual(auditDigestResponse.SessionAudit.SessionDigest.AsReadOnlySpan()),
                "The session's audit digest must equal H(0…0 ‖ cpHash ‖ rpHash) chained from the NV_GlobalWriteLock exchange's own wire octets (TPM 2.0 Library Part 1, clause 17.1, equation 30).");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The third row of the authorization slot's own resolution: "If the session handle is not a handle for an
    /// HMAC session, a handle for a policy session, or, TPM_RS_PW then the TPM shall return TPM_RC_HANDLE" — a
    /// NON-SESSION handle framed into the slot (a transient-object handle, or a defined NV Index handle) is
    /// refused before any credential is evaluated, session-index-encoded to the offending slot.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 4.1; Part 2, clause 6.6.2</see>.
    /// </summary>
    /// <param name="slotHandle">The non-session value framed into the authorization slot's session handle field.</param>
    [TestMethod]
    [DataRow(TransientRangeHandle, DisplayName = "a transient-object handle is not a session")]
    [DataRow(GlobalLockIndexHandle, DisplayName = "a defined NV Index handle is not a session")]
    public async Task NvGlobalWriteLockOverANonSessionAuthorizationSlotHandleReturnsSessionEncodedHandle(uint slotHandle)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);

        (TpmRcConstants rawCode, _, _) = await GlobalWriteLockOverHmacHandFramedAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, default, slotHandleOverride: slotHandle).ConfigureAwait(false);

        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 0), rawCode,
            "A non-session handle at the authorization slot is refused with the session-index-encoded TPM_RC_HANDLE, ahead of any credential evaluation.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED, "A slot refusal applies none of clause 31.12.1's effect.");
    }

    /// <summary>
    /// The accepting half of the raw command-HMAC proof: the same hand-framed composition with no extra session
    /// attribute succeeds, which makes the independently computed cpHash — commandCode folded with the
    /// authorizing handle's own four octets, "the Name of a permanent entity is the handle" (Part 1, clause 13,
    /// Table 9), and an EMPTY parameters term — the thing the TPM's own command-HMAC verification must agree
    /// with (Part 1, clause 15.7, equation 15).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.7, equation 15, and clause 13, Table 9; Part 3, clause 31.12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverHmacHandFramedWithTheCorrectCpHashSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);

        (TpmRcConstants rawCode, _, _) = await GlobalWriteLockOverHmacHandFramedAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, default).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, rawCode, $"A cpHash independently computed the production way must verify: '{rawCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "Clause 31.12.1's effect follows a verified hand-framed command exactly as it follows one the executor composed.");
    }

    /// <summary>
    /// The negative twin: the same composition, but cpHash's Name term is TPM_RH_PLATFORM's four octets while the
    /// wire's handle area still carries TPM_RH_OWNER — a command HMAC keyed on the WRONG Name cannot verify
    /// against the octets the TPM actually received, so the answer is the session-encoded, non-charging
    /// <c>TPM_RC_BAD_AUTH</c> the exempt permanent entity earns.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.7, equation 15, and clause 13, Table 9; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverHmacHandFramedWithTheWrongCpHashReturnsSessionEncodedBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        (TpmRcConstants rawCode, _, _) = await GlobalWriteLockOverHmacHandFramedAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, default, cpHashHandleOverride: TpmRh.TPM_RH_PLATFORM).ConfigureAwait(false);

        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), rawCode,
            "cpHash folding the wrong Name term cannot key a command HMAC that verifies against the octets actually on the wire.");
        Assert.AreEqual(
            counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "TPM_RH_OWNER's authValue is dictionary-attack exempt, so the mismatch never charges failedTries.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED, "A command-HMAC refusal applies none of clause 31.12.1's effect.");
    }

    /// <summary>
    /// A literal replay of a captured, previously successful command is refused: "For a response, the TPM uses
    /// the last nonceCaller and a newly generated nonceTPM in the HMAC" (Part 1, clause 16.6.3) — the success
    /// already rolled nonceTPM, so the identical octets, hmac included, no longer key the session on a second
    /// submission and the answer is the session-encoded, non-charging <c>TPM_RC_BAD_AUTH</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.3; clause 16.6; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverHmacHandFramedReplayOfTheIdenticalOctetsReturnsSessionEncodedBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);

        (TpmRcConstants firstCode, byte[] framedCommand, uint sessionHandle) = await GlobalWriteLockOverHmacHandFramedAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, default, flushSessionAfterSubmit: false).ConfigureAwait(false);
        try
        {
            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, firstCode, $"The captured command must succeed the first time: '{firstCode}'.");

            uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

            using IMemoryOwner<byte> replayOwner = pool.Rent(framedCommand.Length);
            Memory<byte> replay = replayOwner.Memory[..framedCommand.Length];
            framedCommand.CopyTo(replay);

            TpmResult<TpmResponse> replayResult = await device.SubmitAsync(replay, pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(replayResult.IsSuccess, "The transport itself must succeed even when the TPM refuses the replay.");

            using TpmResponse replayResponse = replayResult.Value;
            var replayReader = new TpmReader(replayResponse.AsReadOnlySpan());
            var replayCode = (TpmRcConstants)TpmHeader.Parse(ref replayReader).Code;

            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), replayCode,
                "nonceTPM rolled on the first success, so the captured command HMAC cannot key the identical octets a second time.");
            Assert.AreEqual(
                counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
                "TPM_RH_OWNER's authValue is dictionary-attack exempt, so the replay's mismatch never charges failedTries.");
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Table 263 fixes the tag at <c>TPM_ST_SESSIONS</c>: "If the tag is TPM_ST_NO_SESSIONS and the command
    /// requires TPM_ST_SESSIONS, the TPM will return TPM_RC_AUTH_MISSING" — a <c>TPM_ST_NO_SESSIONS</c> frame
    /// carries no authorization area at all, and the command's <c>@authHandle</c> requires an authorization the
    /// frame does not supply.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.12.2, Table 263; clause 5.5, step 2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockWithoutAnAuthorizationAreaReturnsAuthMissing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        //The handle area alone: the frame declares no sessions and carries no authorization area.
        var body = new List<byte>();
        AppendUInt32(body, (uint)TpmRh.TPM_RH_OWNER);

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_NV_GlobalWriteLock, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_MISSING, code, "An authorized command sent without an authorization area is TPM_RC_AUTH_MISSING.");
    }

    /// <summary>
    /// The handle area is one four-octet <c>TPMI_RH_PROVISION</c>: a frame carrying only three of those octets
    /// runs out of buffer before the handle is read, which Table 2's unmarshalling-error row answers — "the
    /// input buffer did not contain enough octets to allow unmarshaling of the expected data type" — naming
    /// authHandle, handle 1 of Table 263.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.12.2, Table 263; clause 5.8.2, Table 2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockWithATruncatedHandleReturnsInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        //Three octets where the four-octet handle belongs.
        byte[] body = [0x40, 0x00, 0x00];

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_NV_GlobalWriteLock, body).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, handleIndex: 0), code,
            "Table 263: @authHandle is TPM2_NV_GlobalWriteLock()'s sole handle (index 0); a handle area short of its four octets is TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// Table 263 defines no command parameters, so nothing may follow the authorization area: one trailing octet
    /// is unmarshaled as if it began a further structure the command never declares, which Table 2's
    /// unmarshalling-error row answers — "the value of a size parameter is larger or smaller than allowed" — with
    /// no handle, session, or parameter designation, unlike clause 5.2's separate commandSize-consistency check.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.12.2, Table 263; clause 5.8.2, Table 2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockWithATrailingOctetAfterTheAuthorizationAreaReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        //Handle area, a well-formed password authorization area, then one octet too many.
        var body = new List<byte>();
        AppendUInt32(body, (uint)TpmRh.TPM_RH_OWNER);
        AppendPasswordAuthorizationArea(body);
        body.Add(0x00);

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_NV_GlobalWriteLock, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "No octet may follow the authorization area of a command that declares no parameters.");
    }

    /// <summary>
    /// The smallest well-formed authorization block is nine octets — a session handle, an empty nonce, the
    /// <c>sessionAttributes</c> octet and an empty hmac — so a declared <c>authorizationSize</c> below that is
    /// "the value of authorizationSize is out of range or the number of octets in the Authorization Area is
    /// greater than required", the format-zero <c>TPM_RC_AUTHSIZE</c>, refused before the area is ever walked.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5, step 3.1; Part 2, Table 18</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockWithAnUndersizedAuthorizationAreaReturnsAuthsize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        //Handle area, then an authorization area declaring eight octets and framing exactly eight — one short of
        //the nine-octet minimum, so the size itself is what is refused rather than the buffer running out.
        var body = new List<byte>();
        AppendUInt32(body, (uint)TpmRh.TPM_RH_OWNER);
        AppendUInt32(body, 8u);
        AppendUInt32(body, (uint)TpmRh.TPM_RH_PW);
        AppendUInt16(body, 0);
        body.Add((byte)TpmaSession.CONTINUE_SESSION);
        body.Add(0x00);

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_NV_GlobalWriteLock, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTHSIZE, code, "An authorizationSize below the nine-octet minimum is TPM_RC_AUTHSIZE.");
    }

    /// <summary>
    /// The HMAC-session form returns every carrier its parse rented — the always-empty raw parameter area and
    /// the authorization slot's own nonce and hmac credentials — across a refusal at the command HMAC and a
    /// success: the metered pool returns to its baseline after each.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.12; Part 1, clause 15.7</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockOverHmacSessionReturnsItsCarriersAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);

        (uint wrongSessionHandle, TpmSession wrongSession) = await StartUnboundSessionAsync(device, pool, registry, WrongAuth).ConfigureAwait(false);
        (uint correctSessionHandle, TpmSession correctSession) = await StartUnboundSessionAsync(device, pool, registry, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(wrongSession)
            using(correctSession)
            {
                long baseline = trackingPool.OutstandingCount;

                var refusedInput = new NvGlobalWriteLockInput(TpmRh.TPM_RH_OWNER);
                TpmResult<NvGlobalWriteLockResponse> refused = await TpmCommandExecutor.ExecuteAsync<NvGlobalWriteLockResponse>(
                    device, refusedInput, [wrongSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, refused.BaseError);
                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A command refused at its command HMAC releases every carrier its parse rented.");

                var acceptedInput = new NvGlobalWriteLockInput(TpmRh.TPM_RH_OWNER);
                TpmResult<NvGlobalWriteLockResponse> accepted = await TpmCommandExecutor.ExecuteAsync<NvGlobalWriteLockResponse>(
                    device, acceptedInput, [correctSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(accepted.IsSuccess, $"TPM2_NV_GlobalWriteLock() over an HMAC session failed: '{accepted.ResponseCode}'.");
                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The accepting continuation and the response framing between them release every carrier.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, wrongSessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(device, registry, pool, correctSessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Asserts that the executor refuses an authorizing session carrying <paramref name="attribute"/> before any
    /// octet reaches the wire: <c>TPM2_NV_GlobalWriteLock()</c> has neither an encryptable first command
    /// parameter nor an encryptable first response parameter, which is the client-side half of TPM 2.0 Library
    /// Part 1, clause 18.1's rule.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="attribute">The <c>TPMA_SESSION</c> bit under test.</param>
    private async Task AssertExecutorRefusesAttributeAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmaSession attribute)
    {
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(session)
            {
                session.SessionAttributes |= attribute;
                var input = new NvGlobalWriteLockInput(TpmRh.TPM_RH_OWNER);

                _ = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
                    await TpmCommandExecutor.ExecuteAsync<NvGlobalWriteLockResponse>(
                        device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
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
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
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
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(bindHandle, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound to 0x{bindHandle:X8}) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse startResponse = startResult.Value;
        TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(startResponse.SessionHandle.Value), bindAuthValue, startInput.NonceCaller,
            startResponse.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION;

        return (startResponse.SessionHandle.Value, session);
    }

    /// <summary>
    /// Issues <c>TPM2_NV_GlobalWriteLock()</c> over a freshly started UNBOUND, unsalted HMAC session whose
    /// authValue term is <paramref name="suppliedAuth"/>, flushing the session afterwards. The command's sole
    /// handle is a permanent one, so no Name is supplied: the host derives the cpHash Name term from the
    /// handle's own four octets (TPM 2.0 Library Part 1, clause 13, Table 9).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorizing hierarchy.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <returns>The global-write-lock result.</returns>
    private async Task<TpmResult<NvGlobalWriteLockResponse>> GlobalWriteLockOverHmacAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh authHandle, ReadOnlyMemory<byte> suppliedAuth)
    {
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, suppliedAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                return await GlobalWriteLockOverSessionAsync(device, pool, registry, session, authHandle, suppliedAuth).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Issues <c>TPM2_NV_GlobalWriteLock()</c> over a CALLER-OWNED session, folding
    /// <paramref name="suppliedAuth"/> as the entity authValue term (empty composes the bind-omission form on a
    /// session bound to the authorized hierarchy). The <c>handleNames</c> argument is <see langword="null"/>
    /// because the sole handle is permanent.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="session">The authorizing session.</param>
    /// <param name="authHandle">The authorizing hierarchy.</param>
    /// <param name="suppliedAuth">The authValue term to fold, or empty for the omission form.</param>
    /// <returns>The global-write-lock result.</returns>
    private async Task<TpmResult<NvGlobalWriteLockResponse>> GlobalWriteLockOverSessionAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmSession session, TpmRh authHandle, ReadOnlyMemory<byte> suppliedAuth)
    {
        session.SetAuthValue(suppliedAuth.Span, pool);
        var input = new NvGlobalWriteLockInput(authHandle);

        return await TpmCommandExecutor.ExecuteAsync<NvGlobalWriteLockResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The SIMULATOR-side proof for the session-attribute fail-closed gate, the authorization slot's own
    /// resolution, and the raw command-HMAC verification: hand-frames a raw <c>TPM2_NV_GlobalWriteLock()</c>
    /// authorized by a single unbound, unsalted HMAC session whose <c>sessionAttributes</c> octet carries
    /// <paramref name="attribute"/>, and submits it directly to the transport — bypassing
    /// <see cref="TpmCommandExecutor"/>, whose own client-side guard would refuse a bad attribute before any
    /// bytes reach the wire. The cpHash and command HMAC are the SAME production computation
    /// <see cref="TpmSession"/> performs for every other session-authorized case in this file: the command has
    /// ONE handle and no parameters, so equation (15) folds the command code and
    /// <paramref name="cpHashHandleOverride"/> (or <paramref name="authHandle"/> when omitted) with an EMPTY
    /// parameters term. <paramref name="slotHandleOverride"/>, when supplied, patches the wire's authorization
    /// slot handle field AFTER the genuine session has framed a well-formed block, so the nonce, session
    /// attributes and hmac stay exactly as a real session would carry them.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry (used only for the session's own lifecycle commands).</param>
    /// <param name="authHandle">The authorizing hierarchy, written into the wire's handle area.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <param name="attribute">The <c>TPMA_SESSION</c> bit under test.</param>
    /// <param name="slotHandleOverride">A wire-only substitute for the authorization slot's session handle field, or <see langword="null"/> to leave the genuine session handle in place.</param>
    /// <param name="cpHashHandleOverride">A wire-only substitute for cpHash's Name term, or <see langword="null"/> to fold <paramref name="authHandle"/> as every other case in this file does.</param>
    /// <param name="flushSessionAfterSubmit">Whether the session is flushed once the response has been read; <see langword="false"/> leaves it loaded so the caller can submit further octets against the same session before flushing it.</param>
    /// <returns>The raw wire response code (still carrying any session-index encoding), the exact octets submitted, and the session handle — flushed already unless <paramref name="flushSessionAfterSubmit"/> is <see langword="false"/>.</returns>
    private async Task<(TpmRcConstants ResponseCode, byte[] FramedCommand, uint SessionHandle)> GlobalWriteLockOverHmacHandFramedAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh authHandle, ReadOnlyMemory<byte> suppliedAuth, TpmaSession attribute,
        uint? slotHandleOverride = null, TpmRh? cpHashHandleOverride = null, bool flushSessionAfterSubmit = true)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
            session.SetAuthValue(suppliedAuth.Span, pool);
            session.SessionAttributes |= attribute;

            //cpHash = H_SHA256(commandCode || Name(authHandle)) — TPM 2.0 Library Part 1, clause 15.7, equation
            //15, with an EMPTY parameters term because Part 3's Table 263 defines no command parameters, and with the
            //permanent handle's Name being the handle's own four octets (Part 1, clause 13, Table 9).
            const int cpHashInputLength = sizeof(uint) + sizeof(uint);
            using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
            Memory<byte> cpHashInput = cpHashInputOwner.Memory[..cpHashInputLength];
            {
                var cpHashWriter = new TpmWriter(cpHashInput.Span);
                cpHashWriter.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_GlobalWriteLock);
                cpHashWriter.WriteUInt32((uint)(cpHashHandleOverride ?? authHandle));
            }

            using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
                cpHashInput, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            session.RollNonceCaller(pool);
            using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(
                cpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

            const int handlesSize = sizeof(uint);
            int authAreaSize = sizeof(uint) + session.GetAuthCommandSize();
            int totalSize = TpmHeader.HeaderSize + handlesSize + authAreaSize;

            using IMemoryOwner<byte> commandOwner = pool.Rent(totalSize);
            Memory<byte> command = commandOwner.Memory[..totalSize];
            var writer = new TpmWriter(command.Span);
            writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_SESSIONS);
            writer.WriteUInt32((uint)totalSize);
            writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_GlobalWriteLock);
            writer.WriteUInt32((uint)authHandle);
            writer.WriteUInt32((uint)session.GetAuthCommandSize());
            session.WriteAuthCommand(ref writer, hmac);

            if(slotHandleOverride is uint overrideHandle)
            {
                int slotHandleOffset = TpmHeader.HeaderSize + handlesSize + sizeof(uint);
                BinaryPrimitives.WriteUInt32BigEndian(command.Span.Slice(slotHandleOffset, sizeof(uint)), overrideHandle);
            }

            byte[] framedCommand = command.Span.ToArray();

            TpmResult<TpmResponse> transportResult = await device.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(transportResult.IsSuccess, "The transport itself must succeed even when the TPM refuses the command.");

            using TpmResponse response = transportResult.Value;
            var responseReader = new TpmReader(response.AsReadOnlySpan());
            TpmHeader responseHeader = TpmHeader.Parse(ref responseReader);

            return ((TpmRcConstants)responseHeader.Code, framedCommand, sessionHandle);
        }
        finally
        {
            if(flushSessionAfterSubmit)
            {
                await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// The audit twin of <see cref="GlobalWriteLockOverHmacHandFramedAsync"/>: hand-frames a raw
    /// <c>TPM2_NV_GlobalWriteLock()</c> authorized by a single unbound, unsalted HMAC session carrying
    /// <c>audit ‖ continueSession</c>, submits it directly to the transport, and returns the raw response octets,
    /// the session handle and the independently computed cpHash WITHOUT flushing the session — the caller keeps
    /// it loaded to read its audit digest back through <c>TPM2_GetSessionAuditDigest()</c>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry (used only for the session's own StartAuthSession lifecycle).</param>
    /// <param name="authHandle">The authorizing hierarchy, written into the wire's handle area.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <returns>The raw response octets, the session handle (unflushed) and cpHash.</returns>
    private async Task<(byte[] Response, uint SessionHandle, byte[] CpHash)> GlobalWriteLockOverHmacHandFramedForAuditAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh authHandle, ReadOnlyMemory<byte> suppliedAuth)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        session.SetAuthValue(suppliedAuth.Span, pool);
        session.SessionAttributes |= TpmaSession.AUDIT;

        const int cpHashInputLength = sizeof(uint) + sizeof(uint);
        using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
        Memory<byte> cpHashInput = cpHashInputOwner.Memory[..cpHashInputLength];
        {
            var cpHashWriter = new TpmWriter(cpHashInput.Span);
            cpHashWriter.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_GlobalWriteLock);
            cpHashWriter.WriteUInt32((uint)authHandle);
        }

        using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
            cpHashInput, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.RollNonceCaller(pool);
        using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(
            cpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        const int handlesSize = sizeof(uint);
        int authAreaSize = sizeof(uint) + session.GetAuthCommandSize();
        int totalSize = TpmHeader.HeaderSize + handlesSize + authAreaSize;

        using IMemoryOwner<byte> commandOwner = pool.Rent(totalSize);
        Memory<byte> command = commandOwner.Memory[..totalSize];
        var writer = new TpmWriter(command.Span);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_SESSIONS);
        writer.WriteUInt32((uint)totalSize);
        writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_GlobalWriteLock);
        writer.WriteUInt32((uint)authHandle);
        writer.WriteUInt32((uint)session.GetAuthCommandSize());
        session.WriteAuthCommand(ref writer, hmac);

        TpmResult<TpmResponse> transportResult = await device.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(transportResult.IsSuccess, "The transport itself must succeed even when the TPM refuses the command.");

        using TpmResponse response = transportResult.Value;

        return (response.AsReadOnlySpan().ToArray(), sessionHandle, cpHash.AsReadOnlySpan().ToArray());
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

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            input, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
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

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            input, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Builds the digest <see cref="Tag"/> used to independently compute cpHash for
    /// <see cref="GlobalWriteLockOverHmacHandFramedAsync"/>: SHA-256 digest, raw encoding, direct material — the
    /// same shape <c>TpmCommandExecutor</c>'s own cpHash computation uses.
    /// </summary>
    /// <returns>The digest tag.</returns>
    private static Tag DigestTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

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

    /// <summary>
    /// Installs <see cref="InstalledOwnerAuth"/> as <c>ownerAuth</c> over the factory-empty value, so a
    /// subsequent command HMAC is keyed on a genuine secret rather than the empty buffer.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    private async Task InstallOwnerAuthAsync(TpmDevice device)
    {
        TpmResult<HierarchyChangeAuthResponse> result = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, InstalledOwnerAuth, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Installing ownerAuth failed: '{result.ResponseCode}'.");
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

        await DefineIndexAsync(device, pool, registry, BindIndexHandle, DaProtectedAttributes).ConfigureAwait(false);

        TpmResult<NvWriteResponse> wrongResult = await WriteIndexAsync(
            device, pool, registry, BindIndexHandle, WrongAuth, PrimingWriteData).ConfigureAwait(false);

        //Arrangement machinery, not the normative case under proof: the authorizing slot answers TPM_RC_AUTH_FAIL
        //session-encoded to its own index, and with maxTries lowered to one it engages Lockout mode at once.
        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode,
            "The priming write must fail and count, taking the TPM into Lockout mode.");
    }

    /// <summary>Creates a response codec registry for the commands these tests drive directly.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateNvRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite)
            .Register(TpmCcConstants.TPM_CC_NV_GlobalWriteLock, TpmResponseCodec.NvGlobalWriteLock)
            .Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

    /// <summary>
    /// Issues <c>TPM2_NV_DefineSpace()</c> for <paramref name="nvIndex"/> with <see cref="CorrectAuth"/> as the
    /// Index authValue, authorized by the (empty) owner authValue over a password session.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    private async Task DefineIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, TpmaNv attributes)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);

        //The input takes ownership of the auth value and public area and disposes them; the redundant using
        //locals satisfy CA2000 and are safe because both types have idempotent disposal.
        using var auth = Tpm2bAuth.Create(CorrectAuth, pool);
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
    /// Issues an Index-arm <c>TPM2_NV_Read()</c> over an unbound, unsalted HMAC session whose cpHash folds
    /// <paramref name="handleNames"/> — supplied by the caller so a deliberately STALE Name can be proven.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to read.</param>
    /// <param name="suppliedAuth">The authValue proven by the HMAC session.</param>
    /// <param name="size">The number of octets to read.</param>
    /// <param name="handleNames">The Name terms cpHash folds, in handle order.</param>
    /// <returns>The read result; on success, the caller owns and must dispose <see cref="TpmResult{T}.Value"/>.</returns>
    private async Task<TpmResult<NvReadResponse>> ReadIndexOverHmacWithNamesAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ushort size,
        ReadOnlyMemory<byte>[] handleNames)
    {
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, suppliedAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                var input = new NvReadInput(AuthHandle: nvIndex, NvIndex: nvIndex, Size: size, Offset: 0);

                return await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                    device, input, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushIfPresentAsync(device, registry, pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Reads an Index's Name back from the TPM through <c>TPM2_NV_ReadPublic()</c> — the authoritative source of
    /// a session-authorized command's cpHash Name term, since the attribute word a lock changes is part of the
    /// public area the Name digests (TPM 2.0 Library Part 1, clause 13).
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
    /// Reads an Index's <c>TPMA_NV</c> attribute word back through <c>TPM2_NV_ReadPublic()</c>, which is how the
    /// TPM-maintained lock bits are observable from outside (TPM 2.0 Library Part 3, clause 31.6).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Index whose public area is wanted.</param>
    /// <returns>The Index's attribute word.</returns>
    private async Task<TpmaNv> ReadIndexAttributesAsync(TpmDevice device, uint nvIndex)
    {
        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(nvIndex, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(publicResult.IsSuccess, $"NvReadPublicAsync(0x{nvIndex:X8}) failed: '{publicResult.ResponseCode}'.");

        using NvReadPublicResponse indexPublic = publicResult.Value;

        return indexPublic.NvPublic.Attributes;
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
    /// Appends a one-slot authorization area naming <c>TPM_RS_PW</c> with an empty nonce and an empty password —
    /// the password form of <c>TPMS_AUTH_COMMAND</c> (TPM 2.0 Library Part 1, clause 16.6.4.1) — which is enough
    /// for a parse-time proof, since the parse never evaluates the credential.
    /// </summary>
    /// <param name="body">The body being built.</param>
    private static void AppendPasswordAuthorizationArea(List<byte> body)
    {
        var area = new List<byte>();
        AppendUInt32(area, (uint)TpmRh.TPM_RH_PW);
        AppendUInt16(area, 0);
        area.Add((byte)TpmaSession.CONTINUE_SESSION);
        AppendUInt16(area, 0);

        AppendUInt32(body, (uint)area.Count);
        body.AddRange(area);
    }

    /// <summary>Frames a command header around <paramref name="body"/> and submits it straight to the simulator.</summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag.</param>
    /// <param name="commandCode">The command code.</param>
    /// <param name="body">The handle area, authorization area and parameter area, already laid out.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitFramedAsync(
        TpmSimulator simulator, BaseMemoryPool pool, TpmStConstants tag, TpmCcConstants commandCode, byte[] body)
    {
        int length = TpmHeader.HeaderSize + body.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)tag, (uint)length, (uint)commandCode);
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
    /// phase — the precondition <c>TPM2_NV_GlobalWriteLock()</c> carries.
    /// </summary>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync()
    {
        var simulator = new TpmSimulator("tpm-in-house-nv-globalwritelock-session", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitStartupAsync(simulator, BaseMemoryPool.Shared, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false),
            "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
