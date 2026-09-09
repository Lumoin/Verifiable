using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
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
/// Drives the authorization ladder of <c>TPM2_NV_GlobalWriteLock()</c> on its password form - the two hierarchies
/// <c>TPMI_RH_PROVISION</c> admits and nothing else, the dictionary-attack exemption every permanent entity other
/// than <c>TPM_RH_LOCKOUT</c> carries, the hierarchy-enable gate that precedes the authorization, and the
/// cross-authorization rule that an owner-defined Index locks under Platform Authorization just the same -
/// against the in-house behavioural <see cref="TpmSimulator"/>, entirely in-process with no external assets,
/// through the same production command path the production code uses (<see cref="TpmCommandExecutor"/> and the
/// real command/response codecs). TPM 2.0 Library Part 3, clauses 31.12 and 5.4; Part 2, clause 9.21; Part 1,
/// clause 16.8.1.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorNvGlobalWriteLockAuthorizationTests
{
    /// <summary>The declared data size of every Ordinary Index this file defines.</summary>
    private const ushort OrdinaryDataSize = 16;

    /// <summary>The Ordinary Index electing <c>TPMA_NV_GLOBALLOCK</c>, the attribute this command acts on.</summary>
    private const uint GlobalLockIndexHandle = 0x0100_00A0;

    /// <summary>A second defined Index, offered as an inadmissible <c>@authHandle</c> value.</summary>
    private const uint SecondaryIndexHandle = 0x0100_00A1;

    /// <summary>A handle in the transient-object range, which <c>TPMI_RH_PROVISION</c> admits no more than an Index handle does.</summary>
    private const uint TransientRangeHandle = 0x8000_0000;

    /// <summary>The platform NV enable pseudo-hierarchy — the numeric neighbour of <c>TPM_RH_PLATFORM</c>, which <c>TPMI_RH_PROVISION</c> admits no more than that neighbour does.</summary>
    private const uint PlatformNvHandle = 0x4000_000D;

    /// <summary>A PCR handle, at the bottom of the handle space, which <c>TPMI_RH_PROVISION</c> admits no more than any other non-provisioning handle does.</summary>
    private const uint PcrHandle = 0x0000_0000;

    /// <summary>A handle in the session range, which <c>TPMI_RH_PROVISION</c> admits no more than a loaded session handle does.</summary>
    private const uint SessionRangeHandle = 0x0200_0000;

    /// <summary>The tolerated-failure count these tests lower <c>maxTries</c> to before driving the TPM into Lockout mode.</summary>
    private const uint LoweredMaxTries = 2;

    /// <summary>
    /// Ordinary Index attributes electing <c>TPMA_NV_GLOBALLOCK</c>: readable and writable with the Index
    /// authValue, writable with owner authorization, dictionary-attack protected (<c>TPMA_NV_NO_DA</c> clear).
    /// </summary>
    private const TpmaNv GlobalLockAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_GLOBALLOCK;

    /// <summary>The Index authorization value used throughout.</summary>
    private static byte[] IndexAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong authorization value, distinct from every value these tests install.</summary>
    private static byte[] WrongAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>The ownerAuth value installed over the factory-empty one where an installed value is under test.</summary>
    private static byte[] InstalledOwnerAuth { get; } = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5];

    /// <summary>The platformAuth value installed over the factory-empty one where an installed value is under test.</summary>
    private static byte[] InstalledPlatformAuth { get; } = [0x5E, 0x4D, 0x3C, 0x2B, 0x1A];

    /// <summary>The sixteen octets an Ordinary Index is populated with.</summary>
    private static byte[] IndexData { get; } =
        [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];

    /// <summary>
    /// A single-octet payload for a write attempt a lock must refuse; its content is immaterial since the write
    /// never reaches the Index's stored data.
    /// </summary>
    private static byte[] RefusedWriteAttempt { get; } = [0x00];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// "This command requires either platformAuth/platformPolicy or ownerAuth/ownerPolicy" - the owner arm on a
    /// factory-state TPM, whose ownerAuth is the Empty Buffer: the command is authorized and "will SET
    /// TPMA_NV_WRITELOCKED for all indexes that have their TPMA_NV_GLOBALLOCK attribute SET", which the Index's
    /// attribute word reports back.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.12.1; Part 2, clause 9.21, Table 67</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockUnderTheFactoryEmptyOwnerAuthLocks()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvGlobalWriteLockRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The owner arm under the factory-empty ownerAuth must authorize the global write lock: '{result.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "Clause 31.12.1 SETs TPMA_NV_WRITELOCKED on every Index whose TPMA_NV_GLOBALLOCK is SET.");
    }

    /// <summary>
    /// The same owner arm once ownerAuth is a real value: <c>TPM2_HierarchyChangeAuth()</c> "allows the
    /// authorization secret for a hierarchy or lockout to be changed", and the replacement is the value this
    /// command's owner arm must be given - the ladder compares against the live carrier, not the factory one.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.12.1 and 24.8; Part 1, clause 16.6.4.3</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockUnderAnInstalledOwnerAuthLocks()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvGlobalWriteLockRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);
        await InstallHierarchyAuthAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, InstalledOwnerAuth).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, InstalledOwnerAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The installed ownerAuth must authorize the global write lock: '{result.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "An installed ownerAuth authorizes exactly the effect the factory-empty one does.");
    }

    /// <summary>
    /// The other selector Table 67 admits: "This command requires either platformAuth/platformPolicy or
    /// ownerAuth/ownerPolicy" - the platform arm on a factory-state TPM, whose platformAuth is the Empty Buffer,
    /// SETs the same lock bit.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.12.1; Part 2, clause 9.21, Table 67</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockUnderTheFactoryEmptyPlatformAuthLocks()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvGlobalWriteLockRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The platform arm under the factory-empty platformAuth must authorize the global write lock: '{result.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "Either authorization reaches the same transition, so the platform arm SETs the same lock bit.");
    }

    /// <summary>
    /// The platform arm once platformAuth is a real value: platform authorization survives every other
    /// hierarchy's state and is the recovery path, so its own installed secret must authorize this command the
    /// way the installed ownerAuth does.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.12.1 and 24.8; Part 1, clause 16.6.4.3</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockUnderAnInstalledPlatformAuthLocks()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvGlobalWriteLockRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);
        await InstallHierarchyAuthAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, InstalledPlatformAuth).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, InstalledPlatformAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The installed platformAuth must authorize the global write lock: '{result.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "An installed platformAuth authorizes exactly the effect the factory-empty one does.");
    }

    /// <summary>
    /// "The Index will be locked whether the index was defined using Owner Authorization or Platform
    /// Authorization" - an Index defined under Owner Authorization is locked by a command the platform
    /// authorizes, and the lock is real rather than nominal: the Index then refuses <c>TPM2_NV_Write()</c> with
    /// <c>TPM_RC_NV_LOCKED</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.12.1 and 31.7.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockUnderPlatformAuthorizationLocksAnOwnerDefinedIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvGlobalWriteLockRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);

        TpmResult<NvWriteResponse> beforeWrite = await WriteIndexAsync(
            device, pool, registry, GlobalLockIndexHandle, GlobalLockIndexHandle, IndexAuth, IndexData).ConfigureAwait(false);
        Assert.IsTrue(beforeWrite.IsSuccess, $"The owner-defined Index must be writable before the global lock: '{beforeWrite.ResponseCode}'.");

        TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The platform arm must authorize the global write lock: '{result.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "Index locking is independent of the kind of authorization the command carried.");

        TpmResult<NvWriteResponse> afterWrite = await WriteIndexAsync(
            device, pool, registry, GlobalLockIndexHandle, GlobalLockIndexHandle, IndexAuth, RefusedWriteAttempt).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_LOCKED, afterWrite.ResponseCode,
            "A platform-authorized global lock write-locks the owner-defined Index for real, so its next write is TPM_RC_NV_LOCKED.");
    }

    /// <summary>
    /// "The authValue associated with a permanent entity, other than TPM_RH_LOCKOUT, does not receive DA
    /// protection" - a wrong ownerAuth is the plain <c>TPM_RC_BAD_AUTH</c> of a dictionary-attack-exempt entity,
    /// <c>failedTries</c> is untouched (read back over <c>TPM_PT_LOCKOUT_COUNTER</c>), and the refused command
    /// SETs nothing.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 3, clause 31.12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockWithWrongOwnerAuthReturnsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvGlobalWriteLockRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), result.ResponseCode, "The owner hierarchy is DA-exempt, so a wrong value is TPM_RC_BAD_AUTH rather than TPM_RC_AUTH_FAIL.");
        Assert.AreEqual(
            counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "A permanent entity other than TPM_RH_LOCKOUT receives no DA protection, so the refusal charges no failedTries.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED, "A refused command SETs no lock bit.");
    }

    /// <summary>
    /// The same dictionary-attack exemption on the other arm: a wrong platformAuth is <c>TPM_RC_BAD_AUTH</c> with
    /// <c>failedTries</c> untouched, which is what keeps platform authorization usable as the recovery path.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 3, clauses 25.1 and 31.12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockWithWrongPlatformAuthReturnsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvGlobalWriteLockRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), result.ResponseCode, "The platform hierarchy is DA-exempt, so a wrong value is TPM_RC_BAD_AUTH.");
        Assert.AreEqual(
            counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "Platform authorization is categorically exempt from dictionary-attack protection, so the refusal charges no failedTries.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED, "A refused command SETs no lock bit.");
    }

    /// <summary>
    /// "If the handle references a primary seed for a hierarchy (TPM_RH_ENDORSEMENT, TPM_RH_OWNER, or
    /// TPM_RH_PLATFORM) then the enable for the hierarchy is SET (TPM_RC_HIERARCHY)" - with <c>shEnable</c>
    /// CLEARed by <c>TPM2_HierarchyControl()</c> under Platform Authorization, the owner arm is
    /// <c>TPM_RC_HIERARCHY</c> while the platform arm still authorizes the very same command.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.4 and 24.2.1; Part 1, clause 10.2, Table 8</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockWithShEnableClearReturnsHierarchyForTheOwnerArmWhileThePlatformArmLocks()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvGlobalWriteLockRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);
        await DisableHierarchyAsync(device, pool, registry, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> ownerResult = await GlobalWriteLockAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), ownerResult.ResponseCode,
            "A disabled hierarchy's authValue cannot be used to authorize any TPM action, so the owner arm is refused by the availability gate.");

        TpmResult<NvGlobalWriteLockResponse> platformResult = await GlobalWriteLockAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(platformResult.IsSuccess, $"The platform enable is untouched, so its arm must still authorize the command: '{platformResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "The gate binds the authorizing hierarchy, never the effect, so the platform-authorized lock lands in full.");
    }

    /// <summary>
    /// The converse of the same check: with <c>phEnable</c> CLEARed under Platform Authorization ("phEnable may
    /// not be SET using this command", so the CLEAR is one-way until a TPM Reset), the platform arm is
    /// <c>TPM_RC_HIERARCHY</c> while the owner arm still authorizes the command.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.4 and 24.2.1; Part 1, clause 10.2, Table 8</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockWithPhEnableClearReturnsHierarchyForThePlatformArmWhileTheOwnerArmLocks()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvGlobalWriteLockRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);
        await DisableHierarchyAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> platformResult = await GlobalWriteLockAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), platformResult.ResponseCode,
            "platformAuth cannot authorize anything while phEnable is CLEAR, this command included.");

        TpmResult<NvGlobalWriteLockResponse> ownerResult = await GlobalWriteLockAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(ownerResult.IsSuccess, $"The storage enable is untouched, so the owner arm must still authorize the command: '{ownerResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "The owner-authorized lock lands in full while the platform hierarchy is disabled.");
    }

    /// <summary>
    /// The order between the two refusals: clause 5.4's handle checks run ahead of clause 5.6's authorization
    /// checks, so a wrong ownerAuth presented while <c>shEnable</c> is CLEAR is answered <c>TPM_RC_HIERARCHY</c>
    /// by the availability gate and never reaches the value compare that would have answered
    /// <c>TPM_RC_BAD_AUTH</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.4 and 5.6; Part 1, clauses 10.2 and 16.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockWithWrongOwnerAuthUnderADisabledOwnerHierarchyReturnsHierarchyNotBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvGlobalWriteLockRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);
        await DisableHierarchyAsync(device, pool, registry, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), result.ResponseCode, "The enable is judged before the value, so the disabled hierarchy answers first.");
        Assert.AreNotEqual(TpmRcConstants.TPM_RC_BAD_AUTH, result.ResponseCode, "No value compare happens at all once the handle resolves to no usable entity.");
    }

    /// <summary>
    /// <c>@authHandle</c> is a <c>TPMI_RH_PROVISION</c>, whose only values are <c>TPM_RH_OWNER</c> and
    /// <c>TPM_RH_PLATFORM</c>: "Unmarshaling any other value is TPM_RC_VALUE" - the endorsement and lockout
    /// hierarchies, the NULL hierarchy, the platform NV pseudo-hierarchy, a PCR handle, a defined NV Index
    /// handle, a transient-range handle and a session-range handle are each refused with the bare code, ahead of
    /// any enable check and any authorization.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.21, Table 67; Part 3, clause 31.12, Table 263</see>.
    /// </summary>
    /// <param name="authHandle">The inadmissible handle offered as <c>@authHandle</c>.</param>
    [TestMethod]
    [DataRow((uint)TpmRh.TPM_RH_ENDORSEMENT, DisplayName = "TPM_RH_ENDORSEMENT is not a provisioning selector")]
    [DataRow((uint)TpmRh.TPM_RH_LOCKOUT, DisplayName = "TPM_RH_LOCKOUT is not a provisioning selector")]
    [DataRow((uint)TpmRh.TPM_RH_NULL, DisplayName = "TPM_RH_NULL is not a provisioning selector")]
    [DataRow(PlatformNvHandle, DisplayName = "TPM_RH_PLATFORM_NV is not a provisioning selector")]
    [DataRow(PcrHandle, DisplayName = "a PCR handle is not a provisioning selector")]
    [DataRow(SecondaryIndexHandle, DisplayName = "a defined NV Index handle is not a provisioning selector")]
    [DataRow(TransientRangeHandle, DisplayName = "a transient-range handle is not a provisioning selector")]
    [DataRow(SessionRangeHandle, DisplayName = "a session-range handle is not a provisioning selector")]
    public async Task NvGlobalWriteLockWithANonProvisionAuthHandleReturnsValue(uint authHandle)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvGlobalWriteLockRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);
        await DefineIndexAsync(device, pool, registry, SecondaryIndexHandle, GlobalLockAttributes).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockAsync(
            device, pool, registry, (TpmRh)authHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), result.ResponseCode, "TPMI_RH_PROVISION admits TPM_RH_OWNER and TPM_RH_PLATFORM alone.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED, "A handle the interface type refuses runs no part of the command's effect.");
    }

    /// <summary>
    /// "While in Lockout mode, any use of a DA-protected authValue will return TPM_RC_LOCKOUT" gates DA-protected
    /// entities alone, and "the authValue associated with a permanent entity, other than TPM_RH_LOCKOUT, does not
    /// receive DA protection" - so with the TPM driven into Lockout mode by brute-forcing a DA-protected Index's
    /// authValue at a lowered <c>maxTries</c>, the owner arm of this command is untouched and still locks.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.8.1 and 16.8.3; Part 3, clause 31.12.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockUnderTheOwnerArmStillLocksWhileTheTpmIsInLockoutMode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvGlobalWriteLockRegistry();

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);

        for(uint attempt = 1; attempt <= LoweredMaxTries; attempt++)
        {
            TpmResult<NvWriteResponse> wrongResult = await WriteIndexAsync(
                device, pool, registry, GlobalLockIndexHandle, GlobalLockIndexHandle, WrongAuth, RefusedWriteAttempt).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode,
                $"Attempt {attempt} of {LoweredMaxTries} must count as an auth-failure while driving the TPM into Lockout mode.");
        }

        TpmResult<NvWriteResponse> lockedIndexArm = await WriteIndexAsync(
            device, pool, registry, GlobalLockIndexHandle, GlobalLockIndexHandle, IndexAuth, IndexData).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, lockedIndexArm.ResponseCode,
            "The DA-protected Index arm must be refused even with the correct authValue, proving Lockout mode is in force.");

        TpmResult<NvGlobalWriteLockResponse> result = await GlobalWriteLockAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A DA-exempt permanent entity is not gated by Lockout mode: '{result.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED,
            "The owner-authorized lock lands in full while the TPM is in Lockout mode.");
    }

    /// <summary>
    /// The password form returns every carrier its parse rented on each path this command's ladder takes: the
    /// handle refusal at the transition head, the hierarchy refusal at the availability gate, the bad-value
    /// refusal at the compare, and the accepting transition - the metered pool returns to its baseline after
    /// each.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.12, 5.4 and 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockReturnsItsCarriersAcrossRefusalsAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvGlobalWriteLockRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockAttributes).ConfigureAwait(false);
        await DisableHierarchyAsync(device, pool, registry, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<NvGlobalWriteLockResponse> handleRefusal = await GlobalWriteLockAsync(
            device, pool, registry, TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), handleRefusal.ResponseCode, "Table 263: authHandle is TPM2_NV_GlobalWriteLock()'s sole handle (handle 1); a hierarchy handle outside TPM_RH_OWNER/TPM_RH_PLATFORM is handle-encoded TPM_RC_VALUE at index 0.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refusal at the transition head releases the supplied credential through the request's own Dispose.");

        TpmResult<NvGlobalWriteLockResponse> hierarchyRefusal = await GlobalWriteLockAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), hierarchyRefusal.ResponseCode, "Table 263: authHandle is TPM2_NV_GlobalWriteLock()'s sole handle (handle 1); a disabled hierarchy is handle-encoded TPM_RC_HIERARCHY at index 0.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refusal at the availability gate releases the supplied credential through the request's own Dispose.");

        TpmResult<NvGlobalWriteLockResponse> badAuthRefusal = await GlobalWriteLockAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, WrongAuth).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), badAuthRefusal.ResponseCode, "authHandle's authorizing session is session 1 of Table 263 (TPM 2.0 Library Part 2, clause 6.6.2); a wrong platformAuth password is session-encoded TPM_RC_BAD_AUTH there.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refusal at the value compare releases the supplied credential through the request's own Dispose.");

        TpmResult<NvGlobalWriteLockResponse> accepted = await GlobalWriteLockAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(accepted.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{accepted.ResponseCode}'.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The accepting transition is the credential's terminal owner and must release it.");
    }

    /// <summary>Creates a response codec registry for the commands these tests drive.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateNvGlobalWriteLockRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite)
            .Register(TpmCcConstants.TPM_CC_NV_GlobalWriteLock, TpmResponseCodec.NvGlobalWriteLock)
            .Register(TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmResponseCodec.HierarchyChangeAuth)
            .Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl)
            .Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);

    /// <summary>
    /// Issues <c>TPM2_NV_DefineSpace()</c> for <paramref name="nvIndex"/> with <see cref="IndexAuth"/> as the
    /// Index authValue, authorized by the (empty) owner authValue, and asserts the definition succeeded - every
    /// test here starts from a defined Index.
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
        using var auth = Tpm2bAuth.Create(IndexAuth, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, attributes, Tpm2bDigest.Empty, OrdinaryDataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_DefineSpace() failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Issues a password-authorized <c>TPM2_NV_GlobalWriteLock()</c> under <paramref name="authHandle"/>. The
    /// command carries one handle and no parameters, and the authorizing entity is a permanent handle, so the
    /// executor is given no supplied Names (a permanent handle's Name is its own four octets, TPM 2.0 Library
    /// Part 1, clause 13, Table 9).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorizing hierarchy, admissible or not.</param>
    /// <param name="suppliedAuth">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <returns>The global-write-lock result.</returns>
    private async Task<TpmResult<NvGlobalWriteLockResponse>> GlobalWriteLockAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh authHandle, ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var input = new NvGlobalWriteLockInput(authHandle);

        return await TpmCommandExecutor.ExecuteAsync<NvGlobalWriteLockResponse>(
            device, input, [session], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues a password-authorized <c>TPM2_NV_Write()</c> against <paramref name="nvIndex"/> at offset zero.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorization handle.</param>
    /// <param name="nvIndex">The Index to write.</param>
    /// <param name="suppliedAuth">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <param name="data">The octets to store.</param>
    /// <returns>The write result.</returns>
    private async Task<TpmResult<NvWriteResponse>> WriteIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint authHandle, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth,
        ReadOnlyMemory<byte> data)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(data.Span, pool);
        var input = new NvWriteInput(authHandle, nvIndex, buffer, Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Replaces <paramref name="hierarchy"/>'s authorization value through a password-authorized
    /// <c>TPM2_HierarchyChangeAuth()</c>, asserting the rotation succeeded - the way an installed ownerAuth or
    /// platformAuth is put in place before this command's arms are exercised against it.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="hierarchy">The hierarchy whose authorization value is replaced.</param>
    /// <param name="currentAuth">The hierarchy's current authorization value.</param>
    /// <param name="newAuth">The replacement authorization value.</param>
    private async Task InstallHierarchyAuthAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh hierarchy, ReadOnlyMemory<byte> currentAuth,
        ReadOnlyMemory<byte> newAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(currentAuth.Span, pool);

        //The input takes ownership of the replacement carrier and disposes it; the redundant using local
        //satisfies CA2000 and is safe because the carrier's disposal is idempotent.
        using var replacement = Tpm2bAuth.Create(newAuth.Span, pool);
        using var input = new HierarchyChangeAuthInput(hierarchy, replacement);

        TpmResult<HierarchyChangeAuthResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyChangeAuthResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HierarchyChangeAuth() on '{hierarchy}' failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// CLEARs <paramref name="hierarchy"/>'s enable through a password-authorized <c>TPM2_HierarchyControl()</c>
    /// under Platform Authorization, asserting the write succeeded - Platform Authorization may CLEAR any enable
    /// including its own (TPM 2.0 Library Part 3, clause 24.2.1).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="hierarchy">The hierarchy whose enable is CLEARed.</param>
    private async Task DisableHierarchyAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh hierarchy)
    {
        using TpmPasswordSession session = TpmPasswordSession.CreateEmpty(pool);
        var input = new HierarchyControlInput(TpmRh.TPM_RH_PLATFORM, hierarchy, TpmiYesNo.No);

        TpmResult<HierarchyControlResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyControlResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HierarchyControl() disabling '{hierarchy}' failed: '{result.ResponseCode}'.");
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
        Assert.IsTrue(publicResult.IsSuccess, $"NvReadPublicAsync failed: '{publicResult.ResponseCode}'.");

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

    /// <summary>
    /// Frames <c>TPM2_Startup()</c> - a sessionless command (<c>TPM_ST_NO_SESSIONS</c>) - directly to the
    /// simulator and returns its response code.
    /// </summary>
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
    /// phase, which is the precondition <c>TPM2_NV_GlobalWriteLock()</c> carries.
    /// </summary>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync()
    {
        var simulator = new TpmSimulator("tpm-in-house-nv-global-writelock-authorization", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitStartupAsync(simulator, BaseMemoryPool.Shared, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false),
            "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
