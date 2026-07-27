using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the NV Counter Index machinery — <c>TPM2_NV_Increment()</c>'s authorization ladder, the
/// <c>TPM_NT_COUNTER</c> type gate on both <c>TPM2_NV_Increment()</c> and <c>TPM2_NV_Write()</c>,
/// <c>TPM2_NV_DefineSpace()</c>'s counter-related tightening (<c>dataSize</c>, <c>TPMA_NV_CLEAR_STCLEAR</c>,
/// and the BITS/EXTEND unsupported-modifier gate), and the phantom-counter rollback protection across
/// <c>TPM2_NV_UndefineSpace()</c>/redefine — against the in-house behavioural <see cref="TpmSimulator"/>,
/// entirely in-process with no external assets, through the same production command path the production code
/// uses (<see cref="TpmCommandExecutor"/> and the real command/response codecs). TPM 2.0 Library Part 1,
/// clause 37.2.6.3; Part 3, clauses 31.3.1, 31.7.1, 31.8.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorNvCounterTests
{
    /// <summary>The declared data size (octets) of every Counter Index this file defines.</summary>
    private const ushort CounterDataSize = 8;

    /// <summary>The primary Counter Index handle: its most-significant octet is TPM_HT_NV_INDEX (0x01).</summary>
    private const uint CounterIndexHandle = 0x0100_0041;

    /// <summary>A second Counter Index handle, distinct from <see cref="CounterIndexHandle"/>.</summary>
    private const uint SecondCounterIndexHandle = 0x0100_0042;

    /// <summary>An Ordinary Index handle, used to prove <c>TPM2_NV_Increment()</c> refuses a non-Counter type.</summary>
    private const uint OrdinaryIndexHandle = 0x0100_0043;

    /// <summary>A Bit Field Index handle, used only for the define-time rejection test.</summary>
    private const uint BitsIndexHandle = 0x0100_0044;

    /// <summary>An Extend Index handle, used only for the define-time rejection test.</summary>
    private const uint ExtendIndexHandle = 0x0100_0045;

    /// <summary>An <c>authHandle</c> that is neither the owner hierarchy nor any Index defined in this file.</summary>
    private const uint MismatchedAuthHandle = 0x0100_0099;

    /// <summary>The lowered <c>maxTries</c> used by the lockout test to reach Lockout mode quickly.</summary>
    private const uint LoweredMaxTries = 2;

    /// <summary>
    /// Counter attributes that authorize read/increment with the Index authValue and increment with owner
    /// authorization, dictionary-attack protected (<c>TPMA_NV_NO_DA</c> clear).
    /// </summary>
    private const TpmaNv CounterAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE
        | (TpmaNv)((uint)TpmNt.TPM_NT_COUNTER << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>The same Counter attributes, opted out of dictionary-attack protection.</summary>
    private const TpmaNv NonDaCounterAttributes = CounterAttributes | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>Counter attributes deliberately missing <c>TPMA_NV_OWNERWRITE</c>.</summary>
    private const TpmaNv CounterWithoutOwnerWriteAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE
        | (TpmaNv)((uint)TpmNt.TPM_NT_COUNTER << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>Counter attributes deliberately missing <c>TPMA_NV_AUTHWRITE</c>.</summary>
    private const TpmaNv CounterWithoutAuthWriteAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERWRITE
        | (TpmaNv)((uint)TpmNt.TPM_NT_COUNTER << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>Counter attributes with the illegal combination <c>TPMA_NV_CLEAR_STCLEAR</c> SET.</summary>
    private const TpmaNv ClearStclearCounterAttributes = CounterAttributes | TpmaNv.TPMA_NV_CLEAR_STCLEAR;

    /// <summary>Ordinary Index attributes (TPM_NT_ORDINARY is the zero value, so no type shift is needed).</summary>
    private const TpmaNv OrdinaryAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE;

    /// <summary>Bit Field Index attributes, used only to prove <c>TPM2_NV_DefineSpace()</c> now refuses the type.</summary>
    private const TpmaNv BitsAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE
        | (TpmaNv)((uint)TpmNt.TPM_NT_BITS << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>Extend Index attributes, used only to prove <c>TPM2_NV_DefineSpace()</c> now refuses the type.</summary>
    private const TpmaNv ExtendAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE
        | (TpmaNv)((uint)TpmNt.TPM_NT_EXTEND << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>The Index authorization value (and, for owner-arm calls, an alias for "the correct value") used throughout.</summary>
    private static byte[] CorrectAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong Index authorization value, distinct from <see cref="CorrectAuth"/>.</summary>
    private static byte[] WrongAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>
    /// A single-octet payload for a rejected-arm <c>TPM2_NV_Write()</c> attempt; its content is immaterial
    /// since the write must never reach the Index's stored data.
    /// </summary>
    private static byte[] RejectedWriteAttempt { get; } = [0x00];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>Verifies <c>TPM2_NV_Increment()</c> against an undefined handle answers <c>TPM_RC_HANDLE</c>.</summary>
    [TestMethod]
    public async Task NvIncrementOfUndefinedIndexReturnsHandle()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvIncrementResponse> result = await IncrementAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, result.ResponseCode);
    }

    /// <summary>
    /// Verifies repeated wrong-authValue index-arm increments against a DA-protected Counter Index increment
    /// <c>FailedTries</c>, and that the TPM enters Lockout mode exactly at the (lowered) <c>maxTries</c>,
    /// rejecting even the correct authValue thereafter (TPM 2.0 Library Part 1, clause 17.8.3), mirroring
    /// <c>TpmInHouseSimulatorDictionaryAttackTests</c>' own lockout-loop pattern.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementBruteForceLocksOutAtMaxTries()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        for(uint attempt = 1; attempt <= LoweredMaxTries; attempt++)
        {
            TpmResult<NvIncrementResponse> wrongResult = await IncrementAsync(
                device, pool, registry, CounterIndexHandle, CounterIndexHandle, WrongAuth).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_FAIL, wrongResult.ResponseCode,
                $"Attempt {attempt} of {LoweredMaxTries} must count as an auth-failure, not yet Lockout mode.");
        }

        TpmResult<NvIncrementResponse> lockedResult = await IncrementAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, lockedResult.ResponseCode,
            "Once failedTries reaches maxTries, further attempts must reject with TPM_RC_LOCKOUT, even with the correct authValue.");
    }

    /// <summary>
    /// Verifies the owner-authorized increment arm stays available while the TPM is in Lockout mode: the
    /// clause 5.6 lockout gate binds the entity whose authValue is compared, and on this arm that entity is
    /// the owner hierarchy (never dictionary-attack protected, TPM 2.0 Library Part 1, clause 17.8.1), not the
    /// DA-protected Index - the same administrative posture <c>TPM2_NV_Write()</c>'s owner arm takes.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOwnerArmSucceedsDuringLockout()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        for(uint attempt = 1; attempt <= LoweredMaxTries; attempt++)
        {
            TpmResult<NvIncrementResponse> wrongResult = await IncrementAsync(
                device, pool, registry, CounterIndexHandle, CounterIndexHandle, WrongAuth).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_FAIL, wrongResult.ResponseCode,
                $"Attempt {attempt} of {LoweredMaxTries} must count as an auth-failure while driving the TPM into Lockout mode.");
        }

        TpmResult<NvIncrementResponse> lockedIndexArmResult = await IncrementAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, lockedIndexArmResult.ResponseCode,
            "The index-authValue arm must be refused while the TPM is in Lockout mode, proving lockout is in force.");

        TpmResult<NvIncrementResponse> ownerArmResult = await IncrementAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, CounterIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(
            ownerArmResult.IsSuccess,
            $"The owner-authorized administrative arm must stay available during lockout, since it authorizes the owner hierarchy, not the DA-protected Index: '{ownerArmResult.ResponseCode}'.");
    }

    /// <summary>
    /// Verifies the owner-authorized increment arm honors <c>TPMA_NV_OWNERWRITE</c>: an Index whose
    /// <c>TPMA_NV_OWNERWRITE</c> is clear rejects an owner-authorized increment with
    /// <c>TPM_RC_NV_AUTHORIZATION</c> even under a correct (here, empty) owner authorization - the gate runs
    /// before the compare (TPM 2.0 Library Part 2, clause 13.4).
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOwnerArmWithoutOwnerWriteReturnsAuthorization()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterWithoutOwnerWriteAttributes).ConfigureAwait(false);

        TpmResult<NvIncrementResponse> result = await IncrementAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, CounterIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode);
    }

    /// <summary>
    /// Verifies an <c>authHandle</c> that is neither the owner hierarchy nor the Index itself is refused with
    /// <c>TPM_RC_NV_AUTHORIZATION</c> (TPM 2.0 Library Part 3, clause 31.1) - only those two arms are modelled.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementWithMismatchedAuthHandleReturnsAuthorization()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        TpmResult<NvIncrementResponse> result = await IncrementAsync(
            device, pool, registry, MismatchedAuthHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode);
    }

    /// <summary>
    /// Verifies the index-authValue increment arm honors <c>TPMA_NV_AUTHWRITE</c>: with the bit clear the
    /// Index authValue cannot authorize an increment even when it matches (TPM 2.0 Library Part 2, clause
    /// 13.4) - the gate runs before the compare.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementIndexArmWithoutAuthWriteReturnsAuthorization()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterWithoutAuthWriteAttributes).ConfigureAwait(false);

        TpmResult<NvIncrementResponse> result = await IncrementAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode,
            "With TPMA_NV_AUTHWRITE clear the Index authValue cannot authorize an increment, even when it matches.");
    }

    /// <summary>
    /// Verifies a wrong index-arm authValue against a DA-protected Counter Index is an auth-failure (TPM 2.0
    /// Library Part 1, clause 17.8.3), the DA half of the DA/NO_DA contrast this ladder must preserve.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementWithWrongAuthOnDaProtectedIndexReturnsAuthFail()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        TpmResult<NvIncrementResponse> result = await IncrementAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, result.ResponseCode);
    }

    /// <summary>
    /// Verifies a wrong index-arm authValue against a <c>TPMA_NV_NO_DA</c> Counter Index is a plain
    /// bad-authorization (TPM 2.0 Library Part 1, clause 17.8.1) - <c>TPMA_NV_NO_DA</c> applies uniformly,
    /// with no counter-type carve-out (SPEC §5.1), the NO_DA half of the DA/NO_DA contrast.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementWithWrongAuthOnNonDaIndexReturnsBadAuth()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, NonDaCounterAttributes).ConfigureAwait(false);

        TpmResult<NvIncrementResponse> result = await IncrementAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, result.ResponseCode);
    }

    /// <summary>
    /// Verifies <c>TPM2_NV_Increment()</c> refuses a successfully-authorized but non-Counter Index with
    /// <c>TPM_RC_ATTRIBUTES</c> (TPM 2.0 Library Part 3, clause 31.8.1).
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOfOrdinaryIndexReturnsAttributes()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, OrdinaryIndexHandle, OrdinaryAttributes).ConfigureAwait(false);

        TpmResult<NvIncrementResponse> result = await IncrementAsync(
            device, pool, registry, OrdinaryIndexHandle, OrdinaryIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode,
            "TPM2_NV_Increment() must refuse a non-Counter Index once authorization has already succeeded.");
    }

    /// <summary>
    /// Regression test for the pre-wave defect <c>TpmLifecycleTransitions</c>' remarks flagged: a Counter
    /// Index accepted an ordinary <c>TPM2_NV_Write()</c> before this wave. Pins the corrected rejection (TPM
    /// 2.0 Library Part 3, clause 31.7.1: the four update commands partition NV Index types).
    /// </summary>
    [TestMethod]
    public async Task NvWriteOfCounterIndexReturnsAttributes()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        TpmResult<NvWriteResponse> result = await WriteIndexAuthValueAsync(
            device, pool, registry, CounterIndexHandle, CorrectAuth, RejectedWriteAttempt).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode,
            "TPM2_NV_Write() must refuse a Counter Index once authorization has already succeeded - only TPM2_NV_Increment() may modify it.");
    }

    /// <summary>
    /// Verifies <c>TPM2_NV_DefineSpace()</c> rejects a Counter Index whose declared <c>dataSize</c> is not
    /// eight octets with <c>TPM_RC_SIZE</c> - the corrected response per the Part 3, clause 31.3.1 NOTE 2
    /// erratum, not <c>TPM_RC_ATTRIBUTES</c>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOfCounterWithWrongDataSizeReturnsSize()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, CounterIndexHandle, CounterAttributes, dataSize: 4).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, result.ResponseCode);
    }

    /// <summary>
    /// Verifies the phantom high-water mark is TPM-GLOBAL, not per-handle: a Counter Index defined at a
    /// DIFFERENT handle after another counter was deleted still seeds its first increment above that deleted
    /// counter's last value. The specification describes exactly this scope - the mark tracks "the largest
    /// count of any deleted NV Counter" (TPM 2.0 Library Part 1, clause 37.2.6.3 NOTE 2/NOTE 6), so a fresh
    /// counter's first value reflects the TPM's counter history rather than starting at one.
    /// </summary>
    [TestMethod]
    public async Task PhantomHighWaterMarkSeedsACounterDefinedAtADifferentHandle()
    {
        const int IncrementsBeforeDelete = 4;

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        for(int i = 0; i < IncrementsBeforeDelete; i++)
        {
            TpmResult<NvIncrementResponse> seedingResult = await IncrementAsync(
                device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
            Assert.IsTrue(seedingResult.IsSuccess, $"Seeding increment {i + 1} must succeed: '{seedingResult.ResponseCode}'.");
        }

        TpmResult<NvUndefineSpaceResponse> undefineResult = await UndefineIndexAsync(device, pool, registry, CounterIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(undefineResult.IsSuccess, $"Undefine must succeed: '{undefineResult.ResponseCode}'.");

        await DefineIndexAsync(device, pool, registry, SecondCounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        TpmResult<NvIncrementResponse> firstIncrementOfSecond = await IncrementAsync(
            device, pool, registry, SecondCounterIndexHandle, SecondCounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(firstIncrementOfSecond.IsSuccess, $"The first increment of the second counter must succeed: '{firstIncrementOfSecond.ResponseCode}'.");

        TpmResult<NvReadResponse> readResult = await ReadCounterAsync(device, pool, registry, SecondCounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(readResult.IsSuccess, $"The read-back must succeed: '{readResult.ResponseCode}'.");

        using NvReadResponse response = readResult.Value;
        Assert.AreEqual(
            (ulong)IncrementsBeforeDelete + 1, BinaryPrimitives.ReadUInt64BigEndian(response.Data),
            "A counter at a different handle must still seed one past the highest value any deleted counter held.");
    }

    /// <summary>
    /// Verifies <c>TPM2_NV_DefineSpace()</c> rejects a definition that arrives already claiming any of the
    /// three TPM-maintained status attributes: "The TPM shall return TPM_RC_ATTRIBUTES if TPMA_NV_WRITTEN,
    /// TPMA_NV_READLOCKED, or TPMA_NV_WRITELOCKED is SET" (TPM 2.0 Library Part 3, clause 31.3.1).
    /// </summary>
    /// <param name="forgedStatusAttribute">The TPM-maintained status attribute the definition wrongly claims.</param>
    [TestMethod]
    [DataRow((uint)TpmaNv.TPMA_NV_WRITTEN, DisplayName = "TPMA_NV_WRITTEN")]
    [DataRow((uint)TpmaNv.TPMA_NV_READLOCKED, DisplayName = "TPMA_NV_READLOCKED")]
    [DataRow((uint)TpmaNv.TPMA_NV_WRITELOCKED, DisplayName = "TPMA_NV_WRITELOCKED")]
    public async Task NvDefineSpaceWithCallerSuppliedStatusAttributeReturnsAttributes(uint forgedStatusAttribute)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, CounterIndexHandle, CounterAttributes | (TpmaNv)forgedStatusAttribute).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode,
            "A status attribute the TPM alone maintains must never be accepted from the caller at definition.");
    }

    /// <summary>
    /// The rollback exploit that motivated the status-attribute gate above, as a regression test: a caller who
    /// could define a redefined Counter Index with <c>TPMA_NV_WRITTEN</c> already SET would make
    /// <c>TPM2_NV_Increment()</c> read the empty data area as counter value zero and restart the count from
    /// one instead of seeding from the phantom high-water mark, rolling a counter with this Name back below a
    /// value it had already reported (TPM 2.0 Library Part 1, clause 37.2.6.3 NOTE 4 forbids exactly that).
    /// The definition is refused, so the rollback is unreachable and the surviving counter keeps its history.
    /// </summary>
    [TestMethod]
    public async Task RedefiningWithForgedWrittenAttributeCannotRollACounterBack()
    {
        const int IncrementsBeforeDelete = 3;

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        for(int i = 0; i < IncrementsBeforeDelete; i++)
        {
            TpmResult<NvIncrementResponse> seedingResult = await IncrementAsync(
                device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
            Assert.IsTrue(seedingResult.IsSuccess, $"Seeding increment {i + 1} must succeed: '{seedingResult.ResponseCode}'.");
        }

        TpmResult<NvUndefineSpaceResponse> undefineResult = await UndefineIndexAsync(device, pool, registry, CounterIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(undefineResult.IsSuccess, $"Undefine must succeed: '{undefineResult.ResponseCode}'.");

        TpmResult<NvDefineSpaceResponse> forgedRedefineResult = await DefineIndexAsync(
            device, pool, registry, CounterIndexHandle, CounterAttributes | TpmaNv.TPMA_NV_WRITTEN).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, forgedRedefineResult.ResponseCode,
            "A redefinition claiming TPMA_NV_WRITTEN must be refused - accepting it would bypass the phantom high-water seed.");

        TpmResult<NvDefineSpaceResponse> honestRedefineResult = await DefineIndexAsync(
            device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);
        Assert.IsTrue(honestRedefineResult.IsSuccess, $"An honest redefinition must still succeed: '{honestRedefineResult.ResponseCode}'.");

        TpmResult<NvIncrementResponse> firstIncrementAfterRedefine = await IncrementAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(firstIncrementAfterRedefine.IsSuccess, $"The first increment after redefine must succeed: '{firstIncrementAfterRedefine.ResponseCode}'.");

        TpmResult<NvReadResponse> readResult = await ReadCounterAsync(device, pool, registry, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(readResult.IsSuccess, $"The read-back must succeed: '{readResult.ResponseCode}'.");

        using NvReadResponse response = readResult.Value;
        Assert.IsGreaterThan(
            (ulong)IncrementsBeforeDelete, BinaryPrimitives.ReadUInt64BigEndian(response.Data),
            "The redefined counter must still seed above the deleted counter's last value.");
    }

    /// <summary>
    /// Verifies <c>TPM2_NV_DefineSpace()</c> rejects a Counter Index with <c>TPMA_NV_CLEAR_STCLEAR</c> SET
    /// (TPM 2.0 Library Part 3, clause 31.3.1; Part 2, Table 214; Part 1, clause 37.2.4.2 NOTE) - a counter is
    /// either restored on an orderly startup or advanced on a non-orderly one, never cleared by a Reset/Restart.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOfCounterWithClearStClearReturnsAttributes()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, CounterIndexHandle, ClearStclearCounterAttributes).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode);
    }

    /// <summary>
    /// Verifies <c>TPM2_NV_DefineSpace()</c> now rejects <c>TPM_NT_BITS</c> (TPM 2.0 Library Part 3, clause
    /// 31.3.1's unsupported-command gate: a TPM that does not implement a type's modifying command,
    /// <c>TPM2_NV_SetBits()</c> here, must refuse the type at definition).
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOfBitsIndexReturnsAttributes()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode);
    }

    /// <summary>
    /// Verifies <c>TPM2_NV_DefineSpace()</c> now rejects <c>TPM_NT_EXTEND</c> (TPM 2.0 Library Part 3, clause
    /// 31.3.1's unsupported-command gate: a TPM that does not implement a type's modifying command,
    /// <c>TPM2_NV_Extend()</c> here, must refuse the type at definition).
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOfExtendIndexReturnsAttributes()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode);
    }

    /// <summary>
    /// Verifies a read of an unwritten Counter Index answers <c>TPM_RC_NV_UNINITIALIZED</c> exactly as any
    /// other unwritten Index (TPM 2.0 Library Part 3, clause 31.13.1) - the contrast
    /// <c>TPM2_NV_Increment()</c> itself never exhibits (see
    /// <see cref="NvIncrementOfUnwrittenCounterSucceedsAndReadBackIsOneBigEndian"/>).
    /// </summary>
    [TestMethod]
    public async Task NvReadOfCounterBeforeFirstIncrementReturnsUninitialized()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        TpmResult<NvReadResponse> result = await ReadCounterAsync(device, pool, registry, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_UNINITIALIZED, result.ResponseCode);
    }

    /// <summary>
    /// Verifies the first <c>TPM2_NV_Increment()</c> of a counter that has never existed before succeeds
    /// (never <c>TPM_RC_NV_UNINITIALIZED</c> - TPM 2.0 Library Part 3, clause 31.8.1's explicit non-error),
    /// sets <c>TPMA_NV_WRITTEN</c> (a subsequent read now succeeds), and stores exactly <c>1</c> as 8
    /// big-endian octets (TPM 2.0 Library Part 2, clause 13.2).
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOfUnwrittenCounterSucceedsAndReadBackIsOneBigEndian()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        TpmResult<NvIncrementResponse> incrementResult = await IncrementAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(incrementResult.IsSuccess, $"The first increment of an unwritten counter must succeed: '{incrementResult.ResponseCode}'.");

        TpmResult<NvReadResponse> readResult = await ReadCounterAsync(device, pool, registry, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(readResult.IsSuccess, $"A read after the first increment must succeed, since TPMA_NV_WRITTEN is now SET: '{readResult.ResponseCode}'.");

        using NvReadResponse response = readResult.Value;
        Assert.AreEqual(CounterDataSize, (ushort)response.Data.Length, "The counter's data area must be exactly 8 octets.");
        Assert.AreEqual(
            1ul, BinaryPrimitives.ReadUInt64BigEndian(response.Data),
            "The first increment of a counter that has never existed before must produce exactly 1, stored big-endian.");
    }

    /// <summary>
    /// Verifies a run of increments against the same Counter Index reads back strictly monotonically -
    /// exactly the run index each time, proving the stored value (not a re-derived one) drives each successive
    /// increment.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementRunIsMonotonicallyIncreasing()
    {
        const int IncrementCount = 5;

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        for(ulong expected = 1; expected <= IncrementCount; expected++)
        {
            TpmResult<NvIncrementResponse> incrementResult = await IncrementAsync(
                device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
            Assert.IsTrue(incrementResult.IsSuccess, $"Increment {expected} of {IncrementCount} must succeed: '{incrementResult.ResponseCode}'.");

            TpmResult<NvReadResponse> readResult = await ReadCounterAsync(device, pool, registry, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
            Assert.IsTrue(readResult.IsSuccess, $"The read-back after increment {expected} must succeed: '{readResult.ResponseCode}'.");

            using NvReadResponse response = readResult.Value;
            Assert.AreEqual(
                expected, BinaryPrimitives.ReadUInt64BigEndian(response.Data),
                $"After {expected} increments the counter must read back exactly {expected}.");
        }
    }

    /// <summary>
    /// The wave's flagship rollback-protection positive: increments a Counter Index to a known value,
    /// undefines it, redefines the same handle, and verifies the first increment of the redefined Index seeds
    /// strictly above (exactly one past) the deleted counter's last value - the phantom high-water mark (TPM
    /// 2.0 Library Part 1, clause 37.2.6.3 NOTE 2/NOTE 6) proving delete-then-redefine can never roll a
    /// counter with this Name back.
    /// </summary>
    [TestMethod]
    public async Task RedefiningAHandleAfterUndefineSeedsExactlyOnePastTheDeletedCountersValue()
    {
        const int IncrementsBeforeDelete = 3;

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        for(int i = 0; i < IncrementsBeforeDelete; i++)
        {
            TpmResult<NvIncrementResponse> seedingResult = await IncrementAsync(
                device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
            Assert.IsTrue(seedingResult.IsSuccess, $"Seeding increment {i + 1} must succeed: '{seedingResult.ResponseCode}'.");
        }

        TpmResult<NvUndefineSpaceResponse> undefineResult = await UndefineIndexAsync(device, pool, registry, CounterIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(undefineResult.IsSuccess, $"Undefine must succeed: '{undefineResult.ResponseCode}'.");

        TpmResult<NvDefineSpaceResponse> redefineResult = await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);
        Assert.IsTrue(redefineResult.IsSuccess, $"Redefine of the same handle must succeed: '{redefineResult.ResponseCode}'.");

        TpmResult<NvIncrementResponse> firstIncrementAfterRedefine = await IncrementAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(firstIncrementAfterRedefine.IsSuccess, $"The first increment after redefine must succeed: '{firstIncrementAfterRedefine.ResponseCode}'.");

        TpmResult<NvReadResponse> readResult = await ReadCounterAsync(device, pool, registry, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(readResult.IsSuccess, $"The read-back must succeed: '{readResult.ResponseCode}'.");

        using NvReadResponse response = readResult.Value;
        ulong valueAfterRedefine = BinaryPrimitives.ReadUInt64BigEndian(response.Data);

        Assert.IsGreaterThan(
            (ulong)IncrementsBeforeDelete, valueAfterRedefine,
            $"The redefined counter's first increment ({valueAfterRedefine}) must exceed the deleted counter's last value ({IncrementsBeforeDelete}).");
        Assert.AreEqual(
            (ulong)IncrementsBeforeDelete + 1, valueAfterRedefine,
            "The phantom high-water mark must seed the redefined counter's first increment at exactly one past the deleted counter's last value.");
    }

    /// <summary>Creates a response codec registry for the NV commands these tests drive.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateNvRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite)
            .Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Increment, TpmResponseCodec.NvIncrement);

    /// <summary>
    /// Issues <c>TPM2_NV_DefineSpace()</c> for <paramref name="nvIndex"/> with <see cref="CorrectAuth"/> as the
    /// Index authValue, authorized by the (empty) owner authValue.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    /// <param name="dataSize">The declared data area size; defaults to <see cref="CounterDataSize"/>.</param>
    /// <returns>The define-space result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineIndexAsync(
        TpmDevice device, MemoryPool<byte> pool, TpmResponseRegistry registry, uint nvIndex, TpmaNv attributes, ushort dataSize = CounterDataSize)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);

        //The input takes ownership of the auth value and public area and disposes them; the redundant using
        //locals satisfy CA2000 and are safe because both types have idempotent disposal.
        using var auth = Tpm2bAuth.Create(CorrectAuth, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, attributes, Tpm2bDigest.Empty, dataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues <c>TPM2_NV_Increment()</c> against <paramref name="nvIndex"/> authorized by <paramref name="authHandle"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorization handle (the Index itself, the owner hierarchy, or a mismatched value).</param>
    /// <param name="nvIndex">The Counter Index to increment.</param>
    /// <param name="suppliedAuth">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <returns>The increment result.</returns>
    private async Task<TpmResult<NvIncrementResponse>> IncrementAsync(
        TpmDevice device, MemoryPool<byte> pool, TpmResponseRegistry registry, uint authHandle, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var incrementInput = new NvIncrementInput(authHandle, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
            device, incrementInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues <c>TPM2_NV_Read()</c> against <paramref name="nvIndex"/> for the full 8-octet counter window, authorized by Index authValue.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to read.</param>
    /// <param name="suppliedAuth">The authValue supplied for the Index.</param>
    /// <returns>The read result; on success, the caller owns and must dispose <see cref="TpmResult{T}.Value"/>.</returns>
    private async Task<TpmResult<NvReadResponse>> ReadCounterAsync(
        TpmDevice device, MemoryPool<byte> pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var readInput = new NvReadInput(AuthHandle: nvIndex, NvIndex: nvIndex, Size: CounterDataSize, Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues an index-authValue <c>TPM2_NV_Write()</c> against <paramref name="nvIndex"/>, used only to
    /// exercise the counter-type rejection: the write must never reach the Index's stored data.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to write.</param>
    /// <param name="suppliedAuth">The authValue supplied for the Index.</param>
    /// <param name="data">The octets to attempt to write.</param>
    /// <returns>The write result.</returns>
    private async Task<TpmResult<NvWriteResponse>> WriteIndexAuthValueAsync(
        TpmDevice device, MemoryPool<byte> pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, byte[] data)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var writeInput = new NvWriteInput(nvIndex, nvIndex, new Tpm2bMaxBuffer(data), Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, writeInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues an owner-authorized <c>TPM2_NV_UndefineSpace()</c> against <paramref name="nvIndex"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to undefine.</param>
    /// <returns>The undefine result.</returns>
    private async Task<TpmResult<NvUndefineSpaceResponse>> UndefineIndexAsync(
        TpmDevice device, MemoryPool<byte> pool, TpmResponseRegistry registry, uint nvIndex)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        var undefineInput = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            device, undefineInput, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the
    /// operational phase.
    /// </summary>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync()
    {
        var simulator = new TpmSimulator("tpm-in-house-nv-counter");
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed at the transport level.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
