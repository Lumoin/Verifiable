using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
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
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the NV Counter Index machinery — <c>TPM2_NV_Increment()</c>'s authorization ladder, the
/// <c>TPM_NT_COUNTER</c> type gate on both <c>TPM2_NV_Increment()</c> and <c>TPM2_NV_Write()</c>,
/// <c>TPM2_NV_DefineSpace()</c>'s counter-related tightening (<c>dataSize</c>, <c>TPMA_NV_CLEAR_STCLEAR</c>,
/// and the BITS unsupported-modifier gate), and the phantom-counter rollback protection across
/// <c>TPM2_NV_UndefineSpace()</c>/redefine — against the in-house behavioural <see cref="TpmSimulator"/>,
/// entirely in-process with no external assets, through the same production command path the production code
/// uses (<see cref="TpmCommandExecutor"/> and the real command/response codecs). TPM 2.0 Library Part 1,
/// clause 34.2.6.3; Part 3, clauses 31.3.1, 31.7.1, 31.8.
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

    /// <summary>An <c>authHandle</c> that is neither the owner hierarchy nor any Index defined in this file.</summary>
    private const uint MismatchedAuthHandle = 0x0100_0099;

    /// <summary>The lowered <c>maxTries</c> used by the lockout test to reach Lockout mode quickly.</summary>
    private const uint LoweredMaxTries = 2;

    /// <summary>The hash algorithm for every HMAC-arm session these tests compose.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// The SHA-256 digest width, in octets - the output length of the cpHash the hand-framed decrypt/encrypt
    /// tests compute independently of <see cref="TpmCommandExecutor"/>.
    /// </summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The RSA public exponent the framework RSA key generator uses (TPM 2.0 Library Part 2, Table 228).</summary>
    private const uint DefaultRsaExponent = 65537;

    /// <summary>The Name algorithm of the RSA endorsement-key-shaped decrypt key the salted-session tests build.</summary>
    private const TpmAlgIdConstants RsaKeyNameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvIncrementResponse> result = await IncrementAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), result.ResponseCode, "Table 255: nvIndex is TPM2_NV_Increment()'s second handle (handle 2); an undefined Index is handle-encoded TPM_RC_HANDLE at index 1.");
    }

    /// <summary>
    /// Verifies repeated wrong-authValue index-arm increments against a DA-protected Counter Index increment
    /// <c>FailedTries</c>, and that the TPM enters Lockout mode exactly at the (lowered) <c>maxTries</c>,
    /// rejecting even the correct authValue thereafter (TPM 2.0 Library Part 1, clause 16.8.3), mirroring
    /// <c>TpmInHouseSimulatorDictionaryAttackTests</c>' own lockout-loop pattern.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementBruteForceLocksOutAtMaxTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode,
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
    /// the owner hierarchy (never dictionary-attack protected, TPM 2.0 Library Part 1, clause 16.8.1), not the
    /// DA-protected Index - the same administrative posture <c>TPM2_NV_Write()</c>'s owner arm takes.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOwnerArmSucceedsDuringLockout()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode,
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        TpmResult<NvIncrementResponse> result = await IncrementAsync(
            device, pool, registry, MismatchedAuthHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode);
    }

    /// <summary>
    /// Verifies the index-authValue increment arm honors <c>TPMA_NV_AUTHWRITE</c>: with the bit clear the
    /// Index authValue is not an available authorization mechanism for an increment at all, so the attempt is
    /// refused before the compare with <c>TPM_RC_AUTH_UNAVAILABLE</c> even when the value matches (TPM 2.0
    /// Library Part 3, clause 5.6 check 7.2.2).
    /// </summary>
    [TestMethod]
    public async Task NvIncrementIndexArmWithoutAuthWriteReturnsAuthUnavailable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterWithoutAuthWriteAttributes).ConfigureAwait(false);

        TpmResult<NvIncrementResponse> result = await IncrementAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, result.ResponseCode,
            "With TPMA_NV_AUTHWRITE clear the Index authValue cannot authorize an increment, even when it matches.");
    }

    /// <summary>
    /// Verifies a wrong index-arm authValue against a DA-protected Counter Index is an auth-failure (TPM 2.0
    /// Library Part 1, clause 16.8.3), the DA half of the DA/NO_DA contrast this ladder must preserve.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementWithWrongAuthOnDaProtectedIndexReturnsAuthFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        TpmResult<NvIncrementResponse> result = await IncrementAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), result.ResponseCode, "authHandle's authorizing session is session 1 of Table 255 (TPM 2.0 Library Part 2, clause 6.6.2); a wrong authValue on a DA-protected Index is session-encoded TPM_RC_AUTH_FAIL there.");
    }

    /// <summary>
    /// Verifies a wrong index-arm authValue against a <c>TPMA_NV_NO_DA</c> Counter Index is a plain
    /// bad-authorization (TPM 2.0 Library Part 1, clause 16.8.1) - <c>TPMA_NV_NO_DA</c> applies uniformly,
    /// with no counter-type carve-out (TPM 2.0 Library Part 2, clause 13.4's <c>TPMA_NV_NO_DA</c> bit:
    /// "Authorization failures of the Index do not affect the DA logic and authorization of the Index is not
    /// blocked when the TPM is in Lockout mode."), the NO_DA half of the DA/NO_DA contrast.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementWithWrongAuthOnNonDaIndexReturnsBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, NonDaCounterAttributes).ConfigureAwait(false);

        TpmResult<NvIncrementResponse> result = await IncrementAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), result.ResponseCode, "authHandle's authorizing session is session 1 of Table 255 (TPM 2.0 Library Part 2, clause 6.6.2); a wrong authValue on a non-DA Index is session-encoded TPM_RC_BAD_AUTH there.");
    }

    /// <summary>
    /// Verifies <c>TPM2_NV_Increment()</c> refuses a successfully-authorized but non-Counter Index with
    /// <c>TPM_RC_ATTRIBUTES</c> (TPM 2.0 Library Part 3, clause 31.8.1).
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOfOrdinaryIndexReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, OrdinaryIndexHandle, OrdinaryAttributes).ConfigureAwait(false);

        TpmResult<NvIncrementResponse> result = await IncrementAsync(
            device, pool, registry, OrdinaryIndexHandle, OrdinaryIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), result.ResponseCode,
            "TPM2_NV_Increment() must refuse a non-Counter Index once authorization has already succeeded.");
    }

    /// <summary>
    /// Regression test for the previously-fixed defect <c>TpmLifecycleTransitions</c>' remarks flagged: a Counter
    /// Index previously accepted an ordinary <c>TPM2_NV_Write()</c>. Pins the corrected rejection (TPM
    /// 2.0 Library Part 3, clause 31.7.1: the four update commands partition NV Index types).
    /// </summary>
    [TestMethod]
    public async Task NvWriteOfCounterIndexReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, CounterIndexHandle, CounterAttributes, dataSize: 4).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 1), result.ResponseCode, "Table 245: publicInfo is TPM2_NV_DefineSpace()'s second parameter (parameter 2); a Counter Index defined with the wrong dataSize is parameter-encoded TPM_RC_SIZE at index 1.");
    }

    /// <summary>
    /// Verifies the phantom high-water mark is TPM-GLOBAL, not per-handle: a Counter Index defined at a
    /// DIFFERENT handle after another counter was deleted still seeds its first increment above that deleted
    /// counter's last value. The specification describes exactly this scope - the mark tracks "the largest
    /// count of any deleted NV Counter" (TPM 2.0 Library Part 1, clause 34.2.6.3 NOTE 2/NOTE 6), so a fresh
    /// counter's first value reflects the TPM's counter history rather than starting at one.
    /// </summary>
    [TestMethod]
    public async Task PhantomHighWaterMarkSeedsACounterDefinedAtADifferentHandle()
    {
        const int IncrementsBeforeDelete = 4;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, CounterIndexHandle, CounterAttributes | (TpmaNv)forgedStatusAttribute).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), result.ResponseCode,
            "A status attribute the TPM alone maintains must never be accepted from the caller at definition.");
    }

    /// <summary>
    /// The rollback exploit that motivated the status-attribute gate above, as a regression test: a caller who
    /// could define a redefined Counter Index with <c>TPMA_NV_WRITTEN</c> already SET would make
    /// <c>TPM2_NV_Increment()</c> read the empty data area as counter value zero and restart the count from
    /// one instead of seeding from the phantom high-water mark, rolling a counter with this Name back below a
    /// value it had already reported (TPM 2.0 Library Part 1, clause 34.2.6.3 NOTE 4 forbids exactly that).
    /// The definition is refused, so the rollback is unreachable and the surviving counter keeps its history.
    /// </summary>
    [TestMethod]
    public async Task RedefiningWithForgedWrittenAttributeCannotRollACounterBack()
    {
        const int IncrementsBeforeDelete = 3;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), forgedRedefineResult.ResponseCode,
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
    /// (TPM 2.0 Library Part 3, clause 31.3.1; Part 2, Table 249; Part 1, clause 34.2.4.2 NOTE) - a counter is
    /// either restored on an orderly startup or advanced on a non-orderly one, never cleared by a Reset/Restart.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOfCounterWithClearStClearReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, CounterIndexHandle, ClearStclearCounterAttributes).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), result.ResponseCode, "Table 245: publicInfo is TPM2_NV_DefineSpace()'s second parameter (parameter 2); a Counter Index defined with TPMA_NV_CLEAR_STCLEAR SET is parameter-encoded TPM_RC_ATTRIBUTES at index 1.");
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
    /// The flagship rollback-protection positive: increments a Counter Index to a known value,
    /// undefines it, redefines the same handle, and verifies the first increment of the redefined Index seeds
    /// strictly above (exactly one past) the deleted counter's last value - the phantom high-water mark (TPM
    /// 2.0 Library Part 1, clause 34.2.6.3 NOTE 2/NOTE 6) proving delete-then-redefine can never roll a
    /// counter with this Name back.
    /// </summary>
    [TestMethod]
    public async Task RedefiningAHandleAfterUndefineSeedsExactlyOnePastTheDeletedCountersValue()
    {
        const int IncrementsBeforeDelete = 3;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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

    /// <summary>
    /// The rollback protection is a commitment the TPM has made to the world, not owner state, so it must
    /// survive the one event that discards all owner state. <c>TPM2_Clear()</c> "delete[s] any NV Index with
    /// TPMA_NV_PLATFORMCREATE == CLEAR" (TPM 2.0 Library Part 3, clause 24.6.1) - which is every Counter Index
    /// defined under Owner Authorization - yet the phantom high-water mark tracks "the largest count of any
    /// deleted NV Counter" (Part 1, clause 34.2.6.3 NOTE 2/NOTE 6) and never falls, so a counter redefined under
    /// the NEW owner still cannot restart below a value this TPM has already reported. A clear that reset the
    /// mark, or that deleted the Index without retiring its value into the mark, would let an owner change roll
    /// a counter back - the exact history rewrite the mark exists to make impossible.
    /// </summary>
    [TestMethod]
    public async Task ClearDeletesOwnerCreatedCountersWhileTheirPhantomHighWaterMarkSurvivesTheOwnerChange()
    {
        const int IncrementsBeforeClear = 4;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        for(int i = 0; i < IncrementsBeforeClear; i++)
        {
            TpmResult<NvIncrementResponse> seedingResult = await IncrementAsync(
                device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
            Assert.IsTrue(seedingResult.IsSuccess, $"Seeding increment {i + 1} must succeed: '{seedingResult.ResponseCode}'.");
        }

        TpmResult<ClearResponse> clearResult = await device.ClearAsync(ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(clearResult.IsSuccess, $"TPM2_Clear failed: '{clearResult.ResponseCode}'.");

        TpmResult<NvIncrementResponse> orphanedIncrement = await IncrementAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), orphanedIncrement.ResponseCode,
            "The owner-created Counter Index must be gone after the clear, handle and all.");

        //The clear emptied ownerAuth as well, so the redefinition authorizes with the Empty Buffer exactly as the
        //original definition did on a factory-state TPM.
        TpmResult<NvDefineSpaceResponse> redefineResult = await DefineIndexAsync(
            device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);
        Assert.IsTrue(redefineResult.IsSuccess, $"Redefining the counter after the clear failed: '{redefineResult.ResponseCode}'.");

        TpmResult<NvIncrementResponse> firstIncrementAfterClear = await IncrementAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(firstIncrementAfterClear.IsSuccess, $"The first increment after the clear failed: '{firstIncrementAfterClear.ResponseCode}'.");

        TpmResult<NvReadResponse> readResult = await ReadCounterAsync(device, pool, registry, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(readResult.IsSuccess, $"The read-back must succeed: '{readResult.ResponseCode}'.");

        using NvReadResponse response = readResult.Value;
        Assert.AreEqual(
            (ulong)IncrementsBeforeClear + 1, BinaryPrimitives.ReadUInt64BigEndian(response.Data),
            "A counter redefined after an owner change must still seed exactly one past the highest value any deleted counter held.");
    }

    /// <summary>
    /// The HMAC arm of the index-authValue increment gate answers identically to the
    /// password arm. A wrong authValue proven over an HMAC session against a dictionary-attack-protected
    /// (<c>TPMA_NV_NO_DA</c> CLEAR) Counter Index is <c>TPM_RC_AUTH_FAIL</c>, and repeating it drives the TPM
    /// into Lockout mode exactly as the password arm does, proving <c>failedTries</c> genuinely advances on
    /// the HMAC path (TPM 2.0 Library Part 1, clause 16.8.1, p.142; clause 16.8.3, p.143). Each per-attempt
    /// mismatch is asserted against <c>BaseError</c> rather than the raw <c>ResponseCode</c>: a genuine
    /// command-HMAC failure names the offending session, so the wire code is the format-one session-encoded
    /// form - base error + <c>TPM_RC_S</c> + <c>0x100</c> for the offending slot (TPM 2.0 Library Part 2,
    /// clause 6.6.2) - rather than the bare constant; the terminal <c>TPM_RC_LOCKOUT</c> carries no such
    /// encoding, since it fires from the general lockout gate rather than a per-session HMAC mismatch.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOverHmacWithWrongAuthOnDaProtectedIndexAdvancesFailedTriesToLockout()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        for(uint attempt = 1; attempt <= LoweredMaxTries; attempt++)
        {
            TpmResult<NvIncrementResponse> wrongResult = await IncrementOverHmacAsync(
                device, pool, registry, CounterIndexHandle, WrongAuth).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_FAIL, wrongResult.BaseError,
                $"HMAC attempt {attempt} of {LoweredMaxTries} must count as an auth-failure, not yet Lockout mode.");
            Assert.AreNotEqual(
                TpmRcConstants.TPM_RC_AUTH_FAIL, wrongResult.ResponseCode,
                "A genuine command-HMAC mismatch names the offending session, so the raw wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");
        }

        TpmResult<NvIncrementResponse> lockedResult = await IncrementOverHmacAsync(
            device, pool, registry, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, lockedResult.ResponseCode,
            "Once failedTries reaches maxTries, the HMAC arm must reject even the correct authValue with TPM_RC_LOCKOUT, proving the earlier HMAC failures genuinely advanced it.");
    }

    /// <summary>
    /// The HMAC arm's NO_DA contrast to the test above. A wrong authValue proven over an
    /// HMAC session against a <c>TPMA_NV_NO_DA</c> Counter Index is a plain <c>TPM_RC_BAD_AUTH</c> and never
    /// advances the TPM-wide <c>failedTries</c> counter at all (TPM 2.0 Library Part 2, Table 249, bit 25): a
    /// single wrong HMAC attempt against a SEPARATE, freshly defined DA-protected Index right afterward - with
    /// <c>maxTries</c> lowered to one - still reads a plain auth-failure rather than Lockout mode, proving the
    /// NO_DA Index's own failure above left the shared counter untouched. Both mismatches are asserted against
    /// <c>BaseError</c>: a genuine command-HMAC mismatch names the offending session, so the wire code is the
    /// format-one session-encoded form - base error + <c>TPM_RC_S</c> + <c>0x100</c> (TPM 2.0 Library Part 2,
    /// clause 6.6.2) - never the bare constant carried by <c>ResponseCode</c>.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOverHmacWithWrongAuthOnNonDaIndexReturnsBadAuthAndLeavesFailedTriesUntouched()
    {
        const uint SingleAttemptMaxTries = 1;
        const uint SecondIndexHandle = 0x0100_0046;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, SingleAttemptMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, NonDaCounterAttributes).ConfigureAwait(false);

        TpmResult<NvIncrementResponse> noDaWrongResult = await IncrementOverHmacAsync(
            device, pool, registry, CounterIndexHandle, WrongAuth).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, noDaWrongResult.BaseError);
        Assert.AreNotEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, noDaWrongResult.ResponseCode,
            "A genuine command-HMAC mismatch names the offending session, so the raw wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        await DefineIndexAsync(device, pool, registry, SecondIndexHandle, CounterAttributes).ConfigureAwait(false);

        TpmResult<NvIncrementResponse> secondIndexWrongResult = await IncrementOverHmacAsync(
            device, pool, registry, SecondIndexHandle, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_FAIL, secondIndexWrongResult.BaseError,
            "If the NO_DA Index's wrong HMAC auth above had advanced the TPM-wide failedTries counter, this single wrong attempt against a DIFFERENT DA-protected Index (maxTries lowered to one) would already read TPM_RC_LOCKOUT instead of a plain auth-failure.");
    }

    /// <summary>
    /// Lockout mode refuses the HMAC arm exactly as the password arm (TPM 2.0 Library
    /// Part 1, clause 16.8.3). Once wrong PASSWORD attempts have driven the TPM into Lockout mode, a single
    /// HMAC-proven attempt with the CORRECT authValue is refused with <c>TPM_RC_LOCKOUT</c> too - the gate
    /// binds the DA-protected entity, not the mechanism used to present the authValue.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOverHmacInLockoutModeReturnsLockoutExactlyAsThePasswordArm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
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
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode,
                $"Password attempt {attempt} of {LoweredMaxTries} must count as an auth-failure while driving the TPM into Lockout mode.");
        }

        TpmResult<NvIncrementResponse> hmacLockedResult = await IncrementOverHmacAsync(
            device, pool, registry, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, hmacLockedResult.ResponseCode,
            "Lockout mode must refuse the HMAC arm's correct authValue exactly as it refuses the password arm's - the gate binds the entity, not the presentation mechanism.");
    }

    /// <summary>
    /// The HMAC arm's counterpart to <see cref="NvIncrementIndexArmWithoutAuthWriteReturnsAuthUnavailable"/>:
    /// with <c>TPMA_NV_AUTHWRITE</c> clear the Index's own authValue is not an available authorization
    /// mechanism for an increment at all (TPM 2.0 Library Part 1, clause 34.2.6.1), so
    /// this command's session-arm entry gate (TPM 2.0 Library Part 3, clause 5.6, check 7.2.2, ordered
    /// ahead of check 9's command-HMAC verification) refuses the command with a BARE
    /// <c>TPM_RC_AUTH_UNAVAILABLE</c> before the session's command HMAC is ever evaluated and before the
    /// Index's Name is even requested for that HMAC. A WRONG authValue is what makes the refusal sharp: had the
    /// gate not fired pre-HMAC, this credential would instead fail command-HMAC verification, and that failure
    /// carries the session-index-encoded form of the response code (TPM 2.0 Library Part 2, clause 6.6.2)
    /// rather than this bare constant - so the bare code on the wire is itself proof the HMAC was never reached
    /// and failedTries was never charged.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOverHmacIndexArmWithoutAuthWriteReturnsAuthUnavailable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterWithoutAuthWriteAttributes).ConfigureAwait(false);

        TpmResult<NvIncrementResponse> result = await IncrementOverHmacAsync(
            device, pool, registry, CounterIndexHandle, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, result.ResponseCode,
            "With TPMA_NV_AUTHWRITE clear the Index authValue cannot authorize an increment over an HMAC session either, even with a wrong credential the gate never evaluates.");
    }

    /// <summary>
    /// The decrypt-attributed half of the parameter-encryption fail-closed pair:
    /// <c>TPM2_NV_Increment()</c> carries no parameters in either direction
    /// (TPM 2.0 Library Part 3, clause 31.8.2, Tables 255-256), so a <c>decrypt</c>-attributed session names an
    /// operation with nothing to act on, and the SIMULATOR itself must refuse it with <c>TPM_RC_ATTRIBUTES</c>
    /// (Part 3, clause 5.7) rather than silently ignoring it. The command is hand-framed and submitted directly
    /// to the transport (<see cref="IncrementOverHmacHandFramedAsync"/>) because
    /// <see cref="TpmCommandExecutor"/>'s own client-side admissibility guard would refuse this exact
    /// composition before a single byte reaches the wire - that separate, legitimate layer is proven by
    /// <see cref="NvIncrementOverSessionWithDecryptAttributeIsRefusedByTheClientSideGuardBeforeReachingTheSimulator"/>
    /// instead. Proven alongside the DECLINED case, where the identical authValue over an otherwise identical
    /// session with the attribute left CLEAR - routed normally through the executor - still succeeds.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOverSessionWithDecryptAttributeReturnsAttributesWhileTheSameSessionWithoutItSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        TpmRcConstants rawDecryptCode = await IncrementOverHmacHandFramedAsync(
            device, pool, registry, CounterIndexHandle, CorrectAuth, TpmaSession.DECRYPT).ConfigureAwait(false);
        TpmResult<NvIncrementResponse> decryptResult = TpmResult<NvIncrementResponse>.TpmError(rawDecryptCode);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, decryptResult.BaseError,
            "TPM2_NV_Increment() has no parameters in either direction, so the SIMULATOR must fail the decrypt-attributed session closed rather than silently ignoring it.");
        Assert.AreNotEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, decryptResult.ResponseCode,
            "The refusal names the offending session, so the raw wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<NvIncrementResponse> declinedResult = await IncrementOverHmacAsync(
            device, pool, registry, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(
            declinedResult.IsSuccess,
            $"The identical authValue over an otherwise identical session with decrypt left CLEAR must still succeed: '{declinedResult.ResponseCode}'.");
    }

    /// <summary>
    /// The encrypt-attributed half of the parameter-encryption fail-closed pair: the response-side companion to the decrypt test above. Part 3, clause
    /// 31.8.2, Table 256 gives <c>TPM2_NV_Increment()</c> no response parameter either, so an
    /// <c>encrypt</c>-attributed session fails closed with <c>TPM_RC_ATTRIBUTES</c> the same way (Part 3, clause
    /// 5.7), proven the same hand-framed way for the same reason - see the decrypt half's remarks - alongside
    /// the DECLINED case.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOverSessionWithEncryptAttributeReturnsAttributesWhileTheSameSessionWithoutItSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        TpmRcConstants rawEncryptCode = await IncrementOverHmacHandFramedAsync(
            device, pool, registry, CounterIndexHandle, CorrectAuth, TpmaSession.ENCRYPT).ConfigureAwait(false);
        TpmResult<NvIncrementResponse> encryptResult = TpmResult<NvIncrementResponse>.TpmError(rawEncryptCode);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, encryptResult.BaseError,
            "TPM2_NV_Increment() has no response parameter, so the SIMULATOR must fail the encrypt-attributed session closed rather than silently ignoring it.");
        Assert.AreNotEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, encryptResult.ResponseCode,
            "The refusal names the offending session, so the raw wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<NvIncrementResponse> declinedResult = await IncrementOverHmacAsync(
            device, pool, registry, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(
            declinedResult.IsSuccess,
            $"The identical authValue over an otherwise identical session with encrypt left CLEAR must still succeed: '{declinedResult.ResponseCode}'.");
    }

    /// <summary>
    /// The client-side companion (decrypt half) to the SIMULATOR-side proof above: the SAME decrypt-attributed session, routed
    /// through the production <see cref="TpmCommandExecutor"/> the way every other test in this file composes
    /// one (<see cref="IncrementOverHmacAsync"/>), never reaches the wire at all - the executor's own
    /// admissibility guard refuses it with <see cref="ArgumentException"/> before a single byte is framed,
    /// because <c>NvIncrementInput</c> declares no encryptable first command parameter
    /// (<c>ITpmCommandInput.FirstCommandParameterIsEncryptable</c> defaults to <see langword="false"/>). This is
    /// a distinct, legitimate second layer from the SIMULATOR's own <c>TPM_RC_ATTRIBUTES</c> refusal
    /// (<see cref="NvIncrementOverSessionWithDecryptAttributeReturnsAttributesWhileTheSameSessionWithoutItSucceeds"/>),
    /// which is why that test hand-frames the command instead of routing it through here.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOverSessionWithDecryptAttributeIsRefusedByTheClientSideGuardBeforeReachingTheSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await IncrementOverHmacAsync(
                device, pool, registry, CounterIndexHandle, CorrectAuth, TpmaSession.DECRYPT).ConfigureAwait(false)).ConfigureAwait(false);
    }

    /// <summary>
    /// The client-side companion (encrypt half): mirrors the decrypt companion above for the
    /// response-direction attribute - the executor refuses it with <see cref="ArgumentException"/> before any
    /// bytes reach the wire, because the registered <c>NvIncrement</c> codec declares no encryptable first
    /// response parameter.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOverSessionWithEncryptAttributeIsRefusedByTheClientSideGuardBeforeReachingTheSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await IncrementOverHmacAsync(
                device, pool, registry, CounterIndexHandle, CorrectAuth, TpmaSession.ENCRYPT).ConfigureAwait(false)).ConfigureAwait(false);
    }

    /// <summary>
    /// The bound-entity half: a SALTED, BOUND HMAC session bound directly to
    /// <see cref="CounterIndexHandle"/> itself - legal for a Counter Index, unlike the outright prohibition
    /// TPM 2.0 Library Part 1, clause 34.2.8.3 places on binding to a PIN Pass/PIN Fail Index. The Index's own
    /// authValue already feeds the session key's KDFa (Part 1, clause 16.6.12, equation 25), so the
    /// per-command HMAC key omits the authValue term entirely when the session authorizes that SAME bound
    /// entity (equation 27, p.123) - the increment succeeds even though the composing session never calls
    /// <c>SetAuthValue</c>.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOverIndexBoundAndSaltedSessionForTheBoundEntityOmitsAuthValueAndSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(withRsaBackend: true).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateSaltedSessionRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(device, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

        ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

        (StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength) salted = await StartAuthSessionInput.CreateBoundAndSaltedHmacSession(
            tpmKeyHandle, CounterIndexHandle, modulus, DefaultRsaExponent, RsaKeyNameAlg, HmacSessionAlg, rsaBackend.EncryptOaep, TestEntropy.NewCounterStream(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                device, salted.Input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound-to-Index, salted) failed: '{startResult.ResponseCode}'.");

            StartAuthSessionResponse started = startResult.Value;
            uint sessionHandle = started.SessionHandle.Value;

            try
            {
                //Bound to CounterIndexHandle itself with CorrectAuth as the bind entity's own authValue: the
                //session key already carries it (equation 25), so SetAuthValue is deliberately never called -
                //calling it here would double up the authValue term the bound-entity arm (equation 27) omits.
                using TpmSession session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle), CorrectAuth, salted.Input.NonceCaller, started.NonceTPM,
                    HmacSessionAlg, TestEntropy.NewCounterStream(), pool, salt: salted.Salt.Memory[..salted.SaltLength], cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

                TpmResult<NvReadPublicResponse> nameResult = await device.NvReadPublicAsync(CounterIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(nameResult.IsSuccess, $"NvReadPublicAsync failed: '{nameResult.ResponseCode}'.");
                using NvReadPublicResponse namePublic = nameResult.Value;
                ReadOnlyMemory<byte> indexName = namePublic.NvName.Span.ToArray();

                var incrementInput = new NvIncrementInput(CounterIndexHandle, CounterIndexHandle);
                ReadOnlyMemory<byte>[] handleNames = [indexName, indexName];

                TpmResult<NvIncrementResponse> result = await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
                    device, incrementInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(result.IsSuccess, $"The bound-to-the-Index, salted HMAC session must authorize its own bound entity: '{result.ResponseCode}'.");
            }
            finally
            {
                _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                    device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
            }
        }
        finally
        {
            salted.Salt.Memory.Span[..salted.SaltLength].Clear();
            salted.Salt.Dispose();
        }
    }

    /// <summary>
    /// The not-bound-entity half: the companion to the test above (TPM 2.0 Library Part 1,
    /// clause 16.6.12, equation 26, p.123). The SAME salted-and-bound session shape, but bound to the OWNER
    /// hierarchy rather than to the Index being authorized. Because the entity the session authorizes (the
    /// Index) differs from the entity it is bound to (the owner), the authValue term must still be supplied
    /// explicitly via <c>SetAuthValue</c> - the increment succeeds once it is.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOverOwnerBoundAndSaltedSessionNotBoundToTheAuthorizedIndexSucceedsWithAuthValueSupplied()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(withRsaBackend: true).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateSaltedSessionRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(device, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

        ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

        (StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength) salted = await StartAuthSessionInput.CreateBoundAndSaltedHmacSession(
            tpmKeyHandle, (uint)TpmRh.TPM_RH_OWNER, modulus, DefaultRsaExponent, RsaKeyNameAlg, HmacSessionAlg, rsaBackend.EncryptOaep, TestEntropy.NewCounterStream(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                device, salted.Input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (owner-bound, salted) failed: '{startResult.ResponseCode}'.");

            StartAuthSessionResponse started = startResult.Value;
            uint sessionHandle = started.SessionHandle.Value;

            try
            {
                //Bound to the owner hierarchy (empty owner authValue) rather than to CounterIndexHandle: the
                //session key carries the OWNER's authValue term (equation 25), not the Index's, so the Index's
                //own authValue must still be supplied as this per-command HMAC's authValue term (equation 26).
                using TpmSession session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle), ReadOnlyMemory<byte>.Empty, salted.Input.NonceCaller, started.NonceTPM,
                    HmacSessionAlg, TestEntropy.NewCounterStream(), pool, salt: salted.Salt.Memory[..salted.SaltLength], cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
                session.SetAuthValue(CorrectAuth, pool);

                TpmResult<NvReadPublicResponse> nameResult = await device.NvReadPublicAsync(CounterIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(nameResult.IsSuccess, $"NvReadPublicAsync failed: '{nameResult.ResponseCode}'.");
                using NvReadPublicResponse namePublic = nameResult.Value;
                ReadOnlyMemory<byte> indexName = namePublic.NvName.Span.ToArray();

                var incrementInput = new NvIncrementInput(CounterIndexHandle, CounterIndexHandle);
                ReadOnlyMemory<byte>[] handleNames = [indexName, indexName];

                TpmResult<NvIncrementResponse> result = await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
                    device, incrementInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(result.IsSuccess, $"The owner-bound, salted HMAC session with the Index authValue supplied must still authorize the (different) Index entity: '{result.ResponseCode}'.");
            }
            finally
            {
                _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                    device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
            }
        }
        finally
        {
            salted.Salt.Memory.Span[..salted.SaltLength].Clear();
            salted.Salt.Dispose();
        }
    }

    /// <summary>
    /// The stranger-authHandle answer (TPM 2.0 Library Part 3,
    /// clause 31.1) survives on the HMAC arm exactly as it does on the password arm (see
    /// <see cref="NvIncrementWithMismatchedAuthHandleReturnsAuthorization"/>): an <c>authHandle</c> that is
    /// neither the owner hierarchy nor the Index itself is refused with <c>TPM_RC_NV_AUTHORIZATION</c>, never
    /// <c>TPM_RC_AUTH_TYPE</c> (the answer <c>TPM2_NV_Write()</c> gives for the identical case) and never a
    /// generic auth-failure that would suggest the HMAC was ever evaluated.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOverHmacWithMismatchedAuthHandleReturnsAuthorization()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
            session.SetAuthValue(CorrectAuth, pool);

            TpmResult<NvReadPublicResponse> nameResult = await device.NvReadPublicAsync(CounterIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(nameResult.IsSuccess, $"NvReadPublicAsync failed: '{nameResult.ResponseCode}'.");
            using NvReadPublicResponse namePublic = nameResult.Value;
            ReadOnlyMemory<byte> indexName = namePublic.NvName.Span.ToArray();

            //MismatchedAuthHandle never exists as a defined entity, so it has no real Name; its TPM_HT_NV_INDEX
            //handle-type byte still makes the executor demand SOME cpHash Name for it, so the raw handle bytes
            //stand in - immaterial to the outcome, since Part 3, clause 31.1's authHandle == nvIndex rule
            //rejects the command before the HMAC built against this placeholder is ever checked.
            byte[] placeholderName = new byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(placeholderName, MismatchedAuthHandle);

            var incrementInput = new NvIncrementInput(MismatchedAuthHandle, CounterIndexHandle);
            ReadOnlyMemory<byte>[] handleNames = [placeholderName, indexName];

            TpmResult<NvIncrementResponse> result = await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
                device, incrementInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Shared by this file's HMAC-arm tests: issues <c>TPM2_NV_Increment()</c> against <paramref name="nvIndex"/>,
    /// authorizing its own Index arm over an UNBOUND, unsalted HMAC session (TPM 2.0 Library Part 1, clause
    /// 16.6.9, equation 19) whose authValue is <paramref name="suppliedAuth"/>, optionally carrying
    /// <paramref name="extraSessionAttributes"/> for the parameter-encryption fail-closed tests.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Counter Index to increment; also the authorizing handle.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <param name="extraSessionAttributes">Additional <c>TPMA_SESSION</c> bits to set on the composed session.</param>
    /// <returns>The increment result.</returns>
    private async Task<TpmResult<NvIncrementResponse>> IncrementOverHmacAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth,
        TpmaSession extraSessionAttributes = default)
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
            session.SessionAttributes |= extraSessionAttributes;

            TpmResult<NvReadPublicResponse> nameResult = await device.NvReadPublicAsync(nvIndex, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(nameResult.IsSuccess, $"NvReadPublicAsync failed: '{nameResult.ResponseCode}'.");
            using NvReadPublicResponse namePublic = nameResult.Value;
            ReadOnlyMemory<byte> indexName = namePublic.NvName.Span.ToArray();

            var incrementInput = new NvIncrementInput(nvIndex, nvIndex);
            ReadOnlyMemory<byte>[] handleNames = [indexName, indexName];

            return await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
                device, incrementInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The SIMULATOR-side proof for the parameter-encryption fail-closed gate: hand-frames a raw <c>TPM2_NV_Increment()</c> command
    /// authorized by a single unbound, unsalted HMAC session (TPM 2.0 Library Part 1, clause 16.6.9, equation
    /// 19) whose <c>sessionAttributes</c> octet carries <paramref name="attribute"/> (<c>decrypt</c> or
    /// <c>encrypt</c>), and submits it directly to the transport - bypassing <see cref="TpmCommandExecutor"/>
    /// entirely, since its own client-side admissibility guard would refuse this exact composition before any
    /// bytes reach the wire (Part 3, clause 5.7's refusal is the TPM's own, and only the TPM's own answer proves
    /// it; the client-side guard is proven as its own separate layer elsewhere in this file). The cpHash and
    /// command HMAC are the SAME production computation <see cref="TpmSession"/> performs for every other
    /// session-authorized test in this file (<see cref="TpmSession.PrepareAuthHmacAsync"/>,
    /// <see cref="TpmSession.WriteAuthCommand"/>) - only the command envelope and the transport call are
    /// hand-rolled, mirroring the raw-wire technique <c>TpmInHouseSimulatorParameterDecryptionTests</c> uses for
    /// the same reason.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry (used only for the session's own StartAuthSession/FlushContext lifecycle).</param>
    /// <param name="nvIndex">The Counter Index to increment; also the authorizing handle.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <param name="attribute">The <c>TPMA_SESSION</c> bit under test: <see cref="TpmaSession.DECRYPT"/> or <see cref="TpmaSession.ENCRYPT"/>.</param>
    /// <returns>The raw wire response code, still carrying any session-index encoding.</returns>
    private async Task<TpmRcConstants> IncrementOverHmacHandFramedAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, TpmaSession attribute)
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

            TpmResult<NvReadPublicResponse> nameResult = await device.NvReadPublicAsync(nvIndex, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(nameResult.IsSuccess, $"NvReadPublicAsync failed: '{nameResult.ResponseCode}'.");
            using NvReadPublicResponse namePublic = nameResult.Value;
            ReadOnlyMemory<byte> indexName = namePublic.NvName.Span.ToArray();

            //cpHash = H_SHA256(commandCode || Name(authHandle) || Name(nvIndex)) - TPM 2.0 Library Part 1, clause
            //16.7, equation 15. TPM2_NV_Increment() carries no command parameters (Part 3, clause 31.8.2, Table
            //255), and this arm's authHandle and nvIndex are the same Index, so both Name terms are identical.
            int cpHashInputLength = sizeof(uint) + indexName.Length + indexName.Length;
            using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
            Memory<byte> cpHashInput = cpHashInputOwner.Memory[..cpHashInputLength];
            {
                var cpHashWriter = new TpmWriter(cpHashInput.Span);
                cpHashWriter.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_Increment);
                cpHashWriter.WriteBytes(indexName.Span);
                cpHashWriter.WriteBytes(indexName.Span);
            }

            using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
                cpHashInput, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            session.RollNonceCaller(pool);
            using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(
                cpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

            const int handlesSize = 2 * sizeof(uint);
            int authAreaSize = sizeof(uint) + session.GetAuthCommandSize();
            int totalSize = TpmHeader.HeaderSize + handlesSize + authAreaSize;

            using IMemoryOwner<byte> commandOwner = pool.Rent(totalSize);
            Memory<byte> command = commandOwner.Memory[..totalSize];
            var writer = new TpmWriter(command.Span);
            writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_SESSIONS);
            writer.WriteUInt32((uint)totalSize);
            writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_Increment);
            writer.WriteUInt32(nvIndex);
            writer.WriteUInt32(nvIndex);
            writer.WriteUInt32((uint)session.GetAuthCommandSize());
            session.WriteAuthCommand(ref writer, hmac);

            TpmResult<TpmResponse> transportResult = await device.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(transportResult.IsSuccess, "The transport itself must succeed even when the TPM refuses the command.");

            using TpmResponse response = transportResult.Value;
            var responseReader = new TpmReader(response.AsReadOnlySpan());
            TpmHeader responseHeader = TpmHeader.Parse(ref responseReader);

            return (TpmRcConstants)responseHeader.Code;
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Builds the digest <see cref="Tag"/> used to independently compute cpHash for
    /// <see cref="IncrementOverHmacHandFramedAsync"/>: SHA-256 digest, raw encoding, direct material - the same
    /// shape <c>TpmCommandExecutor</c>'s own cpHash computation uses.
    /// </summary>
    /// <returns>The digest tag.</returns>
    private static Tag DigestTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

    /// <summary>Creates the RSA endorsement-key-shaped decrypt key (RESTRICTED+DECRYPT, SHA-256 nameAlg) used as a salted session's RSA tpmKey.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaDecryptKeyAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaEndorsementKey(TpmRh.TPM_RH_OWNER, pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA decrypt key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates a response codec registry for the NV commands these tests drive.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateNvRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite)
            .Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Increment, TpmResponseCodec.NvIncrement)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

    /// <summary>Extends <see cref="CreateNvRegistry"/> with the CreatePrimary codec the salted-session tests need.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateSaltedSessionRegistry() =>
        CreateNvRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);

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
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, TpmaNv attributes, ushort dataSize = CounterDataSize)
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
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint authHandle, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
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
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
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
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, byte[] data)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(data, pool);
        var writeInput = new NvWriteInput(nvIndex, nvIndex, writeInputBuffer, Offset: 0);

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
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        var undefineInput = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            device, undefineInput, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the
    /// operational phase. When <paramref name="withRsaBackend"/> is set, the simulator is also wired with the
    /// ECC (BouncyCastle) and RSA (framework) signing backends a salted HMAC session's RSA <c>tpmKey</c> needs
    /// from <c>TPM2_CreatePrimary()</c> (TPM 2.0 Library Part 1, clause 16.6.11).
    /// </summary>
    /// <param name="withRsaBackend">When <see langword="true"/>, wires the ECC and RSA signing backends; otherwise the simulator carries neither.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(bool withRsaBackend = false)
    {
        var simulator = withRsaBackend
            ? new TpmSimulator(
                "tpm-in-house-nv-counter", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch))
            : new TpmSimulator("tpm-in-house-nv-counter", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        BaseMemoryPool pool = BaseMemoryPool.Shared;
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
