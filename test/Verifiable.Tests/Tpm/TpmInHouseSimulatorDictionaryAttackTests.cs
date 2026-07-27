using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the dictionary-attack (lockout) machinery — <c>FailedTries</c> counting, general Lockout mode,
/// the independent <c>lockoutAuth</c>-disable state, self-healing over elapsed <c>Time</c>, and
/// <c>TPM2_DictionaryAttackLockReset()</c>/<c>TPM2_DictionaryAttackParameters()</c> — against the in-house
/// behavioural <see cref="TpmSimulator"/>, entirely in-process with no external assets, through the same
/// production command path the production code uses (<see cref="TpmDictionaryAttackExtensions"/>,
/// <see cref="TpmCommandExecutor"/>, and the real command/response codecs). TPM 2.0 Library Part 1, clause
/// 17.8; Part 3, clauses 25.2/25.3.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorDictionaryAttackTests
{
    /// <summary>An ordinary NV Index handle: its most-significant octet is TPM_HT_NV_INDEX (0x01).</summary>
    private const uint NvIndexHandle = 0x0100_0001;

    /// <summary>
    /// Index attributes that authorize read with the Index authValue, dictionary-attack protected
    /// (TPMA_NV_NO_DA clear): a wrong authValue is an auth-failure that feeds the lockout counter.
    /// </summary>
    private const TpmaNv DaProtectedAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE;

    /// <summary>The same Index, opted out of dictionary-attack protection (TPMA_NV_NO_DA set).</summary>
    private const TpmaNv NonDaAttributes = DaProtectedAttributes | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>The lowered <c>maxTries</c> used by tests that drive the counter to Lockout mode quickly.</summary>
    private const uint LoweredMaxTries = 2;

    /// <summary>The correct Index authValue used throughout.</summary>
    private static byte[] CorrectAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong Index authValue, distinct from <see cref="CorrectAuth"/>.</summary>
    private static byte[] WrongAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>A wrong lockoutAuth value, distinct from the simulator's empty default.</summary>
    private static byte[] WrongLockoutAuth { get; } = [0x0A];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies repeated wrong-authValue reads against a dictionary-attack-protected Index increment
    /// <c>FailedTries</c> one at a time, that the TPM enters Lockout mode exactly at <c>maxTries</c>
    /// without a further increment, and that a subsequent attempt with the RIGHT authValue is rejected
    /// too — Lockout mode blocks any use of a DA-protected authValue, not just wrong ones (clause 17.8.3).
    /// </summary>
    [TestMethod]
    public async Task NvReadBruteForceIncrementsFailedTriesAndLocksOutAtMaxTries()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        await DefineDaIndexAsync(device, pool, registry).ConfigureAwait(false);

        for(uint attempt = 1; attempt <= LoweredMaxTries; attempt++)
        {
            TpmResult<NvReadResponse> wrongResult = await ReadIndexAsync(device, pool, registry, WrongAuth).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_FAIL, wrongResult.ResponseCode,
                $"Attempt {attempt} of {LoweredMaxTries} must count as an auth-failure, not yet Lockout mode.");
        }

        TpmResult<NvReadResponse> lockedWrongResult = await ReadIndexAsync(device, pool, registry, WrongAuth).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, lockedWrongResult.ResponseCode, "Once failedTries reaches maxTries, further attempts must reject with TPM_RC_LOCKOUT.");

        TpmResult<NvReadResponse> lockedRightResult = await ReadIndexAsync(device, pool, registry, CorrectAuth).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, lockedRightResult.ResponseCode, "Lockout mode must reject even the RIGHT authValue.");

        TpmResult<TpmDictionaryAttackParameters> readBack = await device.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(readBack.IsSuccess, $"GetDictionaryAttackParameters failed: '{readBack.ResponseCode}'.");
        Assert.AreEqual(LoweredMaxTries, readBack.Value.LockoutCounter, "failedTries must stop at maxTries, never overshoot from the LOCKOUT-rejected attempts.");
        Assert.IsTrue(readBack.Value.IsLockedOut, "The reported lockout parameters must reflect Lockout mode.");
    }

    /// <summary>
    /// Verifies repeated wrong-authValue reads against a <c>TPMA_NV_NO_DA</c> Index never increment
    /// <c>FailedTries</c> — the Index is exempt from the global dictionary-attack mechanism by construction
    /// (clause 17.8.1).
    /// </summary>
    [TestMethod]
    public async Task NvReadOnNoDaExemptIndexDoesNotIncrementFailedTries()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        using(TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool))
        {
            TpmResult<NvDefineSpaceResponse> defineResult = await DefineSpaceAsync(
                device, pool, registry, NonDaAttributes, ownerSession).ConfigureAwait(false);
            Assert.IsTrue(defineResult.IsSuccess, $"Define must succeed, got '{defineResult.ResponseCode}'.");
        }

        for(int attempt = 0; attempt < 5; attempt++)
        {
            TpmResult<NvReadResponse> wrongResult = await ReadIndexAsync(device, pool, registry, WrongAuth).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, wrongResult.ResponseCode, "A non-DA Index's failure must never be TPM_RC_AUTH_FAIL.");
        }

        TpmResult<TpmDictionaryAttackParameters> readBack = await device.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(readBack.IsSuccess, $"GetDictionaryAttackParameters failed: '{readBack.ResponseCode}'.");
        Assert.AreEqual(0u, readBack.Value.LockoutCounter, "A noDA-exempt Index's auth failures must never move failedTries.");
    }

    /// <summary>
    /// Verifies <c>FailedTries</c> self-heals by exactly one decrement per <c>RecoveryTime</c> seconds of
    /// elapsed <c>Time</c> (clause 17.8.4), driven deterministically through the simulator's fixed
    /// per-command <see cref="TpmSimulatorState.ClockAdvanceQuantumMs"/> rather than a wall clock.
    /// </summary>
    /// <remarks>
    /// Every dispatched command — including the <c>TPM2_GetCapability()</c> round trip
    /// <see cref="TpmDictionaryAttackExtensions.GetDictionaryAttackParametersAsync"/> issues to read the
    /// counter back — advances <c>Time</c> by one quantum itself (clause 36.1), so the ledger below counts
    /// every command from the seeding failure onward, not just the ones that look DA-related.
    /// </remarks>
    [TestMethod]
    public async Task SelfHealDecrementsFailedTriesPerRecoveryTimeElapsedOnTheTimeBase()
    {
        const ulong QuantumMs = 1000UL;
        const uint RecoveryTimeSeconds = 3u;

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(QuantumMs).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();
        TpmResponseRegistry readClockRegistry = CreateReadClockRegistry();

        TpmResult<DictionaryAttackParametersResponse> setResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, TpmSimulatorState.DefaultMaxTries, RecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(setResult.IsSuccess, $"Setting recoveryTime failed: '{setResult.ResponseCode}'.");

        await DefineDaIndexAsync(device, pool, registry).ConfigureAwait(false);

        TpmResult<NvReadResponse> wrongResult = await ReadIndexAsync(device, pool, registry, WrongAuth).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, wrongResult.ResponseCode, "The seeding failure must count.");

        //One quantum (1000ms) of elapsed Time since the failure is well short of the 3000ms
        //(RecoveryTimeSeconds) interval: no decrement has been earned yet.
        TpmResult<TpmDictionaryAttackParameters> afterFailure = await device.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(1u, afterFailure.Value.LockoutCounter, "failedTries must not heal before a full recoveryTime interval has elapsed.");

        //One more quantum (a harmless TPM2_ReadClock()) brings total elapsed Time to exactly 3000ms since
        //the failure — one whole recoveryTime interval — earning exactly one decrement, applied on the
        //very next dispatched command's self-heal check (the read-back below).
        await SubmitReadClockAsync(device, pool, readClockRegistry).ConfigureAwait(false);
        TpmResult<TpmDictionaryAttackParameters> afterInterval = await device.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(0u, afterInterval.Value.LockoutCounter, "failedTries must decrement by exactly one once a full recoveryTime interval has elapsed.");
    }

    /// <summary>
    /// Verifies a single wrong <c>lockoutAuth</c> use disables <c>lockoutAuth</c> independently of
    /// <c>FailedTries</c>/<c>MaxTries</c> (clause 17.8.5) — no brute-force counting is involved, a lone
    /// wrong attempt suffices — and that a subsequent CORRECT <c>lockoutAuth</c> use is itself rejected
    /// with <c>TPM_RC_LOCKOUT</c> until <c>LockoutRecovery</c> seconds of <c>Time</c> have elapsed.
    /// </summary>
    [TestMethod]
    public async Task WrongLockoutAuthDisablesLockoutAuthEnabledUntilLockoutRecoveryElapses()
    {
        const ulong QuantumMs = 1000UL;
        const uint LockoutRecoverySeconds = 2u;

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(QuantumMs).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry readClockRegistry = CreateReadClockRegistry();

        TpmResult<DictionaryAttackParametersResponse> setResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, TpmSimulatorState.DefaultMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            LockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(setResult.IsSuccess, $"Setting lockoutRecovery failed: '{setResult.ResponseCode}'.");

        TpmResult<DictionaryAttackLockResetResponse> wrongLockoutAuthResult = await device.DictionaryAttackLockResetAsync(
            WrongLockoutAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, wrongLockoutAuthResult.ResponseCode, "A wrong lockoutAuth use must be an auth-failure — lockoutAuth is dictionary-attack protected.");

        TpmResult<DictionaryAttackLockResetResponse> tooSoonResult = await device.DictionaryAttackLockResetAsync(
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, tooSoonResult.ResponseCode,
            "Even the CORRECT lockoutAuth must be rejected while lockoutAuth is disabled, before lockoutRecovery has elapsed.");

        //One quantum (1000ms) brings elapsed Time to exactly 2000ms since the failure — one whole
        //lockoutRecovery interval — re-enabling lockoutAuth on this command's self-heal check.
        await SubmitReadClockAsync(device, pool, readClockRegistry).ConfigureAwait(false);

        TpmResult<DictionaryAttackLockResetResponse> healedResult = await device.DictionaryAttackLockResetAsync(
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(healedResult.IsSuccess, $"The correct lockoutAuth must succeed once lockoutRecovery has elapsed: '{healedResult.ResponseCode}'.");
    }

    /// <summary>
    /// Verifies <c>TPM2_DictionaryAttackLockReset()</c> resets <c>FailedTries</c> to zero and lifts Lockout
    /// mode, re-arming DA-protected authValue use (clause 17.8.4/25.2).
    /// </summary>
    [TestMethod]
    public async Task DictionaryAttackLockResetClearsFailedTriesAndReArmsAfterLockout()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        await DefineDaIndexAsync(device, pool, registry).ConfigureAwait(false);

        for(uint attempt = 0; attempt < LoweredMaxTries; attempt++)
        {
            _ = await ReadIndexAsync(device, pool, registry, WrongAuth).ConfigureAwait(false);
        }

        TpmResult<NvReadResponse> lockedResult = await ReadIndexAsync(device, pool, registry, CorrectAuth).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, lockedResult.ResponseCode, "The Index must be locked out before the reset.");

        TpmResult<DictionaryAttackLockResetResponse> resetResult = await device.DictionaryAttackLockResetAsync(
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(resetResult.IsSuccess, $"DictionaryAttackLockReset under the correct lockoutAuth must succeed even while locked out: '{resetResult.ResponseCode}'.");

        TpmResult<TpmDictionaryAttackParameters> readBack = await device.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(0u, readBack.Value.LockoutCounter, "The reset must clear failedTries to zero.");
        Assert.IsFalse(readBack.Value.IsLockedOut, "The reset must lift Lockout mode.");

        //Re-armed: a correct-auth read is no longer rejected as locked out (it answers uninitialized,
        //since nothing was ever written — proving the outcome is no longer TPM_RC_LOCKOUT).
        TpmResult<NvReadResponse> reArmedResult = await ReadIndexAsync(device, pool, registry, CorrectAuth).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_UNINITIALIZED, reArmedResult.ResponseCode, "A correct-auth read must no longer be rejected as locked out after the reset.");
    }

    /// <summary>
    /// Verifies <c>TPM2_DictionaryAttackParameters()</c> sets all three knobs and deliberately leaves
    /// <c>FailedTries</c> untouched (clause 17.8.6's errata correction).
    /// </summary>
    [TestMethod]
    public async Task DictionaryAttackParametersSetsKnobsWithoutResettingFailedTries()
    {
        const uint NewMaxTries = 10u;
        const uint NewRecoveryTimeSeconds = 100u;
        const uint NewLockoutRecoverySeconds = 200u;

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineDaIndexAsync(device, pool, registry).ConfigureAwait(false);
        _ = await ReadIndexAsync(device, pool, registry, WrongAuth).ConfigureAwait(false);
        _ = await ReadIndexAsync(device, pool, registry, WrongAuth).ConfigureAwait(false);

        TpmResult<TpmDictionaryAttackParameters> beforeChange = await device.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(2u, beforeChange.Value.LockoutCounter, "Two counted failures must set failedTries to 2 before the parameters change.");

        TpmResult<DictionaryAttackParametersResponse> setResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, NewMaxTries, NewRecoveryTimeSeconds, NewLockoutRecoverySeconds,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(setResult.IsSuccess, $"DictionaryAttackParameters failed: '{setResult.ResponseCode}'.");

        TpmResult<TpmDictionaryAttackParameters> afterChange = await device.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(2u, afterChange.Value.LockoutCounter, "DictionaryAttackParameters must not reset failedTries.");
        Assert.AreEqual(NewMaxTries, afterChange.Value.MaxAuthFail, "maxTries must be updated to the new value.");
        Assert.AreEqual(TimeSpan.FromSeconds(NewRecoveryTimeSeconds), afterChange.Value.LockoutInterval, "recoveryTime must be updated to the new value.");
        Assert.AreEqual(TimeSpan.FromSeconds(NewLockoutRecoverySeconds), afterChange.Value.LockoutRecovery, "lockoutRecovery must be updated to the new value.");
    }

    /// <summary>
    /// Verifies the errata-documented side effect (Part 1, clause 17.8.6): lowering <c>maxTries</c> to at or
    /// below the current <c>FailedTries</c> takes the TPM into Lockout mode immediately, with no distinct
    /// error code for the transition itself — the very next DA-gated authorization then rejects with
    /// <c>TPM_RC_LOCKOUT</c>.
    /// </summary>
    [TestMethod]
    public async Task DictionaryAttackParametersLoweringMaxTriesAtOrBelowCurrentCountLocksOutImmediately()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineDaIndexAsync(device, pool, registry).ConfigureAwait(false);
        _ = await ReadIndexAsync(device, pool, registry, WrongAuth).ConfigureAwait(false);
        _ = await ReadIndexAsync(device, pool, registry, WrongAuth).ConfigureAwait(false);

        TpmResult<NvReadResponse> stillOpenResult = await ReadIndexAsync(device, pool, registry, CorrectAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_UNINITIALIZED, stillOpenResult.ResponseCode,
            "Two failures against the default maxTries must not yet lock out.");

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries to the current failedTries must itself succeed: '{lowerResult.ResponseCode}'.");

        TpmResult<TpmDictionaryAttackParameters> readBack = await device.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(readBack.Value.IsLockedOut, "Lowering maxTries to-or-below the current failedTries must put the TPM into Lockout mode immediately.");

        TpmResult<NvReadResponse> nowLockedResult = await ReadIndexAsync(device, pool, registry, CorrectAuth).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, nowLockedResult.ResponseCode, "The very next DA-gated authorization must reject with TPM_RC_LOCKOUT, with no distinct error for the parameters change itself.");
    }

    /// <summary>
    /// Verifies <c>maxTries == 0</c> is fail-CLOSED — permanently in Lockout mode — rather than the pre-fix
    /// fail-OPEN behavior of never locking out (TPM 2.0 Library Part 1, clause 17.8.3). With <c>FailedTries</c>
    /// a <c>uint</c>, <c>IsInLockout =&gt; FailedTries &gt;= MaxTries</c> holds unconditionally once
    /// <c>MaxTries</c> is 0, so <c>TPM2_DictionaryAttackLockReset()</c> remains callable (clause 25.2: it is not
    /// itself gated by Lockout mode) and resets <c>FailedTries</c> to zero, but the TPM stays locked until
    /// <c>MaxTries</c> is raised again by a lockoutAuth-authorized <c>TPM2_DictionaryAttackParameters()</c> —
    /// the genuine recovery path, since <c>DictionaryAttackLockReset()</c> deliberately never touches
    /// <c>MaxTries</c> itself.
    /// </summary>
    [TestMethod]
    public async Task DictionaryAttackParametersSettingMaxTriesToZeroLocksOutPermanentlyUntilMaxTriesIsRaisedAgain()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineDaIndexAsync(device, pool, registry).ConfigureAwait(false);

        TpmResult<DictionaryAttackParametersResponse> zeroMaxTriesResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, newMaxTries: 0, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(zeroMaxTriesResult.IsSuccess, $"Setting maxTries to zero must itself succeed: '{zeroMaxTriesResult.ResponseCode}'.");

        TpmResult<NvReadResponse> lockedResult = await ReadIndexAsync(device, pool, registry, CorrectAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, lockedResult.ResponseCode,
            "maxTries == 0 must put the TPM in permanent Lockout mode (fail-closed), not permanently NOT-locked (the pre-fix fail-open bug).");

        TpmResult<TpmDictionaryAttackParameters> readBackWhileLocked = await device.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(readBackWhileLocked.IsSuccess, $"GetDictionaryAttackParameters failed: '{readBackWhileLocked.ResponseCode}'.");
        Assert.IsTrue(readBackWhileLocked.Value.IsLockedOut, "The reported lockout parameters must reflect Lockout mode with maxTries == 0.");

        TpmResult<DictionaryAttackLockResetResponse> resetResult = await device.DictionaryAttackLockResetAsync(
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(resetResult.IsSuccess, $"DictionaryAttackLockReset must remain callable despite Lockout mode: '{resetResult.ResponseCode}'.");

        //DictionaryAttackLockReset resets FailedTries to zero but never touches MaxTries, so with MaxTries still
        //0, FailedTries(0) >= MaxTries(0) keeps the TPM locked right after the reset — the fail-closed direction
        //is durable, not a one-shot escape the reset alone undoes.
        TpmResult<NvReadResponse> stillLockedResult = await ReadIndexAsync(device, pool, registry, CorrectAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, stillLockedResult.ResponseCode,
            "With maxTries still 0, DictionaryAttackLockReset alone must not exit Lockout mode.");

        TpmResult<DictionaryAttackParametersResponse> restoreResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, TpmSimulatorState.DefaultMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(restoreResult.IsSuccess, $"Raising maxTries back must succeed: '{restoreResult.ResponseCode}'.");

        TpmResult<NvReadResponse> recoveredResult = await ReadIndexAsync(device, pool, registry, CorrectAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_UNINITIALIZED, recoveredResult.ResponseCode,
            "Once maxTries is raised back above the (reset) failedTries, the TPM must exit Lockout mode.");
    }

    /// <summary>
    /// Verifies <c>TPM2_GetCapability()</c> reports the live <c>FailedTries</c>/<c>MaxTries</c> values and
    /// sets the <c>TPMA_PERMANENT.IN_LOCKOUT</c> bit once Lockout mode is entered — closing the gap the
    /// lifecycle capability tests left open pending real dictionary-attack enforcement.
    /// </summary>
    [TestMethod]
    public async Task GetCapabilityReflectsLiveFailedTriesMaxTriesAndLockoutState()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();
        TpmResponseRegistry capabilityRegistry = CreateCapabilityRegistry();

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        await DefineDaIndexAsync(device, pool, registry).ConfigureAwait(false);

        for(uint attempt = 0; attempt < LoweredMaxTries; attempt++)
        {
            _ = await ReadIndexAsync(device, pool, registry, WrongAuth).ConfigureAwait(false);
        }

        TpmResult<GetCapabilityResponse> lockoutCounterResult = await TpmCommandExecutor.ExecuteAsync<GetCapabilityResponse>(
            device, GetCapabilityInput.ForTpmProperties(TpmPtConstants.TPM_PT_LOCKOUT_COUNTER, count: 2), [], null, pool, capabilityRegistry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lockoutCounterResult.IsSuccess, $"GetCapability failed: '{lockoutCounterResult.ResponseCode}'.");

        using GetCapabilityResponse lockoutProperties = lockoutCounterResult.Value;
        var counterAndMax = lockoutProperties.CapabilityData.TpmProperties;
        Assert.IsNotNull(counterAndMax);
        Assert.HasCount(2, counterAndMax);
        Assert.AreEqual(TpmPtConstants.TPM_PT_LOCKOUT_COUNTER, counterAndMax[0].Property);
        Assert.AreEqual(LoweredMaxTries, counterAndMax[0].Value, "TPM_PT_LOCKOUT_COUNTER must report the live failedTries.");
        Assert.AreEqual(TpmPtConstants.TPM_PT_MAX_AUTH_FAIL, counterAndMax[1].Property);
        Assert.AreEqual(LoweredMaxTries, counterAndMax[1].Value, "TPM_PT_MAX_AUTH_FAIL must report the live (lowered) maxTries.");

        TpmResult<GetCapabilityResponse> permanentResult = await TpmCommandExecutor.ExecuteAsync<GetCapabilityResponse>(
            device, GetCapabilityInput.ForTpmProperties(TpmPtConstants.TPM_PT_PERMANENT, count: 1), [], null, pool, capabilityRegistry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(permanentResult.IsSuccess, $"GetCapability failed: '{permanentResult.ResponseCode}'.");

        using GetCapabilityResponse permanentProperties = permanentResult.Value;
        var permanentList = permanentProperties.CapabilityData.TpmProperties;
        Assert.IsNotNull(permanentList);
        Assert.HasCount(1, permanentList);
        var permanent = (TpmaPermanent)permanentList[0].Value;
        Assert.IsTrue(permanent.HasFlag(TpmaPermanent.IN_LOCKOUT), "TPM_PT_PERMANENT must report IN_LOCKOUT once failedTries reaches maxTries.");
    }

    /// <summary>
    /// Defines <see cref="NvIndexHandle"/> as a dictionary-attack-protected Index (<see cref="DaProtectedAttributes"/>)
    /// with <see cref="CorrectAuth"/>, authorized by the (empty) owner authValue.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    private async Task DefineDaIndexAsync(TpmDevice device, MemoryPool<byte> pool, TpmResponseRegistry registry)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<NvDefineSpaceResponse> result = await DefineSpaceAsync(
            device, pool, registry, DaProtectedAttributes, ownerSession).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Define must succeed, got '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Issues <c>TPM2_NV_DefineSpace()</c> for <see cref="NvIndexHandle"/> with the given attributes and
    /// <see cref="CorrectAuth"/> as the Index authValue, authorized by <paramref name="ownerSession"/>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    /// <param name="ownerSession">The owner-hierarchy authorization session.</param>
    /// <returns>The define-space result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineSpaceAsync(
        TpmDevice device, MemoryPool<byte> pool, TpmResponseRegistry registry, TpmaNv attributes, TpmPasswordSession ownerSession)
    {
        //The input takes ownership of the auth value and public area and disposes them; the redundant using
        //locals satisfy CA2000 and are safe because both types have idempotent disposal.
        using var auth = Tpm2bAuth.Create(CorrectAuth, pool);
        using var publicInfo = new TpmsNvPublic(NvIndexHandle, TpmAlgIdConstants.TPM_ALG_SHA256, attributes, Tpm2bDigest.Empty, dataSize: 8);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues <c>TPM2_NV_Read()</c> against <see cref="NvIndexHandle"/>, authorized by Index authValue.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="suppliedAuth">The authValue the caller supplies for the Index.</param>
    /// <returns>The read result.</returns>
    private async Task<TpmResult<NvReadResponse>> ReadIndexAsync(
        TpmDevice device, MemoryPool<byte> pool, TpmResponseRegistry registry, ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);

        //Index authorization: the authorization handle is the Index itself.
        var readInput = new NvReadInput(AuthHandle: NvIndexHandle, NvIndex: NvIndexHandle, Size: 8, Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues <c>TPM2_ReadClock()</c> — an unauthorized, no-op-for-DA command whose sole purpose here is to
    /// advance <see cref="TpmSimulatorState.Time"/> by one quantum and let the per-command self-heal check
    /// run against the freshly advanced value.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    private async Task SubmitReadClockAsync(TpmDevice device, MemoryPool<byte> pool, TpmResponseRegistry registry)
    {
        TpmResult<ReadClockResponse> result = await TpmCommandExecutor.ExecuteAsync<ReadClockResponse>(
            device, new ReadClockInput(), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"TPM2_ReadClock() must succeed: '{result.ResponseCode}'.");
    }

    /// <summary>Creates a response codec registry for the NV commands these tests drive directly.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateNvRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);

    /// <summary>Creates a response codec registry for the standalone <c>TPM2_ReadClock()</c> calls.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateReadClockRegistry() =>
        new TpmResponseRegistry().Register(TpmCcConstants.TPM_CC_ReadClock, TpmResponseCodec.ReadClock);

    /// <summary>Creates a response codec registry for the standalone <c>TPM2_GetCapability()</c> calls.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateCapabilityRegistry() =>
        new TpmResponseRegistry().Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);

    /// <summary>
    /// Creates a simulator with the given clock-advance quantum, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="clockAdvanceQuantumMs">The fixed per-command clock advance, in milliseconds.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(ulong clockAdvanceQuantumMs = TpmSimulatorState.DefaultClockAdvanceQuantumMs)
    {
        var simulator = new TpmSimulator("tpm-in-house-dictionary-attack", clockAdvanceQuantumMs: clockAdvanceQuantumMs);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames
    /// an unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator)
    {
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
    }
}
