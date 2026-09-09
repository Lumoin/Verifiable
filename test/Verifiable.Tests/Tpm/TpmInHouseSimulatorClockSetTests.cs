using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_ClockSet()</c> against the in-house behavioural <see cref="TpmSimulator"/>, entirely
/// in-process, through the same production command path the production code uses
/// (<see cref="TpmCommandExecutor"/> with the real <see cref="ClockSetInput"/> and response codec):
/// a forward set advances Clock and marks it Safe, a backward or above-ceiling set is rejected with
/// <c>TPM_RC_VALUE</c> and leaves Clock unchanged, the owner and the platform hierarchy both authorize it
/// (<c>TPMI_RH_PROVISION</c>, TPM 2.0 Library Part 3, Table 234), and a non-provision authorization handle is
/// rejected with <c>TPM_RC_VALUE</c>, handle-encoded to the same index, that handle shape's own membership check answers (TPM 2.0 Library
/// Part 3, clause 29.2).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorClockSetTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies a forward <c>TPM2_ClockSet()</c> advances Clock to exactly the requested value, which
    /// <c>TPM2_ReadClock()</c> then confirms, and marks <c>Safe</c> YES (TPM 2.0 Library Part 3, clause
    /// 29.2: an explicitly caller-set Clock is, by construction, a value never previously reported).
    /// </summary>
    [TestMethod]
    public async Task ClockSetForwardAdvancesClockAndReadClockConfirms()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = CreatePoweredOff();
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        TpmsTimeInfo before = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);
        ulong forwardTarget = before.ClockInfo.Clock + 1_000_000ul;

        await ClockSetAsync(tpm, registry, pool, forwardTarget).ConfigureAwait(false);

        TpmsTimeInfo after = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);

        //ClockSet sets Clock to exactly forwardTarget; the readback ReadClock command is itself one more
        //dispatched command, so its own per-command quantum advances Clock by one more before it is reported.
        Assert.AreEqual(forwardTarget + 1ul, after.ClockInfo.Clock, "A successful ClockSet must set Clock to exactly the requested value, plus the readback ReadClock's own quantum.");
        Assert.IsTrue(after.ClockInfo.Safe.IsYes, "A successful ClockSet must mark Safe YES.");
    }

    /// <summary>
    /// Verifies that setting Clock backward — a value less than the current Clock — is rejected with
    /// <c>TPM_RC_VALUE</c> and leaves Clock unchanged (TPM 2.0 Library Part 3, clause 29.2).
    /// </summary>
    [TestMethod]
    public async Task ClockSetBackwardReturnsValueAndLeavesClockUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = CreatePoweredOff();
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        TpmsTimeInfo before = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.IsGreaterThan(0ul, before.ClockInfo.Clock, "Clock must already be non-zero (at least the Startup quantum) for a backward set to be meaningful.");

        ClockSetInput input = new(TpmRh.TPM_RH_OWNER, before.ClockInfo.Clock - 1ul);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ClockSetResponse> result = await TpmCommandExecutor.ExecuteAsync<ClockSetResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), result.ResponseCode, "Table 234: newTime is TPM2_ClockSet()'s sole parameter (parameter 1); a backward clock adjustment is parameter-encoded TPM_RC_VALUE at index 0.");

        TpmsTimeInfo after = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.IsGreaterThan(before.ClockInfo.Clock, after.ClockInfo.Clock, "Clock must have advanced only by ReadClock's own quantum, not been set backward.");
    }

    /// <summary>
    /// Verifies that setting Clock above the clause 33.3 ceiling (<c>FF FF 00 00 00 00 00 00(16)</c>) is
    /// rejected with <c>TPM_RC_VALUE</c> (TPM 2.0 Library Part 1, clause 33.3; Part 3, clause 29.2).
    /// </summary>
    [TestMethod]
    public async Task ClockSetAboveTheCeilingReturnsValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = CreatePoweredOff();
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        ClockSetInput input = new(TpmRh.TPM_RH_OWNER, TpmLifecycleTransitions.MaxClockValue + 1ul);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ClockSetResponse> result = await TpmCommandExecutor.ExecuteAsync<ClockSetResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), result.ResponseCode, "Table 234: newTime is TPM2_ClockSet()'s sole parameter (parameter 1); a clock setting above the implementation ceiling is parameter-encoded TPM_RC_VALUE at index 0.");
    }

    /// <summary>
    /// Verifies that the platform hierarchy authorizes <c>TPM2_ClockSet()</c> under its factory-empty
    /// <c>platformAuth</c>, exactly as the owner hierarchy does: "This command requires Platform Authorization
    /// or Owner Authorization." (clause 29.2.1), and <c>TPMI_RH_PROVISION</c> admits <c>TPM_RH_OWNER</c> or
    /// <c>TPM_RH_PLATFORM</c> alike (Table 234), so the set succeeds and advances Clock to the requested value,
    /// confirmed through <c>TPM2_ReadClock()</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.2.2, Table 234</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockSetUnderTheFactoryEmptyPlatformAuthSucceedsAndAdvancesClock()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = CreatePoweredOff();
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        TpmsTimeInfo before = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);
        ulong forwardTarget = before.ClockInfo.Clock + 1_000_000ul;

        ClockSetInput input = new(TpmRh.TPM_RH_PLATFORM, forwardTarget);
        using TpmPasswordSession platformAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ClockSetResponse> result = await TpmCommandExecutor.ExecuteAsync<ClockSetResponse>(
            tpm, input, [platformAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"TPM2_ClockSet under the platform hierarchy must succeed: '{result.ResponseCode}'.");

        TpmsTimeInfo after = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);

        Assert.AreEqual(forwardTarget + 1ul, after.ClockInfo.Clock, "A successful platform-authorized ClockSet must set Clock to exactly the requested value, plus the readback ReadClock's own quantum.");
        Assert.IsTrue(after.ClockInfo.Safe.IsYes, "A successful ClockSet must mark Safe YES.");
    }

    /// <summary>
    /// Verifies that a non-provision authorization handle — <c>TPM_RH_ENDORSEMENT</c>, outside
    /// <c>TPMI_RH_PROVISION</c>'s <c>{TPM_RH_OWNER, TPM_RH_PLATFORM}</c> — is rejected with
    /// <c>TPM_RC_VALUE</c>, handle-encoded to the same index, that interface type's own membership check answers, judged at the transition ahead
    /// of authorization.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.21, Table 67</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockSetWithANonProvisionHandleReturnsValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = CreatePoweredOff();
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        ClockSetInput input = new(TpmRh.TPM_RH_ENDORSEMENT, 1_000_000ul);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ClockSetResponse> result = await TpmCommandExecutor.ExecuteAsync<ClockSetResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), result.ResponseCode,
            "Part 2 Table 67 admits only TPM_RH_OWNER and TPM_RH_PLATFORM, so TPM_RH_ENDORSEMENT designates authHandle, handle 1 of TPM2_ClockSet's own command table.");
    }

    /// <summary>Creates a powered-off simulator needing no asymmetric backend (ClockSet needs none).</summary>
    /// <returns>The powered-off simulator.</returns>
    private static TpmSimulator CreatePoweredOff() => new("tpm-in-house-clock-set", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));

    /// <summary>Issues one <c>TPM2_ReadClock()</c> and returns the parsed current-time snapshot.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The current <c>TPMS_TIME_INFO</c>.</returns>
    private async Task<TpmsTimeInfo> ReadClockAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        TpmResult<ReadClockResponse> result = await TpmCommandExecutor.ExecuteAsync<ReadClockResponse>(
            tpm, new ReadClockInput(), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ReadClock failed: '{result.ResponseCode}'.");

        ReadClockResponse response = result.Value;

        return response.CurrentTime;
    }

    /// <summary>Issues one successful owner-authorized <c>TPM2_ClockSet()</c> to <paramref name="newTime"/>.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="newTime">The requested new Clock setting, in milliseconds.</param>
    private async Task ClockSetAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, ulong newTime)
    {
        ClockSetInput input = new(TpmRh.TPM_RH_OWNER, newTime);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<ClockSetResponse> result = await TpmCommandExecutor.ExecuteAsync<ClockSetResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ClockSet failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

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
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_ReadClock, TpmResponseCodec.ReadClock);
        _ = registry.Register(TpmCcConstants.TPM_CC_ClockSet, TpmResponseCodec.ClockSet);

        return registry;
    }
}
