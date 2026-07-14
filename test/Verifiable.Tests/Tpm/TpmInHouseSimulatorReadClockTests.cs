using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_ReadClock()</c> against the in-house behavioural <see cref="TpmSimulator"/>, entirely
/// in-process, through the same production command path the production code uses
/// (<see cref="TpmCommandExecutor"/> with the real <see cref="ReadClockInput"/> and response codec):
/// monotonic advance of the deterministic per-command quantum, the Time-resets-but-Clock-does-not behaviour
/// across a TPM Restart, the resetCount/restartCount transitions across the three startup classifications
/// (TPM Reset, Restart, Resume — TPM 2.0 Library Part 3, clause 9.3), and the ClockSafe transition on an
/// unorderly reset (TPM 2.0 Library Part 1, clause 36.3).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorReadClockTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that <c>Clock</c> and <c>Time</c> advance by exactly the default one-millisecond quantum per
    /// dispatched command, strictly increasing across two sequential <c>TPM2_ReadClock()</c> calls, while
    /// <c>resetCount</c>/<c>restartCount</c> stay stable within the one power cycle (TPM 2.0 Library Part 1,
    /// clause 36.1).
    /// </summary>
    [TestMethod]
    public async Task ReadClockAdvancesByTheDeterministicQuantumAcrossCommands()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = CreatePoweredOff();
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await SubmitAndAssertSuccessAsync(simulator, new StartupInput(TpmSuConstants.TPM_SU_CLEAR), pool).ConfigureAwait(false);

        //Startup(CLEAR) is this fresh simulator's first TPM Reset: Clock = 1 (the Startup command's own
        //quantum), Time reset to 0 by the Reset arm.
        TpmsTimeInfo first = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.AreEqual(2ul, first.ClockInfo.Clock, "Clock accumulates one quantum for Startup, one for this ReadClock.");
        Assert.AreEqual(1ul, first.Time, "Time accumulates only this ReadClock's quantum after the Reset zeroed it.");

        TpmsTimeInfo second = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.AreEqual(3ul, second.ClockInfo.Clock, "Clock advances by exactly one quantum per dispatched command.");
        Assert.AreEqual(2ul, second.Time, "Time advances by exactly one quantum per dispatched command.");

        Assert.IsGreaterThan(first.ClockInfo.Clock, second.ClockInfo.Clock, "Clock must strictly increase across two sequential commands.");
        Assert.IsGreaterThan(first.Time, second.Time, "Time must strictly increase across two sequential commands within one power cycle.");
        Assert.AreEqual(1u, first.ClockInfo.ResetCount, "A fresh simulator's single Startup(CLEAR) is exactly one TPM Reset.");
        Assert.AreEqual(first.ClockInfo.ResetCount, second.ClockInfo.ResetCount, "resetCount must stay stable within one power cycle.");
        Assert.AreEqual(0u, first.ClockInfo.RestartCount, "No Restart or Resume has occurred yet.");
        Assert.AreEqual(first.ClockInfo.RestartCount, second.ClockInfo.RestartCount, "restartCount must stay stable within one power cycle.");
    }

    /// <summary>
    /// Verifies that <c>Time</c> resets to a small value across a Shutdown(STATE) + Startup(CLEAR) cycle — a
    /// TPM Restart, since Startup(CLEAR) preceded by Shutdown(STATE) is Restart, not Reset (TPM 2.0 Library
    /// Part 3, clause 9.3) — while <c>Clock</c> keeps accumulating across the same boundary and never resets
    /// (TPM 2.0 Library Part 1, clause 36.3), and <c>restartCount</c> increments while <c>resetCount</c> stays
    /// fixed.
    /// </summary>
    [TestMethod]
    public async Task TimeResetsButClockDoesNotAcrossAShutdownStateStartupClearRestart()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = CreatePoweredOff();
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await SubmitAndAssertSuccessAsync(simulator, new StartupInput(TpmSuConstants.TPM_SU_CLEAR), pool).ConfigureAwait(false);

        //Build up Time with a few commands before the Restart so the post-Restart drop is unambiguous.
        _ = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);
        _ = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);
        TpmsTimeInfo beforeRestart = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);

        await SubmitAndAssertSuccessAsync(simulator, new ShutdownInput(TpmSuConstants.TPM_SU_STATE), pool).ConfigureAwait(false);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await SubmitAndAssertSuccessAsync(simulator, new StartupInput(TpmSuConstants.TPM_SU_CLEAR), pool).ConfigureAwait(false);

        TpmsTimeInfo afterRestart = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);

        Assert.IsLessThan(beforeRestart.Time, afterRestart.Time, "Time must reset across the Restart, dropping well below its pre-Restart value.");
        Assert.AreEqual(1ul, afterRestart.Time, "Only this ReadClock's own quantum has accumulated since the Restart zeroed Time.");
        Assert.IsGreaterThan(beforeRestart.ClockInfo.Clock, afterRestart.ClockInfo.Clock, "Clock must never reset: it keeps accumulating across the Restart boundary.");
        Assert.AreEqual(beforeRestart.ClockInfo.ResetCount, afterRestart.ClockInfo.ResetCount, "A Restart leaves resetCount untouched.");
        Assert.AreEqual(beforeRestart.ClockInfo.RestartCount + 1u, afterRestart.ClockInfo.RestartCount, "A Restart increments restartCount by exactly one.");
    }

    /// <summary>
    /// Drives real Shutdown/Startup wire commands through the three startup classifications (TPM 2.0 Library
    /// Part 3, clause 9.3) and verifies <c>resetCount</c>/<c>restartCount</c> transition exactly as specified:
    /// a Reset increments resetCount and zeroes restartCount; a Restart or Resume increments restartCount and
    /// leaves resetCount untouched.
    /// </summary>
    [TestMethod]
    public async Task ResetCountAndRestartCountTransitionAcrossResetRestartAndResume()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = CreatePoweredOff();
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await SubmitAndAssertSuccessAsync(simulator, new StartupInput(TpmSuConstants.TPM_SU_CLEAR), pool).ConfigureAwait(false);

        TpmsTimeInfo afterFirstReset = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.AreEqual(1u, afterFirstReset.ClockInfo.ResetCount, "The first-ever Startup(CLEAR) is a TPM Reset.");
        Assert.AreEqual(0u, afterFirstReset.ClockInfo.RestartCount, "No Restart/Resume has occurred yet.");

        //Shutdown(STATE) + Startup(CLEAR): TPM Restart.
        await SubmitAndAssertSuccessAsync(simulator, new ShutdownInput(TpmSuConstants.TPM_SU_STATE), pool).ConfigureAwait(false);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await SubmitAndAssertSuccessAsync(simulator, new StartupInput(TpmSuConstants.TPM_SU_CLEAR), pool).ConfigureAwait(false);

        TpmsTimeInfo afterRestart = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.AreEqual(1u, afterRestart.ClockInfo.ResetCount, "A Restart leaves resetCount untouched.");
        Assert.AreEqual(1u, afterRestart.ClockInfo.RestartCount, "A Restart increments restartCount.");

        //Shutdown(STATE) + Startup(STATE): TPM Resume.
        await SubmitAndAssertSuccessAsync(simulator, new ShutdownInput(TpmSuConstants.TPM_SU_STATE), pool).ConfigureAwait(false);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await SubmitAndAssertSuccessAsync(simulator, new StartupInput(TpmSuConstants.TPM_SU_STATE), pool).ConfigureAwait(false);

        TpmsTimeInfo afterResume = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.AreEqual(1u, afterResume.ClockInfo.ResetCount, "A Resume leaves resetCount untouched.");
        Assert.AreEqual(2u, afterResume.ClockInfo.RestartCount, "A Resume increments restartCount.");

        //Shutdown(CLEAR) + Startup(CLEAR): TPM Reset again.
        await SubmitAndAssertSuccessAsync(simulator, new ShutdownInput(TpmSuConstants.TPM_SU_CLEAR), pool).ConfigureAwait(false);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await SubmitAndAssertSuccessAsync(simulator, new StartupInput(TpmSuConstants.TPM_SU_CLEAR), pool).ConfigureAwait(false);

        TpmsTimeInfo afterSecondReset = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.AreEqual(2u, afterSecondReset.ClockInfo.ResetCount, "A second Reset increments resetCount again.");
        Assert.AreEqual(0u, afterSecondReset.ClockInfo.RestartCount, "A Reset zeroes restartCount.");
    }

    /// <summary>
    /// Verifies that <c>Safe</c> is YES after a fresh simulator's very first TPM Reset (no prior Clock value
    /// could ever have been reported), then becomes NO after a second Reset that followed no orderly
    /// <c>TPM2_Shutdown()</c> — the disorderly-restart case this simulator can distinguish once
    /// <c>resetCount</c> is no longer zero (TPM 2.0 Library Part 1, clause 36.3).
    /// </summary>
    [TestMethod]
    public async Task ClockSafeIsNoAfterAnUnorderlyResetFollowingPriorOperation()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = CreatePoweredOff();
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await SubmitAndAssertSuccessAsync(simulator, new StartupInput(TpmSuConstants.TPM_SU_CLEAR), pool).ConfigureAwait(false);

        TpmsTimeInfo afterFirstReset = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.IsTrue(afterFirstReset.ClockInfo.Safe.IsYes, "A fresh simulator's very first Reset is Safe.");
        Assert.AreEqual(1u, afterFirstReset.ClockInfo.ResetCount);

        //No TPM2_Shutdown() is issued before powering on again: an unorderly restart following prior operation.
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await SubmitAndAssertSuccessAsync(simulator, new StartupInput(TpmSuConstants.TPM_SU_CLEAR), pool).ConfigureAwait(false);

        TpmsTimeInfo afterUnorderlyReset = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);
        Assert.IsFalse(afterUnorderlyReset.ClockInfo.Safe.IsYes, "A Reset with no preceding orderly shutdown, after resetCount was already non-zero, is not Safe.");
        Assert.AreEqual(2u, afterUnorderlyReset.ClockInfo.ResetCount, "The unorderly restart is itself a second TPM Reset.");
        Assert.AreEqual(0u, afterUnorderlyReset.ClockInfo.RestartCount, "A Reset zeroes restartCount.");
    }

    /// <summary>Creates a powered-off simulator needing no asymmetric backend (ReadClock needs none).</summary>
    /// <returns>The powered-off simulator.</returns>
    private static TpmSimulator CreatePoweredOff() => new("tpm-in-house-read-clock");

    /// <summary>Issues one <c>TPM2_ReadClock()</c> and returns the parsed current-time snapshot.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The current <c>TPMS_TIME_INFO</c>.</returns>
    private async Task<TpmsTimeInfo> ReadClockAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool)
    {
        TpmResult<ReadClockResponse> result = await TpmCommandExecutor.ExecuteAsync<ReadClockResponse>(
            tpm, new ReadClockInput(), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ReadClock failed: '{result.ResponseCode}'.");

        ReadClockResponse response = result.Value;

        return response.CurrentTime;
    }

    /// <summary>
    /// Submits a no-sessions command (<c>TPM2_Startup()</c>/<c>TPM2_Shutdown()</c>) directly to the simulator
    /// and asserts a successful response, mirroring how the production executor frames an unauthorized command
    /// on the wire.
    /// </summary>
    /// <param name="simulator">The simulator to submit to.</param>
    /// <param name="input">The command input.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task SubmitAndAssertSuccessAsync(TpmSimulator simulator, ITpmCommandInput input, MemoryPool<byte> pool)
    {
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"'{input.CommandCode}' must succeed at the transport level.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, $"'{input.CommandCode}' must succeed.");
    }

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_ReadClock, TpmResponseCodec.ReadClock);

        return registry;
    }
}
