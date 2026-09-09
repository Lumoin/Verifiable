using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_ClockRateAdjust()</c> against the in-house behavioural <see cref="TpmSimulator"/>, entirely
/// in-process, through the same production command path the production code uses
/// (<see cref="TpmCommandExecutor"/> with the real <see cref="ClockRateAdjustInput"/> and response codec):
/// "This command adjusts the rate of advance of Clock and Time to provide a better approximation to real
/// time. The rateAdjust value is relative to the current rate and not the nominal rate of advance." The
/// observable effect is the number of milliseconds the NEXT admitted command adds to Clock and Time, read
/// back through <c>TPM2_ReadClock()</c>; the range is bounded by "If the requested adjustment would make the
/// rate advance faster or slower than the nominal accuracy of the input frequency, the TPM shall return
/// TPM_RC_VALUE"; and the authorization is the provisioning ladder <c>TPMI_RH_PROVISION</c> names —
/// "TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}", Auth Role USER.
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3, Table 236; Part 2, clauses 6.7 and 9.21; Part 1, clause 33.3.6</see>.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorClockRateAdjustTests
{
    /// <summary>
    /// The oscillator tick contribution every command in this file carries, chosen so a single coarse, medium
    /// or fine step produces a whole number of milliseconds that can be read back exactly.
    /// </summary>
    private const ulong QuantumMs = 1_000ul;

    /// <summary>The milliseconds one command advances Clock and Time while the divisor is unadjusted.</summary>
    private const ulong NominalAdvanceMs = 1_000ul;

    /// <summary>
    /// The number of commands whose accumulated advance is independent of whatever ticks are already banked
    /// while the divisor stands one coarse step faster than nominal: the tick total of this many commands
    /// divides evenly by that divisor, so the sum identifies the divisor on its own.
    /// </summary>
    private const int CoarseFasterWindowCommands = 99;

    /// <summary>The milliseconds <see cref="CoarseFasterWindowCommands"/> commands advance at one coarse step faster than nominal.</summary>
    private const ulong CoarseFasterWindowAdvanceMs = 100_000ul;

    /// <summary>The commands whose accumulated advance identifies the divisor fifteen coarse faster steps reach.</summary>
    private const int FasterBoundWindowCommands = 17;

    /// <summary>The commands whose accumulated advance identifies the divisor fifteen coarse slower steps reach.</summary>
    private const int SlowerBoundWindowCommands = 23;

    /// <summary>The milliseconds either bound window advances while the divisor stands at the permitted extreme.</summary>
    private const ulong BoundWindowAdvanceMs = 20_000ul;

    /// <summary>The commands whose accumulated advance identifies the divisor two coarse slower steps reach.</summary>
    private const int TwoCoarseSlowerWindowCommands = 51;

    /// <summary>The milliseconds <see cref="TwoCoarseSlowerWindowCommands"/> commands advance two coarse steps slower than nominal.</summary>
    private const ulong TwoCoarseSlowerWindowAdvanceMs = 50_000ul;

    /// <summary>How many coarse steps the fifteen-percent accuracy requirement admits in either direction.</summary>
    private const int CoarseStepsToTheBound = 15;

    /// <summary>An NV Index handle, offered as an inadmissible <c>@auth</c> value.</summary>
    private const uint NvIndexHandle = 0x0100_0130;

    /// <summary>A transient-range handle, offered as an inadmissible <c>@auth</c> value.</summary>
    private const uint TransientRangeHandle = 0x8000_0000;

    /// <summary>An authorization value installed on the platform hierarchy before its arm is exercised.</summary>
    private static byte[] InstalledPlatformAuth { get; } = [0x5E, 0x4D, 0x3C, 0x2B, 0x1A];

    /// <summary>An authorization value no hierarchy in these tests ever carries.</summary>
    private static byte[] WrongAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// "A TPM_CLOCK_ADJUST value in Table 19 is used to change the rate at which the TPM internal oscillator is
    /// divided. A change to the divider will change the rate at which Clock and Time change." Reading Clock
    /// either side of one adjustment shows the change taking effect on the command that FOLLOWS it: the
    /// adjusting command itself is stamped at the rate then in force, so the gap between the two readings is
    /// one nominal advance plus the first advance at the newly requested rate.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3.1; Part 2, clause 6.7, Table 19</see>.
    /// </summary>
    /// <param name="rateAdjust">The requested Table 19 step.</param>
    /// <param name="expectedFirstAdvanceMs">The milliseconds the first command at the new rate advances Clock.</param>
    [TestMethod]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER, 990ul, DisplayName = "one coarse step slower buys 990 ms per command")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_SLOWER, 999ul, DisplayName = "one medium step slower buys 999 ms per command")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_FINE_SLOWER, 999ul, DisplayName = "one fine step slower buys 999 ms and banks the rest")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE, 1_000ul, DisplayName = "no change leaves the nominal advance")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_FINE_FASTER, 1_000ul, DisplayName = "one fine step faster buys 1 000 ms and banks the rest")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_FASTER, 1_001ul, DisplayName = "one medium step faster buys 1 001 ms per command")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER, 1_010ul, DisplayName = "one coarse step faster buys 1 010 ms per command")]
    public async Task ClockRateAdjustGovernsTheAdvanceOfTheCommandThatFollowsIt(TpmClockAdjustConstants rateAdjust, ulong expectedFirstAdvanceMs)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmsTimeInfo before = await ReadClockAsync(device, registry, pool).ConfigureAwait(false);

        await AdjustAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, rateAdjust).ConfigureAwait(false);

        TpmsTimeInfo after = await ReadClockAsync(device, registry, pool).ConfigureAwait(false);

        Assert.AreEqual(
            NominalAdvanceMs + expectedFirstAdvanceMs, after.ClockInfo.Clock - before.ClockInfo.Clock,
            $"The adjusting command is stamped at the old rate and only the following one at '{rateAdjust}'.");
    }

    /// <summary>
    /// "A change to the divider will change the rate at which Clock and Time change." — the divisor governs
    /// both counters at once, so an adjusted command adds exactly the same number of milliseconds to Time as it
    /// adds to Clock, in both directions.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.7; Part 3, clause 29.3.1</see>.
    /// </summary>
    /// <param name="rateAdjust">The requested Table 19 step.</param>
    /// <param name="expectedAdvanceMs">The milliseconds one command then advances both counters.</param>
    [TestMethod]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER, 1_010ul, DisplayName = "a faster rate advances Time and Clock together")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER, 990ul, DisplayName = "a slower rate advances Time and Clock together")]
    public async Task ClockRateAdjustAdvancesTimeAndClockByTheSameAmount(TpmClockAdjustConstants rateAdjust, ulong expectedAdvanceMs)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await AdjustAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, rateAdjust).ConfigureAwait(false);

        (ulong clockAdvance, ulong timeAdvance) = await MeasureNextAdvanceAsync(device, registry, pool).ConfigureAwait(false);

        Assert.AreEqual(expectedAdvanceMs, clockAdvance, $"'{rateAdjust}' must buy '{expectedAdvanceMs}' milliseconds of Clock per command.");
        Assert.AreEqual(clockAdvance, timeAdvance, "Time and Clock are driven by the same divisor and advance by the same amount.");
    }

    /// <summary>
    /// "The interpretation of "fine" and "coarse" adjustments is implementation-specific." — a coarse step
    /// slower buys 990 milliseconds per command yet leaves ticks unconsumed each time, and those banked ticks
    /// are not dropped: after eleven commands the accumulated advance is one millisecond MORE than eleven times
    /// the per-command figure, which is the whole point of carrying the remainder forward.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3.1; Part 2, clause 6.7</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockRateAdjustBanksTheTicksACoarseSlowerDivisionLeavesAndSurfacesThemLater()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await AdjustAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER).ConfigureAwait(false);

        (ulong accumulated, _) = await MeasureAdvanceOverAsync(device, registry, pool, commandCount: 11).ConfigureAwait(false);

        Assert.AreEqual(
            (11ul * 990ul) + 1ul, accumulated,
            "Eleven commands at 990 milliseconds each advance one millisecond further, because the ticks each division left over were banked rather than dropped.");
    }

    /// <summary>
    /// The same banking at the finest step, where the effect is most visible: a fine step faster buys the plain
    /// quantum on most commands, and the millisecond the divisor has been quietly accumulating surfaces on the
    /// thirtieth command after the adjustment.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3.1; Part 2, clause 6.7, Table 19</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockRateAdjustBanksTheTicksAFineFasterDivisionLeavesUntilTheThirtiethCommand()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await AdjustAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmClockAdjustConstants.TPM_CLOCK_FINE_FASTER).ConfigureAwait(false);

        //The first two commands after the adjustment are the second and third of the thirty this case counts.
        (ulong earlyAdvance, _) = await MeasureNextAdvanceAsync(device, registry, pool).ConfigureAwait(false);
        await IssueReadClocksAsync(device, registry, pool, count: 26).ConfigureAwait(false);
        (ulong thirtiethAdvance, _) = await MeasureNextAdvanceAsync(device, registry, pool).ConfigureAwait(false);

        Assert.AreEqual(NominalAdvanceMs, earlyAdvance, "A fine step faster buys the plain quantum on the early commands while the ticks accumulate.");
        Assert.AreEqual(NominalAdvanceMs + 1ul, thirtiethAdvance, "The thirtieth command after the adjustment is the one the accumulated tick finally pays for.");
    }

    /// <summary>
    /// "The rateAdjust value is relative to the current rate and not the nominal rate of advance." — the
    /// specification's own worked example: "If this command had been called three times with rateAdjust =
    /// TPM_CLOCK_COARSE_SLOWER and once with rateAdjust = TPM_CLOCK_COARSE_FASTER, the net effect will be as if
    /// the command had been called twice with rateAdjust = TPM_CLOCK_COARSE_SLOWER." Two simulated TPMs given
    /// those two sequences advance identically over a window whose tick total the resulting divisor consumes
    /// evenly, so the comparison depends on the divisor alone and not on whatever ticks either has banked.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ThreeCoarseSlowerStepsAndOneCoarseFasterStepAdvanceLikeTwoCoarseSlowerSteps()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator mixedSimulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice mixedDevice = TpmDevice.Create(mixedSimulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        using TpmSimulator twiceSimulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice twiceDevice = TpmDevice.Create(twiceSimulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await AdjustRepeatedlyAsync(mixedDevice, pool, registry, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER, 3).ConfigureAwait(false);
        await AdjustRepeatedlyAsync(mixedDevice, pool, registry, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER, 1).ConfigureAwait(false);
        await AdjustRepeatedlyAsync(twiceDevice, pool, registry, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER, 2).ConfigureAwait(false);

        (ulong mixedAdvance, _) = await MeasureAdvanceOverAsync(mixedDevice, registry, pool, TwoCoarseSlowerWindowCommands).ConfigureAwait(false);
        (ulong twiceAdvance, _) = await MeasureAdvanceOverAsync(twiceDevice, registry, pool, TwoCoarseSlowerWindowCommands).ConfigureAwait(false);

        Assert.AreEqual(TwoCoarseSlowerWindowAdvanceMs, twiceAdvance, "Two coarse steps slower must advance the window by exactly the divisor those steps produce.");
        Assert.AreEqual(twiceAdvance, mixedAdvance, "Three coarse steps slower then one faster leave the same rate as two slower, so the same window buys the same milliseconds.");
    }

    /// <summary>
    /// "The range of adjustment shall be sufficient to allow Clock and Time to advance at real time but no
    /// more. If the requested adjustment would make the rate advance faster or slower than the nominal accuracy
    /// of the input frequency, the TPM shall return TPM_RC_VALUE." — with the accuracy requirement at 15 percent
    /// ("with no adjustment applied, Clock and Time shall be advanced at a rate within 15 percent of actual
    /// time"), fifteen coarse steps are admitted in either direction and the sixteenth is refused, leaving the
    /// rate the fifteenth produced still in force.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3.1; Part 1, clause 33.3.6</see>.
    /// </summary>
    /// <param name="rateAdjust">The coarse step repeated toward the bound.</param>
    /// <param name="windowCommands">The commands whose accumulated advance identifies the divisor at that bound.</param>
    [TestMethod]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER, FasterBoundWindowCommands, DisplayName = "fifteen coarse steps faster are admitted and the sixteenth is refused")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER, SlowerBoundWindowCommands, DisplayName = "fifteen coarse steps slower are admitted and the sixteenth is refused")]
    public async Task FifteenCoarseStepsAreAdmittedAndTheSixteenthIsRefusedWithValue(TpmClockAdjustConstants rateAdjust, int windowCommands)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await AdjustRepeatedlyAsync(device, pool, registry, rateAdjust, CoarseStepsToTheBound).ConfigureAwait(false);

        TpmResult<ClockRateAdjustResponse> refused = await ClockRateAdjustAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, rateAdjust).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), refused.ResponseCode, $"A sixteenth '{rateAdjust}' step leaves the 15 percent accuracy requirement and must be refused.");

        (ulong accumulated, _) = await MeasureAdvanceOverAsync(device, registry, pool, windowCommands).ConfigureAwait(false);

        Assert.AreEqual(BoundWindowAdvanceMs, accumulated, "A refused step leaves the rate exactly as the fifteenth admitted step left it.");
    }

    /// <summary>
    /// The bound is judged on the resulting rate, not on the size of the step: standing at the extreme fifteen
    /// coarse steps reach, in EITHER direction, a medium step and a fine step of the SAME direction are each
    /// refused with <c>TPM_RC_VALUE</c> because either would carry the rate past the accuracy requirement, and
    /// the rate is left untouched.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3.1; Part 1, clause 33.3.6</see>.
    /// </summary>
    /// <param name="extreme">The coarse step repeated to the bound.</param>
    /// <param name="rateAdjust">The smaller step of the same direction attempted from the bound.</param>
    /// <param name="windowCommands">The commands whose accumulated advance identifies the divisor at that bound.</param>
    [TestMethod]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER, TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_FASTER, FasterBoundWindowCommands, DisplayName = "a medium step past the faster bound is refused")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER, TpmClockAdjustConstants.TPM_CLOCK_FINE_FASTER, FasterBoundWindowCommands, DisplayName = "a fine step past the faster bound is refused")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER, TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_SLOWER, SlowerBoundWindowCommands, DisplayName = "a medium step past the slower bound is refused")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER, TpmClockAdjustConstants.TPM_CLOCK_FINE_SLOWER, SlowerBoundWindowCommands, DisplayName = "a fine step past the slower bound is refused")]
    public async Task ASmallerStepPastTheBoundIsRefusedWithValueAndLeavesTheRateUnchanged(
        TpmClockAdjustConstants extreme, TpmClockAdjustConstants rateAdjust, int windowCommands)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await AdjustRepeatedlyAsync(device, pool, registry, extreme, CoarseStepsToTheBound).ConfigureAwait(false);

        TpmResult<ClockRateAdjustResponse> refused = await ClockRateAdjustAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, rateAdjust).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), refused.ResponseCode, $"'{rateAdjust}' from the '{extreme}' extreme would still leave the accuracy requirement.");

        (ulong accumulated, _) = await MeasureAdvanceOverAsync(device, registry, pool, windowCommands).ConfigureAwait(false);

        Assert.AreEqual(BoundWindowAdvanceMs, accumulated, "A refused step leaves the rate exactly where the coarse steps left it.");
    }

    /// <summary>
    /// Table 19's <c>TPM_CLOCK_NO_CHANGE</c> is an admitted value that asks for nothing: the command succeeds
    /// and the milliseconds the next command buys are the same nominal quantum as before.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.7, Table 19; Part 3, clause 29.3</see>.
    /// </summary>
    [TestMethod]
    public async Task NoChangeSucceedsAndLeavesTheAdvanceExactlyWhereItWas()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (ulong beforeAdvance, _) = await MeasureNextAdvanceAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<ClockRateAdjustResponse> result = await ClockRateAdjustAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"TPM_CLOCK_NO_CHANGE is one of Table 19's values and must be admitted: '{result.ResponseCode}'.");

        (ulong afterAdvance, _) = await MeasureNextAdvanceAsync(device, registry, pool).ConfigureAwait(false);

        Assert.AreEqual(NominalAdvanceMs, beforeAdvance, "An unadjusted rate advances by exactly the quantum.");
        Assert.AreEqual(beforeAdvance, afterAdvance, "TPM_CLOCK_NO_CHANGE must leave the rate exactly as it stood.");
    }

    /// <summary>
    /// Table 19 carries <c>#TPM_RC_VALUE</c>, so an octet the wire delivered outside its seven values is
    /// refused with the bare code — and the refusal happens where the specification's ordering puts it, in the
    /// parameter-unmarshaling step that follows the authorization checks, so a correctly authorized frame gets
    /// as far as being judged on its parameter at all. The rate is left untouched.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.7, Table 19; Part 3, clauses 5.6, 5.8 and 29.3</see>.
    /// </summary>
    /// <param name="rateAdjustOctet">The raw octet framed in place of a Table 19 value.</param>
    [TestMethod]
    [DataRow((byte)0x04, DisplayName = "04 is one past the fastest step Table 19 lists")]
    [DataRow((byte)0x7F, DisplayName = "7F is the most positive INT8, outside Table 19")]
    [DataRow((byte)0x80, DisplayName = "80 is the most negative INT8, outside Table 19")]
    [DataRow((byte)0xFC, DisplayName = "FC is -4, one past the slowest step Table 19 lists")]
    public async Task AnOctetOutsideTable19IsRefusedWithValueAfterACorrectAuthorization(byte rateAdjustOctet)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmRcConstants code = await SubmitClockRateAdjustFrameAsync(
            simulator, pool, (uint)TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, [rateAdjustOctet]).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), code, $"The octet '{rateAdjustOctet}' names no Table 19 step, so the command is refused with the table's own code.");

        (ulong advance, _) = await MeasureNextAdvanceAsync(device, registry, pool).ConfigureAwait(false);

        Assert.AreEqual(NominalAdvanceMs, advance, "A refused adjustment must leave the rate at nominal.");
    }

    /// <summary>
    /// The order the specification fixes, proved from the other side: "5.6 Authorization Checks" precedes "5.8
    /// Parameter Unmarshaling", so the same out-of-table octet presented with a wrong authorization value earns
    /// <c>TPM_RC_BAD_AUTH</c> and never reaches the judgment on its parameter.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.6 and 5.8; Part 2, clause 6.7, Table 19</see>.
    /// </summary>
    /// <param name="rateAdjustOctet">The raw octet framed in place of a Table 19 value.</param>
    [TestMethod]
    [DataRow((byte)0x04, DisplayName = "04 behind a wrong authorization is a bad-auth refusal")]
    [DataRow((byte)0x7F, DisplayName = "7F behind a wrong authorization is a bad-auth refusal")]
    [DataRow((byte)0x80, DisplayName = "80 behind a wrong authorization is a bad-auth refusal")]
    [DataRow((byte)0xFC, DisplayName = "FC behind a wrong authorization is a bad-auth refusal")]
    public async Task AnOctetOutsideTable19BehindAWrongAuthorizationIsRefusedWithBadAuthInstead(byte rateAdjustOctet)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        TpmRcConstants code = await SubmitClockRateAdjustFrameAsync(
            simulator, pool, (uint)TpmRh.TPM_RH_OWNER, WrongAuth, [rateAdjustOctet]).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), code, "The authorization is judged first, so the parameter is never reached.");
        Assert.AreNotEqual(TpmRcConstants.TPM_RC_VALUE, code, "A frame that fails authorization must not be answered with its parameter's code.");
    }

    /// <summary>
    /// "The TPM may store adjustments to the nominal clock rate in volatile memory." — this TPM keeps the
    /// adjustment where Clock itself lives, so a <c>TPM2_Shutdown(STATE)</c> followed by <c>TPM2_Startup(STATE)</c>
    /// (a TPM Resume) leaves the requested rate in force, proved by the milliseconds a window of commands buys
    /// on the far side of the cycle.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 33.3.6; Part 3, clauses 9.3 and 29.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task TheAdjustedRateSurvivesAShutdownStateAndStartupStateResume()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await AdjustAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER).ConfigureAwait(false);
        (ulong beforeCycle, _) = await MeasureAdvanceOverAsync(device, registry, pool, CoarseFasterWindowCommands).ConfigureAwait(false);

        await SubmitSessionlessAsync(simulator, pool, new ShutdownInput(TpmSuConstants.TPM_SU_STATE)).ConfigureAwait(false);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await SubmitSessionlessAsync(simulator, pool, new StartupInput(TpmSuConstants.TPM_SU_STATE)).ConfigureAwait(false);

        (ulong afterCycle, _) = await MeasureAdvanceOverAsync(device, registry, pool, CoarseFasterWindowCommands).ConfigureAwait(false);

        Assert.AreEqual(CoarseFasterWindowAdvanceMs, beforeCycle, "One coarse step faster must be in force before the cycle.");
        Assert.AreEqual(beforeCycle, afterCycle, "A Resume must leave the requested rate exactly as it stood.");
    }

    /// <summary>
    /// The same persistence across the harder cycle: a <c>TPM2_Shutdown(CLEAR)</c> followed by
    /// <c>TPM2_Startup(CLEAR)</c> is a TPM Reset, which zeroes Time and the restart counter but does not undo
    /// the rate at which both counters advance.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 33.3.6; Part 3, clauses 9.3 and 29.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task TheAdjustedRateSurvivesAShutdownClearAndStartupClearReset()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await AdjustAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER).ConfigureAwait(false);
        (ulong beforeCycle, _) = await MeasureAdvanceOverAsync(device, registry, pool, CoarseFasterWindowCommands).ConfigureAwait(false);

        await SubmitSessionlessAsync(simulator, pool, new ShutdownInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await SubmitSessionlessAsync(simulator, pool, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false);

        (ulong afterCycle, _) = await MeasureAdvanceOverAsync(device, registry, pool, CoarseFasterWindowCommands).ConfigureAwait(false);

        Assert.AreEqual(CoarseFasterWindowAdvanceMs, beforeCycle, "One coarse step faster must be in force before the cycle.");
        Assert.AreEqual(beforeCycle, afterCycle, "A Reset must leave the requested rate exactly as it stood.");
    }

    /// <summary>
    /// The rate also survives the cycle no orderly shutdown precedes: <c>_TPM_Init</c> and a bare
    /// <c>TPM2_Startup(CLEAR)</c>, the disorderly restart that marks Clock unsafe, still leave the requested
    /// rate governing the advance.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 33.3 and 33.3.6; Part 3, clauses 9.3 and 29.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task TheAdjustedRateSurvivesABareStartupClearAfterAnInitializationWithNoOrderlyShutdown()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await AdjustAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER).ConfigureAwait(false);
        (ulong beforeCycle, _) = await MeasureAdvanceOverAsync(device, registry, pool, CoarseFasterWindowCommands).ConfigureAwait(false);

        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await SubmitSessionlessAsync(simulator, pool, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false);

        (ulong afterCycle, _) = await MeasureAdvanceOverAsync(device, registry, pool, CoarseFasterWindowCommands).ConfigureAwait(false);

        Assert.AreEqual(CoarseFasterWindowAdvanceMs, beforeCycle, "One coarse step faster must be in force before the initialization.");
        Assert.AreEqual(beforeCycle, afterCycle, "An initialization with no preceding orderly shutdown must leave the requested rate exactly as it stood.");
    }

    /// <summary>
    /// <c>TPM2_Clear()</c> discards the storage hierarchy's state; the rate at which Clock and Time advance is
    /// not part of what it discards, so the requested adjustment is still in force after a Clear.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 33.3.6; Part 3, clauses 24.6 and 29.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task TheAdjustedRateSurvivesTpm2Clear()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await AdjustAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER).ConfigureAwait(false);
        (ulong beforeClear, _) = await MeasureAdvanceOverAsync(device, registry, pool, CoarseFasterWindowCommands).ConfigureAwait(false);

        await ClearAsync(device, pool, registry).ConfigureAwait(false);

        (ulong afterClear, _) = await MeasureAdvanceOverAsync(device, registry, pool, CoarseFasterWindowCommands).ConfigureAwait(false);

        Assert.AreEqual(CoarseFasterWindowAdvanceMs, beforeClear, "One coarse step faster must be in force before the Clear.");
        Assert.AreEqual(beforeClear, afterClear, "TPM2_Clear() must leave the requested rate exactly as it stood.");
    }

    /// <summary>
    /// <c>@auth</c> is a <c>TPMI_RH_PROVISION</c>: "TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}", Auth Role USER. The
    /// owner hierarchy authorizes the command under its factory-empty <c>ownerAuth</c>, and the adjustment
    /// lands — the following command advances at the requested rate.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3, Table 236; Part 2, clause 9.21, Table 67</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockRateAdjustUnderTheFactoryEmptyOwnerAuthAdjusts()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<ClockRateAdjustResponse> result = await ClockRateAdjustAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"The owner hierarchy authorizes TPM2_ClockRateAdjust(): '{result.ResponseCode}'.");

        (ulong advance, _) = await MeasureNextAdvanceAsync(device, registry, pool).ConfigureAwait(false);

        Assert.AreEqual(1_010ul, advance, "An owner-authorized coarse step faster must take effect.");
    }

    /// <summary>
    /// The other selector Table 67 admits, under its factory-empty <c>platformAuth</c>: the platform hierarchy
    /// authorizes the very same command and the very same effect.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3, Table 236; Part 2, clause 9.21, Table 67</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockRateAdjustUnderTheFactoryEmptyPlatformAuthAdjusts()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<ClockRateAdjustResponse> result = await ClockRateAdjustAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"The platform hierarchy authorizes TPM2_ClockRateAdjust(): '{result.ResponseCode}'.");

        (ulong advance, _) = await MeasureNextAdvanceAsync(device, registry, pool).ConfigureAwait(false);

        Assert.AreEqual(1_010ul, advance, "A platform-authorized coarse step faster must take effect.");
    }

    /// <summary>
    /// The platform arm against a real authorization value rather than the factory-empty one: with
    /// <c>platformAuth</c> replaced through <c>TPM2_HierarchyChangeAuth()</c>, the installed value authorizes
    /// the adjustment and the effect lands.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 24.8 and 29.3; Part 2, clause 9.21, Table 67</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockRateAdjustUnderAnInstalledPlatformAuthAdjusts()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await InstallHierarchyAuthAsync(device, pool, registry, TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, InstalledPlatformAuth).ConfigureAwait(false);

        TpmResult<ClockRateAdjustResponse> result = await ClockRateAdjustAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_PLATFORM, InstalledPlatformAuth, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"An installed platformAuth authorizes TPM2_ClockRateAdjust(): '{result.ResponseCode}'.");

        (ulong advance, _) = await MeasureNextAdvanceAsync(device, registry, pool).ConfigureAwait(false);

        Assert.AreEqual(1_010ul, advance, "An adjustment authorized by an installed platformAuth must take effect.");
    }

    /// <summary>
    /// "the authValue associated with a permanent entity, other than TPM_RH_LOCKOUT, does not receive DA
    /// protection" — a wrong value offered for either provisioning hierarchy is <c>TPM_RC_BAD_AUTH</c> rather
    /// than <c>TPM_RC_AUTH_FAIL</c>, the lockout counter is untouched, and the rate is left at nominal.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 3, clause 29.3</see>.
    /// </summary>
    /// <param name="authHandle">The provisioning hierarchy the wrong value is offered for.</param>
    [TestMethod]
    [DataRow((uint)TpmRh.TPM_RH_OWNER, DisplayName = "a wrong ownerAuth is refused uncharged")]
    [DataRow((uint)TpmRh.TPM_RH_PLATFORM, DisplayName = "a wrong platformAuth is refused uncharged")]
    public async Task ClockRateAdjustWithAWrongAuthorizationValueReturnsBadAuthUncharged(uint authHandle)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<ClockRateAdjustResponse> result = await ClockRateAdjustAsync(
            device, pool, registry, authHandle, WrongAuth, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), result.ResponseCode, "A provisioning hierarchy is DA-exempt, so a wrong value is TPM_RC_BAD_AUTH.");
        Assert.AreEqual(
            counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "A permanent entity other than TPM_RH_LOCKOUT receives no DA protection, so the refusal charges no failedTries.");

        (ulong advance, _) = await MeasureNextAdvanceAsync(device, registry, pool).ConfigureAwait(false);

        Assert.AreEqual(NominalAdvanceMs, advance, "A refused command runs no part of the adjustment.");
    }

    /// <summary>
    /// <c>@auth</c> is a <c>TPMI_RH_PROVISION</c>, whose only values are <c>TPM_RH_OWNER</c> and
    /// <c>TPM_RH_PLATFORM</c>: the endorsement and lockout hierarchies, the NULL hierarchy, an NV Index handle
    /// and a transient-range handle are each refused with the <c>TPM_RC_VALUE</c>, handle-encoded to the same index that interface type's own
    /// membership check answers, ahead of any authorization, and the rate is untouched.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.21, Table 67; Part 3, clause 29.3, Table 236</see>.
    /// </summary>
    /// <param name="authHandle">The inadmissible handle offered as <c>@auth</c>.</param>
    [TestMethod]
    [DataRow((uint)TpmRh.TPM_RH_ENDORSEMENT, DisplayName = "TPM_RH_ENDORSEMENT is not a provisioning selector")]
    [DataRow((uint)TpmRh.TPM_RH_LOCKOUT, DisplayName = "TPM_RH_LOCKOUT is not a provisioning selector")]
    [DataRow((uint)TpmRh.TPM_RH_NULL, DisplayName = "TPM_RH_NULL is not a provisioning selector")]
    [DataRow(NvIndexHandle, DisplayName = "an NV Index handle is not a provisioning selector")]
    [DataRow(TransientRangeHandle, DisplayName = "a transient-range handle is not a provisioning selector")]
    public async Task ClockRateAdjustWithANonProvisionAuthHandleReturnsValue(uint authHandle)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<ClockRateAdjustResponse> result = await ClockRateAdjustAsync(
            device, pool, registry, authHandle, ReadOnlyMemory<byte>.Empty, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), result.ResponseCode, "TPMI_RH_PROVISION admits TPM_RH_OWNER and TPM_RH_PLATFORM alone.");

        (ulong advance, _) = await MeasureNextAdvanceAsync(device, registry, pool).ConfigureAwait(false);

        Assert.AreEqual(NominalAdvanceMs, advance, "A handle the interface type refuses runs no part of the command's effect.");
    }

    /// <summary>
    /// "If the handle references a primary seed for a hierarchy (TPM_RH_ENDORSEMENT, TPM_RH_OWNER, or
    /// TPM_RH_PLATFORM) then the enable for the hierarchy is SET (TPM_RC_HIERARCHY)" — with <c>shEnable</c>
    /// CLEARed by <c>TPM2_HierarchyControl()</c> under Platform Authorization, the owner arm is
    /// <c>TPM_RC_HIERARCHY</c> while the platform arm still adjusts the very same rate.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.4, 24.2.1 and 29.3; Part 1, clause 10.2, Table 8</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockRateAdjustUnderADisabledOwnerHierarchyReturnsHierarchyWhileThePlatformArmAdjusts()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DisableHierarchyAsync(device, pool, registry, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        TpmResult<ClockRateAdjustResponse> ownerArm = await ClockRateAdjustAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), ownerArm.ResponseCode, "A disabled hierarchy is refused before its authorization value is compared.");

        TpmResult<ClockRateAdjustResponse> platformArm = await ClockRateAdjustAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER).ConfigureAwait(false);

        Assert.IsTrue(platformArm.IsSuccess, $"Platform Authorization is unaffected by shEnable: '{platformArm.ResponseCode}'.");

        (ulong advance, _) = await MeasureNextAdvanceAsync(device, registry, pool).ConfigureAwait(false);

        Assert.AreEqual(1_010ul, advance, "Exactly one of the two arms adjusted the rate, and it was the platform one.");
    }

    /// <summary>
    /// Table 236's <c>tag</c> row is <c>TPM_ST_SESSIONS</c> without qualification, and "If the tag is
    /// TPM_ST_NO_SESSIONS and the command requires TPM_ST_SESSIONS, the TPM will return TPM_RC_AUTH_MISSING" —
    /// a sessionless frame is refused before anything else about it is judged.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.5 and 29.3, Table 236</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockRateAdjustFramedWithoutSessionsReturnsAuthMissing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        var body = new List<byte>();
        AppendUInt32(body, (uint)TpmRh.TPM_RH_OWNER);
        body.Add((byte)0x03);

        TpmRcConstants code = await SubmitFramedAsync(simulator, pool, TpmStConstants.TPM_ST_NO_SESSIONS, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_MISSING, code, "TPM2_ClockRateAdjust() requires TPM_ST_SESSIONS.");
    }

    /// <summary>
    /// "the input buffer did not contain enough octets to allow unmarshaling of the expected data type" — a
    /// frame whose handle area is cut short cannot yield <c>@auth</c> at all and is <c>TPM_RC_INSUFFICIENT</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.8.2, Table 2; clause 29.3, Table 236</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockRateAdjustWithATruncatedHandleReturnsInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        TpmRcConstants code = await SubmitFramedAsync(simulator, pool, TpmStConstants.TPM_ST_SESSIONS, [0x40, 0x00, 0x00]).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, handleIndex: 0), code,
            "Table 236: @auth is TPM2_ClockRateAdjust()'s sole handle (index 0); three octets cannot carry its four octets.");
    }

    /// <summary>
    /// The same rule at the other end of the frame: an authorization area followed by no parameter at all
    /// leaves the single <c>rateAdjust</c> octet Table 236 requires unread, which is
    /// <c>TPM_RC_INSUFFICIENT</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.8.2, Table 2; clause 29.3, Table 236</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockRateAdjustWithoutItsParameterOctetReturnsInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        TpmRcConstants code = await SubmitClockRateAdjustFrameAsync(
            simulator, pool, (uint)TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, []).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, parameterIndex: 0), code,
            "Table 236: rateAdjust is TPM2_ClockRateAdjust()'s sole parameter (index 0), and its octet is not optional.");
    }

    /// <summary>
    /// <c>rateAdjust</c> is Table 236's final parameter, so the command's octets end with it: an octet after it
    /// makes the frame inconsistent with the size the header declared and is <c>TPM_RC_SIZE</c> — "the value of
    /// a size parameter is larger or smaller than allowed".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.2 and 5.8.2, Table 2; clause 29.3, Table 236</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockRateAdjustWithATrailingOctetReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        TpmRcConstants code = await SubmitClockRateAdjustFrameAsync(
            simulator, pool, (uint)TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, [0x03, 0x00]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "An octet after the final parameter must be refused with TPM_RC_SIZE.");
    }

    /// <summary>
    /// The password form returns every carrier its parse rented on each path this command's ladder takes: the
    /// handle refusal at the transition head, the hierarchy refusal at the availability gate, the bad-value
    /// refusal at the compare, the Table 19 refusal in the tail behind a correct authorization, and the
    /// accepting transition — the metered pool returns to its baseline after each.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.4, 5.6 and 29.3</see>.
    /// </summary>
    [TestMethod]
    public async Task ClockRateAdjustReturnsItsCarriersAcrossRefusalsAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        await DisableHierarchyAsync(device, pool, registry, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<ClockRateAdjustResponse> handleRefusal = await ClockRateAdjustAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), handleRefusal.ResponseCode, "Table 236: auth is TPM2_ClockRateAdjust()'s sole handle (handle 1); a hierarchy handle outside TPM_RH_OWNER/TPM_RH_PLATFORM is handle-encoded TPM_RC_VALUE at index 0.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refusal at the transition head releases the supplied credential through the request's own Dispose.");

        TpmResult<ClockRateAdjustResponse> hierarchyRefusal = await ClockRateAdjustAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HIERARCHY, 0), hierarchyRefusal.ResponseCode, "Table 236: auth is TPM2_ClockRateAdjust()'s sole handle (handle 1); a disabled hierarchy is handle-encoded TPM_RC_HIERARCHY at index 0.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refusal at the availability gate releases the supplied credential through the request's own Dispose.");

        TpmResult<ClockRateAdjustResponse> badAuthRefusal = await ClockRateAdjustAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_PLATFORM, WrongAuth, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), badAuthRefusal.ResponseCode, "auth's authorizing session is session 1 of Table 236 (TPM 2.0 Library Part 2, clause 6.6.2); a wrong platformAuth password is session-encoded TPM_RC_BAD_AUTH there.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refusal at the value compare releases the supplied credential through the request's own Dispose.");

        TpmRcConstants tableRefusal = await SubmitClockRateAdjustFrameAsync(
            simulator, pool, (uint)TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, [0x04]).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), tableRefusal, "Table 236: rateAdjust is TPM2_ClockRateAdjust()'s sole parameter (parameter 1); an out-of-range table byte is parameter-encoded TPM_RC_VALUE at index 0.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refusal in the tail behind a correct authorization releases the supplied credential too.");

        TpmResult<ClockRateAdjustResponse> accepted = await ClockRateAdjustAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_PLATFORM, ReadOnlyMemory<byte>.Empty, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER).ConfigureAwait(false);
        Assert.IsTrue(accepted.IsSuccess, $"TPM2_ClockRateAdjust() failed: '{accepted.ResponseCode}'.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The accepting transition is the credential's terminal owner and must release it.");
    }

    /// <summary>
    /// Creates a simulator whose per-command oscillator contribution is <see cref="QuantumMs"/>, powers it on,
    /// and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase, which is the precondition
    /// <c>TPM2_ClockRateAdjust()</c> carries.
    /// </summary>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync()
    {
        var simulator = new TpmSimulator("tpm-in-house-clock-rate-adjust", clockAdvanceQuantumMs: QuantumMs, rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        await SubmitSessionlessAsync(simulator, BaseMemoryPool.Shared, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase, "The command's precondition is the operational phase.");

        return simulator;
    }

    /// <summary>Creates a response codec registry for the commands these tests drive.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_ReadClock, TpmResponseCodec.ReadClock)
            .Register(TpmCcConstants.TPM_CC_ClockRateAdjust, TpmResponseCodec.ClockRateAdjust)
            .Register(TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmResponseCodec.HierarchyChangeAuth)
            .Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl)
            .Register(TpmCcConstants.TPM_CC_Clear, TpmResponseCodec.Clear)
            .Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);

    /// <summary>Issues one <c>TPM2_ReadClock()</c> and returns the parsed current-time snapshot.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The current <c>TPMS_TIME_INFO</c>.</returns>
    private async Task<TpmsTimeInfo> ReadClockAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        TpmResult<ReadClockResponse> result = await TpmCommandExecutor.ExecuteAsync<ReadClockResponse>(
            device, new ReadClockInput(), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ReadClock failed: '{result.ResponseCode}'.");

        ReadClockResponse response = result.Value;

        return response.CurrentTime;
    }

    /// <summary>
    /// Issues one password-authorized <c>TPM2_ClockRateAdjust()</c> and returns its result unexamined, so a
    /// refusal is the caller's to assert on.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorizing handle, admissible or not.</param>
    /// <param name="suppliedAuth">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <param name="rateAdjust">The requested Table 19 step.</param>
    /// <returns>The rate-adjust result.</returns>
    private async Task<TpmResult<ClockRateAdjustResponse>> ClockRateAdjustAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint authHandle, ReadOnlyMemory<byte> suppliedAuth,
        TpmClockAdjustConstants rateAdjust)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var input = new ClockRateAdjustInput((TpmRh)authHandle, rateAdjust);

        return await TpmCommandExecutor.ExecuteAsync<ClockRateAdjustResponse>(
            device, input, [session], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues one <c>TPM2_ClockRateAdjust()</c> and asserts it was admitted.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorizing hierarchy.</param>
    /// <param name="suppliedAuth">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <param name="rateAdjust">The requested Table 19 step.</param>
    private async Task AdjustAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh authHandle, ReadOnlyMemory<byte> suppliedAuth,
        TpmClockAdjustConstants rateAdjust)
    {
        TpmResult<ClockRateAdjustResponse> result = await ClockRateAdjustAsync(device, pool, registry, (uint)authHandle, suppliedAuth, rateAdjust).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ClockRateAdjust('{rateAdjust}') failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Issues <paramref name="count"/> successful owner-authorized adjustments of the same step — the way a run
    /// of steps toward the permitted extreme is built up before the step that crosses it is attempted.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="rateAdjust">The step to repeat.</param>
    /// <param name="count">How many times to apply it.</param>
    private async Task AdjustRepeatedlyAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmClockAdjustConstants rateAdjust, int count)
    {
        for(int applied = 0; applied < count; ++applied)
        {
            await AdjustAsync(device, pool, registry, TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, rateAdjust).ConfigureAwait(false);
        }
    }

    /// <summary>Issues <paramref name="count"/> <c>TPM2_ReadClock()</c> commands and discards their answers.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="count">How many commands to dispatch.</param>
    private async Task IssueReadClocksAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, int count)
    {
        for(int issued = 0; issued < count; ++issued)
        {
            _ = await ReadClockAsync(device, registry, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Measures how far the very next admitted command advances Clock and Time: two <c>TPM2_ReadClock()</c>
    /// commands, the gap between them being the second one's own advance at whatever rate is then in force.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The milliseconds that one command added to Clock and to Time.</returns>
    private async Task<(ulong ClockAdvance, ulong TimeAdvance)> MeasureNextAdvanceAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        return await MeasureAdvanceOverAsync(device, registry, pool, commandCount: 1).ConfigureAwait(false);
    }

    /// <summary>
    /// Measures how far <paramref name="commandCount"/> admitted commands advance Clock and Time, by reading
    /// the counters, dispatching that many further commands, and reading again — the reading that establishes
    /// the baseline is itself one command, so the measured gap belongs entirely to the commands that follow it.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="commandCount">How many commands the measured window spans.</param>
    /// <returns>The milliseconds those commands added to Clock and to Time.</returns>
    private async Task<(ulong ClockAdvance, ulong TimeAdvance)> MeasureAdvanceOverAsync(
        TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool, int commandCount)
    {
        TpmsTimeInfo before = await ReadClockAsync(device, registry, pool).ConfigureAwait(false);
        await IssueReadClocksAsync(device, registry, pool, commandCount - 1).ConfigureAwait(false);
        TpmsTimeInfo after = await ReadClockAsync(device, registry, pool).ConfigureAwait(false);

        return (after.ClockInfo.Clock - before.ClockInfo.Clock, after.Time - before.Time);
    }

    /// <summary>
    /// Replaces <paramref name="hierarchy"/>'s authorization value through a password-authorized
    /// <c>TPM2_HierarchyChangeAuth()</c>, asserting the rotation succeeded — the way an installed
    /// <c>platformAuth</c> is put in place before this command's arms are exercised against it.
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
    /// under Platform Authorization, asserting the write succeeded — Platform Authorization may CLEAR any enable
    /// including its own (TPM 2.0 Library Part 3, clause 24.2.1).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="hierarchy">The hierarchy whose enable is CLEARed.</param>
    private async Task DisableHierarchyAsync(TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh hierarchy)
    {
        using TpmPasswordSession session = TpmPasswordSession.CreateEmpty(pool);
        var input = new HierarchyControlInput(TpmRh.TPM_RH_PLATFORM, hierarchy, TpmiYesNo.No);

        TpmResult<HierarchyControlResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyControlResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_HierarchyControl() disabling '{hierarchy}' failed: '{result.ResponseCode}'.");
    }

    /// <summary>Issues <c>TPM2_Clear()</c> under the empty-password lockout authorization, asserting success.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    private async Task ClearAsync(TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry)
    {
        var input = new ClearInput(TpmRh.TPM_RH_LOCKOUT);
        using TpmPasswordSession lockoutAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<ClearResponse> result = await TpmCommandExecutor.ExecuteAsync<ClearResponse>(
            device, input, [lockoutAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_Clear() failed: '{result.ResponseCode}'.");
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
    /// Appends a one-slot authorization area naming <c>TPM_RS_PW</c> with an empty nonce and
    /// <paramref name="password"/> as the supplied value — the password form of <c>TPMS_AUTH_COMMAND</c>
    /// (TPM 2.0 Library Part 1, clause 16.6.4.1).
    /// </summary>
    /// <param name="body">The body being built.</param>
    /// <param name="password">The authorization value the slot supplies.</param>
    private static void AppendPasswordAuthorizationArea(List<byte> body, ReadOnlyMemory<byte> password)
    {
        var area = new List<byte>();
        AppendUInt32(area, (uint)TpmRh.TPM_RH_PW);
        AppendUInt16(area, 0);
        area.Add((byte)TpmaSession.CONTINUE_SESSION);
        AppendUInt16(area, password.Length);
        area.AddRange(password.Span);

        AppendUInt32(body, (uint)area.Count);
        body.AddRange(area);
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_ClockRateAdjust()</c> command — handle area, a one-slot password authorization
    /// area, then whatever parameter octets the caller chose, which is how an octet Table 19 does not define
    /// and a frame of the wrong length are put on the wire at all.
    /// </summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authHandle">The handle to place in the handle area.</param>
    /// <param name="password">The authorization value the password slot supplies.</param>
    /// <param name="parameterOctets">The parameter area, laid out verbatim.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitClockRateAdjustFrameAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint authHandle, ReadOnlyMemory<byte> password, byte[] parameterOctets)
    {
        var body = new List<byte>();
        AppendUInt32(body, authHandle);
        AppendPasswordAuthorizationArea(body, password);
        body.AddRange(parameterOctets);

        return await SubmitFramedAsync(simulator, pool, TpmStConstants.TPM_ST_SESSIONS, [.. body]).ConfigureAwait(false);
    }

    /// <summary>Frames a <c>TPM2_ClockRateAdjust()</c> header around <paramref name="body"/> and submits it straight to the simulator.</summary>
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
        var header = new TpmHeader((ushort)tag, (uint)length, (uint)TpmCcConstants.TPM_CC_ClockRateAdjust);
        header.WriteTo(ref writer);
        writer.WriteBytes(body);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer a malformed command rather than fault.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>
    /// Frames a sessionless command (<c>TPM2_Startup()</c> or <c>TPM2_Shutdown()</c>) directly to the
    /// simulator, mirroring how the production executor frames an unauthorized command on the wire, and
    /// returns its response code.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="input">The command input.</param>
    private async Task SubmitSessionlessAsync(TpmSimulator simulator, BaseMemoryPool pool, ITpmCommandInput input)
    {
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"'{input.CommandCode}' must succeed at the transport level.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)TpmHeader.Parse(ref reader).Code, $"'{input.CommandCode}' must succeed.");
    }
}
