using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The rate at which <see cref="TpmSimulatorState.Clock"/> and <see cref="TpmSimulatorState.Time"/> advance:
/// the simulator's stand-in for a real TPM's internal oscillator and the divisor <c>TPM2_ClockRateAdjust()</c>
/// changes (TPM 2.0 Library Part 2, clause 6.7: "A TPM_CLOCK_ADJUST value in Table 19 is used to change the
/// rate at which the TPM internal oscillator is divided. A change to the divider will change the rate at
/// which Clock and Time change.").
/// </summary>
/// <remarks>
/// <para>
/// A dispatched command's quantum (<see cref="TpmSimulatorState.ClockAdvanceQuantumMs"/>) is the oscillator
/// tick count the command contributes; <see cref="Divisor"/> converts that tick count into the milliseconds
/// <c>Clock</c> and <c>Time</c> advance (TPM 2.0 Library Part 4, <c>Clock.c</c>'s <c>_plat__ClockRateAdjust()</c>, called from <c>TimeSetAdjustRate()</c>: <c>CLOCK_NOMINAL</c> is "the
/// number of hardware ticks per ms"). Whatever ticks the division does not consume carry forward as
/// <see cref="TickResidue"/> rather than being dropped, so a run of small adjustments still advances Clock and
/// Time by the correct amount on average.
/// </para>
/// <para>
/// <see cref="TryAdjust"/> implements <c>TPM2_ClockRateAdjust()</c>'s own rule: the adjustment is RELATIVE to
/// the current divisor, not the nominal one (TPM 2.0 Library Part 3, clause 29.3.1: "The rateAdjust value is
/// relative to the current rate and not the nominal rate of advance." — the worked example: three
/// <c>TPM_CLOCK_COARSE_SLOWER</c> calls followed by one <c>TPM_CLOCK_COARSE_FASTER</c> call leave the same
/// rate as two <c>TPM_CLOCK_COARSE_SLOWER</c> calls). The bound enforces the specification's accuracy
/// requirement (Part 1, clause 33.3.6: "This specification requires that the nominal rate of advance of Clock
/// when powered is within 15% of the rate of UTC.") by refusing a step that would carry the divisor outside
/// ±15% of <see cref="NominalDivisor"/> (Part 3, clause 29.3.1: "If the requested adjustment would make the rate
/// advance faster or slower than the nominal accuracy of the input frequency, the TPM shall return
/// TPM_RC_VALUE.").
/// </para>
/// </remarks>
/// <param name="Divisor">The current oscillator divisor, in ticks per millisecond; <see cref="NominalDivisor"/> when unadjusted.</param>
/// <param name="TickResidue">The oscillator ticks accumulated since the last millisecond <see cref="Divisor"/> consumed, carried forward rather than dropped.</param>
public readonly record struct TpmClockRate(uint Divisor, uint TickResidue)
{
    /// <summary>
    /// The unadjusted divisor, in ticks per millisecond (TPM 2.0 Library Part 4, <c>TPM2_Clock()</c>,
    /// <c>CLOCK_NOMINAL</c>).
    /// </summary>
    public const uint NominalDivisor = 30_000u;

    /// <summary>
    /// The divisor change one coarse adjustment step applies — approximately 1% of <see cref="NominalDivisor"/>
    /// (TPM 2.0 Library Part 2, clause 6.7: "The recommended adjustments are approximately 1% for a coarse
    /// adjustment").
    /// </summary>
    public const uint CoarseStep = 300u;

    /// <summary>
    /// The divisor change one medium adjustment step applies — approximately 0.1% of
    /// <see cref="NominalDivisor"/> (clause 6.7: "0.1% for a medium adjustment").
    /// </summary>
    public const uint MediumStep = 30u;

    /// <summary>
    /// The divisor change one fine adjustment step applies — the finest step this simulator models (clause 6.7:
    /// "the minimum possible on the implementation for the fine adjustment (e.g., one count of the pre-scalar if
    /// possible)").
    /// </summary>
    public const uint FineStep = 1u;

    /// <summary>
    /// The largest deviation from <see cref="NominalDivisor"/> a sequence of adjustments may reach — 15% of
    /// <see cref="NominalDivisor"/> (TPM 2.0 Library Part 1, clause 33.3.6's accuracy requirement). TPM 2.0
    /// Library Part 4's <c>TimeSetAdjustRate()</c>-called reference <c>_plat__ClockRateAdjust()</c> (<c>Platform/src/Clock.c</c>) instead clamps the
    /// divisor SILENTLY at <c>CLOCK_NOMINAL ± CLOCK_ADJUST_LIMIT</c> (5 000, a 16.7% guard band, with no error
    /// returned); this model refuses with <c>TPM_RC_VALUE</c> at the tighter ±15% bound instead, following Part
    /// 3, clause 29.3.1's "the TPM shall return TPM_RC_VALUE" and this clause's own accuracy requirement.
    /// </summary>
    public const uint MaxDeviation = 4_500u;

    /// <summary>
    /// The unadjusted rate: <see cref="NominalDivisor"/> with no residue, the rate every freshly manufactured or
    /// cleared simulated TPM starts at.
    /// </summary>
    public static TpmClockRate Nominal => new(NominalDivisor, 0u);

    /// <summary>
    /// Gets whether this rate is the unadjusted <see cref="Nominal"/> divisor (regardless of residue).
    /// </summary>
    public bool IsNominal => Divisor == NominalDivisor;

    /// <summary>
    /// Converts one dispatched command's oscillator ticks into the milliseconds <c>Clock</c> and <c>Time</c>
    /// advance, carrying the ticks the division did not consume forward as the next rate's residue.
    /// </summary>
    /// <param name="quantumMs">The command's oscillator tick contribution (<see cref="TpmSimulatorState.ClockAdvanceQuantumMs"/>), measured at the nominal rate.</param>
    /// <param name="advancedMs">The milliseconds <c>Clock</c> and <c>Time</c> advance for this command.</param>
    /// <returns>The rate after this command, carrying the unconsumed tick residue forward.</returns>
    public TpmClockRate Advance(ulong quantumMs, out ulong advancedMs)
    {
        ulong ticks = TickResidue + (quantumMs * NominalDivisor);
        advancedMs = ticks / Divisor;
        uint residue = (uint)(ticks % Divisor);

        return new TpmClockRate(Divisor, residue);
    }

    /// <summary>
    /// Applies one <c>TPM2_ClockRateAdjust()</c> step to <see cref="Divisor"/>: a SLOWER step adds to the
    /// divisor, a FASTER step subtracts, and <c>TPM_CLOCK_NO_CHANGE</c> leaves it as it stands (TPM 2.0 Library
    /// Part 4, <c>Time.c</c>'s <c>TimeSetAdjustRate()</c>: <c>NO_CHANGE: break</c>).
    /// </summary>
    /// <param name="step">The requested adjustment, already known to be one of Table 19's seven members.</param>
    /// <param name="adjusted">The rate after the step, or this rate unchanged when the step is refused.</param>
    /// <returns>
    /// <see langword="true"/> when the resulting divisor stays within <see cref="MaxDeviation"/> of
    /// <see cref="NominalDivisor"/>; <see langword="false"/> when it would not, in which case
    /// <paramref name="adjusted"/> is this rate unchanged.
    /// </returns>
    public bool TryAdjust(TpmClockAdjustConstants step, out TpmClockRate adjusted)
    {
        long candidate = step switch
        {
            TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER => Divisor + CoarseStep,
            TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_SLOWER => Divisor + MediumStep,
            TpmClockAdjustConstants.TPM_CLOCK_FINE_SLOWER => Divisor + FineStep,
            TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE => Divisor,
            TpmClockAdjustConstants.TPM_CLOCK_FINE_FASTER => Divisor - FineStep,
            TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_FASTER => Divisor - MediumStep,
            TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER => Divisor - CoarseStep,
            _ => -1L
        };

        if(candidate < NominalDivisor - MaxDeviation || candidate > NominalDivisor + MaxDeviation)
        {
            adjusted = this;

            return false;
        }

        adjusted = new TpmClockRate((uint)candidate, TickResidue);

        return true;
    }
}
