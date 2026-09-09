using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// The rate-of-advance value <c>TPM2_ClockRateAdjust()</c> changes, exercised at the unit level:
/// "A TPM_CLOCK_ADJUST value in Table 19 is used to change the rate at which the TPM internal oscillator is
/// divided. A change to the divider will change the rate at which Clock and Time change." The divisor converts
/// a command's oscillator ticks into the milliseconds Clock and Time advance, carrying the unconsumed ticks
/// forward as a residue; a step is relative to the current divisor rather than the nominal one; and the range
/// is bounded by the accuracy requirement "the nominal rate of advance of Clock when powered is within 15% of
/// the rate of UTC", beyond which "the TPM shall return TPM_RC_VALUE".
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.7, Table 19; Part 3, clause 29.3.1; Part 1, clause 33.3.6</see>.
/// </summary>
[TestClass]
internal sealed class TpmClockRateTests
{
    /// <summary>The oscillator tick contribution the arithmetic tests measure a command's advance over.</summary>
    private const ulong Quantum = 1_000ul;

    /// <summary>
    /// "The recommended adjustments are approximately 1% for a coarse adjustment, 0.1% for a medium
    /// adjustment, and the minimum possible on the implementation for the fine adjustment" — an unadjusted rate
    /// is the nominal divisor with no residue owed, and reports itself nominal.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.7; Part 1, clause 33.3.6</see>.
    /// </summary>
    [TestMethod]
    public void NominalRateIsTheNominalDivisorWithNoResidueOwed()
    {
        TpmClockRate nominal = TpmClockRate.Nominal;

        Assert.AreEqual(30_000u, nominal.Divisor, "CLOCK_NOMINAL, the hardware ticks per millisecond, is fixed at 30 000 (TPM 2.0 Library Part 1, clause 33.3.6), which is the unadjusted divisor.");
        Assert.AreEqual(0u, nominal.TickResidue, "An unadjusted rate owes no carried ticks.");
        Assert.IsTrue(nominal.IsNominal, "The unadjusted rate must report itself nominal.");
    }

    /// <summary>
    /// "with no adjustment applied, Clock and Time shall be advanced at a rate within 15 percent of actual
    /// time" — at the nominal divisor a command advances by EXACTLY its own quantum with a zero residue, for
    /// every quantum this simulator's tests use, so no measurement recorded before the divisor existed moves.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3.1; Part 1, clause 33.3.6</see>.
    /// </summary>
    /// <param name="quantumMs">The command's oscillator tick contribution.</param>
    [TestMethod]
    [DataRow(0ul, DisplayName = "a zero quantum advances nothing")]
    [DataRow(1ul, DisplayName = "the default one-millisecond quantum")]
    [DataRow(600ul, DisplayName = "the six-hundred-millisecond quantum")]
    [DataRow(1_000ul, DisplayName = "the one-second quantum")]
    [DataRow(5_000ul, DisplayName = "the five-second quantum")]
    public void AdvanceAtTheNominalDivisorReturnsExactlyTheQuantumWithNoResidue(ulong quantumMs)
    {
        TpmClockRate advanced = TpmClockRate.Nominal.Advance(quantumMs, out ulong advancedMs);

        Assert.AreEqual(quantumMs, advancedMs, $"At the nominal divisor a quantum of '{quantumMs}' must advance exactly that many milliseconds.");
        Assert.AreEqual(0u, advanced.TickResidue, "A nominal division consumes every tick, leaving no residue.");
        Assert.AreEqual(TpmClockRate.NominalDivisor, advanced.Divisor, "Advancing never changes the divisor.");
    }

    /// <summary>
    /// "A change to the divider will change the rate at which Clock and Time change": each of Table 19's six
    /// changing steps moves the divisor by its own step size — a SLOWER step increases the divisor and a FASTER
    /// step decreases it — and the resulting divisor converts the same quantum into a different number of
    /// milliseconds, banking whatever ticks the division does not consume.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.7, Table 19; TPM 2.0 Library Part 3, clause 29.3.1</see>.
    /// </summary>
    /// <param name="step">The requested Table 19 step.</param>
    /// <param name="expectedDivisor">The divisor the step produces from the nominal rate.</param>
    /// <param name="expectedAdvanceMs">The milliseconds one quantum then advances.</param>
    /// <param name="expectedResidue">The ticks the division leaves behind.</param>
    [TestMethod]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER, 30_300u, 990ul, 3_000u, DisplayName = "one coarse step slower divides at 30 300")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_SLOWER, 30_030u, 999ul, 30u, DisplayName = "one medium step slower divides at 30 030")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_FINE_SLOWER, 30_001u, 999ul, 29_001u, DisplayName = "one fine step slower divides at 30 001")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE, 30_000u, 1_000ul, 0u, DisplayName = "no change leaves the nominal divisor")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_FINE_FASTER, 29_999u, 1_000ul, 1_000u, DisplayName = "one fine step faster divides at 29 999")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_FASTER, 29_970u, 1_001ul, 30u, DisplayName = "one medium step faster divides at 29 970")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER, 29_700u, 1_010ul, 3_000u, DisplayName = "one coarse step faster divides at 29 700")]
    public void EachTable19StepMovesTheDivisorAndTheMillisecondsOneQuantumBuys(
        TpmClockAdjustConstants step, uint expectedDivisor, ulong expectedAdvanceMs, uint expectedResidue)
    {
        bool isAdjusted = TpmClockRate.Nominal.TryAdjust(step, out TpmClockRate adjusted);

        Assert.IsTrue(isAdjusted, $"'{step}' is one step from nominal, well inside the permitted range.");
        Assert.AreEqual(expectedDivisor, adjusted.Divisor, $"'{step}' must move the divisor to '{expectedDivisor}'.");
        Assert.AreEqual(0u, adjusted.TickResidue, "An adjustment carries the current residue across unchanged, and the nominal rate owed none.");

        TpmClockRate advanced = adjusted.Advance(Quantum, out ulong advancedMs);

        Assert.AreEqual(expectedAdvanceMs, advancedMs, $"At divisor '{expectedDivisor}' a quantum of '{Quantum}' advances '{expectedAdvanceMs}' milliseconds.");
        Assert.AreEqual(expectedResidue, advanced.TickResidue, $"The ticks the division at '{expectedDivisor}' leaves unconsumed must be banked as the residue.");
    }

    /// <summary>
    /// Part 4's <c>TimeSetAdjustRate</c> answers <c>TPM_CLOCK_NO_CHANGE</c> with a plain <c>break</c>: the
    /// request is admitted and the rate — divisor and banked residue alike — is returned exactly as it stood.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.7, Table 19; TPM 2.0 Library Part 3, clause 29.3</see>.
    /// </summary>
    [TestMethod]
    public void NoChangeIsAdmittedAndReturnsTheSameRateIncludingItsBankedResidue()
    {
        var carrying = new TpmClockRate(30_300u, 17u);

        bool isAdjusted = carrying.TryAdjust(TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE, out TpmClockRate adjusted);

        Assert.IsTrue(isAdjusted, "TPM_CLOCK_NO_CHANGE is one of Table 19's seven values and is always admitted.");
        Assert.AreEqual(carrying, adjusted, "TPM_CLOCK_NO_CHANGE returns the identical rate, residue included.");
    }

    /// <summary>
    /// "The rateAdjust value is relative to the current rate and not the nominal rate of advance." — the
    /// specification's own worked example: "If this command had been called three times with rateAdjust =
    /// TPM_CLOCK_COARSE_SLOWER and once with rateAdjust = TPM_CLOCK_COARSE_FASTER, the net effect will be as if
    /// the command had been called twice with rateAdjust = TPM_CLOCK_COARSE_SLOWER."
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3.1</see>.
    /// </summary>
    [TestMethod]
    public void ThreeCoarseSlowerStepsAndOneCoarseFasterStepEqualTwoCoarseSlowerSteps()
    {
        TpmClockRate mixed = ApplyRepeated(TpmClockRate.Nominal, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER, 3);
        mixed = ApplyRepeated(mixed, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER, 1);

        TpmClockRate twice = ApplyRepeated(TpmClockRate.Nominal, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER, 2);

        Assert.AreEqual(30_600u, twice.Divisor, "Two coarse steps slower carry the divisor 600 ticks above nominal.");
        Assert.AreEqual(twice.Divisor, mixed.Divisor, "Three coarse steps slower then one faster must land on the same divisor as two slower.");

        _ = mixed.Advance(Quantum, out ulong mixedAdvance);
        _ = twice.Advance(Quantum, out ulong twiceAdvance);

        Assert.AreEqual(twiceAdvance, mixedAdvance, "Landing on the same divisor must buy the same milliseconds for the same quantum.");
    }

    /// <summary>
    /// "If the requested adjustment would make the rate advance faster or slower than the nominal accuracy of
    /// the input frequency, the TPM shall return TPM_RC_VALUE." — with the accuracy requirement at 15%, fifteen
    /// coarse steps reach the bound in either direction and the sixteenth is refused, leaving the rate exactly
    /// as the fifteenth left it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3.1; Part 1, clause 33.3.6</see>.
    /// </summary>
    /// <param name="step">The coarse step repeated toward the bound.</param>
    /// <param name="expectedBoundDivisor">The divisor fifteen such steps reach.</param>
    [TestMethod]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER, 25_500u, DisplayName = "fifteen coarse steps faster reach 15% below nominal")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER, 34_500u, DisplayName = "fifteen coarse steps slower reach 15% above nominal")]
    public void FifteenCoarseStepsReachTheFifteenPercentBoundAndTheSixteenthIsRefused(TpmClockAdjustConstants step, uint expectedBoundDivisor)
    {
        TpmClockRate atBound = ApplyRepeated(TpmClockRate.Nominal, step, 15);

        Assert.AreEqual(expectedBoundDivisor, atBound.Divisor,
            $"Fifteen '{step}' steps of 300 ticks each move the divisor 4 500 ticks — 15% of nominal — onto the permitted extreme '{expectedBoundDivisor}'.");

        bool isAdjusted = atBound.TryAdjust(step, out TpmClockRate refused);

        Assert.IsFalse(isAdjusted, $"A sixteenth '{step}' step would carry the divisor outside the 15% accuracy requirement.");
        Assert.AreEqual(atBound, refused, "A refused step must leave the rate exactly as it stood.");
    }

    /// <summary>
    /// The same bound reached by the smaller steps, in EITHER direction: a hundred and fifty medium steps and
    /// four thousand five hundred fine steps each reach the identical extreme, and the step past it is refused
    /// — "The interpretation of "fine" and "coarse" adjustments is implementation-specific", but the range they
    /// may span is not.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3.1; Part 2, clause 6.7</see>.
    /// </summary>
    /// <param name="step">The step repeated toward the bound.</param>
    /// <param name="stepsToTheBound">How many such steps the bound admits.</param>
    /// <param name="expectedBoundDivisor">The divisor that many steps reach.</param>
    [TestMethod]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_FASTER, 150, TpmClockRate.NominalDivisor - TpmClockRate.MaxDeviation, DisplayName = "a hundred and fifty medium steps faster reach the lower bound")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_FINE_FASTER, 4_500, TpmClockRate.NominalDivisor - TpmClockRate.MaxDeviation, DisplayName = "four thousand five hundred fine steps faster reach the lower bound")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_SLOWER, 150, TpmClockRate.NominalDivisor + TpmClockRate.MaxDeviation, DisplayName = "a hundred and fifty medium steps slower reach the upper bound")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_FINE_SLOWER, 4_500, TpmClockRate.NominalDivisor + TpmClockRate.MaxDeviation, DisplayName = "four thousand five hundred fine steps slower reach the upper bound")]
    public void TheSmallerStepsReachTheSameBoundAndAreRefusedBeyondIt(TpmClockAdjustConstants step, int stepsToTheBound, uint expectedBoundDivisor)
    {
        TpmClockRate atBound = ApplyRepeated(TpmClockRate.Nominal, step, stepsToTheBound);

        Assert.AreEqual(expectedBoundDivisor, atBound.Divisor,
            $"'{stepsToTheBound}' '{step}' steps must land exactly on the permitted extreme '{expectedBoundDivisor}'.");

        bool isAdjusted = atBound.TryAdjust(step, out TpmClockRate refused);

        Assert.IsFalse(isAdjusted, "One step past the bound must be refused.");
        Assert.AreEqual(atBound, refused, "A refused step must leave the rate exactly as it stood.");
    }

    /// <summary>
    /// A step of a different size is judged against the same bound, in EITHER direction: standing at the
    /// extreme fifteen coarse steps reach, a medium step and a fine step of the SAME direction are each refused
    /// because either would carry the divisor past the accuracy requirement, however small the step is.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3.1; Part 1, clause 33.3.6</see>.
    /// </summary>
    /// <param name="extreme">The coarse step repeated to the bound.</param>
    /// <param name="step">The smaller step of the same direction attempted from the bound.</param>
    [TestMethod]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER, TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_FASTER, DisplayName = "a medium step past the faster bound is refused")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER, TpmClockAdjustConstants.TPM_CLOCK_FINE_FASTER, DisplayName = "a fine step past the faster bound is refused")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER, TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_SLOWER, DisplayName = "a medium step past the slower bound is refused")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER, TpmClockAdjustConstants.TPM_CLOCK_FINE_SLOWER, DisplayName = "a fine step past the slower bound is refused")]
    public void ASmallerStepFromTheCoarseBoundIsRefusedToo(TpmClockAdjustConstants extreme, TpmClockAdjustConstants step)
    {
        TpmClockRate atBound = ApplyRepeated(TpmClockRate.Nominal, extreme, 15);

        bool isAdjusted = atBound.TryAdjust(step, out TpmClockRate refused);

        Assert.IsFalse(isAdjusted, $"'{step}' from the '{extreme}' extreme would still cross the 15% bound.");
        Assert.AreEqual(atBound, refused, "A refused step must leave the rate exactly as it stood.");
    }

    /// <summary>
    /// Table 19 carries <c>#TPM_RC_VALUE</c>: an octet the wire delivered outside the seven listed values is
    /// not a step at all, so it is refused and changes nothing — the arithmetic never treats an undefined
    /// selector as a silent no-op.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.7, Table 19</see>.
    /// </summary>
    /// <param name="rawValue">The raw signed octet cast to the step type.</param>
    [TestMethod]
    [DataRow((sbyte)4, DisplayName = "4 is one past the fastest step Table 19 lists")]
    [DataRow((sbyte)(-4), DisplayName = "-4 is one past the slowest step Table 19 lists")]
    [DataRow((sbyte)127, DisplayName = "the most positive INT8 is outside Table 19")]
    [DataRow((sbyte)(-128), DisplayName = "the most negative INT8 is outside Table 19")]
    public void AnUndefinedStepIsRefusedAndChangesNothing(sbyte rawValue)
    {
        TpmClockRate nominal = TpmClockRate.Nominal;

        bool isAdjusted = nominal.TryAdjust((TpmClockAdjustConstants)rawValue, out TpmClockRate refused);

        Assert.IsFalse(isAdjusted, $"The octet '{rawValue}' names no Table 19 step.");
        Assert.AreEqual(nominal, refused, "A refused step must leave the rate exactly as it stood.");
    }

    /// <summary>
    /// Table 19's trailing <c>#TPM_RC_VALUE</c> marker is the response code an out-of-table octet earns, so the
    /// membership predicate admits exactly the seven listed values and refuses everything else the signed octet
    /// can carry — the values immediately outside the range and both of the type's extremes included.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.7, Table 19</see>.
    /// </summary>
    /// <param name="rawValue">The raw signed octet offered to the predicate.</param>
    /// <param name="isDefinedExpected">Whether Table 19 lists that value.</param>
    [TestMethod]
    [DataRow((sbyte)(-3), true, DisplayName = "-3 is TPM_CLOCK_COARSE_SLOWER")]
    [DataRow((sbyte)(-2), true, DisplayName = "-2 is TPM_CLOCK_MEDIUM_SLOWER")]
    [DataRow((sbyte)(-1), true, DisplayName = "-1 is TPM_CLOCK_FINE_SLOWER")]
    [DataRow((sbyte)0, true, DisplayName = "0 is TPM_CLOCK_NO_CHANGE")]
    [DataRow((sbyte)1, true, DisplayName = "1 is TPM_CLOCK_FINE_FASTER")]
    [DataRow((sbyte)2, true, DisplayName = "2 is TPM_CLOCK_MEDIUM_FASTER")]
    [DataRow((sbyte)3, true, DisplayName = "3 is TPM_CLOCK_COARSE_FASTER")]
    [DataRow((sbyte)4, false, DisplayName = "4 is outside Table 19")]
    [DataRow((sbyte)(-4), false, DisplayName = "-4 is outside Table 19")]
    [DataRow((sbyte)127, false, DisplayName = "the most positive INT8 is outside Table 19")]
    [DataRow((sbyte)(-128), false, DisplayName = "the most negative INT8 is outside Table 19")]
    public void ClockAdjustMembershipAdmitsTable19Alone(sbyte rawValue, bool isDefinedExpected)
    {
        var candidate = (TpmClockAdjustConstants)rawValue;

        Assert.AreEqual(isDefinedExpected, candidate.IsDefined(),
            $"Table 19's membership must judge the raw octet '{rawValue}' as '{isDefinedExpected}'.");
    }

    /// <summary>
    /// Applies <paramref name="step"/> to <paramref name="rate"/> exactly <paramref name="count"/> times,
    /// asserting every one of them is admitted — the way a run of adjustments toward the permitted extreme is
    /// built up before the step that crosses it is attempted.
    /// </summary>
    /// <param name="rate">The rate to start from.</param>
    /// <param name="step">The step to repeat.</param>
    /// <param name="count">How many times to apply it.</param>
    /// <returns>The rate after all the steps.</returns>
    private static TpmClockRate ApplyRepeated(TpmClockRate rate, TpmClockAdjustConstants step, int count)
    {
        TpmClockRate current = rate;
        for(int applied = 0; applied < count; ++applied)
        {
            bool isAdjusted = current.TryAdjust(step, out TpmClockRate next);
            Assert.IsTrue(isAdjusted, $"Step '{applied + 1}' of '{count}' '{step}' steps must be admitted.");
            current = next;
        }

        return current;
    }
}
