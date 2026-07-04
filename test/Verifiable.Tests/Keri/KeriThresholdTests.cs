using System.Collections.Generic;
using Verifiable.Keri;

namespace Verifiable.Tests.Keri;

/// <summary>
/// Tests for <see cref="KeriThreshold"/> — parsing and evaluating KERI signing thresholds in both the unweighted
/// (hexadecimal count) and weighted (rational-weight clauses) forms. The weighted cases exercise the exact
/// rational arithmetic, including the thirds that must sum to exactly one, and the multi-clause AND.
/// </summary>
[TestClass]
internal sealed class KeriThresholdTests
{
    /// <summary>
    /// An unweighted threshold is satisfied by at least the required number of signing positions, regardless of
    /// which.
    /// </summary>
    [TestMethod]
    public void UnweightedThresholdCountsSignatures()
    {
        KeriThreshold threshold = KeriThreshold.Parse("2");

        Assert.IsFalse(threshold.IsWeighted);
        Assert.IsTrue(threshold.IsSatisfiedBy([0, 2], keyCount: 3), "Any two of three keys satisfy a count of two.");
        Assert.IsFalse(threshold.IsSatisfiedBy([1], keyCount: 3), "One signature does not satisfy a count of two.");
    }


    /// <summary>
    /// An unweighted threshold parses from lowercase hexadecimal.
    /// </summary>
    [TestMethod]
    public void UnweightedThresholdParsesHexadecimal()
    {
        Assert.IsTrue(KeriThreshold.Parse("a").IsSatisfiedBy([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], keyCount: 12), "'a' is ten.");
        Assert.IsFalse(KeriThreshold.Parse("a").IsSatisfiedBy([0, 1, 2, 3, 4, 5, 6, 7, 8], keyCount: 12), "Nine does not satisfy ten.");
    }


    /// <summary>
    /// A weighted single-clause threshold is satisfied when the signing positions' weights sum to at least one.
    /// </summary>
    [TestMethod]
    public void WeightedSingleClauseSumsToOne()
    {
        KeriThreshold threshold = KeriThreshold.Parse(new List<string> { "1/2", "1/2", "1/2" });

        Assert.IsTrue(threshold.IsWeighted);
        Assert.IsTrue(threshold.IsSatisfiedBy([0, 1], keyCount: 3), "Two half-weights reach one.");
        Assert.IsFalse(threshold.IsSatisfiedBy([2], keyCount: 3), "One half-weight is below one.");
        Assert.IsFalse(threshold.IsSatisfiedBy([], keyCount: 3), "No signatures never satisfy a positive threshold.");
    }


    /// <summary>
    /// Weighted arithmetic is exact: three thirds sum to exactly one, with no floating-point shortfall.
    /// </summary>
    [TestMethod]
    public void WeightedThirdsSumExactlyToOne()
    {
        KeriThreshold threshold = KeriThreshold.Parse(new List<string> { "1/3", "1/3", "1/3" });

        Assert.IsTrue(threshold.IsSatisfiedBy([0, 1, 2], keyCount: 3), "Three thirds are exactly one.");
        Assert.IsFalse(threshold.IsSatisfiedBy([0, 1], keyCount: 3), "Two thirds are below one.");
    }


    /// <summary>
    /// A weighted multi-clause threshold requires every clause to independently reach one (an AND across the
    /// contiguous key blocks).
    /// </summary>
    [TestMethod]
    public void WeightedMultiClauseRequiresEveryClause()
    {
        var value = new List<object?>
        {
            new List<string> { "1/2", "1/2" },
            new List<string> { "1" }
        };
        KeriThreshold threshold = KeriThreshold.Parse(value);

        Assert.IsTrue(threshold.IsSatisfiedBy([0, 1, 2], keyCount: 3), "Both clauses reach one.");
        Assert.IsFalse(threshold.IsSatisfiedBy([0, 1], keyCount: 3), "The second clause is unmet.");
        Assert.IsFalse(threshold.IsSatisfiedBy([0, 2], keyCount: 3), "The first clause reaches only one half.");
    }


    /// <summary>
    /// Thresholds compare by value: a parsed threshold equals the factory-built or re-parsed equivalent.
    /// </summary>
    [TestMethod]
    public void ThresholdsCompareByValue()
    {
        Assert.AreEqual(KeriThreshold.Unweighted(2), KeriThreshold.Parse("2"));
        Assert.AreEqual(KeriThreshold.Parse(new List<string> { "1/2", "1/2" }), KeriThreshold.Parse(new List<string> { "1/2", "1/2" }));
        Assert.AreNotEqual(KeriThreshold.Unweighted(2), KeriThreshold.Parse(new List<string> { "1/2", "1/2" }));
    }


    /// <summary>
    /// A zero count and a malformed weight are rejected, so a degenerate or unparseable threshold fails closed.
    /// </summary>
    [TestMethod]
    public void RejectsDegenerateOrMalformedThreshold()
    {
        Assert.ThrowsExactly<KeriException>(() => KeriThreshold.Parse("0"));
        Assert.ThrowsExactly<KeriException>(() => KeriThreshold.Parse(new List<string> { "half" }));
    }


    /// <summary>
    /// A weighted clause of many pairwise-coprime denominators is summed exactly: the product of the denominators
    /// exceeds a signed 64-bit accumulator, so a fixed-width accumulator would wrap — mis-deciding the threshold,
    /// or throwing on the wrapped non-positive denominator — whereas the arbitrary-precision arithmetic decides it
    /// exactly and never throws. This matters because a signing threshold is parsed from an untrusted key event: a
    /// crafted weighted threshold in a served key event log must not overflow the verifier.
    /// </summary>
    [TestMethod]
    public void WeightedThresholdWithManyCoprimeDenominatorsEvaluatesExactly()
    {
        //Sixteen distinct-prime denominators; the product 2·3·5·…·53 is about 3.3e19, past long.MaxValue (9.2e18).
        var weights = new List<string> { "1/2", "1/3", "1/5", "1/7", "1/11", "1/13", "1/17", "1/19", "1/23", "1/29", "1/31", "1/37", "1/41", "1/43", "1/47", "1/53" };
        KeriThreshold threshold = KeriThreshold.Parse(weights);

        var everyPosition = new List<int>();
        for(int position = 0; position < weights.Count; position++)
        {
            everyPosition.Add(position);
        }

        //The exact reciprocal sum passes one by the third term, so the full set satisfies the threshold, computed
        //exactly with no overflow and no thrown exception where a fixed-width accumulator wrapped.
        Assert.IsTrue(threshold.IsSatisfiedBy(everyPosition, keyCount: weights.Count), "The exact reciprocal sum exceeds one.");

        //A two-position subset whose exact reciprocal sum is far below one does not satisfy it.
        Assert.IsFalse(threshold.IsSatisfiedBy([14, 15], keyCount: weights.Count), "1/47 + 1/53 is well below one.");
    }


    /// <summary>
    /// A weighted clause of many pairwise-coprime LARGE denominators is rejected rather than summed at unbounded
    /// cost. Under exact rational arithmetic the running denominator accumulates their product, whose bit length
    /// grows without limit; a hostile controller could publish such a threshold (with real keys and signatures over
    /// its own key event) to force super-linear arbitrary-precision effort on every verifier that replays the log —
    /// a cost-amplification denial of service against the verifying party, not self-harm. The denominators here are
    /// large enough that their reciprocals never sum to one, so the bound (not an early exit) is what stops the
    /// accumulation: the evaluation throws when the reduced denominator crosses its limit instead of grinding on.
    /// </summary>
    [TestMethod]
    public void WeightedThresholdWithManyLargeCoprimeDenominatorsIsRejectedNotUnbounded()
    {
        var weights = new List<string>();
        foreach(long denominator in LargeCoprimeDenominators(120))
        {
            weights.Add($"1/{denominator}");
        }

        //Parsing succeeds: each individual denominator is a modest, well-formed integer; the growth is an emergent
        //property of summing them, so the clause is only rejected when it is evaluated.
        KeriThreshold threshold = KeriThreshold.Parse(weights);

        var everyPosition = new List<int>();
        for(int position = 0; position < weights.Count; position++)
        {
            everyPosition.Add(position);
        }

        Assert.ThrowsExactly<KeriException>(
            () => threshold.IsSatisfiedBy(everyPosition, keyCount: weights.Count),
            "A weighted clause whose accumulated denominator exceeds the bound must be rejected rather than summed at unbounded cost.");
    }


    /// <summary>
    /// Yields <paramref name="count"/> distinct primes at least one hundred thousand, deterministically by trial
    /// division: pairwise-coprime denominators whose product grows the accumulated rational denominator past its
    /// bound while their reciprocals stay far below one (so no early termination masks the growth).
    /// </summary>
    /// <param name="count">The number of large coprime denominators to yield.</param>
    /// <returns>The denominators.</returns>
    private static List<long> LargeCoprimeDenominators(int count)
    {
        var denominators = new List<long>(count);
        for(long candidate = 100003; denominators.Count < count; candidate += 2)
        {
            if(IsPrime(candidate))
            {
                denominators.Add(candidate);
            }
        }

        return denominators;

        static bool IsPrime(long value)
        {
            if(value % 2 == 0)
            {
                return value == 2;
            }

            for(long divisor = 3; divisor * divisor <= value; divisor += 2)
            {
                if(value % divisor == 0)
                {
                    return false;
                }
            }

            return true;
        }
    }
}
