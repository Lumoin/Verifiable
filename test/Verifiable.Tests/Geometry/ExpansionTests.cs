using CsCheck;
using Verifiable.Geometry;

namespace Verifiable.Tests.Geometry
{
    /// <summary>
    /// Differential-oracle tests for <see cref="Expansions"/>: after every
    /// operation the exact rational sum of the produced components must
    /// equal the exact rational result, the components must arrive
    /// zero-eliminated in increasing magnitude, and the sign read from the
    /// dominant component must be the exact sign.
    /// </summary>
    [TestClass]
    internal sealed class ExpansionTests
    {
        private const long IterationCount = 500;

        /// <summary>Stack budget mirrors the chain length the property tests build.</summary>
        private const int ChainCapacity = 64;

        public TestContext TestContext { get; set; } = null!;

        [TestMethod]
        public void GrowChainTracksExactValue()
        {
            SpreadDoubleGen().Array[1, 16].Sample(values =>
            {
                Span<double> expansion = stackalloc double[ChainCapacity];
                Span<double> next = stackalloc double[ChainCapacity];

                expansion[0] = values[0];
                int length = 1;
                ExactRational exact = ExactRational.FromDouble(values[0]);

                for(int index = 1; index < values.Length; index++)
                {
                    length = Expansions.Grow(expansion[..length], values[index], next);
                    next[..length].CopyTo(expansion);
                    exact += ExactRational.FromDouble(values[index]);
                }

                return ExactRational.SumOf(expansion[..length]).ValueEquals(exact)
                    && IsValidExpansion(expansion[..length])
                    && Expansions.Sign(expansion[..length]) == exact.Sign;
            }, iter: IterationCount);
        }

        [TestMethod]
        public void SumOfTwoExpansionsTracksExactValue()
        {
            Gen.Select(SpreadDoubleGen().Array[1, 8], SpreadDoubleGen().Array[1, 8]).Sample((eValues, fValues) =>
            {
                Span<double> e = stackalloc double[ChainCapacity];
                Span<double> f = stackalloc double[ChainCapacity];
                Span<double> scratch = stackalloc double[ChainCapacity];

                int eLength = BuildExpansion(eValues, e, scratch);
                int fLength = BuildExpansion(fValues, f, scratch);

                Span<double> sum = stackalloc double[ChainCapacity];
                int sumLength = Expansions.Sum(e[..eLength], f[..fLength], sum);

                ExactRational exact = ExactRational.SumOf(e[..eLength]) + ExactRational.SumOf(f[..fLength]);

                return ExactRational.SumOf(sum[..sumLength]).ValueEquals(exact)
                    && IsValidExpansion(sum[..sumLength])
                    && sumLength <= Expansions.SumCapacity(eLength, fLength)
                    && Expansions.Sign(sum[..sumLength]) == exact.Sign;
            }, iter: IterationCount);
        }

        [TestMethod]
        public void ScaleTracksExactValue()
        {
            Gen.Select(SpreadDoubleGen().Array[1, 8], SpreadDoubleGen()).Sample((values, factor) =>
            {
                Span<double> e = stackalloc double[ChainCapacity];
                Span<double> scratch = stackalloc double[ChainCapacity];
                int eLength = BuildExpansion(values, e, scratch);

                Span<double> scaled = stackalloc double[ChainCapacity];
                int scaledLength = Expansions.Scale(e[..eLength], factor, scaled);

                ExactRational exact = ExactRational.SumOf(e[..eLength]) * ExactRational.FromDouble(factor);

                return ExactRational.SumOf(scaled[..scaledLength]).ValueEquals(exact)
                    && IsValidExpansion(scaled[..scaledLength])
                    && scaledLength <= Expansions.ScaleCapacity(eLength)
                    && Expansions.Sign(scaled[..scaledLength]) == exact.Sign;
            }, iter: IterationCount);
        }

        [TestMethod]
        public void ExactCancellationCollapsesToSingleZeroComponent()
        {
            Span<double> e = stackalloc double[2];
            e[0] = 1.5;

            Span<double> result = stackalloc double[Expansions.GrowCapacity(1)];
            int length = Expansions.Grow(e[..1], -1.5, result);

            Assert.AreEqual(1, length, "A zero value is represented by exactly one component.");
            Assert.AreEqual(0.0, result[0]);
            Assert.AreEqual(0, Expansions.Sign(result[..length]));
        }

        [TestMethod]
        public void EstimateOfSingleComponentIsExact()
        {
            Span<double> e = stackalloc double[1];
            e[0] = -42.125;

            Assert.AreEqual(-42.125, Expansions.Estimate(e));
        }

        [TestMethod]
        public void GrowRecoversTheClassicAbsorbedUnit()
        {
            //2^53 + 1 is not representable in one double; the expansion
            //must carry both components and the exact value.
            double large = Math.ScaleB(1.0, 53);
            Span<double> e = stackalloc double[1];
            e[0] = large;

            Span<double> result = stackalloc double[Expansions.GrowCapacity(1)];
            int length = Expansions.Grow(e, 1.0, result);

            Assert.AreEqual(2, length);
            Assert.AreEqual(1.0, result[0]);
            Assert.AreEqual(large, result[1]);
        }

        [TestMethod]
        public void PooledFallbackBufferIsExactSizeAndTagged()
        {
            using var buffer = ExpansionBuffer.Rent(40);

            Assert.AreEqual(40, buffer.Length, "The pool contract is exact-size rentals.");
            Assert.IsTrue(buffer.Tag.TryGet(out GeometryBufferKind kind));
            Assert.AreEqual(GeometryBufferKind.ExpansionScratch, kind);

            buffer.Components[39] = 1.25;
            Assert.AreEqual(1.25, buffer.Components[39]);
        }

        /// <summary>Builds a valid expansion from arbitrary doubles by growing one component at a time.</summary>
        private static int BuildExpansion(double[] values, Span<double> destination, Span<double> scratch)
        {
            destination[0] = values[0];
            int length = 1;

            for(int index = 1; index < values.Length; index++)
            {
                length = Expansions.Grow(destination[..length], values[index], scratch);
                scratch[..length].CopyTo(destination);
            }

            return length;
        }

        /// <summary>
        /// Validates the expansion storage contract: zero-eliminated (a
        /// lone zero only as the whole value) and nondecreasing magnitude.
        /// </summary>
        private static bool IsValidExpansion(ReadOnlySpan<double> e)
        {
            if(e.Length == 1)
            {
                return true;
            }

            for(int index = 0; index < e.Length; index++)
            {
                if(e[index] == 0.0)
                {
                    return false;
                }

                if(index > 0 && Math.Abs(e[index]) < Math.Abs(e[index - 1]))
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>Doubles with spread magnitudes; see the transform tests for the rationale.</summary>
        private static Gen<double> SpreadDoubleGen()
        {
            return Gen.Select(Gen.Double[-1.0, 1.0], Gen.Int[-60, 60], (mantissa, exponent) => Math.ScaleB(mantissa, exponent));
        }
    }
}
