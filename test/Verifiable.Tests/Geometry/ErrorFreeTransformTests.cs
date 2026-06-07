using CsCheck;
using Verifiable.Geometry;

namespace Verifiable.Tests.Geometry
{
    /// <summary>
    /// Differential-oracle tests for <see cref="ErrorFreeTransforms"/>:
    /// every transform's defining identity — the two returned components
    /// sum exactly to the exact result of the operation — is verified
    /// against <see cref="ExactRational"/> arbitrary-precision arithmetic
    /// on property-generated inputs, including magnitude spreads that
    /// stress the roundoff paths.
    /// </summary>
    [TestClass]
    internal sealed class ErrorFreeTransformTests
    {
        private const long IterationCount = 1000;

        public TestContext TestContext { get; set; } = null!;

        [TestMethod]
        public void TwoSumIsExactOverSpreadMagnitudes()
        {
            SpreadDoubleGen().Select(SpreadDoubleGen()).Sample((a, b) =>
            {
                (double high, double low) = ErrorFreeTransforms.TwoSum(a, b);

                ExactRational exact = ExactRational.FromDouble(a) + ExactRational.FromDouble(b);
                ExactRational represented = ExactRational.FromDouble(high) + ExactRational.FromDouble(low);

                return represented.ValueEquals(exact) && high == a + b;
            }, iter: IterationCount);
        }

        [TestMethod]
        public void FastTwoSumIsExactWhenMagnitudeOrdered()
        {
            SpreadDoubleGen().Select(SpreadDoubleGen()).Sample((first, second) =>
            {
                double a = Math.Abs(first) >= Math.Abs(second) ? first : second;
                double b = Math.Abs(first) >= Math.Abs(second) ? second : first;

                (double high, double low) = ErrorFreeTransforms.FastTwoSum(a, b);

                ExactRational exact = ExactRational.FromDouble(a) + ExactRational.FromDouble(b);
                ExactRational represented = ExactRational.FromDouble(high) + ExactRational.FromDouble(low);

                return represented.ValueEquals(exact);
            }, iter: IterationCount);
        }

        [TestMethod]
        public void TwoDiffIsExactOverSpreadMagnitudes()
        {
            SpreadDoubleGen().Select(SpreadDoubleGen()).Sample((a, b) =>
            {
                (double high, double low) = ErrorFreeTransforms.TwoDiff(a, b);

                ExactRational exact = ExactRational.FromDouble(a) - ExactRational.FromDouble(b);
                ExactRational represented = ExactRational.FromDouble(high) + ExactRational.FromDouble(low);

                return represented.ValueEquals(exact) && high == a - b;
            }, iter: IterationCount);
        }

        [TestMethod]
        public void TwoProductIsExactOverSpreadMagnitudes()
        {
            SpreadDoubleGen().Select(SpreadDoubleGen()).Sample((a, b) =>
            {
                (double high, double low) = ErrorFreeTransforms.TwoProduct(a, b);

                ExactRational exact = ExactRational.FromDouble(a) * ExactRational.FromDouble(b);
                ExactRational represented = ExactRational.FromDouble(high) + ExactRational.FromDouble(low);

                return represented.ValueEquals(exact) && high == a * b;
            }, iter: IterationCount);
        }

        [TestMethod]
        public void TwoProductAgreesWithSplitFormulation()
        {
            SpreadDoubleGen().Select(SpreadDoubleGen()).Sample((a, b) =>
            {
                (double fusedHigh, double fusedLow) = ErrorFreeTransforms.TwoProduct(a, b);
                (double splitHigh, double splitLow) = ErrorFreeTransforms.TwoProductBySplit(a, b);

                return fusedHigh.Equals(splitHigh) && fusedLow.Equals(splitLow);
            }, iter: IterationCount);
        }

        [TestMethod]
        public void SquareIsExactOverSpreadMagnitudes()
        {
            SpreadDoubleGen().Sample(a =>
            {
                (double high, double low) = ErrorFreeTransforms.Square(a);

                ExactRational value = ExactRational.FromDouble(a);
                ExactRational exact = value * value;
                ExactRational represented = ExactRational.FromDouble(high) + ExactRational.FromDouble(low);

                return represented.ValueEquals(exact);
            }, iter: IterationCount);
        }

        [TestMethod]
        public void SplitPartsRecombineExactly()
        {
            SpreadDoubleGen().Sample(a =>
            {
                (double high, double low) = ErrorFreeTransforms.Split(a);

                return high + low == a
                    && ExactRational.FromDouble(high)
                        .ValueEquals(ExactRational.FromDouble(a) - ExactRational.FromDouble(low));
            }, iter: IterationCount);
        }

        [TestMethod]
        public void TwoSumCapturesTheRoundoffOfTheClassicCancellation()
        {
            //2^53 absorbs +1 entirely in double addition; the transform must
            //recover the lost unit exactly in the low component.
            double large = Math.ScaleB(1.0, 53);

            (double high, double low) = ErrorFreeTransforms.TwoSum(large, 1.0);

            Assert.AreEqual(large, high);
            Assert.AreEqual(1.0, low);
        }

        /// <summary>
        /// Doubles with well-spread magnitudes: a mantissa in
        /// <c>[-1, 1]</c> scaled by <c>2^e</c> for <c>e</c> in
        /// <c>[-60, 60]</c>. The range keeps sums and products comfortably
        /// inside normal range — the transforms' documented domain — while
        /// forcing large alignment shifts that exercise the roundoff paths.
        /// </summary>
        private static Gen<double> SpreadDoubleGen()
        {
            return Gen.Select(Gen.Double[-1.0, 1.0], Gen.Int[-60, 60], (mantissa, exponent) => Math.ScaleB(mantissa, exponent));
        }
    }
}
