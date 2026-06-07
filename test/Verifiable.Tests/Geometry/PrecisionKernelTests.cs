using CsCheck;
using Verifiable.Geometry;

namespace Verifiable.Tests.Geometry
{
    /// <summary>
    /// Tests for the precision-kernel seam: <see cref="AdaptiveKernel"/>
    /// must return the exact orientation sign on every input — verified
    /// against the <see cref="ExactRational"/> oracle — while
    /// <see cref="NaiveKernel"/> demonstrably fails near degeneracy, which
    /// is the differential evidence the seam exists to provide. The
    /// near-degenerate sweep is Shewchuk's classic grid: points perturbed
    /// from a diagonal by single ulps against two far collinear anchors.
    /// </summary>
    [TestClass]
    internal sealed class PrecisionKernelTests
    {
        private const long IterationCount = 1000;

        /// <summary>Side length of the ulp-perturbation grid swept around the diagonal.</summary>
        private const int DegenerateGridSize = 32;

        public TestContext TestContext { get; set; } = null!;

        [TestMethod]
        public void AdaptiveOrientationMatchesExactSignOnRandomTriangles()
        {
            CoordinateGen().Array[6, 6].Sample(c =>
            {
                int adaptive = AdaptiveKernel.Orient2D(c[0], c[1], c[2], c[3], c[4], c[5]);

                return adaptive == ExactOrientationSign(c[0], c[1], c[2], c[3], c[4], c[5]);
            }, iter: IterationCount);
        }

        [TestMethod]
        public void AdaptiveOrientationIsExactAcrossTheUlpPerturbationGrid()
        {
            double ulp = Math.ScaleB(1.0, -53);

            for(int i = 0; i < DegenerateGridSize; i++)
            {
                for(int j = 0; j < DegenerateGridSize; j++)
                {
                    double px = 0.5 + (ulp * i);
                    double py = 0.5 + (ulp * j);

                    int adaptive = AdaptiveKernel.Orient2D(px, py, 12.0, 12.0, 24.0, 24.0);
                    int exact = ExactOrientationSign(px, py, 12.0, 12.0, 24.0, 24.0);

                    Assert.AreEqual(exact, adaptive,
                        $"Adaptive kernel returned a wrong sign at grid offset ({i}, {j}).");
                }
            }
        }

        [TestMethod]
        public void NaiveKernelFailsSomewhereOnTheSameGrid()
        {
            double ulp = Math.ScaleB(1.0, -53);
            int mismatches = 0;

            for(int i = 0; i < DegenerateGridSize; i++)
            {
                for(int j = 0; j < DegenerateGridSize; j++)
                {
                    double px = 0.5 + (ulp * i);
                    double py = 0.5 + (ulp * j);

                    int naive = NaiveKernel.Orient2D(px, py, 12.0, 12.0, 24.0, 24.0);
                    int exact = ExactOrientationSign(px, py, 12.0, 12.0, 24.0, 24.0);

                    if(naive != exact)
                    {
                        mismatches++;
                    }
                }
            }

            //The grid is the canonical demonstration that hardware doubles
            //misjudge near-collinear orientation; if the naive kernel ever
            //passed it completely, the differential foil (and this sweep)
            //would no longer be exercising the robustness boundary.
            Assert.IsGreaterThan(0, mismatches,
                "The naive kernel unexpectedly survived the near-degenerate grid; the sweep no longer covers the robustness boundary.");
        }

        [TestMethod]
        public void ExactlyCollinearPointsReturnZero()
        {
            Assert.AreEqual(0, AdaptiveKernel.Orient2D(0.0, 0.0, 1.0, 1.0, 7.0, 7.0));
            Assert.AreEqual(0, AdaptiveKernel.Orient2D(-3.0, 2.0, -3.0, 9.0, -3.0, -50.0));
            Assert.AreEqual(0, AdaptiveKernel.Orient2D(1e30, 1e30, 2e30, 2e30, 4e30, 4e30));
            Assert.AreEqual(0, AdaptiveKernel.Orient2D(1e-300, 1e-300, 2e-300, 2e-300, 3e-300, 3e-300));
        }

        [TestMethod]
        public void ClearWindingsHaveTheObviousSigns()
        {
            Assert.AreEqual(1, AdaptiveKernel.Orient2D(0.0, 0.0, 1.0, 0.0, 0.0, 1.0));
            Assert.AreEqual(-1, AdaptiveKernel.Orient2D(0.0, 0.0, 0.0, 1.0, 1.0, 0.0));
        }

        [TestMethod]
        public void KernelGenericConsumerMonomorphizesOverBothKernels()
        {
            int adaptive = OrientThroughSeam<AdaptiveKernel>(0.0, 0.0, 1.0, 0.0, 0.0, 1.0);
            int naive = OrientThroughSeam<NaiveKernel>(0.0, 0.0, 1.0, 0.0, 0.0, 1.0);

            Assert.AreEqual(1, adaptive);
            Assert.AreEqual(1, naive);
        }

        /// <summary>
        /// The seam in consumer position: an algorithm generic over the
        /// kernel struct, the shape triangulation and overlay will use.
        /// </summary>
        private static int OrientThroughSeam<TKernel>(
            double ax, double ay,
            double bx, double by,
            double cx, double cy) where TKernel : struct, IPrecisionKernel
        {
            return TKernel.Orient2D(ax, ay, bx, by, cx, cy);
        }

        /// <summary>The oracle: the orientation determinant evaluated in exact rational arithmetic.</summary>
        private static int ExactOrientationSign(
            double ax, double ay,
            double bx, double by,
            double cx, double cy)
        {
            ExactRational acx = ExactRational.FromDouble(ax) - ExactRational.FromDouble(cx);
            ExactRational bcy = ExactRational.FromDouble(by) - ExactRational.FromDouble(cy);
            ExactRational acy = ExactRational.FromDouble(ay) - ExactRational.FromDouble(cy);
            ExactRational bcx = ExactRational.FromDouble(bx) - ExactRational.FromDouble(cx);

            return ((acx * bcy) - (acy * bcx)).Sign;
        }

        /// <summary>Coordinates spread across magnitudes, the same scheme as the arithmetic tests.</summary>
        private static Gen<double> CoordinateGen()
        {
            return Gen.Select(Gen.Double[-1.0, 1.0], Gen.Int[-30, 30], (mantissa, exponent) => Math.ScaleB(mantissa, exponent));
        }
    }
}
