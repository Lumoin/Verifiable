using System.Runtime.CompilerServices;
using Verifiable.Geometry;

namespace Verifiable.Tests.Geometry
{
    /// <summary>
    /// The contraction canary: fails if the compiled code begins fusing
    /// <c>a * b + c</c> sequences into FMA or reassociating the error-free
    /// transform bodies. The exact-arithmetic layer is correct only when
    /// each written operation rounds individually; a toolchain that
    /// contracts silently would pass casual tests and fail only on
    /// near-degenerate input. A failure here is a build-configuration
    /// defect to fix, never a test to weaken.
    /// </summary>
    /// <remarks>
    /// The probe inputs make fused and unfused results differ provably:
    /// with <c>a = b = 1 + 2^-27</c>, the exact square is
    /// <c>1 + 2^-26 + 2^-54</c>, which rounds to <c>1 + 2^-26</c> with
    /// roundoff <c>2^-54</c>. Adding <c>c = -(1 + 2^-26)</c> unfused gives
    /// exactly zero; fused gives the roundoff <c>2^-54</c>.
    /// </remarks>
    [TestClass]
    internal sealed class FmaContractionCanaryTests
    {
        public TestContext TestContext { get; set; } = null!;

        private static double ProbeFactor { get; } = 1.0 + Math.ScaleB(1.0, -27);

        private static double ProbeAddend { get; } = -(1.0 + Math.ScaleB(1.0, -26));

        private static double ProbeRoundoff { get; } = Math.ScaleB(1.0, -54);

        [TestMethod]
        public void MultiplyAddWrittenAsSeparateOperationsDoesNotFuse()
        {
            double unfused = MultiplyThenAdd(ProbeFactor, ProbeFactor, ProbeAddend);

            Assert.AreEqual(0.0, unfused,
                "The JIT contracted a written multiply-then-add into FMA; the exact-arithmetic layer is unsound on this build.");
        }

        [TestMethod]
        public void ExplicitFusedMultiplyAddSeesTheRoundoff()
        {
            double fused = Math.FusedMultiplyAdd(ProbeFactor, ProbeFactor, ProbeAddend);

            Assert.AreEqual(ProbeRoundoff, fused,
                "Math.FusedMultiplyAdd must produce the exact unrounded tail on the probe inputs.");
        }

        [TestMethod]
        public void TwoProductRecoversTheProbeRoundoffExactly()
        {
            (double high, double low) = ErrorFreeTransforms.TwoProduct(ProbeFactor, ProbeFactor);

            Assert.AreEqual(-ProbeAddend, high, "The rounded product must lose the 2^-54 tail.");
            Assert.AreEqual(ProbeRoundoff, low, "The transform must recover exactly the tail the rounding lost.");
        }

        [TestMethod]
        public void SplitFormulationAgreesOnTheProbe()
        {
            (double fusedHigh, double fusedLow) = ErrorFreeTransforms.TwoProduct(ProbeFactor, ProbeFactor);
            (double splitHigh, double splitLow) = ErrorFreeTransforms.TwoProductBySplit(ProbeFactor, ProbeFactor);

            Assert.AreEqual(fusedHigh, splitHigh);
            Assert.AreEqual(fusedLow, splitLow);
        }

        /// <summary>
        /// Replicates the exact code shape the transform bodies use — a
        /// product stored, then an add — with inlining suppressed so the
        /// probe observes the JIT's treatment of the pattern itself.
        /// </summary>
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static double MultiplyThenAdd(double a, double b, double c)
        {
            double product = a * b;

            return product + c;
        }
    }
}
