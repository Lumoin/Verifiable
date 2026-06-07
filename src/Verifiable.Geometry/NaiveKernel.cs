using System.Diagnostics;

namespace Verifiable.Geometry;

/// <summary>
/// The naive floating-point kernel: evaluates predicates directly in
/// hardware doubles with no robustness guarantee. Fast everywhere and
/// wrong near degeneracy — it exists as the differential foil the test
/// suite contrasts against <see cref="AdaptiveKernel"/>, and as the
/// honest baseline for benchmarks. Production consumers use
/// <see cref="AdaptiveKernel"/>.
/// </summary>
[DebuggerDisplay("NaiveKernel (non-robust)")]
public readonly record struct NaiveKernel: IPrecisionKernel
{
    /// <inheritdoc/>
    public static int Orient2D(
        double ax, double ay,
        double bx, double by,
        double cx, double cy)
    {
        double determinant = ((ax - cx) * (by - cy)) - ((ay - cy) * (bx - cx));

        if(determinant > 0.0)
        {
            return 1;
        }

        if(determinant < 0.0)
        {
            return -1;
        }

        return 0;
    }
}
