namespace Verifiable.Geometry;

/// <summary>
/// The precision-kernel seam: the single configurable element of robust
/// geometric computation. A kernel's contract is narrow and total —
/// coordinates in, a sign in <c>{-1, 0, 1}</c> out — and consumers such as
/// triangulation and overlay read only that sign, never the arithmetic
/// behind it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Compile-time seam, not runtime dispatch.</b> Kernels are zero-field
/// structs implementing these static abstract members; algorithms are
/// generic over the kernel type (<c>TKernel : struct, IPrecisionKernel</c>)
/// so the JIT monomorphizes and inlines every predicate call — no vtable,
/// no boxing, no call-site cost. The interface exists only as the
/// compile-time constraint surface; it is never used as a runtime type.
/// </para>
/// <para>
/// <b>Why parameterize the kernel and not the number type.</b> Robustness
/// strategies (adaptive precision, fixed point, naive float) do not share
/// an arithmetic surface; they agree only at the sign. Abstracting the
/// scalar would force exact-arithmetic cost onto every operation, where
/// the adaptive strategy's entire value is staying in hardware doubles for
/// the easy cases and escalating only near degeneracy.
/// </para>
/// <para>
/// The seam deliberately admits future kernels beyond
/// <see cref="AdaptiveKernel"/>: a fixed-point kernel for cross-platform
/// bit determinism, and externally verifiable predicate evaluation, both
/// slotting in behind this same constraint with no consumer changes.
/// </para>
/// </remarks>
public interface IPrecisionKernel
{
    /// <summary>
    /// The orientation of point <c>c</c> relative to the directed line
    /// through <c>a</c> and <c>b</c>: <c>1</c> when the triangle
    /// <c>(a, b, c)</c> winds counter-clockwise, <c>-1</c> when clockwise,
    /// <c>0</c> when the three points are exactly collinear.
    /// </summary>
    static abstract int Orient2D(
        double ax, double ay,
        double bx, double by,
        double cx, double cy);
}
