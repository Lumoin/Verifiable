using System.Runtime.CompilerServices;

namespace Verifiable.Geometry;

/// <summary>
/// Error-free floating-point transforms: each operation returns the exact
/// result of a <see cref="double"/> operation as an unevaluated sum of two
/// doubles, <c>High + Low</c>, where <c>High</c> is the rounded result and
/// <c>Low</c> is the exact roundoff. These are the atoms the expansion
/// arithmetic in <see cref="Expansions"/> is built from, following
/// Shewchuk's adaptive-precision construction.
/// </summary>
/// <remarks>
/// <para>
/// <b>The contraction prohibition.</b> Every sequence in this file is
/// exact only when each written operation is performed as one IEEE 754
/// double operation, in the written order. Reassociation breaks them, and
/// fusing a multiply-add pair into an FMA silently changes results. Do not
/// rewrite these bodies into <c>a * b + c</c> shapes, do not introduce
/// <see cref="Math.FusedMultiplyAdd"/> except where this file already uses
/// it deliberately, and do not vectorise them without re-deriving the
/// proofs. The test suite carries a contraction canary that fails if the
/// compiled code begins fusing; treat a canary failure as a build
/// configuration defect, never as a test to weaken.
/// </para>
/// <para>
/// <b>The deliberate FMA.</b> <see cref="TwoProduct"/> uses
/// <see cref="Math.FusedMultiplyAdd"/> on purpose: by the definition of
/// fused multiply-add, <c>fma(a, b, -fl(a*b))</c> is the exact tail of the
/// product in one operation. This is the one place a fused operation makes
/// the transform <i>more</i> exact rather than less; on hardware without
/// FMA the runtime falls back to a correct (slower) software path.
/// <see cref="TwoProductBySplit"/> preserves the split-based formulation
/// as the reference the differential tests compare against.
/// </para>
/// <para>
/// Preconditions are the caller's responsibility and are deliberately not
/// checked here: these methods sit at the bottom of every predicate's hot
/// path.
/// </para>
/// </remarks>
public static class ErrorFreeTransforms
{
    /// <summary>
    /// The Veltkamp splitter, <c>2^27 + 1</c> for IEEE 754 binary64: the
    /// constant that splits a double into two 26-bit halves whose products
    /// are exact.
    /// </summary>
    public const double Splitter = 134217729.0;

    /// <summary>
    /// Sums two doubles exactly: returns <c>(x, y)</c> with
    /// <c>x = fl(a + b)</c> and <c>x + y == a + b</c> exactly. No
    /// precondition on the magnitudes of <paramref name="a"/> and
    /// <paramref name="b"/>.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static (double High, double Low) TwoSum(double a, double b)
    {
        double x = a + b;
        double bvirt = x - a;
        double avirt = x - bvirt;
        double bround = b - bvirt;
        double around = a - avirt;
        double y = around + bround;

        return (x, y);
    }

    /// <summary>
    /// Sums two doubles exactly under the precondition
    /// <c>|a| &gt;= |b|</c> (or <c>a == 0</c>): returns <c>(x, y)</c> with
    /// <c>x = fl(a + b)</c> and <c>x + y == a + b</c> exactly, in three
    /// operations instead of six.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static (double High, double Low) FastTwoSum(double a, double b)
    {
        double x = a + b;
        double bvirt = x - a;
        double y = b - bvirt;

        return (x, y);
    }

    /// <summary>
    /// Subtracts two doubles exactly: returns <c>(x, y)</c> with
    /// <c>x = fl(a - b)</c> and <c>x + y == a - b</c> exactly. No
    /// precondition on magnitudes.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static (double High, double Low) TwoDiff(double a, double b)
    {
        double x = a - b;
        double bvirt = a - x;
        double avirt = x + bvirt;
        double bround = bvirt - b;
        double around = a - avirt;
        double y = around + bround;

        return (x, y);
    }

    /// <summary>
    /// Splits <paramref name="a"/> into a 26-bit high part and a 26-bit
    /// low part with <c>High + Low == a</c> exactly, such that products of
    /// halves are exact in double precision. The building block of
    /// <see cref="TwoProductBySplit"/>.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static (double High, double Low) Split(double a)
    {
        double c = Splitter * a;
        double abig = c - a;
        double high = c - abig;
        double low = a - high;

        return (high, low);
    }

    /// <summary>
    /// Multiplies two doubles exactly: returns <c>(x, y)</c> with
    /// <c>x = fl(a * b)</c> and <c>x + y == a * b</c> exactly. Uses the
    /// deliberate fused multiply-add described in the type remarks.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static (double High, double Low) TwoProduct(double a, double b)
    {
        double x = a * b;
        double y = Math.FusedMultiplyAdd(a, b, -x);

        return (x, y);
    }

    /// <summary>
    /// Multiplies two doubles exactly through Veltkamp splitting — the
    /// classic FMA-free formulation. Functionally identical to
    /// <see cref="TwoProduct"/>; retained as the differential reference
    /// and for any target where the fused path is unavailable or distrusted.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static (double High, double Low) TwoProductBySplit(double a, double b)
    {
        double x = a * b;
        (double ahi, double alo) = Split(a);
        (double bhi, double blo) = Split(b);
        double err1 = x - (ahi * bhi);
        double err2 = err1 - (alo * bhi);
        double err3 = err2 - (ahi * blo);
        double y = (alo * blo) - err3;

        return (x, y);
    }

    /// <summary>
    /// Squares a double exactly: returns <c>(x, y)</c> with
    /// <c>x = fl(a * a)</c> and <c>x + y == a * a</c> exactly.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static (double High, double Low) Square(double a)
    {
        double x = a * a;
        double y = Math.FusedMultiplyAdd(a, a, -x);

        return (x, y);
    }
}
