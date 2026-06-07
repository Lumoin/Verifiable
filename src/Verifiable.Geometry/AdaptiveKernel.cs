using System.Diagnostics;

namespace Verifiable.Geometry;

/// <summary>
/// The adaptive-precision kernel: predicates evaluate in hardware doubles
/// with a static error-bound filter and escalate to exact expansion
/// arithmetic only when the filter cannot certify the sign. The sign
/// returned is always exact; only the cost adapts to how close the input
/// is to degeneracy.
/// </summary>
/// <remarks>
/// <para>
/// The filter constant follows Shewchuk: with <c>ε</c> the machine epsilon
/// of the rounded-to-nearest double format, a computed orientation
/// determinant whose magnitude exceeds <c>(3 + 16ε)ε · detsum</c> has the
/// exact sign. Below that bound the predicate recomputes the determinant
/// exactly: the six bilinear terms of the expanded determinant as
/// error-free products, summed as expansions, and the sign read from the
/// dominant component. The exact path allocates nothing — its worst case
/// fits comfortably in stack scratch.
/// </para>
/// <para>
/// This first stage deliberately omits Shewchuk's intermediate B/C
/// refinement stages: they are a performance ladder for near-degenerate
/// inputs, not a correctness requirement, and belong to the predicate
/// expansion phase together with <c>InCircle</c>.
/// </para>
/// </remarks>
[DebuggerDisplay("AdaptiveKernel (filtered exact)")]
public readonly record struct AdaptiveKernel: IPrecisionKernel
{
    /// <summary>The machine epsilon of binary64 round-to-nearest: <c>2^-53</c>.</summary>
    private const double Epsilon = 1.1102230246251565e-16;

    /// <summary>Shewchuk's static filter bound for the 2D orientation determinant.</summary>
    private const double OrientBoundA = (3.0 + (16.0 * Epsilon)) * Epsilon;

    /// <summary>
    /// Capacity for the exact determinant accumulation: six two-component
    /// products merge pairwise into expansions of at most twelve components.
    /// </summary>
    private const int ExactDeterminantCapacity = 12;

    /// <inheritdoc/>
    public static int Orient2D(
        double ax, double ay,
        double bx, double by,
        double cx, double cy)
    {
        double detLeft = (ax - cx) * (by - cy);
        double detRight = (ay - cy) * (bx - cx);
        double det = detLeft - detRight;
        double detSum;

        if(detLeft > 0.0)
        {
            if(detRight <= 0.0)
            {
                return SignOf(det);
            }

            detSum = detLeft + detRight;
        }
        else if(detLeft < 0.0)
        {
            if(detRight >= 0.0)
            {
                return SignOf(det);
            }

            detSum = -detLeft - detRight;
        }
        else
        {
            return SignOf(det);
        }

        double errorBound = OrientBoundA * detSum;

        if(det >= errorBound || -det >= errorBound)
        {
            return SignOf(det);
        }

        return Orient2DExact(ax, ay, bx, by, cx, cy);
    }

    /// <summary>
    /// The exact fallback: evaluates the orientation determinant
    /// <c>ax·by − ax·cy − cx·by − ay·bx + ay·cx + cy·bx</c> (the full
    /// expansion of <c>(a−c) × (b−c)</c>; the <c>cx·cy</c> terms cancel)
    /// in expansion arithmetic and returns the exact sign.
    /// </summary>
    private static int Orient2DExact(
        double ax, double ay,
        double bx, double by,
        double cx, double cy)
    {
        //Each pair of products with opposite signs combines into one exact
        //four-component expansion through TwoTwoDiff-style accumulation:
        //here as two-component products merged by expansion sums.
        Span<double> termStorage = stackalloc double[2];
        Span<double> positive = stackalloc double[ExactDeterminantCapacity];
        Span<double> negative = stackalloc double[ExactDeterminantCapacity];
        Span<double> scratch = stackalloc double[ExactDeterminantCapacity];

        //Positive terms: ax·by, ay·cx, cy·bx.
        (termStorage[1], termStorage[0]) = ErrorFreeTransforms.TwoProduct(ax, by);
        int positiveLength = CopyComponents(termStorage, positive);

        (termStorage[1], termStorage[0]) = ErrorFreeTransforms.TwoProduct(ay, cx);
        positiveLength = MergeInto(positive, positiveLength, termStorage, scratch);
        scratch[..positiveLength].CopyTo(positive);

        (termStorage[1], termStorage[0]) = ErrorFreeTransforms.TwoProduct(cy, bx);
        positiveLength = MergeInto(positive, positiveLength, termStorage, scratch);
        scratch[..positiveLength].CopyTo(positive);

        //Negative terms: ax·cy, cx·by, ay·bx.
        (termStorage[1], termStorage[0]) = ErrorFreeTransforms.TwoProduct(ax, cy);
        int negativeLength = CopyComponents(termStorage, negative);

        (termStorage[1], termStorage[0]) = ErrorFreeTransforms.TwoProduct(cx, by);
        negativeLength = MergeInto(negative, negativeLength, termStorage, scratch);
        scratch[..negativeLength].CopyTo(negative);

        (termStorage[1], termStorage[0]) = ErrorFreeTransforms.TwoProduct(ay, bx);
        negativeLength = MergeInto(negative, negativeLength, termStorage, scratch);
        scratch[..negativeLength].CopyTo(negative);

        //det = positive − negative: negate the negative side and sum.
        Span<double> negated = negative[..negativeLength];

        for(int index = 0; index < negated.Length; index++)
        {
            negated[index] = -negated[index];
        }

        Span<double> determinant = stackalloc double[2 * ExactDeterminantCapacity];
        int determinantLength = Expansions.Sum(positive[..positiveLength], negated, determinant);

        return Expansions.Sign(determinant[..determinantLength]);
    }

    /// <summary>Copies the nonzero components of a two-component product into expansion storage, zero-eliminating.</summary>
    private static int CopyComponents(ReadOnlySpan<double> product, Span<double> destination)
    {
        int written = 0;

        if(product[0] != 0.0)
        {
            destination[written] = product[0];
            written++;
        }

        if(product[1] != 0.0 || written == 0)
        {
            destination[written] = product[1];
            written++;
        }

        return written;
    }

    /// <summary>Sums an accumulated expansion with one product term into <paramref name="scratch"/>.</summary>
    private static int MergeInto(
        ReadOnlySpan<double> accumulated,
        int accumulatedLength,
        ReadOnlySpan<double> product,
        Span<double> scratch)
    {
        Span<double> term = stackalloc double[2];
        int termLength = CopyComponents(product, term);

        return Expansions.Sum(accumulated[..accumulatedLength], term[..termLength], scratch);
    }

    private static int SignOf(double value)
    {
        if(value > 0.0)
        {
            return 1;
        }

        if(value < 0.0)
        {
            return -1;
        }

        return 0;
    }
}
