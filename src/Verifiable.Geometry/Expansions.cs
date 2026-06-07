namespace Verifiable.Geometry;

/// <summary>
/// Floating-point expansion arithmetic after Shewchuk: a number is held as
/// a sequence of nonoverlapping <see cref="double"/> components in
/// increasing magnitude order whose exact sum is the represented value.
/// All operations here are exact; the only approximation is the one the
/// caller explicitly requests through <see cref="Estimate"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Storage contract.</b> Callers own the component storage and size it
/// with the capacity functions (<see cref="SumCapacity"/>,
/// <see cref="GrowCapacity"/>, <see cref="ScaleCapacity"/>): stack
/// allocation within a frame budget, a pooled
/// <see cref="ExpansionBuffer"/> beyond it. Every operation returns the
/// number of components written. Outputs are zero-eliminated; a zero
/// value is represented by a single <c>0.0</c> component so that a length
/// of zero never occurs.
/// </para>
/// <para>
/// <b>The contraction prohibition of
/// <see cref="ErrorFreeTransforms"/> applies to this file in full.</b>
/// The summation chains are exact only unfused and unreordered.
/// </para>
/// </remarks>
public static class Expansions
{
    /// <summary>Components needed for <see cref="Sum"/> over expansions of the given lengths.</summary>
    public static int SumCapacity(int eLength, int fLength) => eLength + fLength;

    /// <summary>Components needed for <see cref="Grow"/> over an expansion of the given length.</summary>
    public static int GrowCapacity(int eLength) => eLength + 1;

    /// <summary>Components needed for <see cref="Scale"/> over an expansion of the given length.</summary>
    public static int ScaleCapacity(int eLength) => 2 * eLength;

    /// <summary>
    /// Adds the single double <paramref name="b"/> to expansion
    /// <paramref name="e"/>, writing a zero-eliminated expansion into
    /// <paramref name="result"/> and returning its component count.
    /// Shewchuk's <c>GROW_EXPANSION_ZEROELIM</c>.
    /// </summary>
    public static int Grow(ReadOnlySpan<double> e, double b, Span<double> result)
    {
        double q = b;
        int written = 0;

        for(int index = 0; index < e.Length; index++)
        {
            (double sum, double roundoff) = ErrorFreeTransforms.TwoSum(q, e[index]);
            q = sum;

            if(roundoff != 0.0)
            {
                result[written] = roundoff;
                written++;
            }
        }

        if(q != 0.0 || written == 0)
        {
            result[written] = q;
            written++;
        }

        return written;
    }

    /// <summary>
    /// Adds expansions <paramref name="e"/> and <paramref name="f"/>,
    /// writing a zero-eliminated expansion into <paramref name="result"/>
    /// and returning its component count. Shewchuk's
    /// <c>FAST_EXPANSION_SUM_ZEROELIM</c>; requires both inputs to be
    /// valid expansions (nonoverlapping, increasing magnitude).
    /// </summary>
    public static int Sum(ReadOnlySpan<double> e, ReadOnlySpan<double> f, Span<double> result)
    {
        int eIndex = 0;
        int fIndex = 0;
        double eNow = e[0];
        double fNow = f[0];
        double q;

        //Selects the smaller-magnitude head as the initial accumulator; the
        //comparison shape is Shewchuk's branchless-magnitude idiom.
        if((fNow > eNow) == (fNow > -eNow))
        {
            q = eNow;
            eIndex++;
        }
        else
        {
            q = fNow;
            fIndex++;
        }

        int written = 0;
        double high;
        double low;

        if(eIndex < e.Length && fIndex < f.Length)
        {
            eNow = e[eIndex];
            fNow = f[fIndex];

            if((fNow > eNow) == (fNow > -eNow))
            {
                (high, low) = ErrorFreeTransforms.FastTwoSum(eNow, q);
                eIndex++;
            }
            else
            {
                (high, low) = ErrorFreeTransforms.FastTwoSum(fNow, q);
                fIndex++;
            }

            q = high;

            if(low != 0.0)
            {
                result[written] = low;
                written++;
            }

            while(eIndex < e.Length && fIndex < f.Length)
            {
                eNow = e[eIndex];
                fNow = f[fIndex];

                if((fNow > eNow) == (fNow > -eNow))
                {
                    (high, low) = ErrorFreeTransforms.TwoSum(q, eNow);
                    eIndex++;
                }
                else
                {
                    (high, low) = ErrorFreeTransforms.TwoSum(q, fNow);
                    fIndex++;
                }

                q = high;

                if(low != 0.0)
                {
                    result[written] = low;
                    written++;
                }
            }
        }

        while(eIndex < e.Length)
        {
            (high, low) = ErrorFreeTransforms.TwoSum(q, e[eIndex]);
            eIndex++;
            q = high;

            if(low != 0.0)
            {
                result[written] = low;
                written++;
            }
        }

        while(fIndex < f.Length)
        {
            (high, low) = ErrorFreeTransforms.TwoSum(q, f[fIndex]);
            fIndex++;
            q = high;

            if(low != 0.0)
            {
                result[written] = low;
                written++;
            }
        }

        if(q != 0.0 || written == 0)
        {
            result[written] = q;
            written++;
        }

        return written;
    }

    /// <summary>
    /// Multiplies expansion <paramref name="e"/> by the single double
    /// <paramref name="b"/>, writing a zero-eliminated expansion into
    /// <paramref name="result"/> and returning its component count.
    /// Shewchuk's <c>SCALE_EXPANSION_ZEROELIM</c>, with the per-component
    /// exact product carried by <see cref="ErrorFreeTransforms.TwoProduct"/>.
    /// </summary>
    public static int Scale(ReadOnlySpan<double> e, double b, Span<double> result)
    {
        int written = 0;

        //The exact tail of the first product is the lowest-magnitude
        //component of the whole scaled expansion; the rounded product
        //continues as the accumulator.
        (double q, double firstRoundoff) = ErrorFreeTransforms.TwoProduct(e[0], b);

        if(firstRoundoff != 0.0)
        {
            result[written] = firstRoundoff;
            written++;
        }

        for(int index = 1; index < e.Length; index++)
        {
            (double productHigh, double productLow) = ErrorFreeTransforms.TwoProduct(e[index], b);
            (double sum, double sumRoundoff) = ErrorFreeTransforms.TwoSum(q, productLow);

            if(sumRoundoff != 0.0)
            {
                result[written] = sumRoundoff;
                written++;
            }

            (q, sumRoundoff) = ErrorFreeTransforms.FastTwoSum(productHigh, sum);

            if(sumRoundoff != 0.0)
            {
                result[written] = sumRoundoff;
                written++;
            }
        }

        if(q != 0.0 || written == 0)
        {
            result[written] = q;
            written++;
        }

        return written;
    }

    /// <summary>
    /// Returns an approximation of the expansion's value: the components
    /// summed lowest magnitude first. Correct to within one ulp of the
    /// exact value for a valid expansion.
    /// </summary>
    public static double Estimate(ReadOnlySpan<double> e)
    {
        double value = 0.0;

        for(int index = 0; index < e.Length; index++)
        {
            value += e[index];
        }

        return value;
    }

    /// <summary>
    /// Returns the exact sign of the expansion's value: <c>-1</c>,
    /// <c>0</c>, or <c>1</c>. For a valid zero-eliminated expansion the
    /// largest-magnitude component is last and dominates the exact sum.
    /// </summary>
    public static int Sign(ReadOnlySpan<double> e)
    {
        double dominant = e[^1];

        if(dominant > 0.0)
        {
            return 1;
        }

        if(dominant < 0.0)
        {
            return -1;
        }

        return 0;
    }
}
