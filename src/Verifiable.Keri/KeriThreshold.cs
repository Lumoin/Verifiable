using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Text;

namespace Verifiable.Keri;

/// <summary>
/// A KERI signing threshold: the rule that decides whether a set of signatures satisfies a key list. KERI admits
/// two forms — an unweighted count (a lowercase hexadecimal integer: how many of the keys must sign) and a
/// weighted threshold (a list of rational weights, or a list of such lists, where each clause's signing weights
/// must sum to at least one). This models both and evaluates them exactly, so a multi-signature controller's
/// fractional-weight policy is honored without floating-point error.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the KERI specification's <see href="https://trustoverip.github.io/kswg-keri-specification/#signing-threshold">
/// signing threshold</see>. The unweighted form <c>"2"</c> is satisfied by any two of the listed keys. The
/// weighted single-clause form <c>["1/2","1/2","1/2"]</c> assigns each key its positional weight and is satisfied
/// when the signing keys' weights sum to at least one (so any two of three half-weight keys suffice). The weighted
/// multi-clause form <c>[["1/2","1/2"],["1"]]</c> partitions the key list into contiguous clauses that each must
/// independently reach one — an AND across clauses. The weighted next threshold (<c>nt</c>) is carried in the same
/// type; partial and reserve rotation, which reveal a threshold-satisfying subset of the committed keys, are a
/// later slice.
/// </para>
/// </remarks>
public sealed class KeriThreshold: IEquatable<KeriThreshold>
{
    private int UnweightedCount { get; }
    private Fraction[][]? Clauses { get; }


    private KeriThreshold(int unweightedCount)
    {
        this.UnweightedCount = unweightedCount;
    }


    private KeriThreshold(Fraction[][] clauses)
    {
        this.Clauses = clauses;
    }


    /// <summary>
    /// Whether this threshold is the weighted form (a list of rational-weight clauses) rather than an unweighted
    /// count.
    /// </summary>
    public bool IsWeighted => Clauses is not null;


    /// <summary>
    /// Creates an unweighted threshold requiring at least <paramref name="count"/> signatures.
    /// </summary>
    /// <param name="count">The number of signatures required; MUST be at least one.</param>
    /// <returns>The unweighted threshold.</returns>
    /// <exception cref="KeriException">The count is less than one.</exception>
    public static KeriThreshold Unweighted(int count)
    {
        if(count < 1)
        {
            throw new KeriException($"An unweighted signing threshold must be at least one, not {count}.");
        }

        return new KeriThreshold(count);
    }


    /// <summary>
    /// Parses a threshold from its decoded field-map value: a hexadecimal string for the unweighted form, a list
    /// of weight strings for the weighted single-clause form, or a list of such lists for the weighted multi-clause
    /// form.
    /// </summary>
    /// <param name="value">The decoded threshold value (a <see cref="string"/>, an <see cref="IReadOnlyList{T}"/> of <see cref="string"/>, or a list of lists).</param>
    /// <returns>The parsed threshold.</returns>
    /// <exception cref="KeriException">The value is not a recognized threshold shape, or carries an invalid count or weight.</exception>
    public static KeriThreshold Parse(object? value)
    {
        switch(value)
        {
            case string text:
            {
                if(!int.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int count))
                {
                    throw new KeriException($"The unweighted signing threshold '{text}' is not a hexadecimal integer.");
                }

                return Unweighted(count);
            }
            case IReadOnlyList<string> weights:
            {
                return new KeriThreshold([ParseClause(weights)]);
            }
            case IEnumerable<object?> items:
            {
                return ParseClauses(items);
            }
            default:
            {
                throw new KeriException("A signing threshold must be a hexadecimal string or a list of weight strings.");
            }
        }
    }


    /// <summary>
    /// Whether the keys at the given positions satisfy this threshold. For the unweighted form, at least the
    /// required number of distinct positions must be present; for the weighted form, every clause's signing
    /// weights must sum to at least one.
    /// </summary>
    /// <param name="signedKeyIndices">The zero-based positions, in the key list, of the keys that produced a valid signature.</param>
    /// <param name="keyCount">The number of keys in the list the threshold applies to.</param>
    /// <returns><see langword="true"/> when the signing positions satisfy the threshold.</returns>
    public bool IsSatisfiedBy(IReadOnlyCollection<int> signedKeyIndices, int keyCount)
    {
        ArgumentNullException.ThrowIfNull(signedKeyIndices);

        var signed = new HashSet<int>(signedKeyIndices);
        if(Clauses is null)
        {
            return signed.Count >= UnweightedCount;
        }

        int offset = 0;
        foreach(Fraction[] clause in Clauses)
        {
            Fraction sum = Fraction.Zero;
            for(int position = 0; position < clause.Length; position++)
            {
                if(signed.Contains(offset + position))
                {
                    sum = sum.Add(clause[position]);
                }
            }

            if(!sum.IsAtLeastOne)
            {
                return false;
            }

            offset += clause.Length;
        }

        return true;
    }


    /// <inheritdoc/>
    public bool Equals(KeriThreshold? other)
    {
        if(other is null)
        {
            return false;
        }

        if(Clauses is null || other.Clauses is null)
        {
            return Clauses is null && other.Clauses is null && UnweightedCount == other.UnweightedCount;
        }

        if(Clauses.Length != other.Clauses.Length)
        {
            return false;
        }

        for(int clauseIndex = 0; clauseIndex < Clauses.Length; clauseIndex++)
        {
            Fraction[] clause = Clauses[clauseIndex];
            Fraction[] otherClause = other.Clauses[clauseIndex];
            if(clause.Length != otherClause.Length)
            {
                return false;
            }

            for(int position = 0; position < clause.Length; position++)
            {
                if(!clause[position].Equals(otherClause[position]))
                {
                    return false;
                }
            }
        }

        return true;
    }


    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is KeriThreshold other && Equals(other);


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        if(Clauses is null)
        {
            return HashCode.Combine(false, UnweightedCount);
        }

        HashCode hash = new();
        hash.Add(true);
        foreach(Fraction[] clause in Clauses)
        {
            foreach(Fraction weight in clause)
            {
                hash.Add(weight);
            }
        }

        return hash.ToHashCode();
    }


    /// <summary>
    /// Renders the threshold in its canonical field-map form: a hexadecimal string for the unweighted form, or a
    /// bracketed list (of lists) of weight strings for the weighted form.
    /// </summary>
    /// <returns>The canonical textual form.</returns>
    public override string ToString()
    {
        if(Clauses is null)
        {
            return UnweightedCount.ToString("x", CultureInfo.InvariantCulture);
        }

        var builder = new StringBuilder();
        builder.Append('[');
        for(int clauseIndex = 0; clauseIndex < Clauses.Length; clauseIndex++)
        {
            if(clauseIndex > 0)
            {
                builder.Append(',');
            }

            if(Clauses.Length > 1)
            {
                builder.Append('[');
            }

            AppendClause(builder, Clauses[clauseIndex]);

            if(Clauses.Length > 1)
            {
                builder.Append(']');
            }
        }

        builder.Append(']');

        return builder.ToString();
    }


    /// <summary>
    /// Parses a threshold from its <see cref="string"/> field-map value (the unweighted hexadecimal form), the
    /// common case, so a caller can write a threshold literal directly.
    /// </summary>
    /// <param name="value">The unweighted hexadecimal threshold string.</param>
    public static implicit operator KeriThreshold(string value) => Parse(value);


    private static KeriThreshold ParseClauses(IEnumerable<object?> items)
    {
        var clauseList = new List<Fraction[]>();
        var topLevelWeights = new List<string>();
        bool nested = false;

        foreach(object? item in items)
        {
            switch(item)
            {
                case string weight:
                {
                    topLevelWeights.Add(weight);
                    break;
                }
                case IReadOnlyList<string> clauseWeights:
                {
                    nested = true;
                    clauseList.Add(ParseClause(clauseWeights));
                    break;
                }
                case IEnumerable<object?> clauseItems:
                {
                    nested = true;
                    clauseList.Add(ParseClause(AsStrings(clauseItems)));
                    break;
                }
                default:
                {
                    throw new KeriException("A weighted signing threshold clause must contain weight strings.");
                }
            }
        }

        if(nested && topLevelWeights.Count > 0)
        {
            throw new KeriException("A weighted signing threshold cannot mix weight strings and clauses at the top level.");
        }

        return nested
            ? new KeriThreshold(clauseList.ToArray())
            : new KeriThreshold([ParseClause(topLevelWeights)]);
    }


    private static Fraction[] ParseClause(IReadOnlyList<string> weights)
    {
        if(weights.Count == 0)
        {
            throw new KeriException("A weighted signing threshold clause must contain at least one weight.");
        }

        var fractions = new Fraction[weights.Count];
        for(int i = 0; i < weights.Count; i++)
        {
            fractions[i] = Fraction.Parse(weights[i]);
        }

        return fractions;
    }


    private static List<string> AsStrings(IEnumerable<object?> items)
    {
        var strings = new List<string>();
        foreach(object? item in items)
        {
            if(item is not string text)
            {
                throw new KeriException("A weighted signing threshold clause must contain weight strings.");
            }

            strings.Add(text);
        }

        return strings;
    }


    private static void AppendClause(StringBuilder builder, Fraction[] clause)
    {
        for(int i = 0; i < clause.Length; i++)
        {
            if(i > 0)
            {
                builder.Append(',');
            }

            builder.Append('"').Append(clause[i].ToString()).Append('"');
        }
    }


    /// <summary>
    /// An exact non-negative rational weight, kept in lowest terms so weighted thresholds sum without
    /// floating-point error (so that, for example, three thirds sum to exactly one). The numerator and denominator
    /// are arbitrary-precision integers, so summing a clause of many small weights (as a threshold parsed from an
    /// untrusted key event may carry) is exact and cannot overflow — a fixed-width accumulator would wrap on a
    /// product of coprime denominators and mis-decide the threshold or throw. Arbitrary precision removes the
    /// overflow, but a hostile threshold could then drive unbounded cost: a clause of many pairwise-coprime large
    /// denominators accumulates a denominator that is their product, whose bit length grows without limit and makes
    /// each subsequent addition and reduction cost more, so a small crafted threshold could impose super-linear
    /// arbitrary-precision effort on a verifier replaying the key event log. The reduced denominator is therefore
    /// bounded (<see cref="MaxDenominatorBitLength"/>): no legitimate fractional-weight policy needs a combined
    /// denominator that large, and one that exceeds it is rejected rather than evaluated.
    /// </summary>
    private readonly struct Fraction: IEquatable<Fraction>
    {
        /// <summary>
        /// The maximum bit length of a weight's reduced denominator — and so of the running denominator a clause
        /// accumulates, since each sum passes through this constructor. A legitimate weighted threshold's combined
        /// denominator (the least common multiple of its weights' denominators) is small; this bound is far above
        /// any real policy yet caps the per-operation cost, so a crafted clause of many coprime large denominators
        /// is rejected before it can amplify verifier effort rather than growing the denominator without limit.
        /// </summary>
        private const int MaxDenominatorBitLength = 1024;


        private BigInteger Numerator { get; }

        private BigInteger Denominator { get; }


        public Fraction(BigInteger numerator, BigInteger denominator)
        {
            if(denominator.Sign <= 0)
            {
                throw new KeriException($"A signing weight denominator must be positive, not {denominator}.");
            }

            if(numerator.Sign < 0)
            {
                throw new KeriException($"A signing weight must not be negative, not {numerator}.");
            }

            BigInteger divisor = BigInteger.GreatestCommonDivisor(numerator, denominator);
            BigInteger reducedNumerator = numerator / divisor;
            BigInteger reducedDenominator = denominator / divisor;
            if(reducedDenominator.GetBitLength() > MaxDenominatorBitLength)
            {
                throw new KeriException($"A weighted signing threshold's reduced denominator exceeds {MaxDenominatorBitLength} bits; a combined denominator that large is not a legitimate fractional-weight policy and is rejected rather than allowed to impose unbounded rational-arithmetic cost on the verifier.");
            }

            Numerator = reducedNumerator;
            Denominator = reducedDenominator;
        }


        public static Fraction Zero => new(BigInteger.Zero, BigInteger.One);


        public bool IsAtLeastOne => Numerator >= Denominator;


        public Fraction Add(Fraction other)
        {
            return new Fraction(
                (Numerator * other.Denominator) + (other.Numerator * Denominator),
                Denominator * other.Denominator);
        }


        public static Fraction Parse(string weight)
        {
            ArgumentNullException.ThrowIfNull(weight);

            int slash = weight.IndexOf('/', StringComparison.Ordinal);
            if(slash < 0)
            {
                return long.TryParse(weight, NumberStyles.Integer, CultureInfo.InvariantCulture, out long whole)
                    ? new Fraction(whole, BigInteger.One)
                    : throw new KeriException($"The signing weight '{weight}' is not a rational number.");
            }

            if(!long.TryParse(weight.AsSpan(0, slash), NumberStyles.Integer, CultureInfo.InvariantCulture, out long parsedNumerator)
                || !long.TryParse(weight.AsSpan(slash + 1), NumberStyles.Integer, CultureInfo.InvariantCulture, out long parsedDenominator))
            {
                throw new KeriException($"The signing weight '{weight}' is not a rational number.");
            }

            return new Fraction(parsedNumerator, parsedDenominator);
        }


        public bool Equals(Fraction other) => Numerator == other.Numerator && Denominator == other.Denominator;


        public override bool Equals(object? obj) => obj is Fraction other && Equals(other);


        public override int GetHashCode() => HashCode.Combine(Numerator, Denominator);


        public override string ToString()
        {
            return Denominator.IsOne
                ? Numerator.ToString(CultureInfo.InvariantCulture)
                : $"{Numerator.ToString(CultureInfo.InvariantCulture)}/{Denominator.ToString(CultureInfo.InvariantCulture)}";
        }
    }
}
