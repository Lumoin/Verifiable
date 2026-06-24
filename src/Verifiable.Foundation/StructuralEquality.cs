using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace Verifiable.Foundation;

/// <summary>
/// Structural equality and hashing primitives for the materialized-JSON object model — the
/// <see cref="Dictionary{TKey, TValue}"/> of <see cref="string"/> to <see cref="object"/>, the
/// <see cref="List{T}"/> of <see cref="object"/>, and the scalar leaves
/// (<see cref="string"/>/<see cref="bool"/>/<see cref="int"/>/<see cref="long"/>/<see cref="decimal"/>/<see langword="null"/>)
/// that JSON parsing produces — plus null-safe ordered sequence helpers.
/// </summary>
/// <remarks>
/// These let a settable POCO carried as a serialization target implement value equality over both its typed members
/// and its arbitrary-JSON members (a <c>body</c> or extension bag) without taking a dependency on a serialization
/// library. The materialized shapes mirror the leaf converter's output: a JSON object is a
/// <c>Dictionary&lt;string, object&gt;</c>, an array is a <c>List&lt;object&gt;</c>, and numbers narrow to
/// <see cref="int"/> then <see cref="long"/> then <see cref="decimal"/>. Scalars therefore compare by CLR value, so an
/// <see cref="int"/> <c>42</c> is NOT equal to a <see cref="long"/> <c>42</c> — the two never materialize from the same
/// wire token, so distinguishing them keeps equality consistent with "would serialize identically".
/// </remarks>
public static class StructuralEquality
{
    /// <summary>
    /// The maximum nesting depth <see cref="JsonEqual"/> traverses. A tree materialized from parsed JSON is already
    /// bounded by the parser's own depth limit and can never reach this; the guard exists only to fail fast on a
    /// hand-built cyclic or pathologically deep graph rather than exhaust memory.
    /// </summary>
    private const int MaxDepth = 64;

    /// <summary>
    /// Determines whether two materialized-JSON values are structurally equal: dictionaries match iff they have the
    /// same key set and per-key structurally-equal values (key order is irrelevant), lists match iff they are
    /// element-wise structurally equal in order, and scalars match by CLR value. The walk is iterative with an
    /// explicit work stack — never recursion — so its call-stack use is bounded independently of input nesting.
    /// </summary>
    /// <param name="left">The first value: a <c>Dictionary&lt;string, object&gt;</c>, a <c>List&lt;object&gt;</c>, a scalar, or <see langword="null"/>.</param>
    /// <param name="right">The second value, of the same materialized shape family.</param>
    /// <returns><see langword="true"/> when the two graphs are structurally equal.</returns>
    /// <exception cref="InvalidOperationException">Thrown when nesting exceeds <see cref="MaxDepth"/>, indicating a cyclic or adversarial graph.</exception>
    public static bool JsonEqual(object? left, object? right)
    {
        var stack = new Stack<(object? Left, object? Right, int Depth)>();
        stack.Push((left, right, 0));

        while(stack.Count > 0)
        {
            (object? a, object? b, int depth) = stack.Pop();

            if(a is null || b is null)
            {
                if(!ReferenceEquals(a, b))
                {
                    return false;
                }

                continue;
            }

            if(depth > MaxDepth)
            {
                throw new InvalidOperationException(
                    "Structural JSON comparison exceeded the maximum nesting depth; the graph is cyclic or pathologically deep.");
            }

            if(TryAsMap(a, out IReadOnlyDictionary<string, object>? leftMap))
            {
                if(!TryAsMap(b, out IReadOnlyDictionary<string, object>? rightMap) || leftMap.Count != rightMap.Count)
                {
                    return false;
                }

                //Equal counts plus every left key present in right implies equal key sets (no duplicate keys exist).
                foreach(KeyValuePair<string, object> entry in leftMap)
                {
                    if(!rightMap.TryGetValue(entry.Key, out object? rightValue))
                    {
                        return false;
                    }

                    stack.Push((entry.Value, rightValue, depth + 1));
                }

                continue;
            }

            if(TryAsList(a, out IReadOnlyList<object>? leftList))
            {
                if(!TryAsList(b, out IReadOnlyList<object>? rightList) || leftList.Count != rightList.Count)
                {
                    return false;
                }

                for(int i = 0; i < leftList.Count; ++i)
                {
                    stack.Push((leftList[i], rightList[i], depth + 1));
                }

                continue;
            }

            //A scalar can only equal a scalar: if the other operand is a container, the two differ.
            if(TryAsMap(b, out _) || TryAsList(b, out _))
            {
                return false;
            }

            if(!a.Equals(b))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Computes a hash code consistent with <see cref="JsonEqual"/>: structurally-equal graphs hash equal. A
    /// dictionary contributes its entry count and an order-independent combination of its keys, a list its element
    /// count, and a scalar its own hash. The summary is intentionally shallow — it does not descend into nested
    /// values — which keeps it cheap while preserving the equal-implies-equal-hash contract (it never claims two
    /// unequal graphs differ).
    /// </summary>
    /// <param name="value">A materialized-JSON value, or <see langword="null"/>.</param>
    /// <returns>A hash code over <paramref name="value"/>.</returns>
    public static int JsonHashCode(object? value)
    {
        if(value is null)
        {
            return 0;
        }

        if(TryAsMap(value, out IReadOnlyDictionary<string, object>? map))
        {
            //XOR over keys is order-independent, matching the key-set equality JsonEqual uses for dictionaries.
            int keyAccumulator = 0;
            foreach(string key in map.Keys)
            {
                keyAccumulator ^= key.GetHashCode(StringComparison.Ordinal);
            }

            return HashCode.Combine(map.Count, keyAccumulator);
        }

        if(TryAsList(value, out IReadOnlyList<object>? list))
        {
            return HashCode.Combine(list.Count, 0x5D);
        }

        return value.GetHashCode();
    }


    /// <summary>
    /// Determines whether two sequences are equal element-wise in order, treating two <see langword="null"/>
    /// sequences as equal and a <see langword="null"/> sequence as unequal to a non-null one.
    /// </summary>
    /// <typeparam name="T">The element type.</typeparam>
    /// <param name="left">The first sequence, or <see langword="null"/>.</param>
    /// <param name="right">The second sequence, or <see langword="null"/>.</param>
    /// <param name="comparer">The element comparer, or <see langword="null"/> for <see cref="EqualityComparer{T}.Default"/>.</param>
    /// <returns><see langword="true"/> when both are <see langword="null"/>, or both are non-null and element-wise equal.</returns>
    public static bool SequenceEqual<T>(IEnumerable<T>? left, IEnumerable<T>? right, IEqualityComparer<T>? comparer = null)
    {
        if(left is null || right is null)
        {
            return ReferenceEquals(left, right);
        }

        return left.SequenceEqual(right, comparer);
    }


    /// <summary>
    /// Computes an order-sensitive hash code over a sequence, consistent with <see cref="SequenceEqual"/>: a
    /// <see langword="null"/> sequence hashes to <c>0</c>, and two sequences equal under <see cref="SequenceEqual"/>
    /// hash equal.
    /// </summary>
    /// <typeparam name="T">The element type.</typeparam>
    /// <param name="items">The sequence, or <see langword="null"/>.</param>
    /// <param name="comparer">The element comparer, or <see langword="null"/> for <see cref="EqualityComparer{T}.Default"/>.</param>
    /// <returns>A hash code over <paramref name="items"/>.</returns>
    public static int SequenceHashCode<T>(IEnumerable<T>? items, IEqualityComparer<T>? comparer = null)
    {
        if(items is null)
        {
            return 0;
        }

        comparer ??= EqualityComparer<T>.Default;

        var hash = new HashCode();
        foreach(T item in items)
        {
            hash.Add(item is null ? 0 : comparer.GetHashCode(item));
        }

        return hash.ToHashCode();
    }


    //Materialized JSON objects are Dictionary<string, object>, which is an IReadOnlyDictionary<string, object>;
    //matching that interface covers every value the leaf converter produces and any hand-built read-only map.
    private static bool TryAsMap(object value, [NotNullWhen(true)] out IReadOnlyDictionary<string, object>? map)
    {
        map = value as IReadOnlyDictionary<string, object>;

        return map is not null;
    }


    //Materialized JSON arrays are List<object>, which is an IReadOnlyList<object>; string is not, so a scalar
    //string is correctly classified as a leaf rather than a sequence.
    private static bool TryAsList(object value, [NotNullWhen(true)] out IReadOnlyList<object>? list)
    {
        list = value as IReadOnlyList<object>;

        return list is not null;
    }
}
