using System.Diagnostics.CodeAnalysis;

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
    /// Determines whether two materialized-JSON values are structurally equal: two maps match iff their member-name
    /// sets are equal under ordinal comparison and the values under each name are structurally equal, whatever
    /// comparer either map carries (member order is irrelevant); lists match iff they are element-wise structurally
    /// equal in order; and scalars match by CLR value. Member names compare code unit by code unit, the comparison
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.3">RFC 8259 Section 8.3</see> names
    /// interoperable: "Implementations that transform the textual representation into sequences of Unicode code
    /// units and then perform the comparison numerically, code unit by code unit, are interoperable in the sense
    /// that implementations will agree in all cases on equality or inequality of two strings." The walk is
    /// iterative with an explicit work stack, never recursion, so its call-stack use is bounded independently of
    /// input nesting.
    /// </summary>
    /// <remarks>
    /// A map's own comparer decides which names it can hold, not which names match: a map over a comparer that
    /// ignores letter case holding <c>account</c> does not match a map holding <c>ACCOUNT</c>. A map whose
    /// comparer is known to be ordinal is read directly; any other map is read through an ordinal view built for
    /// the comparison (<see cref="AsOrdinalLookup"/>). A map can hold one name twice, under two strings that are
    /// ordinally equal, only when its comparer tells such strings apart; its ordinal view then holds fewer names
    /// than the map. The comparison refuses such a map: it is equal to no value other than itself (the same
    /// object), so neither of its values under the repeated name decides a match.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 Section 4</see>: "When the names
    /// within an object are not unique, the behavior of software that receives such an object is unpredictable."
    /// </remarks>
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
                if(!TryAsMap(b, out IReadOnlyDictionary<string, object>? rightMap))
                {
                    return false;
                }

                //A view holding fewer names than its map means the map holds one name twice; such a map equals
                //only itself, so the comparison neither reads one of its values nor descends into it.
                Dictionary<string, object> leftByOrdinalName = AsOrdinalLookup(leftMap);
                Dictionary<string, object> rightByOrdinalName = AsOrdinalLookup(rightMap);
                bool hasRepeatedName = leftByOrdinalName.Count != leftMap.Count || rightByOrdinalName.Count != rightMap.Count;
                if(hasRepeatedName)
                {
                    if(!ReferenceEquals(a, b))
                    {
                        return false;
                    }

                    continue;
                }

                //Each view's names are distinct ordinally: equal counts plus every left name present ordinally in
                //right implies equal ordinal name sets.
                if(leftByOrdinalName.Count != rightByOrdinalName.Count)
                {
                    return false;
                }

                foreach(KeyValuePair<string, object> entry in leftByOrdinalName)
                {
                    if(!rightByOrdinalName.TryGetValue(entry.Key, out object? rightValue))
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
    /// map contributes the count and an order-independent combination of the ordinal hashes of the member names
    /// of its ordinal view (<see cref="AsOrdinalLookup"/>), the name set <see cref="JsonEqual"/> compares, a list
    /// its element count, and a scalar its own hash. The summary is intentionally shallow: it does not descend
    /// into nested values, which keeps it cheap while preserving the equal-implies-equal-hash contract (it never
    /// claims two unequal graphs differ). A map holding one name twice is equal only to itself, and its hash is
    /// computed from its own members each time, so equal values hash equal for it too.
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
            //XOR over the ordinal names is order-independent, matching the ordinal name-set equality JsonEqual uses.
            Dictionary<string, object> byOrdinalName = AsOrdinalLookup(map);
            int nameAccumulator = 0;
            foreach(string name in byOrdinalName.Keys)
            {
                nameAccumulator ^= name.GetHashCode(StringComparison.Ordinal);
            }

            return HashCode.Combine(byOrdinalName.Count, nameAccumulator);
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


    /// <summary>
    /// The view of <paramref name="map"/> that finds a member name code unit by code unit, the comparison
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.3">RFC 8259 Section 8.3</see> names
    /// interoperable: the map itself when it is a <see cref="Dictionary{TKey, TValue}"/> whose comparer is ordinal,
    /// else a copy of its members into a map over <see cref="StringComparer.Ordinal"/>, built for one comparison.
    /// </summary>
    /// <remarks>
    /// A map over a comparer that ignores letter case finds <c>ACCOUNT</c> under <c>account</c>; its ordinal view
    /// does not. The copy keeps the first of any names that are ordinally equal, so the view's names are distinct
    /// ordinally whatever comparer the map carries. A view holding fewer names than its map is the refusal's
    /// signal: <see cref="JsonEqual"/> holds such a map equal to itself only and reads none of its values through
    /// the view.
    /// </remarks>
    /// <param name="map">A materialized JSON object.</param>
    /// <returns>A map holding the members of <paramref name="map"/> and looking their names up ordinally.</returns>
    private static Dictionary<string, object> AsOrdinalLookup(IReadOnlyDictionary<string, object> map) => map switch
    {
        Dictionary<string, object> dictionary when IsOrdinal(dictionary.Comparer) => dictionary,
        _ => CopyByOrdinalName(map)
    };


    /// <summary>
    /// Whether <paramref name="comparer"/> compares strings code unit by code unit: the default string equality
    /// comparer, which a <see cref="Dictionary{TKey, TValue}"/> built without a comparer reports, or
    /// <see cref="StringComparer.Ordinal"/>.
    /// </summary>
    /// <param name="comparer">The comparer a map reports.</param>
    /// <returns><see langword="true"/> when the comparer is known to be ordinal.</returns>
    private static bool IsOrdinal(IEqualityComparer<string> comparer) =>
        ReferenceEquals(comparer, EqualityComparer<string>.Default) || ReferenceEquals(comparer, StringComparer.Ordinal);


    /// <summary>
    /// Copies the members of <paramref name="map"/> into a map over <see cref="StringComparer.Ordinal"/>, keeping
    /// the first of any names that are ordinally equal.
    /// </summary>
    /// <param name="map">A materialized JSON object whose comparer is not known to be ordinal.</param>
    /// <returns>The ordinal copy.</returns>
    private static Dictionary<string, object> CopyByOrdinalName(IReadOnlyDictionary<string, object> map)
    {
        var byOrdinalName = new Dictionary<string, object>(map.Count, StringComparer.Ordinal);
        foreach(KeyValuePair<string, object> entry in map)
        {
            _ = byOrdinalName.TryAdd(entry.Key, entry.Value);
        }

        return byOrdinalName;
    }
}
