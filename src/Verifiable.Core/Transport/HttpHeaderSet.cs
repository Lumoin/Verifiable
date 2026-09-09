using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Transport;

/// <summary>
/// An immutable HTTP header set — case-insensitive and multi-valued per
/// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110 §5.1</see>: "Field names are
/// case-insensitive". Preserves first-appearance name order and, within a name, received value order.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110 §5.3</see> (Field Order): "A
/// recipient MAY combine multiple field lines within a field section that have the same field name into
/// one field line, without changing the semantics of the message, by appending each subsequent field line
/// value to the initial field line value in order" — implemented as <see cref="GetValues(string)"/>, which
/// never joins the values with a comma; the caller decides whether and how to combine them. "[A] proxy MUST
/// NOT change the order of these field line values when forwarding a message" — the set never reorders a
/// name's received values. "[A] sender MUST NOT generate multiple field lines with the same name in a
/// message … unless that field's definition allows multiple field line values to be recombined as a
/// comma-separated list" — enforced by <see cref="Builder.Add(string, string)"/>, which throws on a second
/// line for a name already present; a caller that knows the field allows a list uses
/// <see cref="Builder.AddValues(string, IReadOnlyList{string})"/> instead. RFC 9110 §5.3 also records that
/// <c>Set-Cookie</c> violates this rule in practice (it appears as repeated field lines that are not a
/// comma-separated list) — a caller composing <c>Set-Cookie</c> uses <see cref="AddValues"/>/<see cref="WithValues"/>,
/// never <see cref="Add"/>/<see cref="With"/>.
/// </para>
/// <para>
/// A known header name is stored under its canonical spelling
/// (<see cref="WellKnownHttpHeaderNames.GetCanonicalizedValue(string)"/>); an unrecognized name is stored
/// exactly as first received. Lookup by <see cref="TryGetValue"/>, <see cref="GetValues"/>, and
/// <see cref="Contains"/> is case-insensitive regardless of stored casing.
/// </para>
/// <para>
/// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.5">RFC 9110, Section 5.5</see>: "Field values
/// containing CR, LF, or NUL characters are invalid and dangerous, due to the varying ways that
/// implementations might parse and interpret those characters". Every value a caller composes onto this set
/// — <see cref="Builder.Add"/>, <see cref="Builder.AddValues"/>, <see cref="FromPairs"/>, <see cref="With"/>,
/// <see cref="WithValues"/> — is checked for those three characters and rejected. A value is never trimmed:
/// leading and trailing whitespace is carried exactly as received.
/// </para>
/// <para>
/// <see cref="FromReceived"/> is the one factory for header lines a transport decoded off the wire — the
/// recipient side of the same RFC 9110 §5.5 sentence, which continues: "a recipient of CR, LF, or NUL
/// within a field value MUST either reject the message or replace each of those characters with SP before
/// further processing or forwarding of that message." Unlike every composing-side entry point above, which
/// throws, <see cref="FromReceived"/> takes the replace-with-SP arm, and drops a name that is not an RFC
/// 9110 §5.6.2 token rather than throwing (a well-formed field line cannot carry one, so keeping it would
/// misrepresent what was received).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class HttpHeaderSet
{
    /// <summary>The shared empty value list handed back for a name the set does not carry.</summary>
    private static ReadOnlyCollection<string> EmptyValues { get; } = new([]);

    /// <summary>The distinct header names this set carries, in first-appearance order.</summary>
    private ReadOnlyCollection<string> NamesInOrder { get; }

    /// <summary>Each carried name's field lines, keyed case-insensitively.</summary>
    private Dictionary<string, ReadOnlyCollection<string>> ValuesByName { get; }


    /// <summary>Wraps already-validated name order and value storage into an immutable set.</summary>
    /// <param name="namesInOrder">The distinct names, in first-appearance order.</param>
    /// <param name="valuesByName">Each name's field lines, keyed case-insensitively.</param>
    private HttpHeaderSet(ReadOnlyCollection<string> namesInOrder, Dictionary<string, ReadOnlyCollection<string>> valuesByName)
    {
        this.NamesInOrder = namesInOrder;
        this.ValuesByName = valuesByName;
    }


    /// <summary>The empty header set.</summary>
    public static HttpHeaderSet Empty { get; } = new HttpHeaderSet(
        new ReadOnlyCollection<string>([]),
        new Dictionary<string, ReadOnlyCollection<string>>(0, StringComparer.OrdinalIgnoreCase));


    /// <summary>The number of distinct header names present.</summary>
    public int Count => NamesInOrder.Count;

    /// <summary>
    /// The header names, in first-appearance order. A well-known name is canonicalized
    /// (<see cref="WellKnownHttpHeaderNames.GetCanonicalizedValue(string)"/>); an unrecognized name is the
    /// casing it was first received under.
    /// </summary>
    public IReadOnlyList<string> Names => NamesInOrder;


    /// <summary>Whether <paramref name="name"/> is present, compared case-insensitively.</summary>
    /// <param name="name">The header name.</param>
    public bool Contains(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        return ValuesByName.ContainsKey(name);
    }


    /// <summary>
    /// Tries to read the first received value for <paramref name="name"/>, compared case-insensitively.
    /// Chosen so today's <c>request.Headers.TryGetValue("Content-Type", out string? x)</c> call shape
    /// compiles unchanged against a single-valued field; a caller that needs every value uses
    /// <see cref="GetValues(string)"/>.
    /// </summary>
    /// <param name="name">The header name.</param>
    /// <param name="first">The first value when the header is present; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the header is present with at least one value.</returns>
    public bool TryGetValue(string name, [NotNullWhen(true)] out string? first)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        if(ValuesByName.TryGetValue(name, out ReadOnlyCollection<string>? values) && values.Count > 0)
        {
            first = values[0];

            return true;
        }

        first = null;

        return false;
    }


    /// <summary>
    /// Every value received for <paramref name="name"/>, in received order — the RFC 9110 §5.3 MAY-combine
    /// list, never comma-joined. Compared case-insensitively.
    /// </summary>
    /// <param name="name">The header name.</param>
    /// <returns>The values, or an empty list when <paramref name="name"/> is absent.</returns>
    public IReadOnlyList<string> GetValues(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        return ValuesByName.TryGetValue(name, out ReadOnlyCollection<string>? values) ? values : EmptyValues;
    }


    /// <summary>The first <see cref="WellKnownHttpHeaderNames.ContentType"/> value, or <see langword="null"/>.</summary>
    public string? ContentType => TryGetValue(WellKnownHttpHeaderNames.ContentType, out string? value) ? value : null;

    /// <summary>The first <see cref="WellKnownHttpHeaderNames.Accept"/> value, or <see langword="null"/>.</summary>
    public string? Accept => TryGetValue(WellKnownHttpHeaderNames.Accept, out string? value) ? value : null;

    /// <summary>The first <see cref="WellKnownHttpHeaderNames.Location"/> value, or <see langword="null"/>.</summary>
    public string? Location => TryGetValue(WellKnownHttpHeaderNames.Location, out string? value) ? value : null;


    /// <summary>
    /// Returns a new set with <paramref name="name"/> set to the single value <paramref name="value"/>,
    /// replacing any values <paramref name="name"/> already carried. Every other name's values are carried
    /// forward unchanged, in their original order.
    /// </summary>
    /// <param name="name">The header name; validated as an RFC 9110 §5.6.2 token.</param>
    /// <param name="value">The value.</param>
    public HttpHeaderSet With(string name, string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(value);
        ValidateFieldName(name);
        ValidateFieldValue(value);

        return Replace(name, [value]);
    }


    /// <summary>
    /// Returns a new set with <paramref name="name"/> set to <paramref name="values"/> (a field whose
    /// definition allows multiple field lines, RFC 9110 §5.3), replacing any values <paramref name="name"/>
    /// already carried. Every other name's values are carried forward unchanged, in their original order.
    /// </summary>
    /// <param name="name">The header name; validated as an RFC 9110 §5.6.2 token.</param>
    /// <param name="values">The values, in the order they are to be carried.</param>
    public HttpHeaderSet WithValues(string name, IReadOnlyList<string> values)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(values);
        ValidateFieldName(name);

        foreach(string value in values)
        {
            ArgumentNullException.ThrowIfNull(value);
            ValidateFieldValue(value);
        }

        return Replace(name, values);
    }


    /// <summary>Builds a new set carrying every name unchanged except <paramref name="name"/>, whose field lines become <paramref name="values"/>.</summary>
    /// <param name="name">The header name to replace or add, already canonicalized-comparable.</param>
    /// <param name="values">The field lines <paramref name="name"/> carries on the new set.</param>
    private HttpHeaderSet Replace(string name, IReadOnlyList<string> values)
    {
        string canonical = WellKnownHttpHeaderNames.GetCanonicalizedValue(name);
        var builder = new Builder();
        bool replaced = false;

        foreach(string existing in NamesInOrder)
        {
            if(string.Equals(existing, canonical, StringComparison.OrdinalIgnoreCase))
            {
                builder.AddValues(canonical, values);
                replaced = true;
            }
            else
            {
                builder.AddValues(existing, ValuesByName[existing]);
            }
        }

        if(!replaced)
        {
            builder.AddValues(canonical, values);
        }

        return builder.Build();
    }


    /// <summary>
    /// Builds a set from name/value pairs — each entry a received field line. Consecutive or scattered
    /// pairs sharing a name (case-insensitively) are grouped into that name's <see cref="GetValues(string)"/>
    /// list, in the order the pairs appear; a name's group takes the position of its first pair.
    /// </summary>
    /// <param name="pairs">The name/value pairs.</param>
    public static HttpHeaderSet FromPairs(params ReadOnlySpan<(string Name, string Value)> pairs)
    {
        List<string> order = [];
        Dictionary<string, List<string>> grouped = new(StringComparer.OrdinalIgnoreCase);

        foreach((string name, string value) in pairs)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(name);
            ArgumentNullException.ThrowIfNull(value);
            ValidateFieldName(name);
            ValidateFieldValue(value);

            string canonical = WellKnownHttpHeaderNames.GetCanonicalizedValue(name);
            if(!grouped.TryGetValue(canonical, out List<string>? values))
            {
                values = [];
                grouped[canonical] = values;
                order.Add(canonical);
            }

            values.Add(value);
        }

        var builder = new Builder();
        foreach(string name in order)
        {
            builder.AddValues(name, grouped[name]);
        }

        return builder.Build();
    }


    /// <summary>
    /// Builds a set from header lines as a receiving transport decoded them off the wire — the recipient
    /// side of <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.5">RFC 9110, Section 5.5</see>,
    /// which every composing-side entry point on this type takes the opposite (reject) arm of: "a recipient
    /// of CR, LF, or NUL within a field value MUST either reject the message or replace each of those
    /// characters with SP before further processing or forwarding of that message." Every value here takes
    /// the replace arm instead of throwing. A name that is not an RFC 9110 §5.6.2 token names no field and
    /// is dropped rather than rejecting the whole set — it cannot be the name a well-formed field line
    /// carries. Names are grouped case-insensitively in received order, exactly as <see cref="FromPairs"/>
    /// groups its pairs (RFC 9110 §5.3's recipient MAY-combine); a group takes the position of its first
    /// received line.
    /// </summary>
    /// <param name="fieldLines">The received field lines, name to value, in received order.</param>
    public static HttpHeaderSet FromReceived(IEnumerable<(string Name, string Value)> fieldLines)
    {
        ArgumentNullException.ThrowIfNull(fieldLines);

        List<string> order = [];
        Dictionary<string, List<string>> grouped = new(StringComparer.OrdinalIgnoreCase);

        foreach((string name, string value) in fieldLines)
        {
            if(string.IsNullOrEmpty(name) || !IsFieldNameToken(name))
            {
                continue;
            }

            string canonical = WellKnownHttpHeaderNames.GetCanonicalizedValue(name);
            if(!grouped.TryGetValue(canonical, out List<string>? values))
            {
                values = [];
                grouped[canonical] = values;
                order.Add(canonical);
            }

            values.Add(SanitizeReceivedValue(value));
        }

        var builder = new Builder();
        foreach(string name in order)
        {
            builder.AddValues(name, grouped[name]);
        }

        return builder.Build();
    }


    /// <summary>
    /// Whether <paramref name="name"/> is an RFC 9110 §5.6.2 token: "token = 1*tchar" over "tchar = '!' /
    /// '#' / '$' / '%' / '&amp;' / ''' / '*' / '+' / '-' / '.' / '^' / '_' / '`' / '|' / '~' / DIGIT / ALPHA".
    /// The shared test both <see cref="ValidateFieldName"/> (which throws for a composing-side caller) and
    /// <see cref="FromReceived"/> (which drops for a receiving one) apply.
    /// </summary>
    /// <param name="name">The candidate field name.</param>
    private static bool IsFieldNameToken(string name)
    {
        foreach(char c in name)
        {
            if(!(char.IsAsciiLetterOrDigit(c) || "!#$%&'*+-.^_`|~".Contains(c, StringComparison.Ordinal)))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Replaces every CR, LF, or NUL in <paramref name="value"/> with SP — RFC 9110 §5.5's replace arm for a
    /// received field value — leaving every other character, including surrounding whitespace, untouched.
    /// </summary>
    /// <param name="value">The received field value.</param>
    private static string SanitizeReceivedValue(string value)
    {
        if(value.AsSpan().IndexOfAny('\r', '\n', '\0') < 0)
        {
            return value;
        }

        char[] sanitized = value.ToCharArray();
        for(int i = 0; i < sanitized.Length; ++i)
        {
            if(sanitized[i] is '\r' or '\n' or '\0')
            {
                sanitized[i] = ' ';
            }
        }

        return new string(sanitized);
    }


    /// <summary>
    /// RFC 9110 §5.6.2: "token = 1*tchar". A header name a caller composes onto this set — never a name a
    /// receiving transport already decoded, which <see cref="FromReceived"/> alone reads — is API misuse
    /// when it is not a token, and throws rather than being silently accepted or dropped.
    /// </summary>
    /// <param name="name">The candidate field name.</param>
    /// <exception cref="ArgumentException"><paramref name="name"/> is not an RFC 9110 §5.6.2 token.</exception>
    private static void ValidateFieldName(string name)
    {
        foreach(char c in name)
        {
            bool isTchar = char.IsAsciiLetterOrDigit(c) || "!#$%&'*+-.^_`|~".Contains(c, StringComparison.Ordinal);
            if(!isTchar)
            {
                throw new ArgumentException(
                    $"'{name}' is not a valid HTTP field name (RFC 9110 §5.6.2 token) — the character '{c}' is not a tchar.",
                    nameof(name));
            }
        }
    }


    /// <summary>
    /// RFC 9110 §5.5: "Field values containing CR, LF, or NUL characters are invalid and dangerous, due to
    /// the varying ways that implementations might parse and interpret those characters; a recipient of CR,
    /// LF, or NUL within a field value MUST either reject the message or replace each of those characters
    /// with SP before further processing or forwarding of that message." A value a caller composes onto
    /// this set — never a value a receiving transport already decoded, which <see cref="FromReceived"/>
    /// alone reads, taking the replace arm — takes the reject arm: left uncaught, a canned or third-party
    /// <c>OutboundTransportDelegate</c> that writes raw bytes could emit an injected header line. The value
    /// is not otherwise altered: leading and trailing whitespace is preserved as received.
    /// </summary>
    /// <param name="value">The candidate field value.</param>
    /// <exception cref="ArgumentException"><paramref name="value"/> contains a CR, LF, or NUL character.</exception>
    private static void ValidateFieldValue(string value)
    {
        foreach(char c in value)
        {
            if(c is '\r' or '\n' or '\0')
            {
                throw new ArgumentException(
                    $"'{value}' contains a CR, LF, or NUL character; RFC 9110 §5.5 calls a field value " +
                    "with one of those characters invalid and dangerous.",
                    nameof(value));
            }
        }
    }


    /// <summary>The compact string the debugger displays for an instance of this type.</summary>
    private string DebuggerDisplay => $"HttpHeaderSet ({Count} headers)";


    /// <summary>
    /// Accumulates header name/value entries into an <see cref="HttpHeaderSet"/>, preserving the order
    /// entries are added.
    /// </summary>
    public sealed class Builder
    {
        /// <summary>The distinct names added so far, in the order they were first added.</summary>
        private List<string> NamesInOrder { get; } = [];

        /// <summary>Each added name's field lines, keyed case-insensitively.</summary>
        private Dictionary<string, ReadOnlyCollection<string>> ValuesByName { get; } = new(StringComparer.OrdinalIgnoreCase);


        /// <summary>
        /// Adds a single-valued header. Throws when <paramref name="name"/> is already present — RFC 9110
        /// §5.3: "a sender MUST NOT generate multiple field lines with the same name in a message … unless
        /// that field's definition allows multiple field line values to be recombined as a comma-separated
        /// list". A field that allows a list uses <see cref="AddValues(string, IReadOnlyList{string})"/>.
        /// </summary>
        /// <param name="name">The header name; validated as an RFC 9110 §5.6.2 token.</param>
        /// <param name="value">The value.</param>
        /// <exception cref="ArgumentException"><paramref name="name"/> already has field lines on this builder, or is not a valid token.</exception>
        public Builder Add(string name, string value)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(name);
            ArgumentNullException.ThrowIfNull(value);

            return AddValues(name, [value]);
        }


        /// <summary>
        /// Adds a header whose definition allows multiple field lines to be recombined as a list (RFC 9110
        /// §5.3), in the order <paramref name="values"/> is given. Throws when <paramref name="name"/> is
        /// already present.
        /// </summary>
        /// <param name="name">The header name; validated as an RFC 9110 §5.6.2 token.</param>
        /// <param name="values">The values, in the order they were received or are to be sent.</param>
        /// <exception cref="ArgumentException"><paramref name="name"/> already has field lines on this builder, or is not a valid token.</exception>
        public Builder AddValues(string name, IReadOnlyList<string> values)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(name);
            ArgumentNullException.ThrowIfNull(values);
            ValidateFieldName(name);

            string canonical = WellKnownHttpHeaderNames.GetCanonicalizedValue(name);
            if(ValuesByName.ContainsKey(canonical))
            {
                throw new ArgumentException(
                    $"'{canonical}' already has field lines on this builder; supply every value for a name in one AddValues call (RFC 9110 §5.3).",
                    nameof(name));
            }

            var copy = new string[values.Count];
            for(int i = 0; i < values.Count; ++i)
            {
                string value = values[i];
                ArgumentNullException.ThrowIfNull(value);
                ValidateFieldValue(value);
                copy[i] = value;
            }

            NamesInOrder.Add(canonical);
            ValuesByName[canonical] = new ReadOnlyCollection<string>(copy);

            return this;
        }


        /// <summary>Builds the immutable <see cref="HttpHeaderSet"/> from the entries added so far.</summary>
        public HttpHeaderSet Build() =>
            new(
                new ReadOnlyCollection<string>([.. NamesInOrder]),
                new Dictionary<string, ReadOnlyCollection<string>>(ValuesByName, StringComparer.OrdinalIgnoreCase));
    }
}
