using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace Verifiable.Server;

/// <summary>
/// Span-conservative, allocation-aware JSON building primitives shared
/// across the protocol families' response composers, metadata builders, and
/// entity-statement serialisers.
/// </summary>
/// <remarks>
/// <para>
/// The endpoint host and its protocol families deliberately carry no JSON
/// serialisation library dependency — STJ pulls in reflection-driven generic
/// infrastructure the rest of the library does not need. This appender is the single place
/// where JSON object/array/value structure and escape rules live. Every
/// consumer routes through these methods so escape coverage and field-
/// ordering invariants are defined once.
/// </para>
/// <para>
/// Two complementary styles are offered:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       <see cref="AppendObject"/>, <see cref="AppendValue"/>,
///       <see cref="AppendArray"/> — dispatch walker for callers with a
///       <c>Dictionary&lt;string, object&gt;</c>-shaped value ready. Used by
///       Federation entity statements.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="AppendStringField"/>, <see cref="AppendInt64Field"/>,
///       <see cref="AppendBoolField"/>, <see cref="AppendUriField"/>,
///       <see cref="AppendStringArrayField"/>,
///       <see cref="AppendUriArrayField"/>, <see cref="AppendRawField"/> —
///       incremental writers used by callers composing a JSON object
///       field-by-field with branching on which fields are populated. The
///       <c>ref bool first</c> parameter tracks whether the field is the
///       first emitted (no leading comma) and is flipped to <c>false</c>
///       after the call.
///     </description>
///   </item>
/// </list>
/// <para>
/// Escape coverage matches
/// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-7">RFC 8259 §7</see>:
/// the named escapes for U+0008..U+000D + U+0022 + U+005C, and
/// <c>\u00XX</c> for the remaining control characters U+0000..U+001F.
/// Hex digits are lowercase, matching STJ output.
/// </para>
/// <para>
/// A small <see cref="StringBuilder"/> pool (<see cref="Rent"/>/<see cref="Return"/>)
/// reduces allocation on burst response composition. The pool has a soft
/// upper bound; over-capacity returns are discarded. <see cref="Rent"/> is
/// safe to call without a matching <see cref="Return"/> — the cost is a
/// missed pooling opportunity, not a leak.
/// </para>
/// </remarks>
[DebuggerDisplay("JsonAppender")]
public static class JsonAppender
{
    private const int DefaultCapacity = 256;
    private const int MaxPooledCapacity = 64 * 1024;
    private const int MaxPoolSize = 16;

    private static ConcurrentQueue<StringBuilder> Pool { get; } = new();
    private static int pooledCount;


    /// <summary>
    /// Rents a <see cref="StringBuilder"/> from the pool, or allocates a
    /// fresh one when the pool is empty. The returned instance is cleared
    /// and ready to write into. Callers should pair every <see cref="Rent"/>
    /// with <see cref="Return"/> when done — the call is safe to omit but
    /// loses the pooling benefit on that call.
    /// </summary>
    /// <param name="initialCapacity">
    /// Hint for the initial buffer capacity. Honoured when allocating fresh;
    /// ignored when a pooled instance is available (the pooled instance keeps
    /// its existing capacity).
    /// </param>
    public static StringBuilder Rent(int initialCapacity = DefaultCapacity)
    {
        if(Pool.TryDequeue(out StringBuilder? sb))
        {
            Interlocked.Decrement(ref pooledCount);
            sb.Clear();

            return sb;
        }

        return new StringBuilder(initialCapacity);
    }


    /// <summary>
    /// UTF-8 encodes the content of <paramref name="sb"/> directly into a
    /// freshly-allocated byte array, walking <see cref="StringBuilder.GetChunks"/>
    /// without materialising an intermediate <see cref="string"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The returned <c>byte[]</c> is heap-allocated and unpooled — it
    /// typically flows out of the call site through a value type
    /// (e.g. <c>TaggedMemory&lt;byte&gt;</c>) that carries no ownership
    /// contract, so the buffer's lifetime is GC-bound. Routing this
    /// through a pooled owner would require widening the consumer's
    /// ownership model and is a separate design choice.
    /// </para>
    /// </remarks>
    public static byte[] ToUtf8Bytes(StringBuilder sb)
    {
        ArgumentNullException.ThrowIfNull(sb);

        Encoding utf8 = Encoding.UTF8;
        int byteCount = 0;
        foreach(ReadOnlyMemory<char> chunk in sb.GetChunks())
        {
            byteCount += utf8.GetByteCount(chunk.Span);
        }

        byte[] bytes = new byte[byteCount];
        int written = 0;
        foreach(ReadOnlyMemory<char> chunk in sb.GetChunks())
        {
            written += utf8.GetBytes(chunk.Span, bytes.AsSpan(written));
        }

        return bytes;
    }


    /// <summary>
    /// Returns a <see cref="StringBuilder"/> rented via <see cref="Rent"/>
    /// to the pool. Instances exceeding <c>MaxPooledCapacity</c> are dropped
    /// to keep the pool bounded; oversize transient allocations should not
    /// pin large buffers across requests. Soft upper bound on pool size
    /// avoids unbounded growth under cold-start bursts.
    /// </summary>
    public static void Return(StringBuilder sb)
    {
        ArgumentNullException.ThrowIfNull(sb);

        if(sb.Capacity > MaxPooledCapacity)
        {
            return;
        }

        if(Interlocked.Increment(ref pooledCount) > MaxPoolSize)
        {
            Interlocked.Decrement(ref pooledCount);
            return;
        }

        Pool.Enqueue(sb);
    }


    /// <summary>
    /// Appends a JSON object literal — <c>{"k1":v1,"k2":v2,...}</c> — to
    /// <paramref name="sb"/>. Property values are dispatched through
    /// <see cref="AppendValue"/>. The dictionary's enumeration order is
    /// preserved on the wire; callers that need deterministic ordering
    /// must pass an ordered dictionary.
    /// </summary>
    public static void AppendObject(StringBuilder sb, IReadOnlyDictionary<string, object> dict)
    {
        ArgumentNullException.ThrowIfNull(sb);
        ArgumentNullException.ThrowIfNull(dict);

        sb.Append('{');
        bool first = true;
        foreach(KeyValuePair<string, object> entry in dict)
        {
            if(!first)
            {
                sb.Append(',');
            }

            first = false;
            sb.Append('"');
            AppendEscapedString(sb, entry.Key);
            sb.Append("\":");
            AppendValue(sb, entry.Value);
        }

        sb.Append('}');
    }


    /// <summary>
    /// Appends a single JSON value, dispatching on the runtime CLR type of
    /// <paramref name="value"/>. Strings, booleans, numeric primitives,
    /// <see cref="Uri"/>, nested dictionaries, and enumerables are
    /// recognised explicitly; <see cref="IFormattable"/> values fall through
    /// to invariant-culture formatting. Any other type is wrapped as a JSON
    /// string via <see cref="object.ToString"/>.
    /// </summary>
    public static void AppendValue(StringBuilder sb, object? value)
    {
        ArgumentNullException.ThrowIfNull(sb);

        _ = value switch
        {
            null => AppendNull(sb),
            string s => AppendQuoted(sb, s),
            bool b => AppendBoolLiteral(sb, b),
            Uri uri => AppendQuoted(sb, uri.ToString()),
            byte or sbyte or short or ushort or int or uint or long or ulong => AppendNumber(sb, (IFormattable)value, null),
            float or double or decimal => AppendNumber(sb, (IFormattable)value, "G"),
            IReadOnlyDictionary<string, object> nested => AppendNestedObject(sb, nested),
            IEnumerable<object?> list => AppendNestedArray(sb, list),
            IFormattable formattable => AppendQuoted(sb, formattable.ToString(null, CultureInfo.InvariantCulture)),
            _ => AppendQuoted(sb, value.ToString() ?? string.Empty)
        };

        static bool AppendNull(StringBuilder sb)
        {
            sb.Append("null");

            return true;
        }

        static bool AppendQuoted(StringBuilder sb, string s)
        {
            sb.Append('"');
            AppendEscapedString(sb, s);
            sb.Append('"');

            return true;
        }

        static bool AppendBoolLiteral(StringBuilder sb, bool b)
        {
            sb.Append(b ? "true" : "false");

            return true;
        }

        static bool AppendNumber(StringBuilder sb, IFormattable formattable, string? format)
        {
            sb.Append(formattable.ToString(format, CultureInfo.InvariantCulture));

            return true;
        }

        static bool AppendNestedObject(StringBuilder sb, IReadOnlyDictionary<string, object> nested)
        {
            AppendObject(sb, nested);

            return true;
        }

        static bool AppendNestedArray(StringBuilder sb, IEnumerable<object?> list)
        {
            AppendArray(sb, list);

            return true;
        }
    }


    /// <summary>
    /// Appends a JSON array literal — <c>[v1,v2,...]</c> — to
    /// <paramref name="sb"/> by walking <paramref name="items"/> through
    /// <see cref="AppendValue"/>.
    /// </summary>
    public static void AppendArray(StringBuilder sb, IEnumerable<object?> items)
    {
        ArgumentNullException.ThrowIfNull(sb);
        ArgumentNullException.ThrowIfNull(items);

        sb.Append('[');
        bool first = true;
        foreach(object? item in items)
        {
            if(!first)
            {
                sb.Append(',');
            }

            first = false;
            AppendValue(sb, item);
        }

        sb.Append(']');
    }


    /// <summary>
    /// Appends a JSON-escaped string body — without surrounding quotes — to
    /// <paramref name="sb"/>. Escapes the characters RFC 8259 §7 requires:
    /// <c>\"</c>, <c>\\</c>, <c>\b</c>, <c>\f</c>, <c>\n</c>, <c>\r</c>,
    /// <c>\t</c>, and <c>\uXXXX</c> for the remaining U+0000..U+001F control
    /// characters. Hex digits are lowercase.
    /// </summary>
    public static void AppendEscapedString(StringBuilder sb, string value)
    {
        ArgumentNullException.ThrowIfNull(sb);
        ArgumentNullException.ThrowIfNull(value);

        for(int i = 0; i < value.Length; ++i)
        {
            char c = value[i];
            _ = c switch
            {
                '"' => AppendLiteral(sb, "\\\""),
                '\\' => AppendLiteral(sb, "\\\\"),
                '\b' => AppendLiteral(sb, "\\b"),
                '\f' => AppendLiteral(sb, "\\f"),
                '\n' => AppendLiteral(sb, "\\n"),
                '\r' => AppendLiteral(sb, "\\r"),
                '\t' => AppendLiteral(sb, "\\t"),
                < (char)0x20 => AppendControlEscape(sb, c),
                _ => AppendChar(sb, c)
            };
        }

        static bool AppendLiteral(StringBuilder sb, string escape)
        {
            sb.Append(escape);

            return true;
        }

        static bool AppendControlEscape(StringBuilder sb, char c)
        {
            sb.Append("\\u");
            sb.Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));

            return true;
        }

        static bool AppendChar(StringBuilder sb, char c)
        {
            sb.Append(c);

            return true;
        }
    }


    /// <summary>
    /// Appends a <c>"key":"value"</c> string-valued field to an in-progress
    /// JSON object. Emits a leading comma when <paramref name="first"/> is
    /// <see langword="false"/>; flips it to <see langword="false"/> on
    /// return.
    /// </summary>
    public static void AppendStringField(
        StringBuilder sb, string key, string value, ref bool first)
    {
        ArgumentNullException.ThrowIfNull(sb);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(value);

        if(!first)
        {
            sb.Append(',');
        }

        sb.Append('"');
        AppendEscapedString(sb, key);
        sb.Append("\":\"");
        AppendEscapedString(sb, value);
        sb.Append('"');

        first = false;
    }


    /// <summary>
    /// Appends a <c>"key":n</c> integer-valued field to an in-progress JSON
    /// object. Integer is formatted with invariant culture.
    /// </summary>
    public static void AppendInt64Field(
        StringBuilder sb, string key, long value, ref bool first)
    {
        ArgumentNullException.ThrowIfNull(sb);
        ArgumentNullException.ThrowIfNull(key);

        if(!first)
        {
            sb.Append(',');
        }

        sb.Append('"');
        AppendEscapedString(sb, key);
        sb.Append("\":");
        sb.Append(value.ToString(CultureInfo.InvariantCulture));

        first = false;
    }


    /// <summary>
    /// Appends a <c>"key":true|false</c> boolean-valued field to an
    /// in-progress JSON object.
    /// </summary>
    public static void AppendBoolField(
        StringBuilder sb, string key, bool value, ref bool first)
    {
        ArgumentNullException.ThrowIfNull(sb);
        ArgumentNullException.ThrowIfNull(key);

        if(!first)
        {
            sb.Append(',');
        }

        sb.Append('"');
        AppendEscapedString(sb, key);
        sb.Append("\":");
        sb.Append(value ? "true" : "false");

        first = false;
    }


    /// <summary>
    /// Appends a <c>"key":"uri"</c> Uri-valued field. Uses
    /// <see cref="Uri.OriginalString"/> to preserve the caller's exact
    /// authority/percent-encoding shape on the wire.
    /// </summary>
    public static void AppendUriField(
        StringBuilder sb, string key, Uri value, ref bool first)
    {
        ArgumentNullException.ThrowIfNull(sb);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(value);

        AppendStringField(sb, key, value.OriginalString, ref first);
    }


    /// <summary>
    /// Appends a <c>"key":["v1","v2",...]</c> string-array-valued field to
    /// an in-progress JSON object.
    /// </summary>
    public static void AppendStringArrayField(
        StringBuilder sb, string key, IEnumerable<string> values, ref bool first)
    {
        ArgumentNullException.ThrowIfNull(sb);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(values);

        if(!first)
        {
            sb.Append(',');
        }

        sb.Append('"');
        AppendEscapedString(sb, key);
        sb.Append("\":[");

        bool itemFirst = true;
        foreach(string value in values)
        {
            if(!itemFirst)
            {
                sb.Append(',');
            }

            itemFirst = false;
            sb.Append('"');
            AppendEscapedString(sb, value);
            sb.Append('"');
        }

        sb.Append(']');
        first = false;
    }


    /// <summary>
    /// Appends a <c>"key":["uri1","uri2",...]</c> Uri-array-valued field
    /// using <see cref="Uri.OriginalString"/> for each entry.
    /// </summary>
    public static void AppendUriArrayField(
        StringBuilder sb, string key, IEnumerable<Uri> values, ref bool first)
    {
        ArgumentNullException.ThrowIfNull(sb);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(values);

        if(!first)
        {
            sb.Append(',');
        }

        sb.Append('"');
        AppendEscapedString(sb, key);
        sb.Append("\":[");

        bool itemFirst = true;
        foreach(Uri value in values)
        {
            if(!itemFirst)
            {
                sb.Append(',');
            }

            itemFirst = false;
            sb.Append('"');
            AppendEscapedString(sb, value.OriginalString);
            sb.Append('"');
        }

        sb.Append(']');
        first = false;
    }


    /// <summary>
    /// Appends a <c>"key":rawJsonValue</c> field where the value is already
    /// a serialised JSON token (object, array, number, etc.) the caller
    /// composed elsewhere. The caller is responsible for the value's
    /// well-formedness — no escaping or validation is applied.
    /// </summary>
    public static void AppendRawField(
        StringBuilder sb, string key, string rawJsonValue, ref bool first)
    {
        ArgumentNullException.ThrowIfNull(sb);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(rawJsonValue);

        if(!first)
        {
            sb.Append(',');
        }

        sb.Append('"');
        AppendEscapedString(sb, key);
        sb.Append("\":");
        sb.Append(rawJsonValue);

        first = false;
    }


}