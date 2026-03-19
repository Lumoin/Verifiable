using System.Text;

namespace Verifiable.JCose;

/// <summary>
/// Span-based, zero-allocation JSON writer for canonical JWK representations.
/// Writes directly into a caller-supplied <see cref="Span{T}"/> of UTF-8 bytes.
/// </summary>
/// <remarks>
/// <para>
/// Used by <see cref="JwkThumbprintUtilities"/> for RFC 7638 thumbprint computation
/// and by <see cref="EphemeralEncryptionKeyPair"/> for JWK serialisation. Both require
/// the same canonical key-value format without depending on a JSON serialisation library.
/// </para>
/// <para>
/// Callers must pre-calculate the required buffer size using <see cref="JwkTemplateConstants"/>
/// before renting from the pool.
/// </para>
/// </remarks>
public ref struct JwkJsonWriter
{
    private readonly Span<byte> buffer;
    private int position;

    /// <summary>Gets the current write position in the buffer.</summary>
    public readonly int Position => position;


    /// <summary>
    /// Initializes a new <see cref="JwkJsonWriter"/> writing into <paramref name="buffer"/>.
    /// </summary>
    /// <param name="buffer">The target buffer. Must be large enough for all intended writes.</param>
    public JwkJsonWriter(Span<byte> buffer)
    {
        this.buffer = buffer;
        position = 0;
    }


    /// <summary>Writes the JSON object start character <c>{</c>.</summary>
    public void WriteObjectStart() => WriteLiteral("{"u8);

    /// <summary>Writes the JSON object end character <c>}</c>.</summary>
    public void WriteObjectEnd() => WriteLiteral("}"u8);

    /// <summary>Writes the JSON array start character <c>[</c>.</summary>
    public void WriteArrayStart() => WriteLiteral("["u8);

    /// <summary>Writes the JSON array end character <c>]</c>.</summary>
    public void WriteArrayEnd() => WriteLiteral("]"u8);

    /// <summary>Writes the JSON property separator character <c>,</c>.</summary>
    public void WritePropertySeparator() => WriteLiteral(","u8);

    /// <summary>Writes a <c>"key":"value"</c> string property pair.</summary>
    /// <param name="key">The property key.</param>
    /// <param name="value">The property value.</param>
    public void WriteProperty(string key, string value)
    {
        WriteLiteral("\""u8);
        WriteString(key);
        WriteLiteral("\":\""u8);
        WriteString(value);
        WriteLiteral("\""u8);
    }

    /// <summary>Writes a <c>"key":</c> property key followed by a raw JSON value token.</summary>
    /// <param name="key">The property key.</param>
    /// <param name="rawJsonValue">
    /// A raw JSON value such as <c>true</c>, a number, or a pre-built JSON object/array.
    /// </param>
    public void WritePropertyRaw(string key, string rawJsonValue)
    {
        WriteLiteral("\""u8);
        WriteString(key);
        WriteLiteral("\":"u8);
        WriteString(rawJsonValue);
    }


    private void WriteLiteral(ReadOnlySpan<byte> utf8Literal)
    {
        utf8Literal.CopyTo(buffer[position..]);
        position += utf8Literal.Length;
    }


    private void WriteString(string value)
    {
        position += Encoding.UTF8.GetBytes(value, buffer[position..]);
    }
}
