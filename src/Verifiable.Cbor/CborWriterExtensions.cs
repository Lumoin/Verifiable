using System.Formats.Cbor;

namespace Verifiable.Cbor;

/// <summary>
/// Extension methods for <see cref="CborWriter"/> providing higher-level writing operations.
/// </summary>
/// <remarks>
/// These extensions simplify common patterns such as writing typed arrays, maps with known
/// key types, and handling nullable values. All methods produce definite-length output
/// as required by SD-CWT and other cryptographic specifications.
/// </remarks>
public static class CborWriterExtensions
{
    /// <summary>
    /// Writes a CBOR array of byte strings.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="values">The byte arrays to write.</param>
    public static void WriteByteStringArray(this CborWriter writer, IReadOnlyList<byte[]> values)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(values);

        writer.WriteStartArray(values.Count);
        for(int i = 0; i < values.Count; i++)
        {
            writer.WriteByteString(values[i]);
        }

        writer.WriteEndArray();
    }


    /// <summary>
    /// Writes a CBOR array of byte strings from a span.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="values">The byte array spans to write.</param>
    public static void WriteByteStringArray(this CborWriter writer, ReadOnlySpan<byte[]> values)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteStartArray(values.Length);
        for(int i = 0; i < values.Length; i++)
        {
            writer.WriteByteString(values[i]);
        }

        writer.WriteEndArray();
    }


    /// <summary>
    /// Writes a CBOR array of text strings.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="values">The strings to write.</param>
    public static void WriteTextStringArray(this CborWriter writer, IReadOnlyList<string> values)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(values);

        writer.WriteStartArray(values.Count);
        for(int i = 0; i < values.Count; i++)
        {
            writer.WriteTextString(values[i]);
        }

        writer.WriteEndArray();
    }


    /// <summary>
    /// Writes a CBOR array of integers.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="values">The integers to write.</param>
    public static void WriteInt32Array(this CborWriter writer, IReadOnlyList<int> values)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(values);

        writer.WriteStartArray(values.Count);
        for(int i = 0; i < values.Count; i++)
        {
            writer.WriteInt32(values[i]);
        }

        writer.WriteEndArray();
    }


    /// <summary>
    /// Writes a CBOR array of unsigned integers.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="values">The unsigned integers to write.</param>
    public static void WriteUInt32Array(this CborWriter writer, IReadOnlyList<uint> values)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(values);

        writer.WriteStartArray(values.Count);
        for(int i = 0; i < values.Count; i++)
        {
            writer.WriteUInt32(values[i]);
        }

        writer.WriteEndArray();
    }


    /// <summary>
    /// Writes a CBOR map with integer keys.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="map">The dictionary to write.</param>
    /// <param name="valueWriter">A function to write each value.</param>
    /// <typeparam name="TValue">The type of map values.</typeparam>
    public static void WriteIntKeyedMap<TValue>(
        this CborWriter writer,
        IReadOnlyDictionary<long, TValue> map,
        Action<CborWriter, TValue> valueWriter)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(map);
        ArgumentNullException.ThrowIfNull(valueWriter);

        writer.WriteStartMap(map.Count);
        foreach(KeyValuePair<long, TValue> kvp in map)
        {
            writer.WriteInt64(kvp.Key);
            valueWriter(writer, kvp.Value);
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Writes a CBOR map with text string keys.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="map">The dictionary to write.</param>
    /// <param name="valueWriter">A function to write each value.</param>
    /// <typeparam name="TValue">The type of map values.</typeparam>
    public static void WriteStringKeyedMap<TValue>(
        this CborWriter writer,
        IReadOnlyDictionary<string, TValue> map,
        Action<CborWriter, TValue> valueWriter)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(map);
        ArgumentNullException.ThrowIfNull(valueWriter);

        writer.WriteStartMap(map.Count);
        foreach(KeyValuePair<string, TValue> kvp in map)
        {
            writer.WriteTextString(kvp.Key);
            valueWriter(writer, kvp.Value);
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Writes a nullable byte string, writing CBOR null if the value is null.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="value">The byte string to write, or null.</param>
    public static void WriteNullableByteString(this CborWriter writer, byte[]? value)
    {
        ArgumentNullException.ThrowIfNull(writer);
        if(value is null)
        {
            writer.WriteNull();
        }
        else
        {
            writer.WriteByteString(value);
        }
    }


    /// <summary>
    /// Writes a nullable byte string from a span, writing CBOR null if empty.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="value">The byte span to write.</param>
    /// <param name="writeNullIfEmpty">If true, writes null for empty spans; otherwise writes empty byte string.</param>
    public static void WriteByteString(this CborWriter writer, ReadOnlySpan<byte> value, bool writeNullIfEmpty = false)
    {
        ArgumentNullException.ThrowIfNull(writer);
        if(writeNullIfEmpty && value.IsEmpty)
        {
            writer.WriteNull();
        }
        else
        {
            writer.WriteByteString(value);
        }
    }


    /// <summary>
    /// Writes a nullable text string, writing CBOR null if the value is null.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="value">The text string to write, or null.</param>
    public static void WriteNullableTextString(this CborWriter writer, string? value)
    {
        ArgumentNullException.ThrowIfNull(writer);
        if(value is null)
        {
            writer.WriteNull();
        }
        else
        {
            writer.WriteTextString(value);
        }
    }


    /// <summary>
    /// Writes a map entry with an integer key and byte string value.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="key">The integer key.</param>
    /// <param name="value">The byte string value.</param>
    public static void WriteMapEntry(this CborWriter writer, long key, byte[] value)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteInt64(key);
        writer.WriteByteString(value);
    }


    /// <summary>
    /// Writes a map entry with an integer key and byte string value from a span.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="key">The integer key.</param>
    /// <param name="value">The byte string value.</param>
    public static void WriteMapEntry(this CborWriter writer, long key, ReadOnlySpan<byte> value)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteInt64(key);
        writer.WriteByteString(value);
    }


    /// <summary>
    /// Writes a map entry with an integer key and text string value.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="key">The integer key.</param>
    /// <param name="value">The text string value.</param>
    public static void WriteMapEntry(this CborWriter writer, long key, string value)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteInt64(key);
        writer.WriteTextString(value);
    }


    /// <summary>
    /// Writes a map entry with an integer key and integer value.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="key">The integer key.</param>
    /// <param name="value">The integer value.</param>
    public static void WriteMapEntry(this CborWriter writer, long key, long value)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteInt64(key);
        writer.WriteInt64(value);
    }


    /// <summary>
    /// Writes a map entry with a text string key and text string value.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="key">The text string key.</param>
    /// <param name="value">The text string value.</param>
    public static void WriteMapEntry(this CborWriter writer, string key, string value)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteTextString(key);
        writer.WriteTextString(value);
    }


    /// <summary>
    /// Writes a map entry with a text string key and byte string value.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="key">The text string key.</param>
    /// <param name="value">The byte string value.</param>
    public static void WriteMapEntry(this CborWriter writer, string key, byte[] value)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteTextString(key);
        writer.WriteByteString(value);
    }


    /// <summary>
    /// Conditionally writes a map entry with an integer key if the value is not null.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="key">The integer key.</param>
    /// <param name="value">The byte string value, or null to skip.</param>
    /// <returns><see langword="true"/> if the entry was written; otherwise, <see langword="false"/>.</returns>
    public static bool WriteMapEntryIfNotNull(this CborWriter writer, long key, byte[]? value)
    {
        ArgumentNullException.ThrowIfNull(writer);
        if(value is null)
        {
            return false;
        }

        writer.WriteInt64(key);
        writer.WriteByteString(value);
        return true;
    }


    /// <summary>
    /// Conditionally writes a map entry with an integer key if the value is not null.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="key">The integer key.</param>
    /// <param name="value">The text string value, or null to skip.</param>
    /// <returns><see langword="true"/> if the entry was written; otherwise, <see langword="false"/>.</returns>
    public static bool WriteMapEntryIfNotNull(this CborWriter writer, long key, string? value)
    {
        ArgumentNullException.ThrowIfNull(writer);
        if(value is null)
        {
            return false;
        }

        writer.WriteInt64(key);
        writer.WriteTextString(value);
        return true;
    }
}