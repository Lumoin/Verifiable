using System;
using System.Linq;
using System.Collections.Generic;
using Lumoin.Veritas.Cbor;

namespace Verifiable.Cbor.Converters;

/// <summary>
/// A converter for <see cref="Dictionary{String, Object}"/> that handles arbitrary CBOR maps
/// with text string keys.
/// </summary>
/// <remarks>
/// <para>
/// This converter is the CBOR equivalent of <c>DictionaryStringObjectJsonConverter</c> in
/// the JSON serialization library. It supports nested dictionaries, arrays, and primitive values.
/// </para>
/// <para>
/// Supported value types:
/// </para>
/// <list type="bullet">
/// <item><description>Integers (int, long)</description></item>
/// <item><description>Floating-point numbers (float, double)</description></item>
/// <item><description>Text strings</description></item>
/// <item><description>Byte strings (as byte[])</description></item>
/// <item><description>Booleans</description></item>
/// <item><description>Null</description></item>
/// <item><description>Arrays (as List&lt;object?&gt;)</description></item>
/// <item><description>Maps (as Dictionary&lt;object, object?&gt;)</description></item>
/// </list>
/// <para>
/// This converter delegates to <see cref="CborValueConverter"/> for value serialization,
/// with special handling for string-keyed maps at the top level.
/// </para>
/// </remarks>
public sealed class DictionaryStringObjectCborConverter: CborConverter<Dictionary<string, object>>
{
    /// <inheritdoc/>
    public override Dictionary<string, object> Read(CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);

        if(reader.PeekState() != CborReaderState.StartMap)
        {
            CborThrowHelper.ThrowUnexpectedCborType(CborReaderState.StartMap, reader.PeekState());
        }

        return ReadStringKeyedMap(reader, reader.Options);
    }


    /// <inheritdoc/>
    public override void Write(CborWriter writer, Dictionary<string, object> value)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        WriteStringKeyedMap(writer, value);
    }


    /// <summary>
    /// Reads a CBOR map with string keys into a dictionary.
    /// </summary>
    private static Dictionary<string, object> ReadStringKeyedMap(
        CborReader reader,
        CborSerializerOptions options)
    {
        int? length = reader.ReadStartMap();

        if(length is null && !options.AllowIndefiniteLength)
        {
            CborThrowHelper.ThrowIndefiniteLengthNotAllowed();
        }

        var dictionary = length.HasValue
            ? new Dictionary<string, object>(length.Value)
            : new Dictionary<string, object>();

        while(reader.PeekState() != CborReaderState.EndMap)
        {
            string key = reader.ReadTextString();
            object? value = CborValueConverter.ReadValue(ref reader, options);

            if(value is not null)
            {
                dictionary[key] = value;
            }
        }

        reader.ReadEndMap();

        return dictionary;
    }


    /// <summary>
    /// Writes a string-keyed dictionary as a CBOR map, omitting entries whose value is
    /// <see langword="null"/> — the only null-handling behavior this converter's callers exercise.
    /// </summary>
    private static void WriteStringKeyedMap(CborWriter writer, Dictionary<string, object> value)
    {
        int count = value.Count(kvp => kvp.Value is not null);

        writer.WriteStartMap(count);

        foreach(KeyValuePair<string, object> kvp in value)
        {
            if(kvp.Value is null)
            {
                continue;
            }

            writer.WriteTextString(kvp.Key);
            CborValueConverter.WriteValue(writer, kvp.Value);
        }

        writer.WriteEndMap();
    }
}
