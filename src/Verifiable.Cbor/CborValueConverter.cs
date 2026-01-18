using System.Formats.Cbor;

namespace Verifiable.Cbor;

/// <summary>
/// Provides utilities for reading and writing arbitrary CBOR values with CLR type mapping.
/// </summary>
/// <remarks>
/// <para>
/// This class provides bidirectional conversion between CBOR and common .NET types.
/// It serves as the low-level implementation used by:
/// </para>
/// <list type="bullet">
/// <item><description><see cref="CoseSerialization"/> for COSE structures.</description></item>
/// <item><description><c>SdCwtSerializer</c> for SD-CWT disclosures.</description></item>
/// <item><description><c>DictionaryStringObjectCborConverter</c> for generic dictionary handling.</description></item>
/// </list>
/// <para>
/// Supported types for writing:
/// </para>
/// <list type="bullet">
/// <item><description>Null -> CBOR null.</description></item>
/// <item><description>Boolean -> CBOR boolean.</description></item>
/// <item><description>Integer types (byte, sbyte, short, ushort, int, uint, long, ulong) -> CBOR integer.</description></item>
/// <item><description>Floating-point types (float, double, decimal) -> CBOR float.</description></item>
/// <item><description>String -> CBOR text string.</description></item>
/// <item><description>Byte arrays and Memory&lt;byte&gt; -> CBOR byte string.</description></item>
/// <item><description>DateTimeOffset, DateTime -> CBOR integer (Unix seconds).</description></item>
/// <item><description>Collections -> CBOR arrays.</description></item>
/// <item><description>Dictionaries with int, long, or string keys -> CBOR maps.</description></item>
/// </list>
/// <para>
/// Reading returns these CLR types based on CBOR major type:
/// </para>
/// <list type="bullet">
/// <item><description>CBOR null -> null.</description></item>
/// <item><description>CBOR boolean -> bool.</description></item>
/// <item><description>CBOR integer -> long (always, for consistency).</description></item>
/// <item><description>CBOR float -> float or double.</description></item>
/// <item><description>CBOR text string -> string.</description></item>
/// <item><description>CBOR byte string -> byte[].</description></item>
/// <item><description>CBOR array -> List&lt;object?&gt;.</description></item>
/// <item><description>CBOR map -> Dictionary&lt;object, object?&gt;.</description></item>
/// <item><description>CBOR tagged value -> ValueTuple&lt;ulong, object?&gt;.</description></item>
/// </list>
/// </remarks>
public static class CborValueConverter
{
    /// <summary>
    /// Writes a CLR value as CBOR.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="value">The value to write.</param>
    /// <exception cref="NotSupportedException">Thrown when the type is not supported.</exception>
    public static void WriteValue(CborWriter writer, object? value)
    {
        ArgumentNullException.ThrowIfNull(writer);

        switch(value)
        {
            case null:
            {
                writer.WriteNull();
                break;
            }
            case bool boolValue:
            {
                writer.WriteBoolean(boolValue);
                break;
            }
            case byte byteValue:
            {
                writer.WriteInt32(byteValue);
                break;
            }
            case sbyte sbyteValue:
            {
                writer.WriteInt32(sbyteValue);
                break;
            }
            case short shortValue:
            {
                writer.WriteInt32(shortValue);
                break;
            }
            case ushort ushortValue:
            {
                writer.WriteInt32(ushortValue);
                break;
            }
            case int intValue:
            {
                writer.WriteInt32(intValue);
                break;
            }
            case uint uintValue:
            {
                writer.WriteUInt32(uintValue);
                break;
            }
            case long longValue:
            {
                writer.WriteInt64(longValue);
                break;
            }
            case ulong ulongValue:
            {
                writer.WriteUInt64(ulongValue);
                break;
            }
            case float floatValue:
            {
                writer.WriteSingle(floatValue);
                break;
            }
            case double doubleValue:
            {
                writer.WriteDouble(doubleValue);
                break;
            }
            case decimal decimalValue:
            {
                writer.WriteDecimal(decimalValue);
                break;
            }
            case string stringValue:
            {
                writer.WriteTextString(stringValue);
                break;
            }
            case byte[] bytesValue:
            {
                writer.WriteByteString(bytesValue);
                break;
            }
            case ReadOnlyMemory<byte> memoryValue:
            {
                writer.WriteByteString(memoryValue.Span);
                break;
            }
            case Memory<byte> memoryValue:
            {
                writer.WriteByteString(memoryValue.Span);
                break;
            }
            case DateTimeOffset dateTimeOffset:
            {
                //CWT uses numeric date (seconds since epoch).
                writer.WriteInt64(dateTimeOffset.ToUnixTimeSeconds());
                break;
            }
            case DateTime dateTime:
            {
                //Convert to UTC and write as Unix seconds.
                writer.WriteInt64(new DateTimeOffset(dateTime.ToUniversalTime()).ToUnixTimeSeconds());
                break;
            }
            case IDictionary<int, object?> intDict:
            {
                WriteIntKeyedMap(writer, intDict);
                break;
            }
            case IDictionary<long, object?> longDict:
            {
                WriteLongKeyedMap(writer, longDict);
                break;
            }
            case IDictionary<string, object?> stringDict:
            {
                WriteStringKeyedMap(writer, stringDict);
                break;
            }
            case IReadOnlyDictionary<int, object> intReadOnlyDict:
            {
                WriteIntKeyedMap(writer, intReadOnlyDict);
                break;
            }
            case IReadOnlyDictionary<long, object> longReadOnlyDict:
            {
                WriteLongKeyedMap(writer, longReadOnlyDict);
                break;
            }
            case IReadOnlyDictionary<string, object> stringReadOnlyDict:
            {
                WriteStringKeyedMap(writer, stringReadOnlyDict);
                break;
            }
            case IEnumerable<object?> enumerable:
            {
                WriteArray(writer, enumerable);
                break;
            }
            default:
            {
                throw new NotSupportedException(
                    $"Type '{value.GetType().FullName}' is not supported for CBOR serialization.");
            }
        }
    }


    /// <summary>
    /// Writes a CLR value as CBOR using the specified options.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="value">The value to write.</param>
    /// <param name="options">The serializer options.</param>
    /// <exception cref="NotSupportedException">Thrown when the type is not supported.</exception>
    /// <remarks>
    /// This overload is provided for compatibility with the <see cref="CborConverter{T}"/> infrastructure.
    /// Currently, options only affects null handling via <see cref="CborSerializerOptions.WriteNullValues"/>.
    /// </remarks>
    public static void WriteValue(CborWriter writer, object? value, CborSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(options);

        if(value is null && !options.WriteNullValues)
        {
            return;
        }

        WriteValue(writer, value);
    }


    /// <summary>
    /// Reads a CBOR value and converts it to a CLR object.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The converted CLR object.</returns>
    /// <exception cref="CborContentException">Thrown when the CBOR content is invalid.</exception>
    public static object? ReadValue(ref CborReader reader)
    {
        CborReaderState state = reader.PeekState();

        return state switch
        {
            CborReaderState.Null => ReadNull(ref reader),
            CborReaderState.Boolean => reader.ReadBoolean(),
            CborReaderState.UnsignedInteger => ReadUnsignedInteger(ref reader),
            CborReaderState.NegativeInteger => reader.ReadInt64(),
            CborReaderState.HalfPrecisionFloat => reader.ReadDouble(),
            CborReaderState.SinglePrecisionFloat => reader.ReadSingle(),
            CborReaderState.DoublePrecisionFloat => reader.ReadDouble(),
            CborReaderState.TextString => reader.ReadTextString(),
            CborReaderState.ByteString => reader.ReadByteString(),
            CborReaderState.StartArray => ReadArray(ref reader),
            CborReaderState.StartMap => ReadMap(ref reader),
            CborReaderState.Tag => ReadTaggedValue(ref reader),
            _ => throw new CborContentException($"Unsupported CBOR state: {state}.")
        };
    }


    /// <summary>
    /// Reads a CBOR value using non-ref parameter (for delegate compatibility).
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The converted CLR object.</returns>
    public static object? ReadValue(CborReader reader)
    {
        return ReadValue(ref reader);
    }


    /// <summary>
    /// Reads a CBOR value using the specified options.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <param name="options">The serializer options.</param>
    /// <returns>The converted CLR object.</returns>
    /// <exception cref="CborContentException">Thrown when the CBOR content is invalid.</exception>
    /// <remarks>
    /// This overload is provided for compatibility with the <see cref="CborConverter{T}"/> infrastructure.
    /// Currently, options affects indefinite-length handling via <see cref="CborSerializerOptions.AllowIndefiniteLength"/>.
    /// </remarks>
    public static object? ReadValue(ref CborReader reader, CborSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        CborReaderState state = reader.PeekState();

        return state switch
        {
            CborReaderState.Null => ReadNull(ref reader),
            CborReaderState.Boolean => reader.ReadBoolean(),
            CborReaderState.UnsignedInteger => ReadUnsignedInteger(ref reader),
            CborReaderState.NegativeInteger => reader.ReadInt64(),
            CborReaderState.HalfPrecisionFloat => reader.ReadDouble(),
            CborReaderState.SinglePrecisionFloat => reader.ReadSingle(),
            CborReaderState.DoublePrecisionFloat => reader.ReadDouble(),
            CborReaderState.TextString => reader.ReadTextString(),
            CborReaderState.ByteString => reader.ReadByteString(),
            CborReaderState.StartArray => ReadArray(ref reader, options),
            CborReaderState.StartMap => ReadMap(ref reader, options),
            CborReaderState.Tag => ReadTaggedValue(ref reader, options),
            _ => throw new CborContentException($"Unsupported CBOR state: {state}.")
        };
    }


    private static object? ReadNull(ref CborReader reader)
    {
        reader.ReadNull();
        return null;
    }


    private static object ReadUnsignedInteger(ref CborReader reader)
    {
        //Always return long for consistency.
        //This ensures round-trip behavior is predictable.
        ulong value = reader.ReadUInt64();

        if(value <= long.MaxValue)
        {
            return (long)value;
        }

        return value;
    }


    private static List<object?> ReadArray(ref CborReader reader)
    {
        int? count = reader.ReadStartArray();
        var list = new List<object?>(count ?? 4);

        while(reader.PeekState() != CborReaderState.EndArray)
        {
            list.Add(ReadValue(ref reader));
        }

        reader.ReadEndArray();
        return list;
    }


    private static List<object?> ReadArray(ref CborReader reader, CborSerializerOptions options)
    {
        int? count = reader.ReadStartArray();

        if(count is null && !options.AllowIndefiniteLength)
        {
            CborThrowHelper.ThrowIndefiniteLengthNotAllowed();
        }

        var list = new List<object?>(count ?? 4);

        while(reader.PeekState() != CborReaderState.EndArray)
        {
            list.Add(ReadValue(ref reader, options));
        }

        reader.ReadEndArray();
        return list;
    }


    private static Dictionary<object, object?> ReadMap(ref CborReader reader)
    {
        int? count = reader.ReadStartMap();
        var dict = new Dictionary<object, object?>(count ?? 4);

        while(reader.PeekState() != CborReaderState.EndMap)
        {
            object key = ReadValue(ref reader)!;
            object? value = ReadValue(ref reader);
            dict[key] = value;
        }

        reader.ReadEndMap();
        return dict;
    }


    private static Dictionary<object, object?> ReadMap(ref CborReader reader, CborSerializerOptions options)
    {
        int? count = reader.ReadStartMap();

        if(count is null && !options.AllowIndefiniteLength)
        {
            CborThrowHelper.ThrowIndefiniteLengthNotAllowed();
        }

        var dict = new Dictionary<object, object?>(count ?? 4);

        while(reader.PeekState() != CborReaderState.EndMap)
        {
            object key = ReadValue(ref reader, options)!;
            object? value = ReadValue(ref reader, options);
            dict[key] = value;
        }

        reader.ReadEndMap();
        return dict;
    }


    private static object ReadTaggedValue(ref CborReader reader)
    {
        CborTag tag = reader.ReadTag();
        object? value = ReadValue(ref reader);

        //Return as tuple; callers can handle specific tags as needed.
        return (Tag: (ulong)tag, Value: value);
    }


    private static object ReadTaggedValue(ref CborReader reader, CborSerializerOptions options)
    {
        CborTag tag = reader.ReadTag();
        object? value = ReadValue(ref reader, options);

        return (Tag: (ulong)tag, Value: value);
    }


    private static void WriteIntKeyedMap(CborWriter writer, IDictionary<int, object?> dict)
    {
        writer.WriteStartMap(dict.Count);
        foreach(var kvp in dict)
        {
            writer.WriteInt32(kvp.Key);
            WriteValue(writer, kvp.Value);
        }
        writer.WriteEndMap();
    }


    private static void WriteIntKeyedMap(CborWriter writer, IReadOnlyDictionary<int, object> dict)
    {
        writer.WriteStartMap(dict.Count);
        foreach(var kvp in dict)
        {
            writer.WriteInt32(kvp.Key);
            WriteValue(writer, kvp.Value);
        }
        writer.WriteEndMap();
    }


    private static void WriteLongKeyedMap(CborWriter writer, IDictionary<long, object?> dict)
    {
        writer.WriteStartMap(dict.Count);
        foreach(var kvp in dict)
        {
            writer.WriteInt64(kvp.Key);
            WriteValue(writer, kvp.Value);
        }
        writer.WriteEndMap();
    }


    private static void WriteLongKeyedMap(CborWriter writer, IReadOnlyDictionary<long, object> dict)
    {
        writer.WriteStartMap(dict.Count);
        foreach(var kvp in dict)
        {
            writer.WriteInt64(kvp.Key);
            WriteValue(writer, kvp.Value);
        }
        writer.WriteEndMap();
    }


    private static void WriteStringKeyedMap(CborWriter writer, IDictionary<string, object?> dict)
    {
        writer.WriteStartMap(dict.Count);
        foreach(var kvp in dict)
        {
            writer.WriteTextString(kvp.Key);
            WriteValue(writer, kvp.Value);
        }
        writer.WriteEndMap();
    }


    private static void WriteStringKeyedMap(CborWriter writer, IReadOnlyDictionary<string, object> dict)
    {
        writer.WriteStartMap(dict.Count);
        foreach(var kvp in dict)
        {
            writer.WriteTextString(kvp.Key);
            WriteValue(writer, kvp.Value);
        }
        writer.WriteEndMap();
    }


    private static void WriteArray(CborWriter writer, IEnumerable<object?> items)
    {
        var list = items.ToList();
        writer.WriteStartArray(list.Count);
        foreach(var item in list)
        {
            WriteValue(writer, item);
        }
        writer.WriteEndArray();
    }
}