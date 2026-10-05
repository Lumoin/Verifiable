using Lumoin.Veritas.Cbor;
using Lumoin.Veritas.Cbor.Converters;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

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
/// </list>
/// <para>
/// Supported types for writing:
/// </para>
/// <list type="bullet">
/// <item><description>Null -> CBOR null.</description></item>
/// <item><description>Boolean -> CBOR boolean.</description></item>
/// <item><description>Integer types (byte, sbyte, short, ushort, int, uint, long, ulong) -> CBOR integer.</description></item>
/// <item><description>Floating-point types (float, double) -> CBOR float; decimal -> an RFC 8949 §3.4.4 Tag 4 decimal fraction.</description></item>
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
/// <item><description>CBOR integer -> int if within Int32 range, otherwise long, otherwise ulong.</description></item>
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
                WriteDecimalFraction(writer, decimalValue);
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
            case IDictionary<object, object?> objectDict:
            {
                //ReadMap produces an object-keyed dictionary, so a value re-serialized after a
                //round-trip (e.g. a nested COSE_Key map inside a CWT cnf claim) arrives here.
                //Each boxed key is dispatched back through WriteValue, which writes int, long,
                //and string keys via their respective branches above.
                WriteObjectKeyedMap(writer, objectDict);
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
    /// Reads a CBOR value and converts it to a CLR object.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The converted CLR object.</returns>
    /// <exception cref="CborContentException">Thrown when the CBOR content is invalid.</exception>
    public static object? ReadValue(ref CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        CborReaderState state = reader.PeekState();

        return state switch
        {
            CborReaderState.Null => ReadNull(ref reader),
            CborReaderState.Boolean => reader.ReadBoolean(),
            CborReaderState.UnsignedInteger => ReadUnsignedInteger(ref reader),
            CborReaderState.NegativeInteger => ReadNegativeInteger(ref reader),
            CborReaderState.HalfPrecisionFloat => (double)reader.ReadHalf(),
            CborReaderState.SinglePrecisionFloat => reader.ReadSingle(),
            CborReaderState.DoublePrecisionFloat => reader.ReadDouble(),
            CborReaderState.TextString => reader.ReadTextString(),
            CborReaderState.ByteString => reader.ReadByteString(),
            CborReaderState.StartArray => ReadArray(ref reader),
            CborReaderState.StartMap => ReadMap(ref reader),
            CborReaderState.Tag => ReadTaggedValue(ref reader),
            CborReaderState.Undefined => throw new CborContentException($"Unsupported CBOR state: {state}."),
            CborReaderState.SimpleValue => throw new CborContentException($"Unsupported CBOR state: {state}."),
            CborReaderState.EndArray => throw new CborContentException($"Unsupported CBOR state: {state}."),
            CborReaderState.EndMap => throw new CborContentException($"Unsupported CBOR state: {state}."),
            CborReaderState.Finished => throw new CborContentException($"Unsupported CBOR state: {state}."),
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
        ArgumentNullException.ThrowIfNull(reader);
        return ReadValue(ref reader);
    }


    private static object? ReadNull(ref CborReader reader)
    {
        reader.ReadNull();
        return null;
    }


    [SuppressMessage("Performance", "CA1859:Use concrete types when possible for improved performance", Justification = "Boxing to object is intentional for generic value conversion.")]
    private static object ReadUnsignedInteger(ref CborReader reader)
    {
        ulong value = reader.ReadUInt64();
        if(value <= int.MaxValue)
        {
            return (int)value;
        }

        if(value <= long.MaxValue)
        {
            return (long)value;
        }

        return value;
    }


    [SuppressMessage("Performance", "CA1859:Use concrete types when possible for improved performance", Justification = "Boxing to object is intentional for generic value conversion.")]
    private static object ReadNegativeInteger(ref CborReader reader)
    {
        long value = reader.ReadInt64();
        if(value is >= int.MinValue and <= int.MaxValue)
        {
            return (int)value;
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


    /// <summary>
    /// Reads a CBOR map into a dictionary, refusing a map key that appears twice.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 Section 3.1</see>: "A map
    /// that has duplicate keys may be well-formed, but it is not valid, and thus it causes indeterminate
    /// decoding; see also Section 5.6." Two map keys are the same by the equivalence of Section 5.6.1, which
    /// <see cref="MapKeyEquivalence"/> holds; the answered dictionary compares its map keys by it too, so it
    /// holds every map key Section 5.6.1 calls distinct, two NaN map keys with different significands among them.
    /// </remarks>
    /// <param name="reader">The CBOR reader positioned at the start of the map.</param>
    /// <returns>The map's entries.</returns>
    /// <exception cref="CborContentException">A map key appears twice in the map.</exception>
    private static Dictionary<object, object?> ReadMap(ref CborReader reader)
    {
        int? count = reader.ReadStartMap();
        var dict = new Dictionary<object, object?>(count ?? 4, MapKeyEquivalence.Instance);

        while(reader.PeekState() != CborReaderState.EndMap)
        {
            object key = ReadValue(ref reader)!;
            if(dict.ContainsKey(key))
            {
                throw new CborContentException(
                    "A CBOR map carries the same map key twice; the map is not valid (RFC 8949 Section 3.1).");
            }

            object? value = ReadValue(ref reader);
            dict.Add(key, value);
        }

        reader.ReadEndMap();
        return dict;
    }


    private static object ReadTaggedValue(ref CborReader reader)
    {
        CborTag tag = reader.ReadTag();
        object? value = ReadValue(ref reader);

        //Return as tuple; callers can handle specific tags as needed.
        return (Tag: tag.Value, Value: value);
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


    /// <summary>
    /// Writes an object-keyed dictionary as a CBOR map, each map key through <see cref="WriteValue"/>, after
    /// refusing a dictionary whose entries would be written as the same map key twice.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-9">RFC 9052 Section 9</see>: "Applications MUST
    /// NOT generate messages with the same label used twice as a key in a single map." Two entries the dictionary
    /// tells apart can still be one map key on the wire (a boxed <see cref="int"/> 1 and a boxed
    /// <see cref="long"/> 1 are both the integer 1), so sameness is judged by <see cref="MapKeyEquivalence"/>, the
    /// judgment the reading side refuses a repeated map key by. The dictionary is the caller's own argument, so
    /// the refusal is an exception and nothing is written.
    /// </remarks>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="dict">The dictionary to write.</param>
    /// <exception cref="ArgumentException">Two entries would be written as the same map key.</exception>
    private static void WriteObjectKeyedMap(CborWriter writer, IDictionary<object, object?> dict)
    {
        var mapKeys = new HashSet<object>(dict.Count, MapKeyEquivalence.Instance);
        foreach(object mapKey in dict.Keys)
        {
            if(!mapKeys.Add(mapKey))
            {
                throw new ArgumentException(
                    "Two entries of the dictionary would be written as the same CBOR map key (RFC 9052 Section 9).", nameof(dict));
            }
        }

        writer.WriteStartMap(dict.Count);
        foreach(var kvp in dict)
        {
            WriteValue(writer, kvp.Key);
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


    /// <summary>
    /// Writes <paramref name="value"/> as an RFC 8949 §3.4.4 Tag 4 decimal fraction: the two-element
    /// array <c>[exponent, mantissa]</c> that <see cref="DecimalFractionCborConverter"/> encodes,
    /// with the exponent and unscaled mantissa read directly off the decimal's own bit layout so the
    /// wire value is exact for every representable <see cref="decimal"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="value">The decimal to write.</param>
    private static void WriteDecimalFraction(CborWriter writer, decimal value)
    {
        (int exponent, BigInteger mantissa) = ToDecimalFraction(value);
        new DecimalFractionCborConverter().Write(writer, new CborDecimalFraction(exponent, mantissa));
    }


    /// <summary>
    /// Reads the exponent and the unscaled, signed mantissa of <paramref name="value"/> off the decimal's own bit
    /// layout: the two numbers <see cref="WriteDecimalFraction"/> writes as the Tag 4 content <c>[exponent, mantissa]</c>.
    /// </summary>
    /// <param name="value">The decimal to read.</param>
    /// <returns>The exponent (the negated scale) and the signed mantissa.</returns>
    private static (int Exponent, BigInteger Mantissa) ToDecimalFraction(decimal value)
    {
        Span<int> bits = stackalloc int[4];
        _ = decimal.GetBits(value, bits);

        int scale = (bits[3] >> 16) & 0x7F;
        bool isNegative = bits[3] < 0;

        BigInteger mantissa = (new BigInteger((uint)bits[2]) << 64)
            | (new BigInteger((uint)bits[1]) << 32)
            | new BigInteger((uint)bits[0]);

        if(isNegative)
        {
            mantissa = -mantissa;
        }

        return (-scale, mantissa);
    }


    /// <summary>
    /// The equivalence of map keys of
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-5.6.1">RFC 8949 Section 5.6.1</see> over the CLR
    /// forms this converter reads (<see cref="ReadValue(ref CborReader)"/>) and writes (<see cref="WriteValue"/>):
    /// the one judgment by which a map read is refused for a repeated map key and a dictionary is refused for
    /// two entries that would be written as one map key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Section 5.6.1: "At the generic data model level, numerically equivalent integer and floating-point values
    /// are distinct from each other, as they are from the various big numbers (Tags 2 to 5). Similarly, text
    /// strings are distinct from byte strings, even if composed of the same bytes. A tagged value is distinct from
    /// an untagged value or from a value tagged with a different tag number." and "Within each of these groups,
    /// numeric values are distinct unless they are numerically equal (specifically, -0.0 is equal to 0.0); for the
    /// purpose of map key equivalence, NaN values are equivalent if they have the same significand after
    /// zero-extending both significands at the right to 64 bits." and "Both byte strings and text strings are
    /// compared byte by byte, arrays are compared element by element, and are equal if they have the same number of
    /// bytes/elements and the same values at the same positions. Two maps are equal if they have the same set of
    /// pairs regardless of their order; pairs are equal if both the key and value are equal." and "Tagged values are
    /// equal if both the tag number and the tag content are equal. ... Simple values are equal if they simply have
    /// the same value. Nothing else is equal in the generic data model".
    /// </para>
    /// <para>
    /// The CLR forms: every integer type, and a <see cref="DateTimeOffset"/> or <see cref="DateTime"/> (written
    /// as Unix seconds), is one integer group compared by value; <see cref="Half"/>, <see cref="float"/> and
    /// <see cref="double"/> are one floating-point group compared numerically, a NaN by its significand placed at
    /// the top of 64 bits; a <see cref="string"/> is a text string compared ordinally; a <see cref="byte"/> array,
    /// <see cref="ReadOnlyMemory{T}"/> or <see cref="Memory{T}"/> of bytes is a byte string compared by content; a
    /// dictionary is a map compared as a set of pairs; any other <see cref="IEnumerable{T}"/> of objects is an array
    /// compared element by element; the <c>(ulong Tag, object? Value)</c> tuple <see cref="ReadTaggedValue"/>
    /// answers is a tagged value compared by tag number and content; a <see cref="decimal"/>, written as a Tag 4
    /// decimal fraction, compares by its exponent and mantissa; <see langword="true"/>, <see langword="false"/> and
    /// <see langword="null"/> compare by value; anything else by <see cref="object.Equals(object?, object?)"/>.
    /// </para>
    /// </remarks>
    private sealed class MapKeyEquivalence: IEqualityComparer<object>
    {
        /// <summary>The one instance; the equivalence holds no state.</summary>
        public static MapKeyEquivalence Instance { get; } = new();


        /// <summary>Tells whether two map keys are the same map key.</summary>
        /// <param name="x">The first map key.</param>
        /// <param name="y">The second map key.</param>
        /// <returns><see langword="true"/> when the two are the same map key.</returns>
        public new bool Equals(object? x, object? y) => IsSameMapKey(x, y);


        /// <summary>Answers a hash code equal for every two map keys this equivalence calls the same.</summary>
        /// <param name="obj">The map key.</param>
        /// <returns>The hash code.</returns>
        public int GetHashCode(object obj) => MapKeyHashCode(obj);


        /// <summary>Tells whether two decoded or to-be-written values are the same map key.</summary>
        /// <param name="x">The first value.</param>
        /// <param name="y">The second value.</param>
        /// <returns><see langword="true"/> when the two are the same map key.</returns>
        private static bool IsSameMapKey(object? x, object? y)
        {
            MapKeyKind kind = KindOf(x);
            if(kind != KindOf(y))
            {
                return false;
            }

            return kind switch
            {
                MapKeyKind.Null => true,
                MapKeyKind.Boolean => (bool)x! == (bool)y!,
                MapKeyKind.Integer => ToInteger(x!) == ToInteger(y!),
                MapKeyKind.FloatingPoint => IsSameFloatingPoint(x!, y!),
                MapKeyKind.TextString => string.Equals((string)x!, (string)y!, StringComparison.Ordinal),
                MapKeyKind.ByteString => ToByteString(x!).Span.SequenceEqual(ToByteString(y!).Span),
                MapKeyKind.Array => IsSameArray(ToElements(x!), ToElements(y!)),
                MapKeyKind.Map => IsSameMap(MapEntriesOf(x!)!, MapEntriesOf(y!)!),
                MapKeyKind.Tagged => IsSameTagged((ValueTuple<ulong, object>)x!, (ValueTuple<ulong, object>)y!),
                MapKeyKind.DecimalFraction => ToDecimalFraction((decimal)x!) == ToDecimalFraction((decimal)y!),
                _ => object.Equals(x, y)
            };
        }


        /// <summary>Answers a hash code equal for every two values <see cref="IsSameMapKey"/> calls the same.</summary>
        /// <param name="value">The value.</param>
        /// <returns>The hash code.</returns>
        private static int MapKeyHashCode(object? value)
        {
            MapKeyKind kind = KindOf(value);

            return kind switch
            {
                MapKeyKind.Null => HashCode.Combine(kind),
                MapKeyKind.Boolean => HashCode.Combine(kind, (bool)value!),
                MapKeyKind.Integer => HashCode.Combine(kind, ToInteger(value!)),
                MapKeyKind.FloatingPoint => FloatingPointHashCode(value!),
                MapKeyKind.TextString => HashCode.Combine(kind, StringComparer.Ordinal.GetHashCode((string)value!)),
                MapKeyKind.ByteString => ByteStringHashCode(ToByteString(value!)),
                MapKeyKind.Array => ArrayHashCode(ToElements(value!)),
                MapKeyKind.Map => MapHashCode(MapEntriesOf(value!)!),
                MapKeyKind.Tagged => TaggedHashCode((ValueTuple<ulong, object>)value!),
                MapKeyKind.DecimalFraction => HashCode.Combine(kind, ToDecimalFraction((decimal)value!)),
                _ => HashCode.Combine(kind, value!.GetHashCode())
            };
        }


        /// <summary>Tells which group of Section 5.6.1 a value's map key belongs to.</summary>
        /// <param name="value">The value.</param>
        /// <returns>The group.</returns>
        private static MapKeyKind KindOf(object? value)
        {
            return value switch
            {
                null => MapKeyKind.Null,
                bool => MapKeyKind.Boolean,
                byte or sbyte or short or ushort or int or uint or long or ulong or DateTimeOffset or DateTime => MapKeyKind.Integer,
                Half or float or double => MapKeyKind.FloatingPoint,
                string => MapKeyKind.TextString,
                byte[] or ReadOnlyMemory<byte> or Memory<byte> => MapKeyKind.ByteString,
                decimal => MapKeyKind.DecimalFraction,
                ValueTuple<ulong, object> => MapKeyKind.Tagged,
                _ when MapEntriesOf(value) is not null => MapKeyKind.Map,
                IEnumerable<object?> => MapKeyKind.Array,
                _ => MapKeyKind.Other
            };
        }


        /// <summary>Answers the integer a value of the integer group stands for on the wire.</summary>
        /// <param name="value">A value of the integer group.</param>
        /// <returns>The integer.</returns>
        private static Int128 ToInteger(object value)
        {
            return value switch
            {
                byte number => number,
                sbyte number => number,
                short number => number,
                ushort number => number,
                int number => number,
                uint number => number,
                long number => number,
                ulong number => number,
                DateTimeOffset instant => instant.ToUnixTimeSeconds(),
                DateTime instant => new DateTimeOffset(instant.ToUniversalTime()).ToUnixTimeSeconds(),
                _ => throw new InvalidOperationException($"Type '{value.GetType().FullName}' is not of the integer group.")
            };
        }


        /// <summary>Answers the value of a floating-point group member as a <see cref="double"/>, exactly.</summary>
        /// <param name="value">A value of the floating-point group.</param>
        /// <returns>The value.</returns>
        private static double ToDouble(object value)
        {
            return value switch
            {
                Half number => (double)number,
                float number => number,
                double number => number,
                _ => throw new InvalidOperationException($"Type '{value.GetType().FullName}' is not of the floating-point group.")
            };
        }


        /// <summary>
        /// Answers the significand of a floating-point value zero-extended at the right to 64 bits: the stored
        /// significand bits placed at the top of a 64-bit number.
        /// </summary>
        /// <param name="value">A value of the floating-point group.</param>
        /// <returns>The significand at the top of 64 bits.</returns>
        private static ulong ToExtendedSignificand(object value)
        {
            return value switch
            {
                Half number => (ulong)(BitConverter.HalfToUInt16Bits(number) & 0x03FFu) << 54,
                float number => (ulong)(BitConverter.SingleToUInt32Bits(number) & 0x007F_FFFFu) << 41,
                double number => (BitConverter.DoubleToUInt64Bits(number) & 0x000F_FFFF_FFFF_FFFFul) << 12,
                _ => throw new InvalidOperationException($"Type '{value.GetType().FullName}' is not of the floating-point group.")
            };
        }


        /// <summary>
        /// Tells whether two floating-point values are the same map key: numerically equal, -0.0 equal to 0.0,
        /// and two NaN values equal when their significands are equal at the top of 64 bits.
        /// </summary>
        /// <param name="x">The first value.</param>
        /// <param name="y">The second value.</param>
        /// <returns><see langword="true"/> when the two are the same map key.</returns>
        private static bool IsSameFloatingPoint(object x, object y)
        {
            double xNumber = ToDouble(x);
            double yNumber = ToDouble(y);
            bool isXNaN = double.IsNaN(xNumber);
            bool isYNaN = double.IsNaN(yNumber);

            return (isXNaN, isYNaN) switch
            {
                (true, true) => ToExtendedSignificand(x) == ToExtendedSignificand(y),
                (false, false) => xNumber == yNumber,
                _ => false
            };
        }


        /// <summary>Answers a hash code for a floating-point value consistent with <see cref="IsSameFloatingPoint"/>.</summary>
        /// <param name="value">A value of the floating-point group.</param>
        /// <returns>The hash code.</returns>
        private static int FloatingPointHashCode(object value)
        {
            double number = ToDouble(value);

            return double.IsNaN(number)
                ? HashCode.Combine(MapKeyKind.FloatingPoint, ToExtendedSignificand(value))
                : HashCode.Combine(MapKeyKind.FloatingPoint, number == 0 ? 0.0 : number);
        }


        /// <summary>Answers the bytes of a byte-string group member.</summary>
        /// <param name="value">A value of the byte-string group.</param>
        /// <returns>The bytes.</returns>
        private static ReadOnlyMemory<byte> ToByteString(object value)
        {
            return value switch
            {
                byte[] bytes => bytes,
                ReadOnlyMemory<byte> bytes => bytes,
                Memory<byte> bytes => bytes,
                _ => throw new InvalidOperationException($"Type '{value.GetType().FullName}' is not of the byte-string group.")
            };
        }


        /// <summary>Answers a hash code over a byte string's content.</summary>
        /// <param name="bytes">The bytes.</param>
        /// <returns>The hash code.</returns>
        private static int ByteStringHashCode(ReadOnlyMemory<byte> bytes)
        {
            var hash = new HashCode();
            hash.Add(MapKeyKind.ByteString);
            hash.AddBytes(bytes.Span);

            return hash.ToHashCode();
        }


        /// <summary>Answers the elements of an array group member.</summary>
        /// <param name="value">A value of the array group.</param>
        /// <returns>The elements in order.</returns>
        private static IReadOnlyList<object?> ToElements(object value)
        {
            return value is IReadOnlyList<object?> elements ? elements : [.. (IEnumerable<object?>)value];
        }


        /// <summary>Tells whether two arrays are the same map key: equal in length and element by element.</summary>
        /// <param name="x">The first array's elements.</param>
        /// <param name="y">The second array's elements.</param>
        /// <returns><see langword="true"/> when the two are the same map key.</returns>
        private static bool IsSameArray(IReadOnlyList<object?> x, IReadOnlyList<object?> y)
        {
            if(x.Count != y.Count)
            {
                return false;
            }

            for(int i = 0; i < x.Count; i++)
            {
                if(!IsSameMapKey(x[i], y[i]))
                {
                    return false;
                }
            }

            return true;
        }


        /// <summary>Answers a hash code over an array's elements in order.</summary>
        /// <param name="elements">The elements.</param>
        /// <returns>The hash code.</returns>
        private static int ArrayHashCode(IReadOnlyList<object?> elements)
        {
            var hash = new HashCode();
            hash.Add(MapKeyKind.Array);
            foreach(object? element in elements)
            {
                hash.Add(MapKeyHashCode(element));
            }

            return hash.ToHashCode();
        }


        /// <summary>
        /// Answers the entries of a dictionary in the dictionary shapes <see cref="WriteValue"/> writes as a map,
        /// or <see langword="null"/> for a value that is no such dictionary.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns>The entries, or <see langword="null"/>.</returns>
        private static IReadOnlyList<KeyValuePair<object, object?>>? MapEntriesOf(object? value)
        {
            return value switch
            {
                IDictionary<int, object?> entries => [.. entries.Select(entry => new KeyValuePair<object, object?>(entry.Key, entry.Value))],
                IDictionary<long, object?> entries => [.. entries.Select(entry => new KeyValuePair<object, object?>(entry.Key, entry.Value))],
                IDictionary<string, object?> entries => [.. entries.Select(entry => new KeyValuePair<object, object?>(entry.Key, entry.Value))],
                IReadOnlyDictionary<int, object> entries => [.. entries.Select(entry => new KeyValuePair<object, object?>(entry.Key, entry.Value))],
                IReadOnlyDictionary<long, object> entries => [.. entries.Select(entry => new KeyValuePair<object, object?>(entry.Key, entry.Value))],
                IReadOnlyDictionary<string, object> entries => [.. entries.Select(entry => new KeyValuePair<object, object?>(entry.Key, entry.Value))],
                IDictionary<object, object?> entries => [.. entries],
                _ => null
            };
        }


        /// <summary>
        /// Tells whether two maps are the same map key: the same number of pairs and, for every pair of one, a
        /// pair of the other with the same map key and the same value, in any order.
        /// </summary>
        /// <param name="x">The first map's entries.</param>
        /// <param name="y">The second map's entries.</param>
        /// <returns><see langword="true"/> when the two are the same map key.</returns>
        private static bool IsSameMap(IReadOnlyList<KeyValuePair<object, object?>> x, IReadOnlyList<KeyValuePair<object, object?>> y)
        {
            if(x.Count != y.Count)
            {
                return false;
            }

            var yByMapKey = new Dictionary<object, object?>(y.Count, Instance);
            foreach(KeyValuePair<object, object?> entry in y)
            {
                _ = yByMapKey.TryAdd(entry.Key, entry.Value);
            }

            foreach(KeyValuePair<object, object?> entry in x)
            {
                if(!yByMapKey.TryGetValue(entry.Key, out object? yValue) || !IsSameMapKey(entry.Value, yValue))
                {
                    return false;
                }
            }

            return true;
        }


        /// <summary>Answers a hash code over a map's pairs that does not depend on their order.</summary>
        /// <param name="entries">The map's entries.</param>
        /// <returns>The hash code.</returns>
        private static int MapHashCode(IReadOnlyList<KeyValuePair<object, object?>> entries)
        {
            int pairs = 0;
            foreach(KeyValuePair<object, object?> entry in entries)
            {
                pairs = unchecked(pairs + HashCode.Combine(MapKeyHashCode(entry.Key), MapKeyHashCode(entry.Value)));
            }

            return HashCode.Combine(MapKeyKind.Map, entries.Count, pairs);
        }


        /// <summary>Tells whether two tagged values are the same map key: the same tag number and the same content.</summary>
        /// <param name="x">The first tagged value.</param>
        /// <param name="y">The second tagged value.</param>
        /// <returns><see langword="true"/> when the two are the same map key.</returns>
        private static bool IsSameTagged(ValueTuple<ulong, object> x, ValueTuple<ulong, object> y)
        {
            return x.Item1 == y.Item1 && IsSameMapKey(x.Item2, y.Item2);
        }


        /// <summary>Answers a hash code over a tagged value's tag number and content.</summary>
        /// <param name="tagged">The tagged value.</param>
        /// <returns>The hash code.</returns>
        private static int TaggedHashCode(ValueTuple<ulong, object> tagged)
        {
            return HashCode.Combine(MapKeyKind.Tagged, tagged.Item1, MapKeyHashCode(tagged.Item2));
        }
    }


    /// <summary>The groups of RFC 8949 Section 5.6.1 a map key belongs to; map keys of two groups are never the same.</summary>
    private enum MapKeyKind
    {
        /// <summary>The simple value <c>null</c>.</summary>
        Null,

        /// <summary>The simple values <c>false</c> and <c>true</c>.</summary>
        Boolean,

        /// <summary>An integer.</summary>
        Integer,

        /// <summary>A floating-point number.</summary>
        FloatingPoint,

        /// <summary>A text string.</summary>
        TextString,

        /// <summary>A byte string.</summary>
        ByteString,

        /// <summary>An array.</summary>
        Array,

        /// <summary>A map.</summary>
        Map,

        /// <summary>A tagged value.</summary>
        Tagged,

        /// <summary>A decimal fraction, written as Tag 4.</summary>
        DecimalFraction,

        /// <summary>A value of no other group, compared by <see cref="object.Equals(object?, object?)"/>.</summary>
        Other
    }
}
