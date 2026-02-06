using System.Formats.Cbor;

namespace Verifiable.Cbor;

/// <summary>
/// Extension methods for <see cref="CborReader"/> providing higher-level reading operations.
/// </summary>
/// <remarks>
/// These extensions simplify common patterns such as reading typed arrays, maps with known
/// key types, and handling optional values. They follow the parse-as-far-as-possible principle
/// where partial data can still be useful.
/// </remarks>
public static class CborReaderExtensions
{
    /// <summary>
    /// Reads a CBOR byte string and returns it as a byte array.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The byte string as a byte array.</returns>
    /// <exception cref="CborContentException">Thrown when the current item is not a byte string.</exception>
    public static byte[] ReadByteStringAsArray(this CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        return reader.ReadByteString();
    }


    /// <summary>
    /// Reads a CBOR array of byte strings.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>A list of byte arrays.</returns>
    /// <exception cref="CborContentException">Thrown when the structure is invalid.</exception>
    public static List<byte[]> ReadByteStringArray(this CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        int? length = reader.ReadStartArray();
        if(length is null)
        {
            CborThrowHelper.ThrowIndefiniteLengthNotAllowed();
        }

        var result = new List<byte[]>(length.Value);
        for(int i = 0; i < length.Value; i++)
        {
            result.Add(reader.ReadByteString());
        }

        reader.ReadEndArray();
        return result;
    }


    /// <summary>
    /// Reads a CBOR array of text strings.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>A list of strings.</returns>
    /// <exception cref="CborContentException">Thrown when the structure is invalid.</exception>
    public static List<string> ReadTextStringArray(this CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        int? length = reader.ReadStartArray();
        if(length is null)
        {
            CborThrowHelper.ThrowIndefiniteLengthNotAllowed();
        }

        var result = new List<string>(length.Value);
        for(int i = 0; i < length.Value; i++)
        {
            result.Add(reader.ReadTextString());
        }

        reader.ReadEndArray();
        return result;
    }


    /// <summary>
    /// Reads a CBOR array of integers.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>A list of integers.</returns>
    /// <exception cref="CborContentException">Thrown when the structure is invalid.</exception>
    public static List<int> ReadInt32Array(this CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        int? length = reader.ReadStartArray();
        if(length is null)
        {
            CborThrowHelper.ThrowIndefiniteLengthNotAllowed();
        }

        var result = new List<int>(length.Value);
        for(int i = 0; i < length.Value; i++)
        {
            result.Add(reader.ReadInt32());
        }

        reader.ReadEndArray();
        return result;
    }


    /// <summary>
    /// Reads a CBOR array of unsigned integers.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>A list of unsigned integers.</returns>
    /// <exception cref="CborContentException">Thrown when the structure is invalid.</exception>
    public static List<uint> ReadUInt32Array(this CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        int? length = reader.ReadStartArray();
        if(length is null)
        {
            CborThrowHelper.ThrowIndefiniteLengthNotAllowed();
        }

        var result = new List<uint>(length.Value);
        for(int i = 0; i < length.Value; i++)
        {
            result.Add(reader.ReadUInt32());
        }

        reader.ReadEndArray();
        return result;
    }


    /// <summary>
    /// Tries to peek at the next CBOR state without consuming it.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <param name="state">The peeked state, if available.</param>
    /// <returns><see langword="true"/> if a state was available; otherwise, <see langword="false"/>.</returns>
    public static bool TryPeekState(this CborReader reader, out CborReaderState state)
    {
        ArgumentNullException.ThrowIfNull(reader);
        try
        {
            state = reader.PeekState();
            return true;
        }
        catch(CborContentException)
        {
            state = default;
            return false;
        }
    }


    /// <summary>
    /// Reads a CBOR map with integer keys into a dictionary.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <param name="valueReader">A function to read each value.</param>
    /// <typeparam name="TValue">The type of map values.</typeparam>
    /// <returns>A dictionary with integer keys.</returns>
    /// <exception cref="CborContentException">Thrown when the structure is invalid.</exception>
    public static Dictionary<long, TValue> ReadIntKeyedMap<TValue>(
        this CborReader reader,
        Func<CborReader, TValue> valueReader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(valueReader);
        int? length = reader.ReadStartMap();
        if(length is null)
        {
            CborThrowHelper.ThrowIndefiniteLengthNotAllowed();
        }

        var result = new Dictionary<long, TValue>(length.Value);
        for(int i = 0; i < length.Value; i++)
        {
            long key = reader.ReadInt64();
            TValue value = valueReader(reader);
            result[key] = value;
        }

        reader.ReadEndMap();
        return result;
    }


    /// <summary>
    /// Reads a CBOR map with text string keys into a dictionary.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <param name="valueReader">A function to read each value.</param>
    /// <typeparam name="TValue">The type of map values.</typeparam>
    /// <returns>A dictionary with string keys.</returns>
    /// <exception cref="CborContentException">Thrown when the structure is invalid.</exception>
    public static Dictionary<string, TValue> ReadStringKeyedMap<TValue>(
        this CborReader reader,
        Func<CborReader, TValue> valueReader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(valueReader);
        int? length = reader.ReadStartMap();
        if(length is null)
        {
            CborThrowHelper.ThrowIndefiniteLengthNotAllowed();
        }

        var result = new Dictionary<string, TValue>(length.Value);
        for(int i = 0; i < length.Value; i++)
        {
            string key = reader.ReadTextString();
            TValue value = valueReader(reader);
            result[key] = value;
        }

        reader.ReadEndMap();
        return result;
    }


    /// <summary>
    /// Skips the current CBOR value, including any nested structures.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <remarks>
    /// This is useful for skipping unknown properties when <see cref="CborSerializerOptions.IgnoreUnknownProperties"/>
    /// is enabled.
    /// </remarks>
    public static void SkipValue(this CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        reader.SkipValue();
    }


    /// <summary>
    /// Reads a nullable byte string, returning null if the CBOR null value is encountered.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The byte string, or null.</returns>
    public static byte[]? ReadNullableByteString(this CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        if(reader.PeekState() == CborReaderState.Null)
        {
            reader.ReadNull();
            return null;
        }

        return reader.ReadByteString();
    }


    /// <summary>
    /// Reads a nullable text string, returning null if the CBOR null value is encountered.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The text string, or null.</returns>
    public static string? ReadNullableTextString(this CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        if(reader.PeekState() == CborReaderState.Null)
        {
            reader.ReadNull();
            return null;
        }

        return reader.ReadTextString();
    }


    /// <summary>
    /// Expects and reads a specific array length, throwing if the length does not match.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <param name="expectedLength">The expected array length.</param>
    /// <exception cref="CborContentException">Thrown when the length does not match.</exception>
    public static void ReadStartArrayExpectLength(this CborReader reader, int expectedLength)
    {
        ArgumentNullException.ThrowIfNull(reader);
        int? length = reader.ReadStartArray();
        if(length is null)
        {
            CborThrowHelper.ThrowIndefiniteLengthNotAllowed();
        }

        if(length.Value != expectedLength)
        {
            CborThrowHelper.ThrowInvalidArrayLength(expectedLength, length.Value);
        }
    }


    /// <summary>
    /// Reads the start of an array and validates the length is within a range.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <param name="minLength">The minimum allowed length.</param>
    /// <param name="maxLength">The maximum allowed length.</param>
    /// <returns>The actual array length.</returns>
    /// <exception cref="CborContentException">Thrown when the length is out of range.</exception>
    public static int ReadStartArrayExpectLengthRange(this CborReader reader, int minLength, int maxLength)
    {
        ArgumentNullException.ThrowIfNull(reader);
        int? length = reader.ReadStartArray();
        if(length is null)
        {
            CborThrowHelper.ThrowIndefiniteLengthNotAllowed();
            return 0; //Unreachable, but satisfies compiler.
        }

        if(length.Value < minLength || length.Value > maxLength)
        {
            CborThrowHelper.ThrowInvalidArrayLengthRange(minLength, maxLength, length.Value);
        }

        return length.Value;
    }
}