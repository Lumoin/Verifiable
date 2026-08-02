using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.JCose;

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
    /// Reads a CBOR tag 32 (<c>#6.32(tstr)</c>) value as a <see cref="Uri"/> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.4.5.3">RFC 8949 §3.4.5.3</see>.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The decoded URI.</returns>
    /// <exception cref="CborContentException">Thrown when the current item is not tagged 32.</exception>
    public static Uri ReadUri(this CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);

        CborTag tag = reader.ReadTag();
        if(tag != CborTag.Uri)
        {
            CborThrowHelper.ThrowCborContentException($"Expected CBOR tag {(ulong)CborTag.Uri} (URI), but got tag {(ulong)tag}.");
        }

        string text = reader.ReadTextString();
        return new Uri(text, UriKind.RelativeOrAbsolute);
    }


    /// <summary>
    /// Reads the next CBOR map entry's integer key, requiring it to sort strictly after
    /// <paramref name="previousKey"/> under the canonical (RFC 8949 §4.2.3, equivalently RFC 7049 §3.9)
    /// deterministic map-key ordering the .NET canonical writer enforces on write but the reader does not
    /// enforce on its own — the shorter canonical encoding sorts first; same-length encodings compare
    /// bytewise-lexicographically. Corrected from an earlier naive <c>key &lt;= previousKey</c> signed-integer
    /// comparison (wavecb S3 FX-B), which diverges from canonical order for negative keys: major type 1's
    /// magnitude encoding does not correspond to signed integer order, so a self-round-trip of a
    /// canonically-encoded map carrying a negative key after a positive one used to be rejected as
    /// "not ascending" even though the writer itself produced exactly that byte order.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <param name="previousKey">
    /// The previous key read from the same map (pass <c>0</c> before the first entry — every CB-AdES map
    /// key this method serves is a small nonnegative integer, for which canonical order and signed-integer
    /// order provably coincide). Updated to the newly read key on return.
    /// </param>
    /// <returns>The map entry's integer key.</returns>
    /// <exception cref="CborContentException">
    /// Thrown when the key does not sort strictly after <paramref name="previousKey"/> under canonical order.
    /// </exception>
    public static int ReadAscendingMapKey(this CborReader reader, ref int previousKey)
    {
        ArgumentNullException.ThrowIfNull(reader);

        int key = reader.ReadInt32();
        if(!IsAfterInCanonicalOrder(key, previousKey))
        {
            CborThrowHelper.ThrowMapKeysNotAscending(previousKey, key);
        }

        previousKey = key;
        return key;

        /// <summary>
        /// Determines whether <paramref name="candidateKey"/> sorts strictly after
        /// <paramref name="precedingKey"/> under the canonical CBOR integer encoding .NET's
        /// <see cref="CborConformanceMode.Canonical"/> writer actually produces. Both operands are re-encoded
        /// through a scratch canonical <see cref="CborWriter"/> so the comparison is provably identical to what
        /// the write side (e.g. <see cref="Verifiable.Cbor.CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader"/>)
        /// produces.
        /// </summary>
        /// <param name="candidateKey">The candidate key.</param>
        /// <param name="precedingKey">The previously read key (or the caller's sentinel before the first entry).</param>
        /// <returns><see langword="true"/> when <paramref name="candidateKey"/> sorts strictly after <paramref name="precedingKey"/>.</returns>
        static bool IsAfterInCanonicalOrder(int candidateKey, int precedingKey)
        {
            Span<byte> candidateBuffer = stackalloc byte[5];
            Span<byte> precedingBuffer = stackalloc byte[5];

            int candidateLength = EncodeCanonicalInt32(candidateKey, candidateBuffer);
            int precedingLength = EncodeCanonicalInt32(precedingKey, precedingBuffer);

            return IsEncodedKeyAfterInCanonicalOrder(candidateBuffer[..candidateLength], precedingBuffer[..precedingLength]);

            static int EncodeCanonicalInt32(int value, Span<byte> destination)
            {
                var scratchWriter = new CborWriter(CborConformanceMode.Canonical);
                scratchWriter.WriteInt32(value);
                if(!scratchWriter.TryEncode(destination, out int bytesWritten))
                {
                    CborThrowHelper.ThrowCborContentException(
                        "Canonical map-key comparison encoding overflowed the 5-byte scratch buffer.");
                }

                return bytesWritten;
            }
        }
    }


    /// <summary>
    /// Determines whether <paramref name="candidate"/>'s already-encoded CBOR item bytes sort strictly after
    /// <paramref name="previous"/>'s, under the canonical (RFC 8949 §4.2.3, equivalently RFC 7049 §3.9)
    /// deterministic-encoding map-key ordering: the SHORTER encoding sorts first; same-length encodings compare
    /// bytewise-lexicographically. Shared by <see cref="ReadAscendingMapKey"/> (whose two operands are always a
    /// canonically re-encoded <see langword="int"/>) and CB-AdES's top-level protected-header map-key reader
    /// (<see cref="Verifiable.Cbor.CBAdESSignatureSerialization.ParseCBAdESSign1"/>, whose operands may be
    /// either arm of the general COSE <c>label: int / tstr</c> union, RFC 9052 §1.4) — widened to
    /// <see langword="internal"/> rather than kept <see langword="private"/> so that reader (same assembly) can
    /// reuse this comparison instead of duplicating it, mirroring this file's own precedent for cross-file
    /// <see langword="internal"/> widening (<see cref="Verifiable.Cbor.CBAdESSignatureSerialization"/>'s remarks
    /// on <c>CBAdESSerialization.WriteHashAlgorithmDigestPair</c>).
    /// </summary>
    /// <param name="candidate">The candidate key's encoded bytes.</param>
    /// <param name="previous">The previously read key's encoded bytes.</param>
    /// <returns><see langword="true"/> when <paramref name="candidate"/> sorts strictly after <paramref name="previous"/>.</returns>
    internal static bool IsEncodedKeyAfterInCanonicalOrder(ReadOnlySpan<byte> candidate, ReadOnlySpan<byte> previous)
    {
        if(candidate.Length != previous.Length)
        {
            return candidate.Length > previous.Length;
        }

        return candidate.SequenceCompareTo(previous) > 0;
    }


    /// <summary>
    /// Reads a CBOR array of <see cref="CoseHeaderLabel"/> values — the general COSE <c>label: int / tstr</c>
    /// CDDL union (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-1.4">RFC 9052 §1.4</see>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3.1">RFC 9052 §3.1</see>), as used by the
    /// <c>crit</c> header parameter's array elements. Each element is decoded per its own CBOR major type: a
    /// text string decodes to the <see cref="CoseHeaderTextLabel"/> arm, anything else to the
    /// <see cref="CoseHeaderIntegerLabel"/> arm. RFC 9052 imposes no ordering over <c>crit</c>'s array elements
    /// (unlike a map's keys), so this reader enforces none.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <returns>The decoded labels, in wire order.</returns>
    /// <exception cref="CborContentException">Thrown when the structure is invalid.</exception>
    public static List<CoseHeaderLabel> ReadCoseHeaderLabelArray(this CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        int? length = reader.ReadStartArray();
        if(length is null)
        {
            CborThrowHelper.ThrowIndefiniteLengthNotAllowed();
        }

        var result = new List<CoseHeaderLabel>(length.Value);
        for(int i = 0; i < length.Value; i++)
        {
            CoseHeaderLabel label = reader.PeekState() == CborReaderState.TextString
                ? new CoseHeaderTextLabel(reader.ReadTextString())
                : new CoseHeaderIntegerLabel(reader.ReadInt32());
            result.Add(label);
        }

        reader.ReadEndArray();
        return result;
    }


    /// <summary>
    /// Expects and reads a specific map length, throwing if the length does not match.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <param name="expectedLength">The expected map length.</param>
    /// <returns>The actual map length (equal to <paramref name="expectedLength"/>).</returns>
    /// <exception cref="CborContentException">Thrown when the length does not match, or is indefinite.</exception>
    public static int ReadStartMapExpectLength(this CborReader reader, int expectedLength)
    {
        ArgumentNullException.ThrowIfNull(reader);
        int? length = reader.ReadStartMap();
        if(length is null)
        {
            CborThrowHelper.ThrowIndefiniteLengthNotAllowed();
        }

        if(length!.Value != expectedLength)
        {
            CborThrowHelper.ThrowInvalidMapLength(expectedLength, length.Value);
        }

        return length.Value;
    }


    /// <summary>
    /// Reads the start of a map and validates the length is within a range.
    /// </summary>
    /// <param name="reader">The CBOR reader.</param>
    /// <param name="minLength">The minimum allowed map length.</param>
    /// <param name="maxLength">The maximum allowed map length.</param>
    /// <returns>The actual map length.</returns>
    /// <exception cref="CborContentException">Thrown when the length is out of range, or is indefinite.</exception>
    public static int ReadStartMapExpectLengthRange(this CborReader reader, int minLength, int maxLength)
    {
        ArgumentNullException.ThrowIfNull(reader);
        int? length = reader.ReadStartMap();
        if(length is null)
        {
            CborThrowHelper.ThrowIndefiniteLengthNotAllowed();
            return 0; //Unreachable, but satisfies compiler.
        }

        if(length.Value < minLength || length.Value > maxLength)
        {
            CborThrowHelper.ThrowInvalidMapLengthRange(minLength, maxLength, length.Value);
        }

        return length.Value;
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
