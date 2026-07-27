using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Minimal RFC 8949 CBOR major-type primitives backing <see cref="CtapAuthenticatorSnapshotCborWriter"/>
/// and <see cref="CtapAuthenticatorSnapshotCborReader"/> — an internal implementation detail of the
/// custody snapshot format, never exposed outside this subfolder.
/// </summary>
/// <remarks>
/// Covers exactly the major types this snapshot's own fixed schema needs (unsigned integer, negative
/// integer, byte string, text string, array, and the three simple values <see langword="true"/>/
/// <see langword="false"/>/<see langword="null"/>) — no CBOR map support, no indefinite-length items, and
/// no tag support, since a custody snapshot's shape is fully known ahead of time by both sides of the
/// seam. This is why parsing is bounded and iterative rather than a general recursive-descent CBOR parser
/// (R-5): every nesting level in this format is a specific, named field the higher-level reader visits
/// explicitly, never an arbitrary depth driven by the input bytes themselves.
/// </remarks>
internal static class CborPrimitives
{
    /// <summary>The RFC 8949 major type for an unsigned integer.</summary>
    public const byte MajorUnsigned = 0;

    /// <summary>The RFC 8949 major type for a negative integer (encoded as <c>-1 - argument</c>).</summary>
    public const byte MajorNegative = 1;

    /// <summary>The RFC 8949 major type for a byte string.</summary>
    public const byte MajorByteString = 2;

    /// <summary>The RFC 8949 major type for a UTF-8 text string.</summary>
    public const byte MajorTextString = 3;

    /// <summary>The RFC 8949 major type for a definite-length array.</summary>
    public const byte MajorArray = 4;

    /// <summary>The RFC 8949 major type for a simple value (this format uses only false/true/null).</summary>
    public const byte MajorSimple = 7;

    /// <summary>The RFC 8949 simple-value additional-information code for <see langword="false"/>.</summary>
    public const byte SimpleFalse = 20;

    /// <summary>The RFC 8949 simple-value additional-information code for <see langword="true"/>.</summary>
    public const byte SimpleTrue = 21;

    /// <summary>The RFC 8949 simple-value additional-information code for <see langword="null"/>.</summary>
    public const byte SimpleNull = 22;

    /// <summary>The number of bits a major-type value is shifted into the leading byte's high bits.</summary>
    private const int MajorTypeShift = 5;


    /// <summary>
    /// Writes a major-type-and-argument header using the shortest legal RFC 8949 encoding for
    /// <paramref name="argument"/>.
    /// </summary>
    /// <param name="writer">The buffer to append to.</param>
    /// <param name="majorType">The three-bit major type.</param>
    /// <param name="argument">The header's argument value (a length, a count, or the value itself for an unsigned integer).</param>
    public static void WriteHeader(ArrayBufferWriter<byte> writer, byte majorType, ulong argument)
    {
        byte high = (byte)(majorType << MajorTypeShift);

        if(argument < 24)
        {
            Span<byte> span = writer.GetSpan(1);
            span[0] = (byte)(high | (byte)argument);
            writer.Advance(1);
        }
        else if(argument <= byte.MaxValue)
        {
            Span<byte> span = writer.GetSpan(2);
            span[0] = (byte)(high | 24);
            span[1] = (byte)argument;
            writer.Advance(2);
        }
        else if(argument <= ushort.MaxValue)
        {
            Span<byte> span = writer.GetSpan(3);
            span[0] = (byte)(high | 25);
            BinaryPrimitives.WriteUInt16BigEndian(span[1..], (ushort)argument);
            writer.Advance(3);
        }
        else if(argument <= uint.MaxValue)
        {
            Span<byte> span = writer.GetSpan(5);
            span[0] = (byte)(high | 26);
            BinaryPrimitives.WriteUInt32BigEndian(span[1..], (uint)argument);
            writer.Advance(5);
        }
        else
        {
            Span<byte> span = writer.GetSpan(9);
            span[0] = (byte)(high | 27);
            BinaryPrimitives.WriteUInt64BigEndian(span[1..], argument);
            writer.Advance(9);
        }
    }


    /// <summary>Writes a signed integer as an RFC 8949 unsigned or negative major-type item.</summary>
    /// <param name="writer">The buffer to append to.</param>
    /// <param name="value">The signed value to write.</param>
    public static void WriteInt(ArrayBufferWriter<byte> writer, long value)
    {
        if(value >= 0)
        {
            WriteHeader(writer, MajorUnsigned, (ulong)value);
        }
        else
        {
            WriteHeader(writer, MajorNegative, (ulong)(-1 - value));
        }
    }


    /// <summary>Writes a boolean as an RFC 8949 simple value.</summary>
    /// <param name="writer">The buffer to append to.</param>
    /// <param name="value">The value to write.</param>
    public static void WriteBool(ArrayBufferWriter<byte> writer, bool value)
    {
        Span<byte> span = writer.GetSpan(1);
        span[0] = (byte)((MajorSimple << MajorTypeShift) | (value ? SimpleTrue : SimpleFalse));
        writer.Advance(1);
    }


    /// <summary>Writes the RFC 8949 <see langword="null"/> simple value.</summary>
    /// <param name="writer">The buffer to append to.</param>
    public static void WriteNull(ArrayBufferWriter<byte> writer)
    {
        Span<byte> span = writer.GetSpan(1);
        span[0] = (byte)((MajorSimple << MajorTypeShift) | SimpleNull);
        writer.Advance(1);
    }


    /// <summary>Writes a byte string item: a length header followed by the raw bytes.</summary>
    /// <param name="writer">The buffer to append to.</param>
    /// <param name="value">The bytes to write.</param>
    public static void WriteByteString(ArrayBufferWriter<byte> writer, ReadOnlySpan<byte> value)
    {
        WriteHeader(writer, MajorByteString, (ulong)value.Length);
        Span<byte> span = writer.GetSpan(value.Length);
        value.CopyTo(span);
        writer.Advance(value.Length);
    }


    /// <summary>Writes either the RFC 8949 <see langword="null"/> simple value or a byte string item.</summary>
    /// <param name="writer">The buffer to append to.</param>
    /// <param name="value">The bytes to write when <paramref name="isNull"/> is <see langword="false"/>.</param>
    /// <param name="isNull">Whether to write <see langword="null"/> instead of <paramref name="value"/>.</param>
    public static void WriteNullableByteString(ArrayBufferWriter<byte> writer, ReadOnlySpan<byte> value, bool isNull)
    {
        if(isNull)
        {
            WriteNull(writer);
        }
        else
        {
            WriteByteString(writer, value);
        }
    }


    /// <summary>Writes a UTF-8 text string item: a byte-length header followed by the UTF-8 bytes.</summary>
    /// <param name="writer">The buffer to append to.</param>
    /// <param name="value">The text to write.</param>
    public static void WriteTextString(ArrayBufferWriter<byte> writer, string value)
    {
        int byteCount = Encoding.UTF8.GetByteCount(value);
        WriteHeader(writer, MajorTextString, (ulong)byteCount);
        Span<byte> span = writer.GetSpan(byteCount);
        Encoding.UTF8.GetBytes(value, span);
        writer.Advance(byteCount);
    }


    /// <summary>Writes either the RFC 8949 <see langword="null"/> simple value or a text string item.</summary>
    /// <param name="writer">The buffer to append to.</param>
    /// <param name="value">The text to write, or <see langword="null"/> to write the null simple value.</param>
    public static void WriteNullableTextString(ArrayBufferWriter<byte> writer, string? value)
    {
        if(value is null)
        {
            WriteNull(writer);
        }
        else
        {
            WriteTextString(writer, value);
        }
    }


    /// <summary>Writes a definite-length array header for <paramref name="count"/> following items.</summary>
    /// <param name="writer">The buffer to append to.</param>
    /// <param name="count">The number of items the array holds.</param>
    public static void WriteArrayHeader(ArrayBufferWriter<byte> writer, int count) => WriteHeader(writer, MajorArray, (ulong)count);
}


/// <summary>
/// A bounded, forward-only cursor over a CBOR-encoded snapshot's bytes — the reading counterpart of
/// <see cref="CborPrimitives"/>'s writing helpers. Every read validates enough bytes remain before
/// advancing and every length-prefixed read is checked against a caller-supplied maximum, so a truncated
/// or adversarially large length/count in the input fails closed with a <see cref="CtapAuthenticatorSnapshotException"/>
/// rather than throwing an unrelated <see cref="IndexOutOfRangeException"/> or exhausting memory.
/// </summary>
internal ref struct CborCursor
{
    /// <summary>The full input this cursor reads from.</summary>
    private readonly ReadOnlySpan<byte> data;

    /// <summary>The next unread offset into <see cref="data"/>.</summary>
    private int position;


    /// <summary>Initializes a cursor positioned at the start of <paramref name="data"/>.</summary>
    /// <param name="data">The CBOR-encoded bytes to read from.</param>
    public CborCursor(ReadOnlySpan<byte> data)
    {
        this.data = data;
        position = 0;
    }


    /// <summary>Reads one item header (major type and argument).</summary>
    /// <returns>The item's major type and argument value.</returns>
    /// <exception cref="CtapAuthenticatorSnapshotException">The buffer is truncated or the header uses an unsupported (indefinite-length) additional-information code.</exception>
    public (byte MajorType, ulong Argument) ReadHeader()
    {
        EnsureAvailable(1);
        byte first = data[position];
        position++;

        byte majorType = (byte)(first >> 5);
        byte additionalInfo = (byte)(first & 0x1F);
        ulong argument = additionalInfo switch
        {
            < 24 => additionalInfo,
            24 => ReadRawBigEndian(1),
            25 => ReadRawBigEndian(2),
            26 => ReadRawBigEndian(4),
            27 => ReadRawBigEndian(8),
            _ => throw new CtapAuthenticatorSnapshotException(
                $"Unsupported CBOR additional-information value '{additionalInfo}' — this format supports only definite-length items.")
        };

        return (majorType, argument);
    }


    /// <summary>Reads a signed integer item (major type 0 or 1).</summary>
    /// <returns>The decoded value.</returns>
    /// <exception cref="CtapAuthenticatorSnapshotException">The next item is not an integer.</exception>
    public long ReadInt()
    {
        (byte majorType, ulong argument) = ReadHeader();

        return majorType switch
        {
            CborPrimitives.MajorUnsigned => checked((long)argument),
            CborPrimitives.MajorNegative => checked(-1L - (long)argument),
            _ => throw new CtapAuthenticatorSnapshotException($"Expected an integer item but found major type '{majorType}'.")
        };
    }


    /// <summary>Reads an unsigned integer item (major type 0).</summary>
    /// <returns>The decoded value.</returns>
    /// <exception cref="CtapAuthenticatorSnapshotException">The next item is not an unsigned integer.</exception>
    public ulong ReadUnsigned()
    {
        (byte majorType, ulong argument) = ReadHeader();
        if(majorType != CborPrimitives.MajorUnsigned)
        {
            throw new CtapAuthenticatorSnapshotException($"Expected an unsigned integer item but found major type '{majorType}'.");
        }

        return argument;
    }


    /// <summary>Reads a boolean simple-value item.</summary>
    /// <returns>The decoded value.</returns>
    /// <exception cref="CtapAuthenticatorSnapshotException">The next item is not a boolean simple value.</exception>
    public bool ReadBool()
    {
        (byte majorType, ulong argument) = ReadHeader();
        if(majorType == CborPrimitives.MajorSimple && argument == CborPrimitives.SimpleTrue)
        {
            return true;
        }

        if(majorType == CborPrimitives.MajorSimple && argument == CborPrimitives.SimpleFalse)
        {
            return false;
        }

        throw new CtapAuthenticatorSnapshotException($"Expected a boolean simple value but found major type '{majorType}', argument '{argument}'.");
    }


    /// <summary>Reads either the <see langword="null"/> simple value or a signed integer item.</summary>
    /// <param name="value">The decoded value when an integer was read; <see langword="0"/> when <see langword="null"/> was read.</param>
    /// <returns><see langword="false"/> if the item was <see langword="null"/>; otherwise <see langword="true"/>.</returns>
    /// <exception cref="CtapAuthenticatorSnapshotException">The next item is neither <see langword="null"/> nor an integer.</exception>
    public bool TryReadNullableInt(out long value)
    {
        (byte majorType, ulong argument) = ReadHeader();
        if(majorType == CborPrimitives.MajorSimple && argument == CborPrimitives.SimpleNull)
        {
            value = 0;
            return false;
        }

        value = majorType switch
        {
            CborPrimitives.MajorUnsigned => checked((long)argument),
            CborPrimitives.MajorNegative => checked(-1L - (long)argument),
            _ => throw new CtapAuthenticatorSnapshotException($"Expected null or an integer item but found major type '{majorType}'.")
        };

        return true;
    }


    /// <summary>Reads either the <see langword="null"/> simple value or a boolean simple-value item.</summary>
    /// <param name="value">The decoded value when a boolean was read; <see langword="false"/> when <see langword="null"/> was read.</param>
    /// <returns><see langword="false"/> if the item was <see langword="null"/>; otherwise <see langword="true"/>.</returns>
    /// <exception cref="CtapAuthenticatorSnapshotException">The next item is neither <see langword="null"/> nor a boolean simple value.</exception>
    public bool TryReadNullableBool(out bool value)
    {
        (byte majorType, ulong argument) = ReadHeader();
        if(majorType == CborPrimitives.MajorSimple && argument == CborPrimitives.SimpleNull)
        {
            value = false;
            return false;
        }

        if(majorType == CborPrimitives.MajorSimple && argument == CborPrimitives.SimpleTrue)
        {
            value = true;
            return true;
        }

        if(majorType == CborPrimitives.MajorSimple && argument == CborPrimitives.SimpleFalse)
        {
            value = false;
            return true;
        }

        throw new CtapAuthenticatorSnapshotException($"Expected null or a boolean simple value but found major type '{majorType}', argument '{argument}'.");
    }


    /// <summary>Reads a definite-length array header.</summary>
    /// <param name="maxCount">The maximum legal item count — a defensive bound against a corrupt or adversarial length claim.</param>
    /// <returns>The array's declared item count.</returns>
    /// <exception cref="CtapAuthenticatorSnapshotException">The next item is not an array, or its count exceeds <paramref name="maxCount"/>.</exception>
    public int ReadArrayHeader(int maxCount)
    {
        (byte majorType, ulong argument) = ReadHeader();
        if(majorType != CborPrimitives.MajorArray)
        {
            throw new CtapAuthenticatorSnapshotException($"Expected an array item but found major type '{majorType}'.");
        }

        if(argument > (ulong)maxCount)
        {
            throw new CtapAuthenticatorSnapshotException($"Array count '{argument}' exceeds the bound '{maxCount}'.");
        }

        return (int)argument;
    }


    /// <summary>Reads a byte string item's bytes as a view over the input (no copy).</summary>
    /// <param name="maxLength">The maximum legal byte length — a defensive bound against a corrupt or adversarial length claim.</param>
    /// <returns>A span over exactly the item's bytes, valid only as long as the original input is.</returns>
    /// <exception cref="CtapAuthenticatorSnapshotException">The next item is not a byte string, its length exceeds <paramref name="maxLength"/>, or the buffer is truncated.</exception>
    public ReadOnlySpan<byte> ReadByteString(int maxLength)
    {
        (byte majorType, ulong argument) = ReadHeader();
        if(majorType != CborPrimitives.MajorByteString)
        {
            throw new CtapAuthenticatorSnapshotException($"Expected a byte string item but found major type '{majorType}'.");
        }

        return ReadBodyBytes(argument, maxLength);
    }


    /// <summary>Reads either the <see langword="null"/> simple value or a byte string item's bytes.</summary>
    /// <param name="maxLength">The maximum legal byte length — see <see cref="ReadByteString"/>.</param>
    /// <param name="value">The item's bytes when a byte string was read; an empty span when <see langword="null"/> was read.</param>
    /// <returns><see langword="false"/> if the item was <see langword="null"/>; otherwise <see langword="true"/>.</returns>
    /// <exception cref="CtapAuthenticatorSnapshotException">The next item is neither <see langword="null"/> nor a byte string, or its length exceeds <paramref name="maxLength"/>.</exception>
    public bool TryReadNullableByteString(int maxLength, out ReadOnlySpan<byte> value)
    {
        (byte majorType, ulong argument) = ReadHeader();
        if(majorType == CborPrimitives.MajorSimple && argument == CborPrimitives.SimpleNull)
        {
            value = ReadOnlySpan<byte>.Empty;
            return false;
        }

        if(majorType != CborPrimitives.MajorByteString)
        {
            throw new CtapAuthenticatorSnapshotException($"Expected null or a byte string item but found major type '{majorType}'.");
        }

        value = ReadBodyBytes(argument, maxLength);
        return true;
    }


    /// <summary>Reads a UTF-8 text string item.</summary>
    /// <param name="maxByteLength">The maximum legal UTF-8 byte length — a defensive bound against a corrupt or adversarial length claim.</param>
    /// <returns>The decoded text.</returns>
    /// <exception cref="CtapAuthenticatorSnapshotException">The next item is not a text string, its length exceeds <paramref name="maxByteLength"/>, or the buffer is truncated.</exception>
    public string ReadTextString(int maxByteLength)
    {
        (byte majorType, ulong argument) = ReadHeader();
        if(majorType != CborPrimitives.MajorTextString)
        {
            throw new CtapAuthenticatorSnapshotException($"Expected a text string item but found major type '{majorType}'.");
        }

        ReadOnlySpan<byte> bytes = ReadBodyBytes(argument, maxByteLength);

        return Encoding.UTF8.GetString(bytes);
    }


    /// <summary>Reads either the <see langword="null"/> simple value or a UTF-8 text string item.</summary>
    /// <param name="maxByteLength">The maximum legal UTF-8 byte length — see <see cref="ReadTextString"/>.</param>
    /// <returns>The decoded text, or <see langword="null"/> when the item was <see langword="null"/>.</returns>
    /// <exception cref="CtapAuthenticatorSnapshotException">The next item is neither <see langword="null"/> nor a text string, or its length exceeds <paramref name="maxByteLength"/>.</exception>
    public string? ReadNullableTextString(int maxByteLength)
    {
        (byte majorType, ulong argument) = ReadHeader();
        if(majorType == CborPrimitives.MajorSimple && argument == CborPrimitives.SimpleNull)
        {
            return null;
        }

        if(majorType != CborPrimitives.MajorTextString)
        {
            throw new CtapAuthenticatorSnapshotException($"Expected null or a text string item but found major type '{majorType}'.");
        }

        ReadOnlySpan<byte> bytes = ReadBodyBytes(argument, maxByteLength);

        return Encoding.UTF8.GetString(bytes);
    }


    /// <summary>Reads exactly <paramref name="length"/> bytes as the body of a string item, bounded by <paramref name="maxLength"/>.</summary>
    private ReadOnlySpan<byte> ReadBodyBytes(ulong length, int maxLength)
    {
        if(length > (ulong)maxLength)
        {
            throw new CtapAuthenticatorSnapshotException($"String length '{length}' exceeds the bound '{maxLength}'.");
        }

        int len = (int)length;
        EnsureAvailable(len);
        ReadOnlySpan<byte> slice = data.Slice(position, len);
        position += len;

        return slice;
    }


    /// <summary>Reads <paramref name="byteCount"/> bytes as a big-endian unsigned integer header argument.</summary>
    private ulong ReadRawBigEndian(int byteCount)
    {
        EnsureAvailable(byteCount);
        ulong value = byteCount switch
        {
            1 => data[position],
            2 => BinaryPrimitives.ReadUInt16BigEndian(data.Slice(position, 2)),
            4 => BinaryPrimitives.ReadUInt32BigEndian(data.Slice(position, 4)),
            8 => BinaryPrimitives.ReadUInt64BigEndian(data.Slice(position, 8)),
            _ => throw new CtapAuthenticatorSnapshotException("Unreachable CBOR header argument width.")
        };
        position += byteCount;

        return value;
    }


    /// <summary>Throws if fewer than <paramref name="count"/> bytes remain unread.</summary>
    private readonly void EnsureAvailable(int count)
    {
        if(position + count > data.Length)
        {
            throw new CtapAuthenticatorSnapshotException("The snapshot payload is truncated.");
        }
    }
}
