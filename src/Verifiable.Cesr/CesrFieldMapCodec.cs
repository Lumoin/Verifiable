using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Verifiable.Cesr.Text;
using Verifiable.Cryptography;

namespace Verifiable.Cesr;

/// <summary>
/// Decodes a CESR-native field map: a generic map group (<c>-I</c>) whose body is a sequence of (label, value)
/// primitive pairs, where a value may itself be a nested map or list group. The primitive layer turns each label
/// primitive into its label text and each value primitive into its serialization-neutral value, and the group
/// walk alternates them and recurses into nested groups to build the neutral <see cref="MessageFieldMap"/>, the
/// same way the KERI fixed-field decoder composes over <see cref="CesrPrimitiveCodec"/>.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#master-code-table-for-genusversion--_aaacaa-keriacdc-protocol-stack-version-200">
/// Master code table</see> and its native field-map encoding: a label is a compact tag or Base64-string primitive,
/// and a value is one of the fixed markers (null, boolean, empty), a decimal-number primitive, a text primitive,
/// an escaped verbatim primitive, or any other fully qualified primitive carried through verbatim (a SAID, an AID,
/// or another qualified value). The neutral value follows the same conventions the other decode arms normalize to:
/// a scalar text value is a <see cref="string"/>, a null value is <see langword="null"/>, a boolean is a
/// <see cref="bool"/>, and a number is narrowed to an <see cref="int"/>, <see cref="long"/>, or
/// <see cref="decimal"/> as the JSON and CBOR arms narrow theirs. The code families and the fixed markers are
/// named by <see cref="CesrFieldMapCodes"/>.
/// </para>
/// </remarks>
public static class CesrFieldMapCodec
{
    /// <summary>The Base64URL zero character an integer decimal string is left-padded with before the code strips it.</summary>
    private const char DecimalZeroPad = 'A';

    /// <summary>The Base64URL-safe stand-in the decimal codec substitutes for the radix point.</summary>
    private const char DecimalPointStandIn = 'p';

    /// <summary>The generic (nested) field-map group codes: the small map group and its big variant.</summary>
    private const string MapGroupCode = "-I";

    /// <summary>The big generic field-map group code, for a body exceeding the small count's capacity.</summary>
    private const string BigMapGroupCode = "--I";

    /// <summary>The generic list group codes: the small list group and its big variant.</summary>
    private const string ListGroupCode = "-J";

    /// <summary>The big generic list group code, for a body exceeding the small count's capacity.</summary>
    private const string BigListGroupCode = "--J";

    /// <summary>
    /// The greatest nesting depth a field map may reach, matching the bound the JSON decode arm places on the
    /// same messages: a defence against an adversarial deeply nested serialization exhausting resources.
    /// </summary>
    private const int MaximumNestingDepth = 32;

    /// <summary>The number of text-domain characters in a CESR quadlet, the unit a count code frames.</summary>
    private const int QuadletCharacters = 4;

    /// <summary>The greatest quadlet count a small (four-character) count code can carry before the big code is needed.</summary>
    private const int SmallCountCapacity = (64 * 64) - 1;


    /// <summary>
    /// Decodes a CESR-native field-map label primitive into its label text.
    /// </summary>
    /// <param name="qb64">The fully qualified Base64URL text; only the leading label primitive is consumed.</param>
    /// <param name="pool">The memory pool the transient decode buffer is rented from.</param>
    /// <param name="consumedChars">The number of leading characters the decoded label primitive occupied.</param>
    /// <returns>The label text.</returns>
    /// <exception cref="CesrFormatException">The leading primitive is not a tag- or Base64-string-coded field-map label.</exception>
    public static string DecodeLabel(ReadOnlySpan<char> qb64, MemoryPool<byte> pool, out int consumedChars)
    {
        ArgumentNullException.ThrowIfNull(pool);

        using CesrParsedPrimitive primitive = CesrPrimitiveCodec.DecodeText(qb64, pool, out consumedChars);
        string code = primitive.Code;

        if(CesrFieldMapCodes.IsTagCode(code))
        {
            return primitive.Soft;
        }

        if(CesrFieldMapCodes.IsBase64TextCode(code))
        {
            return CesrBase64Text.Decode(code, primitive.Raw);
        }

        throw new CesrFormatException($"A CESR field-map label must be a tag- or Base64-string-coded label; code '{code}' is not a valid strict label code.");
    }


    /// <summary>
    /// Decodes a CESR-native field-map value primitive into its serialization-neutral value. A value that is a
    /// nested group (a map or list, opening with the count-code selector) is decoded by the field-map group walk,
    /// not here.
    /// </summary>
    /// <param name="qb64">The fully qualified Base64URL text; only the leading value primitive (and, for an escaped value, the primitive it escapes) is consumed.</param>
    /// <param name="pool">The memory pool the transient decode buffers are rented from.</param>
    /// <param name="consumedChars">The number of leading characters the decoded value occupied.</param>
    /// <returns>The neutral value: <see langword="null"/>, a <see cref="bool"/>, an <see cref="int"/>/<see cref="long"/>/<see cref="decimal"/> number, or a <see cref="string"/> (text or a verbatim qualified primitive).</returns>
    /// <exception cref="CesrFormatException">The leading material is a nested group (decoded by the field-map walk, not here).</exception>
    public static object? DecodeValuePrimitive(ReadOnlySpan<char> qb64, MemoryPool<byte> pool, out int consumedChars)
    {
        ArgumentNullException.ThrowIfNull(pool);
        RejectGroup(qb64);

        using CesrParsedPrimitive primitive = CesrPrimitiveCodec.DecodeText(qb64, pool, out consumedChars);
        string code = primitive.Code;

        if(code == CesrFieldMapCodes.Escape)
        {
            return DecodeEscapedValue(qb64, pool, ref consumedChars);
        }

        if(code == CesrFieldMapCodes.Null)
        {
            return null;
        }

        if(code == CesrFieldMapCodes.Yes)
        {
            return true;
        }

        if(code == CesrFieldMapCodes.No)
        {
            return false;
        }

        if(CesrFieldMapCodes.IsDecimalCode(code))
        {
            return DecodeDecimal(primitive);
        }

        if(IsTextValueCode(code))
        {
            return DecodeTextValue(primitive);
        }

        //Any other fully qualified primitive (a SAID, an AID, or another qualified value) is carried through as
        //its verbatim qb64 text, the same string the other serializations carry.
        return new string(qb64[..consumedChars]);
    }


    /// <summary>
    /// Decodes a single CESR-native field value, which may be a primitive or a nested generic map group. A
    /// message-level decoder that frames its own body composes this with <see cref="DecodeLabel"/> per field.
    /// </summary>
    /// <param name="qb64">The fully qualified Base64URL text; only the leading value is consumed.</param>
    /// <param name="pool">The memory pool the transient decode buffers are rented from.</param>
    /// <param name="consumedChars">The number of leading characters the decoded value occupied.</param>
    /// <returns>The neutral value: a primitive value, or a nested <see cref="MessageFieldMap"/>.</returns>
    /// <exception cref="CesrFormatException">The value is a list group, whose decode is a later slice, or is malformed.</exception>
    public static object? DecodeValue(ReadOnlySpan<char> qb64, MemoryPool<byte> pool, out int consumedChars)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(!qb64.IsEmpty && qb64[0] == CesrCountCodeTables.CountSelector)
        {
            CesrParsedCountCode group = CesrCountCodeCodec.DecodeText(qb64);
            if(group.Code is MapGroupCode or BigMapGroupCode)
            {
                return DecodeMap(qb64, pool, out consumedChars);
            }

            throw new CesrFormatException($"Decoding a CESR field-map value group '{group.Code}' at the message level is a later slice; only a nested map ('{MapGroupCode}') and primitive values are supported.");
        }

        return DecodeValuePrimitive(qb64, pool, out consumedChars);
    }


    /// <summary>
    /// Decodes a standalone CESR-native field-map serialization (a single generic map group) into its neutral
    /// field map, requiring the whole input to be the map and nothing more.
    /// </summary>
    /// <param name="nativeText">The received native serialization: the qb64 text-domain bytes (ASCII) of the whole map group.</param>
    /// <param name="pool">The memory pool the transient decode buffers are rented from.</param>
    /// <returns>The decoded field map, preserving field order, with nested maps as further <see cref="MessageFieldMap"/> values and lists as <see cref="IReadOnlyList{T}"/> of neutral values.</returns>
    /// <exception cref="CesrFormatException">The bytes are not a single well-formed generic map group, or carry trailing characters.</exception>
    public static MessageFieldMap DecodeFieldMap(ReadOnlyMemory<byte> nativeText, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        char[] rented = ArrayPool<char>.Shared.Rent(Math.Max(nativeText.Length, 1));
        try
        {
            int charCount = Encoding.ASCII.GetChars(nativeText.Span, rented);
            MessageFieldMap map = DecodeMap(rented.AsSpan(0, charCount), pool, out int consumed);
            if(consumed != charCount)
            {
                throw new CesrFormatException($"The CESR-native field map has {charCount - consumed} trailing characters after its declared body.");
            }

            return map;
        }
        finally
        {
            ArrayPool<char>.Shared.Return(rented);
        }
    }


    /// <summary>
    /// Decodes one CESR-native generic map group (with all of its nesting) into a neutral field map, reporting how
    /// many characters the group occupied so a caller can advance past it. The walk is iterative over an explicit
    /// stack of in-progress containers rather than recursive, so an adversarial serialization cannot exhaust the
    /// call stack; nesting is additionally bounded by <see cref="MaximumNestingDepth"/>.
    /// </summary>
    /// <param name="qb64">The fully qualified Base64URL text; only the leading map group is consumed.</param>
    /// <param name="pool">The memory pool the transient decode buffers are rented from.</param>
    /// <param name="consumedChars">The number of leading characters the decoded map group occupied.</param>
    /// <returns>The decoded field map, preserving field order.</returns>
    /// <exception cref="CesrFormatException">The leading group is not a generic map group, or its body is malformed.</exception>
    public static MessageFieldMap DecodeMap(ReadOnlySpan<char> qb64, MemoryPool<byte> pool, out int consumedChars)
    {
        ArgumentNullException.ThrowIfNull(pool);

        MessageFieldMap root = OpenMapGroup(qb64, at: 0, out int bodyStart, out int rootEnd);
        var stack = new Stack<FieldMapFrame>();
        stack.Push(new FieldMapFrame(root, rootEnd));
        int offset = bodyStart;

        while(true)
        {
            FieldMapFrame frame = stack.Peek();
            if(offset >= frame.End)
            {
                stack.Pop();
                if(stack.Count == 0)
                {
                    break;
                }

                Attach(stack.Peek(), frame.Container);

                continue;
            }

            if(frame.Map is not null && frame.PendingLabel is null)
            {
                frame.PendingLabel = DecodeLabel(qb64[offset..frame.End], pool, out int labelChars);
                offset += labelChars;

                continue;
            }

            if(qb64[offset] == CesrCountCodeTables.CountSelector)
            {
                offset += OpenValueGroup(qb64, offset, frame.End, stack);

                continue;
            }

            object? value = DecodeValuePrimitive(qb64[offset..frame.End], pool, out int valueChars);
            offset += valueChars;
            Attach(frame, value);
        }

        consumedChars = rootEnd;

        return root;
    }


    /// <summary>
    /// Encodes a field map into its CESR-native serialization: a generic map group whose body is the (label, value)
    /// primitive pairs in the map's insertion order, with a nested map or list value encoded as its own group. The
    /// inverse of <see cref="DecodeMap"/>; the encode is iterative over an explicit stack of in-progress group
    /// bodies rather than recursive, matching the encode arm of the other serializations.
    /// </summary>
    /// <param name="map">The field map to encode, whose nested maps are <see cref="MessageFieldMap"/> and whose lists are <see cref="IReadOnlyList{T}"/> of neutral values, as the decode produces.</param>
    /// <param name="pool">The memory pool the transient primitive-classification buffers are rented from.</param>
    /// <param name="output">The buffer the CESR-native qb64 bytes (ASCII) are written to.</param>
    /// <exception cref="CesrFormatException">A value is of a type the neutral map does not use, or needs an encoding that is a later slice.</exception>
    public static void EncodeFieldMap(MessageFieldMap map, MemoryPool<byte> pool, IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(map);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(output);

        string qb64 = EncodeToText(map, pool);
        Span<byte> destination = output.GetSpan(qb64.Length);
        int written = Encoding.ASCII.GetBytes(qb64, destination);
        output.Advance(written);
    }


    /// <summary>
    /// Encodes a single CESR-native field value, which may be a primitive or a nested map. A message-level encoder
    /// that frames its own body composes this with <see cref="EncodeLabel"/> per field.
    /// </summary>
    /// <param name="value">The neutral value: a primitive value, or a nested <see cref="MessageFieldMap"/>.</param>
    /// <param name="pool">The memory pool the transient primitive-classification buffers are rented from.</param>
    /// <returns>The value's qb64 text.</returns>
    /// <exception cref="CesrFormatException">The value is a list, whose encode is a later slice, or is of a type the neutral map does not use.</exception>
    public static string EncodeValue(object? value, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return value switch
        {
            MessageFieldMap nested => EncodeToText(nested, pool),
            List<object?> => throw new CesrFormatException($"Encoding a CESR field-map list value at the message level is a later slice; only a nested map and primitive values are supported."),
            _ => EncodeScalarValue(value, pool)
        };
    }


    /// <summary>
    /// Decodes a standalone CESR-native field map from the binary domain (qb2) into its neutral field map. A
    /// field-map serialization is a concatenation of 24-bit-aligned primitives and groups, so its binary domain is
    /// exactly the Base64URL decoding of its text domain; this transcodes to the text domain and decodes.
    /// </summary>
    /// <param name="qb2">The binary-domain bytes of the whole map group.</param>
    /// <param name="pool">The memory pool the transient decode buffers are rented from.</param>
    /// <returns>The decoded field map, preserving field order.</returns>
    /// <exception cref="CesrFormatException">The bytes are not a single well-formed 24-bit-aligned map group.</exception>
    public static MessageFieldMap DecodeFieldMapBinary(ReadOnlyMemory<byte> qb2, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        string qb64 = Base64Url.EncodeToString(qb2.Span);
        MessageFieldMap map = DecodeMap(qb64, pool, out int consumed);
        if(consumed != qb64.Length)
        {
            throw new CesrFormatException($"The CESR-native binary field map has {qb64.Length - consumed} trailing characters after its declared body.");
        }

        return map;
    }


    /// <summary>
    /// Encodes a field map into its CESR-native binary-domain (qb2) serialization: the Base64URL decoding of the
    /// text-domain serialization, which is well-defined because the serialization is 24-bit aligned.
    /// </summary>
    /// <param name="map">The field map to encode.</param>
    /// <param name="pool">The memory pool the transient primitive-classification buffers are rented from.</param>
    /// <param name="output">The buffer the CESR-native binary bytes are written to.</param>
    /// <exception cref="CesrFormatException">A value needs an encoding that is a later slice.</exception>
    public static void EncodeFieldMapBinary(MessageFieldMap map, MemoryPool<byte> pool, IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(map);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(output);

        string qb64 = EncodeToText(map, pool);
        Span<byte> destination = output.GetSpan(Base64Url.GetMaxDecodedLength(qb64.Length));
        if(Base64Url.DecodeFromChars(qb64, destination, out _, out int written) != OperationStatus.Done)
        {
            throw new CesrFormatException("The CESR-native field map does not transcode to a 24-bit-aligned binary form.");
        }

        output.Advance(written);
    }


    //Builds the qb64 text of a map group and all of its nesting by an iterative post-order walk: each frame
    //accumulates its group body, and a completed nested group is framed with its count code and appended to its
    //parent's body, so a group's count code is written only once its body length is known.
    private static string EncodeToText(MessageFieldMap map, MemoryPool<byte> pool)
    {
        var stack = new Stack<EncodeFrame>();
        stack.Push(new EncodeFrame(map));
        string? result = null;

        while(stack.Count > 0)
        {
            EncodeFrame frame = stack.Peek();
            if(frame.TryGetNext(out string? label, out object? value))
            {
                if(label is not null)
                {
                    frame.Body.Append(EncodeLabel(label));
                }

                EncodeFrame? child = value switch
                {
                    MessageFieldMap nested => new EncodeFrame(nested),
                    List<object?> list => new EncodeFrame(list),
                    _ => AppendScalar(frame.Body, value, pool)
                };

                if(child is not null)
                {
                    stack.Push(child);
                }

                continue;
            }

            stack.Pop();
            string wrapped = WrapGroup(frame);
            if(stack.Count == 0)
            {
                result = wrapped;
            }
            else
            {
                stack.Peek().Body.Append(wrapped);
            }
        }

        return result!;
    }


    //Appends a scalar value's encoding to a group body and yields no child frame (scalars do not open a group).
    private static EncodeFrame? AppendScalar(StringBuilder body, object? value, MemoryPool<byte> pool)
    {
        body.Append(EncodeScalarValue(value, pool));

        return null;
    }


    //Frames a completed group body with its count code: the small map/list code, or the big code when the body
    //exceeds the small count's capacity.
    private static string WrapGroup(EncodeFrame frame)
    {
        string body = frame.Body.ToString();
        int quadlets = body.Length / QuadletCharacters;
        string code = frame.IsMap
            ? (quadlets > SmallCountCapacity ? BigMapGroupCode : MapGroupCode)
            : (quadlets > SmallCountCapacity ? BigListGroupCode : ListGroupCode);

        return CesrCountCodeCodec.EncodeText(code, quadlets) + body;
    }


    /// <summary>
    /// Encodes a single field label as its compact tag primitive: the label text is the tag's soft value, sized by
    /// the label's length. A message-level decoder that frames its own body composes this with <see cref="EncodeValue"/>.
    /// </summary>
    /// <param name="label">The field label to encode; a valid Base64 attribute name.</param>
    /// <returns>The label's qb64 tag primitive, or a Base64-string primitive when longer than a compact tag.</returns>
    public static string EncodeLabel(string label)
    {
        ArgumentNullException.ThrowIfNull(label);

        string? code = TagCodeForLength(label.Length);

        return code is not null
            ? CesrPrimitiveCodec.EncodeText(code, ReadOnlySpan<byte>.Empty, soft: label)
            : CesrBase64Text.Encode(label);
    }


    //Encodes a scalar field value as its primitive, inverse of the value-primitive decode: the fixed markers, a
    //number, or a text/verbatim primitive. A container value never reaches here (the walk opens a group for it).
    private static string EncodeScalarValue(object? value, MemoryPool<byte> pool) => value switch
    {
        null => EncodeMarker(CesrFieldMapCodes.Null),
        bool boolean => EncodeMarker(boolean ? CesrFieldMapCodes.Yes : CesrFieldMapCodes.No),
        int integer => EncodeNumber(integer.ToString(CultureInfo.InvariantCulture)),
        long wide => EncodeNumber(wide.ToString(CultureInfo.InvariantCulture)),
        decimal fraction => EncodeNumber(fraction.ToString(CultureInfo.InvariantCulture)),
        string text => EncodeStringValue(text, pool),
        _ => throw new CesrFormatException($"A CESR field-map value of type '{value.GetType()}' is not one the neutral map uses.")
    };


    //Encodes a fixed marker (null, boolean, empty) as its zero-raw primitive.
    private static string EncodeMarker(string code) => CesrPrimitiveCodec.EncodeText(code, ReadOnlySpan<byte>.Empty);


    //Encodes a decimal number as its compact Base64 number-string primitive: the radix point travels as a
    //Base64-safe stand-in, the string is left-padded to a quadlet boundary and Base64-decoded, and the lead the
    //padding implies selects the lead-sized decimal code.
    private static string EncodeNumber(string numberString)
    {
        string translated = numberString.Replace('.', DecimalPointStandIn);
        int tail = translated.Length % QuadletCharacters;
        int pad = (QuadletCharacters - tail) % QuadletCharacters;
        int leadSize = (3 - tail) % 3;

        Span<char> padded = stackalloc char[pad + translated.Length];
        padded[..pad].Fill(DecimalZeroPad);
        translated.CopyTo(padded[pad..]);

        Span<byte> decoded = stackalloc byte[Base64Url.GetMaxDecodedLength(padded.Length)];
        Base64Url.DecodeFromChars(padded, decoded, out _, out int decodedLength);
        ReadOnlySpan<byte> raw = decoded[leadSize..decodedLength];

        return CesrPrimitiveCodec.EncodeText(DecimalCodeForLead(leadSize), raw);
    }


    //Encodes a string value, inverse of the value-primitive text/verbatim decode: the empty marker for an empty
    //string; a complete qualified primitive carried verbatim (escaped when it would be mistaken for a typed value);
    //otherwise a compact tag or Base64-string primitive for Base64 text, or a byte-string primitive for other text.
    private static string EncodeStringValue(string text, MemoryPool<byte> pool)
    {
        if(text.Length == 0)
        {
            return EncodeMarker(CesrFieldMapCodes.Empty);
        }

        if(IsCompletePrimitive(text, pool, out string code))
        {
            return CesrFieldMapCodes.IsEscapableValueCode(code)
                ? EncodeMarker(CesrFieldMapCodes.Escape) + text
                : text;
        }

        if(IsBase64(text))
        {
            string? tag = TagCodeForLength(text.Length);

            return tag is not null
                ? CesrPrimitiveCodec.EncodeText(tag, ReadOnlySpan<byte>.Empty, soft: text)
                : CesrBase64Text.Encode(text);
        }

        if(text.Length <= 2)
        {
            throw new CesrFormatException("Encoding a one- or two-character non-Base64 CESR field-map text value is a later slice.");
        }

        int byteCount = Encoding.UTF8.GetByteCount(text);
        byte[] rented = ArrayPool<byte>.Shared.Rent(byteCount);
        try
        {
            int written = Encoding.UTF8.GetBytes(text, rented);
            ReadOnlySpan<byte> raw = rented.AsSpan(0, written);
            int leadSize = (3 - (written % 3)) % 3;

            return CesrPrimitiveCodec.EncodeText(ByteStringCodeForLead(leadSize), raw);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }


    //Whether a string is exactly one complete CESR primitive (it decodes and consumes the whole string), reporting
    //the primitive's code; used to decide whether a string value is carried verbatim or as text.
    private static bool IsCompletePrimitive(string text, MemoryPool<byte> pool, out string code)
    {
        try
        {
            using CesrParsedPrimitive primitive = CesrPrimitiveCodec.DecodeText(text, pool, out int consumed);
            if(consumed == text.Length)
            {
                code = primitive.Code;

                return true;
            }
        }
        catch(CesrFormatException)
        {
            //Not a well-formed primitive, so it is text.
        }

        code = string.Empty;

        return false;
    }


    //Whether every character of a string is a Base64URL character (so it can be carried as a compact tag or a
    //Base64-string primitive rather than as raw bytes).
    private static bool IsBase64(string text)
    {
        foreach(char character in text)
        {
            bool ok = character is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_';
            if(!ok)
            {
                return false;
            }
        }

        return true;
    }


    //Maps a label/text length (in Base64 characters) to the compact tag code that carries it, or null when the
    //length exceeds the largest compact tag (eleven characters).
    private static string? TagCodeForLength(int length) => length switch
    {
        1 => "0J",
        2 => "0K",
        3 => "X",
        4 => "1AAF",
        5 => "0L",
        6 => "0M",
        7 => "Y",
        8 => "1AAN",
        9 => "0N",
        10 => "0O",
        11 => "Z",
        _ => null
    };


    //Maps a lead size to the lead-sized decimal-number code.
    private static string DecimalCodeForLead(int leadSize) => leadSize switch
    {
        0 => "4H",
        1 => "5H",
        2 => "6H",
        _ => throw new CesrFormatException($"Invalid decimal lead size {leadSize}.")
    };


    //Maps a lead size to the lead-sized byte-string code.
    private static string ByteStringCodeForLead(int leadSize) => leadSize switch
    {
        0 => "4B",
        1 => "5B",
        2 => "6B",
        _ => throw new CesrFormatException($"Invalid byte-string lead size {leadSize}.")
    };


    //Opens a generic map group at the given position: validates the framing code, computes the body's start and
    //absolute end, and returns the empty ordered map the body will fill.
    private static MessageFieldMap OpenMapGroup(ReadOnlySpan<char> qb64, int at, out int bodyStart, out int end)
    {
        CesrParsedCountCode frame = CesrCountCodeCodec.DecodeText(qb64[at..]);
        if(frame.Code is not (MapGroupCode or BigMapGroupCode))
        {
            throw new CesrFormatException($"A CESR-native field map must be framed by a generic map group '{MapGroupCode}' or '{BigMapGroupCode}', not '{frame.Code}'.");
        }

        int codeLength = CesrCountCodeTables.SizingForSelector(qb64[at], qb64[at + 1]).FullSize;
        bodyStart = at + codeLength;

        //Compute the body end in long: a big map group's declared character count can exceed int range, and an
        //int addition would overflow to a value that slips past the length guard below (silently accepting a group
        //that claims a multi-gigabyte body while supplying none). The guard then bounds it to the input, so the
        //narrowing to int is safe.
        long declaredEnd = (long)bodyStart + frame.TextCharCount;
        if(qb64.Length < declaredEnd)
        {
            throw new CesrFormatException($"The CESR-native map group declares {frame.TextCharCount} body characters but fewer are present.");
        }

        end = (int)declaredEnd;

        return new MessageFieldMap(StringComparer.Ordinal);
    }


    //Opens a nested value group (a map or a list) at the given position, pushing its frame onto the stack, and
    //returns the number of characters its count code occupied so the caller can advance to the group's body.
    private static int OpenValueGroup(ReadOnlySpan<char> qb64, int at, int parentEnd, Stack<FieldMapFrame> stack)
    {
        if(stack.Count >= MaximumNestingDepth)
        {
            throw new CesrFormatException($"A CESR-native field map nests deeper than the {MaximumNestingDepth}-level limit.");
        }

        CesrParsedCountCode group = CesrCountCodeCodec.DecodeText(qb64[at..]);
        int codeLength = CesrCountCodeTables.SizingForSelector(qb64[at], qb64[at + 1]).FullSize;

        //Long arithmetic (see OpenMapGroup): a big group's declared count can exceed int range, so an int end
        //could overflow negative and slip past the overrun check, silently accepting a lying nested group.
        long declaredEnd = (long)at + codeLength + group.TextCharCount;
        if(declaredEnd > parentEnd)
        {
            throw new CesrFormatException("A nested CESR field-map group overruns its enclosing group.");
        }

        int end = (int)declaredEnd;

        FieldMapFrame child = group.Code switch
        {
            MapGroupCode or BigMapGroupCode => new FieldMapFrame(new MessageFieldMap(StringComparer.Ordinal), end),
            ListGroupCode or BigListGroupCode => new FieldMapFrame(new List<object?>(), end),
            _ => throw new CesrFormatException($"A CESR field-map value group must be a map ('{MapGroupCode}') or list ('{ListGroupCode}'); code '{group.Code}' is neither.")
        };
        stack.Push(child);

        return codeLength;
    }


    //Attaches a completed value to its enclosing container: under the map's pending label, or appended to the list.
    private static void Attach(FieldMapFrame frame, object? value)
    {
        if(frame.Map is not null)
        {
            frame.Map[frame.PendingLabel!] = value;
            frame.PendingLabel = null;
        }
        else
        {
            frame.List!.Add(value);
        }
    }


    //Rejects a value that opens a nested group: a map or list value is walked by the field-map group decoder, so
    //it must not reach the primitive value decoder.
    private static void RejectGroup(ReadOnlySpan<char> qb64)
    {
        if(!qb64.IsEmpty && qb64[0] == CesrCountCodeTables.CountSelector)
        {
            throw new CesrFormatException("A CESR field-map value that is a nested group is decoded by the field-map walk, not as a value primitive.");
        }
    }


    //Decodes an escaped value: the escape marker is followed by the primitive it escapes, whose verbatim qb64 text
    //is the neutral value. Both the marker and the escaped primitive are consumed.
    private static string DecodeEscapedValue(ReadOnlySpan<char> qb64, MemoryPool<byte> pool, ref int consumedChars)
    {
        using CesrParsedPrimitive escaped = CesrPrimitiveCodec.DecodeText(qb64[consumedChars..], pool, out int escapedChars);
        string verbatim = new string(qb64.Slice(consumedChars, escapedChars));
        consumedChars += escapedChars;

        return verbatim;
    }


    //Whether a primitive value code renders to text: a compact tag, the empty marker, a raw-byte string, or a
    //Base64 string (which renders to text via the Base64-string codec rather than to verbatim passthrough).
    private static bool IsTextValueCode(string code) =>
        CesrFieldMapCodes.IsTagCode(code)
        || code == CesrFieldMapCodes.Empty
        || CesrFieldMapCodes.IsRawTextCode(code)
        || CesrFieldMapCodes.IsBase64TextCode(code);


    //Decodes a text value: a compact tag carries its text in the soft part, the empty marker is the empty string,
    //a raw-byte string is its UTF-8 bytes; and a Base64-string primitive is its packed characters.
    private static string DecodeTextValue(CesrParsedPrimitive primitive)
    {
        string code = primitive.Code;

        if(CesrFieldMapCodes.IsTagCode(code))
        {
            return primitive.Soft;
        }

        if(code == CesrFieldMapCodes.Empty)
        {
            return string.Empty;
        }

        if(CesrFieldMapCodes.IsRawTextCode(code))
        {
            return Encoding.UTF8.GetString(primitive.Raw);
        }

        return CesrBase64Text.Decode(code, primitive.Raw);
    }


    //Decodes a decimal-number value: the number is carried as a compact Base64 number string, recovered by
    //re-rendering the raw value under its lead size and stripping the pad the code conveys, then narrowed to the
    //neutral map's number convention (an int, else a long, else a decimal, matching the JSON and CBOR arms), so a
    //number reaches the reader as the same value whatever serialization carried it (the radix point travels as a
    //Base64-safe stand-in).
    private static object DecodeDecimal(CesrParsedPrimitive primitive)
    {
        int leadSize = CesrCodeTables.Sizes[primitive.Code].LeadSize;
        string encoded = CesrTextCodec.EncodeValue(primitive.Raw, prefixZeros: leadSize, skip: 0);
        int strip = leadSize == 0
            ? (encoded.Length > 0 && encoded[0] == DecimalZeroPad ? 1 : 0)
            : (leadSize + 1) % 4;
        string numberString = encoded[strip..].Replace(DecimalPointStandIn, '.');

        if(int.TryParse(numberString, NumberStyles.Integer, CultureInfo.InvariantCulture, out int narrow))
        {
            return narrow;
        }

        if(long.TryParse(numberString, NumberStyles.Integer, CultureInfo.InvariantCulture, out long wide))
        {
            return wide;
        }

        //A decimal-coded field whose recovered characters are not a valid number is malformed wire input, not a
        //programming error: reject it as a CESR format violation rather than letting decimal.Parse escape as a
        //FormatException or OverflowException (a peer can craft a decimal code over arbitrary content).
        if(decimal.TryParse(numberString, NumberStyles.Float, CultureInfo.InvariantCulture, out decimal wideDecimal))
        {
            return wideDecimal;
        }

        throw new CesrFormatException("A CESR field-map decimal value is not a valid number.");
    }


    //One in-progress container on the field-map walk stack: exactly one of Map or List is non-null. A map frame
    //also tracks the label whose value it is waiting to attach.
    private sealed class FieldMapFrame
    {
        /// <summary>Initializes a frame for an in-progress map ending at the given absolute character offset.</summary>
        /// <param name="map">The ordered map the frame fills.</param>
        /// <param name="end">The absolute character offset at which the group's body ends.</param>
        public FieldMapFrame(MessageFieldMap map, int end)
        {
            Map = map;
            End = end;
        }


        /// <summary>Initializes a frame for an in-progress list ending at the given absolute character offset.</summary>
        /// <param name="list">The list the frame fills.</param>
        /// <param name="end">The absolute character offset at which the group's body ends.</param>
        public FieldMapFrame(List<object?> list, int end)
        {
            List = list;
            End = end;
        }


        /// <summary>The ordered map this frame fills, or <see langword="null"/> when the frame is a list.</summary>
        public MessageFieldMap? Map { get; }

        /// <summary>The list this frame fills, or <see langword="null"/> when the frame is a map.</summary>
        public List<object?>? List { get; }

        /// <summary>The absolute character offset at which this group's body ends.</summary>
        public int End { get; }

        /// <summary>The label a map frame has read and is waiting to attach a value under; <see langword="null"/> when a label is expected next.</summary>
        public string? PendingLabel { get; set; }

        /// <summary>The container object this frame fills, for attaching to an enclosing frame when it completes.</summary>
        public object? Container => Map is not null ? Map : List;
    }


    //One in-progress group body on the encode stack: it accumulates the group's qb64 body as its entries are
    //encoded, and holds the (struct) enumerator over its source map or list. Held as a class so the enumerator
    //advances in place across Stack.Peek() calls — a struct frame would be copied and lose enumerator progress.
    private sealed class EncodeFrame
    {
        /// <summary>The enumerator over a map frame's entries; used only when the frame is a map.</summary>
        private OrderedDictionary<string, object?>.Enumerator mapEntries;

        /// <summary>The enumerator over a list frame's elements; used only when the frame is a list.</summary>
        private List<object?>.Enumerator listEntries;

        /// <summary>Initializes a frame that encodes the entries of the given map.</summary>
        /// <param name="map">The map whose entries the frame encodes.</param>
        public EncodeFrame(MessageFieldMap map)
        {
            IsMap = true;
            mapEntries = map.GetEnumerator();
        }


        /// <summary>Initializes a frame that encodes the elements of the given list.</summary>
        /// <param name="list">The list whose elements the frame encodes.</param>
        public EncodeFrame(List<object?> list)
        {
            listEntries = list.GetEnumerator();
        }


        /// <summary>Whether this frame encodes a map (and so emits a label before each value); otherwise a list.</summary>
        public bool IsMap { get; }

        /// <summary>The accumulated qb64 body of this group, without its framing count code.</summary>
        public StringBuilder Body { get; } = new StringBuilder();

        /// <summary>
        /// Advances to the next entry to encode.
        /// </summary>
        /// <param name="label">The entry's label for a map frame; <see langword="null"/> for a list element.</param>
        /// <param name="value">The entry's value.</param>
        /// <returns><see langword="true"/> when an entry was produced; <see langword="false"/> when the frame is exhausted.</returns>
        public bool TryGetNext(out string? label, out object? value)
        {
            if(IsMap)
            {
                if(mapEntries.MoveNext())
                {
                    label = mapEntries.Current.Key;
                    value = mapEntries.Current.Value;

                    return true;
                }
            }
            else if(listEntries.MoveNext())
            {
                label = null;
                value = listEntries.Current;

                return true;
            }

            label = null;
            value = null;

            return false;
        }
    }
}
