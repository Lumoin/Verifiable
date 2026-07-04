using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Text;
using Verifiable.Cesr;
using Verifiable.Cesr.Text;
using Verifiable.Cryptography;

namespace Verifiable.Keri;

/// <summary>
/// Decodes a CESR-native (qb64 text-domain) KERI key event into the neutral field map that the
/// serialization-agnostic <see cref="KeriEventReader"/> folds into a typed key event. This is the CESR-native arm
/// of the bytes-to-field-map decode seam — the counterpart of the JSON, CBOR, and MGPK arms — and it produces the
/// same neutral map shape (scalars as strings, key-state list fields as string lists), so the reader consumes the
/// result identically whatever the serialization was.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#universal-code-table-genusversion-codes-that-do-not-allow-genusversion-override">
/// native message body codes</see> (<c>-F</c>/<c>--F</c> for a top-level fixed-field message) and the KERI
/// specification's <see href="https://trustoverip.github.io/kswg-keri-specification/#key-event-messages">key
/// event message</see> native examples. A native KERI key event is one <c>-F</c> fixed-field group whose body is
/// the field values in the message type's fixed order with no labels: the version primitive (<c>0O</c>), the
/// message-type tag (<c>X</c>), then the remaining values — fully qualified primitives for the digest and prefix
/// fields, number primitives for the sequence number and thresholds, and <c>-J</c> list groups for the key,
/// digest, and backer lists.
/// </para>
/// <para>
/// A native field map carries no size-bearing version string: the <c>-F</c> count code gives the size, and the
/// body's leading <c>v</c> primitive encodes only the protocol and version, not the serialization kind or length
/// (CESR specification, <see href="https://trustoverip.github.io/kswg-cesr-specification/#version-string-field">
/// Version String field</see>). So the decoder reconstructs the in-memory placeholder <c>v</c> the specification
/// prescribes — the same protocol and version with the serialization kind set to <c>CESR</c> and the length taken
/// from the framing — which is what re-serialization would key on and what the spec's worked examples show as the
/// in-memory value. The SAID is verified over the received native bytes by <see cref="KeriEventSaid"/>, exactly as
/// for the other serializations, since the SAID digests the serialization with its <c>d</c> field dummied.
/// </para>
/// </remarks>
public static class KeriEventCesr
{
    /// <summary>The CESR code of the KERI protocol/version primitive that opens a native message body (Tag10).</summary>
    private const string VersionPrimitiveCode = "0O";


    /// <summary>
    /// Decodes a CESR-native KERI key event serialization into its neutral field map.
    /// </summary>
    /// <param name="nativeText">The received native event serialization: the qb64 text-domain bytes (ASCII) of the whole <c>-F</c> framed message.</param>
    /// <param name="pool">The memory pool the transient decode buffers are rented from.</param>
    /// <returns>The decoded message field map, preserving the fields' serialization order: scalar fields as strings, key-state list fields as string lists, keyed by the message field label.</returns>
    /// <exception cref="CesrFormatException">The bytes are not a well-formed native fixed-field KERI message.</exception>
    /// <exception cref="KeriException">The message type is not a modeled key event with a fixed field order.</exception>
    public static MessageFieldMap DecodeFieldMap(ReadOnlyMemory<byte> nativeText, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        char[] rented = ArrayPool<char>.Shared.Rent(Math.Max(nativeText.Length, 1));
        try
        {
            int charCount = Encoding.ASCII.GetChars(nativeText.Span, rented);

            return Decode(rented.AsSpan(0, charCount), pool);
        }
        finally
        {
            ArrayPool<char>.Shared.Return(rented);
        }
    }


    //Walks the fixed-field message: the leading -F frame fixes the total size, the body opens with the universal
    //v and t prefix, and the remaining values follow positionally in the message type's fixed field order. The
    //resulting map preserves that field order (a native body is inherently ordered, so the canonical order is met).
    private static MessageFieldMap Decode(ReadOnlySpan<char> message, MemoryPool<byte> pool)
    {
        CesrParsedCountCode frame = CesrCountCodeCodec.DecodeText(message);
        if(frame.Code is not ("-F" or "--F"))
        {
            throw new CesrFormatException($"A CESR-native KERI key event must be framed by the fixed-field body code '-F' or '--F', not '{frame.Code}'.");
        }

        int frameCodeLength = CesrCountCodeTables.SizingForSelector(message[0], message[1]).FullSize;

        //Compare the declared body size in long (see the ACDC message decoder): a big -F frame's character count can
        //exceed int range, so an int total could overflow and spuriously equal the message length. The equality
        //against the actual length bounds it, so the narrowing to int is safe.
        long declaredTotal = frameCodeLength + frame.TextCharCount;
        if(declaredTotal != message.Length)
        {
            throw new CesrFormatException($"The CESR-native message frame declares {frame.TextCharCount} body characters but the message has {message.Length - frameCodeLength}.");
        }

        int total = (int)declaredTotal;

        var map = new MessageFieldMap(StringComparer.Ordinal);
        int offset = frameCodeLength;

        offset += DecodeVersion(message[offset..], total, pool, out string version);
        map[KeriMessageFields.Version] = version;

        offset += DecodeTag(message[offset..], pool, out string messageType);
        map[KeriMessageFields.MessageType] = messageType;

        IReadOnlyList<string> fieldOrder = KeriMessageFields.FieldOrderFor(messageType);
        for(int i = 2; i < fieldOrder.Count; i++)
        {
            string label = fieldOrder[i];
            offset += DecodeField(label, message[offset..], pool, out object? value);
            map[label] = value;
        }

        if(offset != message.Length)
        {
            throw new CesrFormatException($"The CESR-native message has {message.Length - offset} trailing characters after its declared fields.");
        }

        return map;
    }


    //Decodes the body's leading version primitive (0O) and reconstructs the in-memory placeholder version string
    //the specification prescribes: the primitive's protocol and version, the CESR serialization marker, and the
    //total serialization length (the count code, not an embedded version string, carries the size natively).
    private static int DecodeVersion(ReadOnlySpan<char> span, int totalLength, MemoryPool<byte> pool, out string version)
    {
        using CesrParsedPrimitive primitive = CesrPrimitiveCodec.DecodeText(span, pool, out int consumed);
        if(primitive.Code != VersionPrimitiveCode)
        {
            throw new CesrFormatException($"A CESR-native KERI message body must open with the version primitive '{VersionPrimitiveCode}', not '{primitive.Code}'.");
        }

        version = CesrVersionPrimitive.Reconstruct(primitive.Soft, totalLength);

        return consumed;
    }


    //Decodes a tag primitive (the message type t, or a configuration trait c), whose neutral value is the tag's
    //soft value (the special-value characters the tag conveys, for example "icp" or "DID").
    private static int DecodeTag(ReadOnlySpan<char> span, MemoryPool<byte> pool, out string tag)
    {
        using CesrParsedPrimitive primitive = CesrPrimitiveCodec.DecodeText(span, pool, out int consumed);
        if(primitive.Soft.Length == 0)
        {
            throw new CesrFormatException($"A CESR-native KERI message expected a tag primitive but '{primitive.Code}' carries no special value.");
        }

        tag = primitive.Soft;

        return consumed;
    }


    //Dispatches a field to its native decode by the field's kind, which the field label determines: the fixed-field
    //native schema fixes each label's value type, exactly as it fixes the field order.
    private static int DecodeField(string label, ReadOnlySpan<char> span, MemoryPool<byte> pool, out object? value)
    {
        if(label == KeriMessageFields.Said || label == KeriMessageFields.Prefix || label == KeriMessageFields.PriorSaid || label == KeriMessageFields.DelegatorPrefix)
        {
            return DecodePassthrough(span, pool, out value);
        }

        if(label == KeriMessageFields.SequenceNumber || label == KeriMessageFields.BackerThreshold)
        {
            int consumed = DecodeNumber(span, pool, out string hex);
            value = hex;

            return consumed;
        }

        if(label == KeriMessageFields.KeysSigningThreshold || label == KeriMessageFields.NextKeysSigningThreshold)
        {
            return DecodeThreshold(span, pool, out value);
        }

        if(label == KeriMessageFields.SigningKeys || label == KeriMessageFields.NextKeyDigests || label == KeriMessageFields.Backers || label == KeriMessageFields.BackersToRemove || label == KeriMessageFields.BackersToAdd)
        {
            int consumed = DecodeList(span, pool, tags: false, out List<string> list);
            value = list;

            return consumed;
        }

        if(label == KeriMessageFields.ConfigurationTraits)
        {
            int consumed = DecodeList(span, pool, tags: true, out List<string> list);
            value = list;

            return consumed;
        }

        if(label == KeriMessageFields.Anchors)
        {
            return DecodeSealList(span, pool, out value);
        }

        throw new CesrFormatException($"The KERI field '{label}' has no CESR-native decode.");
    }


    //Decodes a field whose value is a single fully qualified primitive carried through verbatim (a digest or
    //prefix): the neutral value is the primitive's own qb64 text, the same string the other serializations carry.
    private static int DecodePassthrough(ReadOnlySpan<char> span, MemoryPool<byte> pool, out object? value)
    {
        using CesrParsedPrimitive primitive = CesrPrimitiveCodec.DecodeText(span, pool, out int consumed);
        value = new string(span[..consumed]);

        return consumed;
    }


    //Decodes a number primitive (a sequence number or unweighted threshold/count) to its lowercase hexadecimal
    //string, the neutral form the reader parses, with no insignificant leading zeros.
    private static int DecodeNumber(ReadOnlySpan<char> span, MemoryPool<byte> pool, out string hex)
    {
        using CesrParsedPrimitive primitive = CesrPrimitiveCodec.DecodeText(span, pool, out int consumed);
        hex = BigEndianToHex(primitive.Raw);

        return consumed;
    }


    //Decodes a signing threshold: an unweighted threshold is a number primitive whose hexadecimal value the reader
    //parses; a weighted (fractional) threshold is a variable-length Base64 string carrying the threshold as an infix
    //expression. The two are distinguished by the leading selector — a variable-length code (selector 4 to 9) is the
    //weighted form, a number code the unweighted.
    private static int DecodeThreshold(ReadOnlySpan<char> span, MemoryPool<byte> pool, out object? value)
    {
        if(span.Length > 0 && span[0] is >= '4' and <= '9')
        {
            return DecodeWeightedThreshold(span, pool, out value);
        }

        int consumed = DecodeNumber(span, pool, out string hex);
        value = hex;

        return consumed;
    }


    //Decodes a weighted (fractional) threshold: a variable-length Base64 string whose value characters are the
    //quadlet-aligned Base64 of the infix threshold expression, left-padded with the Base64URL zero character to
    //align on a 24-bit boundary. The infix expression begins with a weight digit, never with the zero pad, so
    //stripping the leading zero characters recovers it.
    private static int DecodeWeightedThreshold(ReadOnlySpan<char> span, MemoryPool<byte> pool, out object? value)
    {
        using CesrParsedPrimitive primitive = CesrPrimitiveCodec.DecodeText(span, pool, out int consumed);
        int codeSize = CesrCodeTables.Sizes[primitive.Code].CodeSize;
        ReadOnlySpan<char> infix = span.Slice(codeSize, consumed - codeSize).TrimStart(Base64UrlAlphabet.Zero);
        value = ParseWeightedThreshold(infix);

        return consumed;
    }


    //Parses an infix weighted-threshold expression into the list of weight strings the reader's threshold parser
    //consumes (KERI specification, Threshold): the slash operator 's' separates a fraction, and the simple
    //weight-list operator 'c' separates the clause's weights. The ANDed-clause operator 'a' and the map-weight
    //operators 'k' and 'v' (multi-clause and nested map weights) are a later slice.
    private static List<string> ParseWeightedThreshold(ReadOnlySpan<char> infix)
    {
        foreach(char operatorCharacter in infix)
        {
            if(operatorCharacter is 'a' or 'k' or 'v')
            {
                throw new CesrFormatException("Decoding a multi-clause or nested (map-weighted) CESR-native signing threshold is a later slice; only a single fractional-weight clause is supported.");
            }
        }

        var weights = new List<string>();
        int start = 0;
        for(int i = 0; i <= infix.Length; i++)
        {
            if(i == infix.Length || infix[i] == 'c')
            {
                weights.Add(new string(infix[start..i]).Replace('s', '/'));
                start = i + 1;
            }
        }

        return weights;
    }


    //Walks a -J generic list group, returning either each element's qb64 text (a key or digest list) or each
    //element's tag soft value (a configuration-trait list); the empty group yields an empty list.
    private static int DecodeList(ReadOnlySpan<char> span, MemoryPool<byte> pool, bool tags, out List<string> list)
    {
        (int codeLength, long bodyChars) = OpenListGroup(span);
        long declaredEnd = codeLength + bodyChars;
        if(declaredEnd > span.Length)
        {
            throw new CesrFormatException("A CESR-native KERI list field declares more characters than the message holds.");
        }

        int end = (int)declaredEnd;
        list = new List<string>();

        int inner = codeLength;
        while(inner < end)
        {
            using CesrParsedPrimitive element = CesrPrimitiveCodec.DecodeText(span[inner..end], pool, out int consumed);
            list.Add(tags ? element.Soft : new string(span.Slice(inner, consumed)));
            inner += consumed;
        }

        return end;
    }


    //Decodes the anchored seals (a) -J list group: each element is a seal count group (-Q..-W) whose body holds
    //one or more flat seal tuples of that type. The result is a list of seal field maps, the neutral shape the
    //serialization-agnostic seal reader consumes.
    private static int DecodeSealList(ReadOnlySpan<char> span, MemoryPool<byte> pool, out object? value)
    {
        (int codeLength, long bodyChars) = OpenListGroup(span);
        long declaredEnd = codeLength + bodyChars;
        if(declaredEnd > span.Length)
        {
            throw new CesrFormatException("A CESR-native KERI list field declares more characters than the message holds.");
        }

        int end = (int)declaredEnd;
        var seals = new List<object?>();

        int inner = codeLength;
        while(inner < end)
        {
            inner += DecodeSealGroup(span[inner..end], pool, seals);
        }

        value = seals;

        return end;
    }


    //Decodes one seal count group (a clan of same-typed seals) into one field map per seal tuple in its body.
    private static int DecodeSealGroup(ReadOnlySpan<char> span, MemoryPool<byte> pool, List<object?> seals)
    {
        CesrParsedCountCode group = CesrCountCodeCodec.DecodeText(span);
        (string Label, bool IsNumber)[] schema = SealFieldSchema(group.Code);
        int codeLength = CesrCountCodeTables.SizingForSelector(span[0], span[1]).FullSize;
        long declaredEnd = codeLength + group.TextCharCount;
        if(declaredEnd > span.Length)
        {
            throw new CesrFormatException("A CESR-native KERI seal group declares more characters than its enclosing list holds.");
        }

        int end = (int)declaredEnd;

        int inner = codeLength;
        while(inner < end)
        {
            var seal = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach((string label, bool isNumber) in schema)
            {
                using CesrParsedPrimitive primitive = CesrPrimitiveCodec.DecodeText(span[inner..end], pool, out int consumed);
                seal[label] = isNumber ? BigEndianToHex(primitive.Raw) : new string(span.Slice(inner, consumed));
                inner += consumed;
            }

            seals.Add(seal);
        }

        return end;
    }


    //The ordered field schema of a seal count group: the labels and per-field kinds (a sequence number is a number,
    //every other field a fully qualified primitive carried through). Only the anchoring event seal (-T), which the
    //key event vectors exercise, is supported; the other seal groups are a later slice.
    private static (string Label, bool IsNumber)[] SealFieldSchema(string sealCode) => sealCode switch
    {
        "-T" or "--T" => KeyEventSealSchema,
        _ => throw new CesrFormatException($"Decoding the CESR-native seal group '{sealCode}' is a later slice; only the anchoring event seal '-T' is supported.")
    };


    //The anchoring event seal (-T) tuple: prefix, sequence number, and SAID (KERI specification, Seal Count Codes).
    private static (string Label, bool IsNumber)[] KeyEventSealSchema { get; } =
    [
        (KeriSealFields.Prefix, false),
        (KeriSealFields.SequenceNumber, true),
        (KeriSealFields.Digest, false)
    ];


    //Reads a -J list group's count code, returning the code's character length and the body's character count. The
    //body count is a long (a big list group can declare more than int range); the caller bounds it to the message.
    private static (int CodeLength, long BodyChars) OpenListGroup(ReadOnlySpan<char> span)
    {
        CesrParsedCountCode group = CesrCountCodeCodec.DecodeText(span);
        if(group.Code is not ("-J" or "--J"))
        {
            throw new CesrFormatException($"A CESR-native KERI list field must be a generic list group '-J' or '--J', not '{group.Code}'.");
        }

        return (CesrCountCodeTables.SizingForSelector(span[0], span[1]).FullSize, group.TextCharCount);
    }


    //Reads a big-endian unsigned number's raw bytes as its minimal lowercase hexadecimal string ("0" for zero),
    //matching the hexadecimal form the sequence number and unweighted thresholds take in the other serializations.
    private static string BigEndianToHex(ReadOnlySpan<byte> raw)
    {
        var value = new BigInteger(raw, isUnsigned: true, isBigEndian: true);
        string hex = value.ToString("x", CultureInfo.InvariantCulture);

        int firstSignificant = 0;
        while(firstSignificant < hex.Length - 1 && hex[firstSignificant] == '0')
        {
            firstSignificant++;
        }

        return hex[firstSignificant..];
    }
}
