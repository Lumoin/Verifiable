using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using Verifiable.Cesr;
using Verifiable.Cryptography;

namespace Verifiable.Acdc;

/// <summary>
/// The CESR-native serialization arm for ACDC: it decodes and encodes an ACDC message body as a CESR-native field-map
/// message group (<c>-G</c>), and serializes an aggregate-section value as a count-coded group of quadlets. The
/// message body is the CESR-native counterpart of the JSON, CBOR, and MGPK decode arms, producing and consuming the
/// same neutral <see cref="MessageFieldMap"/> the serialization-agnostic <see cref="AcdcReader"/> folds into a typed
/// ACDC; the aggregate-list arm plugs into the same seam as the JSON array arm (<see cref="AcdcAggregateListSerializer"/>).
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#ordered-nested-field-maps">
/// ordered nested field maps</see> and the CESR specification's native <see href="https://trustoverip.github.io/kswg-cesr-specification/#universal-code-table-genusversion-codes-that-do-not-allow-genusversion-override">
/// field-map message body code</see> (<c>-G</c>/<c>--G</c> for a top-level field-map message). A native ACDC message
/// is one <c>-G</c> group whose body is the top-level (label, value) primitive pairs — the version primitive, the
/// message-type tag, the SAIDs and AIDs, and the section values (a SAID, or a nested <c>-I</c> field-map block) —
/// so the generic field-map codec (<see cref="CesrFieldMapCodec"/>) carries every field except the version, which is
/// reconstructed as the in-memory placeholder the specification prescribes (the same way the KERI native decoder
/// reconstructs its version). The aggregate list is written as the count code framing a group of quadlets followed
/// by the fully-qualified primitives; the specification's worked example digests <c>-JAs</c> (a 44-quadlet group).
/// </para>
/// </remarks>
public static class AcdcCesr
{
    /// <summary>
    /// The CESR count code that frames an ACDC aggregate section's blinded attribute list as a group of quadlets,
    /// per the specification's CESR-native aggregate serialization (the leading <c>-J</c> of the group).
    /// </summary>
    private const string AggregateListCountCode = "-J";

    /// <summary>The number of text-domain characters in a CESR quadlet.</summary>
    private const int QuadletCharacters = 4;

    /// <summary>The CESR count code that frames a top-level field-map message body (the ACDC message group).</summary>
    private const string MessageBodyGroupCode = "-G";

    /// <summary>The big field-map message body code, for a body exceeding the small count's capacity.</summary>
    private const string BigMessageBodyGroupCode = "--G";

    /// <summary>The greatest quadlet count a small (four-character) count code can carry before the big code is needed.</summary>
    private const int SmallCountCapacity = (64 * 64) - 1;


    /// <summary>
    /// Serializes a blinded attribute list to its CESR-native bytes: the count code framing the group of quadlets
    /// followed by the concatenated fully-qualified primitives. This is the CESR arm of
    /// <see cref="AcdcAggregateListSerializer"/>, the serialization an aggregate section's AGID is digested over for
    /// a CESR-serialized ACDC.
    /// </summary>
    /// <param name="elements">The list elements in order: the AGID (or its placeholder) followed by the blocks' SAIDs, each a fully-qualified Base64URL CESR primitive.</param>
    /// <param name="output">The buffer the CESR-native bytes are written to.</param>
    /// <exception cref="AcdcException">An element is not a whole number of CESR quadlets, so it is not a well-formed text-domain primitive.</exception>
    /// <exception cref="CesrFormatException">The group's quadlet count exceeds the small count code's capacity.</exception>
    public static void EncodeAggregateList(IReadOnlyList<string> elements, IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(elements);
        ArgumentNullException.ThrowIfNull(output);

        int totalCharacters = 0;
        foreach(string element in elements)
        {
            if(element.Length % QuadletCharacters != 0)
            {
                throw new AcdcException($"An ACDC aggregate list element is {element.Length} characters, not a whole number of CESR quadlets; it is not a well-formed text-domain primitive.");
            }

            totalCharacters += element.Length;
        }

        string countCode = CesrCountCodeCodec.EncodeText(AggregateListCountCode, totalCharacters / QuadletCharacters);

        WriteAscii(countCode, output);
        foreach(string element in elements)
        {
            WriteAscii(element, output);
        }

        static void WriteAscii(string text, IBufferWriter<byte> output)
        {
            Span<byte> destination = output.GetSpan(text.Length);
            int written = Encoding.ASCII.GetBytes(text, destination);
            output.Advance(written);
        }
    }


    /// <summary>
    /// Decodes a CESR-native ACDC message serialization into its neutral field map: the same order-preserving map
    /// the JSON, CBOR, and MGPK arms produce, which <see cref="AcdcReader"/> folds into a typed ACDC.
    /// </summary>
    /// <param name="nativeText">The received native serialization: the qb64 text-domain bytes (ASCII) of the whole <c>-G</c> framed message.</param>
    /// <param name="pool">The memory pool the transient decode buffers are rented from.</param>
    /// <returns>The decoded message field map, preserving field order: scalar fields as strings, section blocks as nested <see cref="MessageFieldMap"/> values, with the version field reconstructed as the in-memory placeholder.</returns>
    /// <exception cref="AcdcException">The bytes are not a single well-formed native field-map message.</exception>
    /// <exception cref="CesrFormatException">A field is not a well-formed CESR-native value.</exception>
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


    //Walks the -G message body: the frame fixes the total size and the body is the top-level (label, value)
    //primitive pairs. Every field decodes through the generic field-map codec except the version, whose primitive
    //carries only the protocol and version and is reconstructed into the in-memory placeholder the spec prescribes.
    private static MessageFieldMap Decode(ReadOnlySpan<char> message, MemoryPool<byte> pool)
    {
        CesrParsedCountCode frame = CesrCountCodeCodec.DecodeText(message);
        if(frame.Code is not (MessageBodyGroupCode or BigMessageBodyGroupCode))
        {
            throw new AcdcException($"A CESR-native ACDC message must be framed by the field-map message body code '{MessageBodyGroupCode}' or '{BigMessageBodyGroupCode}', not '{frame.Code}'.");
        }

        int frameCodeLength = CesrCountCodeTables.SizingForSelector(message[0], message[1]).FullSize;

        //Compare the declared body size in long: a big message-body group's character count can exceed int range,
        //and an int total would overflow to a value that could spuriously equal the message length. The equality
        //against the actual length then bounds it, so the narrowing to int is safe.
        long declaredTotal = frameCodeLength + frame.TextCharCount;
        if(declaredTotal != message.Length)
        {
            throw new AcdcException($"The CESR-native ACDC message frame declares {frame.TextCharCount} body characters but the message has {message.Length - frameCodeLength}.");
        }

        int total = (int)declaredTotal;

        var map = new MessageFieldMap(StringComparer.Ordinal);
        int offset = frameCodeLength;
        while(offset < total)
        {
            string label = CesrFieldMapCodec.DecodeLabel(message[offset..total], pool, out int labelChars);
            offset += labelChars;

            object? value = CesrFieldMapCodec.DecodeValue(message[offset..total], pool, out int valueChars);
            offset += valueChars;

            map[label] = label == AcdcMessageFields.Version && value is string protocolAndVersion
                ? CesrVersionPrimitive.Reconstruct(protocolAndVersion, total)
                : value;
        }

        return map;
    }


    /// <summary>
    /// Encodes an ACDC message's neutral field map into its CESR-native serialization: a <c>-G</c> field-map message
    /// group whose body is the top-level fields in order, the inverse of <see cref="DecodeFieldMap"/>. The version
    /// field's serialization kind and length are dropped from its primitive (the native frame carries the size).
    /// </summary>
    /// <param name="message">The ACDC message field map to encode, in canonical field order.</param>
    /// <param name="pool">The memory pool the transient primitive-classification buffers are rented from.</param>
    /// <param name="output">The buffer the CESR-native qb64 bytes (ASCII) are written to.</param>
    /// <exception cref="AcdcException">The version field is not a well-formed version string.</exception>
    /// <exception cref="CesrFormatException">A field value needs an encoding that is a later slice.</exception>
    public static void EncodeFieldMap(MessageFieldMap message, MemoryPool<byte> pool, IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(output);

        var body = new StringBuilder();
        foreach((string label, object? value) in message)
        {
            body.Append(CesrFieldMapCodec.EncodeLabel(label));

            object? fieldValue = label == AcdcMessageFields.Version && value is string version ? CesrVersionPrimitive.ProtocolAndVersion(version) : value;
            body.Append(CesrFieldMapCodec.EncodeValue(fieldValue, pool));
        }

        string bodyText = body.ToString();
        int quadlets = bodyText.Length / QuadletCharacters;
        string code = quadlets > SmallCountCapacity ? BigMessageBodyGroupCode : MessageBodyGroupCode;
        string qb64 = CesrCountCodeCodec.EncodeText(code, quadlets) + bodyText;

        Span<byte> destination = output.GetSpan(qb64.Length);
        int written = Encoding.ASCII.GetBytes(qb64, destination);
        output.Advance(written);
    }
}
