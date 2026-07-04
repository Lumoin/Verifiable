using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Cryptography;

namespace Verifiable.Cbor;

/// <summary>
/// Decodes a CBOR-serialized KERI message body into the neutral field map that the serialization-agnostic KERI
/// event reader (in <c>Verifiable.Keri</c>) folds into a typed key event. The bytes-to-field-map decode is the
/// per-serialization seam; this is the CBOR arm of it, the sibling of the JSON arm in <c>Verifiable.Json</c>. The
/// decoder produces only Base Class Library types (a dictionary of strings to objects, with the key-state list
/// fields as string lists), so <c>Verifiable.Keri</c> consumes the result without a code dependency on this
/// serializer leaf, exactly as <c>Verifiable.Core</c> is firewalled from a CBOR serializer.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#performant-resynchronization">
/// requirement that a conformant parser support the JSON, CBOR, and MGPK serializations</see> of a field map. A
/// KERI key event CBOR body is a map with text-string keys whose scalar fields (including the sequence number
/// <c>s</c>, a hexadecimal text string) are text strings and whose key-state list fields (<c>k</c>, <c>n</c>,
/// <c>b</c>, <c>br</c>, <c>ba</c>, <c>c</c>) are arrays of text strings; the anchored seals (<c>a</c>) are the
/// data plane and may be an array of maps. The neutral-map conventions the reader requires are therefore: a scalar
/// is a <see cref="string"/> and a homogeneous text-string array is an <see cref="IReadOnlyList{T}"/> of
/// <see cref="string"/>; any other array (or a nested map) is read through the general value conversion so the
/// data plane is preserved without being interpreted here.
/// </para>
/// </remarks>
public static class KeriEventCbor
{
    /// <summary>
    /// Decodes a CBOR-serialized KERI message body into its neutral field map.
    /// </summary>
    /// <param name="cbor">The CBOR bytes of a single KERI message body (the whole event serialization).</param>
    /// <returns>The decoded message field map, preserving the fields' serialization order: scalar fields as strings, key-state list fields as string lists, keyed by the message field label.</returns>
    /// <exception cref="CborContentException">The bytes are not a CBOR map.</exception>
    public static MessageFieldMap DecodeFieldMap(ReadOnlyMemory<byte> cbor)
    {
        var reader = new CborReader(cbor);
        if(reader.PeekState() != CborReaderState.StartMap)
        {
            throw new CborContentException("A KERI message body MUST be a CBOR map.");
        }

        int? length = reader.ReadStartMap();
        var map = new MessageFieldMap(length ?? 16, StringComparer.Ordinal);
        while(reader.PeekState() != CborReaderState.EndMap)
        {
            string key = reader.ReadTextString();
            map[key] = ReadField(reader);
        }

        reader.ReadEndMap();

        return map;
    }


    //A homogeneous array of text strings becomes a typed string list, the neutral-map convention the reader's
    //list fields require; every other value (scalars, the anchored-seal array, a nested map) reads through the
    //general value conversion so the data plane survives without being interpreted here.
    private static object? ReadField(CborReader reader)
    {
        if(reader.PeekState() != CborReaderState.StartArray)
        {
            return CborValueConverter.ReadValue(reader);
        }

        int? count = reader.ReadStartArray();
        var items = new List<object?>(count ?? 4);
        while(reader.PeekState() != CborReaderState.EndArray)
        {
            items.Add(CborValueConverter.ReadValue(reader));
        }

        reader.ReadEndArray();

        return AsStringListOrGeneral(items);
    }


    private static object AsStringListOrGeneral(List<object?> items)
    {
        var strings = new List<string>(items.Count);
        foreach(object? item in items)
        {
            if(item is not string text)
            {
                return items;
            }

            strings.Add(text);
        }

        return strings;
    }
}
