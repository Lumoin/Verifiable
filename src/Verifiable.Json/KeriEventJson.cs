using System;
using System.Collections.Generic;
using System.Text.Json;
using Verifiable.Cryptography;

namespace Verifiable.Json;

/// <summary>
/// Decodes a JSON-serialized KERI message body into the neutral field map that the serialization-agnostic KERI
/// event reader (in <c>Verifiable.Keri</c>) folds into a typed key event. The bytes-to-field-map decode is the
/// per-serialization seam; this is the JSON arm of it. The decoder produces only Base Class Library types
/// (a dictionary of strings to objects, with list fields as string lists), so <c>Verifiable.Keri</c> consumes the
/// result without a code dependency on this serializer leaf, exactly as <c>Verifiable.Core</c> is firewalled from
/// a JSON serializer.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#performant-resynchronization">
/// requirement that a conformant parser support the JSON, CBOR, and MGPK serializations</see> of a field map. A
/// KERI key event JSON body is a flat object whose scalar fields (including the sequence number <c>s</c>, a
/// hexadecimal string) are JSON strings and whose key-state list fields (<c>k</c>, <c>n</c>, <c>b</c>, <c>br</c>,
/// <c>ba</c>, <c>c</c>) are JSON arrays of strings; the anchored seals (<c>a</c>) are the data plane and may be an
/// array of objects. The neutral-map conventions the reader requires are therefore: a scalar is a
/// <see cref="string"/> (numbers and booleans pass through for completeness) and a homogeneous string array is an
/// <see cref="IReadOnlyList{T}"/> of <see cref="string"/>; any other array (or a nested object) converts through
/// the general element conversion so the data plane is preserved without being interpreted here.
/// </para>
/// </remarks>
public static class KeriEventJson
{
    /// <summary>
    /// The parse options bound the JSON nesting depth, defending against adversarial input independently of the
    /// iterative conversion, matching the depth bound the other readers in this leaf apply.
    /// </summary>
    private static readonly JsonDocumentOptions ParseOptions = new() { MaxDepth = 32 };


    /// <summary>
    /// Decodes a JSON-serialized KERI message body into its neutral field map.
    /// </summary>
    /// <param name="utf8Json">The UTF-8 JSON bytes of a single KERI message body (the whole event serialization).</param>
    /// <returns>The decoded message field map, preserving the fields' serialization order: scalar fields as strings, key-state list fields as string lists, keyed by the message field label.</returns>
    /// <exception cref="JsonException">The bytes are not a JSON object.</exception>
    public static MessageFieldMap DecodeFieldMap(ReadOnlyMemory<byte> utf8Json)
    {
        using JsonDocument document = JsonDocument.Parse(utf8Json, ParseOptions);
        if(document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("A KERI message body MUST be a JSON object.");
        }

        var map = new MessageFieldMap(StringComparer.Ordinal);
        foreach(JsonProperty field in document.RootElement.EnumerateObject())
        {
            map[field.Name] = ConvertField(field.Value);
        }

        return map;
    }


    //A homogeneous array of strings becomes a typed string list, the neutral-map convention the reader's list
    //fields require; every other value (scalars, the anchored-seal array, a nested object) converts through the
    //general iterative element conversion so the data plane survives without being interpreted here.
    private static object? ConvertField(JsonElement value)
    {
        if(value.ValueKind == JsonValueKind.Array && TryConvertStringList(value, out List<string>? strings))
        {
            return strings;
        }

        return JsonElementConversion.Convert(value);
    }


    private static bool TryConvertStringList(JsonElement array, out List<string>? strings)
    {
        var list = new List<string>(array.GetArrayLength());
        foreach(JsonElement element in array.EnumerateArray())
        {
            if(element.ValueKind != JsonValueKind.String)
            {
                strings = null;

                return false;
            }

            list.Add(element.GetString()!);
        }

        strings = list;

        return true;
    }
}
