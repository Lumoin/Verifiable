using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text.Encodings.Web;
using System.Text.Json;
using Verifiable.Cryptography;

namespace Verifiable.Json;

/// <summary>
/// Decodes a JSON-serialized ACDC body into the neutral field map that the serialization-agnostic ACDC reader (in
/// <c>Verifiable.Acdc</c>) folds into a typed ACDC. The bytes-to-field-map decode is the per-serialization seam;
/// this is the JSON arm of it. The decoder produces only Base Class Library types — the order-preserving
/// <see cref="MessageFieldMap"/> for every object (including nested section blocks) and a list of objects for every
/// array — so <c>Verifiable.Acdc</c> consumes the result without a code dependency on this serializer leaf, exactly
/// as <c>Verifiable.Core</c> is firewalled from a JSON serializer.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#ordered-nested-field-maps">
/// ordered nested field maps</see>: an ACDC is a nested set of field maps whose canonical serialization is
/// insertion-ordered, and a section value is either a SAID string (compact) or a nested field map (expanded). Unlike
/// a KERI key event, whose only nesting is the data-plane seal list, an ACDC nests SAIDed blocks at every level, so
/// this decodes every nested object as an order-preserving <see cref="MessageFieldMap"/> — the field order a
/// section's SAID is taken over. The objects and arrays are materialized iteratively with an explicit work stack,
/// not by recursion, so the decode uses bounded call-stack space regardless of how deeply the input nests, and the
/// parse depth is bounded independently as a defense against adversarial input.
/// </para>
/// </remarks>
public static class AcdcJson
{
    /// <summary>
    /// The parse options bound the JSON nesting depth, defending against adversarial input independently of the
    /// iterative materialization, matching the depth bound the other readers in this leaf apply.
    /// </summary>
    private static readonly JsonDocumentOptions ParseOptions = new() { MaxDepth = 32 };

    /// <summary>
    /// The writer options that produce the ACDC canonical serialization: compact (no inter-token whitespace) and
    /// the relaxed escaping that escapes only the JSON-required characters, leaving the rest as UTF-8, so the
    /// output matches the specification's serialization (which is produced without ASCII-escaping).
    /// </summary>
    private static readonly JsonWriterOptions WriterOptions = new() { Indented = false, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };


    /// <summary>
    /// Decodes a JSON-serialized ACDC body into its neutral field map.
    /// </summary>
    /// <param name="utf8Json">The UTF-8 JSON bytes of a single ACDC body (the whole serialization).</param>
    /// <returns>The decoded field map, preserving the fields' serialization order at every level: scalars as strings, numbers, or booleans, nested objects as <see cref="MessageFieldMap"/>, and arrays as lists of objects, keyed by the field label.</returns>
    /// <exception cref="JsonException">The bytes are not a JSON object.</exception>
    public static MessageFieldMap DecodeFieldMap(ReadOnlyMemory<byte> utf8Json)
    {
        using JsonDocument document = JsonDocument.Parse(utf8Json, ParseOptions);
        if(document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("An ACDC body MUST be a JSON object.");
        }

        var root = new MessageFieldMap(StringComparer.Ordinal);

        var stack = new Stack<Frame>();
        stack.Push(new Frame(document.RootElement, root));

        while(stack.Count > 0)
        {
            Frame frame = stack.Peek();
            if(!frame.TryGetNext(out string? name, out JsonElement value))
            {
                stack.Pop();
                continue;
            }

            if(value.ValueKind is JsonValueKind.Object or JsonValueKind.Array)
            {
                object child = NewContainer(value.ValueKind);
                frame.Add(name, child);
                stack.Push(new Frame(value, child));
            }
            else
            {
                frame.Add(name, ConvertScalar(value));
            }
        }

        return root;

        static object NewContainer(JsonValueKind kind) =>
            kind == JsonValueKind.Object ? new MessageFieldMap(StringComparer.Ordinal) : new List<object?>();

        static object? ConvertScalar(JsonElement element) => element.ValueKind switch
        {
            JsonValueKind.String => element.GetString(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null,
            JsonValueKind.Number => JsonElementConversion.NarrowNumber(element),
            _ => throw new NotSupportedException($"Unsupported JSON value kind: {element.ValueKind}.")
        };
    }


    /// <summary>
    /// Encodes a field map into its ACDC canonical JSON serialization: compact, with the fields in the map's
    /// insertion order at every level, the form an ACDC's SAID is taken over. The inverse of
    /// <see cref="DecodeFieldMap(ReadOnlyMemory{byte})"/>.
    /// </summary>
    /// <param name="map">The field map to encode, whose nested objects are <see cref="MessageFieldMap"/> and whose arrays are lists of objects, as the decode produces.</param>
    /// <param name="output">The buffer the UTF-8 JSON bytes are written to.</param>
    /// <exception cref="System.NotSupportedException">A scalar value is of a type the ACDC neutral map does not use.</exception>
    public static void Encode(MessageFieldMap map, IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(map);
        ArgumentNullException.ThrowIfNull(output);

        using var writer = new Utf8JsonWriter(output, WriterOptions);

        writer.WriteStartObject();

        var stack = new Stack<EncodeFrame>();
        stack.Push(EncodeFrame.ForObject(map));

        while(stack.Count > 0)
        {
            EncodeFrame frame = stack.Peek();
            if(!frame.TryGetNext(out string? name, out object? value))
            {
                if(frame.IsObject)
                {
                    writer.WriteEndObject();
                }
                else
                {
                    writer.WriteEndArray();
                }

                stack.Pop();
                continue;
            }

            if(name is not null)
            {
                writer.WritePropertyName(name);
            }

            //A container value writes its opening token and yields a frame to descend into; a scalar writes its
            //value and yields no frame. The discriminated result is what the loop pushes (or does not).
            EncodeFrame? child = value switch
            {
                MessageFieldMap nested => StartObject(writer, nested),
                List<object?> list => StartArray(writer, list),
                null => WriteNull(writer),
                string text => WriteString(writer, text),
                bool boolean => WriteBoolean(writer, boolean),
                int integer => WriteWhole(writer, integer),
                long wide => WriteWhole(writer, wide),
                decimal exact => WriteFraction(writer, exact),
                _ => throw new NotSupportedException($"Unsupported scalar value type in an ACDC field map: {value?.GetType()}.")
            };

            if(child is not null)
            {
                stack.Push(child);
            }
        }

        writer.Flush();

        static EncodeFrame StartObject(Utf8JsonWriter writer, MessageFieldMap nested)
        {
            writer.WriteStartObject();
            return EncodeFrame.ForObject(nested);
        }

        static EncodeFrame StartArray(Utf8JsonWriter writer, List<object?> list)
        {
            writer.WriteStartArray();
            return EncodeFrame.ForArray(list);
        }

        static EncodeFrame? WriteNull(Utf8JsonWriter writer)
        {
            writer.WriteNullValue();
            return null;
        }

        static EncodeFrame? WriteString(Utf8JsonWriter writer, string value)
        {
            writer.WriteStringValue(value);
            return null;
        }

        static EncodeFrame? WriteBoolean(Utf8JsonWriter writer, bool value)
        {
            writer.WriteBooleanValue(value);
            return null;
        }

        static EncodeFrame? WriteWhole(Utf8JsonWriter writer, long value)
        {
            writer.WriteNumberValue(value);
            return null;
        }

        static EncodeFrame? WriteFraction(Utf8JsonWriter writer, decimal value)
        {
            writer.WriteNumberValue(value);
            return null;
        }
    }


    /// <summary>
    /// Encodes a flat list of strings into its ACDC canonical JSON array serialization: compact, in order, the form
    /// an aggregate section's AGID is taken over. This is the JSON arm of the aggregate-list serialization seam,
    /// distinct from <see cref="Encode(MessageFieldMap, IBufferWriter{byte})"/> because the AGID is digested over a
    /// JSON array of the blocks' SAIDs, not over a field map.
    /// </summary>
    /// <param name="elements">The list elements in order: the AGID (or its placeholder) followed by the blocks' SAIDs.</param>
    /// <param name="output">The buffer the UTF-8 JSON bytes are written to.</param>
    public static void EncodeAggregateList(IReadOnlyList<string> elements, IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(elements);
        ArgumentNullException.ThrowIfNull(output);

        using var writer = new Utf8JsonWriter(output, WriterOptions);

        writer.WriteStartArray();
        foreach(string element in elements)
        {
            writer.WriteStringValue(element);
        }

        writer.WriteEndArray();
        writer.Flush();
    }


    //A mutable work item: the container being filled plus the (struct) enumerator over its source children. Held
    //as a class so the enumerator mutates in place across Stack.Peek() calls — a struct frame would be copied and
    //lose enumerator progress.
    private sealed class Frame
    {
        private readonly object container;
        private readonly bool isObject;
        private JsonElement.ObjectEnumerator objectEnumerator;
        private JsonElement.ArrayEnumerator arrayEnumerator;

        public Frame(JsonElement element, object container)
        {
            this.container = container;
            isObject = element.ValueKind == JsonValueKind.Object;
            if(isObject)
            {
                objectEnumerator = element.EnumerateObject();
            }
            else
            {
                arrayEnumerator = element.EnumerateArray();
            }
        }


        public bool TryGetNext(out string? name, out JsonElement value)
        {
            if(isObject)
            {
                if(objectEnumerator.MoveNext())
                {
                    JsonProperty property = objectEnumerator.Current;
                    name = property.Name;
                    value = property.Value;

                    return true;
                }
            }
            else if(arrayEnumerator.MoveNext())
            {
                name = null;
                value = arrayEnumerator.Current;

                return true;
            }

            name = null;
            value = default;

            return false;
        }


        public void Add(string? name, object? value)
        {
            if(isObject)
            {
                ((MessageFieldMap)container)[name!] = value;
            }
            else
            {
                ((List<object?>)container).Add(value);
            }
        }
    }


    //A mutable work item for the encode walk: the (struct) enumerator over an object's fields or an array's
    //elements. Held as a class so the enumerator mutates in place across Stack.Peek() calls.
    private sealed class EncodeFrame
    {
        private readonly bool isObject;
        private OrderedDictionary<string, object?>.Enumerator objectEnumerator;
        private List<object?>.Enumerator arrayEnumerator;

        private EncodeFrame(MessageFieldMap map)
        {
            isObject = true;
            objectEnumerator = map.GetEnumerator();
        }


        private EncodeFrame(List<object?> list)
        {
            isObject = false;
            arrayEnumerator = list.GetEnumerator();
        }


        public bool IsObject => isObject;


        public static EncodeFrame ForObject(MessageFieldMap map) => new(map);


        public static EncodeFrame ForArray(List<object?> list) => new(list);


        public bool TryGetNext(out string? name, out object? value)
        {
            if(isObject)
            {
                if(objectEnumerator.MoveNext())
                {
                    name = objectEnumerator.Current.Key;
                    value = objectEnumerator.Current.Value;

                    return true;
                }
            }
            else if(arrayEnumerator.MoveNext())
            {
                name = null;
                value = arrayEnumerator.Current;

                return true;
            }

            name = null;
            value = default;

            return false;
        }
    }
}
