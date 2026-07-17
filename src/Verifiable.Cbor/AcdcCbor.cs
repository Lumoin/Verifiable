using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Cryptography;

namespace Verifiable.Cbor;

/// <summary>
/// The CBOR serialization arm for ACDC field maps: decodes a CBOR-serialized ACDC body into the neutral
/// <see cref="MessageFieldMap"/> the serialization-agnostic ACDC reader folds, and encodes a field map back to its
/// canonical CBOR. The sibling of the JSON arm in <c>Verifiable.Json</c>; it produces and consumes only Base Class
/// Library types, so <c>Verifiable.Acdc</c> stays firewalled from this serializer leaf.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#performant-resynchronization">
/// requirement that a conformant parser support the JSON, CBOR, and MGPK serializations</see> of a field map, and
/// the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#ordered-nested-field-maps">
/// ordered nested field maps</see>. An ACDC nests SAIDed blocks at every level, so every nested map decodes as an
/// order-preserving <see cref="MessageFieldMap"/> — the field order a section's SAID is taken over — and the encode
/// writes definite-length maps in the field map's insertion order (not the canonical sorting of CBOR's canonical
/// conformance modes). The maps and arrays are walked iteratively with an explicit stack, not by recursion.
/// </para>
/// </remarks>
public static class AcdcCbor
{
    /// <summary>
    /// Decodes a CBOR-serialized ACDC body into its neutral field map.
    /// </summary>
    /// <param name="cbor">The CBOR bytes of a single ACDC body (the whole serialization).</param>
    /// <returns>The decoded field map, preserving the fields' serialization order at every level: scalars as strings, numbers, or booleans, nested maps as <see cref="MessageFieldMap"/>, and arrays as lists of objects, keyed by the field label.</returns>
    /// <exception cref="CborContentException">The bytes are not a CBOR map, or carry a value an ACDC field map does not use.</exception>
    public static MessageFieldMap DecodeFieldMap(ReadOnlyMemory<byte> cbor)
    {
        var reader = new CborReader(cbor);
        if(reader.PeekState() != CborReaderState.StartMap)
        {
            throw new CborContentException("An ACDC body MUST be a CBOR map.");
        }

        reader.ReadStartMap();
        var root = new MessageFieldMap(StringComparer.Ordinal);

        var stack = new Stack<DecodeFrame>();
        stack.Push(DecodeFrame.ForMap(root));

        while(stack.Count > 0)
        {
            DecodeFrame frame = stack.Peek();
            if(frame.IsMap ? reader.PeekState() == CborReaderState.EndMap : reader.PeekState() == CborReaderState.EndArray)
            {
                if(frame.IsMap)
                {
                    reader.ReadEndMap();
                }
                else
                {
                    reader.ReadEndArray();
                }

                stack.Pop();
                continue;
            }

            string? key = frame.IsMap ? reader.ReadTextString() : null;

            DecodeFrame? child = reader.PeekState() switch
            {
                CborReaderState.StartMap => BeginMap(reader, frame, key),
                CborReaderState.StartArray => BeginArray(reader, frame, key),
                _ => AddScalar(reader, frame, key)
            };

            if(child is not null)
            {
                stack.Push(child);
            }
        }

        return root;

        static DecodeFrame BeginMap(CborReader reader, DecodeFrame parent, string? key)
        {
            reader.ReadStartMap();
            var child = new MessageFieldMap(StringComparer.Ordinal);
            parent.Add(key, child);

            return DecodeFrame.ForMap(child);
        }

        static DecodeFrame BeginArray(CborReader reader, DecodeFrame parent, string? key)
        {
            reader.ReadStartArray();
            var child = new List<object?>();
            parent.Add(key, child);

            return DecodeFrame.ForArray(child);
        }

        static DecodeFrame? AddScalar(CborReader reader, DecodeFrame parent, string? key)
        {
            parent.Add(key, ReadScalar(reader));

            return null;
        }

        static object? ReadScalar(CborReader reader) => reader.PeekState() switch
        {
            CborReaderState.TextString => reader.ReadTextString(),
            CborReaderState.UnsignedInteger => Narrow(reader.ReadInt64()),
            CborReaderState.NegativeInteger => Narrow(reader.ReadInt64()),
            CborReaderState.Boolean => reader.ReadBoolean(),
            CborReaderState.Null => ReadNull(reader),
            _ => throw new CborContentException($"Unsupported CBOR value in an ACDC field map: {reader.PeekState()}.")
        };

        static object Narrow(long value) => value >= int.MinValue && value <= int.MaxValue ? (int)value : value;

        static object? ReadNull(CborReader reader)
        {
            reader.ReadNull();

            return null;
        }
    }


    /// <summary>
    /// Encodes a field map into its canonical CBOR serialization: definite-length maps with the fields in the map's
    /// insertion order at every level. The inverse of <see cref="DecodeFieldMap(ReadOnlyMemory{byte})"/>.
    /// </summary>
    /// <param name="map">The field map to encode, whose nested maps are <see cref="MessageFieldMap"/> and whose arrays are lists of objects, as the decode produces.</param>
    /// <param name="output">The buffer the CBOR bytes are written to.</param>
    /// <exception cref="NotSupportedException">A scalar value is of a type the ACDC neutral map does not use.</exception>
    public static void Encode(MessageFieldMap map, IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(map);
        ArgumentNullException.ThrowIfNull(output);

        var writer = new CborWriter();

        writer.WriteStartMap(map.Count);

        var stack = new Stack<EncodeFrame>();
        stack.Push(EncodeFrame.ForMap(map));

        while(stack.Count > 0)
        {
            EncodeFrame frame = stack.Peek();
            if(!frame.TryGetNext(out string? name, out object? value))
            {
                if(frame.IsMap)
                {
                    writer.WriteEndMap();
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
                writer.WriteTextString(name);
            }

            EncodeFrame? child = value switch
            {
                MessageFieldMap nested => StartMap(writer, nested),
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

        Span<byte> destination = output.GetSpan(writer.BytesWritten);
        output.Advance(writer.Encode(destination));

        static EncodeFrame StartMap(CborWriter writer, MessageFieldMap nested)
        {
            writer.WriteStartMap(nested.Count);
            return EncodeFrame.ForMap(nested);
        }

        static EncodeFrame StartArray(CborWriter writer, List<object?> list)
        {
            writer.WriteStartArray(list.Count);
            return EncodeFrame.ForArray(list);
        }

        static EncodeFrame? WriteNull(CborWriter writer)
        {
            writer.WriteNull();
            return null;
        }

        static EncodeFrame? WriteString(CborWriter writer, string value)
        {
            writer.WriteTextString(value);
            return null;
        }

        static EncodeFrame? WriteBoolean(CborWriter writer, bool value)
        {
            writer.WriteBoolean(value);
            return null;
        }

        static EncodeFrame? WriteWhole(CborWriter writer, long value)
        {
            writer.WriteInt64(value);
            return null;
        }

        static EncodeFrame? WriteFraction(CborWriter writer, decimal value)
        {
            writer.WriteDecimal(value);
            return null;
        }
    }


    //A decode work item: the container being filled and whether it is a map (so the end token and the key reads
    //are chosen correctly). The reader itself is the cursor, so the frame holds no enumerator.
    private sealed class DecodeFrame
    {
        private object Container { get; }

        private DecodeFrame(object container, bool isMap)
        {
            this.Container = container;
            IsMap = isMap;
        }


        public bool IsMap { get; }


        public static DecodeFrame ForMap(MessageFieldMap map) => new(map, true);


        public static DecodeFrame ForArray(List<object?> list) => new(list, false);


        public void Add(string? key, object? value)
        {
            if(IsMap)
            {
                ((MessageFieldMap)Container)[key!] = value;
            }
            else
            {
                ((List<object?>)Container).Add(value);
            }
        }
    }


    //An encode work item: the (struct) enumerator over a map's fields or an array's elements. Held as a class so
    //the enumerator mutates in place across Stack.Peek() calls.
    private sealed class EncodeFrame
    {
        private OrderedDictionary<string, object?>.Enumerator mapEnumerator;
        private List<object?>.Enumerator arrayEnumerator;

        private EncodeFrame(MessageFieldMap map)
        {
            IsMap = true;
            mapEnumerator = map.GetEnumerator();
        }


        private EncodeFrame(List<object?> list)
        {
            IsMap = false;
            arrayEnumerator = list.GetEnumerator();
        }


        public bool IsMap { get; }


        public static EncodeFrame ForMap(MessageFieldMap map) => new(map);


        public static EncodeFrame ForArray(List<object?> list) => new(list);


        public bool TryGetNext(out string? name, out object? value)
        {
            if(IsMap)
            {
                if(mapEnumerator.MoveNext())
                {
                    name = mapEnumerator.Current.Key;
                    value = mapEnumerator.Current.Value;

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
