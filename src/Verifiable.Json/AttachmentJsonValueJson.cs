using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text.Json;
using Verifiable.DidComm;
using Verifiable.Foundation;
using Verifiable.Json.Converters;

namespace Verifiable.Json;

/// <summary>
/// The concrete JSON implementation of the DIDComm <see cref="JsonValueSerializer"/> seam — it
/// serializes an attachment <c>data.json</c> value (the directly embedded JSON content, DIDComm
/// Messaging v2.1 §Attachments) to pooled UTF-8 bytes.
/// </summary>
/// <remarks>
/// <para>
/// The <c>Verifiable.DidComm</c> attachment resolver is serialization-agnostic and receives this as a
/// delegate, exactly as the pack/unpack pipeline receives <see cref="DidCommMessageSerializer"/>; this
/// leaf package is the only place the <see cref="System.Text.Json"/> machinery touches a json
/// attachment value. An embedded JSON value is a <see cref="Dictionary{TKey, TValue}"/> of
/// <see cref="string"/> to <see cref="object"/> (the object graph the plaintext parser produces), so
/// the shared <see cref="DictionaryStringObjectJsonConverter"/> writes its graph — the same converter
/// the DIDComm message envelope uses.
/// </para>
/// </remarks>
public static class AttachmentJsonValueJson
{
    /// <summary>
    /// The serialization options the attachment-json serializer uses: the source-generated
    /// <see cref="VerifiableJsonContext"/> resolver plus the
    /// <see cref="DictionaryStringObjectJsonConverter"/> for the embedded JSON object graph.
    /// </summary>
    public static JsonSerializerOptions Options { get; } = CreateOptions();


    /// <summary>
    /// The <see cref="JsonValueSerializer"/> that serializes a <c>data.json</c> value to an owned buffer
    /// holding its UTF-8 JSON bytes, drawn from the supplied pool.
    /// </summary>
    public static JsonValueSerializer Serializer { get; } = Serialize;


    //Serializes the embedded JSON value into an owned, exact-length pooled buffer. A System.Text.Json
    //serialization failure is translated into the framework-neutral FormatException so no STJ type escapes
    //this leaf into Verifiable.DidComm; the resolver maps that to MalformedInline.
    private static IMemoryOwner<byte> Serialize(object jsonValue, MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(jsonValue);
        ArgumentNullException.ThrowIfNull(memoryPool);

        byte[] utf8;
        try
        {
            utf8 = WriteValue(jsonValue);
        }
        catch(JsonException exception)
        {
            throw new FormatException("The attachment data.json value is not serializable JSON.", exception);
        }

        IMemoryOwner<byte> owner = memoryPool.Rent(utf8.Length);
        utf8.AsSpan().CopyTo(owner.Memory.Span);

        return owner;
    }


    //Serializes the value's object graph to UTF-8 JSON. An object value goes through the registered
    //Dictionary<string, object> path (the DictionaryStringObjectJsonConverter); any other shape is written
    //through a Utf8JsonWriter wrapped in a single-member object the same converter renders, then unwrapped is
    //not needed because the spec's data.json is "natively conveyable as JSON" content, in practice an object.
    private static byte[] WriteValue(object jsonValue)
    {
        if(jsonValue is Dictionary<string, object> objectGraph)
        {
            return JsonSerializerExtensions.SerializeToUtf8Bytes(objectGraph, Options);
        }

        //A non-object embedded JSON value (an array or a primitive) is written directly through a writer that
        //reuses the converter for nested objects. The converter's value-writing is internal, so the top-level
        //array/primitive is written here and any nested object delegates to the registered converter.
        var buffer = new System.Buffers.ArrayBufferWriter<byte>();
        using(var writer = new Utf8JsonWriter(buffer))
        {
            WriteJsonValue(writer, jsonValue);
        }

        return buffer.WrittenSpan.ToArray();
    }


    //Writes a single embedded JSON value (object, array, or primitive) to the writer. An object delegates to
    //the registered Dictionary<string, object> converter via the options; arrays and primitives are written
    //element-by-element. Mirrors the value cases the DictionaryStringObjectJsonConverter handles.
    private static void WriteJsonValue(Utf8JsonWriter writer, object? value)
    {
        switch(value)
        {
            case null:
            {
                writer.WriteNullValue();
                break;
            }
            case Dictionary<string, object> objectGraph:
            {
                JsonSerializer.Serialize(writer, objectGraph, (System.Text.Json.Serialization.Metadata.JsonTypeInfo<Dictionary<string, object>>)Options.GetTypeInfo(typeof(Dictionary<string, object>)));
                break;
            }
            case string text:
            {
                writer.WriteStringValue(text);
                break;
            }
            case bool boolean:
            {
                writer.WriteBooleanValue(boolean);
                break;
            }
            case int integer:
            {
                writer.WriteNumberValue(integer);
                break;
            }
            case long longValue:
            {
                writer.WriteNumberValue(longValue);
                break;
            }
            case double doubleValue:
            {
                writer.WriteNumberValue(doubleValue);
                break;
            }
            case decimal decimalValue:
            {
                writer.WriteNumberValue(decimalValue);
                break;
            }
            case IEnumerable<object> items:
            {
                writer.WriteStartArray();
                foreach(object? item in items)
                {
                    WriteJsonValue(writer, item);
                }

                writer.WriteEndArray();
                break;
            }
            default:
            {
                throw new JsonException($"Token of type '{value.GetType()}' is not a serializable attachment json value.");
            }
        }
    }


    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            TypeInfoResolver = VerifiableJsonContext.Default
        };

        options.Converters.Add(new DictionaryStringObjectJsonConverter(VerifiableJsonContext.Default));

        return options;
    }
}
