using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text.Json;
using Verifiable.JCose;
using Verifiable.Json;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared JSON plumbing for Security Event Token tests: the JWT part serializers
/// used at issuance and a <em>faithful</em> part deserializer for the receiving
/// side — strings stay strings (no DateTime coercion), numbers narrow to
/// <see cref="long"/> then <see cref="decimal"/>, nested objects become
/// <see cref="Dictionary{TKey,TValue}"/> and arrays <see cref="List{T}"/>,
/// matching what the SET parser expects.
/// </summary>
internal static class SecurityEventTestJson
{
    internal static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    internal static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);


    internal static Dictionary<string, object>? DeserializePart(ReadOnlySpan<byte> json)
    {
        using JsonDocument document = JsonDocument.Parse(json.ToArray());

        return document.RootElement.ValueKind == JsonValueKind.Object
            ? ConvertObject(document.RootElement)
            : null;
    }


    internal static byte[] DecodeSegment(string segment, MemoryPool<byte> pool)
    {
        using IMemoryOwner<byte> owner = TestSetup.Base64UrlDecoder(segment, pool);

        return owner.Memory.Span.ToArray();
    }


    private static Dictionary<string, object> ConvertObject(JsonElement element)
    {
        var dictionary = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach(JsonProperty property in element.EnumerateObject())
        {
            object? value = ConvertElement(property.Value);
            if(value is not null)
            {
                dictionary[property.Name] = value;
            }
        }

        return dictionary;
    }


    private static object? ConvertElement(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.String => element.GetString(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null => null,
        JsonValueKind.Number => element.TryGetInt64(out long l) ? l : element.GetDecimal(),
        JsonValueKind.Object => ConvertObject(element),
        JsonValueKind.Array => ConvertArray(element),
        _ => null
    };


    private static List<object> ConvertArray(JsonElement element)
    {
        var list = new List<object>();
        foreach(JsonElement item in element.EnumerateArray())
        {
            object? value = ConvertElement(item);
            if(value is not null)
            {
                list.Add(value);
            }
        }

        return list;
    }
}
