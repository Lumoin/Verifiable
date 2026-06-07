using System;
using System.Collections.Generic;
using System.Text.Json;
using Verifiable.Core.Model.DataIntegrity;

namespace Verifiable.Json.Converters;

/// <summary>
/// Member (de)serialization helpers shared by <see cref="VerifiableCredentialConverter"/> and
/// <see cref="VerifiablePresentationConverter"/>. Complex member values delegate to the
/// converters already registered on the options via
/// <see cref="JsonSerializerOptions.GetTypeInfo"/>, so the wire shape stays identical to the
/// source-generated path the hand-written converters replace.
/// </summary>
internal static class CredentialConverterShared
{
    //Deserializes a member value through the options' registered converters and source-gen
    //metadata. Returns the type default for a JSON null.
    internal static T? Deserialize<T>(JsonElement element, JsonSerializerOptions options)
    {
        if(element.ValueKind == JsonValueKind.Null)
        {
            return default;
        }

        return (T?)JsonSerializer.Deserialize(element, options.GetTypeInfo(typeof(T)));
    }


    //Serializes a member value through the options' registered converters and source-gen
    //metadata. The writer must already be positioned after WritePropertyName.
    internal static void WriteMember(Utf8JsonWriter writer, Type memberType, object value, JsonSerializerOptions options)
    {
        JsonSerializer.Serialize(writer, value, options.GetTypeInfo(memberType));
    }


    //Reads a "proof" member, which Data Integrity allows as either a single proof object or an
    //array of proofs (a proof chain). Both forms normalize to an ordered list.
    internal static List<DataIntegrityProof>? ReadProofs(JsonElement element, JsonSerializerOptions options)
    {
        if(element.ValueKind == JsonValueKind.Array)
        {
            return Deserialize<List<DataIntegrityProof>>(element, options);
        }

        if(element.ValueKind == JsonValueKind.Object)
        {
            var single = Deserialize<DataIntegrityProof>(element, options);
            return single is null ? null : [single];
        }

        return null;
    }


    //Reads a "type" member, normally a JSON array of strings but tolerant of a single string
    //per JSON-LD. Primitive arrays are read manually, matching the convention in this assembly.
    internal static List<string>? ReadStringList(JsonElement element)
    {
        if(element.ValueKind == JsonValueKind.String)
        {
            var single = element.GetString();
            return single is null ? null : [single];
        }

        if(element.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var list = new List<string>();
        foreach(var item in element.EnumerateArray())
        {
            var value = item.GetString();
            if(value is not null)
            {
                list.Add(value);
            }
        }

        return list;
    }


    //Writes a list of strings as a JSON array property.
    internal static void WriteStringList(Utf8JsonWriter writer, string propertyName, List<string> values)
    {
        writer.WriteStartArray(propertyName);
        for(int i = 0; i < values.Count; ++i)
        {
            writer.WriteStringValue(values[i]);
        }

        writer.WriteEndArray();
    }
}
