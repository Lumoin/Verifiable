using System.Diagnostics.CodeAnalysis;
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
    /// <summary>
    /// Deserializes a member value through the options' registered converters and source-generated
    /// metadata. Returns the type default for a JSON null.
    /// </summary>
    /// <typeparam name="T">The member's declared type.</typeparam>
    /// <param name="element">The member's JSON element.</param>
    /// <param name="options">The serializer options carrying the registered converters.</param>
    internal static T? Deserialize<T>(JsonElement element, JsonSerializerOptions options)
    {
        if(element.ValueKind == JsonValueKind.Null)
        {
            return default;
        }

        return element.Deserialize(options.GetTypeInfo<T>());
    }


    /// <summary>
    /// Serializes a member value through the options' registered converters and source-generated
    /// metadata. The writer must already be positioned after <c>WritePropertyName</c>.
    /// </summary>
    /// <remarks>
    /// <paramref name="memberType"/> is resolved at runtime because the member's declared type varies
    /// by call site, so the generic <see cref="JsonSerializerOptions.GetTypeInfo"/> overload that
    /// CA2263 prefers cannot apply here.
    /// </remarks>
    /// <param name="writer">The writer, positioned after the property name.</param>
    /// <param name="memberType">The member's declared type.</param>
    /// <param name="value">The member value.</param>
    /// <param name="options">The serializer options carrying the registered converters.</param>
    [SuppressMessage("Performance", "CA2263:Prefer generic overload when type is known", Justification = "memberType is a runtime Type parameter, not a compile-time type; no generic overload is possible.")]
    internal static void WriteMember(Utf8JsonWriter writer, Type memberType, object value, JsonSerializerOptions options)
    {
        JsonSerializer.Serialize(writer, value, options.GetTypeInfo(memberType));
    }


    /// <summary>
    /// Reads a <c>proof</c> member, which Data Integrity allows as either a single proof object or
    /// an array of proofs (a proof chain). Both forms normalize to an ordered list.
    /// </summary>
    /// <param name="element">The member's JSON element.</param>
    /// <param name="options">The serializer options carrying the registered converters.</param>
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


    /// <summary>
    /// Reads a <c>type</c> member, normally a JSON array of strings but tolerant of a single string
    /// per JSON-LD. Primitive arrays are read manually, matching the convention in this assembly.
    /// </summary>
    /// <param name="element">The member's JSON element.</param>
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


    /// <summary>
    /// Writes a list of strings as a JSON array property.
    /// </summary>
    /// <param name="writer">The writer, positioned inside the parent object.</param>
    /// <param name="propertyName">The property name.</param>
    /// <param name="values">The strings to write.</param>
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
