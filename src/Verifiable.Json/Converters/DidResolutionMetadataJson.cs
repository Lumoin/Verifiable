using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Verifiable.Core.Resolvers;

namespace Verifiable.Json.Converters;

/// <summary>
/// Shared read/write helpers for the DID resolution and dereferencing metadata objects, which
/// share an identical shape: <c>{ "contentType"?, "error"?, "proof"? }</c>. The
/// <see cref="DidResolutionMetadataConverter"/> and
/// <see cref="DidDereferencingMetadataConverter"/> both delegate here so the member handling lives
/// in one place.
/// </summary>
internal static class DidResolutionMetadataJson
{
    /// <summary>
    /// Writes the shared metadata members. <c>contentType</c> is omitted when absent. When an error is present
    /// the <c>error</c> field is the lowerCamelCase string code (per the DID Resolution and did:webvh error
    /// model) and the RFC 9457 Problem Details object is carried separately in the recommended (SHOULD)
    /// <c>problemDetails</c> field (did:webvh v1.0, error envelope: L872). <c>proof</c> is written as an array
    /// of opaque maps via <see cref="ManualJsonWriter"/> and omitted when absent.
    /// </summary>
    internal static void WriteMembers(
        Utf8JsonWriter writer,
        string? contentType,
        DidProblemDetails? error,
        IReadOnlyList<IReadOnlyDictionary<string, object>>? proof,
        JsonSerializerOptions options)
    {
        if(contentType is not null)
        {
            writer.WriteString("contentType"u8, contentType);
        }

        if(error is not null)
        {
            writer.WriteString("error"u8, error.Code);

            writer.WritePropertyName("problemDetails"u8);
            JsonSerializer.Serialize(writer, error, options.GetTypeInfo(typeof(DidProblemDetails)));
        }

        if(proof is not null)
        {
            writer.WriteStartArray("proof"u8);
            foreach(IReadOnlyDictionary<string, object> entry in proof)
            {
                WriteOpaqueMap(writer, entry);
            }

            writer.WriteEndArray();
        }
    }


    /// <summary>
    /// Reads the shared metadata members from a buffered <see cref="JsonElement"/> object, returning the parsed
    /// <c>contentType</c>, <c>error</c> and <c>proof</c> values. The <c>error</c> field is the lowerCamelCase
    /// string code; the full RFC 9457 Problem Details object is read from the separate <c>problemDetails</c>
    /// field and is the source of the reconstructed <see cref="DidProblemDetails"/> (it carries the type URI). A
    /// bare string code with no <c>problemDetails</c> object is reconstructed from the code alone. Unrecognized
    /// members are ignored.
    /// </summary>
    internal static (string? ContentType, DidProblemDetails? Error, List<IReadOnlyDictionary<string, object>>? Proof) ReadMembers(
        JsonElement element,
        JsonSerializerOptions options)
    {
        string? contentType = null;
        string? errorCode = null;
        DidProblemDetails? problemDetails = null;
        List<IReadOnlyDictionary<string, object>>? proof = null;

        foreach(JsonProperty property in element.EnumerateObject())
        {
            if(property.NameEquals("contentType"u8))
            {
                contentType = property.Value.GetString();
            }
            else if(property.NameEquals("error"u8) && property.Value.ValueKind == JsonValueKind.String)
            {
                errorCode = property.Value.GetString();
            }
            else if(property.NameEquals("problemDetails"u8) && property.Value.ValueKind == JsonValueKind.Object)
            {
                problemDetails = property.Value.Deserialize((JsonTypeInfo<DidProblemDetails>)options.GetTypeInfo(typeof(DidProblemDetails)));
            }
            else if(property.NameEquals("proof"u8) && property.Value.ValueKind == JsonValueKind.Array)
            {
                proof = ReadProof(property.Value);
            }
        }

        //The problemDetails object carries the full RFC 9457 problem (including the type URI), so it is the
        //preferred reconstruction. When only the error code string is present, the problem is reconstructed from
        //the code -> type URI mapping.
        DidProblemDetails? error = problemDetails
            ?? (errorCode is not null ? new DidProblemDetails(DidErrorTypes.FromErrorCode(errorCode)) : null);

        return (contentType, error, proof);
    }


    private static List<IReadOnlyDictionary<string, object>> ReadProof(JsonElement array)
    {
        var proofs = new List<IReadOnlyDictionary<string, object>>(array.GetArrayLength());
        foreach(JsonElement item in array.EnumerateArray())
        {
            if(item.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            Dictionary<string, object>? map = null;
            foreach(JsonProperty member in item.EnumerateObject())
            {
                AdditionalDataJson.AddFromElement(ref map, member.Name, member.Value);
            }

            proofs.Add(map ?? new Dictionary<string, object>(StringComparer.Ordinal));
        }

        return proofs;
    }


    private static void WriteOpaqueMap(Utf8JsonWriter writer, IReadOnlyDictionary<string, object> entry)
    {
        writer.WriteStartObject();
        foreach(KeyValuePair<string, object> member in entry)
        {
            writer.WritePropertyName(member.Key);
            ManualJsonWriter.WriteValue(writer, member.Value);
        }

        writer.WriteEndObject();
    }
}
