using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Resolvers;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts <see cref="DidDocumentMetadata"/> to and from the DID Resolution document metadata JSON object.
/// </summary>
/// <remarks>
/// The DID Resolution document metadata is a flat open map: the typed DID-Resolution properties and the
/// method-specific properties carried in <see cref="DidDocumentMetadata.AdditionalData"/> are all top-level
/// members. Unrecognized properties round-trip through <see cref="DidDocumentMetadata.AdditionalData"/> (via
/// <see cref="AdditionalDataJson"/>), and the bucket is flattened back at the object root on write — there is
/// no nested <c>additionalData</c> member and no type discriminator.
/// </remarks>
public class DidDocumentMetadataConverter: JsonConverter<DidDocumentMetadata>
{
    /// <inheritdoc />
    public override bool CanConvert(Type typeToConvert)
    {
        return typeToConvert == typeof(DidDocumentMetadata);
    }


    /// <inheritdoc />
    public override DidDocumentMetadata Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if(reader.TokenType != JsonTokenType.StartObject)
        {
            JsonThrowHelper.ThrowJsonException("DID document metadata must be a JSON object.");
        }

        using(var document = JsonDocument.ParseValue(ref reader))
        {
            JsonElement element = document.RootElement;

            DateTimeOffset? created = null;
            DateTimeOffset? updated = null;
            DateTimeOffset? nextUpdate = null;
            bool deactivated = false;
            string? versionId = null;
            string? nextVersionId = null;
            string? canonicalId = null;
            List<string>? equivalentId = null;
            Dictionary<string, object>? additionalData = null;

            foreach(JsonProperty property in element.EnumerateObject())
            {
                if(property.NameEquals("created"u8))
                {
                    created = ReadTimestamp(property.Value);
                }
                else if(property.NameEquals("updated"u8))
                {
                    updated = ReadTimestamp(property.Value);
                }
                else if(property.NameEquals("nextUpdate"u8))
                {
                    nextUpdate = ReadTimestamp(property.Value);
                }
                else if(property.NameEquals("deactivated"u8))
                {
                    deactivated = property.Value.ValueKind == JsonValueKind.True;
                }
                else if(property.NameEquals("versionId"u8))
                {
                    versionId = property.Value.GetString();
                }
                else if(property.NameEquals("nextVersionId"u8))
                {
                    nextVersionId = property.Value.GetString();
                }
                else if(property.NameEquals("canonicalId"u8))
                {
                    canonicalId = property.Value.GetString();
                }
                else if(property.NameEquals("equivalentId"u8))
                {
                    equivalentId = ReadStringArray(property.Value);
                }
                else
                {
                    AdditionalDataJson.AddFromElement(ref additionalData, property.Name, property.Value);
                }
            }

            return new DidDocumentMetadata
            {
                Created = created,
                Updated = updated,
                NextUpdate = nextUpdate,
                Deactivated = deactivated,
                VersionId = versionId,
                NextVersionId = nextVersionId,
                CanonicalId = canonicalId,
                EquivalentId = equivalentId,
                AdditionalData = additionalData
            };
        }
    }


    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, DidDocumentMetadata value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(options);

        writer.WriteStartObject();

        if(value.Created is { } created)
        {
            writer.WriteString("created"u8, created.ToString("O", CultureInfo.InvariantCulture));
        }

        if(value.Updated is { } updated)
        {
            writer.WriteString("updated"u8, updated.ToString("O", CultureInfo.InvariantCulture));
        }

        if(value.NextUpdate is { } nextUpdate)
        {
            writer.WriteString("nextUpdate"u8, nextUpdate.ToString("O", CultureInfo.InvariantCulture));
        }

        //A resolver that determined the deactivation status (for example did:webvh, which always does) signals
        //it by carrying an explicit "deactivated" boolean in the open-world bucket, so the property is emitted
        //true OR false. Absent that signal, "deactivated" is emitted only when true (a method that does not
        //determine the status omits the default-false value).
        bool hasExplicitDeactivated = value.AdditionalData is { } bucket
            && bucket.TryGetValue("deactivated", out object? deactivatedValue)
            && deactivatedValue is bool;

        if(hasExplicitDeactivated)
        {
            writer.WriteBoolean("deactivated"u8, value.Deactivated);
        }
        else if(value.Deactivated)
        {
            writer.WriteBoolean("deactivated"u8, true);
        }

        if(value.VersionId is not null)
        {
            writer.WriteString("versionId"u8, value.VersionId);
        }

        if(value.NextVersionId is not null)
        {
            writer.WriteString("nextVersionId"u8, value.NextVersionId);
        }

        if(value.CanonicalId is not null)
        {
            writer.WriteString("canonicalId"u8, value.CanonicalId);
        }

        if(value.EquivalentId is not null)
        {
            writer.WriteStartArray("equivalentId"u8);
            foreach(string equivalent in value.EquivalentId)
            {
                writer.WriteStringValue(equivalent);
            }

            writer.WriteEndArray();
        }

        //Method-specific and unknown properties are flattened to the object root (no nested bucket). The
        //"deactivated" bucket signal, when present, is already emitted above as the typed property, so it is
        //excluded here to avoid writing it twice.
        AdditionalDataJson.WriteEntries(writer, value.AdditionalData, excludedKey: hasExplicitDeactivated ? "deactivated" : null);

        writer.WriteEndObject();
    }


    private static DateTimeOffset? ReadTimestamp(JsonElement value)
    {
        return value.ValueKind != JsonValueKind.Null
            && DateTimeOffset.TryParse(value.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTimeOffset parsed)
            ? parsed
            : null;
    }


    private static List<string>? ReadStringArray(JsonElement value)
    {
        if(value.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var items = new List<string>(value.GetArrayLength());
        foreach(JsonElement item in value.EnumerateArray())
        {
            if(item.GetString() is { } text)
            {
                items.Add(text);
            }
        }

        return items;
    }
}
