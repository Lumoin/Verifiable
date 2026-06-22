using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Resolvers;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts <see cref="DidProblemDetails"/> to and from the RFC 9457 Problem Details JSON object
/// used as the <c>error</c> value in DID resolution and dereferencing metadata.
/// </summary>
/// <remarks>
/// The <c>type</c> member is the DID error type URI and is always written. The optional
/// <c>title</c>, <c>status</c>, <c>detail</c> and <c>instance</c> members are omitted when absent.
/// See <see href="https://www.rfc-editor.org/rfc/rfc9457">RFC 9457</see> and
/// <see href="https://w3c.github.io/did-resolution/#errors">DID Resolution Errors</see>.
/// </remarks>
public class DidProblemDetailsConverter: JsonConverter<DidProblemDetails>
{
    /// <inheritdoc />
    public override bool CanConvert(Type typeToConvert)
    {
        return typeToConvert == typeof(DidProblemDetails);
    }


    /// <inheritdoc />
    public override DidProblemDetails Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if(reader.TokenType != JsonTokenType.StartObject)
        {
            JsonThrowHelper.ThrowJsonException("A DID problem details value must be a JSON object.");
        }

        using(var document = JsonDocument.ParseValue(ref reader))
        {
            JsonElement element = document.RootElement;

            Uri? type = null;
            string? title = null;
            int? status = null;
            string? detail = null;
            Uri? instance = null;

            foreach(JsonProperty property in element.EnumerateObject())
            {
                if(property.NameEquals("type"u8))
                {
                    type = ReadUri(property.Value);
                }
                else if(property.NameEquals("title"u8))
                {
                    title = property.Value.GetString();
                }
                else if(property.NameEquals("status"u8))
                {
                    status = property.Value.ValueKind == JsonValueKind.Number ? property.Value.GetInt32() : null;
                }
                else if(property.NameEquals("detail"u8))
                {
                    detail = property.Value.GetString();
                }
                else if(property.NameEquals("instance"u8))
                {
                    instance = ReadUri(property.Value);
                }
            }

            if(type is null)
            {
                JsonThrowHelper.ThrowJsonException("A DID problem details value must carry a 'type' URI.");
            }

            return new DidProblemDetails(type!, title, status, detail, instance);
        }
    }


    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, DidProblemDetails value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(options);

        writer.WriteStartObject();

        writer.WriteString("type"u8, value.Type.AbsoluteUri);

        if(value.Title is not null)
        {
            writer.WriteString("title"u8, value.Title);
        }

        if(value.Status is { } status)
        {
            writer.WriteNumber("status"u8, status);
        }

        if(value.Detail is not null)
        {
            writer.WriteString("detail"u8, value.Detail);
        }

        if(value.Instance is not null)
        {
            writer.WriteString("instance"u8, value.Instance.AbsoluteUri);
        }

        writer.WriteEndObject();
    }


    private static Uri? ReadUri(JsonElement value)
    {
        return value.ValueKind == JsonValueKind.String
            && value.GetString() is { } text
            && Uri.TryCreate(text, UriKind.Absolute, out Uri? uri)
            ? uri
            : null;
    }
}
