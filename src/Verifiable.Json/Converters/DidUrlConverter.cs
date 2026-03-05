using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Did;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts <see cref="DidUrl"/> to and from a JSON string value using
/// <see cref="DidUrl.Parse"/> for reading and <see cref="DidUrl.ToString"/>
/// for writing.
/// </summary>
/// <remarks>
/// <para>
/// This converter is needed when STJ encounters a <see cref="DidUrl"/> property
/// during default (non-manual) serialization, such as on derived <see cref="Service"/>
/// subclasses that are deserialized via <see cref="JsonSerializerOptions.GetTypeInfo"/>.
/// </para>
/// <para>
/// Register this converter in the <see cref="JsonSerializerOptions.Converters"/>
/// collection alongside other DID-related converters.
/// </para>
/// </remarks>
public sealed class DidUrlConverter: JsonConverter<DidUrl>
{
    /// <inheritdoc />
    public override DidUrl? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType == JsonTokenType.Null)
        {
            return null;
        }

        if(reader.TokenType != JsonTokenType.String)
        {
            JsonThrowHelper.ThrowJsonException($"Expected a string token for DidUrl, but got {reader.TokenType}.");
        }

        string? value = reader.GetString();
        if(value is null)
        {
            return null;
        }

        return DidUrl.Parse(value);
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, DidUrl value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);

        if(value is null)
        {
            writer.WriteNullValue();
            return;
        }

        writer.WriteStringValue(value.ToString());
    }
}