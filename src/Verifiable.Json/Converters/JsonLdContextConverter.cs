using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Common;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts <see cref="Context"/> to and from JSON. Handles the JSON-LD <c>@context</c>
/// property which can be a single string, an array of strings and objects, or a bare object.
/// </summary>
public class JsonLdContextConverter: JsonConverter<Context>
{
    /// <inheritdoc/>
    public override bool CanConvert(Type typeToConvert)
    {
        return typeToConvert == typeof(Context);
    }


    /// <inheritdoc/>
    public override Context Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var context = new Context { Contexts = new List<object>(), AdditionalData = new Dictionary<string, object>() };

        if(reader.TokenType == JsonTokenType.PropertyName && reader.ValueTextEquals("@context"u8))
        {
            reader.Read();
        }

        if(reader.TokenType == JsonTokenType.String)
        {
            if(reader.ValueTextEquals("@context"u8))
            {
                reader.Read();
            }

            string? ctx = reader.GetString();
            if(ctx is not null)
            {
                context.Contexts.Add(ctx);
            }

            return context;
        }

        if(reader.TokenType == JsonTokenType.StartArray)
        {
            while(reader.Read())
            {
                if(reader.TokenType == JsonTokenType.EndArray)
                {
                    break;
                }

                object? element = ManualJsonReader.ReadValue(ref reader);
                if(element is not null)
                {
                    context.Contexts.Add(element);
                }
            }

            return context;
        }

        //Bare object form.
        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.EndObject)
            {
                return context;
            }

            if(reader.TokenType != JsonTokenType.PropertyName)
            {
                throw new JsonException($"Expected PropertyName, got '{reader.TokenType}'.");
            }

            string propertyName = reader.GetString()!;
            reader.Read();

            object? val = ManualJsonReader.ReadValue(ref reader);
            if(val is not null)
            {
                context.AdditionalData.Add(propertyName, val);
            }
        }

        return context;
    }


    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, Context value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        if(value.Contexts?.Count == 1 && (value.AdditionalData is null || value.AdditionalData.Count == 0))
        {
            //Single context string.
            if(value.Contexts[0] is string s)
            {
                writer.WriteStringValue(s);
            }
            else
            {
                ManualJsonWriter.WriteValue(writer, value.Contexts[0]);
            }
        }
        else if(value.Contexts?.Count > 0)
        {
            writer.WriteStartArray();
            for(int i = 0; i < value.Contexts.Count; ++i)
            {
                ManualJsonWriter.WriteValue(writer, value.Contexts[i]);
            }

            writer.WriteEndArray();
        }

        if(value.AdditionalData?.Count > 0)
        {
            ManualJsonWriter.WriteObject(writer, value.AdditionalData);
        }
    }
}