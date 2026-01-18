using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Credentials;

namespace Verifiable.Json.Converters
{
    /// <summary>
    /// Converts <see cref="Issuer"/> to and from JSON, handling both URI string
    /// and object forms.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The issuer property in Verifiable Credentials can be either a simple URI string
    /// or an object with an <c>id</c> property and optional metadata. This converter
    /// handles both forms transparently.
    /// </para>
    /// <para>
    /// Reading:
    /// </para>
    /// <list type="bullet">
    /// <item><description>String value: Creates an <see cref="Issuer"/> with only the <c>Id</c> set.</description></item>
    /// <item><description>Object value: Deserializes all properties into the <see cref="Issuer"/>.</description></item>
    /// </list>
    /// <para>
    /// Writing:
    /// </para>
    /// <list type="bullet">
    /// <item><description>If only <c>Id</c> is set: Writes as a simple string.</description></item>
    /// <item><description>If other properties are set: Writes as an object.</description></item>
    /// </list>
    /// </remarks>
    public class IssuerConverter: JsonConverter<Issuer>
    {
        /// <inheritdoc/>
        public override Issuer? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if(reader.TokenType == JsonTokenType.Null)
            {
                return null;
            }

            if(reader.TokenType == JsonTokenType.String)
            {
                string? id = reader.GetString();
                if(id is null)
                {
                    return null;
                }

                return new Issuer { Id = id };
            }

            if(reader.TokenType == JsonTokenType.StartObject)
            {
                string? id = null;
                string? name = null;
                string? description = null;
                string? image = null;

                while(reader.Read())
                {
                    if(reader.TokenType == JsonTokenType.EndObject)
                    {
                        break;
                    }

                    if(reader.TokenType != JsonTokenType.PropertyName)
                    {
                        throw new JsonException("Expected property name.");
                    }

                    string? propertyName = reader.GetString();
                    reader.Read();

                    switch(propertyName)
                    {
                        case "id":
                            id = reader.GetString();
                            break;
                        case "name":
                            name = reader.GetString();
                            break;
                        case "description":
                            description = reader.GetString();
                            break;
                        case "image":
                            image = reader.GetString();
                            break;
                        default:
                            reader.Skip();
                            break;
                    }
                }

                if(id is null)
                {
                    throw new JsonException("Issuer object must have an 'id' property.");
                }

                return new Issuer
                {
                    Id = id,
                    Name = name,
                    Description = description,
                    Image = image
                };
            }

            throw new JsonException($"Unexpected token type {reader.TokenType} when parsing Issuer.");
        }


        /// <inheritdoc/>
        public override void Write(Utf8JsonWriter writer, Issuer value, JsonSerializerOptions options)
        {
            if(value is null)
            {
                writer.WriteNullValue();

                return;
            }

            bool hasOnlyId = value.Name is null
                && value.Description is null
                && value.Image is null
                && (value.AdditionalData is null || value.AdditionalData.Count == 0);

            if(hasOnlyId)
            {
                writer.WriteStringValue(value.Id);
            }
            else
            {
                writer.WriteStartObject();
                writer.WriteString("id", value.Id);

                if(value.Name is not null)
                {
                    writer.WriteString("name", value.Name);
                }

                if(value.Description is not null)
                {
                    writer.WriteString("description", value.Description);
                }

                if(value.Image is not null)
                {
                    writer.WriteString("image", value.Image);
                }

                writer.WriteEndObject();
            }
        }
    }
}