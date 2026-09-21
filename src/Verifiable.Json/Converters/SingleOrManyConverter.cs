using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Did;

namespace Verifiable.Json.Converters
{
    //TODO: A temporary structure.
    /// <summary>
    /// A converter for array of <see cref="Controller"/> instances.
    /// </summary>
    public class SingleOrArrayControllerConverter: JsonConverter<Controller[]>
    {
        /// <summary>Returns <see langword="true"/> when <paramref name="typeToConvert"/> is <see cref="Controller"/>[].</summary>
        /// <param name="typeToConvert">The runtime type the serializer is about to (de)serialize.</param>
        public override bool CanConvert(Type typeToConvert)
        {
            return typeToConvert == typeof(Controller[]);
        }

        /// <summary>Reads either a single controller string or a JSON array of them into a <see cref="Controller"/>[].</summary>
        /// <param name="reader">The UTF-8 JSON reader positioned at the value.</param>
        /// <param name="typeToConvert">The runtime type being converted.</param>
        /// <param name="options">The active serializer options.</param>
        public override Controller[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if(reader.TokenType == JsonTokenType.PropertyName)
            {
                _ = reader.Read();
            }

            var list = new List<Controller>();
            if(reader.TokenType == JsonTokenType.StartArray)
            {
                while(reader.Read())
                {
                    if(reader.TokenType == JsonTokenType.EndArray)
                    {
                        break;
                    }

                    list.Add(new Controller(reader.GetString()!));
                }
            }
            else if(reader.TokenType == JsonTokenType.String)
            {
                list.Add(new Controller(reader.GetString()!));
            }
            else
            {
                throw new JsonException();
            }

            return list.ToArray();
        }

        /// <summary>Writes a one-element array as a bare string; writes a longer array as a JSON array of strings.</summary>
        /// <param name="writer">The UTF-8 JSON writer.</param>
        /// <param name="controller">The controllers to write.</param>
        /// <param name="options">The active serializer options.</param>
        public override void Write(Utf8JsonWriter writer, Controller[] controller, JsonSerializerOptions options)
        {
            ArgumentNullException.ThrowIfNull(writer);
            ArgumentNullException.ThrowIfNull(controller);
            if(controller.Length == 1)
            {
                writer.WriteStringValue(controller[0].Did);
            }
            else
            {
                writer.WriteStartArray();
                for(int i = 0; i < controller.Length; ++i)
                {
                    writer.WriteStringValue(controller[i].Did);
                }
                writer.WriteEndArray();
            }
        }
    }
}
