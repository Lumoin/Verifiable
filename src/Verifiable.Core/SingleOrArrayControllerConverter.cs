using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Verifiable.Core.Did
{
    //TODO: A temporary structure.
    /// <summary>
    /// A converter for array of <see cref="Controller"/> instances.
    /// </summary>
    public class SingleOrArrayControllerConverter: JsonConverter<Controller[]>
    {
        public override bool CanConvert(Type typeToConvert)
        {
            return typeToConvert == typeof(Controller[]);
        }

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

        public override void Write(Utf8JsonWriter writer, Controller[] controller, JsonSerializerOptions options)
        {
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
