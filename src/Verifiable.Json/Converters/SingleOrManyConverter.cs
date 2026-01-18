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


    //TODO: A temporary structure.
    /// <summary>
    /// A converter for array of <see cref="VerificationMethod"/> instances.
    /// </summary>
    public class SingleOrArrayVerificationMethodConverter: JsonConverter<VerificationMethod[]>
    {
        public override bool CanConvert(Type typeToConvert)
        {
            return typeToConvert == typeof(VerificationMethod[]);
        }

        public override VerificationMethod[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if(reader.TokenType == JsonTokenType.PropertyName)
            {
                _ = reader.Read();
            }

            var list = new List<VerificationMethod>();
            if(reader.TokenType == JsonTokenType.StartArray)
            {
                while(reader.Read())
                {
                    if(reader.TokenType == JsonTokenType.EndArray)
                    {
                        break;
                    }

                    list.Add(JsonSerializer.Deserialize<VerificationMethod>(ref reader, options)!);
                }
            }
            else if(reader.TokenType == JsonTokenType.String)
            {
                list.Add(JsonSerializer.Deserialize<VerificationMethod>(ref reader, options)!);
            }
            else
            {
                throw new JsonException();
            }

            return list.ToArray();
        }


        public override void Write(Utf8JsonWriter writer, VerificationMethod[] verificationMethod, JsonSerializerOptions options)
        {
            if(verificationMethod.Length == 1)
            {
                JsonSerializer.Serialize(writer, verificationMethod[0]);
            }
            else
            {
                writer.WriteStartArray();
                for(int i = 0; i < verificationMethod.Length; ++i)
                {
                    JsonSerializer.Serialize(writer, verificationMethod[i], options);
                }
                writer.WriteEndArray();
            }
        }
    }
}
