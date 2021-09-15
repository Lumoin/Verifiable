using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Did;

namespace Verifiable.Core
{
    /// <summary>
    /// A conventer for 
    /// </summary>
    public class ControllerConverter: JsonConverter<Controller>
    {
        public override Controller Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if(reader.TokenType == JsonTokenType.String)
            {
                return new Controller(reader.GetString()!);
            }

            throw new JsonException();
        }


        public override void Write(Utf8JsonWriter writer, Controller controller, JsonSerializerOptions options)
        {
            writer.WriteStringValue(controller.Did);
        }
    }
}
