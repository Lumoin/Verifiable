using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Did;

namespace Verifiable.Json.Converters
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
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(controller);
            writer.WriteStringValue(controller.Did);
        }
    }
}
