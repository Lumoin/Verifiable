using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Common;

namespace Verifiable.Json.Converters
{
    /// <summary>
    /// Converts <see cref="Context" to and from JSON.
    /// Based on DictionaryTKeyEnumTValueConverter
    /// at https://docs.microsoft.com/en-us/dotnet/standard/serialization/system-text-json-converters-how-to.
    /// https://w3c.github.io/did-imp-guide/
    /// </summary>
    public class JsonLdContextConverter: JsonConverter<Context>
    {
        public override bool CanConvert(Type typeToConvert)
        {
            return typeToConvert == typeof(Context);
        }


        public override Context Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            //The DID JSON-LD context starts either with a single string, array of strings, array of objects and strings
            //or is an object that can contain whatever elements.
            var context = new Context { Contexts = new List<object>(), AdditionalData = new Dictionary<string, object>() };
            var tokenType = reader.TokenType;
            if(reader.TokenType == JsonTokenType.PropertyName && reader.ValueTextEquals("@context"))
            {
                _ = reader.Read();
            }

            if(tokenType == JsonTokenType.String)
            {
                if(reader.ValueTextEquals("@context"))
                {
                    _ = reader.Read();
                }

                var ctx = reader.GetString();
                if(ctx != null)
                {
                    context.Contexts.Add(ctx);
                }

                return context;
            }

            if(tokenType == JsonTokenType.StartArray)
            {
                var strList = JsonSerializer.Deserialize<object[]>(ref reader);
                if(strList != null)
                {
                    for(int i = 0; i < strList.Length; i++)
                    {
                        var s = strList[i];
                        context.Contexts.Add(s);
                    }
                }

                return context;
            }

            while(reader.Read())
            {
                if(reader.TokenType == JsonTokenType.EndObject)
                {
                    return context;
                }

                if(reader.TokenType != JsonTokenType.PropertyName)
                {
                    throw new JsonException($"JsonTokenType was not {nameof(JsonTokenType.PropertyName)}");
                }

                var propertyName = reader.GetString();
                if(string.IsNullOrWhiteSpace(propertyName))
                {
                    throw new JsonException("Failed to get property name");
                }

                _ = reader.Read();
                object? val = ExtractValue(ref reader, propertyName, options);
                if(val != null)
                {
                    context.AdditionalData.Add(propertyName, val);
                }
            }

            return context;
        }


        public override void Write(Utf8JsonWriter writer, Context value, JsonSerializerOptions options)
        {
            ArgumentNullException.ThrowIfNull(writer);
            ArgumentNullException.ThrowIfNull(value);
            //writer.WritePropertyName("@context");
            if(value?.Contexts?.Count == 1)
            {
                writer.WriteStringValue((string)value.Contexts.ElementAt(0));
            }
            else if(value?.Contexts?.Count > 1)
            {
                writer.WriteStartArray();
                for(int i = 0; i < value?.Contexts.Count; ++i)
                {
                    if (value.Contexts.ElementAt(i) is string)
                    {
                        writer.WriteStringValue((string)value.Contexts.ElementAt(i));
                    }
                    else
                    {
                        JsonSerializer.Serialize(writer, value.Contexts.ElementAt(i));
                    }
                }

                writer.WriteEndArray();
            }

            if(value?.AdditionalData?.Count > 0)
            {
                JsonSerializer.Serialize(writer, value.AdditionalData);
            }
        }


        [return: MaybeNull]
        private static object? ExtractValue(ref Utf8JsonReader reader, string propertyName, JsonSerializerOptions options)
        {
            //https://github.com/dotnet/corefx/blob/master/src/System.Text.Json/src/System/Text/Json/Serialization/Converters/JsonValueConverterKeyValuePair.cs
            switch(reader.TokenType)
            {
                case JsonTokenType.String:
                    if(reader.TryGetDateTime(out DateTime date))
                    {
                        return date;
                    }
                    return reader.GetString();
                case JsonTokenType.False:
                    return false;
                case JsonTokenType.True:
                    return true;
                case JsonTokenType.Null:
                    return null;
                case JsonTokenType.Number:
                    if(reader.TryGetInt64(out long result))
                    {
                        return result;
                    }
                    return reader.GetDecimal();
                case JsonTokenType.StartObject:
                {
                    return JsonSerializer.Deserialize<object>(ref reader, options);
                }
                case JsonTokenType.StartArray:

                    var list = new List<object>();
                    while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                    {
                        list.Add(ExtractValue(ref reader, propertyName, options)!);
                    }
                    return list;
                //return JsonSerializer.Deserialize(ref reader, typeof(object[]));
                default:
                    throw new JsonException($"'{reader.TokenType}' is not supported");
            }
        }
    }
}
