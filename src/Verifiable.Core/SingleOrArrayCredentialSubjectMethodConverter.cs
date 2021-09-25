using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Verifiable.Core.Vc
{
    /// <summary>
    /// A converter for array of <see cref="VerificationMethod"/> instances.
    /// </summary>
    public class SingleOrArrayCredentialSubjectMethodConverter: JsonConverter<CredentialSubject[]>
    {
        public override bool CanConvert(Type typeToConvert)
        {
            return typeToConvert == typeof(CredentialSubject[]);
        }

        public override CredentialSubject[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if(reader.TokenType == JsonTokenType.PropertyName)
            {
                _ = reader.Read();
            }

            var list = new List<CredentialSubject>();
            if(reader.TokenType == JsonTokenType.StartArray)
            {
                while(reader.Read())
                {
                    if(reader.TokenType == JsonTokenType.EndArray)
                    {
                        break;
                    }

                    list.Add(JsonSerializer.Deserialize<CredentialSubject>(ref reader, options)!);
                }
            }
            else if(reader.TokenType == JsonTokenType.String)
            {
                list.Add(JsonSerializer.Deserialize<CredentialSubject>(ref reader, options)!);
            }
            else
            {
                throw new JsonException();
            }

            return list.ToArray();
        }


        public override void Write(Utf8JsonWriter writer, CredentialSubject[] verificationMethod, JsonSerializerOptions options)
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
