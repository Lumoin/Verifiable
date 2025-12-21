using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Did;
using Verifiable.Json;

namespace Verifiable.Json.Converters
{
    public delegate VerificationMethodTypeInfo VerificationMethodTypeInfoFactoryDelegate(string verificationMethodTypeName);

    public class CryptographicSuiteJsonConverter: JsonConverter<VerificationMethodTypeInfo>
    {
        private VerificationMethodTypeInfoFactoryDelegate FactoryDelegate { get; }

        public override bool CanConvert(Type objectType) => typeof(VerificationMethodTypeInfo).IsAssignableFrom(objectType);

        public CryptographicSuiteJsonConverter(VerificationMethodTypeInfoFactoryDelegate factoryDelegate)
        {
            FactoryDelegate = factoryDelegate;
        }

        public override VerificationMethodTypeInfo Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            string? suite = reader.GetString();
            if(suite == null)
            {
                JsonThrowHelper.ThrowJsonException("Crypto suite identifier must be a valid identifier string.");
            }

            return FactoryDelegate(suite);
        }

        public override void Write(Utf8JsonWriter writer, VerificationMethodTypeInfo value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.TypeName);
        }
    }
}
