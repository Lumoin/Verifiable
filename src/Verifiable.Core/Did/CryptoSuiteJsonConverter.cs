using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Verifiable.Core.Did
{
    public delegate CryptoSuite CryptoSuiteFactoryDelegate(string suiteIdentifier);

    public class CryptoSuiteJsonConverter: JsonConverter<CryptoSuite>
    {
        private CryptoSuiteFactoryDelegate FactoryDelegate { get; }

        public override bool CanConvert(Type objectType) => typeof(CryptoSuite).IsAssignableFrom(objectType);

        public CryptoSuiteJsonConverter(CryptoSuiteFactoryDelegate factoryDelegate)
        {
            FactoryDelegate = factoryDelegate;
        }

        public override CryptoSuite Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            string? suite = reader.GetString();
            if(suite == null)
            {
                ThrowHelper.ThrowJsonException("Crypto suite identifier must be a valid identifier string.");
            }

            return FactoryDelegate(suite);
        }

        public override void Write(Utf8JsonWriter writer, CryptoSuite value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.CryptoSuiteId);
        }
    }
}
