using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Did.CryptographicSuites;

namespace Verifiable.Core.Did
{
    public delegate CryptographicSuite CryptoSuiteFactoryDelegate(string suiteIdentifier);

    public class CryptographicSuiteJsonConverter: JsonConverter<CryptographicSuite>
    {
        private CryptoSuiteFactoryDelegate FactoryDelegate { get; }

        public override bool CanConvert(Type objectType) => typeof(CryptographicSuite).IsAssignableFrom(objectType);

        public CryptographicSuiteJsonConverter(CryptoSuiteFactoryDelegate factoryDelegate)
        {
            FactoryDelegate = factoryDelegate;
        }

        public override CryptographicSuite Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            string? suite = reader.GetString();
            if(suite == null)
            {
                ThrowHelper.ThrowJsonException("Crypto suite identifier must be a valid identifier string.");
            }

            return FactoryDelegate(suite);
        }

        public override void Write(Utf8JsonWriter writer, CryptographicSuite value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.VerificationMethodType);
        }
    }
}
