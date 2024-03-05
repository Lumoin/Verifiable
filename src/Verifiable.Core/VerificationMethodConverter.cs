using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// Converts DID verifications methods to and from JSON.
    /// </summary>
    public class VerificationMethodConverter: JsonConverter<VerificationMethod>
    {
        public override bool CanConvert(Type typeToConvert)
        {
            return typeToConvert == typeof(VerificationMethod);
            //var canConvert = typeToConvert == typeof(VerificationMethod) || typeToConvert == typeof(VerificationMethod[]);
            //return typeToConvert == typeof(VerificationMethod) || typeToConvert == typeof(VerificationMethod[]);
        }


        /// <summary>
        /// Default converters for the verification key types and formats.
        /// This can be used as a basis for an extened type map that is
        /// given as a constructor parameter. For for standard defined
        /// verification types and key formats see at
        /// https://w3c.github.io/did-core/#key-types-and-formats.
        /// </summary>
        public static ImmutableDictionary<string, Func<string, JsonSerializerOptions, KeyFormat>> DefaultTypeMap =>
            new Dictionary<string, Func<string, JsonSerializerOptions, KeyFormat>>(StringComparer.OrdinalIgnoreCase)
        {
            { "publicKeyMultibase", new Func<string, JsonSerializerOptions, PublicKeyMultibase>((json, _) => new PublicKeyMultibase(json)) },
            { "publicKeyBase58", new Func<string, JsonSerializerOptions, PublicKeyBase58>((json, _) => new PublicKeyBase58(json)) },            
            { "publicKeyPem", new Func<string, JsonSerializerOptions, PublicKeyPem>((json, _) => new PublicKeyPem(json)) },
            { "publicKeyHex", new Func<string, JsonSerializerOptions, PublicKeyHex>((json, _) => new PublicKeyHex(json)) },
            { "publicKeyJwk", new Func<string, JsonSerializerOptions, PublicKeyJwk>((json, options) =>
            {
                var headers = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options)!;
                return new PublicKeyJwk { Header = headers };
            })}
        }.ToImmutableDictionary();


        private static CryptoSuiteFactoryDelegate DefaultCryptoSuiteFactory { get; } = cryptoSuite =>
        {
            return cryptoSuite switch
            {
                "JsonWebKey2020" => new JsonWebKey2020(),
                "Ed25519VerificationKey2020" => new Ed25519VerificationKey2020(),
                "Secp256k1VerificationKey2018" => new Secp256k1VerificationKey2018(),
                "multikey" => new Multikey(),
                _ => new CryptoSuite(cryptoSuite, [])
            };
        };

        /// <summary>
        /// Xyz.
        /// </summary>
        private ImmutableDictionary<string, Func<string, JsonSerializerOptions, KeyFormat>> TypeMap { get; }

        private CryptoSuiteFactoryDelegate CryptoSuiteFactory { get; }


        /// <summary>
        /// A default constructor that maps <see cref="DefaultTypeMap"/> to be used.
        /// </summary>
        public VerificationMethodConverter() : this(DefaultCryptoSuiteFactory, DefaultTypeMap) { }


        /// <summary>
        /// A default constructor for <see cref="VerificationMethod"/> and sub-type conversions.
        /// </summary>
        /// <param name="typeMap">A runtime map of <see cref="Service"/> and sub-types.</param>
        public VerificationMethodConverter(CryptoSuiteFactoryDelegate cryptoSuiteFactory, ImmutableDictionary<string, Func<string, JsonSerializerOptions, KeyFormat>> typeMap)
        {
            ArgumentNullException.ThrowIfNull(nameof(typeMap));
            ArgumentNullException.ThrowIfNull(nameof(cryptoSuiteFactory));

            TypeMap = typeMap;
            CryptoSuiteFactory = cryptoSuiteFactory;
        }


        /// <inheritdoc/>
        public override VerificationMethod Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if(reader.TokenType != JsonTokenType.StartObject)
            {
                ThrowHelper.ThrowJsonException();
            }

            //TODO: There can be also other properties. So there likely needs to be a simlar construct to
            //as ServiceConverter, e.g. "public class SocialWebInboxService: Service".

            //Parsing the document forwards moves the index. The element start position
            //is stored to a temporary variable here so it can be given directly to JsonSerializer.
            var verificationMethod = new VerificationMethod();
            using(var jsonDocument = JsonDocument.ParseValue(ref reader))
            {
                var element = jsonDocument.RootElement;

                //First the values are filled to the object.
                verificationMethod.Id = element.GetProperty("id").GetString()!;
                verificationMethod.Controller = element.GetProperty("controller").GetString();
                verificationMethod.Type = CryptoSuiteFactory(element.GetProperty("type").GetString()!);

                //Then the known key format tags are tested and its corresponding transformation
                //function is used. This is done like this because JSON can contain any format tags
                //supported by DID Core or registry or extended in custom build. So they need to
                //be tried one-by-one.
                //
                //N.B.! Or find a way to read the next property directly!
                foreach(string serviceTypeDiscriminator in TypeMap.Keys)
                {
                    Func<string, JsonSerializerOptions, KeyFormat> keyFunc;
                    if(element.TryGetProperty(serviceTypeDiscriminator, out JsonElement serviceTypeElement)
                        && TypeMap.TryGetValue(serviceTypeDiscriminator, out keyFunc!))
                    {
                        verificationMethod.KeyFormat = keyFunc(serviceTypeElement.ToString()!, options);
                        return verificationMethod;
                    }
                }
            }

            throw new JsonException($"{nameof(VerificationMethodConverter.Read)} could not find a converter for \"{verificationMethod.Type}\".");
        }


        /// <inheritdoc/>
        public override void Write(Utf8JsonWriter writer, VerificationMethod value, JsonSerializerOptions options)
        {
            //TODO: Write use TypeMap as KeyFormat Converter so that these need not to be hardcoded like this.
            //See also ServiceConverter for using options.
            writer.WriteStartObject();
            writer.WriteString("id", value?.Id?.ToString());
            writer.WriteString("controller", value?.Controller);
            writer.WriteString("type", value?.Type!);

            if(value?.KeyFormat is PublicKeyHex hex)
            {
                writer.WriteString("publicKeyHex", hex?.Key);
            }

            if(value?.KeyFormat is PublicKeyMultibase multibase)
            {
                writer.WriteString("publicKeyMultibase", multibase?.Key);
            }

            if(value?.KeyFormat is PublicKeyBase58 base58)
            {
                writer.WriteString("publicKeyBase58", base58?.Key);
            }

            if(value?.KeyFormat is PublicKeyJwk jwk)
            {
                writer.WriteStartObject("publicKeyJwk");

                foreach(var header in jwk.Header)
                {
                    writer.WriteString(header.Key, (string)header.Value);
                }

                writer.WriteEndObject();
            }

            if(value?.KeyFormat is PublicKeyPem pem)
            {
                writer.WriteString("publicKeyPem", pem?.Key);
            }

            writer.WriteEndObject();
        }

        private JsonSerializerOptions CopyOptionsWithoutThisConverter(JsonSerializerOptions options)
        {
            var newOptions = new JsonSerializerOptions(options);
            Type thisConverterType = this.GetType();

            for(int i = newOptions.Converters.Count - 1; i >= 0; i--)
            {
                if(newOptions.Converters[i].GetType() == thisConverterType)
                {
                    newOptions.Converters.RemoveAt(i);
                    break;
                }
            }

            return newOptions;
        }
    }
}
