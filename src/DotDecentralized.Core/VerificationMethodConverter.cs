using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DotDecentralized.Core.Did
{
    /// <summary>
    /// Converts DID verifications methods to and from JSON.
    /// </summary>
    public class VerificationMethodConverter: JsonConverter<VerificationMethod>
    {
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
            { "publicKeyBase58", new Func<string, JsonSerializerOptions, PublicKeyBase58>((json, _) => new PublicKeyBase58(json)) },
            { "publicKeyPem", new Func<string, JsonSerializerOptions, PublicKeyPem>((json, _) => new PublicKeyPem(json)) },
            { "publicKeyHex", new Func<string, JsonSerializerOptions, PublicKeyHex>((json, _) => new PublicKeyHex(json)) },
            { "publicKeyJwk", new Func<string, JsonSerializerOptions, PublicKeyJwk>((json, options) => JsonSerializer.Deserialize<PublicKeyJwk>(json, options)!) }
        }.ToImmutableDictionary();

        /// <summary>
        /// Xyz.
        /// </summary>
        private ImmutableDictionary<string, Func<string, JsonSerializerOptions, KeyFormat>> TypeMap { get; }


        /// <summary>
        /// A default constructor that maps <see cref="DefaultTypeMap"/> to be used.
        /// </summary>
        public VerificationMethodConverter(): this(DefaultTypeMap) { }


        /// <summary>
        /// A default constructor for <see cref="VerificationMethod"/> and sub-type conversions.
        /// </summary>
        /// <param name="typeMap">A runtime map of <see cref="Service"/> and sub-types.</param>
        public VerificationMethodConverter(ImmutableDictionary<string, Func<string, JsonSerializerOptions, KeyFormat>> typeMap)
        {
            TypeMap =  typeMap ?? throw new ArgumentNullException(nameof(typeMap));
        }


        /// <inheritdoc/>
        public override VerificationMethod Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if(reader.TokenType != JsonTokenType.StartObject)
            {
                ThrowHelper.ThrowJsonException();
            }

            //Parsing the document forwards moves the index. The element start position
            //is stored to a temporary variable here so it can be given directly to JsonSerializer.
            var verificationMethod = new VerificationMethod();
            using(var jsonDocument = JsonDocument.ParseValue(ref reader))
            {
                var element = jsonDocument.RootElement;

                //First the values are filled to the object.
                verificationMethod.Id = element.GetProperty("id").GetString()!;
                verificationMethod.Controller = element.GetProperty("controller").GetString();
                verificationMethod.Type = element.GetProperty("type").GetString();

                //Then the known key format tags are tested and its corresponding transformation
                //function is used. This is done like this because JSON can contain any format tags
                //supported by DID Core or registry or extended in custom build. So they need to
                //be tried one-by-one.
                //
                //N.B.! Or find a way to read the next property directly!
                foreach(var serviceTypeDiscriminator in TypeMap.Keys)
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
            writer.WriteString("type", value?.Type);

            if(value?.KeyFormat is PublicKeyHex hex)
            {
                writer.WriteString("publicKeyHex", hex?.Key);
            }

            if(value?.KeyFormat is PublicKeyBase58 base58)
            {
                writer.WriteString("publicKeyBase58", base58?.Key);
            }

            if(value?.KeyFormat is PublicKeyJwk jwk)
            {
                writer.WriteStartObject("publicKeyJwk");
                if(!string.IsNullOrWhiteSpace(jwk.Crv))
                {
                    writer.WriteString("crv", jwk.Crv);
                }

                if(!string.IsNullOrWhiteSpace(jwk.X))
                {
                    writer.WriteString("x", jwk.X);
                }

                if(!string.IsNullOrWhiteSpace(jwk.Y))
                {
                    writer.WriteString("y", jwk.Y);
                }

                if(!string.IsNullOrWhiteSpace(jwk.Kty))
                {
                    writer.WriteString("kty", jwk.Kty);
                }

                if(!string.IsNullOrWhiteSpace(jwk.Kid))
                {
                    writer.WriteString("kid", jwk.Kid);
                }

                if(!string.IsNullOrWhiteSpace(jwk.E))
                {
                    writer.WriteString("e", jwk.E);
                }

                if(!string.IsNullOrWhiteSpace(jwk.N))
                {
                    writer.WriteString("n", jwk.N);
                }

                writer.WriteEndObject();
            }

            if(value?.KeyFormat is PublicKeyPem pem)
            {
                writer.WriteString("publicKeyPem", pem?.Key);
            }

            writer.WriteEndObject();
        }
    }
}
