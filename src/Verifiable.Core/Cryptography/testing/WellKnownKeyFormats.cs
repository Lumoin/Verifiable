using System;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Did;
using Verifiable.Cryptography;

namespace Verifiable.Core
{
    /// <summary>
    /// <para>Represents well-known key formats utilized in the context of decentralized identifiers (DIDs)
    /// and verifiable credentials.</para>
    /// 
    /// <para>The choice of a key format is inherently linked to the cryptographic suite (<see cref="CryptoSuite"/>) in use.
    /// However, a single suite may support multiple key formats (<see cref="KeyFormat"/>).</para>
    /// 
    /// <para>This enumeration codifies a set of formats that are widely recognized and applied within the community.
    /// This allows for the use of a curated set of formats when constructing the actual key format representation.
    /// The selection of a suitable format is guided by the <see cref="KeyFormatSelector"/> function.</para>
    /// 
    /// The choice of a key format can be influenced by several factors:
    /// <list type="number">
    /// <item>
    /// <description>The DID method in use: Different DID methods may support different key encoding formats.
    /// For example, systems using the did:key method primarily prefer crypto multibase encoding for key representation
    /// </description>
    /// </item>
    /// <item>
    /// <description>The cryptographic suite in use: Different cryptographic suites may favor certain encoding formats.
    /// For instance, <see href="https://www.w3.org/TR/vc-di-bbs/">BBS Cryptosuite v2023</see> supports key representation
    /// in [MULTIBASE], [MULTICODEC], JSON Web Key [RFC7517], and [BLS-JOSE-COSE].</description>
    /// </item>
    /// <item>
    /// <description>The application requirements: Specific use cases or applications may dictate the choice of representation.
    /// Certain applications may prefer one encoding format over another due to factors like interoperability,
    /// ease of use, security requirements, or industry standards.</description>
    /// </item>
    /// </list>
    /// </summary>    
    public static class WellKnownKeyFormats
    {
        /// <summary>
        /// JSON Web Key (JWK): A JSON-based format for representing cryptographic keys.
        /// Defined in the JSON Web Key (JWK) specification, part of the larger JSON Web Token (JWT) framework.
        /// JWKs can represent various types of keys, including RSA, ECDSA, and others.
        /// <see href="https://tools.ietf.org/html/rfc7517">More info</see>
        /// </summary>
        public static Type PublicKeyJwk { get; } = typeof(PublicKeyJwk);

        /// <summary>
        /// Privacy Enhanced Mail (PEM): A widely used format for encoding and storing cryptographic keys and certificates.
        /// Commonly used in the context of TLS/SSL for securing web connections.
        /// PEM files typically have extensions such as .pem, .crt, .cer, or .key.
        /// </summary>
        public static Type PublicKeyPem { get; } = typeof(PublicKeyPem);

        /// <summary>
        /// Base58: A binary-to-text encoding format that is commonly used in cryptocurrencies like Bitcoin.
        /// Designed to avoid visual ambiguity between similar-looking characters (like 'O' and '0').
        /// This format is often used to encode public keys and addresses in blockchain systems.
        /// </summary>
        public static Type PublicKeyBase58 { get; } = typeof(PublicKeyBase58);

        /// <summary>
        /// Hexadecimal: A simple binary-to-text encoding scheme that represents binary data as hexadecimal numbers.
        /// Often used for simplicity, especially in systems where the keys are relatively small.
        /// </summary>
        public static Type PublicKeyHex { get; } = typeof(PublicKeyHex);

        /// <summary>
        /// Multibase: A format for encoding binary data as strings, along with an indicator of the encoding used.
        /// Designed for use in systems where multiple binary-to-text encoding schemes may be used.
        /// <see href="https://github.com/multiformats/multibase">More info</see>
        /// </summary>
        public static Type PublicKeyMultibase { get; } = typeof(PublicKeyMultibase);
    }
    
    public delegate Type KeyFormatSelector(Type didMethod, CryptoSuite cryptoSuite, Type? preferredFormat = null);
    public delegate KeyFormat KeyFormatCreator(Type keyFormatSelector, PublicKeyMemory keyMaterial);


    public static class SsiKeyFormatSelector
    {
        public static KeyFormatSelector DefaultKeyFormatSelector = (Type didMethod, CryptoSuite cryptoSuite, Type? preferredFormat) =>
        {
            //TOOD: If a preferred format is provided and it matches one of the well-known formats, return it. No other reasong at the moment...
            //Should there be a parameter "application" or something to that effect, as it probably can't be covered with "preferred format".
            return (didMethod, cryptoSuite, preferredFormat) switch
            {
                var (method, suite, pfa) when pfa == WellKnownKeyFormats.PublicKeyJwk => WellKnownKeyFormats.PublicKeyJwk,
                var (method, suite, pfa) when pfa == WellKnownKeyFormats.PublicKeyPem => WellKnownKeyFormats.PublicKeyPem,
                var (method, suite, pfa) when pfa == WellKnownKeyFormats.PublicKeyBase58 => WellKnownKeyFormats.PublicKeyBase58,
                var (method, suite, pfa) when pfa == WellKnownKeyFormats.PublicKeyHex => WellKnownKeyFormats.PublicKeyHex,
                var (method, suite, pfa) when pfa == WellKnownKeyFormats.PublicKeyMultibase => WellKnownKeyFormats.PublicKeyMultibase,
                var (method, suite, pfa) when suite is JsonWebKey2020 => WellKnownKeyFormats.PublicKeyJwk,
                var (method, suite, pfa) when suite is Multikey => WellKnownKeyFormats.PublicKeyMultibase,
                _ => throw new ArgumentException($"Unsupported preferred format: ")
            };
        };


        public static KeyFormatCreator DefaultKeyFormatCreator = (Type format, PublicKeyMemory keyMaterial) =>
        {
            Tag tag = keyMaterial.Tag;
            CryptoAlgorithm cryptoAlgorithm = (CryptoAlgorithm)tag[typeof(CryptoAlgorithm)];
            Purpose purpose = (Purpose)tag[typeof(Purpose)];

            //Select the appropriate encoder based on the format.
            BufferAllocationEncodeDelegate? encoder = DefaultEncoderSelector.Select(format);

            return format switch
            {
                var pfa when format == WellKnownKeyFormats.PublicKeyJwk => new PublicKeyJwk
                {
                    Header = KeyHeaderConversion.DefaultAlgorithmToJwkConverter(cryptoAlgorithm, purpose, keyMaterial.AsReadOnlySpan())
                },
                var pfa when format == WellKnownKeyFormats.PublicKeyMultibase => new PublicKeyMultibase(KeyHeaderConversion.DefaultAlgorithmToBase58Converter(cryptoAlgorithm, purpose, keyMaterial.AsReadOnlySpan(), encoder)),                
                _ => throw new ArgumentException($"Unsupported format: {format}")
            };
        };
    }
}
