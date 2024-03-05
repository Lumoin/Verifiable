using System;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
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


    /// <summary>
    /// Selects a key format given a set of parameters. The purpose of this is to formalize key format selection.
    /// </summary>
    /// <param name="didMethod">The DID method. If this is known to <c>Verifiable</c> it is inherited from <see cref="GenericDidId"/>.</param>
    /// <param name="cryptoSuite">The cryptosuite. If this is known to <c>Verifiable</c> it is inherited from <see cref="CryptoSuite"/>.</param>
    /// <param name="preferredFormat">A format preference. If it's a known type for <c>Verifiable</c>, it is enumerated in <see cref="WellKnownKeyFormats"/>.</param>
    /// <returns>Returns a preferred format. If it's a known type for <c>Verifiable</c>, it is enumerated in <see cref="WellKnownKeyFormats"/>.</returns>
    public delegate Type KeyFormatSelector(Type didMethod, CryptoSuite cryptoSuite, Type? preferredFormat = null);


    /// <summary>
    /// Creates a <see cref="KeyFormat"/> based on the provided <paramref name="format"/> and <paramref name="keyMaterial"/>
    /// </summary>
    /// <param name="format">A well known key format. If it's a known type for <c>Verifiable</c>, it is enumerated in <see cref="WellKnownKeyFormats"/>.</param>
    /// <param name="keyMaterial">The key material from which to create the <see cref="KeyFormat"/>.</param>
    /// <returns>The created <see cref="KeyFormat"/>.</returns>
    public delegate KeyFormat KeyFormatCreator(Type format, PublicKeyMemory keyMaterial);


    public static class SsiKeyFormatSelector
    {
        public static KeyFormatSelector DefaultKeyFormatSelector { get; set; } = (Type didMethod, CryptoSuite cryptoSuite, Type? preferredFormat) =>
        {
            //TOOD: If a preferred format is provided and it matches one of the well-known formats, return it. No other reason at the moment...
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
                var (method, suite, pfa) when suite is Ed25519VerificationKey2020 => WellKnownKeyFormats.PublicKeyMultibase,
                _ => throw new ArgumentException($"Not matching format for the given parameters.")
            };
        };


        /// <summary>
        /// Returns a delegate that creates a <see cref="KeyFormat"/> based on the provided <paramref name="format"/> and <paramref name="keyMaterial"/>.
        /// </summary>
        public static KeyFormatCreator DefaultKeyFormatCreator { get; set; } = (Type format, PublicKeyMemory keyMaterial) =>
        {
            Tag tag = keyMaterial.Tag;
            CryptoAlgorithm cryptoAlgorithm = (CryptoAlgorithm)tag[typeof(CryptoAlgorithm)];
            Purpose purpose = (Purpose)tag[typeof(Purpose)];

            //Select the appropriate encoder based on the format that was selected based on choice in
            //SsiKeyFormatSelector.DefaultKeyFormatSelector.
            //TODO: The Base64Url is hardcoded at the moment, so it does not have a parameter. It should have one.
            BufferAllocationEncodeDelegate? encoder = DefaultEncoderSelector.Select(format);

            return format switch
            {
                var pfa when format == WellKnownKeyFormats.PublicKeyJwk => new PublicKeyJwk { Header = KeyHeaderConversion.DefaultAlgorithmToJwkConverter(cryptoAlgorithm, purpose, keyMaterial.AsReadOnlySpan()) },
                var pfa when format == WellKnownKeyFormats.PublicKeyMultibase => new PublicKeyMultibase(KeyHeaderConversion.DefaultAlgorithmToBase58Converter(cryptoAlgorithm, purpose, keyMaterial.AsReadOnlySpan(), encoder)),                
                _ => throw new ArgumentException($"Unsupported format: \"{format}\".")
            };
        };
    }
}
