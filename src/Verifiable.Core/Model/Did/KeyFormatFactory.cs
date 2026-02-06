using System;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Jose;

namespace Verifiable.Core.Model.Did
{
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
        /// Base58: A binary-to-text encoding format that is commonly used in cryptocurrencies like Bitcoin.
        /// Designed to avoid visual ambiguity between similar-looking characters (like 'O' and '0').
        /// This format is often used to encode public keys and addresses in blockchain systems.
        /// </summary>
        [Obsolete("Test JSON material still contains these CompatibleKeyFormatsArray.")]
        public static Type PublicKeyBase58 { get; } = typeof(PublicKeyBase58);

        /// <summary>
        /// Multibase: A format for encoding binary data as strings, along with an indicator of the encoding used.
        /// Designed for use in systems where multiple binary-to-text encoding schemes may be used.
        /// <see href="https://github.com/multiformats/multibase">More info</see>
        /// </summary>
        public static Type PublicKeyMultibase { get; } = typeof(PublicKeyMultibase);
    }


    /// <summary>
    /// Creates a <see cref="KeyFormat"/> based on the provided <paramref name="format"/> and <paramref name="keyMaterial"/>
    /// </summary>
    /// <param name="format">A well known key format. If it's a known type for <c>Verifiable</c>, it is enumerated in <see cref="KeyFormatFactory"/>.</param>
    /// <param name="keyMaterial">The key material from which to create the <see cref="KeyFormat"/>.</param>
    /// <returns>The created <see cref="KeyFormat"/>.</returns>
    public delegate KeyFormat KeyFormatCreator(Type format, PublicKeyMemory keyMaterial);

    /// <summary>
    /// <para>Represents well-known key formats utilized in the context of decentralized identifiers (DIDs)
    /// and verifiable credentials.</para>
    ///
    /// <para>The choice of a key format is inherently linked to the cryptographic suite (<see cref="VerificationMethodTypeInfo"/>) in use.
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
    public static class KeyFormatFactory
    {
        /// <summary>
        /// Returns a delegate that creates a <see cref="KeyFormat"/> based on the provided <paramref name="format"/> and <paramref name="keyMaterial"/>.
        /// </summary>
        public static KeyFormatCreator DefaultKeyFormatCreator { get; set; } = (Type format, PublicKeyMemory keyMaterial) =>
        {
            Tag tag = keyMaterial.Tag;
            CryptoAlgorithm cryptoAlgorithm = tag.Get<CryptoAlgorithm>();
            Purpose purpose = tag.Get<Purpose>();

            //Select the appropriate encoder based on the format that was selected based on choice in
            //SsiKeyFormatSelector.DefaultKeyFormatSelector.
            EncodeDelegate encoder = DefaultCoderSelector.SelectEncoder(format);

            return format switch
            {
                //TODO: Here .DefaultAlgorithmToJwkConverter blindly assumes the key material is COMPRESSED.
                Type pfa when format == WellKnownKeyFormats.PublicKeyJwk => new PublicKeyJwk { Header = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(cryptoAlgorithm, purpose, keyMaterial.AsReadOnlySpan(), encoder) },
                Type pfa when format == WellKnownKeyFormats.PublicKeyMultibase => new PublicKeyMultibase(CryptoFormatConversions.DefaultAlgorithmToBase58Converter(cryptoAlgorithm, purpose, keyMaterial.AsReadOnlySpan(), encoder)),
                _ => throw new ArgumentException($"Unsupported format: \"{format}\".")
            };
        };
    }
}