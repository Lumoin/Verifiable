using System.Collections.Generic;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// <para>Represents a cryptographic suite, a collection of cryptographic algorithms and data formats 
    /// designed to work together for specific security features in the context of Decentralized Identifiers (DIDs) 
    /// and verifiable credentials.</para>
    ///
    /// <para>A <see cref="CryptoSuite"/> defines the technical specifications for cryptographic operations 
    /// such as signing, verification, encryption, and decryption. It may also suggest or mandate the use 
    /// of specific key formats (<see cref="KeyFormat"/>) for serialization and deserialization.</para>
    ///
    /// <para>While a cryptographic suite provides a broad range of allowed algorithms and key formats, 
    /// the actual implementation and usage may be further constrained by the DID method in use or even by 
    /// application-specific requirements. See default implementation of <see cref="SsiKeyFormatSelector"/>
    /// that makes use of <see cref="WellKnownKeyFormats"/>.</para>
    ///
    /// <para>It's important to note that the list of supported or allowed algorithms may be influenced by various factors:
    /// <list type="number">
    /// <item>
    /// <description>DID Method Constraints: The DID method in use may have its own set of allowed algorithms or key formats.</description>
    /// </item>
    /// <item>
    /// <description>Application Requirements: Specific use-cases may demand particular algorithms or key formats for compliance or interoperability.</description>
    /// </item>
    /// </list>
    /// </para>
    /// </summary>
    public record CryptoSuite
    {
        public static CryptoSuite DefaultInstance => new CryptoSuite();

        public string CryptoSuiteId { get; set; }

        public List<string> AllowedAlgorithms { get; set; }
        
        public CryptoSuite()
        {
            CryptoSuiteId = string.Empty;
            AllowedAlgorithms = new List<string>();
        }

        public CryptoSuite(string suiteIdentifier, List<string> allowedAlgorithms)
        {
            CryptoSuiteId = suiteIdentifier;
            AllowedAlgorithms = allowedAlgorithms;
        }


        /// <summary>
        /// Implicit conversion from <see cref="CryptoSuite"/> or derived crypto suites to <see langword="string"/>.
        /// </summary>
        /// <param name="cryptoSuiteId"></param>
        public static implicit operator string(CryptoSuite cryptoSuiteId) => cryptoSuiteId.CryptoSuiteId;


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="CryptoSuite"/> or derived crypto suites.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator CryptoSuite(string cryptoSuiteId) => new(cryptoSuiteId, new List<string>());
    }

       
    public record JsonWebKey2020: CryptoSuite
    {
        public static new JsonWebKey2020 DefaultInstance => new();


        public string? fakeParam;


        public JsonWebKey2020(string fakeParam)
        {
            this.fakeParam = fakeParam;
        }

        
        public JsonWebKey2020(): base("JsonWebKey2020", new List<string> { "ES256K", "RS256", "EdDSA" }) { }

        /// <summary>
        /// Implicit conversion from <see cref="JsonWebKey2020"/> or derived crypto suites to <see langword="string"/>.
        /// </summary>
        /// <param name="cryptoSuiteId"></param>
        public static implicit operator string(JsonWebKey2020 cryptoSuiteId) => cryptoSuiteId.CryptoSuiteId;


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="JsonWebKey2020"/> or derived crypto suites.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator JsonWebKey2020(string cryptoSuiteId) => new();
    }


    public record Ed25519VerificationKey2020: CryptoSuite
    {
        public Ed25519VerificationKey2020(): base("Ed25519VerificationKey2020", new List<string> { "EdDSA" }) { }


        /// <summary>
        /// Implicit conversion from <see cref="Ed25519VerificationKey2020"/> or derived crypto suites to <see langword="string"/>.
        /// </summary>
        /// <param name="cryptoSuiteId"></param>
        public static implicit operator string(Ed25519VerificationKey2020 cryptoSuiteId) => cryptoSuiteId.CryptoSuiteId;


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="Ed25519VerificationKey2020"/> or derived crypto suites.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator Ed25519VerificationKey2020(string cryptoSuiteId) => new();
    }


    public record Secp256k1VerificationKey2018: CryptoSuite
    {
        public Secp256k1VerificationKey2018() : base("Secp256k1VerificationKey2018", new List<string> { "Secp256k1" }) { }


        /// <summary>
        /// Implicit conversion from <see cref="Secp256k1VerificationKey2018"/> or derived crypto suites to <see langword="string"/>.
        /// </summary>
        /// <param name="cryptoSuiteId"></param>
        public static implicit operator string(Secp256k1VerificationKey2018 cryptoSuiteId) => cryptoSuiteId.CryptoSuiteId;


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="Secp256k1VerificationKey2018"/> or derived crypto suites.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator Secp256k1VerificationKey2018(string cryptoSuiteId) => new();
    }

    public record X25519KeyAgreementKey2020: CryptoSuite
    {
        public X25519KeyAgreementKey2020(): base("X25519KeyAgreementKey2020", new List<string> { "Ed25519", "X25519" })  { }


        /// <summary>
        /// Implicit conversion from <see cref="X25519KeyAgreementKey2020"/> or derived crypto suites to <see langword="string"/>.
        /// </summary>
        /// <param name="cryptoSuiteId"></param>
        public static implicit operator string(X25519KeyAgreementKey2020 cryptoSuiteId) => cryptoSuiteId.CryptoSuiteId;


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="X25519KeyAgreementKey2020"/> or derived crypto suites.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator X25519KeyAgreementKey2020(string cryptoSuiteId) => new();
    }


    public record Multikey: CryptoSuite
    {
        public static new Multikey DefaultInstance => new Multikey();


        public Multikey() : base("Multikey", new List<string> { }) { }


        /// <summary>
        /// Implicit conversion from <see cref="Multikey"/> or derived crypto suites to <see langword="string"/>.
        /// </summary>
        /// <param name="cryptoSuiteId"></param>
        public static implicit operator string(Multikey cryptoSuiteId) => cryptoSuiteId.CryptoSuiteId;


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="Multikey"/> or derived crypto suites.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator Multikey(string cryptoSuiteId) => new();
    }


    public record JsonWebSignature2020: CryptoSuite
    {
        public JsonWebSignature2020() : base("JsonWebSignature2020", new List<string> { "ES256K", "RS256", "EdDSA" }) { }


        /// <summary>
        /// Implicit conversion from <see cref="JsonWebSignature2020"/> or derived crypto suites to <see langword="string"/>.
        /// </summary>
        /// <param name="cryptoSuiteId"></param>
        public static implicit operator string(JsonWebSignature2020 cryptoSuiteId) => cryptoSuiteId.CryptoSuiteId;


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="JsonWebSignature2020"/> or derived crypto suites.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator JsonWebSignature2020(string cryptoSuiteId) => new();
    }
}
