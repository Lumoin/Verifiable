namespace Verifiable.Core.Did.CryptographicSuites
{
    /// <summary>
    /// <para>Represents a cryptographic suite as defined in the W3C DID specification.</para>
    ///
    /// <para>According to <see href="https://www.w3.org/TR/did-1.0/#terminology">W3C DID Terminology</see>:
    /// "A specification defining the usage of specific cryptographic primitives in order to achieve
    /// a particular security goal. These documents are often used to specify verification methods,
    /// digital signature types, their identifiers, and other related properties."</para>
    ///
    /// <para>A <see cref="CryptographicSuite"/> provides the technical specifications for both:</para>
    /// <list type="number">
    /// <item>
    /// <description><strong>Verification Methods</strong>: How cryptographic material is represented
    /// in DID documents, including the verification method type and required JSON-LD contexts.</description>
    /// </item>
    /// <item>
    /// <description><strong>Data Integrity Proofs</strong>: How cryptographic proofs are created and verified,
    /// including proof types and required JSON-LD contexts.</description>
    /// </item>
    /// </list>
    ///
    /// <para><strong>Key Format Selection:</strong> This class deliberately does not specify supported key formats.
    /// Key format selection is handled externally via <see cref="SsiKeyFormatSelector"/> to provide maximum
    /// flexibility for different DID methods, application requirements, and user preferences. This separation
    /// of concerns allows for complex selection logic while keeping cryptographic suite definitions focused
    /// on their core specifications.</para>
    ///
    /// <para><strong>Extensibility Pattern:</strong> This class uses C# 14 extensions to provide a clean,
    /// discoverable API while maintaining extensibility. Library-defined suites are accessible via
    /// <c>CryptoSuite.Ed25519</c> syntax through <see cref="CryptoSuiteExtensions"/>.
    /// Applications can define custom suites and make them available with the same syntax by creating
    /// their own extension groups. This pattern ensures type safety while providing a unified API
    /// for both built-in and user-defined cryptographic suites.</para>
    ///
    /// <para>For more context on the architectural decisions around key format definitions in W3C specifications,
    /// see <see href="https://github.com/w3c/vc-di-ecdsa/issues/76">W3C VC-DI-ECDSA Issue #76</see> regarding
    /// the duplication of Multikey definitions across different specifications.</para>
    /// </summary>
    public abstract class CryptographicSuite
    {
        /// <summary>
        /// The verification method type identifier used in DID documents.
        /// </summary>
        public abstract string VerificationMethodType { get; }

        /// <summary>
        /// The proof type identifier used in Data Integrity proofs.
        /// </summary>
        public abstract string ProofType { get; }

        /// <summary>
        /// The JSON-LD context URLs required for verification methods in DID documents.
        /// These contexts provide semantic definitions for the verification method type.
        /// </summary>
        public abstract string[] VerificationMethodContexts { get; }

        /// <summary>
        /// The JSON-LD context URLs required for Data Integrity proofs.
        /// These contexts provide semantic definitions for the proof type.
        /// </summary>
        public abstract string[] ProofContexts { get; }
    }
}