using System;
using System.Collections.Generic;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Cryptography.Context;

namespace Verifiable.Core.Model.DataIntegrity
{
    /// <summary>
    /// Describes a cryptographic suite for Data Integrity proofs.
    /// A cryptosuite defines the complete algorithm combination for proof creation
    /// and verification: canonicalization, hashing, and signing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class follows the same pattern as <see cref="VerificationMethodTypeInfo"/>,
    /// providing metadata about the cryptosuite without containing actual cryptographic
    /// implementations. The implementations are registered separately in registries
    /// and resolved at runtime based on the cryptosuite identifier.
    /// </para>
    /// <para>
    /// <strong>Relationship to Data Integrity Proofs:</strong>
    /// </para>
    /// <para>
    /// In the Data Integrity specification, a proof structure contains:
    /// </para>
    /// <list type="bullet">
    /// <item><description><c>type</c>: Always <c>"DataIntegrityProof"</c> for Data Integrity proofs.</description></item>
    /// <item><description><c>cryptosuite</c>: The cryptosuite identifier (e.g., <c>"eddsa-rdfc-2022"</c>).</description></item>
    /// <item><description><c>verificationMethod</c>: Reference to the key used for signing.</description></item>
    /// <item><description><c>proofPurpose</c>: The intended purpose (e.g., <c>"assertionMethod"</c>).</description></item>
    /// <item><description><c>proofValue</c>: The multibase-encoded signature.</description></item>
    /// </list>
    /// <para>
    /// The <see cref="CryptosuiteName"/> property corresponds to the <c>cryptosuite</c> field in the proof.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-integrity/#cryptographic-suites">
    /// Data Integrity §5 Cryptographic Suites</see>.
    /// </para>
    /// </remarks>
    public class CryptosuiteInfo
    {
        /// <summary>
        /// The cryptosuite identifier as used in the proof's <c>cryptosuite</c> property.
        /// </summary>
        /// <remarks>
        /// This value is serialized directly into the proof structure.
        /// Examples: <c>"eddsa-rdfc-2022"</c>, <c>"ecdsa-rdfc-2019"</c>, <c>"ecdsa-sd-2023"</c>.
        /// </remarks>
        public required string CryptosuiteName { get; init; }

        /// <summary>
        /// The canonicalization algorithm this cryptosuite uses to transform
        /// documents into a deterministic byte representation before hashing.
        /// </summary>
        public required CanonicalizationAlgorithm Canonicalization { get; init; }

        /// <summary>
        /// The hash algorithm identifier used to hash the canonicalized document.
        /// </summary>
        /// <remarks>
        /// Common values are <c>"SHA-256"</c> and <c>"SHA-384"</c>.
        /// </remarks>
        public required string HashAlgorithm { get; init; }

        /// <summary>
        /// The cryptographic algorithm used for signing, corresponding to
        /// <see cref="CryptoAlgorithm"/> values from the key system.
        /// </summary>
        public required CryptoAlgorithm SignatureAlgorithm { get; init; }

        /// <summary>
        /// The JSON-LD context URIs required when using this cryptosuite.
        /// These contexts must be included in the document for proper interpretation.
        /// </summary>
        public required IReadOnlyList<string> Contexts { get; init; }

        /// <summary>
        /// Determines whether a verification method type is compatible with this cryptosuite.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Compatibility means the verification method can represent keys suitable for
        /// this cryptosuite's signature algorithm and can be properly serialized in
        /// the DID document or proof structure.
        /// </para>
        /// <para>
        /// For example, <c>eddsa-rdfc-2022</c> is compatible with <c>Multikey</c> and
        /// <c>Ed25519VerificationKey2020</c> verification method types, as both can
        /// represent Ed25519 public keys.
        /// </para>
        /// </remarks>
        public required Func<VerificationMethodTypeInfo, bool> IsCompatibleWith { get; init; }
    }
}