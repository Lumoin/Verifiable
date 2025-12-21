using System;
using System.Collections.ObjectModel;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Represents a cryptographic proof type used in Verifiable Credentials and DIDs.
    /// </summary>
    /// <remarks>
    /// A proof type defines the envelope and cryptographic structure for producing and verifying digital signatures
    /// in Verifiable Credentials and DID documents. It includes information such as the proof type name,
    /// required JSON-LD contexts, and compatibility logic for verification methods.
    ///
    /// <para>
    /// This concept is described in the
    /// <a href="https://www.w3.org/TR/vc-data-integrity/">
    /// W3C Verifiable Credentials Data Integrity specification</a>, particularly in Section 5,
    /// where fields like <c>type</c>, <c>cryptosuite</c>, and <c>verificationMethod</c> are defined as part of the proof structure.
    /// </para>
    /// </remarks>
    public class ProofTypeInfo
    {
        /// <summary>
        /// The string identifier of the proof type, such as <c>"DataIntegrityProof"</c>
        /// or <c>"Ed25519Signature2020"</c>. This value maps to the <c>type</c> property in
        /// the <c>proof</c> object of a verifiable credential.
        /// </summary>
        public required string TypeName { get; init; }

        /// <summary>
        /// The list of JSON-LD context URIs that define the terms and semantics
        /// used by this proof type. These contexts must be present when expressing
        /// the proof in a verifiable credential.
        /// </summary>
        public required ReadOnlyCollection<string> Contexts { get; init; }

        /// <summary>
        /// A predicate function that determines whether a given verification method type
        /// is compatible with this proof type.
        /// </summary>
        /// <remarks>
        /// Compatibility means that the method type:
        /// <list type="bullet">
        /// <item><description>Uses a key format accepted by the cryptographic suite.</description></item>
        /// <item><description>Is semantically and cryptographically valid for this proof structure.</description></item>
        /// </list>
        /// <para>
        /// This behavior follows validation requirements described in the
        /// <a href="https://www.w3.org/TR/vc-data-integrity/">W3C VC Data Integrity specification</a>,
        /// Section 5.2, which defines how verification methods are validated against cryptographic suites.
        /// </para>
        /// </remarks>
        public required Func<VerificationMethodTypeInfo, bool> IsCompatibleWith { get; init; }
    }
}
