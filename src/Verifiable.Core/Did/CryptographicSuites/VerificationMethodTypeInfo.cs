using System;
using System.Collections.Generic;

namespace Verifiable.Core.Did.CryptographicSuites
{
    /// <summary>
    /// Represents a verification method type used in DID documents and verifiable credentials.
    /// </summary>
    /// <remarks>
    /// A verification method type describes how public keys are represented and interpreted in
    /// decentralized identity (DID) systems and verifiable credential proofs. It defines:
    /// <list type="bullet">
    /// <item><description>The <c>type</c> string (e.g., <c>"Ed25519VerificationKey2020"</c>).</description></item>
    /// <item><description>The default .NET key format type used for serialization or creation.</description></item>
    /// <item><description>The required JSON-LD contexts used in DID documents.</description></item>
    /// </list>
    /// <para>
    /// This aligns with the concept of <em>verification method</em> in the
    /// <a href="https://www.w3.org/TR/did-core/">W3C DID Core specification</a>,
    /// which defines public key material and how it is bound to cryptographic proofs.
    /// </para>
    /// </remarks>
    public class VerificationMethodTypeInfo
    {
        /// <summary>
        /// The unique string identifier of this verification method type, such as
        /// <c>"Ed25519VerificationKey2020"</c> or <c>"JsonWebKey2020"</c>.
        /// </summary>
        public required string TypeName { get; init; }

        /// <summary>
        /// The default .NET type used to represent key material for this method type.
        /// </summary>
        /// <remarks>
        /// This is typically used when generating or parsing DID documents,
        /// or when selecting a format for signing keys.
        /// </remarks>
        public required Type DefaultKeyFormatType { get; init; }

        /// <summary>
        /// A list of JSON-LD context URIs that must be included when expressing this method
        /// in a DID document. These define the semantics and vocabulary of the method.
        /// </summary>
        public required IReadOnlyCollection<string> Contexts { get; init; }
    }
}
