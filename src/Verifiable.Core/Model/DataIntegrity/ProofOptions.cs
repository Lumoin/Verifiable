using System;

namespace Verifiable.Core.Model.DataIntegrity
{
    /// <summary>
    /// Options for creating a Data Integrity proof. These options configure
    /// the metadata included in the proof structure.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When creating a proof, these options determine values for optional
    /// fields in the resulting <see cref="DataIntegrityProof"/>. Required
    /// fields like <c>type</c>, <c>cryptosuite</c>, and <c>proofValue</c>
    /// are determined by the cryptosuite and signing process.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-integrity/#proof-options">
    /// Data Integrity §4.4 Proof Options</see>.
    /// </para>
    /// </remarks>
    public sealed class ProofOptions
    {
        /// <summary>
        /// The verification method identifier (typically a DID URL) that will be
        /// included in the proof. This must reference a key that can be resolved
        /// and used to verify the signature.
        /// </summary>
        /// <remarks>
        /// Example: <c>"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"</c>
        /// </remarks>
        public required string VerificationMethod { get; init; }

        /// <summary>
        /// The purpose of the proof, indicating how the proof should be used.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The proof purpose must correspond to a verification relationship in the
        /// signer's DID document. Common values include:
        /// </para>
        /// <list type="bullet">
        /// <item><description><c>"assertionMethod"</c>: For issuing credentials.</description></item>
        /// <item><description><c>"authentication"</c>: For proving DID control.</description></item>
        /// <item><description><c>"capabilityInvocation"</c>: For invoking capabilities.</description></item>
        /// <item><description><c>"capabilityDelegation"</c>: For delegating capabilities.</description></item>
        /// </list>
        /// </remarks>
        public required string ProofPurpose { get; init; }

        /// <summary>
        /// The date and time to record as the proof creation time.
        /// If not specified, the current UTC time will be used.
        /// </summary>
        public DateTime? Created { get; init; }

        /// <summary>
        /// The date and time when the proof should be considered expired.
        /// If not specified, the proof does not expire.
        /// </summary>
        public DateTime? Expires { get; init; }

        /// <summary>
        /// An optional domain to bind the proof to. This limits the scope of
        /// the proof and prevents replay attacks across different domains.
        /// </summary>
        /// <remarks>
        /// When set, verifiers should check that the domain matches their expected value.
        /// </remarks>
        public string? Domain { get; init; }

        /// <summary>
        /// An optional challenge value for interactive protocols. The challenge
        /// should be a value previously issued by the verifier.
        /// </summary>
        /// <remarks>
        /// When set, this prevents replay attacks by ensuring the proof was
        /// created in response to a specific challenge.
        /// </remarks>
        public string? Challenge { get; init; }

        /// <summary>
        /// An optional nonce for additional randomness in the proof.
        /// </summary>
        public string? Nonce { get; init; }
    }
}