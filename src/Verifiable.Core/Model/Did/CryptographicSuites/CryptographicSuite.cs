using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Represents a cryptographic suite used for signing and verifying data in the context of
    /// decentralized identifiers (DIDs) and verifiable credentials.
    /// </summary>
    /// <remarks>
    /// A cryptographic suite defines a set of supported proof types (e.g., <c>"DataIntegrityProof"</c>,
    /// <c>"Ed25519Signature2020"</c>), each of which encapsulates the algorithms and constraints
    /// required to apply a digital signature or commitment.
    ///
    /// <para>
    /// Compatibility with verification methods is determined indirectly: proof types know which
    /// verification method types are allowed. Therefore, cryptographic suites use those proof types
    /// to determine compatible keys.
    /// </para>
    /// <para>
    /// For context, see the
    /// <a href="https://www.w3.org/TR/vc-data-integrity/">W3C Verifiable Credentials Data Integrity specification</a>,
    /// which outlines how cryptographic suites and verification methods interact via proof structures.
    /// </para>
    /// </remarks>
    public abstract class CryptographicSuite
    {
        /// <summary>
        /// The proof types supported by this cryptographic suite.
        /// </summary>
        /// <remarks>
        /// Each proof type defines a valid signing and verification mechanism.
        /// These determine which verification methods can be used with this suite.
        /// </remarks>
        public abstract ReadOnlyCollection<ProofTypeInfo> ProofTypes { get; }

        /// <summary>
        /// Filters the provided verification method types to return only those that are compatible
        /// with at least one proof type in this suite.
        /// </summary>
        /// <param name="availableVerificationMethods">A set of known verification method types to evaluate.</param>
        /// <returns>
        /// The subset of verification method types that are usable with this suite's proof types.
        /// </returns>
        public IEnumerable<VerificationMethodTypeInfo> GetCompatibleVerificationMethods(IEnumerable<VerificationMethodTypeInfo> availableVerificationMethods)
        {
            return availableVerificationMethods.Where(vm => ProofTypes.Any(pt => pt.IsCompatibleWith(vm)));
        }
    }
}
