using System.Diagnostics;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// Represents a verification method in a DID document. Verification methods are used to verify 
    /// digital signatures and other cryptographic material. Each method specifies a cryptographic key 
    /// or other process to perform the verification.    
    /// </summary>
    /// <remarks>See more at <see href="Reference: https://www.w3.org/TR/did-core/#verification-methods">
    /// DID Core specification: Verification methods</see>.</remarks>
    [DebuggerDisplay("VerificationMethod(Id = {Id}, Type = {Type}, Controller = {Controller})")]
    public class VerificationMethod
    {
        /// <summary>
        /// A unique identifier for the verification method that conforms to the rules in Section 3.2 DID URL Syntax of the DID specification.
        /// </summary>
        public string? Id { get; set; }

        /// <summary>
        /// The DID of the entity that controls the verification method.
        /// </summary>
        public string? Controller { get; set; }

        /// <summary>
        /// A string that indicates the type of verification method (e.g., <see cref="PublicKeyMultibase"/>, <see cref="PublicKeyJwk"/>).
        /// </summary>
        public string? Type { get; set; }

        /// <summary>
        /// A key format object representing the public key material used for verification. Depending on the type, 
        /// this could be a publicKeyJwk or publicKeyMultibase as defined in the DID specification registries.
        /// </summary>
        public KeyFormat? KeyFormat { get; set; }
    }
}
