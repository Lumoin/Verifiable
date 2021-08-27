using System.Diagnostics;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// https://w3c.github.io/did-core/#verification-methods
    /// </summary>
    [DebuggerDisplay("AuthenticationMethod(Id = {Id}, IsEmbeddedVerification = {IsEmbeddedVerification})")]
    public class AuthenticationMethod: VerificationRelationship
    {
        public AuthenticationMethod(string verificationReferenceId) : base(verificationReferenceId) { }
        public AuthenticationMethod(VerificationMethod embeddedVerification) : base(embeddedVerification) { }
    }
}
