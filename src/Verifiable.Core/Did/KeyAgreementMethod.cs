using System.Diagnostics;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// https://w3c.github.io/did-core/#verification-methods
    /// </summary>
    [DebuggerDisplay("KeyAgreementMethod(Id = {Id}, IsEmbeddedVerification = {IsEmbeddedVerification})")]
    public class KeyAgreementMethod: VerificationRelationship
    {
        public KeyAgreementMethod(string verificationReferenceId) : base(verificationReferenceId) { }

        public KeyAgreementMethod(VerificationMethod embeddedVerification) : base(embeddedVerification) { }
    }
}
