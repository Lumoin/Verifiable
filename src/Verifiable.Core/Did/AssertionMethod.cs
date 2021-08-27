using System.Diagnostics;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// https://w3c.github.io/did-core/#verification-methods
    /// </summary>
    [DebuggerDisplay("AssertionMethod(Id = {Id}, IsEmbeddedVerification = {IsEmbeddedVerification})")]
    public class AssertionMethod: VerificationRelationship
    {
        public AssertionMethod(string verificationReferenceId) : base(verificationReferenceId) { }
        public AssertionMethod(VerificationMethod embeddedVerification) : base(embeddedVerification) { }
    }
}
