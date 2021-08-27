using System.Diagnostics;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// https://w3c.github.io/did-core/#verification-methods
    /// </summary>
    [DebuggerDisplay("CapabilityInvocationMethod(Id = {Id}, IsEmbeddedVerification = {IsEmbeddedVerification})")]
    public class CapabilityInvocationMethod: VerificationRelationship
    {
        public CapabilityInvocationMethod(string verificationReferenceId) : base(verificationReferenceId) { }
        public CapabilityInvocationMethod(VerificationMethod embeddedVerification) : base(embeddedVerification) { }
    }
}
