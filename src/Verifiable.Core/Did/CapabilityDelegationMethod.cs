using System.Diagnostics;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// https://www.w3.org/TR/did-core/#verification-methods
    /// </summary>
    [DebuggerDisplay("CapabilityDelegationMethod(Id = {Id}, IsEmbeddedVerification = {IsEmbeddedVerification})")]
    public class CapabilityDelegationMethod: VerificationRelationship
    {
        public CapabilityDelegationMethod(string verificationReferenceId) : base(verificationReferenceId) { }

        public CapabilityDelegationMethod(VerificationMethod embeddedVerification) : base(embeddedVerification) { }
    }
}
