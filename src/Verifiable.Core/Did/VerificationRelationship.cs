using System.Diagnostics;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// https://w3c.github.io/did-core/#verification-methods
    /// The reference Id field is string because it can be a fragment like "#key-1".
    /// </summary>
    [DebuggerDisplay("VerificationRelationship(Id = {Id}, IsEmbeddedVerification = {IsEmbeddedVerification})")]
    public abstract class VerificationRelationship
    {
        public string? VerificationReferenceId { get; }

        public VerificationMethod? EmbeddedVerification { get; }

        protected VerificationRelationship(string verificationReferenceId) => VerificationReferenceId = verificationReferenceId;

        protected VerificationRelationship(VerificationMethod embeddedVerification) => EmbeddedVerification = embeddedVerification;

        public string? Id => EmbeddedVerification == null ? VerificationReferenceId : EmbeddedVerification.Id?.ToString();

        public bool IsEmbeddedVerification { get { return EmbeddedVerification != null; } }
    }
}
