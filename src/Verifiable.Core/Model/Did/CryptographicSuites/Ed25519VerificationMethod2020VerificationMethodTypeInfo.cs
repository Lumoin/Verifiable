using System.Collections.ObjectModel;

namespace Verifiable.Core.Model.Did.CryptographicSuites
{
    /// <summary>
    /// The <c>Ed25519VerificationKey2020</c> verification method type: an Ed25519 public key encoded as
    /// <see cref="PublicKeyMultibase"/>, per the Ed25519 Signature 2020 suite.
    /// </summary>
    public sealed class Ed25519VerificationMethod2020VerificationMethodTypeInfo: VerificationMethodTypeInfo
    {
        private static ReadOnlyCollection<string> ContextsArray { get; } = new(new[] { "https://w3id.org/security/suites/ed25519-2020/v1" });


        /// <summary>The shared <see cref="Ed25519VerificationMethod2020VerificationMethodTypeInfo"/> instance.</summary>
        public static Ed25519VerificationMethod2020VerificationMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "Ed25519VerificationKey2020",
            DefaultKeyFormatType = typeof(PublicKeyMultibase),
            Contexts = ContextsArray
        };
    }
}
