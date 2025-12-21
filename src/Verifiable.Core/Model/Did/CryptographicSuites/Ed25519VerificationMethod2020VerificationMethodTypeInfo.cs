using System.Collections.ObjectModel;

namespace Verifiable.Core.Model.Did
{
    public sealed class Ed25519VerificationMethod2020VerificationMethodTypeInfo: VerificationMethodTypeInfo
    {
        private static readonly ReadOnlyCollection<string> ContextsArray = new(new[] { "https://w3id.org/security/suites/ed25519-2020/v1" });


        public static Ed25519VerificationMethod2020VerificationMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "Ed25519VerificationKey2020",
            DefaultKeyFormatType = typeof(PublicKeyMultibase),
            Contexts = ContextsArray
        };
    }
}