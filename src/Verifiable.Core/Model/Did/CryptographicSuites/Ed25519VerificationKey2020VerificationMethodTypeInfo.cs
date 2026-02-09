using System.Linq;

namespace Verifiable.Core.Model.Did.CryptographicSuites
{
    public sealed class Ed25519VerificationKey2020VerificationMethodTypeInfo : VerificationMethodTypeInfo
    {
        public static Ed25519VerificationKey2020VerificationMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "Ed25519VerificationKey2020",
            DefaultKeyFormatType = typeof(PublicKeyMultibase),
            Contexts = new[] { "https://w3id.org/security/suites/ed25519-2020/v1" }.ToList().AsReadOnly()
        };
    }
}