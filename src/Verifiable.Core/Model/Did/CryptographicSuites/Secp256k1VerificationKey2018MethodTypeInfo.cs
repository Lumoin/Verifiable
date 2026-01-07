using System.Linq;

namespace Verifiable.Core.Model.Did
{
    public sealed class Secp256k1VerificationKey2018MethodTypeInfo : VerificationMethodTypeInfo
    {
        public static Secp256k1VerificationKey2018MethodTypeInfo Instance { get; } = new()
        {
            TypeName = "Secp256k1VerificationKey2018",
            DefaultKeyFormatType = typeof(PublicKeyMultibase),
            Contexts = new[] { "https://w3id.org/security/suites/secp256k1-2019/v1" }.ToList().AsReadOnly()
        };
    }
}