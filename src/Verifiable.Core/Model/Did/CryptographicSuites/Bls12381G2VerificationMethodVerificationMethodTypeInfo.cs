using System.Linq;

namespace Verifiable.Core.Model.Did.CryptographicSuites
{
    public sealed class Bls12381G2VerificationMethodVerificationMethodTypeInfo: VerificationMethodTypeInfo
    {
        public static Bls12381G2VerificationMethodVerificationMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "Bls12381G2Key2020",
            DefaultKeyFormatType = typeof(PublicKeyMultibase),
            Contexts = new[] { "https://w3id.org/security/suites/bls12381-2020/v1" }.ToList().AsReadOnly()
        };
    }
}