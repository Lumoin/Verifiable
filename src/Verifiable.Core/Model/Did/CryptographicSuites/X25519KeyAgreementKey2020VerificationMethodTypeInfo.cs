using System.Linq;

namespace Verifiable.Core.Model.Did.CryptographicSuites
{
    public sealed class X25519KeyAgreementKey2020VerificationMethodTypeInfo: VerificationMethodTypeInfo
    {
        public static X25519KeyAgreementKey2020VerificationMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "X25519KeyAgreementKey2020",
            DefaultKeyFormatType = typeof(PublicKeyMultibase),
            Contexts = new[] { "https://w3id.org/security/suites/x25519-2020/v1" }.ToList().AsReadOnly()
        };
    }
}