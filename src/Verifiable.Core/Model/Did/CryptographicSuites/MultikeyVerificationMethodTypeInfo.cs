using System.Linq;

namespace Verifiable.Core.Model.Did.CryptographicSuites
{
    public sealed class MultikeyVerificationMethodTypeInfo : VerificationMethodTypeInfo
    {
        public static MultikeyVerificationMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "Multikey",
            DefaultKeyFormatType = typeof(PublicKeyMultibase),
            Contexts = new[] { "https://w3id.org/security/multikey/v1" }.ToList().AsReadOnly()
        };
    }
}