using System.Linq;

namespace Verifiable.Core.Model.Did.CryptographicSuites
{
    public sealed class RsaVerificationKey2018VerificationMethodTypeInfo : VerificationMethodTypeInfo
    {
#pragma warning disable CS0618 // Type or member is obsolete
        public static RsaVerificationKey2018VerificationMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "RsaVerificationKey2018",
            DefaultKeyFormatType = typeof(PublicKeyPem), // RSA keys often use PEM format
            Contexts = new[] { "https://w3id.org/security/suites/rsa-2018/v1" }.ToList().AsReadOnly(),
        };
#pragma warning restore CS0618 // Type or member is obsolete
    }
}