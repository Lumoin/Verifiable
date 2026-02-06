using System.Linq;

namespace Verifiable.Core.Model.Did.CryptographicSuites
{
    public sealed class JwsVerificationKey2020VerificationMethodTypeInfo: VerificationMethodTypeInfo
    {
#pragma warning disable CS0618 // Type or member is obsolete
        public static JwsVerificationKey2020VerificationMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "JwsVerificationKey2020",
            DefaultKeyFormatType = typeof(PublicKeyJwk),
            Contexts = new[] { "https://w3id.org/security/suites/jws-2020/v1" }.ToList().AsReadOnly()
        };
#pragma warning restore CS0618 // Type or member is obsolete
    }
}