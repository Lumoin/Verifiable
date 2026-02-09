using System.Collections.ObjectModel;

namespace Verifiable.Core.Model.Did.CryptographicSuites
{
    public sealed class JsonWebKey2020VerificationMethodTypeInfo : VerificationMethodTypeInfo
    {
        private static readonly ReadOnlyCollection<string> ContextsArray = new(["https://w3id.org/security/suites/jws-2020/v1"]);

        public static JsonWebKey2020VerificationMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "JsonWebKey2020",
            DefaultKeyFormatType = typeof(PublicKeyJwk),
            Contexts = ContextsArray
        };
    }
}