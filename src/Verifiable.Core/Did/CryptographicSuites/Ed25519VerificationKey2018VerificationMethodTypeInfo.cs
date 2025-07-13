using System;
using System.Linq;

namespace Verifiable.Core.Did.CryptographicSuites
{
    public sealed class Ed25519VerificationKey2018VerificationMethodTypeInfo : VerificationMethodTypeInfo
    {
#pragma warning disable CS0618 // Type or member is obsolete
        public static Ed25519VerificationKey2018VerificationMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "Ed25519VerificationKey2018",
            DefaultKeyFormatType = typeof(PublicKeyBase58),
            Contexts = new[] { "https://w3id.org/security/suites/ed25519-2018/v1" }.ToList().AsReadOnly()
        };
#pragma warning restore CS0618 // Type or member is obsolete
    }
}