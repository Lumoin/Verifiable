using System;
using System.Linq;

namespace Verifiable.Core.Did.CryptographicSuites
{
    public sealed class X25519KeyAgreementKey2019VerificationMethodTypeInfo: VerificationMethodTypeInfo
    {
#pragma warning disable CS0618 // Type or member is obsolete
        public static X25519KeyAgreementKey2019VerificationMethodTypeInfo Instance { get; } = new()
        {
            TypeName = "X25519KeyAgreementKey2019",
            DefaultKeyFormatType = typeof(PublicKeyMultibase),
            //TODO: this context here is wrong (and deprecated)!
            Contexts = new[] { "https://ns.did.ai/suites/x25519-2019/v1/" }.ToList().AsReadOnly()
        };
#pragma warning restore CS0618 // Type or member is obsolete
    }
}