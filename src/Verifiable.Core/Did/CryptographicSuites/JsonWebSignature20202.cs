using System;
using System.Collections.ObjectModel;
using System.Linq;

namespace Verifiable.Core.Did.CryptographicSuites
{
    public sealed class JsonWebSignature20202: CryptographicSuite2
    {
        public static readonly JsonWebSignature20202 Instance = new();

        private JsonWebSignature20202() { }


        private static readonly ProofTypeInfo JwsProofType = new("JsonWebSignature2020",
            new[] { "https://w3id.org/security/suites/jws-2020/v1" },
            vm => vm.DefaultKeyFormatType == typeof(PublicKeyJwk) ||
                  (vm.CompatibleKeyFormats?.Contains(typeof(PublicKeyJwk)) == true)
        );

        public override ReadOnlyCollection<ProofTypeInfo> ProofTypes => new[] { JwsProofType }.ToList().AsReadOnly();
    }
}
