namespace Verifiable.Core.Did.CryptographicSuites
{
    public sealed class JsonWebKey2020: CryptographicSuite
    {
        public static readonly JsonWebKey2020 Instance = new();
        private JsonWebKey2020() { }

        public override string VerificationMethodType => "JsonWebKey2020";
        public override string ProofType => "JsonWebSignature2020";
        public override string[] VerificationMethodContexts => ["https://w3id.org/security/suites/jws-2020/v1"];
        public override string[] ProofContexts => ["https://w3id.org/security/suites/jws-2020/v1"];
    }
}
