namespace Verifiable.Core.Did.CryptographicSuites
{
    public sealed class Secp256k1VerificationKey2018 : CryptographicSuite
    {
        public static readonly Secp256k1VerificationKey2018 Instance = new();
        private Secp256k1VerificationKey2018() { }

        public override string VerificationMethodType => "Secp256k1VerificationKey2018";
        public override string ProofType => "EcdsaSecp256k1Signature2019";
        public override string[] VerificationMethodContexts => ["https://w3id.org/security/suites/secp256k1-2019/v1"];
        public override string[] ProofContexts => ["https://w3id.org/security/suites/secp256k1-2019/v1"];
    }
}
