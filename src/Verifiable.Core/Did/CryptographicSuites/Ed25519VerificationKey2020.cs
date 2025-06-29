namespace Verifiable.Core.Did.CryptographicSuites
{
    public sealed class Ed25519VerificationKey2020 : CryptographicSuite
    {
        public static readonly Ed25519VerificationKey2020 Instance = new();
        private Ed25519VerificationKey2020() { }

        public override string VerificationMethodType => "Ed25519VerificationKey2020";
        public override string ProofType => "Ed25519Signature2020";
        public override string[] VerificationMethodContexts => ["https://w3id.org/security/suites/ed25519-2020/v1"];
        public override string[] ProofContexts => ["https://w3id.org/security/suites/ed25519-2020/v1"];
    }
}
