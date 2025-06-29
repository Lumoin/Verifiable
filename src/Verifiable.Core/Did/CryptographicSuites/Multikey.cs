namespace Verifiable.Core.Did.CryptographicSuites
{
    public sealed class Multikey : CryptographicSuite
    {
        public static readonly Multikey Instance = new();
        private Multikey() { }

        public override string VerificationMethodType => "Multikey";
        public override string ProofType => "DataIntegrityProof";
        public override string[] VerificationMethodContexts => ["https://w3id.org/security/multikey/v1"];
        public override string[] ProofContexts => ["https://w3id.org/security/data-integrity/v1"];
    }
}
