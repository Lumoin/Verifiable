namespace Verifiable.Core.Did.CryptographicSuites
{
    //TODO: This is currently only in some test that has this obsolete suite.
    public sealed class Ed25519VerificationKey2018 : CryptographicSuite
    {
        public static readonly Ed25519VerificationKey2018 Instance = new();
        private Ed25519VerificationKey2018() { }

        public override string VerificationMethodType => "Ed25519VerificationKey2018";
        public override string ProofType => "Ed25519VerificationKey2018";
        public override string[] VerificationMethodContexts => [];
        public override string[] ProofContexts => [];
    }
}
