namespace Verifiable.Core.Did.CryptographicSuites
{
    //TODO: This is currently only in some test that has this obsolete suite.
    public sealed class X25519KeyAgreementKey2019 : CryptographicSuite
    {
        public static readonly X25519KeyAgreementKey2019 Instance = new();
        private X25519KeyAgreementKey2019() { }

        public override string VerificationMethodType => "X25519KeyAgreementKey2019";
        public override string ProofType => "X25519KeyAgreementKey2019";
        public override string[] VerificationMethodContexts => [];
        public override string[] ProofContexts => [];
    }
}
