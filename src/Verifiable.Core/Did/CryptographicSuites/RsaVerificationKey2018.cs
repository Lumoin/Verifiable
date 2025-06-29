namespace Verifiable.Core.Did.CryptographicSuites
{
    //TODO: This is currently only in some test that has this obsolete suite.
    public sealed class RsaVerificationKey2018 : CryptographicSuite
    {
        public static readonly RsaVerificationKey2018 Instance = new();
        private RsaVerificationKey2018() { }

        public override string VerificationMethodType => "RsaVerificationKey2018";
        public override string ProofType => "RsaVerificationKey2018";
        public override string[] VerificationMethodContexts => [];
        public override string[] ProofContexts => [];
    }
}
