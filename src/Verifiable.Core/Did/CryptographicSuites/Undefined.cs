namespace Verifiable.Core.Did.CryptographicSuites
{
    public sealed class Undefined : CryptographicSuite
    {
        public static readonly Undefined Instance = new();
        private Undefined() { }

        public override string VerificationMethodType => "Undefined";
        public override string ProofType => "Undefined";
        public override string[] VerificationMethodContexts => [];
        public override string[] ProofContexts => [];
    }
}
