using System;
using System.Collections.Generic;
using System.Text;

namespace Verifiable.Core.Did.CryptographicSuites
{
    //TODO: This is currently only in some test that has this obsolete suite.
    public sealed class JwsVerificationKey2020 : CryptographicSuite
    {
        public static readonly JwsVerificationKey2020 Instance = new();
        private JwsVerificationKey2020() { }

        public override string VerificationMethodType => "JwsVerificationKey2020";
        public override string ProofType => "JwsVerificationKey2020";
        public override string[] VerificationMethodContexts => [];
        public override string[] ProofContexts => [];
    }
}
