using System;
using System.Collections.Generic;
using Verifiable.Core.Did;


namespace Verifiable.Core.Credential
{
    public class Credential
    {
        public Context? Context { get; set; }

        public string? Id { get; set; }

        public List<string>? Type { get; set; }

        public string? Issuer { get; set; }

        public DateTime IssuanceDate { get; set; }

        public Dictionary<string, object>? CredentialSubject { get; set; }
    }


    public class VerifiableCredential: Credential
    {
        public Proof? Proof { get; set; }
    }


    public class Proof
    {
        public string? Type { get; set; }
        public DateTime? Created { get; set; }
        public string? VerificationMethod { get; set; }
        public string? ProofPurpose { get; set; }
        public string? ProofValue { get; set; }
    }
}
