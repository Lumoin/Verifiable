using System;
using Verifiable.Core.Builders;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;
using Verifiable.Core.Did.Methods;

namespace Verifiable.Core.Credential
{
#pragma warning disable CA1815 // Override equals and operator equals on value types
    public struct VerifiableCredentialBuildState
#pragma warning restore CA1815 // Override equals and operator equals on value types
    {
        public PublicKeyMemory PublicKey { get; init; }

        public CryptoSuite Suite { get; init; }

        public string WebDomain { get; init; }
    }


    /// <summary>
    /// ...
    /// </summary>
    public sealed class VerifiedCredentialBuilder: Builder<VerifiableCredential, VerifiableCredentialBuildState, VerifiedCredentialBuilder>
    {
        public VerifiedCredentialBuilder()
        {
            _ = With((verifiableCredential, builder, buildInvariant) =>
            {
                verifiableCredential.Proof = new Proof
                {
                    Type = buildInvariant.Suite.CryptoSuiteId,
                    ProofPurpose = "",
                    ProofValue = "",
                    VerificationMethod = "",
                    Created = DateTime.UtcNow
                };

                return verifiableCredential;
            });
        }


        public VerifiableCredential Build(PublicKeyMemory publicKey, CryptoSuite cryptoSuite, string webDomain)
        {
            CryptoAlgorithm alg = (CryptoAlgorithm)publicKey.Tag[typeof(CryptoAlgorithm)];
            Purpose purp = (Purpose)publicKey.Tag[typeof(Purpose)];

            VerifiableCredentialBuildState buildState = new() { PublicKey = publicKey, Suite = cryptoSuite, WebDomain = webDomain };

            VerifiableCredential finalDocument;
            /*if(includeDefaultContext)
            {
                var initialDidDoc = new VerifiableCredential();

                finalDocument = Build(doc => initialDidDoc, (publicKey, cryptoSuite), (param, builder) => buildState);
            }*/

            finalDocument = Build((publicKey, cryptoSuite), (param, builder) => buildState);

            finalDocument.Id = new WebDidMethod($"{WebDidMethod.Prefix}:{webDomain}");
            return finalDocument;
        }
    }
}
