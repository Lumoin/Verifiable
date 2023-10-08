using Verifiable.Core.Cryptography;
using Verifiable.Core.Did;
using Verifiable.Cryptography;

namespace Verifiable.Core.Builders
{
    public struct BuildState
    {
        public string EncodedKey { get; set; }

        public PublicKeyMemory PublicKey { get; set; }

        public CryptoSuite Suite { get; set; }
    }


    /// <summary>
    /// ...
    /// </summary>
    public sealed class KeyDidBuilder: Builder<DidDocument, BuildState, KeyDidBuilder>
    {
        public KeyDidBuilder()
        {
            _ = With((didDocument, builder, buildInvariant) =>
            {
                string encodedPublicKey = buildInvariant.EncodedKey;
                PublicKeyMemory publicKey = buildInvariant.PublicKey;
                CryptoSuite cryptoSuiteChosen = buildInvariant.Suite;

                var keyFormatSelected = SsiKeyFormatSelector.DefaultKeyFormatSelector(typeof(KeyDidId), cryptoSuiteChosen);
                var keyFormat = SsiKeyFormatSelector.DefaultKeyFormatCreator(keyFormatSelected, publicKey);
                didDocument.VerificationMethod = new[]
                {
                    new VerificationMethod
                    {
                        //TODO: Add a method to create 
                        Id = $"did:key:{encodedPublicKey}#{encodedPublicKey}",
                        Type = cryptoSuiteChosen,
                        Controller = $"did:key:{encodedPublicKey}",
                        KeyFormat = keyFormat
                    }
                };

                return didDocument;
            })
            .With((didDocument, builder, buildInvariant) =>
            {
                string encodedPublicKey = buildInvariant.EncodedKey;
                PublicKeyMemory publicKey = buildInvariant.PublicKey;
                var base58EncodedKey = encodedPublicKey;

                var didId = $"did:key:{base58EncodedKey}";
                var didFormalId = $"did:key:{base58EncodedKey}#{base58EncodedKey}";

                didDocument.Id = new KeyDidId(didId);

                didDocument.AssertionMethod = new[] { new AssertionMethod(didFormalId) };
                didDocument.Authentication = new[] { new AuthenticationMethod(didFormalId) };
                didDocument.CapabilityDelegation = new[] { new CapabilityDelegationMethod(didFormalId) };
                didDocument.CapabilityInvocation = new[] { new CapabilityInvocationMethod(didFormalId) };
                didDocument.KeyAgreement = new[] { new KeyAgreementMethod(didFormalId) };

                return didDocument;
            });
        }


        public DidDocument Build(PublicKeyMemory publicKey, CryptoSuite cryptoSuite, bool includeDefaultContext = false)
        {
            CryptoAlgorithm alg = (CryptoAlgorithm)publicKey.Tag[typeof(CryptoAlgorithm)];
            Purpose purp = (Purpose)publicKey.Tag[typeof(Purpose)];

            string encodedPublicKey = KeyHeaderConversion.DefaultAlgorithmToBase58Converter(alg, purp, publicKey.AsReadOnlySpan(), DefaultEncoderSelector.Select(WellKnownKeyFormats.PublicKeyMultibase));

            BuildState buildState = new BuildState { EncodedKey = encodedPublicKey, PublicKey = publicKey, Suite = cryptoSuite };

            if(includeDefaultContext)
            {
                //TODO: See at https://w3c-ccg.github.io/did-method-key/#signature-method-creation-algorithm if verification
                //method should be created with an extension method with some parameters and checks like described
                //in that definition.
                var initialDidDoc = new DidDocument();
                initialDidDoc.AddDefaultContext();

                return Build(doc => initialDidDoc, (publicKey, cryptoSuite), (param, builder) => buildState);
            }

            return Build((publicKey, cryptoSuite), (param, builder) => buildState);
        }
    }
}
