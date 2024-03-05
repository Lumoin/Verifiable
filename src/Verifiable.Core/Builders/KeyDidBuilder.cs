using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Cryptography;

namespace Verifiable.Core.Builders
{
#pragma warning disable CA1815 // Override equals and operator equals on value types
    public struct BuildState
#pragma warning restore CA1815 // Override equals and operator equals on value types
    {
        public string EncodedKey { get; init; }

        public PublicKeyMemory PublicKey { get; init; }

        public CryptoSuite Suite { get; init; }
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

                var keyFormatSelected = SsiKeyFormatSelector.DefaultKeyFormatSelector(typeof(KeyDidMethod), cryptoSuiteChosen);
                var keyFormat = SsiKeyFormatSelector.DefaultKeyFormatCreator(keyFormatSelected, publicKey);
                didDocument.VerificationMethod =
                [
                    new VerificationMethod
                    {
                        //TODO: Add a method to create 
                        Id = $"did:key:{encodedPublicKey}#{encodedPublicKey}",
                        Type = cryptoSuiteChosen,
                        Controller = $"did:key:{encodedPublicKey}",
                        KeyFormat = keyFormat
                    }
                ];

                return didDocument;
            })
            .With((didDocument, builder, buildInvariant) =>
            {
                string encodedPublicKey = buildInvariant.EncodedKey;
                PublicKeyMemory publicKey = buildInvariant.PublicKey;
                var base58EncodedKey = encodedPublicKey;

                var didId = $"did:key:{base58EncodedKey}";
                var didFormalId = $"did:key:{base58EncodedKey}#{base58EncodedKey}";

                didDocument.Id = new KeyDidMethod(didId);

                didDocument.AssertionMethod = [new AssertionMethod(didFormalId)];
                didDocument.Authentication = [new AuthenticationMethod(didFormalId)];
                didDocument.CapabilityDelegation = [new CapabilityDelegationMethod(didFormalId)];
                didDocument.CapabilityInvocation = [new CapabilityInvocationMethod(didFormalId)];
                didDocument.KeyAgreement = [new KeyAgreementMethod(didFormalId)];

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
