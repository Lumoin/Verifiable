using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Cryptography;
using Verifiable.Jwt;

namespace Verifiable.Core.Builders
{
    //TODO: Refactor along with MultibaseSerializer and WellKnownKeyFormats. I.e. this should use a delegate to 
    //use a user supplied Base64Url encoder.
    public static class IdentifierExtensions
    {
        public static string EncodeKey(PublicKeyMemory publicKey, KeyFormat keyFormat)
        {
            if(keyFormat is PublicKeyJwk)
            {
                return Base64Url.Encode(publicKey.AsReadOnlySpan());
            }

            CryptoAlgorithm alg = (CryptoAlgorithm)publicKey.Tag[typeof(CryptoAlgorithm)];
            Purpose purp = (Purpose)publicKey.Tag[typeof(Purpose)];

            return KeyHeaderConversion.DefaultAlgorithmToBase58Converter(alg, purp, publicKey.AsReadOnlySpan(), DefaultEncoderSelector.Select(WellKnownKeyFormats.PublicKeyMultibase));
        }
    }

#pragma warning disable CA1815 // Override equals and operator equals on value types
    public struct WebDidBuildState
#pragma warning restore CA1815 // Override equals and operator equals on value types
    {
        public PublicKeyMemory PublicKey { get; init; }
        
        public CryptoSuite Suite { get; init; }

        public string WebDomain { get; init; }
    }


    /// <summary>
    /// Builds <c>did:web</c> documents with the given parameters.
    /// </summary>
    public sealed class WebDidBuilder: Builder<DidDocument, WebDidBuildState, WebDidBuilder>
    {
        public WebDidBuilder() 
        {
            _ = With((didDocument, builder, buildInvariant) =>
            {                
                PublicKeyMemory publicKey = buildInvariant.PublicKey;
                CryptoSuite cryptoSuiteChosen = buildInvariant.Suite;

                var keyFormatSelected = SsiKeyFormatSelector.DefaultKeyFormatSelector(typeof(WebDidMethod), cryptoSuiteChosen);
                var keyFormat = SsiKeyFormatSelector.DefaultKeyFormatCreator(keyFormatSelected, publicKey);
                
                string keyIdentifier = IdentifierExtensions.EncodeKey(publicKey, keyFormat);
                if(keyFormat is PublicKeyJwk publicKeyJwk)
                {
                    publicKeyJwk.Header.Add("kid", keyIdentifier);
                }

                didDocument.VerificationMethod =
                [
                    new VerificationMethod
                    {                        
                        Id = $"{WebDidMethod.Prefix}{buildInvariant.WebDomain}#{keyIdentifier}",
                        Type = cryptoSuiteChosen,
                        Controller = $"{WebDidMethod.Prefix}{buildInvariant.WebDomain}#{keyIdentifier}",
                        KeyFormat = keyFormat
                    }
                ];

                return didDocument;
            });
        }


        public DidDocument Build(PublicKeyMemory publicKey, CryptoSuite cryptoSuite, string webDomain, bool includeDefaultContext = false)
        {
            CryptoAlgorithm alg = (CryptoAlgorithm)publicKey.Tag[typeof(CryptoAlgorithm)];
            Purpose purp = (Purpose)publicKey.Tag[typeof(Purpose)];
            
            WebDidBuildState buildState = new() { PublicKey = publicKey, Suite = cryptoSuite, WebDomain = webDomain };

            DidDocument finalDocument;
            if(includeDefaultContext)
            {
                var initialDidDoc = new DidDocument();
                _ = initialDidDoc.AddDefaultContext();

                finalDocument = Build(doc => initialDidDoc, (publicKey, cryptoSuite), (param, builder) => buildState);
            }

            finalDocument = Build((publicKey, cryptoSuite), (param, builder) => buildState);
            
            finalDocument.Id = new WebDidMethod($"{WebDidMethod.Prefix}{webDomain}");
            return finalDocument;
        }        
    }
}
