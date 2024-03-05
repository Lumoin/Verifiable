using System;
using Verifiable.Core;
using Verifiable.Core.Builders;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Did;
using Verifiable.Core.Did.Methods;

namespace Verifiable.Tests.Builders
{
    /// <summary>
    /// These are extension methods for the various DID builders to make building DID documents more straightforward.
    /// </summary>
    public static class DidBuilderExtensions
    {
        public static VerificationMethod CreateVerificationMethod(
            PublicKeyMemory publicKey,
            CryptoSuite cryptoSuite,
            string verificationMethodId,
            string controller)
        {
            return CreateVerificationMethod<GenericDidMethod>(
                publicKey,
                cryptoSuite,
                verificationMethodId,
                controller,
                SsiKeyFormatSelector.DefaultKeyFormatSelector,
                SsiKeyFormatSelector.DefaultKeyFormatCreator);
        }


        public static VerificationMethod CreateVerificationMethod<TDidMethod>(
            PublicKeyMemory publicKey,
            CryptoSuite cryptoSuite,
            string verificationMethodId,
            string controller) where TDidMethod: GenericDidMethod
        {
            return CreateVerificationMethod<TDidMethod>(
                publicKey,
                cryptoSuite,
                verificationMethodId,
                controller,
                SsiKeyFormatSelector.DefaultKeyFormatSelector,
                SsiKeyFormatSelector.DefaultKeyFormatCreator);
        }


        public static VerificationMethod CreateVerificationMethod<TDidMethod>(
            PublicKeyMemory publicKey,
            CryptoSuite cryptoSuite,
            string verificationMethodId,
            string controller,            
            KeyFormatSelector keyFormatSelector,
            KeyFormatCreator keyFormatCreator) where TDidMethod: GenericDidMethod
        {
            //Determine the key format type using the provided selector.
            Type keyFormatType = keyFormatSelector(typeof(TDidMethod), cryptoSuite);

            //Creates the key format using the provided creator.
            KeyFormat keyFormat = keyFormatCreator(keyFormatType, publicKey);
            
            //Finally, construct the verification method.
            return new VerificationMethod
            {
                Id = verificationMethodId,
                Type = cryptoSuite,
                Controller = controller,
                KeyFormat = keyFormat
            };
        }


        public static TBuilder WithVerificationMethod<TBuilder>(
            this TBuilder builder,
            string verificationMethodId,
            CryptoSuite cryptoSuite,
            string controller,
        PublicKeyMemory publicKey) where TBuilder: Builder<DidDocument, BuildState, TBuilder>
        {
            return builder.With((didDocument, _, buildInvariant) =>
            {
                // Determine the key format based on the builder type and crypto suite
                var keyFormatSelected = SsiKeyFormatSelector.DefaultKeyFormatSelector(typeof(TBuilder), cryptoSuite);
                var keyFormat = SsiKeyFormatSelector.DefaultKeyFormatCreator(keyFormatSelected, publicKey);

                // Create and add the verification method
                var verificationMethod = new VerificationMethod
                {
                    Id = verificationMethodId, // or construct this based on conventions
                    Type = cryptoSuite,
                    Controller = controller,
                    KeyFormat = keyFormat
                };
               
                didDocument.VerificationMethod ??= [];
                didDocument.VerificationMethod = [..didDocument.VerificationMethod, verificationMethod];                

                return didDocument;
            });
        }

        public static TBuilder WithVerificationMethod<TBuilder>(this TBuilder builder, Func<BuildState, VerificationMethod> createMethod) where TBuilder: Builder<DidDocument, BuildState, TBuilder>
        {
            return builder.With((didDocument, _, buildState) =>
            {
                VerificationMethod verificationMethod = createMethod(buildState);
                didDocument.VerificationMethod ??= [];
                didDocument.VerificationMethod = [.. didDocument.VerificationMethod, verificationMethod];
                
                return didDocument;
            });
        }


        public static TBuilder WithService<TBuilder>(this TBuilder builder, Action<DidDocument, Service> configureService) where TBuilder: Builder<DidDocument, BuildState, TBuilder>
        {
            return builder.With((didDocument, _, buildState) =>
            {                
                var service = new Service();
                configureService(didDocument, service);
                didDocument.Service ??= [];
                didDocument.Service = [.. didDocument.Service, service];
                
                return didDocument;
            });
        }
    }
}
