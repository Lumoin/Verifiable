using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Delegate for converting a verification method to algorithm representation.
    /// </summary>
    public delegate (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, IMemoryOwner<byte> keyMaterial) VerificationMethodToAlgorithmConverterDelegate(VerificationMethod method, BaseMemoryPool memoryPool);


    /// <summary>
    /// Provides conversions from DID verification methods to cryptographic algorithm representations.
    /// </summary>
    public static class VerificationMethodCryptoConversions
    {
        /// <summary>
        /// Default converter from verification method to algorithm representation.
        /// </summary>
        public static VerificationMethodToAlgorithmConverterDelegate DefaultConverter => (method, memoryPool) =>
        {
            if(method == null)
            {
                throw new ArgumentNullException(nameof(method), "VerificationMethod cannot be null.");
            }

            if(string.IsNullOrWhiteSpace(method.Type))
            {
                throw new ArgumentException("VerificationMethod must have a valid 'Type' property.", nameof(method));
            }

            if(method.KeyFormat == null)
            {
                throw new ArgumentException("VerificationMethod must have a valid 'KeyFormat' property.", nameof(method));
            }

            return method.KeyFormat switch
            {
                PublicKeyMultibase multibaseKey when !string.IsNullOrWhiteSpace(multibaseKey.Key) =>
                    CryptoFormatConversions.DefaultBase58ToAlgorithmConverter(
                        multibaseKey.Key,
                        memoryPool,
                        DefaultCoderSelector.SelectDecoder(multibaseKey.GetType())),

                //This converter's own contract answers a key format it reads no key of with its ArgumentException, so the JWK
                //reconstruction's refusal is answered as that format's; its key is answered in the converter's own shape.
                PublicKeyJwk jwkKey when jwkKey.Header is Dictionary<string, object> jwkHeader =>
                    CryptoFormatConversions.DefaultJwkToAlgorithmConverter(jwkHeader, memoryPool, DefaultCoderSelector.SelectDecoder(jwkKey.GetType())) switch
                    {
                        JwkKeyReconstructed key => (key.Algorithm, key.Purpose, key.Scheme, key.KeyMaterial),
                        JwkKeyRefused refused => throw new ArgumentException(
                            $"The JWK of VerificationMethod of Type '{method.Type}' states no public key: {refused.Description}", nameof(method)),
                        _ => throw new InvalidOperationException("The JWK reconstruction answered a reconstruction it never answers.")
                    },

                _ => throw new ArgumentException($"Unsupported KeyFormat for VerificationMethod of Type '{method.Type}'.", nameof(method))
            };
        };
    }
}
