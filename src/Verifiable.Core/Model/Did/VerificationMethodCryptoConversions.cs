using System;
using System.Buffers;
using System.Collections.Generic;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Delegate for converting a verification method to algorithm representation.
    /// </summary>
    public delegate (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, IMemoryOwner<byte> keyMaterial) VerificationMethodToAlgorithmConverterDelegate(VerificationMethod method, MemoryPool<byte> memoryPool);


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

                PublicKeyJwk jwkKey when jwkKey.Header is Dictionary<string, object> jwkHeader =>
                    CryptoFormatConversions.DefaultJwkToAlgorithmConverter(
                        jwkHeader,
                        memoryPool,
                        DefaultCoderSelector.SelectDecoder(jwkKey.GetType())),

                _ => throw new ArgumentException($"Unsupported KeyFormat for VerificationMethod of Type '{method.Type}'.", nameof(method))
            };
        };
    }
}