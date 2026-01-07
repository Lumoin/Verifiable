using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Function-based signature verification that directly uses the cryptographic function registry.
    /// These functions extract key material and call registered verification functions without
    /// creating intermediate PublicKey instances.
    /// </summary>
    public static class VerificationMethodExtensions
    {
        /// <summary>
        /// Verifies a signature using a verification method by directly calling registered verification functions.
        /// This function extracts key material and resolves the verification function from the registry.
        /// </summary>
        /// <param name="verificationMethod">The verification method containing the public key information.</param>
        /// <param name="data">The original data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="memoryPool">Memory pool for key material extraction.</param>
        /// <returns>A task that resolves to true if the signature is valid; otherwise, false.</returns>
        public static async ValueTask<bool> VerifySignatureAsync(
            this VerificationMethod verificationMethod,
            ReadOnlyMemory<byte> data,
            Signature signature,
            MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(verificationMethod, nameof(verificationMethod));
            ArgumentNullException.ThrowIfNull(signature, nameof(signature));
            ArgumentNullException.ThrowIfNull(memoryPool, nameof(memoryPool));

            //Extract key material using existing conversion infrastructure
            var rawKeyMaterial = VerificationMethodCryptoConversions.DefaultConverter(verificationMethod, memoryPool);

            if(rawKeyMaterial.keyMaterial == null)
            {
                throw new InvalidOperationException($"Unable to extract key material from verification method '{verificationMethod.Id}'.");
            }

            using(rawKeyMaterial.keyMaterial)
            {
                //Resolve verification function from registry.
                var verificationFunction = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(
                    rawKeyMaterial.Algorithm,
                    rawKeyMaterial.Purpose);

                //Call verification function directly with extracted key material.
                return await verificationFunction(data.Span, signature.AsReadOnlySpan(), rawKeyMaterial.keyMaterial.Memory.Span);
            }
        }


        /// <summary>
        /// Creates a PublicKey instance from verification method for cases where state needs to be maintained.
        /// This function is useful when you want to cache the key for multiple operations.
        /// </summary>
        /// <param name="verificationMethod">The verification method containing public key information.</param>
        /// <param name="memoryPool">Memory pool for key material allocation.</param>
        /// <returns>A PublicKey instance ready for verification operations.</returns>
        public static PublicKey CreatePublicKeyFromVerificationMethod(this VerificationMethod verificationMethod, MemoryPool<byte> memoryPool)
        {
            ArgumentNullException.ThrowIfNull(verificationMethod, nameof(verificationMethod));
            ArgumentNullException.ThrowIfNull(memoryPool, nameof(memoryPool));

            //Extract key material using existing conversion infrastructure
            var rawKeyMaterial = VerificationMethodCryptoConversions.DefaultConverter(verificationMethod, memoryPool);

            if(rawKeyMaterial.keyMaterial == null)
            {
                throw new InvalidOperationException($"Unable to extract key material from verification method '{verificationMethod.Id}'.");
            }

            //Create PublicKeyMemory with proper tags
            var publicKeyMemory = new PublicKeyMemory(rawKeyMaterial.keyMaterial, new Tag(new Dictionary<Type, object>
            {
                [typeof(CryptoAlgorithm)] = rawKeyMaterial.Algorithm,
                [typeof(Purpose)] = rawKeyMaterial.Purpose,
                [typeof(EncodingScheme)] = rawKeyMaterial.Scheme
            }));

            return CryptographicKeyFactory.CreatePublicKey(
                publicKeyMemory,
                verificationMethod.Id ?? throw new InvalidOperationException("Verification method must have an ID"),
                rawKeyMaterial.Algorithm,
                rawKeyMaterial.Purpose);
        }


        /// <summary>
        /// Pure function that determines whether a verification method supports signing operations.
        /// </summary>
        /// <param name="verificationMethod">The verification method to examine.</param>
        /// <returns>true if the verification method supports signing; otherwise, false.</returns>
        public static bool DetermineSigningSupport(this VerificationMethod verificationMethod)
        {
            ArgumentNullException.ThrowIfNull(verificationMethod, nameof(verificationMethod));

            try
            {
                using var tempMemoryPool = SensitiveMemoryPool<byte>.Shared;
                var rawKeyMaterial = VerificationMethodCryptoConversions.DefaultConverter(verificationMethod, tempMemoryPool);
                using(rawKeyMaterial.keyMaterial)
                {
                    //Verification methods have Purpose.Verification but can verify signatures from Purpose.Signing keys.
                    return rawKeyMaterial.Purpose == Purpose.Verification;
                }
            }
            catch
            {
                return false;
            }
        }
    }
}