using System;
using System.Buffers;
using System.Threading.Tasks;

namespace Verifiable.Core.Cryptography
{
    /// <summary>
    /// Convenience functions to be used with <see cref="SensitiveMemoryKey"/> derived types.
    /// </summary>
    public static class KeyExtensions
    {
        /// <summary>
        /// Signs data using private key memory derived types.
        /// </summary>
        /// <param name="privateKey">Private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signingFunction">The function that signs the data with the given parameters.</param>
        /// <returns>The signed data.</returns>        
        public static ValueTask<Signature> SignAsync(this PrivateKeyMemory privateKey, ReadOnlyMemory<byte> dataToSign, SigningFunction<byte, byte, ValueTask<Signature>> signingFunction, MemoryPool<byte> signaturePool)
        {
            return privateKey.WithKeyBytesAsync((privateKeyBytes, dataToSign, signaturePool) => signingFunction(privateKeyBytes, dataToSign, signaturePool), dataToSign, signaturePool);
        }


        /// <summary>
        /// Verifies data using public key memory derived types.
        /// </summary>
        /// <param name="publicKey">Public key.</param>
        /// <param name="dataToVerify">The data which needs to be verified using <paramref name="signature"/>.</param>
        /// <param name="signature">The signature used to verify <paramref name="dataToVerify"/>.</param>
        /// <param name="verificationFunction">The function that verifies that data with the given signature.</param>
        /// <returns><em>True</em> if the signature matches the data for the used key. <em>False</em> otherwise.</returns>        
        public static ValueTask<bool> VerifyAsync(this PublicKeyMemory publicKey, ReadOnlyMemory<byte> dataToVerify, Signature signature, VerificationFunction<byte, byte, Signature, ValueTask<bool>> verificationFunction)
        {
            return publicKey.WithKeyBytesAsync((publicKeyBytes, dataToVerify, signature) => verificationFunction(publicKeyBytes, dataToVerify, signature), dataToVerify, signature);
        }
    }
}
