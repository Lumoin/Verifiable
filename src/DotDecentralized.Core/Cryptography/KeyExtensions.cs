using System;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace DotDecentralized.Core.Cryptography
{
    /// <summary>
    /// Convenience functions to be used with <see cref="SensitiveMemory"/> types.
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
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Signature Sign(this PrivateKeyMemory privateKey, ReadOnlySpan<byte> dataToSign, SigningFunction<byte, byte, Signature> signingFunction, MemoryPool<byte> signaturePool)
        {
            return privateKey.WithKeyBytes((privateKeyBytes, dataToSign, signaturePool) => signingFunction(privateKeyBytes, dataToSign, signaturePool), dataToSign, signaturePool);
        }


        /// <summary>
        /// Verifies data using public key memory derived types.
        /// </summary>
        /// <param name="publicKey">Public key.</param>
        /// <param name="dataToVerify">The data which needs to be verified using <paramref name="signature"/>.</param>
        /// <param name="signature">The signature used to verify <paramref name="dataToVerify"/>.</param>
        /// <param name="verificationFunction">The function that verifies that data with the given signature.</param>
        /// <returns><em>True</em> if the signature matches the data for the used key. <em>False</em> otherwise.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool Verify(this PublicKeyMemory publicKey, ReadOnlySpan<byte> dataToVerify, Signature signature, VerificationFunction<byte, byte, Signature, bool> verificationFunction)
        {
            return publicKey.WithKeyBytes((publicKeyBytes, dataToVerify, signature) => verificationFunction(publicKeyBytes, dataToVerify, signature), dataToVerify, signature);
        }
    }
}
