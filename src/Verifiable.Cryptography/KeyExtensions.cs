using System.Buffers;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography
{
    /// <summary>
    /// Convenience extension methods for direct cryptographic operations on key memory.
    /// These extensions provide low-level access to cryptographic functions without requiring
    /// wrapper classes like <see cref="PublicKey"/> or <see cref="PrivateKey"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These extensions serve two primary purposes:
    /// </para>
    /// <list type="number">
    /// <item><description>
    /// <strong>Foundation for high-level classes:</strong> Classes like <see cref="PublicKey"/>
    /// delegate their operations to these extension methods internally.
    /// </description></item>
    /// <item><description>
    /// <strong>Direct access:</strong> Allow users to combine verification functions with key material
    /// directly without creating wrapper objects when performance or flexibility is needed.
    /// </description></item>
    /// </list>
    /// <para>
    /// Use these extensions when you need to combine different verification functions with the same
    /// key material, or when you want to avoid creating <see cref="PublicKey"/>
    /// or <see cref="PrivateKey"/> objects that combine the key material with the cryptographic function.
    /// </para>
    /// </remarks>
    /// <seealso cref="PublicKey"/>
    /// <seealso cref="PrivateKey"/>
    /// <seealso cref="SensitiveMemoryKey"/>
    public static class KeyExtensions
    {
        /// <summary>
        /// Signs data using private key memory and a specified signing function.
        /// This method provides direct access to signing operations without requiring a <see cref="PrivateKey"/> instance.
        /// </summary>
        /// <param name="privateKey">The private key memory containing the key material.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signingFunction">The function that signs the data with the given parameters.</param>
        /// <param name="signaturePool">The memory pool from which to allocate signature memory.</param>
        /// <returns>The signature of the data.</returns>
        /// <remarks>
        /// This extension is used internally by <see cref="PrivateKey.SignAsync"/> and can also be used
        /// directly when you need to combine different signing functions with the same key material.
        /// </remarks>
        /// <seealso cref="PrivateKey.SignAsync"/>
        public static ValueTask<Signature> SignAsync(this PrivateKeyMemory privateKey, ReadOnlyMemory<byte> dataToSign, SigningFunction<byte, byte, ValueTask<Signature>> signingFunction, MemoryPool<byte> signaturePool)
        {
            return privateKey.WithKeyBytesAsync((privateKeyBytes, dataToSign, signaturePool) => signingFunction(privateKeyBytes, dataToSign, signaturePool), dataToSign, signaturePool);
        }


        /// <summary>
        /// Signs data using private key memory and the cryptographic function registry.
        /// This method resolves the signing function from the registry using the key's tag information.
        /// </summary>
        /// <param name="privateKey">The private key memory containing the key material.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool from which to allocate signature memory.</param>
        /// <returns>The signature of the data.</returns>
        /// <remarks>
        /// This extension automatically resolves the signing function from the registry using the algorithm
        /// and purpose information stored in the private key's tag.
        /// </remarks>
        public static async ValueTask<Signature> SignAsync(this PrivateKeyMemory privateKey, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool)
        {
            ArgumentNullException.ThrowIfNull(privateKey, nameof(privateKey));
            ArgumentNullException.ThrowIfNull(signaturePool, nameof(signaturePool));

            //Get the signing function from the private key material's tag.
            var algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
            var purpose = privateKey.Tag.Get<Purpose>();

            //Resolve the signing delegate from the registry.
            var signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

            //Call the signing delegate directly with the private key material.
            return await privateKey.WithKeyBytesAsync(async (privateKeyBytes, dataToSign, signaturePool) =>
            {
                var signatureMemory = await signingDelegate(privateKeyBytes.Span, dataToSign.Span, signaturePool);

                return new Signature(signatureMemory, privateKey.Tag);
            },
            dataToSign,
            signaturePool);
        }


        /// <summary>
        /// Verifies data using public key memory and a specified verification function.
        /// This method provides direct access to verification operations without requiring a <see cref="PublicKey"/> instance.
        /// </summary>
        /// <param name="publicKey">The public key memory containing the key material.</param>
        /// <param name="dataToVerify">The data which needs to be verified using <paramref name="signature"/>.</param>
        /// <param name="signature">The signature used to verify <paramref name="dataToVerify"/>.</param>
        /// <param name="verificationFunction">The function that verifies the data with the given signature.</param>
        /// <returns>True if the signature matches the data for the used key. False otherwise.</returns>
        /// <remarks>
        /// This extension is used internally by <see cref="PublicKey.VerifyAsync"/> and can also be used
        /// directly when you need to combine different verification functions with the same key material.
        /// </remarks>
        /// <seealso cref="PublicKey.VerifyAsync"/>
        public static ValueTask<bool> VerifyAsync(this PublicKeyMemory publicKey, ReadOnlyMemory<byte> dataToVerify, Signature signature, VerificationFunction<byte, byte, Signature, ValueTask<bool>> verificationFunction)
        {
            return publicKey.WithKeyBytesAsync((publicKeyBytes, dataToVerify, signature) => verificationFunction(publicKeyBytes, dataToVerify, signature), dataToVerify, signature);
        }
    }
}
