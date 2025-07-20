using System;
using System.Buffers;
using System.Threading.Tasks;

namespace Verifiable.Core.Cryptography
{
    /// <summary>
    /// Represents a private cryptographic key.
    /// </summary>
    public class PrivateKey: SensitiveMemoryKey
    {
        /// <summary>
        /// The actual function that calculates the signature on the data using this key.
        /// </summary>
        private readonly SigningFunction<byte, byte, ValueTask<Signature>> signingFunction;


        /// <summary>
        /// Private key constructor.
        /// </summary>
        /// <param name="privateKeyMaterial">The private key bytes of this key.</param>
        /// <param name="id">The identifier for this private key.</param>
        /// <param name="signingFunction">The function this key uses for signing.</param>
        public PrivateKey(PrivateKeyMemory privateKeyMaterial, string id, SigningFunction<byte, byte, ValueTask<Signature>> signingFunction): base(privateKeyMaterial, id)
        {
            ArgumentNullException.ThrowIfNull(privateKeyMaterial, nameof(privateKeyMaterial));
            ArgumentException.ThrowIfNullOrEmpty(id, nameof(id));
            ArgumentNullException.ThrowIfNull(signingFunction, nameof(signingFunction));

            this.signingFunction = signingFunction;
        }


        /// <summary>
        /// A convenience getter to return <see cref="PrivateKeyMemory"/> instead of a <see cref="SensitiveMemory"/>.
        /// </summary>
        /// <remarks>Since this is a private key, this stored private key memory material. This is a type class.</remarks>
        protected new PrivateKeyMemory KeyMaterial { get { return (PrivateKeyMemory)base.KeyMaterial; } }


        /// <summary>
        /// Signs data given by <paramref name="dataToSign"/> using this key.
        /// </summary>
        /// <param name="dataToSign"></param>
        /// <param name="signaturePool">The pool from which to reserve the memory for the signature.</param>
        /// <returns>The signature of the data.</returns>
        public ValueTask<Signature> SignAsync(ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool)
        {
            return KeyMaterial.WithKeyBytesAsync((privateKeyBytes, dataToSign, signaturePool) => signingFunction(privateKeyBytes, dataToSign, signaturePool), dataToSign, signaturePool);
        }
    }
}
