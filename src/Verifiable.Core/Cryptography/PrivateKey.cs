using System;
using System.Buffers;

namespace Verifiable.Core.Cryptography
{
    /// <summary>
    /// Represents a private cryptographic key.
    /// </summary>
    public class PrivateKey: Key
    {
        /// <summary>
        /// The actual function that calculates the signature on the data using this key.
        /// </summary>
        private readonly SigningFunction<byte, byte, Signature> signingFunction;

        /// <summary>
        /// Private key constructor.
        /// </summary>
        /// <param name="privateKeyMaterial">The private key bytes of this key.</param>
        /// <param name="id">The identifier for this private key.</param>
        /// <param name="signingFunction">The function this key uses for signging.</param>
        public PrivateKey(PrivateKeyMemory privateKeyMaterial, string id, SigningFunction<byte, byte, Signature> signingFunction): base(privateKeyMaterial, id)
        {
            this.signingFunction = signingFunction ?? throw new ArgumentNullException(nameof(signingFunction));
        }

        /// <summary>
        /// A convenience getter to return <see cref="PrivateKeyMemory"/> instead of a <see cref="SensitiveMemory"/>.
        /// </summary>
        /// <remarks>Since this is a private key, this stored private key memory material. This is a type class.</remarks>
        new protected PrivateKeyMemory KeyMaterial { get { return (PrivateKeyMemory)base.KeyMaterial; } }

        /// <summary>
        /// Signs data given by <paramref name="dataToSign"/> using this key.
        /// </summary>
        /// <param name="dataToSign"></param>
        /// <param name="signaturePool">The pool from which to reserve the memory for the signature.</param>
        /// <returns>The signature of the data.</returns>
        public Signature Sign(ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool)
        {
            return KeyMaterial.WithKeyBytes((privateKeyBytes, dataToSign, signaturePool) => signingFunction(privateKeyBytes, dataToSign, signaturePool), dataToSign, signaturePool);
        }
    }
}
