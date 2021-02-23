using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotDecentralized.Core.Cryptography
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
        /// <param name="sensitiveMemory">The private key bytes of this key.</param>
        /// <param name="id">The identifier for this private key.</param>
        /// <param name="signingFunction">The function this key uses for signging.</param>
        public PrivateKey(PrivateKeyMemory sensitiveMemory, string id, SigningFunction<byte, byte, Signature> signingFunction): base(sensitiveMemory, id)
        {
            this.signingFunction = signingFunction ?? throw new ArgumentNullException(nameof(signingFunction));
        }

        /// <summary>
        /// A convenience getter to return private key memory instead of a generic one.
        /// </summary>
        protected PrivateKeyMemory KeyMemory { get { return (PrivateKeyMemory)keyMemory; } }

        /// <summary>
        /// Signs data given by <paramref name="dataToSign"/> using this key.
        /// </summary>
        /// <param name="dataToSign"></param>
        /// <param name="signaturePool">The pool from which to reserve the memory for the signature.</param>
        /// <returns>The signature of the data.</returns>
        public Signature Sign(ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool)
        {
            return KeyMemory.WithKeyBytes((privateKeyBytes, dataToSign, signaturePool) => signingFunction(privateKeyBytes, dataToSign, signaturePool), dataToSign, signaturePool);
        }
    }
}
