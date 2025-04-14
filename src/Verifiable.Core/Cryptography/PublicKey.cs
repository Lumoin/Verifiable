using System;
using System.Threading.Tasks;

namespace Verifiable.Core.Cryptography
{
    /// <summary>
    /// Represents a public cryptographic key.
    /// </summary>
    public class PublicKey: SensitiveMemoryKey
    {
        /// <summary>
        /// The actual function that verifies the signature against data using this key.
        /// </summary>
        private readonly VerificationFunction<byte, byte, Signature, ValueTask<bool>> verificationFunction;

        /// <summary>
        /// A convenience getter to return the public key memory instead of a generic one.
        /// </summary>
        protected new PublicKeyMemory KeyMaterial { get { return (PublicKeyMemory)base.KeyMaterial; } }

        /// <summary>
        /// Public key constructor.
        /// </summary>
        /// <param name="sensitiveMemory">The public key bytes of this key.</param>
        /// <param name="id">The key identifier.</param>
        /// <param name="verificationFunction">The function that verifies the signature against data using this key.</param>
        public PublicKey(PublicKeyMemory sensitiveMemory, string id, VerificationFunction<byte, byte, Signature, ValueTask<bool>> verificationFunction): base(sensitiveMemory, id)
        {
            this.verificationFunction = verificationFunction;
        }


        /// <summary>
        /// Verifies if <paramref name="signature"/> generated using a private key corresponding to
        /// this public key matches <paramref name="dataToVerify"/>.
        /// </summary>
        /// <param name="dataToVerify">The data from which the signature supposedly has been generated.</param>
        /// <param name="signature">The signature.</param>
        /// <returns><em>True</em> if the signature matches the data. <em>False</em> otherwise.</returns>        
        public ValueTask<bool> VerifyAsync(ReadOnlyMemory<byte> dataToVerify, Signature signature)
        {
            return KeyMaterial.VerifyAsync(dataToVerify, signature, verificationFunction);
        }
    }
}
