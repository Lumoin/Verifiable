using System;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace DotDecentralized.Core.Cryptography
{
    /// <summary>
    /// Represents a public cryptographic key.
    /// </summary>
    public class PublicKey: Key
    {
        /// <summary>
        /// The actual function that verifies the signature against data using this key.
        /// </summary>
        private readonly VerificationFunction<byte, byte, Signature, bool> verificationFunction;

        /// <summary>
        /// A convenience getter to return the public key memory instead of a generic one.
        /// </summary>
        protected PublicKeyMemory KeyMemory { get { return (PublicKeyMemory)keyMemory; } }

        /// <summary>
        /// Public key constructor.
        /// </summary>
        /// <param name="sensitiveMemory">The public key bytes of this key.</param>
        /// <param name="id">The key identity.</param>
        /// <param name="verificationFunction">The function that verifies the signature against data using this key.</param>
        public PublicKey(PublicKeyMemory sensitiveMemory, string id, VerificationFunction<byte, byte, Signature, bool> verificationFunction): base(sensitiveMemory, id)
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
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool Verify(ReadOnlySpan<byte> dataToVerify, Signature signature)
        {
            return KeyMemory.Verify(dataToVerify, signature, verificationFunction);
        }
    }
}
