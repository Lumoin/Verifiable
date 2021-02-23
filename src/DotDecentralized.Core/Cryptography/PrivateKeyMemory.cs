using System;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace DotDecentralized.Core.Cryptography
{
    /// <summary>
    /// A wrapper for private key memory that has the capability to
    /// unwrap the data during public key operations.
    /// </summary>
    /// <remarks>If counters, statistics or other statistics or functionality
    /// is needed this class can be inherited. Potential need: key rotation initiated
    /// by some statistics.</remarks>
    public class PrivateKeyMemory: SensitiveMemory
    {
        /// <summary>
        /// KeyMemory constructor.
        /// </summary>
        /// <param name="keyMemory">The piece of sensitive data.</param>
        public PrivateKeyMemory(IMemoryOwner<byte> keyMemory): base(keyMemory) { }


        /// <summary>
        /// An unwrap function for this memory.
        /// </summary>
        /// <typeparam name="TDataToSign">The data type from which to calculate signature. Likely <see cref="byte"/>.</typeparam>
        /// <typeparam name="TResult">The result of verification type.</typeparam>
        /// <param name="sensitiveFunc">The function that uses this memory. Example caller: <see cref="PublicKey"/>.</param>
        /// <param name="arg">An argument given to <paramref name="sensitiveFunc"/>.</param>
        /// <returns>The result of calling of <paramref name="sensitiveFunc"/>. Likely a <see cref="Signature"/>.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public TResult WithKeyBytes<TDataToSign, TResult>(SigningFunction<byte, TDataToSign, TResult> sensitiveFunc, ReadOnlySpan<TDataToSign> arg, MemoryPool<byte> signaturePool) where TResult: Signature
        {
            return sensitiveFunc(sensitiveData.Memory.Span, arg, signaturePool);
        }
    }
}
