using System.Buffers;

namespace Verifiable.Cryptography
{
    /// <summary>
    /// A wrapper for private key memory that has the capability to
    /// unwrap the data during private key operations.
    /// </summary>
    /// <remarks>If counters, statistics or other statistics or functionality
    /// is needed this class can be inherited. Potential need: key rotation initiated
    /// by some statistics.</remarks>
    /// <remarks>
    /// KeyMemory constructor.
    /// </remarks>
    /// <param name="keyMemory">The piece of sensitive data.</param>
    /// <param name="tag">Tags the memory with out-of-band information such as key material information.</param>
    public class PrivateKeyMemory(IMemoryOwner<byte> keyMemory, Tag tag): SensitiveMemory(keyMemory, tag)
    {
        /// <summary>
        /// An unwrap function for this memory.
        /// </summary>
        /// <typeparam name="TDataToSign">The data type from which to calculate signature. Likely <see cref="byte"/>.</typeparam>
        /// <typeparam name="TResult">The result of verification type.</typeparam>
        /// <param name="sensitiveFunc">The function that uses this memory. Example caller: <see cref="PrivateKey"/>.</param>
        /// <param name="arg">An argument given to <paramref name="sensitiveFunc"/>.</param>
        /// <returns>The result of calling of <paramref name="sensitiveFunc"/>. Likely a <see cref="Signature"/>.</returns>
        public ValueTask<TResult> WithKeyBytesAsync<TDataToSign, TResult>(SigningFunction<byte, TDataToSign, ValueTask<TResult>> sensitiveFunc, ReadOnlyMemory<TDataToSign> arg, MemoryPool<byte> signaturePool) where TResult: Signature
        {
            return sensitiveFunc(MemoryOwner.Memory, arg, signaturePool);
        }
    }
}
