using System.Buffers;

namespace Verifiable.Cryptography
{
    /// <summary>
    /// A wrapper for private key memory that has the capability to
    /// unwrap the data during private key operations.
    /// </summary>
    /// <remarks>
    /// <para>
    /// If counters, statistics or other functionality is needed this class
    /// can be inherited. Potential need: key rotation initiated by some statistics.
    /// </para>
    /// </remarks>
    /// <param name="keyMemory">The piece of sensitive data.</param>
    /// <param name="tag">Tags the memory with out-of-band information such as key material information.</param>
    public class PrivateKeyMemory(IMemoryOwner<byte> keyMemory, Tag tag): SensitiveMemory(keyMemory, tag)
    {
        /// <summary>
        /// An unwrap function for this memory.
        /// </summary>
        /// <typeparam name="TDataToSign">The data type from which to calculate signature. Likely <see cref="byte"/>.</typeparam>
        /// <param name="sensitiveFunc">The function that uses this memory. Example caller: <see cref="PrivateKey"/>.</param>
        /// <param name="arg">An argument given to <paramref name="sensitiveFunc"/>.</param>
        /// <param name="signaturePool">The memory pool used to allocate the resulting signature.</param>
        /// <returns>The resulting <see cref="Signature"/>.</returns>
        public ValueTask<Signature> SignWithKeyBytesAsync<TDataToSign>(SigningFunction<byte, TDataToSign, ValueTask<Signature>> sensitiveFunc, ReadOnlyMemory<TDataToSign> arg, MemoryPool<byte> signaturePool)
        {
            ArgumentNullException.ThrowIfNull(sensitiveFunc);
            ArgumentNullException.ThrowIfNull(signaturePool);

            return sensitiveFunc(MemoryOwner.Memory, arg, signaturePool);
        }
    }
}