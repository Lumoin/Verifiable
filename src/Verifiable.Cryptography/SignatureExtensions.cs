using System.Buffers;

namespace Verifiable.Cryptography;

/// <summary>
/// Extension methods for creating <see cref="Signature"/> instances from byte data.
/// </summary>
public static class SignatureExtensions
{
    extension(ReadOnlySpan<byte> bytes)
    {
        /// <summary>
        /// Creates a <see cref="Signature"/> from bytes using pooled memory.
        /// </summary>
        /// <param name="tag">The signature algorithm tag.</param>
        /// <param name="pool">Memory pool for allocation.</param>
        /// <returns>A new <see cref="Signature"/> owning pooled memory. Caller must dispose.</returns>
        public Signature ToSignature(Tag tag, MemoryPool<byte> pool)
        {
            var owner = pool.Rent(bytes.Length);
            bytes.CopyTo(owner.Memory.Span);

            return new Signature(owner, tag);
        }
    }


    extension(byte[] bytes)
    {
        /// <summary>
        /// Creates a <see cref="Signature"/> from bytes using pooled memory.
        /// </summary>
        /// <param name="tag">The signature algorithm tag.</param>
        /// <param name="pool">Memory pool for allocation.</param>
        /// <returns>A new <see cref="Signature"/> owning pooled memory. Caller must dispose.</returns>
        public Signature ToSignature(Tag tag, MemoryPool<byte> pool)
        {
            var owner = pool.Rent(bytes.Length);
            bytes.CopyTo(owner.Memory.Span);

            return new Signature(owner, tag);
        }
    }
}