using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography;

/// <summary>
/// Extension methods for creating <see cref="Signature"/> instances from byte data.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not up to date with the latest syntax.")]
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case", Justification = "The analyzer is not up to date with the latest syntax.")]
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
            ArgumentNullException.ThrowIfNull(tag);
            ArgumentNullException.ThrowIfNull(pool);
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
            ArgumentNullException.ThrowIfNull(bytes);
            ArgumentNullException.ThrowIfNull(tag);
            ArgumentNullException.ThrowIfNull(pool);
            var owner = pool.Rent(bytes.Length);
            bytes.CopyTo(owner.Memory.Span);

            return new Signature(owner, tag);
        }
    }
}