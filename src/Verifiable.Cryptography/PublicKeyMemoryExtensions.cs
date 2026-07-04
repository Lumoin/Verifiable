using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography;

/// <summary>
/// Extension methods for creating <see cref="PublicKeyMemory"/> instances from byte data, mirroring
/// <see cref="SignatureExtensions"/>: raw key bytes are copied into pooled, auto-clearing memory and wrapped in
/// the semantic carrier rather than being held as a naked array.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not up to date with the latest syntax.")]
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case", Justification = "The analyzer is not up to date with the latest syntax.")]
public static class PublicKeyMemoryExtensions
{
    extension(ReadOnlySpan<byte> bytes)
    {
        /// <summary>
        /// Creates a <see cref="PublicKeyMemory"/> from bytes using pooled memory.
        /// </summary>
        /// <param name="tag">The public-key algorithm tag.</param>
        /// <param name="pool">Memory pool for allocation.</param>
        /// <returns>A new <see cref="PublicKeyMemory"/> owning pooled memory. Caller must dispose.</returns>
        public PublicKeyMemory ToPublicKeyMemory(Tag tag, MemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(tag);
            ArgumentNullException.ThrowIfNull(pool);
            var owner = pool.Rent(bytes.Length);
            bytes.CopyTo(owner.Memory.Span);

            return new PublicKeyMemory(owner, tag);
        }
    }


    extension(byte[] bytes)
    {
        /// <summary>
        /// Creates a <see cref="PublicKeyMemory"/> from bytes using pooled memory.
        /// </summary>
        /// <param name="tag">The public-key algorithm tag.</param>
        /// <param name="pool">Memory pool for allocation.</param>
        /// <returns>A new <see cref="PublicKeyMemory"/> owning pooled memory. Caller must dispose.</returns>
        public PublicKeyMemory ToPublicKeyMemory(Tag tag, MemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(bytes);
            ArgumentNullException.ThrowIfNull(tag);
            ArgumentNullException.ThrowIfNull(pool);
            var owner = pool.Rent(bytes.Length);
            bytes.CopyTo(owner.Memory.Span);

            return new PublicKeyMemory(owner, tag);
        }
    }
}
