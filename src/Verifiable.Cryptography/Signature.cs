using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography
{
    /// <summary>
    /// Represents a cryptographic signature that owns its backing memory.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This type takes ownership of the <see cref="IMemoryOwner{T}"/> provided at construction.
    /// The caller must not use the memory owner after passing it to <see cref="Signature"/>.
    /// Disposing the signature clears and releases the underlying memory.
    /// </para>
    /// <para>
    /// Equality is defined by byte-level content comparison of the signature data,
    /// consistent with the base <see cref="SensitiveMemory"/> semantics. Two signatures
    /// with identical bytes are considered equal regardless of their <see cref="SensitiveData.Tag"/>.
    /// </para>
    /// <example>
    /// <code>
    /// using var signature = await privateKey.SignAsync(data, SensitiveMemoryPool&lt;byte&gt;.Shared);
    /// bool verified = await publicKey.VerifyAsync(data, signature, SensitiveMemoryPool&lt;byte&gt;.Shared);
    /// </code>
    /// </example>
    /// </remarks>
    [DebuggerDisplay("{DebuggerDisplay,nq}")]
    public sealed class Signature(IMemoryOwner<byte> sensitiveMemory, Tag tag)
        : SensitiveMemory(sensitiveMemory, tag), IEquatable<Signature>
    {
        /// <summary>
        /// Gets the length of the signature in bytes.
        /// </summary>
        public int Length => MemoryOwner.Memory.Length;

        /// <summary>
        /// An implicit conversion from <see cref="Signature"/> to <see cref="ReadOnlySpan{Byte}"/>.
        /// </summary>
        /// <param name="signature">The signature to convert.</param>
        [DebuggerStepThrough]
        [SuppressMessage("Usage", "CA2225:Operator overloads have named alternates",
            Justification = "AsReadOnlySpan() inherited from SensitiveMemory serves as the named alternative.")]
        public static implicit operator ReadOnlySpan<byte>(Signature signature)
        {
            ArgumentNullException.ThrowIfNull(signature);
            return signature.AsReadOnlySpan();
        }

        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool Equals([NotNullWhen(true)] Signature? other)
        {
            return other is not null
                && MemoryOwner.Memory.Span.SequenceEqual(other.MemoryOwner.Memory.Span);
        }

        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals([NotNullWhen(true)] object? obj)
        {
            return obj switch
            {
                Signature s => Equals(s),
                SensitiveMemory sm => base.Equals(sm),
                _ => false
            };
        }

        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode() => base.GetHashCode();

        /// <summary>
        /// Determines whether two <see cref="Signature"/> instances are equal.
        /// </summary>
        /// <param name="left">The first signature.</param>
        /// <param name="right">The second signature.</param>
        /// <returns><see langword="true"/> if both signatures contain identical bytes; otherwise, <see langword="false"/>.</returns>
        public static bool operator ==(Signature? left, Signature? right)
        {
            if(left is null)
            {
                return right is null;
            }

            return left.Equals(right);
        }

        /// <summary>
        /// Determines whether two <see cref="Signature"/> instances are not equal.
        /// </summary>
        /// <param name="left">The first signature.</param>
        /// <param name="right">The second signature.</param>
        /// <returns><see langword="true"/> if the signatures differ; otherwise, <see langword="false"/>.</returns>
        public static bool operator !=(Signature? left, Signature? right) => !(left == right);

        /// <inheritdoc />
        public override string ToString() => DebuggerDisplay;

        /// <summary>
        /// Provides a debugger-friendly representation showing algorithm, length, and a hex preview of the content.
        /// </summary>
        private string DebuggerDisplay
        {
            get
            {
                string algorithmName = Tag.TryGet<CryptoAlgorithm>(out var alg)
                    ? CryptoAlgorithmNames.GetName(alg)
                    : "Unknown";

                ReadOnlySpan<byte> span = MemoryOwner.Memory.Span;
                int previewLength = Math.Min(span.Length, 8);
                string hexPreview = Convert.ToHexStringLower(span[..previewLength]);
                string ellipsis = span.Length > 8 ? "..." : string.Empty;

                return $"Signature({algorithmName}, {span.Length} bytes, {hexPreview}{ellipsis})";
            }
        }
    }
}