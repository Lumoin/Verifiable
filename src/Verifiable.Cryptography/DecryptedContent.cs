using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography;

/// <summary>
/// Plaintext bytes produced by a decryption operation.
/// </summary>
/// <remarks>
/// <para>
/// Holds the result of decrypting ciphertext. The content is sensitive — it must be
/// cleared on disposal and must not be logged or persisted. Typical consumers read it
/// once and immediately parse or forward the bytes.
/// </para>
/// <para>
/// Allocated from <see cref="SensitiveMemoryPool{T}"/> and cleared on disposal.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class DecryptedContent: SensitiveMemory, IEquatable<DecryptedContent>
{
    /// <summary>Gets the length of the decrypted content in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Initializes a new <see cref="DecryptedContent"/> from owned memory.
    /// </summary>
    /// <param name="memory">The owned memory. Ownership transfers to this instance.</param>
    /// <param name="tag">Metadata identifying the algorithm context and purpose.</param>
    /// <param name="lifetime">
    /// Optional OTel activity spanning this value's lifetime. Pass <see langword="null"/>
    /// when no OTel listener is active.
    /// </param>
    public DecryptedContent(IMemoryOwner<byte> memory, Tag tag, Activity? lifetime = null)
        : base(memory, tag, lifetime)
    {
        ArgumentNullException.ThrowIfNull(memory);
        ArgumentNullException.ThrowIfNull(tag);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] DecryptedContent? other) =>
        other is not null
            && MemoryOwner.Memory.Span.SequenceEqual(other.MemoryOwner.Memory.Span);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj switch
    {
        DecryptedContent d => Equals(d),
        SensitiveMemory sm => base.Equals(sm),
        _ => false
    };

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <summary>Determines whether two <see cref="DecryptedContent"/> instances contain identical bytes.</summary>
    public static bool operator ==(DecryptedContent? left, DecryptedContent? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Determines whether two <see cref="DecryptedContent"/> instances differ.</summary>
    public static bool operator !=(DecryptedContent? left, DecryptedContent? right) =>
        !(left == right);

    /// <inheritdoc/>
    public override string ToString() => DebuggerDisplay;

    private string DebuggerDisplay
    {
        get
        {
            ReadOnlySpan<byte> span = MemoryOwner.Memory.Span;
            int previewLength = Math.Min(span.Length, 8);
            string hexPreview = Convert.ToHexStringLower(span[..previewLength]);
            string ellipsis = span.Length > 8 ? "..." : string.Empty;

            return $"DecryptedContent({span.Length} bytes, {hexPreview}{ellipsis})";
        }
    }
}