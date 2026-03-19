using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// The encrypted bytes produced by a symmetric encryption operation.
/// </summary>
/// <remarks>
/// <para>
/// Contains the output of applying a symmetric cipher to plaintext. For AEAD
/// constructions such as AES-GCM and ChaCha20-Poly1305 the ciphertext length equals
/// the plaintext length — no padding is added.
/// </para>
/// <para>
/// A <see cref="Ciphertext"/> produced by an AEAD cipher is paired with an
/// <see cref="AuthenticationTag"/>. Decryption verifies the tag before producing
/// any plaintext — a mismatched tag means the ciphertext has been tampered with.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Ciphertext: SensitiveMemory, IEquatable<Ciphertext>
{
    /// <summary>Gets the length of the ciphertext in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Initializes a new <see cref="Ciphertext"/> from owned memory.
    /// </summary>
    /// <param name="memory">The owned memory. Ownership transfers to this instance.</param>
    /// <param name="tag">Metadata including algorithm, purpose, and provenance entries.</param>
    /// <param name="lifetime">
    /// Optional OTel activity spanning this value's lifetime. Pass <see langword="null"/>
    /// when no OTel listener is active.
    /// </param>
    public Ciphertext(IMemoryOwner<byte> memory, Tag tag, Activity? lifetime = null)
        : base(memory, tag, lifetime)
    {
        ArgumentNullException.ThrowIfNull(memory);
        ArgumentNullException.ThrowIfNull(tag);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] Ciphertext? other) =>
        other is not null
            && MemoryOwner.Memory.Span.SequenceEqual(other.MemoryOwner.Memory.Span);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj switch
    {
        Ciphertext c => Equals(c),
        SensitiveMemory sm => base.Equals(sm),
        _ => false
    };

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <summary>Determines whether two <see cref="Ciphertext"/> instances contain identical bytes.</summary>
    public static bool operator ==(Ciphertext? left, Ciphertext? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Determines whether two <see cref="Ciphertext"/> instances differ.</summary>
    public static bool operator !=(Ciphertext? left, Ciphertext? right) =>
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

            return $"Ciphertext({span.Length} bytes, {hexPreview}{ellipsis})";
        }
    }
}