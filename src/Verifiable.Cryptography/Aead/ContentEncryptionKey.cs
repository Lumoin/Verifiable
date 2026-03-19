using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// A content encryption key (CEK) derived from ECDH key agreement and a key derivation
/// function. Used as the symmetric key for a single AEAD encrypt or decrypt operation.
/// </summary>
/// <remarks>
/// <para>
/// A CEK is ephemeral derived key material — it must be used immediately for one
/// encryption or decryption operation and then zeroed and disposed. It is never
/// transmitted and must never be persisted.
/// </para>
/// <para>
/// For ECDH-ES the CEK is derived from the shared secret Z via Concat KDF per
/// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.6.2">RFC 7518 §4.6.2</see>.
/// The key length is determined by the content encryption algorithm: 128 bits for
/// A128GCM, 256 bits for A256GCM.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class ContentEncryptionKey: SensitiveMemory, IEquatable<ContentEncryptionKey>
{
    /// <summary>Gets the length of the CEK in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Initializes a new <see cref="ContentEncryptionKey"/> from owned memory.
    /// </summary>
    /// <param name="memory">The owned memory. Ownership transfers to this instance.</param>
    /// <param name="tag">Metadata identifying the algorithm and purpose.</param>
    /// <param name="lifetime">
    /// Optional OTel activity spanning this value's lifetime. Pass <see langword="null"/>
    /// when no OTel listener is active.
    /// </param>
    public ContentEncryptionKey(IMemoryOwner<byte> memory, Tag tag, Activity? lifetime = null)
        : base(memory, tag, lifetime)
    {
        ArgumentNullException.ThrowIfNull(memory);
        ArgumentNullException.ThrowIfNull(tag);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] ContentEncryptionKey? other) =>
        other is not null
            && MemoryOwner.Memory.Span.SequenceEqual(other.MemoryOwner.Memory.Span);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj switch
    {
        ContentEncryptionKey c => Equals(c),
        SensitiveMemory sm => base.Equals(sm),
        _ => false
    };

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <summary>Determines whether two instances contain identical bytes.</summary>
    public static bool operator ==(ContentEncryptionKey? left, ContentEncryptionKey? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Determines whether two instances differ.</summary>
    public static bool operator !=(ContentEncryptionKey? left, ContentEncryptionKey? right) =>
        !(left == right);

    /// <inheritdoc/>
    public override string ToString() => DebuggerDisplay;

    private string DebuggerDisplay
    {
        get
        {
            ReadOnlySpan<byte> span = MemoryOwner.Memory.Span;

            return $"ContentEncryptionKey({span.Length} bytes)";
        }
    }
}
