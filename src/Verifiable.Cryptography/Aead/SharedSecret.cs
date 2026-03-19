using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// The shared secret produced by a KEM decapsulation or ECDH key agreement operation.
/// </summary>
/// <remarks>
/// <para>
/// A shared secret is transient key material — it must be used immediately to derive a
/// content encryption key via a key derivation function and then disposed. It is never
/// transmitted and must never be persisted.
/// </para>
/// <para>
/// For ECDH-ES the shared secret is the x-coordinate of the elliptic curve point
/// resulting from scalar multiplication of the recipient's private key with the sender's
/// ephemeral public key, encoded as a fixed-length unsigned big-endian integer.
/// </para>
/// <para>
/// For ML-KEM the shared secret is the 32-byte value produced by decapsulation per
/// NIST FIPS 203.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class SharedSecret: SensitiveMemory, IEquatable<SharedSecret>
{
    /// <summary>Gets the length of the shared secret in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Initializes a new <see cref="SharedSecret"/> from owned memory.
    /// </summary>
    /// <param name="memory">The owned memory. Ownership transfers to this instance.</param>
    /// <param name="tag">Metadata identifying the key agreement algorithm and purpose.</param>
    /// <param name="lifetime">
    /// Optional OTel activity spanning this value's lifetime. Pass <see langword="null"/>
    /// when no OTel listener is active.
    /// </param>
    public SharedSecret(IMemoryOwner<byte> memory, Tag tag, Activity? lifetime = null)
        : base(memory, tag, lifetime)
    {
        ArgumentNullException.ThrowIfNull(memory);
        ArgumentNullException.ThrowIfNull(tag);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] SharedSecret? other) =>
        other is not null
            && MemoryOwner.Memory.Span.SequenceEqual(other.MemoryOwner.Memory.Span);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj switch
    {
        SharedSecret s => Equals(s),
        SensitiveMemory sm => base.Equals(sm),
        _ => false
    };

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <summary>Determines whether two <see cref="SharedSecret"/> instances contain identical bytes.</summary>
    public static bool operator ==(SharedSecret? left, SharedSecret? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Determines whether two <see cref="SharedSecret"/> instances differ.</summary>
    public static bool operator !=(SharedSecret? left, SharedSecret? right) =>
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
            return $"SharedSecret({span.Length} bytes, {hexPreview}{ellipsis})";
        }
    }
}
