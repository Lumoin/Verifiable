using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// The authentication tag produced by an authenticated encryption operation.
/// </summary>
/// <remarks>
/// <para>
/// An authentication tag is the MAC output of an AEAD cipher. It proves both that the
/// ciphertext has not been tampered with and that the additional authenticated data has
/// not been modified. Decryption verifies the tag before producing any plaintext — a
/// mismatched tag means tampering has occurred and no plaintext is returned.
/// </para>
/// <para>
/// <strong>This is a MAC, not an HMAC.</strong>
/// HMAC is a specific construction that builds a MAC using a hash function (RFC 2104).
/// AEAD authentication tags use different constructions: AES-GCM uses GHASH (Galois
/// field multiplication), ChaCha20-Poly1305 uses Poly1305. Neither is HMAC. The
/// <see cref="Tag"/> carries <see cref="Verifiable.Cryptography.Context.Purpose.Mac"/>
/// to reflect this.
/// </para>
/// <para>
/// The required tag length is algorithm-specific and is enforced by the caller, not by
/// this type. AES-GCM requires 128 bits (16 bytes) per NIST SP 800-38D.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class AuthenticationTag: SensitiveMemory, IEquatable<AuthenticationTag>
{
    /// <summary>Gets the length of the authentication tag in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Initializes a new <see cref="AuthenticationTag"/> from owned memory.
    /// </summary>
    /// <param name="memory">The owned memory. Ownership transfers to this instance.</param>
    /// <param name="tag">Metadata including algorithm, purpose, and provenance entries.</param>
    /// <param name="lifetime">
    /// Optional OTel activity spanning this value's lifetime. Pass <see langword="null"/>
    /// when no OTel listener is active.
    /// </param>
    public AuthenticationTag(IMemoryOwner<byte> memory, Tag tag, Activity? lifetime = null)
        : base(memory, tag, lifetime)
    {
        ArgumentNullException.ThrowIfNull(memory);
        ArgumentNullException.ThrowIfNull(tag);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] AuthenticationTag? other) =>
        other is not null
            && MemoryOwner.Memory.Span.SequenceEqual(other.MemoryOwner.Memory.Span);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj switch
    {
        AuthenticationTag a => Equals(a),
        SensitiveMemory sm => base.Equals(sm),
        _ => false
    };

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <summary>Determines whether two <see cref="AuthenticationTag"/> instances contain identical bytes.</summary>
    public static bool operator ==(AuthenticationTag? left, AuthenticationTag? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Determines whether two <see cref="AuthenticationTag"/> instances differ.</summary>
    public static bool operator !=(AuthenticationTag? left, AuthenticationTag? right) =>
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

            return $"AuthenticationTag({span.Length} bytes, {hexPreview}{ellipsis})";
        }
    }
}