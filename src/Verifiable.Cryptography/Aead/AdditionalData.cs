using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// Additional authenticated data (AAD) supplied to an authenticated encryption operation.
/// </summary>
/// <remarks>
/// <para>
/// Additional authenticated data is fed into the authentication tag computation
/// alongside the ciphertext but is not encrypted. It binds context to the encrypted
/// payload — decryption fails if either the ciphertext or the AAD has been modified
/// since encryption. The AAD bytes themselves are transmitted in the clear.
/// </para>
/// <para>
/// In compact JWE serialization the AAD is the ASCII bytes of the Base64url-encoded
/// protected header exactly as it appeared on the wire, before any decoding. This binds
/// the algorithm, encryption, and ephemeral key parameters to the ciphertext so they
/// cannot be substituted without detection.
/// </para>
/// <para>
/// In other AEAD contexts the AAD may be any caller-supplied byte sequence — a record
/// header, a session identifier, a protocol version tag, or any other data that must
/// be authenticated but need not be encrypted.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class AdditionalData: SensitiveMemory, IEquatable<AdditionalData>
{
    /// <summary>Gets the length of the additional authenticated data in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Initializes a new <see cref="AdditionalData"/> from owned memory.
    /// </summary>
    /// <param name="memory">The owned memory. Ownership transfers to this instance.</param>
    /// <param name="tag">Metadata including algorithm, purpose, and provenance entries.</param>
    /// <param name="lifetime">
    /// Optional OTel activity spanning this value's lifetime. Pass <see langword="null"/>
    /// when no OTel listener is active.
    /// </param>
    public AdditionalData(IMemoryOwner<byte> memory, Tag tag, Activity? lifetime = null)
        : base(memory, tag, lifetime)
    {
        ArgumentNullException.ThrowIfNull(memory);
        ArgumentNullException.ThrowIfNull(tag);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] AdditionalData? other) =>
        other is not null
            && MemoryOwner.Memory.Span.SequenceEqual(other.MemoryOwner.Memory.Span);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj switch
    {
        AdditionalData a => Equals(a),
        SensitiveMemory sm => base.Equals(sm),
        _ => false
    };

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <summary>Determines whether two <see cref="AdditionalData"/> instances contain identical bytes.</summary>
    public static bool operator ==(AdditionalData? left, AdditionalData? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Determines whether two <see cref="AdditionalData"/> instances differ.</summary>
    public static bool operator !=(AdditionalData? left, AdditionalData? right) =>
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

            return $"AdditionalData({span.Length} bytes, {hexPreview}{ellipsis})";
        }
    }
}