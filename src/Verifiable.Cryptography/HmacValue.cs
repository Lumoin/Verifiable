using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Verifiable.Cryptography;

/// <summary>
/// The output of an HMAC (Hash-based Message Authentication Code) computation per
/// RFC 2104. A keyed hash that proves both message integrity and possession of the
/// shared key.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Distinction from <see cref="Signature"/>.</strong>
/// Both are proofs over data, but their verifier sets differ. A <see cref="Signature"/>
/// is produced under an asymmetric private key and verifiable by anyone holding the
/// matching public key. An <see cref="HmacValue"/> is produced and verified under the
/// same symmetric key — both parties must hold it. Forgery resistance is symmetric in
/// nature: anyone with the key can forge.
/// </para>
/// <para>
/// <strong>Distinction from <see cref="Verifiable.Cryptography.Aead.AuthenticationTag"/>.</strong>
/// Both are MAC outputs. An <see cref="HmacValue"/> is the output of the HMAC construction
/// (RFC 2104) — a keyed hash. An <see cref="Verifiable.Cryptography.Aead.AuthenticationTag"/>
/// is the MAC output produced inside an AEAD cipher — GHASH (AES-GCM) or Poly1305
/// (ChaCha20-Poly1305). The constructions differ; the bytes are not interchangeable
/// across them. The <see cref="Tag"/>'s <see cref="Verifiable.Cryptography.Context.Purpose"/>
/// distinguishes them: <see cref="Verifiable.Cryptography.Context.Purpose.Hmac"/> for
/// <see cref="HmacValue"/>, <see cref="Verifiable.Cryptography.Context.Purpose.Mac"/> for
/// AEAD-internal MAC tags.
/// </para>
/// <para>
/// <strong>Distinction from <see cref="DigestValue"/>.</strong>
/// A <see cref="DigestValue"/> is unkeyed and depends only on the input — anyone with the
/// input can recompute it. An <see cref="HmacValue"/> is keyed and depends on both the
/// input and a secret. Two parties without a shared key cannot both produce or verify an
/// <see cref="HmacValue"/>.
/// </para>
/// <para>
/// <strong>Handling.</strong>
/// This type extends <see cref="SensitiveMemory"/> not because HMAC tag values are
/// secret — they are typically transmitted in the clear — but because their mishandling
/// (algorithm confusion, truncation, non-constant-time comparison) can break protocol
/// correctness or enable timing attacks. Use <see cref="VerifyHmacDelegate"/> (or the
/// extension overloads on <see cref="SymmetricKeyMemory"/>) to verify, not byte
/// equality — verification uses
/// <see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class HmacValue: SensitiveMemory, IEquatable<HmacValue>
{
    private readonly Activity? hmacLifetime;

    /// <summary>
    /// The length of the HMAC tag in bytes. SHA-256 produces 32 bytes,
    /// SHA-384 produces 48 bytes, SHA-512 produces 64 bytes.
    /// </summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Initialises a new <see cref="HmacValue"/> from owned memory.
    /// </summary>
    /// <param name="sensitiveMemory">The owned memory. Ownership transfers to this instance.</param>
    /// <param name="tag">Metadata including algorithm, purpose, and CBOM provenance entries.</param>
    /// <param name="lifetime">
    /// Optional OTel activity spanning this value's lifetime. Started by the backend;
    /// stopped on <see cref="SensitiveMemory.Dispose()"/>. Pass <see langword="null"/>
    /// when no OTel listener is active.
    /// </param>
    public HmacValue(IMemoryOwner<byte> sensitiveMemory, Tag tag, Activity? lifetime = null)
        : base(sensitiveMemory, tag, lifetime)
    {
        hmacLifetime = lifetime;
    }


    /// <summary>
    /// Tags the OTel lifetime activity with algorithm and output length before the
    /// base disposes the memory and stops the activity.
    /// </summary>
    protected override void Dispose(bool disposing)
    {
        if(disposing
            && hmacLifetime is not null
            && Tag.TryGet(out HashAlgorithmName algorithmName))
        {
            hmacLifetime.SetTag(CryptoTelemetry.Hmac.Algorithm, algorithmName.Name);
            hmacLifetime.SetTag(CryptoTelemetry.Hmac.OutputLength, Length);
        }

        base.Dispose(disposing);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] HmacValue? other)
    {
        return other is not null
            && MemoryOwner.Memory.Span.SequenceEqual(other.MemoryOwner.Memory.Span);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj)
    {
        return obj switch
        {
            HmacValue h => Equals(h),
            SensitiveMemory sm => base.Equals(sm),
            _ => false
        };
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();


    /// <summary>
    /// Determines whether two <see cref="HmacValue"/> instances contain identical bytes.
    /// </summary>
    /// <remarks>
    /// Equality is byte-level only. Two HMAC values computed with different algorithms
    /// may compare equal if their bytes happen to match — always verify that both
    /// instances carry the same algorithm <see cref="Tag"/> before treating equality
    /// as meaningful. For cryptographic verification use the dedicated verify path,
    /// which performs constant-time comparison.
    /// </remarks>
    public static bool operator ==(HmacValue? left, HmacValue? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>Determines whether two <see cref="HmacValue"/> instances differ.</summary>
    public static bool operator !=(HmacValue? left, HmacValue? right) => !(left == right);


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

            return $"HmacValue({span.Length} bytes, {hexPreview}{ellipsis})";
        }
    }
}
