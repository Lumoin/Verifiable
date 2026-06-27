using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography;

/// <summary>
/// The output of a block-cipher Message Authentication Code computation — a keyed
/// tag produced by a CBC-MAC family construction over a symmetric block cipher,
/// such as AES-CMAC (RFC 4493) or the ISO/IEC 9797-1 MAC Algorithm 3 ("Retail MAC")
/// over DES used by ICAO Doc 9303 Secure Messaging.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Distinction from <see cref="HmacValue"/>.</strong>
/// Both are symmetric MACs — produced and verified under the same key. An
/// <see cref="HmacValue"/> is the output of the HMAC construction (RFC 2104), a keyed
/// <em>hash</em>. A <see cref="MacValue"/> is the output of a keyed <em>block cipher</em>
/// run as a MAC (CMAC, Retail MAC). The constructions differ and the bytes are not
/// interchangeable; the algorithm is identified by the <see cref="CryptoAlgorithm"/>
/// carried in the <see cref="Tag"/>, with <see cref="Purpose.Mac"/>.
/// </para>
/// <para>
/// <strong>Distinction from <see cref="Verifiable.Cryptography.Aead.AuthenticationTag"/>.</strong>
/// An <see cref="Verifiable.Cryptography.Aead.AuthenticationTag"/> is the MAC produced
/// <em>inside</em> an AEAD cipher (GHASH for AES-GCM, Poly1305 for ChaCha20-Poly1305) and
/// is bound to a single encryption operation. A <see cref="MacValue"/> is a standalone MAC
/// over arbitrary input, computed independently of any encryption.
/// </para>
/// <para>
/// <strong>Handling.</strong>
/// Like <see cref="HmacValue"/>, this type extends <see cref="SensitiveMemory"/> not because
/// MAC tag values are secret — they are transmitted in the clear — but because their
/// mishandling (algorithm confusion, truncation, non-constant-time comparison) can break
/// protocol correctness or enable timing attacks. Verify with
/// <see cref="VerifyBlockCipherMacDelegate"/>, not byte equality — verification uses
/// <see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class MacValue: SensitiveMemory, IEquatable<MacValue>
{
    private Activity? MacLifetime { get; }

    /// <summary>
    /// The length of the MAC tag in bytes. The ICAO Doc 9303 Retail MAC and the
    /// AES-CMAC truncation it pairs with both produce 8 bytes.
    /// </summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Initialises a new <see cref="MacValue"/> from owned memory.
    /// </summary>
    /// <param name="sensitiveMemory">The owned memory. Ownership transfers to this instance.</param>
    /// <param name="tag">Metadata including algorithm, purpose, and CBOM provenance entries.</param>
    /// <param name="lifetime">
    /// Optional OTel activity spanning this value's lifetime. Started by the backend;
    /// stopped on <see cref="SensitiveMemory.Dispose()"/>. Pass <see langword="null"/>
    /// when no OTel listener is active.
    /// </param>
    public MacValue(IMemoryOwner<byte> sensitiveMemory, Tag tag, Activity? lifetime = null)
        : base(sensitiveMemory, tag, lifetime)
    {
        MacLifetime = lifetime;
    }


    /// <summary>
    /// Tags the OTel lifetime activity with algorithm and output length before the
    /// base disposes the memory and stops the activity.
    /// </summary>
    protected override void Dispose(bool disposing)
    {
        if(disposing
            && MacLifetime is not null
            && Tag.TryGet(out CryptoAlgorithm algorithm))
        {
            MacLifetime.SetTag(CryptoTelemetry.BlockCipherMac.Algorithm, algorithm.ToString());
            MacLifetime.SetTag(CryptoTelemetry.BlockCipherMac.OutputLength, Length);
        }

        base.Dispose(disposing);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] MacValue? other)
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
            MacValue m => Equals(m),
            SensitiveMemory sm => base.Equals(sm),
            _ => false
        };
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();


    /// <summary>
    /// Determines whether two <see cref="MacValue"/> instances contain identical bytes.
    /// </summary>
    /// <remarks>
    /// Equality is byte-level only. Two MAC values computed with different algorithms
    /// may compare equal if their bytes happen to match — always verify that both
    /// instances carry the same algorithm <see cref="Tag"/> before treating equality
    /// as meaningful. For cryptographic verification use the dedicated verify path,
    /// which performs constant-time comparison.
    /// </remarks>
    public static bool operator ==(MacValue? left, MacValue? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>Determines whether two <see cref="MacValue"/> instances differ.</summary>
    public static bool operator !=(MacValue? left, MacValue? right) => !(left == right);


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

            return $"MacValue({span.Length} bytes, {hexPreview}{ellipsis})";
        }
    }
}
