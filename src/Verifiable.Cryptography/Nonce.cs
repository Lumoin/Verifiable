using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography;

/// <summary>
/// A value that must be used at most once within its scope of application.
/// </summary>
/// <remarks>
/// <para>
/// The word <em>nonce</em> is a contraction of "number used once". The critical
/// invariant is uniqueness within the scope of use — not secrecy per se, though
/// many protocols derive security from both properties simultaneously.
/// </para>
/// <para>
/// <strong>Distinction from <see cref="Salt"/>:</strong>
/// Both types are random byte sequences and the terms are sometimes used
/// interchangeably in literature. The difference lies in intent:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       A <see cref="Nonce"/> prevents <em>replay</em>. It must not be reused
///       across invocations of the same protocol step. Examples: PKCE verifier,
///       OAuth <c>nonce</c> claim, TLS record nonces, AEAD IV values.
///     </description>
///   </item>
///   <item>
///     <description>
///       A <see cref="Salt"/> prevents <em>precomputation</em>. It must be unique
///       per credential or key but may be stored alongside it. Examples: password
///       hashing salts, KDF input salts.
///     </description>
///   </item>
/// </list>
/// <para>
/// <strong>Cryptographically strong generation required.</strong>
/// A nonce must be generated using a cryptographically strong random number
/// generator. Predictable or sequentially generated nonces undermine the
/// anti-replay guarantee. Use <see cref="Generate"/> which calls
/// <see cref="RandomNumberGenerator.Fill"/> by default, or supply a
/// <see cref="FillEntropyDelegate"/> from a hardware source (TPM, HSM).
/// </para>
/// <para>
/// <strong>Handling.</strong>
/// This type extends <see cref="SensitiveMemory"/> not because nonce values are
/// necessarily secret, but because their mishandling — wrong length, encoding
/// errors, accidental reuse — can break protocol security.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Nonce(IMemoryOwner<byte> sensitiveMemory, Tag tag): SensitiveMemory(sensitiveMemory, tag), IEquatable<Nonce>
{
    /// <summary>Gets the length of the nonce in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Generates a new nonce using the supplied entropy source.
    /// </summary>
    /// <param name="byteLength">
    /// The number of random bytes to generate. Must be greater than zero.
    /// RFC 7636 §4.1 requires at least 32 bytes for PKCE verifiers.
    /// </param>
    /// <param name="tag">The tag identifying the purpose of this nonce.</param>
    /// <param name="fillEntropy">
    /// The entropy source delegate. Must fill the entire span with
    /// cryptographically random bytes. Use <see cref="RandomNumberGenerator.Fill"/>
    /// for software CSPRNG or a TPM/HSM delegate for hardware entropy.
    /// </param>
    /// <param name="health">
    /// The health observation for the entropy source at generation time.
    /// </param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>A new <see cref="Nonce"/> containing cryptographically random bytes.</returns>
    public static Nonce Generate(
        int byteLength,
        Tag tag,
        FillEntropyDelegate fillEntropy,
        EntropyHealthObservation health,
        MemoryPool<byte> pool)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(byteLength, 0);
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(fillEntropy);
        ArgumentNullException.ThrowIfNull(health);
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(byteLength);
        fillEntropy(owner.Memory.Span);

        Purpose purpose = tag.TryGet<Purpose>(out Purpose p) ? p : Purpose.Nonce;
        EntropySource source = tag.TryGet<EntropySource>(out EntropySource s) ? s : EntropySource.Unknown;

        CryptoObservable.Emit(EntropyConsumedEvent.Create(source, byteLength, purpose, health));

        return new Nonce(owner, tag);
    }


    /// <summary>
    /// Generates a new nonce using the OS CSPRNG (<see cref="RandomNumberGenerator.Fill"/>).
    /// Convenience overload for the common case where hardware entropy is not required.
    /// </summary>
    public static Nonce Generate(int byteLength, Tag tag, MemoryPool<byte> pool) =>
        Generate(byteLength, tag, RandomNumberGenerator.Fill, EntropyHealthObservation.Unknown, pool);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] Nonce? other)
    {
        return other is not null
            && MemoryOwner.Memory.Span.SequenceEqual(other.MemoryOwner.Memory.Span);
    }

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj switch { Nonce n => Equals(n), SensitiveMemory sm => base.Equals(sm), _ => false };

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <summary>Determines whether two <see cref="Nonce"/> instances contain identical bytes.</summary>
    public static bool operator ==(Nonce? left, Nonce? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Determines whether two <see cref="Nonce"/> instances differ.</summary>
    public static bool operator !=(Nonce? left, Nonce? right) => !(left == right);

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
            return $"Nonce({span.Length} bytes, {hexPreview}{ellipsis})";
        }
    }
}