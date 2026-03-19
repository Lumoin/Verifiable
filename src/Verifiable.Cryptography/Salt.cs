using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Verifiable.Cryptography;

/// <summary>
/// Random bytes whose purpose is to prevent precomputation attacks such as
/// rainbow tables and dictionary attacks.
/// </summary>
/// <remarks>
/// <para>
/// A salt is mixed with a secret before hashing or key derivation, ensuring
/// that two identical inputs produce different outputs when different salts are
/// used. The salt itself is not secret — it is typically stored alongside the
/// derived value — but must be unique per credential or key derivation to be
/// effective.
/// </para>
/// <para>
/// <strong>Distinction from <see cref="Nonce"/>:</strong>
/// Both types are random byte sequences and the terms are sometimes used
/// interchangeably in literature. The difference lies in intent:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       A <see cref="Salt"/> prevents <em>precomputation</em>. It must be unique
///       per credential but may be stored and reused for verification. Examples:
///       password hashing salts (bcrypt, Argon2), KDF input salts (HKDF, PBKDF2),
///       SD-JWT disclosure salts.
///     </description>
///   </item>
///   <item>
///     <description>
///       A <see cref="Nonce"/> prevents <em>replay</em>. It must not be reused
///       across invocations. Examples: PKCE verifiers, AEAD IV values.
///     </description>
///   </item>
/// </list>
/// <para>
/// <strong>Cryptographically strong generation required.</strong>
/// A salt must be generated using a cryptographically strong random number
/// generator. Predictable salts defeat the precomputation resistance they are
/// intended to provide. NIST SP 800-132 recommends at least 16 bytes (128 bits).
/// Use <see cref="Generate"/> which calls <see cref="RandomNumberGenerator.Fill"/>
/// by default, or supply a <see cref="FillEntropyDelegate"/> from a hardware source.
/// </para>
/// <para>
/// <strong>Handling.</strong>
/// This type extends <see cref="SensitiveMemory"/> not because salt values are
/// secret, but because their mishandling — reuse across credentials, insufficient
/// length — reduces security margins.
/// </para>
/// </remarks>
/// <remarks>
/// Initializes a new <see cref="Salt"/> from owned memory.
/// </remarks>
/// <param name="sensitiveMemory">The owned memory. Ownership transfers to this instance.</param>
/// <param name="tag">Metadata including algorithm, purpose, and CBOM provenance entries.</param>
/// <param name="lifetime">
/// Optional OTel activity spanning this salt's lifetime. Started by the backend;
/// stopped on <see cref="SensitiveMemory.Dispose()"/>. Pass <see langword="null"/>
/// when no OTel listener is active.
/// </param>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Salt(IMemoryOwner<byte> sensitiveMemory, Tag tag, Activity? lifetime = null): SensitiveMemory(sensitiveMemory, tag, lifetime), IEquatable<Salt>
{
    /// <summary>Gets the length of the salt in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Generates a new salt using the supplied entropy source.
    /// </summary>
    /// <param name="byteLength">
    /// The number of random bytes to generate. Must be greater than zero.
    /// NIST SP 800-132 recommends at least 16 bytes (128 bits).
    /// </param>
    /// <param name="tag">The tag identifying the purpose of this salt.</param>
    /// <param name="fillEntropy">
    /// The entropy source delegate. Must fill the entire span with
    /// cryptographically random bytes.
    /// </param>
    /// <param name="health">
    /// The health observation for the entropy source at generation time.
    /// </param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>A new <see cref="Salt"/> containing cryptographically random bytes.</returns>
    public static Salt Generate(
        int byteLength,
        Tag tag,
        FillEntropyDelegate fillEntropy,
        EntropyHealthObservation health,
        MemoryPool<byte> pool,
        System.Diagnostics.Activity? lifetime = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(byteLength, 0);
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(fillEntropy);
        ArgumentNullException.ThrowIfNull(health);
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(byteLength);
        fillEntropy(owner.Memory.Span);

        return new Salt(owner, tag, lifetime);
    }


    /// <summary>
    /// Generates a new salt using the OS CSPRNG (<see cref="RandomNumberGenerator.Fill"/>).
    /// Convenience overload for the common case where hardware entropy is not required.
    /// </summary>
    public static Salt Generate(int byteLength, Tag tag, MemoryPool<byte> pool) =>
        Generate(byteLength, tag, RandomNumberGenerator.Fill,
            EntropyHealthObservation.Unknown, pool, lifetime: null);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] Salt? other)
    {
        return other is not null
            && MemoryOwner.Memory.Span.SequenceEqual(other.MemoryOwner.Memory.Span);
    }

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj switch { Salt s => Equals(s), SensitiveMemory sm => base.Equals(sm), _ => false };

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <summary>Determines whether two <see cref="Salt"/> instances contain identical bytes.</summary>
    public static bool operator ==(Salt? left, Salt? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Determines whether two <see cref="Salt"/> instances differ.</summary>
    public static bool operator !=(Salt? left, Salt? right) => !(left == right);

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

            return $"Salt({span.Length} bytes, {hexPreview}{ellipsis})";
        }
    }
}