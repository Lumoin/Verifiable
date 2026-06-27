using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

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
/// Obtain salts through an entropy provider (e.g. <c>MicrosoftEntropyFunctions.GenerateSalt</c>
/// or <c>BouncyCastleEntropyFunctions.GenerateSalt</c>), which supplies the entropy source and
/// records CBOM provenance and entropy-tracking events; <see cref="Generate"/> is the underlying
/// seam those providers call, taking an explicit <see cref="FillEntropyDelegate"/> and
/// <see cref="EntropyHealthObservation"/>. There is deliberately no zero-argument convenience that
/// fills from the OS CSPRNG directly, because that would bypass provenance and entropy tracking.
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
    /// A sensible general-purpose salt length in bytes (16 bytes = 128 bits) —
    /// NIST SP 800-132's 128-bit minimum for salts. A convenience default for
    /// <see cref="Generate(Tag, MemoryPool{byte})"/> and an explicit-provenance
    /// alternative to a literal length; it is <strong>not</strong> a protocol
    /// rule. Salt is a general primitive — its <see cref="Length"/> flows through
    /// the seams and each consumer decides whether a length is sufficient against
    /// the spec that applies to it (e.g. an SD-JWT verifier against RFC 9901 §9.3).
    /// </summary>
    public const int RecommendedByteLength = 16;


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
        Activity? lifetime = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(byteLength, 0);
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(fillEntropy);
        ArgumentNullException.ThrowIfNull(health);
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(byteLength);
        try
        {
            fillEntropy(owner.Memory.Span);
        }
        catch
        {
            //A throwing entropy source (e.g. a TPM/HSM fill that fails) must not leak the rented buffer.
            owner.Dispose();
            throw;
        }

        return new Salt(owner, tag, lifetime);
    }


    /// <summary>
    /// Computes a privacy-preserving commitment to this salt — the digest of its bytes — without
    /// exposing the salt itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A salt is not secret, but a commitment is what a reuse-detection store should hold: it lets an
    /// application record "this salt was seen (under this identifier)" and later test a new salt for a
    /// match by comparing commitments, so the raw salt bytes never have to leave this type or be
    /// persisted. The commitment is deterministic — the same salt bytes always yield the same
    /// <see cref="DigestValue"/> under the same hash function — which is exactly what equality testing
    /// for reuse needs. This is a general operation on the primitive (the digest of a value, like a
    /// thumbprint); it embeds no protocol semantics, and detection/keying are the caller's concern.
    /// </para>
    /// </remarks>
    /// <param name="hashFunction">
    /// The hash function to apply, e.g. <c>SHA256.HashData</c>. The caller chooses the algorithm; pass
    /// the matching <paramref name="outputByteLength"/> and <paramref name="tag"/>.
    /// </param>
    /// <param name="outputByteLength">The hash output length in bytes (32 for SHA-256, 48 for SHA-384, 64 for SHA-512).</param>
    /// <param name="tag">The tag identifying the hash algorithm, carried on the returned digest.</param>
    /// <param name="pool">The memory pool to allocate the digest from.</param>
    /// <param name="lifetime">Optional OTel activity bracketing the digest's lifetime.</param>
    /// <returns>A <see cref="DigestValue"/> committing to this salt's bytes. The caller owns and disposes it.</returns>
    public DigestValue ComputeCommitment(
        HashFunctionDelegate hashFunction,
        int outputByteLength,
        Tag tag,
        MemoryPool<byte> pool,
        Activity? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(hashFunction);
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        return DigestValue.Compute(MemoryOwner.Memory.Span, hashFunction, outputByteLength, tag, pool, lifetime);
    }


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