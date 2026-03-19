using System;
using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;

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
/// <strong>Single-use enforcement.</strong>
/// Call <see cref="UseNonce"/> exactly once to consume the nonce for its intended
/// protocol purpose. The method increments <see cref="UseCount"/> on every call.
/// A value greater than one is a replay signal observable via the OTel lifetime
/// span and the <see cref="UseCount"/> property. Use <c>Debug.Assert(nonce.UseCount == 0)</c>
/// before calling to catch misuse in debug builds.
/// </para>
/// <para>
/// <strong>OTel lifetime span.</strong>
/// When a backend supplies an <see cref="Activity"/> at construction, this class
/// tags it with <c>crypto.nonce.use_count</c> at each <see cref="UseNonce"/> call
/// and stops it on disposal. The base class tags <c>crypto.lifetime_ms</c>.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Nonce: SensitiveMemory, IEquatable<Nonce>
{
    private int useCount;
    private readonly Activity? lifetime;

    /// <summary>Gets the length of the nonce in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;

    /// <summary>
    /// The number of times <see cref="UseNonce"/> has been called.
    /// A value greater than one indicates the nonce has been used more than
    /// once, which undermines its anti-replay guarantee.
    /// </summary>
    public int UseCount => useCount;


    /// <summary>
    /// Initializes a new <see cref="Nonce"/> from owned memory.
    /// </summary>
    /// <param name="sensitiveMemory">The owned memory. Ownership transfers to this instance.</param>
    /// <param name="tag">
    /// Metadata including algorithm, purpose, and CBOM provenance entries stamped by the backend.
    /// </param>
    /// <param name="lifetime">
    /// Optional OTel activity spanning this nonce's lifetime. Started by the backend;
    /// stopped on <see cref="Dispose()"/>. Pass <see langword="null"/> when no OTel
    /// listener is active.
    /// </param>
    public Nonce(IMemoryOwner<byte> sensitiveMemory, Tag tag, Activity? lifetime = null)
        : base(sensitiveMemory, tag, lifetime)
    {
        this.lifetime = lifetime;
    }


    /// <summary>
    /// Signals that this nonce is being consumed for its intended protocol purpose
    /// and returns its bytes. Increments <see cref="UseCount"/> on each call.
    /// </summary>
    /// <returns>The nonce bytes as a read-only span.</returns>
    /// <remarks>
    /// <para>
    /// This method is not enforced — <see cref="AsReadOnlySpan"/> still provides
    /// access to the bytes regardless. <see cref="UseNonce"/> exists as an explicit
    /// usage pattern that makes intent clear and makes misuse observable via
    /// <see cref="UseCount"/> and the OTel lifetime span.
    /// </para>
    /// <para>
    /// Check <see cref="UseCount"/> before calling to detect accidental reuse:
    /// </para>
    /// <code>
    /// Debug.Assert(nonce.UseCount == 0, "Nonce has already been used.");
    /// ReadOnlySpan&lt;byte&gt; bytes = nonce.UseNonce();
    /// </code>
    /// </remarks>
    public ReadOnlySpan<byte> UseNonce()
    {
        int count = Interlocked.Increment(ref useCount);
        lifetime?.SetTag(CryptoTelemetry.Nonce.UseCount, count);
        return AsReadOnlySpan();
    }


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
    /// <param name="health">The health observation for the entropy source at generation time.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <param name="lifetime">
    /// Optional OTel activity started by the backend before calling this method.
    /// Passed through to the <see cref="Nonce"/> constructor and stopped on disposal.
    /// </param>
    /// <returns>A new <see cref="Nonce"/> containing cryptographically random bytes.</returns>
    public static Nonce Generate(
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
        fillEntropy(owner.Memory.Span);

        return new Nonce(owner, tag, lifetime);
    }


    /// <summary>
    /// Generates a new nonce using the OS CSPRNG (<see cref="RandomNumberGenerator.Fill"/>).
    /// Convenience overload for the common case where hardware entropy is not required.
    /// </summary>
    public static Nonce Generate(int byteLength, Tag tag, MemoryPool<byte> pool) =>
        Generate(byteLength, tag, RandomNumberGenerator.Fill,
            EntropyHealthObservation.Unknown, pool, lifetime: null);


    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if(disposing)
        {
            lifetime?.SetTag(CryptoTelemetry.Nonce.FinalUseCount, useCount);
            lifetime?.SetTag(CryptoTelemetry.Nonce.Used, useCount > 0);
        }

        base.Dispose(disposing);
    }


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