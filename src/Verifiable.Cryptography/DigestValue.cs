using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography;

/// <summary>
/// The output of a deterministic hash function applied to some input.
/// </summary>
/// <remarks>
/// <para>
/// This type has several synonyms in cryptographic literature, all referring to
/// the same concept — the fixed-length output produced by applying a hash function
/// to an arbitrary-length input:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       <em>Digest</em> or <em>message digest</em> — the formal cryptographic
///       term, used in standards such as FIPS 180-4 and RFC 4634.
///     </description>
///   </item>
///   <item>
///     <description>
///       <em>Hash</em> or <em>hash value</em> — the common programming term,
///       used in most API documentation and informal usage.
///     </description>
///   </item>
///   <item>
///     <description>
///       <em>Fingerprint</em> or <em>thumbprint</em> — a digest used specifically
///       to identify a key or certificate. JWK thumbprints (RFC 7638) and X.509
///       certificate thumbprints are digests of the DER-encoded structure.
///       The terms fingerprint and thumbprint are themselves synonyms.
///     </description>
///   </item>
/// </list>
/// <para>
/// The <see cref="Tag"/> carries the hash algorithm identifier (e.g. SHA-256,
/// SHA-384) so that two <see cref="DigestValue"/> instances computed with different
/// algorithms are not accidentally compared or interchanged.
/// </para>
/// <para>
/// <strong>Cryptographically strong generation:</strong>
/// Unlike <see cref="Nonce"/> and <see cref="Salt"/>, a <see cref="DigestValue"/>
/// is <em>not</em> randomly generated — it is computed deterministically from its
/// input. No random number generator is involved. Security properties such as
/// preimage resistance and collision resistance derive from the hash algorithm
/// itself, identified by the <see cref="Tag"/>.
/// </para>
/// <para>
/// <strong>Handling:</strong>
/// This type extends <see cref="SensitiveMemory"/> not because digest values are
/// secret — a PKCE challenge, a JWK thumbprint, and a certificate fingerprint are
/// all transmitted in the clear — but because their mishandling (algorithm
/// confusion, truncation, encoding errors) can break protocol correctness or
/// enable substitution attacks. Pooled ownership and deterministic disposal
/// enforce disciplined use.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class DigestValue(IMemoryOwner<byte> sensitiveMemory, Tag tag): SensitiveMemory(sensitiveMemory, tag), IEquatable<DigestValue>
{
    /// <summary>
    /// Gets the length of the digest in bytes. SHA-256 produces 32 bytes,
    /// SHA-384 produces 48 bytes, SHA-512 produces 64 bytes.
    /// </summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Computes a <see cref="DigestValue"/> over <paramref name="input"/> using
    /// the hash function supplied by <paramref name="hashFunction"/>.
    /// </summary>
    /// <param name="input">The bytes to hash.</param>
    /// <param name="hashFunction">
    /// The hash function to apply. Matches the signature of standard .NET hash
    /// methods such as <c>SHA256.HashData</c>, <c>SHA384.HashData</c>, and
    /// <c>SHA512.HashData</c>, allowing direct method group usage.
    /// </param>
    /// <param name="outputByteLength">
    /// The expected output length in bytes. Must match the hash function's output
    /// size: 32 for SHA-256, 48 for SHA-384, 64 for SHA-512.
    /// </param>
    /// <param name="tag">
    /// The tag identifying the hash algorithm, e.g. a <c>HashAlgorithmName</c>
    /// carried in a <see cref="Tag"/>.
    /// </param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>A new <see cref="DigestValue"/> containing the computed digest.</returns>
    public static DigestValue Compute(
        ReadOnlySpan<byte> input,
        HashFunctionDelegate hashFunction,
        int outputByteLength,
        Tag tag,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(hashFunction);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(outputByteLength, 0);
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(outputByteLength);
        hashFunction(input, owner.Memory.Span);

        Purpose purpose = tag.TryGet<Purpose>(out Purpose p) ? p : Purpose.Digest;
        string algorithmName = tag.TryGet<HashAlgorithmName>(out HashAlgorithmName alg)
            ? alg.Name ?? "Unknown"
            : "Unknown";

        CryptoObservable.Emit(DigestComputedEvent.Create(
            algorithmName,
            input.Length,
            outputByteLength,
            purpose));
        return new DigestValue(owner, tag);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] DigestValue? other)
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
            DigestValue d => Equals(d),
            SensitiveMemory sm => base.Equals(sm),
            _ => false
        };
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();


    /// <summary>
    /// Determines whether two <see cref="DigestValue"/> instances contain identical bytes.
    /// </summary>
    /// <remarks>
    /// Equality is byte-level only. Two digests computed with different algorithms
    /// may compare equal if their bytes happen to match — always verify that both
    /// instances carry the same algorithm <see cref="Tag"/> before treating equality
    /// as meaningful.
    /// </remarks>
    public static bool operator ==(DigestValue? left, DigestValue? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>
    /// Determines whether two <see cref="DigestValue"/> instances differ.
    /// </summary>
    public static bool operator !=(DigestValue? left, DigestValue? right) => !(left == right);


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
            return $"DigestValue({span.Length} bytes, {hexPreview}{ellipsis})";
        }
    }
}