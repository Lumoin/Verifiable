using System;
using System.Security.Cryptography;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Ready-made <see cref="DecoyDigestCountDelegate"/> policies for issuing decoy digests.
/// </summary>
/// <remarks>
/// <para>
/// Decoy digests (<see href="https://www.rfc-editor.org/rfc/rfc9901.html#section-4.2.5">RFC 9901 §4.2.5</see>)
/// are an <strong>opt-in</strong> privacy enhancement. The default at every issuance entry point is
/// <see cref="None"/>: the issued token then contains exactly the claims the issuer specified, in the
/// minimal, deterministic, spec-canonical form. That default is a correctness choice, not a
/// test-convenience one — decoys add size, make issuance non-deterministic, and only obscure the
/// claim <em>count</em> when provisioned in a schema-aware way; applied blindly and uniformly they
/// are privacy theatre. The issuer is the party that knows its schema and threat model, so it opts in.
/// </para>
/// <para>
/// When an issuer does opt in, this type drives the randomization so callers need not write their own
/// RNG: <see cref="Random(int, int)"/> draws a cryptographically-random count per <c>_sd</c> location.
/// </para>
/// </remarks>
public static class DecoyDigestPolicy
{
    /// <summary>
    /// Adds no decoy digests. This is the default at every issuance entry point.
    /// </summary>
    public static DecoyDigestCountDelegate None { get; } = static _ => 0;


    /// <summary>
    /// Adds a fixed number of decoy digests at every <c>_sd</c> location.
    /// </summary>
    /// <param name="count">The number of decoys to add at each location. Must be non-negative.</param>
    /// <remarks>
    /// A constant count is itself a (weak) signal — every object of a given type carries the same number
    /// of extra digests. Prefer <see cref="Random(int, int)"/> unless a fixed count is specifically wanted.
    /// </remarks>
    public static DecoyDigestCountDelegate Fixed(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);

        return _ => count;
    }


    /// <summary>
    /// Adds a cryptographically-random number of decoy digests in the inclusive range
    /// <paramref name="minInclusive"/>..<paramref name="maxInclusive"/>, drawn independently at each
    /// <c>_sd</c> location.
    /// </summary>
    /// <param name="minInclusive">The minimum number of decoys (inclusive). Must be non-negative.</param>
    /// <param name="maxInclusive">The maximum number of decoys (inclusive). Must be at least <paramref name="minInclusive"/>.</param>
    /// <remarks>
    /// The count is drawn with <see cref="RandomNumberGenerator.GetInt32(int, int)"/> so the library,
    /// not the caller, owns the randomization. Drawing per location obscures the per-object claim count
    /// independently.
    /// </remarks>
    public static DecoyDigestCountDelegate Random(int minInclusive, int maxInclusive)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(minInclusive);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxInclusive, minInclusive);

        //GetInt32's upper bound is exclusive; +1 makes maxInclusive reachable.
        return _ => RandomNumberGenerator.GetInt32(minInclusive, maxInclusive + 1);
    }


    /// <summary>
    /// Pads every <c>_sd</c> location up to <paramref name="bucketSize"/> total digests, so an
    /// adversarial verifier sees the same digest count at each padded location regardless of how many
    /// claims are actually disclosable there. A location that already has at least
    /// <paramref name="bucketSize"/> real disclosures gets no decoys.
    /// </summary>
    /// <param name="bucketSize">The target total digest count per location. Must be non-negative.</param>
    /// <remarks>
    /// This is the canonical count-flattening (k-anonymity-style) strategy and the primary reason the
    /// policy receives a <see cref="DecoyDigestContext"/>: the decoy count depends on how many real
    /// disclosures are at the location being padded.
    /// </remarks>
    public static DecoyDigestCountDelegate PadToBucket(int bucketSize)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(bucketSize);

        return context => Math.Max(0, bucketSize - context.RealDisclosureCount);
    }
}
