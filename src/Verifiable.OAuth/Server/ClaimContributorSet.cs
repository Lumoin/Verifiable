using System.Collections;
using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// An immutable, ordered set of <see cref="ClaimContributor"/> modules that
/// decorate token payloads with additional claims during the token-endpoint
/// pipeline.
/// </summary>
/// <remarks>
/// <para>
/// Each contributor's <see cref="ClaimContributor.IsApplicable"/> receives the
/// <see cref="TokenProducer"/> currently being processed, so contributors
/// target specific token types — Verified Claims contributing to the ID token,
/// tenancy claims contributing to the access token, ACR/AMR contributing to
/// the ID token based on authentication events, and so on.
/// </para>
/// <para>
/// Contributors run in set order after the producer's
/// <see cref="TokenProducer.BuildAsync"/> returns; later contributors overwrite
/// earlier values for the same claim name. The library preserves order across
/// construction and composition.
/// </para>
/// <para>
/// The set is immutable: <see cref="Add"/> and <see cref="Plus"/> return new
/// instances rather than mutating in place. Configuration changes happen by
/// constructing a new <see cref="ServerConfiguration"/> (which carries a new
/// <see cref="ClaimContributorSet"/>) and applying it via
/// <see cref="AuthorizationServer.ApplyConfiguration"/>.
/// </para>
/// <para>
/// <strong>Concurrency.</strong>
/// The set is fully immutable. A single instance is safe for concurrent reads.
/// Configuration mutation happens through atomic reference swaps on
/// <see cref="AuthorizationServer.Configuration"/>, never by mutating an
/// existing set.
/// </para>
/// </remarks>
[DebuggerDisplay("ClaimContributorSet Count={Count}")]
public sealed class ClaimContributorSet: IReadOnlyList<ClaimContributor>
{
    private ClaimContributor[] Contributors { get; }


    /// <summary>
    /// An empty <see cref="ClaimContributorSet"/>.
    /// </summary>
    public static ClaimContributorSet Empty { get; } = new(Array.Empty<ClaimContributor>());


    /// <summary>
    /// Constructs a set wrapping the supplied contributors. The set takes a
    /// snapshot; subsequent mutations of the source collection have no effect
    /// on the set.
    /// </summary>
    /// <param name="contributors">
    /// The claim contributors in the order they should run during token
    /// composition.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="contributors"/> is <see langword="null"/>.
    /// </exception>
    public ClaimContributorSet(IEnumerable<ClaimContributor> contributors)
    {
        ArgumentNullException.ThrowIfNull(contributors);
        Contributors = contributors.ToArray();
    }


    private ClaimContributorSet(ClaimContributor[] contributors)
    {
        Contributors = contributors;
    }


    /// <summary>
    /// The number of contributors in the set.
    /// </summary>
    public int Count => Contributors.Length;

    /// <summary>
    /// The contributor at the given position.
    /// </summary>
    public ClaimContributor this[int index] => Contributors[index];


    /// <summary>
    /// Returns a new set with <paramref name="contributor"/> appended after the
    /// existing contributors.
    /// </summary>
    /// <param name="contributor">The contributor to append.</param>
    /// <returns>A new <see cref="ClaimContributorSet"/> instance.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="contributor"/> is <see langword="null"/>.
    /// </exception>
    public ClaimContributorSet Add(ClaimContributor contributor)
    {
        ArgumentNullException.ThrowIfNull(contributor);
        ClaimContributor[] next = new ClaimContributor[Contributors.Length + 1];
        for(int i = 0; i < Contributors.Length; i++)
        {
            next[i] = Contributors[i];
        }
        next[Contributors.Length] = contributor;
        return new ClaimContributorSet(next);
    }


    /// <summary>
    /// Returns a new set combining this set with another, preserving the
    /// order of <paramref name="other"/>'s contributors after this set's.
    /// </summary>
    /// <param name="other">The set to append.</param>
    /// <returns>A new <see cref="ClaimContributorSet"/> instance.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="other"/> is <see langword="null"/>.
    /// </exception>
    public ClaimContributorSet Plus(ClaimContributorSet other)
    {
        ArgumentNullException.ThrowIfNull(other);
        if(other.Count == 0)
        {
            return this;
        }
        if(Count == 0)
        {
            return other;
        }

        ClaimContributor[] next = new ClaimContributor[Contributors.Length + other.Contributors.Length];
        for(int i = 0; i < Contributors.Length; i++)
        {
            next[i] = Contributors[i];
        }
        for(int j = 0; j < other.Contributors.Length; j++)
        {
            next[Contributors.Length + j] = other.Contributors[j];
        }
        return new ClaimContributorSet(next);
    }


    /// <inheritdoc/>
    public IEnumerator<ClaimContributor> GetEnumerator() => ((IEnumerable<ClaimContributor>)Contributors).GetEnumerator();

    /// <inheritdoc/>
    IEnumerator IEnumerable.GetEnumerator() => Contributors.GetEnumerator();
}
