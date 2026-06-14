using System.Collections;
using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// An immutable, ordered set of <see cref="TokenProducer"/> modules that
/// compose the response of a token-issuing endpoint.
/// </summary>
/// <remarks>
/// <para>
/// The library's token endpoint walks the set, filters by
/// <see cref="TokenProducer.RequiredCapability"/> and
/// <see cref="TokenProducer.IsApplicable"/>, calls each producer's
/// <see cref="TokenProducer.BuildAsync"/>, and composes the JSON response from
/// the collected tokens keyed by <see cref="TokenProducer.ResponseField"/>.
/// </para>
/// <para>
/// Order matters when two producers target the same response field: the later
/// one wins. The library preserves order across construction and composition.
/// </para>
/// <para>
/// The set is immutable: <see cref="Add"/> and <see cref="Plus"/> return new
/// instances rather than mutating in place. Configuration changes happen by
/// assigning a new <see cref="TokenProducerSet"/> to
/// <see cref="AuthorizationServerIntegration.TokenProducers"/>.
/// </para>
/// <para>
/// <strong>Concurrency.</strong>
/// The set is fully immutable. A single instance is safe for concurrent reads.
/// Configuration mutation happens through atomic reference swaps on
/// <see cref="EndpointServer.Configuration"/>, never by mutating an
/// existing set.
/// </para>
/// </remarks>
[DebuggerDisplay("TokenProducerSet Count={Count}")]
public sealed class TokenProducerSet: IReadOnlyList<TokenProducer>
{
    private TokenProducer[] Producers { get; }


    /// <summary>
    /// An empty <see cref="TokenProducerSet"/>.
    /// </summary>
    public static TokenProducerSet Empty { get; } = new(Array.Empty<TokenProducer>());


    /// <summary>
    /// Constructs a set wrapping the supplied producers. The set takes a
    /// snapshot; subsequent mutations of the source collection have no effect
    /// on the set.
    /// </summary>
    /// <param name="producers">
    /// The token producers in the order they should compose response fields.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="producers"/> is <see langword="null"/>.
    /// </exception>
    public TokenProducerSet(IEnumerable<TokenProducer> producers)
    {
        ArgumentNullException.ThrowIfNull(producers);
        Producers = producers.ToArray();
    }


    private TokenProducerSet(TokenProducer[] producers)
    {
        Producers = producers;
    }


    /// <summary>
    /// The number of producers in the set.
    /// </summary>
    public int Count => Producers.Length;

    /// <summary>
    /// The producer at the given position.
    /// </summary>
    public TokenProducer this[int index] => Producers[index];


    /// <summary>
    /// Returns a new set with <paramref name="producer"/> appended after the
    /// existing producers.
    /// </summary>
    /// <param name="producer">The producer to append.</param>
    /// <returns>A new <see cref="TokenProducerSet"/> instance.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="producer"/> is <see langword="null"/>.
    /// </exception>
    public TokenProducerSet Add(TokenProducer producer)
    {
        ArgumentNullException.ThrowIfNull(producer);
        TokenProducer[] next = new TokenProducer[Producers.Length + 1];
        for(int i = 0; i < Producers.Length; i++)
        {
            next[i] = Producers[i];
        }
        next[Producers.Length] = producer;
        return new TokenProducerSet(next);
    }


    /// <summary>
    /// Returns a new set combining this set with another, preserving the
    /// order of <paramref name="other"/>'s producers after this set's.
    /// </summary>
    /// <param name="other">The set to append.</param>
    /// <returns>A new <see cref="TokenProducerSet"/> instance.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="other"/> is <see langword="null"/>.
    /// </exception>
    public TokenProducerSet Plus(TokenProducerSet other)
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

        TokenProducer[] next = new TokenProducer[Producers.Length + other.Producers.Length];
        for(int i = 0; i < Producers.Length; i++)
        {
            next[i] = Producers[i];
        }
        for(int j = 0; j < other.Producers.Length; j++)
        {
            next[Producers.Length + j] = other.Producers[j];
        }
        return new TokenProducerSet(next);
    }


    /// <inheritdoc/>
    public IEnumerator<TokenProducer> GetEnumerator() => ((IEnumerable<TokenProducer>)Producers).GetEnumerator();

    /// <inheritdoc/>
    IEnumerator IEnumerable.GetEnumerator() => Producers.GetEnumerator();
}
