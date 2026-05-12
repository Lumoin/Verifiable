using System.Collections;
using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// An immutable, ordered set of <see cref="EndpointBuilderDelegate"/> modules
/// that contribute <see cref="ServerEndpoint"/> records when invoked against a
/// <see cref="ClientRecord"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="EndpointBuilderSet"/> is the source-of-truth surface for the
/// modules a server uses to assemble per-registration endpoint chains. The
/// set is immutable: <see cref="Add"/> and <see cref="Plus"/> return new
/// instances rather than mutating in place. Configuration changes happen by
/// constructing a new <see cref="ServerConfiguration"/> (which carries a new
/// <see cref="EndpointBuilderSet"/>) and applying it via
/// <see cref="AuthorizationServer.ApplyConfiguration"/>.
/// </para>
/// <para>
/// The set composes naturally: <c>WellKnownEndpointBuilders.OAuth20</c>
/// can be combined with <c>WellKnownEndpointBuilders.Oidc10</c> and an
/// application-specific set via <see cref="Plus"/>.
/// </para>
/// <para>
/// Order is preserved across construction and composition. Builders are
/// invoked in order during chain assembly; the resulting endpoints are
/// concatenated in the order their producing builders contribute them.
/// </para>
/// <para>
/// <strong>Concurrency.</strong>
/// The set is fully immutable. A single instance is safe for concurrent
/// reads. Configuration mutation happens through atomic reference swaps on
/// <see cref="AuthorizationServer.Configuration"/>, never by mutating an
/// existing set.
/// </para>
/// </remarks>
[DebuggerDisplay("EndpointBuilderSet Count={Count}")]
public sealed class EndpointBuilderSet: IReadOnlyList<EndpointBuilderDelegate>
{
    private EndpointBuilderDelegate[] Builders { get; }


    /// <summary>
    /// An empty <see cref="EndpointBuilderSet"/>.
    /// </summary>
    public static EndpointBuilderSet Empty { get; } = new(Array.Empty<EndpointBuilderDelegate>());


    /// <summary>
    /// Constructs a set wrapping the supplied delegates. The set takes a
    /// snapshot; subsequent mutations of the source list have no effect on
    /// the set.
    /// </summary>
    /// <param name="builders">
    /// The endpoint-builder modules in the order they should be invoked
    /// during chain assembly.
    /// </param>
    /// <exception cref="System.ArgumentNullException">
    /// Thrown when <paramref name="builders"/> is <see langword="null"/>.
    /// </exception>
    public EndpointBuilderSet(IEnumerable<EndpointBuilderDelegate> builders)
    {
        ArgumentNullException.ThrowIfNull(builders);
        Builders = builders.ToArray();
    }


    /// <summary>
    /// Constructs a set wrapping a pre-allocated array. Internal fast-path used
    /// by <see cref="Empty"/> to avoid the defensive copy that the public
    /// constructor performs.
    /// </summary>
    private EndpointBuilderSet(EndpointBuilderDelegate[] builders)
    {
        Builders = builders;
    }


    /// <summary>
    /// The number of builders in the set.
    /// </summary>
    public int Count => Builders.Length;

    /// <summary>
    /// The builder at the given position.
    /// </summary>
    public EndpointBuilderDelegate this[int index] => Builders[index];


    /// <summary>
    /// Returns a new set with <paramref name="builder"/> appended after the
    /// existing builders.
    /// </summary>
    /// <param name="builder">The builder to append.</param>
    /// <returns>A new <see cref="EndpointBuilderSet"/> instance.</returns>
    /// <exception cref="System.ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    public EndpointBuilderSet Add(EndpointBuilderDelegate builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        EndpointBuilderDelegate[] next = new EndpointBuilderDelegate[Builders.Length + 1];
        for(int i = 0; i < Builders.Length; i++)
        {
            next[i] = Builders[i];
        }
        next[Builders.Length] = builder;
        return new EndpointBuilderSet(next);
    }


    /// <summary>
    /// Returns a new set combining this set with another, preserving the
    /// order of <paramref name="other"/>'s builders after this set's.
    /// </summary>
    /// <param name="other">The set to append.</param>
    /// <returns>A new <see cref="EndpointBuilderSet"/> instance.</returns>
    /// <exception cref="System.ArgumentNullException">
    /// Thrown when <paramref name="other"/> is <see langword="null"/>.
    /// </exception>
    public EndpointBuilderSet Plus(EndpointBuilderSet other)
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

        EndpointBuilderDelegate[] next = new EndpointBuilderDelegate[Builders.Length + other.Builders.Length];
        for(int i = 0; i < Builders.Length; i++)
        {
            next[i] = Builders[i];
        }
        for(int j = 0; j < other.Builders.Length; j++)
        {
            next[Builders.Length + j] = other.Builders[j];
        }
        return new EndpointBuilderSet(next);
    }


    /// <inheritdoc/>
    public IEnumerator<EndpointBuilderDelegate> GetEnumerator() => ((IEnumerable<EndpointBuilderDelegate>)Builders).GetEnumerator();

    /// <inheritdoc/>
    IEnumerator IEnumerable.GetEnumerator() => Builders.GetEnumerator();
}
