using System.Diagnostics;

namespace Verifiable.Server;

/// <summary>
/// An immutable snapshot of the dispatch host's protocol-neutral configuration:
/// the endpoint builders that contribute the endpoints each protocol flow supports.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ServerConfiguration"/> is the unit of atomic change for the host's
/// composable surface. Mutating the running host's set of endpoint builders happens
/// by constructing a new <see cref="ServerConfiguration"/> and calling
/// <see cref="EndpointServer.ApplyConfiguration"/>. The reference swap is atomic;
/// in-flight dispatches that captured the previous configuration finish on it; new
/// dispatches see the new one.
/// </para>
/// <para>
/// The builder set is itself immutable; this configuration is a value-shaped wrapper
/// around a reference to that set. Each protocol family carries its own family-scoped
/// configuration (token producers, claim issuers, action executors, cryptography) on
/// its family integration, registered through the host's integration registry — the
/// neutral configuration carries nothing any single family owns.
/// </para>
/// </remarks>
[DebuggerDisplay("ServerConfiguration EndpointBuilders={EndpointBuilders.Count}")]
public sealed record ServerConfiguration
{
    /// <summary>
    /// An empty configuration carrying an empty builder set. Useful as a starting
    /// point for compositional construction:
    /// <c>ServerConfiguration.Empty.WithEndpointBuilders(...)</c>.
    /// </summary>
    public static ServerConfiguration Empty { get; } = new()
    {
        EndpointBuilders = EndpointBuilderSet.Empty
    };


    /// <summary>
    /// The endpoint-builder modules that contribute <see cref="ServerEndpoint"/>
    /// records when invoked against a registration.
    /// </summary>
    public required EndpointBuilderSet EndpointBuilders { get; init; }


    /// <summary>
    /// Returns a copy of this configuration with a different
    /// <see cref="EndpointBuilders"/> set. Convenience for non-destructive
    /// updates.
    /// </summary>
    /// <param name="builders">The replacement builder set.</param>
    /// <returns>A new <see cref="ServerConfiguration"/> instance.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builders"/> is <see langword="null"/>.
    /// </exception>
    public ServerConfiguration WithEndpointBuilders(EndpointBuilderSet builders)
    {
        ArgumentNullException.ThrowIfNull(builders);

        return this with { EndpointBuilders = builders };
    }
}
