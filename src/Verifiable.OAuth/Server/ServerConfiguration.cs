using System;
using System.Diagnostics;
using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Server;

/// <summary>
/// An immutable snapshot of the <see cref="AuthorizationServer"/>'s composable
/// configuration: the endpoint builders that contribute protocol flows, the
/// token producers that compose token-endpoint responses, and the claim
/// contributors that decorate token payloads.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ServerConfiguration"/> is the unit of atomic change. Mutating
/// the running server's set of endpoint builders, token producers, or claim
/// contributors happens by constructing a new <see cref="ServerConfiguration"/>
/// and calling <see cref="AuthorizationServer.ApplyConfiguration"/>. The
/// reference swap is atomic; in-flight dispatches that captured the previous
/// configuration finish on it; new dispatches see the new one. Multiple
/// correlated changes — adding a builder, adding a producer, adding a
/// contributor — commit together.
/// </para>
/// <para>
/// The three set types (<see cref="EndpointBuilderSet"/>,
/// <see cref="TokenProducerSet"/>, <see cref="ClaimContributorSet"/>) are
/// themselves immutable; this configuration is a value-shaped wrapper around
/// references to those sets.
/// </para>
/// <para>
/// <strong>Concurrency.</strong>
/// The configuration is fully immutable. The
/// <see cref="AuthorizationServer.Configuration"/> field holds a single
/// <see cref="ServerConfiguration"/> reference, swapped atomically by
/// <see cref="AuthorizationServer.ApplyConfiguration"/>. Reads need no
/// synchronisation; the .NET memory model guarantees that a published
/// reference is fully visible to subsequent reads.
/// </para>
/// </remarks>
[DebuggerDisplay("ServerConfiguration EndpointBuilders={EndpointBuilders.Count} TokenProducers={TokenProducers.Count} ClaimContributors={ClaimContributors.Count}")]
public sealed record ServerConfiguration
{
    /// <summary>
    /// An empty configuration carrying empty sets for all three surfaces.
    /// Useful as a starting point for compositional construction:
    /// <c>ServerConfiguration.Empty.WithEndpointBuilders(...)</c>.
    /// </summary>
    public static ServerConfiguration Empty { get; } = new()
    {
        EndpointBuilders = EndpointBuilderSet.Empty,
        TokenProducers = TokenProducerSet.Empty,
        ClaimContributors = ClaimContributorSet.Empty
    };


    /// <summary>
    /// The endpoint-builder modules that contribute <see cref="ServerEndpoint"/>
    /// records when invoked against a <see cref="ClientRecord"/>.
    /// </summary>
    public required EndpointBuilderSet EndpointBuilders { get; init; }

    /// <summary>
    /// The token producers that compose the response of a token-issuing
    /// endpoint.
    /// </summary>
    public required TokenProducerSet TokenProducers { get; init; }

    /// <summary>
    /// The claim contributors that decorate token payloads with additional
    /// claims during the token-endpoint pipeline.
    /// </summary>
    public required ClaimContributorSet ClaimContributors { get; init; }


    /// <summary>
    /// Composed claim-contribution issuer running every claim-contribution
    /// rule against the target requested by dispatching code. Each rule
    /// is a <see cref="Core.Assessment.ClaimDelegate{T}"/> over
    /// <see cref="ClaimContributionTarget"/> that pattern-matches on the
    /// target subtype to decide applicability; rules emit
    /// <see cref="Core.Assessment.Claim"/>s carrying
    /// <see cref="ClaimContributionContext"/> payloads. Dispatching code
    /// merges <see cref="Core.Assessment.ClaimOutcome.Success"/>
    /// contributions into the response payload.
    /// </summary>
    /// <remarks>
    /// Phase A introduces this slot alongside the legacy
    /// <see cref="ClaimContributors"/> set. The slot is nullable during
    /// the migration window (chunks 3–5); once the walking sites and
    /// producer migrate to consume this issuer (chunk 4b) and the
    /// legacy surface is deleted (chunk 6), this becomes <c>required</c>
    /// and <see cref="ClaimContributors"/> is removed. Wire via
    /// <see cref="ContributionProfiles.StandardClaimIssuer"/> for the
    /// library's standard OIDC contributor set, or compose a custom
    /// issuer.
    /// </remarks>
    public ClaimIssuer<ClaimContributionTarget>? ClaimIssuer { get; init; }


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


    /// <summary>
    /// Returns a copy of this configuration with a different
    /// <see cref="TokenProducers"/> set.
    /// </summary>
    /// <param name="producers">The replacement producer set.</param>
    /// <returns>A new <see cref="ServerConfiguration"/> instance.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="producers"/> is <see langword="null"/>.
    /// </exception>
    public ServerConfiguration WithTokenProducers(TokenProducerSet producers)
    {
        ArgumentNullException.ThrowIfNull(producers);
        return this with { TokenProducers = producers };
    }


    /// <summary>
    /// Returns a copy of this configuration with a different
    /// <see cref="ClaimContributors"/> set.
    /// </summary>
    /// <param name="contributors">The replacement contributor set.</param>
    /// <returns>A new <see cref="ServerConfiguration"/> instance.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="contributors"/> is <see langword="null"/>.
    /// </exception>
    public ServerConfiguration WithClaimContributors(ClaimContributorSet contributors)
    {
        ArgumentNullException.ThrowIfNull(contributors);
        return this with { ClaimContributors = contributors };
    }
}
