using System;
using System.Diagnostics;
using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Server;

/// <summary>
/// An immutable snapshot of the <see cref="AuthorizationServer"/>'s composable
/// configuration: the endpoint builders that contribute protocol flows, the
/// token producers that compose token-endpoint responses, and the composed
/// <see cref="ClaimIssuer{T}"/> that emits the additional claims merged into
/// token payloads.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ServerConfiguration"/> is the unit of atomic change. Mutating
/// the running server's set of endpoint builders, token producers, or the
/// claim issuer happens by constructing a new <see cref="ServerConfiguration"/>
/// and calling <see cref="AuthorizationServer.ApplyConfiguration"/>. The
/// reference swap is atomic; in-flight dispatches that captured the previous
/// configuration finish on it; new dispatches see the new one. Multiple
/// correlated changes — adding a builder, adding a producer, swapping the
/// issuer — commit together.
/// </para>
/// <para>
/// The two set types (<see cref="EndpointBuilderSet"/> and
/// <see cref="TokenProducerSet"/>) are themselves immutable; this
/// configuration is a value-shaped wrapper around references to those sets
/// plus the immutable <see cref="ClaimIssuer{T}"/>.
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
[DebuggerDisplay("ServerConfiguration EndpointBuilders={EndpointBuilders.Count} TokenProducers={TokenProducers.Count}")]
public sealed record ServerConfiguration
{
    /// <summary>
    /// An empty configuration carrying empty builder and producer sets and
    /// an empty (rule-less) <see cref="ClaimIssuer{T}"/>. Useful as a
    /// starting point for compositional construction:
    /// <c>ServerConfiguration.Empty.WithEndpointBuilders(...)</c>.
    /// </summary>
    /// <remarks>
    /// The empty issuer carries no rules — equivalent to "no claim
    /// contributions are produced." Applications composing from
    /// <see cref="Empty"/> typically replace the issuer via
    /// <c>this with { ClaimIssuer = ContributionProfiles.StandardClaimIssuer(timeProvider) }</c>
    /// before applying the configuration.
    /// </remarks>
    public static ServerConfiguration Empty { get; } = new()
    {
        EndpointBuilders = EndpointBuilderSet.Empty,
        TokenProducers = TokenProducerSet.Empty,
        ClaimIssuer = new ClaimIssuer<ClaimContributionTarget>(
            WellKnownAssessorIds.ClaimContributors,
            [],
            TimeProvider.System)
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
    /// Composed claim-contribution issuer running every claim-contribution
    /// rule against the target requested by dispatching code. Each rule
    /// is a <see cref="Core.Assessment.ClaimDelegate{T}"/> over
    /// <see cref="ClaimContributionTarget"/> that pattern-matches on the
    /// target subtype to decide applicability; rules emit
    /// <see cref="Core.Assessment.Claim"/>s carrying
    /// <see cref="ClaimContributionContext"/> payloads. The token endpoint's
    /// walking site merges <see cref="Core.Assessment.ClaimOutcome.Success"/>
    /// contributions into the response payload.
    /// </summary>
    /// <remarks>
    /// Wire via <see cref="ContributionProfiles.StandardClaimIssuer"/> for
    /// the library's standard OIDC contributor set (profile / email /
    /// address / phone / cnf / acr+amr+auth_time), or compose a custom
    /// <see cref="ClaimIssuer{T}"/> with an application-specific rule list.
    /// </remarks>
    public required ClaimIssuer<ClaimContributionTarget> ClaimIssuer { get; init; }


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
    /// <see cref="ClaimIssuer"/>.
    /// </summary>
    /// <param name="issuer">The replacement issuer.</param>
    /// <returns>A new <see cref="ServerConfiguration"/> instance.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="issuer"/> is <see langword="null"/>.
    /// </exception>
    public ServerConfiguration WithClaimIssuer(ClaimIssuer<ClaimContributionTarget> issuer)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        return this with { ClaimIssuer = issuer };
    }
}
