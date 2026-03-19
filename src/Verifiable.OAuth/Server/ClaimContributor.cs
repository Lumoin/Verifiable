using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.Server;

/// <summary>
/// A pluggable source of additional claims merged into a token's payload during the
/// token-endpoint pipeline. Each contributor is invoked once per applicable
/// <see cref="TokenProducer"/> per request and decides via
/// <see cref="IsApplicable"/> whether it contributes for that producer.
/// </summary>
/// <remarks>
/// <para>
/// Contributors are the extension point for content like Verified Claims (per
/// <see href="https://openid.net/specs/openid-ida-verified-claims-1_0-final.html">
/// OIDC Identity Assurance Verified Claims</see>), userinfo claim distribution,
/// authentication-context-class indicators (<c>acr</c> / <c>amr</c>), application
/// tenancy claims, and any other content that decorates a producer's base payload
/// without changing how the token is built or signed.
/// </para>
/// <para>
/// The endpoint handler walks
/// <see cref="AuthorizationServerOptions.ClaimContributors"/> for each applicable
/// producer and merges the contributed claims into the producer's payload before
/// signing. Contributors run in list order; later contributors overwrite earlier
/// values for the same claim name.
/// </para>
/// <para>
/// Both <see cref="IsApplicable"/> and <see cref="BuildAsync"/> receive the
/// producer being processed so contributors can target a specific token type and
/// branch their output:
/// </para>
/// <code>
/// extension(ClaimContributor)
/// {
///     public static ClaimContributor IdTokenAcr => new()
///     {
///         Name = "id-token-acr",
///         IsApplicable = (ctx, producer, _) =>
///             ValueTask.FromResult(WellKnownTokenTypes.IsIdToken(producer.ResponseField)),
///         BuildAsync = (ctx, producer, _) => /* read acr from the flow state, return claim */
///     };
/// }
/// </code>
/// </remarks>
[DebuggerDisplay("ClaimContributor {Name,nq}")]
public sealed record ClaimContributor
{
    /// <summary>
    /// A diagnostic identifier for this contributor used in logging and tracing.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// Whether this contributor applies to the current request and producer.
    /// </summary>
    public required ClaimContributorIsApplicableDelegate IsApplicable { get; init; }

    /// <summary>
    /// Produces the additional claims this contributor wants merged into the
    /// producer's payload.
    /// </summary>
    public required ClaimContributorBuildDelegate BuildAsync { get; init; }
}


/// <summary>
/// Determines whether a <see cref="ClaimContributor"/> applies for the given
/// request context and the producer currently being processed.
/// </summary>
/// <param name="context">The per-request issuance context.</param>
/// <param name="producer">The token producer the contributor would decorate.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// <see langword="true"/> when the contributor should run for this producer in this
/// request; <see langword="false"/> to skip it.
/// </returns>
public delegate ValueTask<bool> ClaimContributorIsApplicableDelegate(
    IssuanceContext context,
    TokenProducer producer,
    CancellationToken cancellationToken);


/// <summary>
/// Builds the additional claims contributed for the producer being processed.
/// </summary>
/// <remarks>
/// <para>
/// The returned dictionary is merged into the producer's payload by the endpoint
/// handler. Contributors that read from external sources (databases, downstream
/// services, hardware attestations) do their I/O here. Contributors that compute
/// claims from in-context state alone return the claims directly without I/O.
/// </para>
/// <para>
/// A contributor may add claims at any path supported by <see cref="JwtPayload"/>;
/// nested structures (e.g., the <c>verified_claims</c> object) are supplied as
/// dictionary values that the payload serializer handles transparently.
/// </para>
/// <para>
/// The <paramref name="producer"/> argument allows contributors that target more
/// than one token type to branch their output without storing per-call state.
/// </para>
/// </remarks>
/// <param name="context">The per-request issuance context.</param>
/// <param name="producer">The token producer the contribution applies to.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The claims to merge into the producer's payload.</returns>
public delegate ValueTask<IReadOnlyDictionary<string, object>> ClaimContributorBuildDelegate(
    IssuanceContext context,
    TokenProducer producer,
    CancellationToken cancellationToken);
