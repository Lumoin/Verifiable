using Verifiable.Core;

namespace Verifiable.Server;

/// <summary>
/// Materializes the client-data-dependent fields of a matched request's registration —
/// for example fetching a client's self-published metadata document — after routing has
/// matched an endpoint and before that endpoint runs. Wired through
/// <see cref="ServerIntegration.MaterializeRegistrationAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// Invoked by <see cref="EndpointServer.DispatchAsync"/> once a request has matched an
/// endpoint and the match-decision inspection stage has run, before the endpoint's own
/// <c>BuildInputAsync</c>. The registration <see cref="ServerIntegration.LoadRegistrationAsync"/>
/// resolved already carries every AS-owned field — capabilities, policy profile, token
/// lifetimes, signing keys — needed to drive tenant resolution, per-request policy, and
/// chain matching; this seam supplies whatever remaining registration data instead depends
/// on the client's own published data. Running it post-match, for the one matched endpoint
/// only, keeps requests that never need that data (discovery, JWKS) from paying its cost.
/// </para>
/// <para>
/// Optional: when left <see langword="null"/>, dispatch proceeds exactly as it does without
/// this seam — the loaded registration reaches the endpoint unchanged.
/// </para>
/// </remarks>
/// <param name="registration">
/// The registration <see cref="ServerIntegration.LoadRegistrationAsync"/> resolved for the
/// matched request.
/// </param>
/// <param name="context">
/// The per-request context. The matched endpoint's capability and the typed
/// <see cref="Routing.ExchangeContextIncomingRequestExtensions.IncomingRequest"/> are already
/// set when this runs.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The materialization outcome — either a registration to continue dispatch with, or a
/// response that short-circuits it.
/// </returns>
public delegate ValueTask<RegistrationMaterialization> MaterializeRegistrationDelegate(
    IRegistrationRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// The outcome of a <see cref="MaterializeRegistrationDelegate"/> call.
/// </summary>
/// <remarks>
/// A non-<see langword="null"/> <see cref="Failure"/> is authoritative:
/// <see cref="EndpointServer.DispatchAsync"/> returns it as the response and never inspects
/// <see cref="Registration"/> in that case. When <see cref="Failure"/> is <see langword="null"/>,
/// a non-<see langword="null"/> <see cref="Registration"/> replaces the loaded registration via
/// <see cref="ExchangeContextServerExtensions.SetRegistration"/> before the endpoint runs.
/// </remarks>
public sealed record RegistrationMaterialization
{
    /// <summary>
    /// The registration to continue dispatch with, or <see langword="null"/> to leave the
    /// currently loaded registration in place.
    /// </summary>
    public IRegistrationRecord? Registration { get; init; }

    /// <summary>
    /// The response that short-circuits dispatch, or <see langword="null"/> to continue with
    /// <see cref="Registration"/>.
    /// </summary>
    public ServerHttpResponse? Failure { get; init; }
}
