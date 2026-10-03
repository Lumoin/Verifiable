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
/// resolved drives tenant resolution, the first policy resolution and the first chain match;
/// this seam supplies whatever registration data instead depends on the client's own published
/// data. Running it post-match, for the one matched endpoint only, keeps requests that never
/// need that data (discovery, JWKS) from paying its cost.
/// </para>
/// <para>
/// The registration this seam answers is the one the request is judged by. For a record of the
/// loaded registration's type, its policy and issuer are resolved again through
/// <see cref="ServerIntegration.ResolvePolicyAsync"/> and <see cref="ServerIntegration.ResolveIssuerAsync"/>,
/// with every entry the loaded registration's policy resolution wrote first returned to the value the
/// request arrived with, or removed when the request arrived without it, so a policy axis its profile
/// does not set reads the arriving value or its strict default.
/// </para>
/// <para>
/// The endpoint chain is built again for this seam's registration and the request matched again when
/// the registration does not allow every capability the loaded registration allows, or when its policy
/// resolution leaves a policy entry at another value than the loaded registration's resolution left it,
/// since the endpoint builders read the policy as they build their candidates.
/// </para>
/// <para>
/// It may narrow the capabilities: a capability it removes is answered as one the registration never
/// held. It never widens the chain or the resolved capabilities: the capabilities resolved for it are
/// held to those resolved for the loaded registration and the endpoints built for it to the endpoints
/// of the chain built for the loaded registration, by name, HTTP method and flow kind together. A
/// capability it adds is absent from the set stashed through
/// <see cref="ExchangeContextServerExtensions.SetResolvedCapabilities"/> and is recorded on the dispatch
/// activity as <see cref="Diagnostics.ServerEventNames.MaterializedCapabilityDropped"/>; a candidate a
/// builder's gate admits for it, a gate that reads two capabilities while its candidate carries one, is
/// dropped unless the loaded chain holds an endpoint of that same name, HTTP method and flow kind. The
/// bound does not tell apart a builder that yields, under one name, HTTP method and flow kind, a
/// candidate whose handler depends on a capability beyond the one it carries: the bound compares what a
/// chain records of an endpoint, and a builder is handed the registration as this seam answered it.
/// Whenever the chain is built again, the match-decision inspection runs again for the decision that
/// is executed, so a request's last announced decision is the one executed. An endpoint that reads the
/// registration's own <see cref="IRegistrationRecord.AllowedCapabilities"/> as it runs, rather than the
/// resolved capabilities, reads those of the registration this seam answers.
/// </para>
/// <para>
/// Two cases do not answer as never held, both whenever the chain is built again. First, a
/// token-serving grant this seam's registration adds and the server serves answers <c>404</c> where a
/// registration that never held it answers <c>unauthorized_client</c>: the token endpoint's module
/// registers the grant from the record's own capabilities, so its grant-type refusal declines the
/// grant, while the bound drops the grant's own candidate. Second, when the added capability precedes
/// every kept one in the order the token endpoint takes its grant-type refusal's capability from, the
/// refusal itself carries the added capability and is dropped, so every token request no kept grant
/// candidate owns answers <c>404</c>: a missing or blank <c>grant_type</c>, a grant the server serves
/// that this seam's registration does not hold, the removed one included, and a grant the server does
/// not serve, where a registration that never held the added capability answers
/// <c>invalid_request</c>, <c>unauthorized_client</c> and <c>unsupported_grant_type</c>. The cause of
/// both is the token endpoint's module, which reads the record's own capabilities for its registered
/// grants and for the capability its refusal carries.
/// </para>
/// <para>
/// A record of another type than the loaded one is a fault of the application's wiring whatever its
/// capabilities: the endpoint builders and handlers cannot read it, so no endpoint runs over it and the
/// request is answered <c>500</c> <c>server_error</c>, with the fault recorded on the dispatch activity.
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
/// <c>Routing.ExchangeContextIncomingRequestExtensions.IncomingRequest</c> are already
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
/// <see cref="ExchangeContextServerExtensions.SetRegistration"/> and is judged as
/// <see cref="MaterializeRegistrationDelegate"/> describes before the endpoint runs.
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
