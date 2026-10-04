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
/// For a record of the loaded registration's type that is another reference, its capabilities are
/// resolved through <see cref="ServerIntegration.ResolveCapabilitiesAsync"/> and held to the bound,
/// whether the chain is kept or built again, whenever the request's context holds the set the request
/// is served under as that registration is judged. The
/// endpoint chain is built again for this seam's registration and the request matched again when the
/// registration does not allow every capability the loaded registration allows, when its policy
/// resolution leaves a policy entry at another value than the loaded registration's resolution left it,
/// since the endpoint builders read the policy as they build their candidates, or when its capabilities
/// resolved and held to the bound are fewer than those resolved for the loaded registration. Otherwise
/// the chain built for the loaded registration and the capabilities resolved for it are kept.
/// </para>
/// <para>
/// It may narrow the capabilities: a capability it removes is answered as one the registration never
/// held. It never widens the chain or the resolved capabilities: the capabilities resolved for it are
/// held to those resolved for the loaded registration and the endpoints built for it to the endpoints
/// of the chain built for the loaded registration, by name, HTTP method and flow kind together. A
/// capability it adds is absent from the set the chain build stashes on the context, read as
/// <c>ResolvedCapabilities</c> of <see cref="ExchangeContextServerExtensions"/>, and is recorded on the dispatch
/// activity as <see cref="Diagnostics.ServerEventNames.MaterializedCapabilityDropped"/>; a candidate a
/// builder's gate admits for it, a gate that reads two capabilities while its candidate carries one, is
/// dropped unless the loaded chain holds an endpoint of that same name, HTTP method and flow kind.
/// Whenever the chain is built again, the match-decision inspection runs again for the decision that
/// is executed, so a request's last announced decision is the one executed.
/// </para>
/// <para>
/// The stashed set is the library's immutable copy of the resolution held to the bound, in the context
/// entry named <c>server.resolvedCapabilities</c>, inside the library's own entry bound to the context it
/// was written for. A value this seam or other code stores under that name that is not the library's own
/// entry for this context, including an entry carried from another request's context, reads as no set,
/// which allows no capability, and the public <see cref="Pipeline.EndpointChain.BuildForRequestAsync"/>
/// refuses the request's context as this seam receives it, since it carries the set the dispatcher's
/// chain build wrote. This seam is the application's code: what it stores in the context, removes from
/// it or builds on it afterwards is the application's to answer for. When this seam answers another
/// reference and the context holds no such entry of the library's as that registration is judged, the
/// request is answered <c>500</c> <c>server_error</c> as a fault of the server's wiring, since that
/// registration's capabilities are held to the stashed set. The library's
/// builders and handlers that act on a capability beyond the one a candidate carries read it, so a
/// capability this seam adds is answered as one the registration never held: the token endpoint's
/// registered grants and the capability its
/// grant-type refusal carries, the request-object endpoints, the end-session back-channel fan-out, the
/// discovery document's back-channel and client ID metadata document members, the federation Entity
/// Configuration's client registration types and the Shared Signals challenge's
/// <c>resource_metadata</c>. A gate that admits a candidate on the capability the candidate itself
/// carries reads the registration's own <see cref="IRegistrationRecord.AllowedCapabilities"/>, and the
/// chain's capability filter holds it to the stashed set. An application's builder or endpoint that reads
/// the registration's own capabilities for anything beyond the candidate it gates reads those of the
/// registration this seam answers, and is held by the endpoint bound only: the bound compares what a
/// chain records of an endpoint, its name, HTTP method and flow kind, not what its handler reads.
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
