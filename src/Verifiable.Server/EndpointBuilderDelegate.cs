using Verifiable.Core;

namespace Verifiable.Server;

/// <summary>
/// Builds <see cref="EndpointCandidate"/> records for a given registration,
/// leaving URI resolution to
/// the dispatcher's chain build, which projects
/// each candidate to a complete <see cref="ServerEndpoint"/> after resolving its
/// endpoint URI.
/// </summary>
/// <remarks>
/// <para>
/// Every protocol flow is a module registered on the host configuration's
/// endpoint-builder set. Library-provided modules and application-provided
/// modules use the same delegate shape and are treated identically.
/// </para>
/// <para>
/// The delegate is called once by each chain build the dispatcher runs for a request: the build
/// for the registration it loaded and, when one follows, the build for a materialized registration.
/// Return an empty
/// list when the registration does not have the capabilities your flow
/// requires, or when per-request signals on <paramref name="context"/>
/// indicate this flow's endpoints should not be active for this request.
/// </para>
/// <para>
/// <strong>Per-request gating.</strong>
/// The <paramref name="context"/> parameter lets the builder read tenant
/// configuration, feature flags, request-time signals (the typed
/// <see cref="IncomingRequest"/> envelope, headers, fields, route values), or
/// per-client policy that determines whether this builder's endpoints belong
/// in the chain for this request. Builders that need backend access read it
/// from <c>context.RequestServer</c>; the dispatcher places
/// the active server on the context at entry.
/// </para>
/// <para>
/// A protocol family's builder downcasts <paramref name="registration"/> to its
/// own richer registration shape when it needs family-specific fields beyond the
/// host-generic <see cref="IRegistrationRecord"/> projection.
/// </para>
/// </remarks>
/// <param name="registration">
/// The registration whose capabilities determine which endpoints to produce.
/// The capabilities the request is served under are the set the chain build
/// writes on <paramref name="context"/> before it calls any builder, read as
/// <c>ResolvedCapabilities</c> of <see cref="ExchangeContextServerExtensions"/>:
/// the library's immutable copy of the capability resolver's answer for this
/// registration, held to the bound when the dispatcher judges a materialized
/// registration. The chain's capability filter drops every candidate whose
/// <see cref="EndpointCandidate.Capability"/> is outside that set, so a gate
/// that admits a candidate on the capability the candidate carries may read
/// <see cref="IRegistrationRecord.AllowedCapabilities"/>, as the library's
/// single-capability gates do. A gate that reads a capability beside the one
/// its candidate carries, or that records what a capability admits for use
/// beyond its own candidate, reads the set on the context, so a capability the
/// resolver withholds or a materialized registration adds admits nothing; in
/// the library's builders such a read of the set on a context that carries
/// none, as for a call outside a chain build, allows no capability.
/// </param>
/// <param name="context">
/// The per-request context. Carries the typed <see cref="IncomingRequest"/>
/// envelope, the resolved registration, tenant identifier, the active dispatch
/// host via <c>context.RequestServer</c>, and any
/// application-supplied request-scoped state.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// Zero or more <see cref="EndpointCandidate"/> records. Return an empty list
/// when the registration does not support this flow or when per-request
/// signals indicate this builder's endpoints should not be active for this
/// request.
/// </returns>
public delegate ValueTask<IReadOnlyList<EndpointCandidate>> EndpointBuilderDelegate(
    IRegistrationRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);
