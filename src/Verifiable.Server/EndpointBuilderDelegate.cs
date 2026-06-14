using Verifiable.Core;

namespace Verifiable.Server;

/// <summary>
/// Builds <see cref="EndpointCandidate"/> records for a given registration,
/// leaving URI resolution to
/// <see cref="Pipeline.EndpointChain.BuildForRequestAsync"/> which projects
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
/// The delegate is called once per request by
/// <see cref="Pipeline.EndpointChain.BuildForRequestAsync"/>. Return an empty
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
/// from <see cref="ExchangeContextServerExtensions.Server"/>; the dispatcher places
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
/// Check <see cref="IRegistrationRecord.AllowedCapabilities"/> before emitting
/// candidates.
/// </param>
/// <param name="context">
/// The per-request context. Carries the typed <see cref="IncomingRequest"/>
/// envelope, the resolved registration, tenant identifier, the active dispatch
/// host via <see cref="ExchangeContextServerExtensions.Server"/>, and any
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
