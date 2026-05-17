namespace Verifiable.OAuth.Server;

/// <summary>
/// Builds <see cref="EndpointCandidate"/> records for a given
/// <see cref="ClientRecord"/>, leaving URI resolution to
/// <see cref="Pipeline.EndpointChain.BuildForRequestAsync"/> which projects
/// each candidate to a complete <see cref="ServerEndpoint"/> after calling
/// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// Every protocol flow is a module registered on
/// <see cref="ServerConfiguration.EndpointBuilders"/>. Library-provided modules
/// (<see cref="AuthCodeEndpoints"/>, <see cref="Oid4VpEndpoints"/>,
/// <see cref="MetadataEndpoints"/>) and application-provided modules use the
/// same delegate shape and are treated identically.
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
/// from <see cref="RequestContextExtensions.Server"/>; the dispatcher places
/// the active server on the context at entry.
/// </para>
/// <para>
/// Example: registering flow modules at startup.
/// </para>
/// <code>
/// EndpointBuilders =
/// [
///     AuthCodeEndpoints.Builder,
///     Oid4VpEndpoints.Builder,
///     MetadataEndpoints.Builder,
///     CibaEndpoints.Builder   //Application-provided.
/// ];
/// </code>
/// </remarks>
/// <param name="registration">
/// The <see cref="ClientRecord"/> whose capabilities determine which
/// endpoints to produce. Check
/// <see cref="ClientRecord.IsCapabilityAllowed"/> before emitting candidates.
/// </param>
/// <param name="context">
/// The per-request context. Carries the typed
/// <see cref="IncomingRequest"/> envelope, the resolved
/// <see cref="ClientRecord"/>, tenant identifier, the active
/// <see cref="AuthorizationServer"/> via
/// <see cref="RequestContextExtensions.Server"/>, and any
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
    ClientRecord registration,
    RequestContext context,
    CancellationToken cancellationToken);
