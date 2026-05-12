namespace Verifiable.OAuth.Server;

/// <summary>
/// Builds <see cref="ServerEndpoint"/> records for a given
/// <see cref="ClientRecord"/> and inbound request, providing the flow
/// factory, input builder, and response builder delegates for each endpoint.
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
/// <see cref="EndpointChain.BuildForRequest"/>. Return an empty sequence when
/// the registration does not have the capabilities your flow requires, or when
/// per-request signals on <paramref name="context"/> indicate this flow's
/// endpoints should not be active for this request.
/// </para>
/// <para>
/// <strong>Per-request gating.</strong>
/// The <paramref name="context"/> parameter lets the builder read tenant
/// configuration, feature flags, request-time signals (the typed
/// <see cref="IncomingRequest"/> envelope, headers, fields, route values), or
/// per-client policy that determines whether this builder's endpoints belong
/// in the chain for this request. Today's library-provided builders gate only
/// on <paramref name="registration"/> capabilities and do not read
/// <paramref name="context"/>; the parameter is provided so future endpoint
/// modules — feature-flagged matchers, tenant-scoped flow variants, policy-
/// driven endpoint exposure — can compose without changing this signature.
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
/// <see cref="ClientRecord.IsCapabilityAllowed"/> before emitting endpoints.
/// </param>
/// <param name="context">
/// The per-request context. Carries the typed
/// <see cref="IncomingRequest"/> envelope, the resolved
/// <see cref="ClientRecord"/>, tenant identifier, and any
/// application-supplied request-scoped state. Builders that gate on
/// per-request signals read them through this context's typed accessor surface.
/// </param>
/// <param name="server">
/// The <see cref="AuthorizationServer"/> instance carrying the integration,
/// cryptography, and codec delegate groups. Endpoint builders may read delegates
/// from the appropriate group — for example
/// <c>server.Cryptography.SigningKeyResolver</c> for a custom token endpoint.
/// </param>
/// <returns>
/// Zero or more <see cref="ServerEndpoint"/> records. Return an empty sequence
/// when the registration does not support this flow or when per-request signals
/// indicate this builder's endpoints should not be active for this request.
/// </returns>
public delegate IEnumerable<ServerEndpoint> EndpointBuilderDelegate(ClientRecord registration, RequestContext context, AuthorizationServer server);
