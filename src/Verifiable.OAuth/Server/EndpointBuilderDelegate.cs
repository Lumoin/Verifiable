namespace Verifiable.OAuth.Server;

/// <summary>
/// Builds <see cref="ServerEndpoint"/> records for a given
/// <see cref="ClientRegistration"/>, providing the flow factory, input builder,
/// and response builder delegates for each endpoint.
/// </summary>
/// <remarks>
/// <para>
/// Every protocol flow is a module registered on
/// <see cref="AuthorizationServerOptions.EndpointBuilders"/>. Library-provided
/// modules (<see cref="AuthCodeEndpoints"/>, <see cref="Oid4VpEndpoints"/>,
/// <see cref="MetadataEndpoints"/>) and application-provided modules use the
/// same delegate shape and are treated identically.
/// </para>
/// <para>
/// The delegate is called once per request by
/// <see cref="AuthorizationServerEndpointRegistry.BuildFor"/>. Return an empty
/// sequence when the registration does not have the capabilities your flow
/// requires.
/// </para>
/// <para>
/// Example: registering flow modules at startup.
/// </para>
/// <code>
/// options.EndpointBuilders =
/// [
///     AuthCodeEndpoints.Builder,
///     Oid4VpEndpoints.Builder,
///     MetadataEndpoints.Builder,
///     CibaEndpoints.Builder   // Application-provided.
/// ];
/// </code>
/// </remarks>
/// <param name="registration">
/// The <see cref="ClientRegistration"/> whose capabilities determine which
/// endpoints to produce. Check
/// <see cref="ClientRegistration.IsCapabilityAllowed"/> before emitting endpoints.
/// </param>
/// <param name="options">
/// The server options carrying all I/O delegates. Endpoint builders may read
/// delegates from here — for example the signing key resolver for a custom
/// token endpoint.
/// </param>
/// <returns>
/// Zero or more <see cref="ServerEndpoint"/> records. Return an empty sequence
/// when the registration does not support this flow.
/// </returns>
public delegate IEnumerable<ServerEndpoint> EndpointBuilderDelegate(
    ClientRegistration registration,
    AuthorizationServerOptions options);
