namespace Verifiable.OAuth.Server;

/// <summary>
/// Assembles <see cref="ServerEndpoint"/> records for a <see cref="ClientRegistration"/>
/// by invoking all registered <see cref="EndpointBuilderDelegate"/> modules.
/// </summary>
/// <remarks>
/// <para>
/// There are no built-in flows. Every flow — Auth Code, OID4VP, JWKS, Discovery,
/// Federation, CIBA — is a module registered on
/// <see cref="AuthorizationServerOptions.EndpointBuilders"/>. The application
/// chooses which modules to include at startup:
/// </para>
/// <code>
/// options.EndpointBuilders =
/// [
///     AuthCodeEndpoints.Builder,
///     Oid4VpEndpoints.Builder,
///     MetadataEndpoints.Builder
/// ];
/// </code>
/// <para>
/// Each module checks the registration's capabilities and returns only the
/// endpoints the registration supports. A registration with only
/// <see cref="ServerCapabilityName.JwksEndpoint"/> gets only the JWKS endpoint.
/// A registration with Auth Code + VP + JWKS + Discovery gets all of them.
/// </para>
/// </remarks>
public static class AuthorizationServerEndpointRegistry
{
    /// <summary>
    /// Assembles all endpoints for a registration by invoking each registered
    /// <see cref="EndpointBuilderDelegate"/> in order.
    /// </summary>
    /// <param name="registration">
    /// The client registration whose capabilities determine which endpoints
    /// each module produces.
    /// </param>
    /// <param name="options">
    /// The server options carrying the <see cref="AuthorizationServerOptions.EndpointBuilders"/>
    /// and all I/O delegates.
    /// </param>
    /// <returns>
    /// The complete list of endpoints for this registration. May be empty if
    /// no modules produce endpoints for the registration's capabilities.
    /// </returns>
    public static IReadOnlyList<ServerEndpoint> BuildFor(
        ClientRegistration registration,
        AuthorizationServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(options);

        if(options.EndpointBuilders is not { Count: > 0 } builders)
        {
            return [];
        }

        List<ServerEndpoint> endpoints = [];

        foreach(EndpointBuilderDelegate builder in builders)
        {
            endpoints.AddRange(builder(registration, options));
        }

        return endpoints;
    }


    /// <summary>The global endpoints mapped once at startup.</summary>
    public static IReadOnlyList<ServerEndpoint> Global { get; } = [];
}
