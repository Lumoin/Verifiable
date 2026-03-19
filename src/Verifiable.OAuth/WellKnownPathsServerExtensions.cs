using System.Diagnostics;

namespace Verifiable.OAuth;

/// <summary>
/// Extends <see cref="WellKnownPaths"/> with URI computation for per-registration
/// Authorization Server endpoints.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="WellKnownPaths"/> computes well-known URIs for discovery — what a
/// client fetches to find an authorization server. This class computes the URIs
/// that appear <em>inside</em> the discovery document — what the server advertises
/// to clients as its endpoint locations.
/// </para>
/// <para>
/// Both sides use the same base URI and segment so the advertised URIs always match
/// the paths the server actually serves:
/// </para>
/// <code>
/// //Server side — compute discovery document endpoint URIs:
/// Uri parEndpoint = WellKnownPathsServer.ComputeEndpointUri(
///     issuer, registration.EndpointSegment, ServerEndpointPaths.Par);
///
/// //Client side — compute the discovery document location:
/// Uri discoveryUri = WellKnownPaths.OpenIdConfiguration.ComputeUri(issuer);
/// </code>
/// </remarks>
[DebuggerDisplay("WellKnownPathsServer")]
public static class WellKnownPathsServer
{
    /// <summary>
    /// Computes the absolute URI for a per-registration endpoint by substituting
    /// the <paramref name="endpointSegment"/> into <paramref name="pathTemplate"/>
    /// and prepending the <paramref name="issuer"/> base URI.
    /// </summary>
    /// <remarks>
    /// Use this when building the discovery document so that the endpoint URIs
    /// the server advertises exactly match the paths it serves.
    /// The <paramref name="pathTemplate"/> should be one of the constants from
    /// <see cref="Verifiable.OAuth.Server.ServerEndpointPaths"/>.
    /// </remarks>
    /// <param name="issuer">
    /// The base URI of the authorization server, e.g. <c>https://verifable.app</c>.
    /// </param>
    /// <param name="endpointSegment">
    /// The unguessable segment from <see cref="Verifiable.OAuth.Server.ClientRegistration.EndpointSegment"/>.
    /// </param>
    /// <param name="pathTemplate">
    /// A path template containing <c>{segment}</c> as the placeholder, e.g.
    /// <c>/connect/{segment}/par</c>.
    /// </param>
    /// <returns>
    /// The absolute endpoint URI, e.g.
    /// <c>https://verifable.app/connect/a3f9b2c1/par</c>.
    /// </returns>
    public static Uri ComputeEndpointUri(
        Uri issuer,
        string endpointSegment,
        string pathTemplate)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(endpointSegment);
        ArgumentException.ThrowIfNullOrWhiteSpace(pathTemplate);

        return Verifiable.OAuth.Server.ServerEndpointPaths.ComputeUri(
            issuer, endpointSegment, pathTemplate);
    }


    /// <summary>
    /// Computes the OIDC discovery document URI for a specific client registration.
    /// </summary>
    /// <remarks>
    /// This is the URI a client would fetch to discover the endpoints for a particular
    /// registered client — distinct from the global
    /// <see cref="WellKnownPaths.OpenIdConfiguration"/> which applies to the server as
    /// a whole. For per-registration discovery, share this URI with the client at
    /// onboarding time alongside its endpoint segment.
    /// </remarks>
    /// <param name="issuer">The base URI of the authorization server.</param>
    /// <param name="endpointSegment">The registration's endpoint segment.</param>
    /// <returns>
    /// The per-registration discovery URI, e.g.
    /// <c>https://verifable.app/connect/a3f9b2c1/.well-known/openid-configuration</c>.
    /// </returns>
    public static Uri ComputeDiscoveryUri(Uri issuer, string endpointSegment) =>
        ComputeEndpointUri(
            issuer,
            endpointSegment,
            Verifiable.OAuth.Server.ServerEndpointPaths.Discovery);
}
