using Verifiable.OAuth.Server;

namespace Verifiable.Json;

/// <summary>
/// Wires the default <c>System.Text.Json</c> RFC 9396 <c>authorization_details</c> parser
/// (<see cref="AuthorizationDetailsJsonParsing"/>) onto an
/// <see cref="AuthorizationServerIntegration"/>. This is the JSON-side counterpart the
/// <c>Verifiable.OAuth</c> serialization firewall expects the application to supply; calling it
/// once is the conformant default.
/// </summary>
public static class AuthorizationDetailsJsonExtensions
{
    /// <summary>
    /// Sets <see cref="AuthorizationServerIntegration.ParseAuthorizationDetailsAsync"/> to the
    /// default STJ parser when it is not already set, so an application can override it before
    /// or after calling this. The decision seam
    /// (<see cref="AuthorizationServerIntegration.ResolveCredentialAuthorizationAsync"/>, which
    /// carries behavior, not wire) is NOT set here — the application always supplies that.
    /// </summary>
    /// <param name="integration">The integration to wire.</param>
    /// <returns>The same <paramref name="integration"/> for chaining.</returns>
    public static AuthorizationServerIntegration UseDefaultAuthorizationDetailsJsonParsing(
        this AuthorizationServerIntegration integration)
    {
        ArgumentNullException.ThrowIfNull(integration);

        integration.ParseAuthorizationDetailsAsync ??=
            AuthorizationDetailsJsonParsing.ParseAuthorizationDetails;

        return integration;
    }
}
