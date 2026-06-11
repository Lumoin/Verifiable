using Verifiable.OAuth.Server;

namespace Verifiable.Json;

/// <summary>
/// Wires the default <c>System.Text.Json</c> OID4VCI 1.0 §8.2 Credential Request parser
/// (<see cref="CredentialRequestJsonParsing"/>) onto an
/// <see cref="AuthorizationServerIntegration"/>. This is the JSON-side counterpart the
/// <c>Verifiable.OAuth</c> serialization firewall expects the application to supply; calling it
/// once is the conformant default.
/// </summary>
public static class CredentialRequestJsonExtensions
{
    /// <summary>
    /// Sets <see cref="AuthorizationServerIntegration.ParseCredentialRequestAsync"/> to the
    /// default STJ parser when it is not already set, so an application can override it before
    /// or after calling this. The issuance decision seam
    /// (<see cref="AuthorizationServerIntegration.IssueCredentialAsync"/>, which carries
    /// behavior, not wire) is NOT set here — the application always supplies that.
    /// </summary>
    /// <param name="integration">The integration to wire.</param>
    /// <returns>The same <paramref name="integration"/> for chaining.</returns>
    public static AuthorizationServerIntegration UseDefaultCredentialRequestJsonParsing(
        this AuthorizationServerIntegration integration)
    {
        ArgumentNullException.ThrowIfNull(integration);

        integration.ParseCredentialRequestAsync ??=
            CredentialRequestJsonParsing.ParseCredentialRequest;

        return integration;
    }
}
