using Verifiable.OAuth.Server;

namespace Verifiable.Json;

/// <summary>
/// Wires the default <c>System.Text.Json</c> AuthZEN request parsers
/// (<see cref="AuthZenJsonParsing"/>) onto an
/// <see cref="AuthorizationServerIntegration"/>. This is the JSON-side
/// counterpart the <c>Verifiable.OAuth</c> serialization firewall expects the
/// application to supply; calling it once is the conformant default.
/// </summary>
public static class AuthZenJsonExtensions
{
    /// <summary>
    /// Sets <see cref="AuthorizationServerIntegration.ParseAccessEvaluationRequestAsync"/>,
    /// <see cref="AuthorizationServerIntegration.ParseAccessEvaluationsRequestAsync"/>, and
    /// <see cref="AuthorizationServerIntegration.ParseAccessSearchRequestAsync"/> to the
    /// default STJ parsers. Existing non-null delegates are left untouched, so
    /// an application can override any single parser before or after calling
    /// this. The PDP and search seams (which carry policy, not wire) are NOT
    /// set here — the application always supplies those.
    /// </summary>
    /// <param name="integration">The integration to wire.</param>
    /// <returns>The same <paramref name="integration"/> for chaining.</returns>
    public static AuthorizationServerIntegration UseDefaultAuthZenJsonParsing(
        this AuthorizationServerIntegration integration)
    {
        ArgumentNullException.ThrowIfNull(integration);

        integration.ParseAccessEvaluationRequestAsync ??= AuthZenJsonParsing.ParseAccessEvaluationRequest;
        integration.ParseAccessEvaluationsRequestAsync ??= AuthZenJsonParsing.ParseAccessEvaluationsRequest;
        integration.ParseAccessSearchRequestAsync ??= AuthZenJsonParsing.ParseAccessSearchRequest;

        return integration;
    }
}
