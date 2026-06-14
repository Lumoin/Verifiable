namespace Verifiable.Server;

/// <summary>
/// The host-level error codes the dispatch loop emits for transport-level failures that
/// occur before any protocol-family handler runs — an unresolved tenant, a malformed
/// correlation handle, an expired flow, an internal fault.
/// </summary>
/// <remarks>
/// These are the OAuth 2.0 error-code strings (<c>invalid_request</c>, <c>server_error</c>),
/// used here as the neutral vocabulary for the host's own pre-handler failures. A protocol
/// family produces its own protocol-shaped error bodies inside its endpoint handlers and
/// returns them as the handler's early-exit response; those never reach this host-level
/// vocabulary. A family that wants different host-failure bodies resolves tenant and
/// registration itself and short-circuits through the stateless path.
/// </remarks>
public static class ServerErrors
{
    /// <summary>The request was malformed or carried no identifiable tenant.</summary>
    public const string InvalidRequest = "invalid_request";

    /// <summary>An internal fault prevented the host from producing a response.</summary>
    public const string ServerError = "server_error";
}
