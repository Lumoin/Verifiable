namespace Verifiable.Server;

/// <summary>
/// The host-level error codes the dispatch loop emits for transport-level failures that
/// occur before any protocol-family handler runs — an unresolved tenant, a malformed
/// correlation handle, an expired flow, an internal fault.
/// </summary>
/// <remarks>
/// These are the OAuth 2.0 error-code strings (<c>invalid_request</c>, <c>server_error</c>,
/// <c>temporarily_unavailable</c>), used here as the neutral vocabulary for the host's own
/// pre-handler failures — <see cref="TemporarilyUnavailable"/> specifically backs
/// <see cref="EndpointServer.AdmissionRefusal"/>, emitted before any handler runs. A protocol
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


    /// <summary>
    /// Admission is temporarily closed while a requested alteration drains and publishes.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>
    /// defines this code for an authorization-endpoint redirect response; <see cref="EndpointServer.AdmissionRefusal"/>
    /// reuses it as the host's transport-level refusal across every capability, including endpoints
    /// (the token endpoint, metadata and JWKS retrieval) for which it is not itself a defined error
    /// response — the refusal is carried entirely by the HTTP 503 status and Retry-After header.
    /// </remarks>
    public static string TemporarilyUnavailable { get; } = "temporarily_unavailable";
}
