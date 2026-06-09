namespace Verifiable.OAuth.Diagnostics;

/// <summary>
/// Span event names emitted during OAuth authorization server operations.
/// </summary>
/// <remarks>
/// <para>
/// Events are points in time within a span. Validation claim results are
/// emitted as individual events so each check is visible in the trace
/// without requiring a child span.
/// </para>
/// </remarks>
public static class OAuthEventNames
{
    /// <summary>
    /// A single validation claim was evaluated. Tags carry the claim code,
    /// name, and outcome.
    /// </summary>
    public static readonly string ValidationClaim = "oauth.validation.claim";

    /// <summary>
    /// All validation claims passed — the request is accepted for processing.
    /// </summary>
    public static readonly string ValidationPassed = "oauth.validation.passed";

    /// <summary>
    /// One or more validation claims failed — the request is rejected.
    /// </summary>
    public static readonly string ValidationFailed = "oauth.validation.failed";

    /// <summary>
    /// A <c>request_uri</c>-referenced authorization request (PAR per RFC 9126, or JAR by
    /// reference per RFC 9101) carried front-channel parameters beyond <c>request_uri</c> and
    /// <c>client_id</c>. Per RFC 9101 §6.3 the authorization server uses only the pushed
    /// parameters and ignores these extras; their presence may indicate a non-conformant client
    /// or a front-channel tampering attempt, so it is surfaced for deployments to alert on.
    /// </summary>
    public static readonly string ExtraneousAuthorizeParameters = "oauth.authorize.extraneous_parameters_ignored";

    /// <summary>
    /// The PDA transitioned to a new state.
    /// </summary>
    public static readonly string StateTransition = "oauth.flow.state_transition";

    /// <summary>
    /// An effectful action was executed by the PDA action loop.
    /// </summary>
    public static readonly string ActionExecuted = "oauth.flow.action_executed";

    /// <summary>
    /// The correlation key was resolved from an external handle to the
    /// internal flow identifier.
    /// </summary>
    public static readonly string CorrelationResolved = "oauth.correlation.resolved";

    /// <summary>
    /// The correlation key could not be resolved — flow not found.
    /// </summary>
    public static readonly string CorrelationNotFound = "oauth.correlation.not_found";

    /// <summary>
    /// A new flow was created with a fresh internal flow identifier.
    /// </summary>
    public static readonly string FlowCreated = "oauth.flow.created";

    /// <summary>
    /// A client was registered.
    /// </summary>
    public static readonly string ClientRegistered = "oauth.client.registered";

    /// <summary>
    /// A client registration was updated (e.g., key rotation).
    /// </summary>
    public static readonly string ClientUpdated = "oauth.client.updated";

    /// <summary>
    /// A client was deregistered.
    /// </summary>
    public static readonly string ClientDeregistered = "oauth.client.deregistered";
}
