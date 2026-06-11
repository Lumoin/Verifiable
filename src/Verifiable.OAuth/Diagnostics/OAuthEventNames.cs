using Verifiable.Cryptography.Text;


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
    /// <summary>The UTF-8 source literal of <see cref="ValidationClaim"/>.</summary>
    public static ReadOnlySpan<byte> ValidationClaimUtf8 => "oauth.validation.claim"u8;

    /// <summary>
    /// A single validation claim was evaluated. Tags carry the claim code,
    /// name, and outcome.
    /// </summary>
    public static readonly string ValidationClaim = Utf8Constants.ToInternedString(ValidationClaimUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ValidationPassed"/>.</summary>
    public static ReadOnlySpan<byte> ValidationPassedUtf8 => "oauth.validation.passed"u8;

    /// <summary>
    /// All validation claims passed — the request is accepted for processing.
    /// </summary>
    public static readonly string ValidationPassed = Utf8Constants.ToInternedString(ValidationPassedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ValidationFailed"/>.</summary>
    public static ReadOnlySpan<byte> ValidationFailedUtf8 => "oauth.validation.failed"u8;

    /// <summary>
    /// One or more validation claims failed — the request is rejected.
    /// </summary>
    public static readonly string ValidationFailed = Utf8Constants.ToInternedString(ValidationFailedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ExtraneousAuthorizeParameters"/>.</summary>
    public static ReadOnlySpan<byte> ExtraneousAuthorizeParametersUtf8 => "oauth.authorize.extraneous_parameters_ignored"u8;

    /// <summary>
    /// A <c>request_uri</c>-referenced authorization request (PAR per RFC 9126, or JAR by
    /// reference per RFC 9101) carried front-channel parameters beyond <c>request_uri</c> and
    /// <c>client_id</c>. Per RFC 9101 §6.3 the authorization server uses only the pushed
    /// parameters and ignores these extras; their presence may indicate a non-conformant client
    /// or a front-channel tampering attempt, so it is surfaced for deployments to alert on.
    /// </summary>
    public static readonly string ExtraneousAuthorizeParameters = Utf8Constants.ToInternedString(ExtraneousAuthorizeParametersUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DuplicateGrantedCredentialConfigurationCollapsed"/>.</summary>
    public static ReadOnlySpan<byte> DuplicateGrantedCredentialConfigurationCollapsedUtf8 =>
        "oauth.token.duplicate_credential_configuration_collapsed"u8;

    /// <summary>
    /// The token endpoint collapsed a second granted authorization for an already-granted
    /// <c>credential_configuration_id</c> into a single OID4VCI 1.0 §6.2 entry. This is the §5.1.2
    /// scope-vs-<c>authorization_details</c> collision: a <c>scope</c> value mapped to the same
    /// Credential type as an <c>openid_credential</c> authorization details object, and the
    /// authorization details object took precedence so the type is granted once. Observational; it
    /// does not change the single-grant outcome.
    /// </summary>
    public static readonly string DuplicateGrantedCredentialConfigurationCollapsed =
        Utf8Constants.ToInternedString(DuplicateGrantedCredentialConfigurationCollapsedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="LongLivedBearerCredentialTokenRefused"/>.</summary>
    public static ReadOnlySpan<byte> LongLivedBearerCredentialTokenRefusedUtf8 =>
        "oauth.token.long_lived_bearer_credential_token_refused"u8;

    /// <summary>
    /// The token endpoint refused to issue an Access Token giving access to Credentials because it
    /// would outlive the OID4VCI 1.0 §13.10 long-lived threshold
    /// (<see cref="Server.TimingPolicy.CredentialAccessTokenSenderConstraintThreshold"/>) without
    /// being sender-constrained. §13.10: "Long-lived Access Tokens giving access to Credentials
    /// MUST not be issued unless sender-constrained." The library fails the request closed rather
    /// than mint a long-lived bearer Credential token; the event surfaces the detection for
    /// deployments to alert on.
    /// </summary>
    public static readonly string LongLivedBearerCredentialTokenRefused =
        Utf8Constants.ToInternedString(LongLivedBearerCredentialTokenRefusedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="StateTransition"/>.</summary>
    public static ReadOnlySpan<byte> StateTransitionUtf8 => "oauth.flow.state_transition"u8;

    /// <summary>
    /// The PDA transitioned to a new state.
    /// </summary>
    public static readonly string StateTransition = Utf8Constants.ToInternedString(StateTransitionUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ActionExecuted"/>.</summary>
    public static ReadOnlySpan<byte> ActionExecutedUtf8 => "oauth.flow.action_executed"u8;

    /// <summary>
    /// An effectful action was executed by the PDA action loop.
    /// </summary>
    public static readonly string ActionExecuted = Utf8Constants.ToInternedString(ActionExecutedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CorrelationResolved"/>.</summary>
    public static ReadOnlySpan<byte> CorrelationResolvedUtf8 => "oauth.correlation.resolved"u8;

    /// <summary>
    /// The correlation key was resolved from an external handle to the
    /// internal flow identifier.
    /// </summary>
    public static readonly string CorrelationResolved = Utf8Constants.ToInternedString(CorrelationResolvedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CorrelationNotFound"/>.</summary>
    public static ReadOnlySpan<byte> CorrelationNotFoundUtf8 => "oauth.correlation.not_found"u8;

    /// <summary>
    /// The correlation key could not be resolved — flow not found.
    /// </summary>
    public static readonly string CorrelationNotFound = Utf8Constants.ToInternedString(CorrelationNotFoundUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FlowCreated"/>.</summary>
    public static ReadOnlySpan<byte> FlowCreatedUtf8 => "oauth.flow.created"u8;

    /// <summary>
    /// A new flow was created with a fresh internal flow identifier.
    /// </summary>
    public static readonly string FlowCreated = Utf8Constants.ToInternedString(FlowCreatedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientRegistered"/>.</summary>
    public static ReadOnlySpan<byte> ClientRegisteredUtf8 => "oauth.client.registered"u8;

    /// <summary>
    /// A client was registered.
    /// </summary>
    public static readonly string ClientRegistered = Utf8Constants.ToInternedString(ClientRegisteredUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientUpdated"/>.</summary>
    public static ReadOnlySpan<byte> ClientUpdatedUtf8 => "oauth.client.updated"u8;

    /// <summary>
    /// A client registration was updated (e.g., key rotation).
    /// </summary>
    public static readonly string ClientUpdated = Utf8Constants.ToInternedString(ClientUpdatedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientDeregistered"/>.</summary>
    public static ReadOnlySpan<byte> ClientDeregisteredUtf8 => "oauth.client.deregistered"u8;

    /// <summary>
    /// A client was deregistered.
    /// </summary>
    public static readonly string ClientDeregistered = Utf8Constants.ToInternedString(ClientDeregisteredUtf8);
}
