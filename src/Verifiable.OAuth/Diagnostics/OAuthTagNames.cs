using Verifiable.Cryptography.Text;


namespace Verifiable.OAuth.Diagnostics;

/// <summary>
/// Tag (attribute) names for OAuth authorization server spans and events.
/// </summary>
/// <remarks>
/// <para>
/// Names follow OTel semantic conventions where applicable. Domain-specific
/// tags use the <c>oauth.</c> prefix. HTTP-level tags use the standard
/// <c>http.</c> prefix per the OTel HTTP semantic conventions.
/// </para>
/// </remarks>
public static class OAuthTagNames
{
    //Flow identification.

    /// <summary>The UTF-8 source literal of <see cref="FlowKind"/>.</summary>
    public static ReadOnlySpan<byte> FlowKindUtf8 => "oauth.flow.kind"u8;

    /// <summary>The flow kind name (e.g., <c>AuthorizationCode</c>, <c>VerifiablePresentation</c>).</summary>
    public static readonly string FlowKind = Utf8Constants.ToInternedString(FlowKindUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EndpointPath"/>.</summary>
    public static ReadOnlySpan<byte> EndpointPathUtf8 => "oauth.endpoint.path"u8;

    /// <summary>The endpoint path template (e.g., <c>par</c>, <c>authorize</c>, <c>token</c>).</summary>
    public static readonly string EndpointPath = Utf8Constants.ToInternedString(EndpointPathUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TenantId"/>.</summary>
    public static ReadOnlySpan<byte> TenantIdUtf8 => "oauth.tenant.id"u8;

    /// <summary>
    /// The tenant identifier the request was resolved against. Opaque from the
    /// library's perspective; meaningful to the application's tenant resolver
    /// and registration store.
    /// </summary>
    public static readonly string TenantId = Utf8Constants.ToInternedString(TenantIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientId"/>.</summary>
    public static ReadOnlySpan<byte> ClientIdUtf8 => "oauth.client.id"u8;

    /// <summary>The registered client identifier.</summary>
    public static readonly string ClientId = Utf8Constants.ToInternedString(ClientIdUtf8);

    //HTTP request/response.

    /// <summary>The UTF-8 source literal of <see cref="HttpMethod"/>.</summary>
    public static ReadOnlySpan<byte> HttpMethodUtf8 => "http.request.method"u8;

    /// <summary>The HTTP method per OTel HTTP semantic conventions.</summary>
    public static readonly string HttpMethod = Utf8Constants.ToInternedString(HttpMethodUtf8);

    /// <summary>The UTF-8 source literal of <see cref="StatusCode"/>.</summary>
    public static ReadOnlySpan<byte> StatusCodeUtf8 => "oauth.response.status_code"u8;

    /// <summary>The HTTP response status code.</summary>
    public static readonly string StatusCode = Utf8Constants.ToInternedString(StatusCodeUtf8);

    //Flow state.

    /// <summary>The UTF-8 source literal of <see cref="FlowState"/>.</summary>
    public static ReadOnlySpan<byte> FlowStateUtf8 => "oauth.flow.state"u8;

    /// <summary>The PDA state type name after the transition.</summary>
    public static readonly string FlowState = Utf8Constants.ToInternedString(FlowStateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FlowStepCount"/>.</summary>
    public static ReadOnlySpan<byte> FlowStepCountUtf8 => "oauth.flow.step_count"u8;

    /// <summary>The PDA step count after the transition.</summary>
    public static readonly string FlowStepCount = Utf8Constants.ToInternedString(FlowStepCountUtf8);

    /// <summary>The UTF-8 source literal of <see cref="StartsNewFlow"/>.</summary>
    public static ReadOnlySpan<byte> StartsNewFlowUtf8 => "oauth.flow.starts_new"u8;

    /// <summary>Whether this endpoint starts a new flow or continues an existing one.</summary>
    public static readonly string StartsNewFlow = Utf8Constants.ToInternedString(StartsNewFlowUtf8);

    //Validation.

    /// <summary>The UTF-8 source literal of <see cref="ClaimCode"/>.</summary>
    public static ReadOnlySpan<byte> ClaimCodeUtf8 => "oauth.validation.claim.code"u8;

    /// <summary>The numeric code of a validation claim.</summary>
    public static readonly string ClaimCode = Utf8Constants.ToInternedString(ClaimCodeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClaimName"/>.</summary>
    public static ReadOnlySpan<byte> ClaimNameUtf8 => "oauth.validation.claim.name"u8;

    /// <summary>The name of a validation claim.</summary>
    public static readonly string ClaimName = Utf8Constants.ToInternedString(ClaimNameUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClaimOutcome"/>.</summary>
    public static ReadOnlySpan<byte> ClaimOutcomeUtf8 => "oauth.validation.claim.outcome"u8;

    /// <summary>The outcome of a validation claim (<c>Success</c> or <c>Failure</c>).</summary>
    public static readonly string ClaimOutcome = Utf8Constants.ToInternedString(ClaimOutcomeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ValidationClaimCount"/>.</summary>
    public static ReadOnlySpan<byte> ValidationClaimCountUtf8 => "oauth.validation.claim_count"u8;

    /// <summary>The total number of validation claims evaluated.</summary>
    public static readonly string ValidationClaimCount = Utf8Constants.ToInternedString(ValidationClaimCountUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ValidationFailureCount"/>.</summary>
    public static ReadOnlySpan<byte> ValidationFailureCountUtf8 => "oauth.validation.failure_count"u8;

    /// <summary>The number of failed validation claims.</summary>
    public static readonly string ValidationFailureCount = Utf8Constants.ToInternedString(ValidationFailureCountUtf8);

    //Client lifecycle.

    /// <summary>The UTF-8 source literal of <see cref="LifecycleOperation"/>.</summary>
    public static ReadOnlySpan<byte> LifecycleOperationUtf8 => "oauth.client.lifecycle.operation"u8;

    /// <summary>The lifecycle operation (<c>registered</c>, <c>updated</c>, <c>deregistered</c>).</summary>
    public static readonly string LifecycleOperation = Utf8Constants.ToInternedString(LifecycleOperationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DeregistrationReason"/>.</summary>
    public static ReadOnlySpan<byte> DeregistrationReasonUtf8 => "oauth.client.lifecycle.reason"u8;

    /// <summary>The reason for deregistration.</summary>
    public static readonly string DeregistrationReason = Utf8Constants.ToInternedString(DeregistrationReasonUtf8);

    //Correlation.

    /// <summary>The UTF-8 source literal of <see cref="CorrelationResolved"/>.</summary>
    public static ReadOnlySpan<byte> CorrelationResolvedUtf8 => "oauth.correlation.resolved"u8;

    /// <summary>Whether the correlation key resolution succeeded.</summary>
    public static readonly string CorrelationResolved = Utf8Constants.ToInternedString(CorrelationResolvedUtf8);
}
