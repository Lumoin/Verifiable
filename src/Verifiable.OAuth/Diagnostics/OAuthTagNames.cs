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

    /// <summary>The flow kind name (e.g., <c>AuthorizationCode</c>, <c>VerifiablePresentation</c>).</summary>
    public static readonly string FlowKind = "oauth.flow.kind";

    /// <summary>The endpoint path template (e.g., <c>par</c>, <c>authorize</c>, <c>token</c>).</summary>
    public static readonly string EndpointPath = "oauth.endpoint.path";

    /// <summary>
    /// The tenant identifier the request was resolved against. Opaque from the
    /// library's perspective; meaningful to the application's tenant resolver
    /// and registration store.
    /// </summary>
    public static readonly string TenantId = "oauth.tenant.id";

    /// <summary>The registered client identifier.</summary>
    public static readonly string ClientId = "oauth.client.id";

    //HTTP request/response.

    /// <summary>The HTTP method per OTel HTTP semantic conventions.</summary>
    public static readonly string HttpMethod = "http.request.method";

    /// <summary>The HTTP response status code.</summary>
    public static readonly string StatusCode = "oauth.response.status_code";

    //Flow state.

    /// <summary>The PDA state type name after the transition.</summary>
    public static readonly string FlowState = "oauth.flow.state";

    /// <summary>The PDA step count after the transition.</summary>
    public static readonly string FlowStepCount = "oauth.flow.step_count";

    /// <summary>Whether this endpoint starts a new flow or continues an existing one.</summary>
    public static readonly string StartsNewFlow = "oauth.flow.starts_new";

    //Validation.

    /// <summary>The numeric code of a validation claim.</summary>
    public static readonly string ClaimCode = "oauth.validation.claim.code";

    /// <summary>The name of a validation claim.</summary>
    public static readonly string ClaimName = "oauth.validation.claim.name";

    /// <summary>The outcome of a validation claim (<c>Success</c> or <c>Failure</c>).</summary>
    public static readonly string ClaimOutcome = "oauth.validation.claim.outcome";

    /// <summary>The total number of validation claims evaluated.</summary>
    public static readonly string ValidationClaimCount = "oauth.validation.claim_count";

    /// <summary>The number of failed validation claims.</summary>
    public static readonly string ValidationFailureCount = "oauth.validation.failure_count";

    //Client lifecycle.

    /// <summary>The lifecycle operation (<c>registered</c>, <c>updated</c>, <c>deregistered</c>).</summary>
    public static readonly string LifecycleOperation = "oauth.client.lifecycle.operation";

    /// <summary>The reason for deregistration.</summary>
    public static readonly string DeregistrationReason = "oauth.client.lifecycle.reason";

    //Correlation.

    /// <summary>Whether the correlation key resolution succeeded.</summary>
    public static readonly string CorrelationResolved = "oauth.correlation.resolved";
}
