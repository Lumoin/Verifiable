namespace Verifiable.OAuth.Diagnostics;

/// <summary>
/// Metric instrument names for the OAuth authorization server.
/// </summary>
/// <remarks>
/// <para>
/// Names follow the OTel naming convention: <c>{domain}.{noun}.{unit}</c> where
/// applicable. Counter names end with the counted noun. Histogram names describe
/// the measured quantity. Gauge names describe the observed value.
/// </para>
/// </remarks>
public static class OAuthMetricNames
{
    //Request handling — counters and histograms.

    /// <summary>
    /// Total number of requests handled, tagged by flow kind and endpoint.
    /// Instrument: Counter.
    /// </summary>
    public static readonly string RequestCount = "oauth.server.requests";

    /// <summary>
    /// Request handling duration in milliseconds, tagged by flow kind and endpoint.
    /// Instrument: Histogram.
    /// </summary>
    public static readonly string RequestDuration = "oauth.server.request.duration";

    /// <summary>
    /// Number of responses by status code, tagged by flow kind.
    /// Instrument: Counter.
    /// </summary>
    public static readonly string ResponseCount = "oauth.server.responses";

    //Validation — counters.

    /// <summary>
    /// Total number of validation claim evaluations, tagged by claim code and outcome.
    /// Instrument: Counter.
    /// </summary>
    public static readonly string ValidationClaimCount = "oauth.server.validation.claims";

    /// <summary>
    /// Total number of failed validation claims, tagged by claim code.
    /// Instrument: Counter.
    /// </summary>
    public static readonly string ValidationFailureCount = "oauth.server.validation.failures";

    //Flow lifecycle — gauges and counters.

    /// <summary>
    /// Number of currently active flows (created but not yet completed or expired).
    /// Instrument: UpDownCounter.
    /// </summary>
    public static readonly string ActiveFlowCount = "oauth.server.flows.active";

    /// <summary>
    /// Total number of flows created, tagged by flow kind.
    /// Instrument: Counter.
    /// </summary>
    public static readonly string FlowCreatedCount = "oauth.server.flows.created";

    /// <summary>
    /// Total number of flows completed (reached terminal state), tagged by flow kind.
    /// Instrument: Counter.
    /// </summary>
    public static readonly string FlowCompletedCount = "oauth.server.flows.completed";

    //Correlation — counters.

    /// <summary>
    /// Total number of correlation key resolution attempts, tagged by outcome
    /// (<c>resolved</c> or <c>not_found</c>).
    /// Instrument: Counter.
    /// </summary>
    public static readonly string CorrelationResolutionCount = "oauth.server.correlation.resolutions";

    //Client lifecycle — gauges and counters.

    /// <summary>
    /// Number of currently registered clients.
    /// Instrument: UpDownCounter.
    /// </summary>
    public static readonly string ActiveClientCount = "oauth.server.clients.active";

    /// <summary>
    /// Total number of client lifecycle events, tagged by operation
    /// (<c>registered</c>, <c>updated</c>, <c>deregistered</c>).
    /// Instrument: Counter.
    /// </summary>
    public static readonly string ClientLifecycleCount = "oauth.server.clients.lifecycle";

    //Token operations — counters and histograms.

    /// <summary>
    /// Total number of tokens signed, tagged by algorithm.
    /// Instrument: Counter.
    /// </summary>
    public static readonly string TokenSignedCount = "oauth.server.tokens.signed";

    /// <summary>
    /// Token signing duration in milliseconds, tagged by algorithm.
    /// Instrument: Histogram.
    /// </summary>
    public static readonly string TokenSignDuration = "oauth.server.tokens.sign.duration";

    //JWKS — counters.

    /// <summary>
    /// Total number of JWKS document builds, tagged by segment.
    /// Instrument: Counter.
    /// </summary>
    public static readonly string JwksBuildCount = "oauth.server.jwks.builds";
}
