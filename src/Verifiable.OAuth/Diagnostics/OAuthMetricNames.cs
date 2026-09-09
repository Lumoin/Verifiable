using Verifiable.Cryptography.Text;


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

    /// <summary>The UTF-8 source literal of <see cref="RequestCount"/>.</summary>
    public static ReadOnlySpan<byte> RequestCountUtf8 => "oauth.server.requests"u8;

    /// <summary>
    /// Total number of requests handled, tagged by flow kind and endpoint.
    /// Instrument: Counter.
    /// </summary>
    public static string RequestCount { get; } = Utf8Constants.ToInternedString(RequestCountUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RequestDuration"/>.</summary>
    public static ReadOnlySpan<byte> RequestDurationUtf8 => "oauth.server.request.duration"u8;

    /// <summary>
    /// Request handling duration in milliseconds, tagged by flow kind and endpoint.
    /// Instrument: Histogram.
    /// </summary>
    public static string RequestDuration { get; } = Utf8Constants.ToInternedString(RequestDurationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ResponseCount"/>.</summary>
    public static ReadOnlySpan<byte> ResponseCountUtf8 => "oauth.server.responses"u8;

    /// <summary>
    /// Number of responses by status code, tagged by flow kind.
    /// Instrument: Counter.
    /// </summary>
    public static string ResponseCount { get; } = Utf8Constants.ToInternedString(ResponseCountUtf8);

    //Validation — counters.

    /// <summary>The UTF-8 source literal of <see cref="ValidationClaimCount"/>.</summary>
    public static ReadOnlySpan<byte> ValidationClaimCountUtf8 => "oauth.server.validation.claims"u8;

    /// <summary>
    /// Total number of validation claim evaluations, tagged by claim code and outcome.
    /// Instrument: Counter.
    /// </summary>
    public static string ValidationClaimCount { get; } = Utf8Constants.ToInternedString(ValidationClaimCountUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ValidationFailureCount"/>.</summary>
    public static ReadOnlySpan<byte> ValidationFailureCountUtf8 => "oauth.server.validation.failures"u8;

    /// <summary>
    /// Total number of failed validation claims, tagged by claim code.
    /// Instrument: Counter.
    /// </summary>
    public static string ValidationFailureCount { get; } = Utf8Constants.ToInternedString(ValidationFailureCountUtf8);

    //Flow lifecycle — gauges and counters.

    /// <summary>The UTF-8 source literal of <see cref="ActiveFlowCount"/>.</summary>
    public static ReadOnlySpan<byte> ActiveFlowCountUtf8 => "oauth.server.flows.active"u8;

    /// <summary>
    /// Number of currently active flows (created but not yet completed or expired).
    /// Instrument: UpDownCounter.
    /// </summary>
    public static string ActiveFlowCount { get; } = Utf8Constants.ToInternedString(ActiveFlowCountUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FlowCreatedCount"/>.</summary>
    public static ReadOnlySpan<byte> FlowCreatedCountUtf8 => "oauth.server.flows.created"u8;

    /// <summary>
    /// Total number of flows created, tagged by flow kind.
    /// Instrument: Counter.
    /// </summary>
    public static string FlowCreatedCount { get; } = Utf8Constants.ToInternedString(FlowCreatedCountUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FlowCompletedCount"/>.</summary>
    public static ReadOnlySpan<byte> FlowCompletedCountUtf8 => "oauth.server.flows.completed"u8;

    /// <summary>
    /// Total number of flows completed (reached terminal state), tagged by flow kind.
    /// Instrument: Counter.
    /// </summary>
    public static string FlowCompletedCount { get; } = Utf8Constants.ToInternedString(FlowCompletedCountUtf8);

    //Correlation — counters.

    /// <summary>The UTF-8 source literal of <see cref="CorrelationResolutionCount"/>.</summary>
    public static ReadOnlySpan<byte> CorrelationResolutionCountUtf8 => "oauth.server.correlation.resolutions"u8;

    /// <summary>
    /// Total number of correlation key resolution attempts, tagged by outcome
    /// (<c>resolved</c> or <c>not_found</c>).
    /// Instrument: Counter.
    /// </summary>
    public static string CorrelationResolutionCount { get; } = Utf8Constants.ToInternedString(CorrelationResolutionCountUtf8);

    //Client lifecycle — gauges and counters.

    /// <summary>The UTF-8 source literal of <see cref="ActiveClientCount"/>.</summary>
    public static ReadOnlySpan<byte> ActiveClientCountUtf8 => "oauth.server.clients.active"u8;

    /// <summary>
    /// Number of currently registered clients.
    /// Instrument: UpDownCounter.
    /// </summary>
    public static string ActiveClientCount { get; } = Utf8Constants.ToInternedString(ActiveClientCountUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientLifecycleCount"/>.</summary>
    public static ReadOnlySpan<byte> ClientLifecycleCountUtf8 => "oauth.server.clients.lifecycle"u8;

    /// <summary>
    /// Total number of client lifecycle events, tagged by operation
    /// (<c>registered</c>, <c>updated</c>, <c>deregistered</c>).
    /// Instrument: Counter.
    /// </summary>
    public static string ClientLifecycleCount { get; } = Utf8Constants.ToInternedString(ClientLifecycleCountUtf8);

    //Token operations — counters and histograms.

    /// <summary>The UTF-8 source literal of <see cref="TokenSignedCount"/>.</summary>
    public static ReadOnlySpan<byte> TokenSignedCountUtf8 => "oauth.server.tokens.signed"u8;

    /// <summary>
    /// Total number of tokens signed, tagged by algorithm.
    /// Instrument: Counter.
    /// </summary>
    public static string TokenSignedCount { get; } = Utf8Constants.ToInternedString(TokenSignedCountUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TokenSignDuration"/>.</summary>
    public static ReadOnlySpan<byte> TokenSignDurationUtf8 => "oauth.server.tokens.sign.duration"u8;

    /// <summary>
    /// Token signing duration in milliseconds, tagged by algorithm.
    /// Instrument: Histogram.
    /// </summary>
    public static string TokenSignDuration { get; } = Utf8Constants.ToInternedString(TokenSignDurationUtf8);

    //JWKS — counters.

    /// <summary>The UTF-8 source literal of <see cref="JwksBuildCount"/>.</summary>
    public static ReadOnlySpan<byte> JwksBuildCountUtf8 => "oauth.server.jwks.builds"u8;

    /// <summary>
    /// Total number of JWKS document builds, tagged by segment.
    /// Instrument: Counter.
    /// </summary>
    public static string JwksBuildCount { get; } = Utf8Constants.ToInternedString(JwksBuildCountUtf8);
}
