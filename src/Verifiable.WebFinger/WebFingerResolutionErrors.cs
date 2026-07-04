namespace Verifiable.WebFinger;

/// <summary>
/// The standard <see cref="WebFingerResolutionError"/> conditions a WebFinger client resolution can end in,
/// each exposed as a shared instance. Getters (not <c>static readonly</c> fields) per the codebase convention
/// for shared well-known values.
/// </summary>
public static class WebFingerResolutionErrors
{
    /// <summary>
    /// The query target could not be turned into a valid HTTPS WebFinger URI (for example an empty
    /// <c>resource</c> or a host that does not form an absolute <c>https</c> URL), per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.1">RFC 7033 §4.1</see>.
    /// </summary>
    public static WebFingerResolutionError InvalidResource { get; } = new()
    {
        Code = "invalid_resource",
        Description = "The WebFinger query target could not be encoded into a valid HTTPS query URI."
    };

    /// <summary>
    /// The HTTPS connection to the WebFinger resource could not be established or the transport failed. Per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.2">RFC 7033 §4.2</see> the client accepts
    /// that the query failed and MUST NOT retry over a non-secure connection.
    /// </summary>
    public static WebFingerResolutionError TransportFailure { get; } = new()
    {
        Code = "transport_failure",
        Description = "The HTTPS WebFinger request failed and was not retried over a non-secure connection."
    };

    /// <summary>
    /// The guarded outbound fetch refused the query URI — the SSRF/trust-anchor policy denied it, or a redirect
    /// was not followed — before any resource could answer. Distinct from <see cref="NotFound"/> so a security
    /// denial is not mistaken for an absent resource.
    /// </summary>
    public static WebFingerResolutionError PolicyDenied { get; } = new()
    {
        Code = "policy_denied",
        Description = "The WebFinger query URI was denied by the outbound-fetch policy before any request was answered."
    };

    /// <summary>
    /// The resource returned no successful JRD for the query target — an absent match or a non-200 response,
    /// per <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.2">RFC 7033 §4.2</see>.
    /// </summary>
    public static WebFingerResolutionError NotFound { get; } = new()
    {
        Code = "not_found",
        Description = "The WebFinger resource returned no descriptor for the query target."
    };

    /// <summary>
    /// The response body was not a well-formed JSON Resource Descriptor, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4">RFC 7033 §4.4</see>.
    /// </summary>
    public static WebFingerResolutionError InvalidJrd { get; } = new()
    {
        Code = "invalid_jrd",
        Description = "The WebFinger response body was not a valid JSON Resource Descriptor."
    };
}
