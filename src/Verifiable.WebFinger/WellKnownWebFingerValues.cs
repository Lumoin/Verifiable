namespace Verifiable.WebFinger;

/// <summary>
/// Well-known WebFinger string values fixed by the
/// <see href="https://www.rfc-editor.org/rfc/rfc7033">WebFinger specification (RFC 7033)</see>:
/// the well-known path a query is issued to, the JRD media type, the query parameter names, and
/// the CORS header the endpoint MUST emit. Centralizing them keeps the client query construction,
/// the endpoint, and the tests reading the same wire constants.
/// </summary>
public static class WellKnownWebFingerValues
{
    /// <summary>
    /// The well-known URI suffix registered for WebFinger, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-10.1">RFC 7033 §10.1</see>
    /// in the "Well-Known URIs" registry of
    /// <see href="https://www.rfc-editor.org/rfc/rfc5785#section-3">RFC 5785 §3</see>: <c>webfinger</c>.
    /// </summary>
    public static string WellKnownSuffix { get; } = "webfinger";

    /// <summary>
    /// The fixed path component of a WebFinger URI, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4">RFC 7033 §4</see>:
    /// <c>/.well-known/webfinger</c>. A WebFinger URI MUST use this path.
    /// </summary>
    public static string WellKnownPath { get; } = "/.well-known/webfinger";

    /// <summary>
    /// The media type a WebFinger resource returns the JSON Resource Descriptor under, registered by
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-10.2">RFC 7033 §10.2</see>:
    /// <c>application/jrd+json</c>.
    /// </summary>
    public static string JrdMediaType { get; } = "application/jrd+json";

    /// <summary>
    /// The query parameter carrying the query target (a URI), per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.1">RFC 7033 §4.1</see>:
    /// <c>resource</c>. It MUST appear exactly once (§4.2).
    /// </summary>
    public static string ResourceParameterName { get; } = "resource";

    /// <summary>
    /// The query parameter carrying an encoded link relation type, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.1">RFC 7033 §4.1</see>:
    /// <c>rel</c>. It MAY appear more than once (§4.3).
    /// </summary>
    public static string RelParameterName { get; } = "rel";

    /// <summary>
    /// The response header a WebFinger resource MUST include so browsers may read the JRD across
    /// origins, per <see href="https://www.rfc-editor.org/rfc/rfc7033#section-5">RFC 7033 §5</see>:
    /// <c>Access-Control-Allow-Origin</c>.
    /// </summary>
    public static string AccessControlAllowOriginHeaderName { get; } = "Access-Control-Allow-Origin";

    /// <summary>
    /// The least restrictive <c>Access-Control-Allow-Origin</c> value, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-5">RFC 7033 §5</see> says servers
    /// SHOULD support unless access is deliberately restricted: <c>*</c>.
    /// </summary>
    public static string AccessControlAllowOriginWildcard { get; } = "*";
}
