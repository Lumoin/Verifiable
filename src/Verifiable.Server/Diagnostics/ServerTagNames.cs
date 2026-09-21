using Verifiable.Cryptography.Text;


namespace Verifiable.Server.Diagnostics;

/// <summary>
/// Tag (attribute) names for protocol-neutral endpoint host spans and events.
/// </summary>
/// <remarks>
/// <para>
/// Names follow OTel semantic conventions where applicable. Host-domain tags use
/// the <c>server.</c> prefix. HTTP-level tags use the standard <c>http.</c> prefix
/// per the OTel HTTP semantic conventions.
/// </para>
/// </remarks>
public static class ServerTagNames
{
    //Flow identification.

    /// <summary>The UTF-8 source literal of <see cref="FlowKind"/>.</summary>
    public static ReadOnlySpan<byte> FlowKindUtf8 => "server.flow.kind"u8;

    /// <summary>The flow kind name (e.g., <c>AuthorizationCode</c>, <c>VerifiablePresentation</c>).</summary>
    public static string FlowKind { get; } = Utf8Constants.ToInternedString(FlowKindUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TenantHandle"/>.</summary>
    public static ReadOnlySpan<byte> TenantHandleUtf8 => "server.tenant.handle"u8;

    /// <summary>
    /// The application-assigned tenant handle the request's registration carries, safe to write
    /// to any configured exporter. A registration with no
    /// <see cref="IRegistrationRecord.TenantHandle"/> produces no tenant-shaped tag on the
    /// dispatch span — never the tenant key, which stays inside the process.
    /// </summary>
    public static string TenantHandle { get; } = Utf8Constants.ToInternedString(TenantHandleUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RegistrationId"/>.</summary>
    public static ReadOnlySpan<byte> RegistrationIdUtf8 => "server.registration.id"u8;

    /// <summary>The registration identifier from <see cref="IRegistrationRecord.ClientId"/>.</summary>
    public static string RegistrationId { get; } = Utf8Constants.ToInternedString(RegistrationIdUtf8);

    //HTTP request/response.

    /// <summary>The UTF-8 source literal of <see cref="HttpMethod"/>.</summary>
    public static ReadOnlySpan<byte> HttpMethodUtf8 => "http.request.method"u8;

    /// <summary>The HTTP method per OTel HTTP semantic conventions.</summary>
    public static string HttpMethod { get; } = Utf8Constants.ToInternedString(HttpMethodUtf8);

    /// <summary>The UTF-8 source literal of <see cref="StatusCode"/>.</summary>
    public static ReadOnlySpan<byte> StatusCodeUtf8 => "server.response.status_code"u8;

    /// <summary>The HTTP response status code.</summary>
    public static string StatusCode { get; } = Utf8Constants.ToInternedString(StatusCodeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ErrorCode"/>.</summary>
    public static ReadOnlySpan<byte> ErrorCodeUtf8 => "server.response.error_code"u8;

    /// <summary>
    /// The error code of a non-success response, from
    /// <see cref="Verifiable.Server.ServerHttpResponse.ErrorCode"/>. Absent when the response
    /// carries no typed error code.
    /// </summary>
    public static string ErrorCode { get; } = Utf8Constants.ToInternedString(ErrorCodeUtf8);

    //Flow state.

    /// <summary>The UTF-8 source literal of <see cref="FlowState"/>.</summary>
    public static ReadOnlySpan<byte> FlowStateUtf8 => "server.flow.state"u8;

    /// <summary>The PDA state type name after the transition.</summary>
    public static string FlowState { get; } = Utf8Constants.ToInternedString(FlowStateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FlowStepCount"/>.</summary>
    public static ReadOnlySpan<byte> FlowStepCountUtf8 => "server.flow.step_count"u8;

    /// <summary>The PDA step count after the transition.</summary>
    public static string FlowStepCount { get; } = Utf8Constants.ToInternedString(FlowStepCountUtf8);

    /// <summary>The UTF-8 source literal of <see cref="StartsNewFlow"/>.</summary>
    public static ReadOnlySpan<byte> StartsNewFlowUtf8 => "server.flow.starts_new"u8;

    /// <summary>Whether this endpoint starts a new flow or continues an existing one.</summary>
    public static string StartsNewFlow { get; } = Utf8Constants.ToInternedString(StartsNewFlowUtf8);

    //Correlation.

    /// <summary>The UTF-8 source literal of <see cref="CorrelationResolved"/>.</summary>
    public static ReadOnlySpan<byte> CorrelationResolvedUtf8 => "server.correlation.resolved"u8;

    /// <summary>Whether the correlation key resolution succeeded.</summary>
    public static string CorrelationResolved { get; } = Utf8Constants.ToInternedString(CorrelationResolvedUtf8);
}
