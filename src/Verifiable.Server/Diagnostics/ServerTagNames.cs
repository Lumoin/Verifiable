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
    public static readonly string FlowKind = Utf8Constants.ToInternedString(FlowKindUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TenantId"/>.</summary>
    public static ReadOnlySpan<byte> TenantIdUtf8 => "server.tenant.id"u8;

    /// <summary>
    /// The tenant identifier the request was resolved against. Opaque from the
    /// library's perspective; meaningful to the application's tenant resolver
    /// and registration store.
    /// </summary>
    public static readonly string TenantId = Utf8Constants.ToInternedString(TenantIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RegistrationId"/>.</summary>
    public static ReadOnlySpan<byte> RegistrationIdUtf8 => "server.registration.id"u8;

    /// <summary>The registration identifier from <see cref="IRegistrationRecord.ClientId"/>.</summary>
    public static readonly string RegistrationId = Utf8Constants.ToInternedString(RegistrationIdUtf8);

    //HTTP request/response.

    /// <summary>The UTF-8 source literal of <see cref="HttpMethod"/>.</summary>
    public static ReadOnlySpan<byte> HttpMethodUtf8 => "http.request.method"u8;

    /// <summary>The HTTP method per OTel HTTP semantic conventions.</summary>
    public static readonly string HttpMethod = Utf8Constants.ToInternedString(HttpMethodUtf8);

    /// <summary>The UTF-8 source literal of <see cref="StatusCode"/>.</summary>
    public static ReadOnlySpan<byte> StatusCodeUtf8 => "server.response.status_code"u8;

    /// <summary>The HTTP response status code.</summary>
    public static readonly string StatusCode = Utf8Constants.ToInternedString(StatusCodeUtf8);

    //Flow state.

    /// <summary>The UTF-8 source literal of <see cref="FlowState"/>.</summary>
    public static ReadOnlySpan<byte> FlowStateUtf8 => "server.flow.state"u8;

    /// <summary>The PDA state type name after the transition.</summary>
    public static readonly string FlowState = Utf8Constants.ToInternedString(FlowStateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FlowStepCount"/>.</summary>
    public static ReadOnlySpan<byte> FlowStepCountUtf8 => "server.flow.step_count"u8;

    /// <summary>The PDA step count after the transition.</summary>
    public static readonly string FlowStepCount = Utf8Constants.ToInternedString(FlowStepCountUtf8);

    /// <summary>The UTF-8 source literal of <see cref="StartsNewFlow"/>.</summary>
    public static ReadOnlySpan<byte> StartsNewFlowUtf8 => "server.flow.starts_new"u8;

    /// <summary>Whether this endpoint starts a new flow or continues an existing one.</summary>
    public static readonly string StartsNewFlow = Utf8Constants.ToInternedString(StartsNewFlowUtf8);

    //Correlation.

    /// <summary>The UTF-8 source literal of <see cref="CorrelationResolved"/>.</summary>
    public static ReadOnlySpan<byte> CorrelationResolvedUtf8 => "server.correlation.resolved"u8;

    /// <summary>Whether the correlation key resolution succeeded.</summary>
    public static readonly string CorrelationResolved = Utf8Constants.ToInternedString(CorrelationResolvedUtf8);
}
