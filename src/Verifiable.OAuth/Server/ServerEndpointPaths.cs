using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Path templates and URI computation for Authorization Server endpoints.
/// </summary>
/// <remarks>
/// <para>
/// All endpoint path templates are owned by the library so that neither the
/// application nor the client ever spells out a path string. Applications map
/// endpoints by looping over <see cref="AuthorizationServerEndpointRegistry.BuildFor"/>
/// and using <see cref="ServerEndpoint.PathTemplate"/> directly in their routing
/// framework. Clients discover endpoint URIs via the discovery document, whose
/// values are computed by <see cref="ComputeUri"/>.
/// </para>
/// <para>
/// The segment placeholder <c>{segment}</c> in path templates uses the same
/// convention as ASP.NET Core minimal API route templates, so templates can be
/// passed directly to <c>app.MapMethods</c> without transformation.
/// </para>
/// <para>
/// Global endpoints — those not scoped to a specific client registration — use
/// fixed paths without a segment parameter and are available in
/// <see cref="Global"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("ServerEndpointPaths")]
public static class ServerEndpointPaths
{
    /// <summary>The route parameter name used in all per-registration path templates.</summary>
    public const string SegmentParameter = "segment";

    /// <summary>The root prefix for all connect endpoints.</summary>
    private const string ConnectRoot = "/connect";

    /// <summary>The segment placeholder as it appears in path templates.</summary>
    private const string SegmentPlaceholder = "{segment}";

    /// <summary>The per-registration path prefix including the segment placeholder.</summary>
    private const string PerRegistrationPrefix = $"{ConnectRoot}/{SegmentPlaceholder}";


    //Per-registration path templates — contain {segment}.

    /// <summary>
    /// Path template for the OIDC discovery document per
    /// <see href="https://openid.net/specs/openid-connect-discovery-1_0.html">OIDC Discovery 1.0</see>.
    /// Example: <c>/connect/a3f9b2c1/.well-known/openid-configuration</c>.
    /// </summary>
    public const string Discovery =
        $"{PerRegistrationPrefix}/.well-known/openid-configuration";

    /// <summary>
    /// Path template for the JSON Web Key Set endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517">RFC 7517</see>.
    /// Example: <c>/connect/a3f9b2c1/jwks</c>.
    /// </summary>
    public const string Jwks = $"{PerRegistrationPrefix}/jwks";

    /// <summary>
    /// Path template for the Pushed Authorization Request endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126</see>.
    /// Example: <c>/connect/a3f9b2c1/par</c>.
    /// </summary>
    public const string Par = $"{PerRegistrationPrefix}/par";

    /// <summary>
    /// Path template for the authorization endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 §3.1</see>.
    /// Example: <c>/connect/a3f9b2c1/authorize</c>.
    /// </summary>
    public const string Authorize = $"{PerRegistrationPrefix}/authorize";

    /// <summary>
    /// Path template for the token endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 §3.2</see>.
    /// Example: <c>/connect/a3f9b2c1/token</c>.
    /// </summary>
    public const string Token = $"{PerRegistrationPrefix}/token";

    /// <summary>
    /// Path template for the token revocation endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009">RFC 7009</see>.
    /// Example: <c>/connect/a3f9b2c1/revoke</c>.
    /// </summary>
    public const string Revoke = $"{PerRegistrationPrefix}/revoke";

    /// <summary>
    /// Path template for the token introspection endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662">RFC 7662</see>.
    /// Example: <c>/connect/a3f9b2c1/introspect</c>.
    /// </summary>
    public const string Introspect = $"{PerRegistrationPrefix}/introspect";

    /// <summary>
    /// Path template for the RFC 7592 client registration management endpoint.
    /// Example: <c>/connect/a3f9b2c1/register</c>.
    /// </summary>
    public const string RegistrationManagement = $"{PerRegistrationPrefix}/register";

    /// <summary>
    /// Path template for the Device Authorization endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8628">RFC 8628</see>.
    /// Example: <c>/connect/a3f9b2c1/device_authorization</c>.
    /// </summary>
    public const string DeviceAuthorization =
        $"{PerRegistrationPrefix}/device_authorization";

    /// <summary>
    /// Path template for the OID4VP JAR request endpoint per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0 §5.7</see>.
    /// The Wallet fetches the signed JAR from this endpoint after scanning the QR code.
    /// Example: <c>/connect/a3f9b2c1/request/{flowId}</c>.
    /// </summary>
    public const string JarRequest = $"{PerRegistrationPrefix}/request/{{flowId}}";

    /// <summary>
    /// Path template for the OID4VP direct_post response endpoint per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0 §8.2</see>.
    /// The Wallet POSTs the encrypted Authorization Response JWE to this endpoint.
    /// Example: <c>/connect/a3f9b2c1/cb</c>.
    /// </summary>
    public const string DirectPost = $"{PerRegistrationPrefix}/cb";


    //Global path templates — no segment, mapped once at startup.

    /// <summary>
    /// Fixed path for the global initial client registration endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7591">RFC 7591</see>.
    /// This endpoint exists before any client registration and is not scoped to
    /// a segment.
    /// </summary>
    public const string GlobalRegistration = $"{ConnectRoot}/register";


    /// <summary>
    /// Computes the absolute URI for a per-registration endpoint given a base URI
    /// and the registration's endpoint segment.
    /// </summary>
    /// <remarks>
    /// Use this to populate the discovery document's endpoint URIs so that the
    /// values clients receive are always consistent with the paths the server serves.
    /// </remarks>
    /// <param name="baseUri">
    /// The base URI of the authorization server, e.g. <c>https://verifable.app</c>.
    /// </param>
    /// <param name="endpointSegment">The registration's endpoint segment.</param>
    /// <param name="pathTemplate">
    /// One of the path template constants on this class, e.g. <see cref="Par"/>.
    /// </param>
    /// <returns>
    /// The absolute URI for the endpoint, e.g.
    /// <c>https://verifable.app/connect/a3f9b2c1/par</c>.
    /// </returns>
    public static Uri ComputeUri(Uri baseUri, string endpointSegment, string pathTemplate)
    {
        ArgumentNullException.ThrowIfNull(baseUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(endpointSegment);
        ArgumentException.ThrowIfNullOrWhiteSpace(pathTemplate);

        string resolvedPath = pathTemplate.Replace(
            SegmentPlaceholder, endpointSegment, StringComparison.Ordinal);

        string authority = baseUri.GetLeftPart(UriPartial.Authority);
        return new Uri($"{authority}{resolvedPath}");
    }


    /// <summary>
    /// Computes the absolute URI for the global registration endpoint.
    /// </summary>
    /// <param name="baseUri">The base URI of the authorization server.</param>
    public static Uri ComputeGlobalRegistrationUri(Uri baseUri)
    {
        ArgumentNullException.ThrowIfNull(baseUri);
        string authority = baseUri.GetLeftPart(UriPartial.Authority);
        return new Uri($"{authority}{GlobalRegistration}");
    }
}
