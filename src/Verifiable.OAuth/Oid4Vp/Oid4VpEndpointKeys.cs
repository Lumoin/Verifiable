using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Endpoint-role identifiers passed by the library's OID4VP flow to
/// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/> when
/// it needs to embed an absolute URL in a produced artifact.
/// </summary>
/// <remarks>
/// <para>
/// These keys identify endpoint roles whose URLs are per-flow rather than
/// per-deployment static. The OID4VP <c>request_uri</c> is the canonical
/// example: each PAR response carries a fresh, single-use URL whose path
/// encodes a flow-scoped opaque token. Library code calls
/// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
/// with one of these keys; the application's delegate reads any per-flow
/// inputs the library placed on <see cref="RequestContext"/> via
/// <see cref="Oid4VpContextKeys"/> and composes the URL according to the
/// deployment's routing scheme.
/// </para>
/// <para>
/// Discovery-document field URLs use the static keys on
/// <see cref="AuthorizationServerMetadataKeys"/> instead. The two key
/// families are kept distinct so a delegate switching on the key value can
/// recognize per-flow versus static endpoints unambiguously.
/// </para>
/// </remarks>
[DebuggerDisplay("Oid4VpEndpointKeys")]
public static class Oid4VpEndpointKeys
{
    /// <summary>
    /// The per-flow JAR-fetch endpoint URL embedded as the <c>request_uri</c>
    /// value in the PAR response per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.2">OID4VP 1.0 §5.2</see>
    /// and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The application's
    /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
    /// delegate composes the absolute URL using the deployment's routing
    /// scheme. The library places the per-flow opaque token on
    /// <see cref="RequestContext"/> via
    /// <see cref="Oid4VpContextKeys.ParHandle"/> before invoking the
    /// delegate; the delegate reads the token and incorporates it into the
    /// URL. The Wallet later dereferences this URL with HTTP GET to fetch
    /// the JAR.
    /// </para>
    /// <para>
    /// The token is unrelated to the internal flow identifier; the flow
    /// identifier never leaves the server process. The application's
    /// <see cref="AuthorizationServerIntegration.ResolveCorrelationKeyAsync"/>
    /// maps the inbound token back to the flow identifier when the JAR-fetch
    /// or direct-post requests arrive.
    /// </para>
    /// </remarks>
    public static readonly string RequestUri = "oid4vp.endpoint.requestUri";
}
