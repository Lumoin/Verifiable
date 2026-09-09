using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Siop.Server;

/// <summary>
/// Endpoint-role identifiers the SIOPv2 RP flow passes to
/// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/> when it needs to embed an
/// absolute URL in a produced artifact. The SIOP parallel of
/// <see cref="Verifiable.OAuth.Oid4Vp.Oid4VpEndpointKeys"/>.
/// </summary>
public static class SiopVerifierEndpointKeys
{
    /// <summary>The UTF-8 source literal of <see cref="RequestUri"/>.</summary>
    public static ReadOnlySpan<byte> RequestUriUtf8 => "siop.endpoint.requestUri"u8;

    /// <summary>
    /// The per-flow §9 Request Object endpoint URL embedded as the <c>request_uri</c> value the
    /// Relying Party returns from request preparation. The Wallet dereferences it with HTTP GET to
    /// fetch the signed Request Object per
    /// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-9">SIOPv2 §9</see>.
    /// </summary>
    /// <remarks>
    /// The application's <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/> delegate
    /// composes the absolute URL using the deployment's routing scheme. The library places the
    /// per-flow request handle on <see cref="ExchangeContext"/> via
    /// <see cref="SiopVerifierExchangeContextExtensions.SetSiopRequestHandle"/> before invoking the
    /// delegate; the delegate reads the handle and incorporates it into the URL. The handle is
    /// unrelated to the internal flow identifier, which never leaves the server process.
    /// </remarks>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "This member is the library's internal endpoint-role KEY NAME 'siop.endpoint.requestUri' (compared as a string, never dereferenced), not the URL it identifies.")]
    public static string RequestUri { get; } = Utf8Constants.ToInternedString(RequestUriUtf8);
}
