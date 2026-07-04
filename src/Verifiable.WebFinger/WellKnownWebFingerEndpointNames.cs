using System.Diagnostics;

namespace Verifiable.WebFinger;

/// <summary>
/// Stable endpoint role identifier for the WebFinger query endpoint, used as the
/// <see cref="EndpointCandidate.Name"/> value and as the lookup key the application's
/// <see cref="ResolveEndpointUriDelegate"/> switches on to produce the per-deployment URL.
/// </summary>
/// <remarks>
/// A getter, not a <c>static readonly</c> field, per the library's well-known-value convention; the
/// single entry mirrors the plain-getter shape <see cref="WellKnownWebFingerValues"/> already
/// establishes in this assembly rather than the UTF-8-first pattern the OAuth and W3C VCALM endpoint-name
/// catalogues use, since WebFinger has exactly one endpoint role to name.
/// </remarks>
[DebuggerDisplay("WellKnownWebFingerEndpointNames")]
public static class WellKnownWebFingerEndpointNames
{
    /// <summary>
    /// The <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4">RFC 7033 §4</see>
    /// <c>GET /.well-known/webfinger</c> query endpoint.
    /// </summary>
    public static string WebFinger { get; } = "WebFinger";
}
