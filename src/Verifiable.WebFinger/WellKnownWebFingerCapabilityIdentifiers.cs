using System.Diagnostics;

namespace Verifiable.WebFinger;

/// <summary>
/// Library-shipped <see cref="CapabilityIdentifier"/> instance gating the WebFinger server endpoint.
/// </summary>
/// <remarks>
/// The <see cref="CapabilityIdentifier"/> TYPE lives in the neutral <c>Verifiable.Server</c> host; the
/// VALUE here is WebFinger's own, colocated with the WebFinger endpoint that consumes it — the same
/// pattern the OAuth and W3C VCALM families use for their own capability sets. A registration's
/// <see cref="IRegistrationRecord.AllowedCapabilities"/> must contain this identifier for
/// <see cref="WebFingerEndpoints.Builder"/> to emit the <c>GET /.well-known/webfinger</c> candidate.
/// </remarks>
[DebuggerDisplay("WellKnownWebFingerCapabilityIdentifiers")]
public static class WellKnownWebFingerCapabilityIdentifiers
{
    /// <summary>
    /// The WebFinger server endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4">RFC 7033 §4</see>: gates the
    /// <c>GET /.well-known/webfinger</c> query endpoint <see cref="WebFingerEndpoints"/> serves.
    /// </summary>
    public static CapabilityIdentifier Endpoint { get; } =
        CapabilityIdentifier.Create("urn:verifiable:capability:webfinger:endpoint");
}
