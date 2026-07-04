using System.Diagnostics;
using Verifiable.Server;

namespace Verifiable.WebFinger;

/// <summary>
/// The WebFinger family integration: the protocol seams <see cref="WebFingerEndpoints"/> resolves
/// through, registered on a neutral <see cref="EndpointServer"/> via
/// <see cref="EndpointServer.AddIntegration{T}"/> and reached from the endpoint with
/// <see cref="EndpointServerWebFingerExtensions.WebFinger(EndpointServer)"/>.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors the shape every protocol family uses to attach its seams to the shared, protocol-neutral host
/// (see the OAuth family's <c>AuthorizationServerIntegration</c> and the W3C VCALM family's
/// <c>VcalmIntegration</c>): a family-specific <see cref="ServerIntegration"/> subclass carries the
/// family's delegates in a plain object the host stores by concrete type; the host itself depends on
/// none of it. WebFinger takes no dependency on any other protocol family — the two delegates here are
/// its complete seam surface, reached without capturing caller/app data in a closure: every endpoint
/// delegate reads them fresh off <see cref="EndpointServer"/> through the per-request
/// <see cref="ExchangeContextServerExtensions.Server"/> accessor rather than a captured reference.
/// </para>
/// <para>
/// <see cref="EndpointServer.AddIntegration{T}"/> / <see cref="EndpointServer.GetIntegration{T}"/> are
/// already fully protocol-neutral, so wiring WebFinger onto the shared host required no addition to
/// <c>Verifiable.Server</c>.
/// </para>
/// </remarks>
[DebuggerDisplay("WebFingerIntegration")]
public sealed class WebFingerIntegration: ServerIntegration
{
    /// <summary>
    /// Resolves a query target to a <see cref="JsonResourceDescriptor"/>. Required — when unwired, the
    /// <see cref="WellKnownWebFingerCapabilityIdentifiers.Endpoint"/> capability does not materialize a
    /// route: fail-closed, since only the application knows its resource store.
    /// </summary>
    public ResolveWebFingerResourceDelegate? ResolveWebFingerResourceAsync { get; set; }

    /// <summary>
    /// Resolves the <c>Access-Control-Allow-Origin</c> value for the current request. Optional — when
    /// unwired, every response carries
    /// <see cref="WellKnownWebFingerValues.AccessControlAllowOriginWildcard"/>, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-5">RFC 7033 §5</see>'s
    /// SHOULD-support-<c>*</c> guidance.
    /// </summary>
    public ResolveCorsOriginDelegate? ResolveCorsOriginAsync { get; set; }
}
