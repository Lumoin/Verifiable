using System.Diagnostics;
using Verifiable.Core;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The typed wire-shape envelope of an inbound request, produced by the
/// application skin and consumed by the library's dispatcher.
/// </summary>
/// <remarks>
/// <para>
/// The skin's only routing-related job is to produce one of these from an
/// HTTP request and hand it to <see cref="AuthorizationServer.DispatchAsync"/>.
/// Path-to-capability mapping is not the skin's job; capability is
/// descriptive metadata on the matcher that wins, not a routing input.
/// </para>
/// <para>
/// The library does all routing — reading whatever signals matchers care
/// about (path, method, body fields, headers, route values) from this
/// envelope. Each matcher's <see cref="ServerEndpoint.MatchesRequest"/>
/// declares its acceptance test in terms of these signals, and the chain
/// runner walks matchers in order until one accepts.
/// </para>
/// <para>
/// <strong>Field shape.</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <see cref="Path"/> — the raw path as it appeared on the wire, including
/// the tenant prefix if any. Matchers do their own substring/suffix checks
/// against the relevant suffix.
/// </description></item>
/// <item><description>
/// <see cref="Method"/> — uppercase HTTP method (<c>"GET"</c>, <c>"POST"</c>,
/// etc.). Matchers compare with <see cref="StringComparison.Ordinal"/>.
/// </description></item>
/// <item><description>
/// <see cref="Fields"/> — merged query and body form fields. The skin
/// merges per its policy (typically: body first, query second, last-write-
/// wins for collisions, matching ASP.NET behavior).
/// </description></item>
/// <item><description>
/// <see cref="Headers"/> — case-insensitive header bag. Matchers that read
/// <c>Authorization</c>, <c>Content-Type</c>, <c>Accept</c>, etc. read
/// here.
/// </description></item>
/// <item><description>
/// <see cref="RouteValues"/> — framework-extracted template parameters,
/// optional. Skins that did template parsing populate this; skins that
/// pass the raw path use <see cref="OAuth.Server.RouteValues.Empty"/>.
/// </description></item>
/// </list>
/// <para>
/// Immutable. The dispatcher reads it once and threads it through the
/// pipeline via <see cref="ExchangeContext"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("IncomingRequest {Method,nq} {Path,nq}")]
public sealed record IncomingRequest(
    string Path,
    string Method,
    RequestFields Fields,
    RequestHeaders Headers,
    RouteValues RouteValues)
{
    /// <summary>
    /// The request body, or <see cref="RequestBody.None"/> when the request
    /// carries no body (GET requests, or form-encoded POSTs whose payload
    /// is already in <see cref="Fields"/>).
    /// </summary>
    public RequestBody Body { get; init; } = RequestBody.None;
}
