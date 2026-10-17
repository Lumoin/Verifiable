using System.Diagnostics;
using Verifiable.Core;

namespace Verifiable.Server;

/// <summary>
/// The typed wire-shape envelope of an inbound request, produced by the
/// application skin and consumed by the library's dispatcher.
/// </summary>
/// <remarks>
/// <para>
/// The skin's only routing-related job is to produce one of these from an
/// HTTP request and hand it to <see cref="EndpointServer.DispatchAsync"/>.
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
/// <see cref="Path"/>: the path the server's own request parsing answers,
/// including the tenant prefix if any: decoded and without the query, the
/// form routing reads. Matchers do their own substring/suffix checks against
/// the relevant suffix.
/// </description></item>
/// <item><description>
/// <see cref="RequestTarget"/>: the request-target exactly as the client sent
/// it, the path and the query in the client's own spelling, the form a
/// request's identity is compared in. Set by the skin from the server's raw
/// target, never from a request field.
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
/// pass the raw path use <see cref="Verifiable.Server.RouteValues.Empty"/>.
/// </description></item>
/// <item><description>
/// <see cref="ListenerAuthority"/>: the scheme and authority of the listener
/// that received the request, as the host's own configuration names it,
/// optional. Set by the skin from its listener, never from a request field.
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

    /// <summary>
    /// The request-target exactly as the client sent it on the request line, in origin-form: the absolute path and,
    /// when present, <c>?</c> and the query, with percent-encoding, dot segments and letter case as the client wrote
    /// them, never decoded. <see href="https://www.rfc-editor.org/rfc/rfc9112#section-3.2.1">RFC 9112 Section
    /// 3.2.1</see>: "origin-form = absolute-path [ "?" query ]" and "a client MUST send only the absolute path and query
    /// components of the target URI as the request-target."
    /// </summary>
    /// <remarks>
    /// <para>
    /// The skin sets it from the server's own raw target (in ASP.NET Core, the
    /// <c>Microsoft.AspNetCore.Http.Features.IHttpRequestFeature.RawTarget</c> of the request's features), never from a
    /// request field (<see cref="Fields"/> merges the client's query and body, so a conventional key there is a value a client
    /// can send), for the reason <see cref="ListenerAuthority"/> states: a value a client chooses would let the client
    /// choose the target a request is judged against. It is required so that every skin sets it.
    /// </para>
    /// <para>
    /// <see cref="Path"/> is the server's decoded path, the form routing reads; this value is the client's own spelling,
    /// the form a request's identity is compared in. The library's own resources read it where a URL the client used is
    /// compared code point for code point
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-6">RFC 9728 Section 6</see>: "Comparisons between the
    /// two strings MUST be performed as a Unicode code-point-to-code-point equality comparison."): a challenge names a
    /// resource's protected resource metadata document only when the request's scheme and authority followed by this
    /// value is the resource's identifier, and a resource's document is served only at the request-target that is its
    /// location's path and query (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section
    /// 3.3</see>).
    /// </para>
    /// </remarks>
    public required string RequestTarget { get; init; }

    /// <summary>
    /// The scheme and authority of the listener that received the request, as the host's own
    /// configuration names it, or <see langword="null"/> when the host names none. The host sets it
    /// when it builds the request from the listener that accepted the connection; it is never read
    /// from a request field (<c>Host</c>, <c>Forwarded</c> or any other), since a value a client
    /// chooses would let the client choose the target a request is judged against.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-7.1">RFC 9110 Section 7.1</see>:
    /// "Upon receipt of a client's request, a server reconstructs the target URI from the received
    /// components in accordance with their local configuration and incoming connection context." A
    /// host behind a proxy or a load balancer serves clients that address an authority other than the
    /// issuer's; this value is that authority. When it is set, the DPoP checks hold a proof's
    /// <c>htu</c> to this authority and the request <see cref="Path"/>, and otherwise to the issuer's
    /// authority and the path (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC
    /// 9449 Section 4.3</see>, check 9: "The htu claim matches the HTTP URI value for the HTTP request
    /// in which the JWT was received, ignoring any query and fragment parts.").
    /// </para>
    /// <para>
    /// The value is an absolute URI. Only its scheme and authority are read
    /// (<see cref="Uri.GetLeftPart(UriPartial)"/> with <see cref="UriPartial.Authority"/>); a path,
    /// query or fragment the value carries takes no part, and a relative URI, which has no authority
    /// to read, fails every DPoP-checked request it is stamped on and every request to one of the
    /// library's own resources whose protected resource metadata document is served, whose challenges
    /// compare the request's target with the resource's identifier. A host that fills it from a request
    /// field lets a client choose it; the value is the host's configuration, and so is its failure,
    /// a relative value among them.
    /// </para>
    /// </remarks>
    public Uri? ListenerAuthority { get; init; }
}
