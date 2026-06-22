using System;
using System.Collections.Generic;
using Verifiable.Cryptography;

namespace Verifiable.Core.OutboundFetch;

/// <summary>
/// A single outbound HTTP request for the guarded <see cref="OutboundFetch"/> —
/// transport-neutral, carrying the target URL, the HTTP method, headers, and an
/// optional body.
/// </summary>
/// <remarks>
/// <para>
/// The method is an <strong>explicit</strong> field rather than an implied
/// <c>GET</c>, and the seam is deliberately <strong>method-agnostic</strong>.
/// </para>
/// <para>
/// <strong>Why method-agnostic — the GET/POST reasoning (keep this).</strong>
/// Restricting the gate to <c>GET</c> dereferences would leave an SSRF gap: the
/// endpoints a client <c>POST</c>s to — an OAuth/RFC 9728 token endpoint, a PAR
/// endpoint — are themselves taken from <em>discovered</em> metadata, so a
/// malicious or misconfigured metadata document could point them at an internal,
/// loopback, or cloud-metadata address. A <c>POST</c> to such an endpoint is just
/// as much an SSRF vector as a <c>GET</c> of a discovered URL. The
/// <see cref="OutboundFetchPolicy"/> must therefore gate every method, and the
/// redirect loop applies HTTP method-rewrite rules per hop (303 and the common
/// 301/302 handling fall back to <c>GET</c> and drop the body; 307/308 preserve
/// method and body). Hence the explicit <see cref="Method"/>.
/// </para>
/// </remarks>
public sealed record OutboundRequest
{
    internal static readonly IReadOnlyDictionary<string, string> EmptyHeaders =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);


    /// <summary>The absolute URL to contact. Validated against the policy before each hop.</summary>
    public required Uri Target { get; init; }

    /// <summary>
    /// The HTTP method (e.g. <c>GET</c>, <c>POST</c>). Explicit and gated; see the
    /// type remarks for why the seam is method-agnostic rather than GET-only.
    /// </summary>
    public required string Method { get; init; }

    /// <summary>Request headers (case-insensitive). Defaults to none.</summary>
    public IReadOnlyDictionary<string, string> Headers { get; init; } = EmptyHeaders;

    /// <summary>
    /// The request body for methods that carry one (e.g. <c>POST</c>), or
    /// <see langword="null"/> for a bodyless request such as a <c>GET</c>
    /// dereference. A tracked carrier, not a naked buffer.
    /// </summary>
    public TaggedMemory<byte>? Body { get; init; }

    /// <summary>
    /// An optional upper bound, in bytes, on the response body the caller will accept. A transport SHOULD stop
    /// reading and abort once the response exceeds this, so a hostile or misconfigured host cannot drive
    /// unbounded buffering before the caller's post-read size check rejects it. <see langword="null"/> imposes
    /// no transport-level bound; the caller's post-read cap remains the backstop either way.
    /// </summary>
    public long? MaxResponseBytes { get; init; }
}
