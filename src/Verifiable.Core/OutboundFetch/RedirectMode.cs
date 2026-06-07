namespace Verifiable.Core.OutboundFetch;

/// <summary>
/// How an <see cref="OutboundFetchPolicy"/> treats HTTP redirects when the
/// guarded outbound fetch encounters a <c>3xx</c> response.
/// </summary>
/// <remarks>
/// Redirects are a primary SSRF vector — a URL that passes the initial policy
/// check can redirect to an internal/loopback/metadata address. The guarded
/// fetch therefore never lets the transport follow redirects automatically; it
/// applies this mode per hop and re-validates each <c>Location</c> against the
/// full policy. See the outbound-fetch design notes for the rationale.
/// </remarks>
public enum RedirectMode
{
    /// <summary>
    /// Do not follow redirects. A <c>3xx</c> response is a failure, not a
    /// follow. The secure default — and the principled default for metadata
    /// discovery (RFC 8414 / RFC 9728), which hands the caller an explicit URL.
    /// </summary>
    None = 0,

    /// <summary>
    /// Follow a redirect only when the target has the same origin
    /// (scheme + host + port) as the request that produced it, up to
    /// <see cref="OutboundFetchPolicy.MaxRedirects"/> hops.
    /// </summary>
    SameOrigin,

    /// <summary>
    /// Follow redirects to any target that itself passes the full
    /// <see cref="OutboundFetchPolicy"/> check, up to
    /// <see cref="OutboundFetchPolicy.MaxRedirects"/> hops.
    /// </summary>
    PolicyChecked
}
