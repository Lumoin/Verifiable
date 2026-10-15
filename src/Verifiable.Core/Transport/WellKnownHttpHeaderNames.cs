using Verifiable.Cryptography.Text;

namespace Verifiable.Core.Transport;

/// <summary>
/// HTTP header name constants, plus per-header <c>IsXxx</c> predicates and a
/// central <see cref="Equals"/> method anchoring the comparison rule.
/// </summary>
/// <remarks>
/// <para>
/// HTTP header names are <strong>case-insensitive on the wire</strong> per
/// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110 §5.1</see>.
/// The canonical spellings here use the conventions established by their
/// defining specifications (<c>Authorization</c> per RFC 9110 §11.6.2,
/// <c>DPoP</c> and <c>DPoP-Nonce</c> per RFC 9449 §4 and §8). Comparisons
/// here use <see cref="StringComparison.OrdinalIgnoreCase"/> per the spec
/// rule, centralised in <see cref="Equals"/>.
/// </para>
/// <para>
/// Fields the library reads or composes include <see cref="Authorization"/>,
/// <see cref="Accept"/>, <see cref="AcceptLanguage"/>, <see cref="ContentLanguage"/>,
/// <see cref="ContentType"/>, <see cref="DPoP"/>, <see cref="DPoPNonce"/>,
/// <see cref="CacheControl"/>, <see cref="WwwAuthenticate"/>, <see cref="Allow"/>,
/// <see cref="Location"/>, <see cref="Date"/>, <see cref="Age"/>, <see cref="Expires"/>,
/// <see cref="RetryAfter"/>, and <see cref="AccessControlExposeHeaders"/>. Hosts that read or write content length, cookies, proxy
/// credentials, trace context and rate limits beside the library can use <see cref="ContentLength"/>,
/// <see cref="Cookie"/>, <see cref="SetCookie"/>, <see cref="ProxyAuthorization"/>,
/// <see cref="TraceParent"/>, <see cref="TraceState"/>,
/// <see cref="Baggage"/>, <see cref="RateLimitPolicy"/>, and <see cref="RateLimit"/>.
/// The trace-context names use the lowercase spelling their specifications ask senders to use:
/// W3C Trace Context says "Vendors MUST expect the header name in any case (upper, lower, mixed),
/// and SHOULD send the header name in lowercase."
/// (<see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#header-name">Section 3.2.1</see>
/// and <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#header-name-0">Section 3.3.1</see>);
/// the W3C Baggage Candidate Recommendation Snapshot says "implementations SHOULD keep the header name lowercase."
/// (<see href="https://www.w3.org/TR/2024/CR-baggage-20240530/#header-name">Section 3.1</see>).
/// Comparisons remain case-insensitive per
/// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110 §5.1</see>.
/// Each entry carries its own <c>IsXxx</c> predicate and a row in <see cref="GetCanonicalizedValue"/>, except
/// <see cref="AccessControlExposeHeaders"/>, which carries its row and no predicate of its own and is compared through
/// <see cref="Equals"/>.
/// This transport vocabulary lives beside <see cref="HttpHeaderSet"/>.
/// </para>
/// </remarks>
public static class WellKnownHttpHeaderNames
{
    /// <summary>The UTF-8 source literal of <see cref="Authorization"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationUtf8 => "Authorization"u8;

    /// <summary>
    /// The <c>Authorization</c> request header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.2">RFC 9110 §11.6.2</see>.
    /// Carries the credentials the client uses to authenticate to the server.
    /// </summary>
    public static string Authorization { get; } = Utf8Constants.ToInternedString(AuthorizationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ProxyAuthorization"/>.</summary>
    public static ReadOnlySpan<byte> ProxyAuthorizationUtf8 => "Proxy-Authorization"u8;

    /// <summary>
    /// The <c>Proxy-Authorization</c> request header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.7.2">RFC 9110 Section 11.7.2</see>:
    /// "The &quot;Proxy-Authorization&quot; header field allows the client to identify itself (or its
    /// user) to a proxy that requires authentication. Its value consists of credentials containing the
    /// authentication information of the client for the proxy and/or realm of the resource being
    /// requested." A credential field, as <see cref="Authorization"/> and <see cref="Cookie"/> are.
    /// </summary>
    public static string ProxyAuthorization { get; } = Utf8Constants.ToInternedString(ProxyAuthorizationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Cookie"/>.</summary>
    public static ReadOnlySpan<byte> CookieUtf8 => "Cookie"u8;

    /// <summary>
    /// The <c>Cookie</c> request header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6265#section-4.2.1">RFC 6265 Section 4.2.1</see>:
    /// "The user agent sends stored cookies to the origin server in the Cookie header." A credential
    /// field, as <see cref="Authorization"/> and <see cref="ProxyAuthorization"/> are.
    /// </summary>
    public static string Cookie { get; } = Utf8Constants.ToInternedString(CookieUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Accept"/>.</summary>
    public static ReadOnlySpan<byte> AcceptUtf8 => "Accept"u8;

    /// <summary>
    /// The <c>Accept</c> request header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-12.5.1">RFC 9110 §12.5.1</see>
    /// — the response media types the caller can process. A resource server requests
    /// an RFC 9701 signed introspection response by setting it to
    /// <c>application/token-introspection+jwt</c>.
    /// </summary>
    public static string Accept { get; } = Utf8Constants.ToInternedString(AcceptUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AcceptLanguage"/>.</summary>
    public static ReadOnlySpan<byte> AcceptLanguageUtf8 => "Accept-Language"u8;

    /// <summary>
    /// The <c>Accept-Language</c> request header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-12.5.4">RFC 9110 §12.5.4</see>
    /// — the natural languages the caller prefers in the response. OID4VCI 1.0 §12.2.2: "The
    /// Wallet is RECOMMENDED to send an Accept-Language header in the HTTP GET request to
    /// indicate the language(s) preferred for display." Its values use the language tags defined
    /// in RFC 3066.
    /// </summary>
    public static string AcceptLanguage { get; } = Utf8Constants.ToInternedString(AcceptLanguageUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ContentLanguage"/>.</summary>
    public static ReadOnlySpan<byte> ContentLanguageUtf8 => "Content-Language"u8;

    /// <summary>
    /// The <c>Content-Language</c> response header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.5">RFC 9110 §8.5</see>.
    /// OID4VCI 1.0 §12.2.2: a Credential Issuer that filters the metadata's internationalized
    /// display data to the requested language(s) MUST "indicate returned languages using the
    /// HTTP Content-Language Header". Its values use the language tags defined in RFC 3066.
    /// </summary>
    public static string ContentLanguage { get; } = Utf8Constants.ToInternedString(ContentLanguageUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ContentType"/>.</summary>
    public static ReadOnlySpan<byte> ContentTypeUtf8 => "Content-Type"u8;

    /// <summary>
    /// The <c>Content-Type</c> header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3">RFC 9110 §8.3</see>:
    /// "The 'Content-Type' header field indicates the media type of the associated
    /// representation … A sender that generates a message containing content SHOULD
    /// generate a Content-Type header field in that message unless the intended media
    /// type of the enclosed representation is unknown to the sender."
    /// </summary>
    public static string ContentType { get; } = Utf8Constants.ToInternedString(ContentTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ContentLength"/>.</summary>
    public static ReadOnlySpan<byte> ContentLengthUtf8 => "Content-Length"u8;

    /// <summary>
    /// The <c>Content-Length</c> header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.6">RFC 9110 Section 8.6</see>:
    /// "The &quot;Content-Length&quot; header field indicates the associated representation's data
    /// length as a decimal non-negative integer number of octets."
    /// </summary>
    public static string ContentLength { get; } = Utf8Constants.ToInternedString(ContentLengthUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DPoP"/>.</summary>
    public static ReadOnlySpan<byte> DPoPUtf8 => "DPoP"u8;

    /// <summary>
    /// The <c>DPoP</c> request header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4">RFC 9449 §4</see>.
    /// Carries the proof JWS bound to the request the client is making.
    /// </summary>
    public static string DPoP { get; } = Utf8Constants.ToInternedString(DPoPUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DPoPNonce"/>.</summary>
    public static ReadOnlySpan<byte> DPoPNonceUtf8 => "DPoP-Nonce"u8;

    /// <summary>
    /// The <c>DPoP-Nonce</c> response header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 §8</see>
    /// (AS) and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">§9</see> (RS).
    /// Carries a server-issued nonce the client must echo in the next proof's
    /// <c>nonce</c> claim.
    /// </summary>
    public static string DPoPNonce { get; } = Utf8Constants.ToInternedString(DPoPNonceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CacheControl"/>.</summary>
    public static ReadOnlySpan<byte> CacheControlUtf8 => "Cache-Control"u8;

    /// <summary>
    /// The <c>Cache-Control</c> header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.2">RFC 9111 §5.2</see>.
    /// Used with the <c>no-store</c> directive on token-bearing responses per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1#section-3.2.3">OAuth 2.1 §3.2.3</see>,
    /// and read for its <c>max-age</c>/<c>s-maxage</c>/<c>no-store</c>/<c>no-cache</c>
    /// directives by <see cref="Verifiable.Core.Outbound.HttpCacheFreshness"/>.
    /// </summary>
    public static string CacheControl { get; } = Utf8Constants.ToInternedString(CacheControlUtf8);

    /// <summary>The UTF-8 source literal of <see cref="WwwAuthenticate"/>.</summary>
    public static ReadOnlySpan<byte> WwwAuthenticateUtf8 => "WWW-Authenticate"u8;

    /// <summary>
    /// The <c>WWW-Authenticate</c> response header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 §11.6.1</see>.
    /// Carries the authentication challenge on <c>401</c> responses; RFC 9728 §5.1
    /// adds the <c>resource_metadata</c> challenge parameter pointing at the
    /// protected resource's metadata document.
    /// </summary>
    public static string WwwAuthenticate { get; } = Utf8Constants.ToInternedString(WwwAuthenticateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AccessControlExposeHeaders"/>.</summary>
    public static ReadOnlySpan<byte> AccessControlExposeHeadersUtf8 => "Access-Control-Expose-Headers"u8;

    /// <summary>
    /// The <c>Access-Control-Expose-Headers</c> response header of the CORS protocol, the list of response field names
    /// a browser makes available to a cross-origin application beside the CORS-safelisted ones.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "In order for the
    /// application to obtain and use the WWW-Authenticate HTTP response header value, the server needs to make it
    /// available to the application by including WWW-Authenticate in the Access-Control-Expose-Headers response header
    /// list value." and <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">Section 8</see>: "In order for the
    /// application to obtain and use the DPoP-Nonce HTTP response header value, the server needs to make it available
    /// to the application by including DPoP-Nonce in the Access-Control-Expose-Headers response header list value."
    /// </summary>
    public static string AccessControlExposeHeaders { get; } = Utf8Constants.ToInternedString(AccessControlExposeHeadersUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Allow"/>.</summary>
    public static ReadOnlySpan<byte> AllowUtf8 => "Allow"u8;

    /// <summary>
    /// The <c>Allow</c> response header
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-10.2.1">RFC 9110 §10.2.1</see>),
    /// which lists the methods the target resource supports. A <c>405 (Method Not Allowed)</c>
    /// response carries it (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.5.6">RFC 9110
    /// §15.5.6</see>) to name the methods the known resource does accept.
    /// </summary>
    public static string Allow { get; } = Utf8Constants.ToInternedString(AllowUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Location"/>.</summary>
    public static ReadOnlySpan<byte> LocationUtf8 => "Location"u8;

    /// <summary>
    /// The <c>Location</c> header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-10.2.2">RFC 9110 §10.2.2</see>:
    /// "used in some responses to refer to a specific resource in relation to the response.
    /// … For 201 (Created) responses, the Location value refers to the primary resource
    /// created by the request. For 3xx (Redirection) responses, the Location value refers
    /// to the preferred target resource for automatically redirecting the request." Read by
    /// <see cref="Verifiable.Core.Outbound.OutboundFetch"/>'s redirect loop on every hop.
    /// </summary>
    public static string Location { get; } = Utf8Constants.ToInternedString(LocationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Date"/>.</summary>
    public static ReadOnlySpan<byte> DateUtf8 => "Date"u8;

    /// <summary>
    /// The <c>Date</c> header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-6.6.1">RFC 9110 §6.6.1</see>:
    /// "represents the date and time at which the message was originated". Read by
    /// <see cref="Verifiable.Core.Outbound.HttpCacheFreshness"/> as the reference instant
    /// for the <see cref="Expires"/> fallback (RFC 9111 §4.2.1).
    /// </summary>
    public static string Date { get; } = Utf8Constants.ToInternedString(DateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Age"/>.</summary>
    public static ReadOnlySpan<byte> AgeUtf8 => "Age"u8;

    /// <summary>
    /// The <c>Age</c> response header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.1">RFC 9111 §5.1</see>:
    /// "The 'Age' response header field conveys the sender's estimate of the time since the
    /// response was generated or successfully validated at the origin server." Read by
    /// <see cref="Verifiable.Core.Outbound.HttpCacheFreshness"/> to reduce a computed
    /// freshness lifetime by the time already elapsed.
    /// </summary>
    public static string Age { get; } = Utf8Constants.ToInternedString(AgeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Expires"/>.</summary>
    public static ReadOnlySpan<byte> ExpiresUtf8 => "Expires"u8;

    /// <summary>
    /// The <c>Expires</c> response header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.3">RFC 9111 §5.3</see>:
    /// "The 'Expires' response header field gives the date/time after which the response is
    /// considered stale." Read by <see cref="Verifiable.Core.Outbound.HttpCacheFreshness"/>
    /// as the fallback freshness signal (against <see cref="Date"/>) when no
    /// <see cref="CacheControl"/> <c>max-age</c>/<c>s-maxage</c> directive is present.
    /// </summary>
    public static string Expires { get; } = Utf8Constants.ToInternedString(ExpiresUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SetCookie"/>.</summary>
    public static ReadOnlySpan<byte> SetCookieUtf8 => "Set-Cookie"u8;

    /// <summary>
    /// The <c>Set-Cookie</c> response header per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6265#section-4.1">RFC 6265 Section 4.1</see>:
    /// "The Set-Cookie HTTP response header is used to send cookies from the server to the user agent."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110 Section 5.3</see>:
    /// "In practice, the &quot;Set-Cookie&quot; header field ([COOKIE]) often appears in a response
    /// message across multiple field lines and does not use the list syntax, violating the above
    /// requirements on multiple field lines with the same field name." The note goes on: "Since it
    /// cannot be combined into a single field value, recipients ought to handle &quot;Set-Cookie&quot;
    /// as a special case while processing fields." A <see cref="HttpHeaderSet"/> holds each
    /// <c>Set-Cookie</c> field line as its own value.
    /// </summary>
    public static string SetCookie { get; } = Utf8Constants.ToInternedString(SetCookieUtf8);

    /// <summary>
    /// The UTF-8 source literal of <see cref="TraceParent"/>: "Header name: traceparent" in the
    /// <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#header-name">W3C Trace Context Recommendation §3.2.1</see>.
    /// </summary>
    public static ReadOnlySpan<byte> TraceParentUtf8 => "traceparent"u8;

    /// <summary>
    /// The interned trace-parent header name derived from <see cref="TraceParentUtf8"/>.
    /// The <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#header-name">W3C Trace Context Recommendation §3.2.1</see>
    /// names "Header name: traceparent" and says "Vendors MUST expect the header name in any case
    /// (upper, lower, mixed), and SHOULD send the header name in lowercase."
    /// </summary>
    public static string TraceParent { get; } = Utf8Constants.ToInternedString(TraceParentUtf8);

    /// <summary>
    /// The UTF-8 source literal of <see cref="TraceState"/>: "Header name: tracestate" in the
    /// <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#header-name-0">W3C Trace Context Recommendation §3.3.1</see>.
    /// </summary>
    public static ReadOnlySpan<byte> TraceStateUtf8 => "tracestate"u8;

    /// <summary>
    /// The interned trace-state header name derived from <see cref="TraceStateUtf8"/>.
    /// The <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#header-name-0">W3C Trace Context Recommendation §3.3.1</see>
    /// names "Header name: tracestate" and says "Vendors MUST expect the header name in any case
    /// (upper, lower, mixed), and SHOULD send the header name in lowercase."
    /// </summary>
    public static string TraceState { get; } = Utf8Constants.ToInternedString(TraceStateUtf8);

    /// <summary>
    /// The UTF-8 source literal of <see cref="Baggage"/>: "Header name: baggage" in the
    /// <see href="https://www.w3.org/TR/2024/CR-baggage-20240530/#header-name">W3C Baggage §3.1</see>,
    /// a Candidate Recommendation Snapshot dated 30 May 2024.
    /// </summary>
    public static ReadOnlySpan<byte> BaggageUtf8 => "baggage"u8;

    /// <summary>
    /// The interned baggage header name derived from <see cref="BaggageUtf8"/>.
    /// <see href="https://www.w3.org/TR/2024/CR-baggage-20240530/#header-name">W3C Baggage §3.1</see>,
    /// a Candidate Recommendation Snapshot dated 30 May 2024, names "Header name: baggage" and says
    /// "implementations SHOULD keep the header name lowercase."
    /// </summary>
    public static string Baggage { get; } = Utf8Constants.ToInternedString(BaggageUtf8);

    /// <summary>
    /// The UTF-8 source literal of <see cref="RetryAfter"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-10.2.3">RFC 9110 §10.2.3</see>
    /// defines "Retry-After = HTTP-date / delay-seconds".
    /// </summary>
    public static ReadOnlySpan<byte> RetryAfterUtf8 => "Retry-After"u8;

    /// <summary>
    /// The interned retry-delay header name derived from <see cref="RetryAfterUtf8"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-10.2.3">RFC 9110 §10.2.3</see>:
    /// "Servers send the &quot;Retry-After&quot; header field to indicate how long the user agent ought
    /// to wait before making a follow-up request." A 429 response
    /// "MAY include a Retry-After header indicating how long to wait before making a new request."
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6585#section-4">RFC 6585 §4</see>).
    /// </summary>
    public static string RetryAfter { get; } = Utf8Constants.ToInternedString(RetryAfterUtf8);

    /// <summary>
    /// The UTF-8 source literal of <see cref="RateLimitPolicy"/>. The Internet-Draft
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-3">draft-ietf-httpapi-ratelimit-headers-11 §3</see>
    /// names "The &quot;RateLimit-Policy&quot; response header field".
    /// </summary>
    public static ReadOnlySpan<byte> RateLimitPolicyUtf8 => "RateLimit-Policy"u8;

    /// <summary>
    /// The interned quota-policy header name derived from <see cref="RateLimitPolicyUtf8"/>.
    /// The Internet-Draft
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-3">draft-ietf-httpapi-ratelimit-headers-11 §3</see>
    /// says "The &quot;RateLimit-Policy&quot; response header field is a non-empty List[SF] of Quota Policy Items (Section 3.1)."
    /// Its registration is proposed in
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-10.1">§10.1</see>.
    /// </summary>
    public static string RateLimitPolicy { get; } = Utf8Constants.ToInternedString(RateLimitPolicyUtf8);

    /// <summary>
    /// The UTF-8 source literal of <see cref="RateLimit"/>. The Internet-Draft
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-4">draft-ietf-httpapi-ratelimit-headers-11 §4</see>
    /// names "the &quot;RateLimit&quot; response header field".
    /// </summary>
    public static ReadOnlySpan<byte> RateLimitUtf8 => "RateLimit"u8;

    /// <summary>
    /// The interned service-limit header name derived from <see cref="RateLimitUtf8"/>.
    /// The Internet-Draft
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-4">draft-ietf-httpapi-ratelimit-headers-11 §4</see>
    /// says "A server uses the &quot;RateLimit&quot; response header field to communicate the current service
    /// limit for a quota policy for a particular partition key." Its registration is proposed in
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-10.1">§10.1</see>.
    /// </summary>
    public static string RateLimit { get; } = Utf8Constants.ToInternedString(RateLimitUtf8);


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Authorization</c> header.
    /// </summary>
    public static bool IsAuthorization(string name) => Equals(name, Authorization);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Proxy-Authorization</c> header.
    /// </summary>
    /// <param name="name">The header name to test.</param>
    /// <returns><see langword="true"/> for <see cref="ProxyAuthorization"/> in any case.</returns>
    public static bool IsProxyAuthorization(string name) => Equals(name, ProxyAuthorization);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Cookie</c> header.
    /// </summary>
    /// <param name="name">The header name to test.</param>
    /// <returns><see langword="true"/> for <see cref="Cookie"/> in any case.</returns>
    public static bool IsCookie(string name) => Equals(name, Cookie);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Accept</c> header.
    /// </summary>
    public static bool IsAccept(string name) => Equals(name, Accept);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Accept-Language</c> header.
    /// </summary>
    public static bool IsAcceptLanguage(string name) => Equals(name, AcceptLanguage);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Content-Language</c> header.
    /// </summary>
    public static bool IsContentLanguage(string name) => Equals(name, ContentLanguage);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Content-Type</c> header.
    /// </summary>
    public static bool IsContentType(string name) => Equals(name, ContentType);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Content-Length</c> header.
    /// </summary>
    public static bool IsContentLength(string name) => Equals(name, ContentLength);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>DPoP</c> header.
    /// </summary>
    public static bool IsDPoP(string name) => Equals(name, DPoP);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>DPoP-Nonce</c> header.
    /// </summary>
    public static bool IsDPoPNonce(string name) => Equals(name, DPoPNonce);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Cache-Control</c> header.
    /// </summary>
    public static bool IsCacheControl(string name) => Equals(name, CacheControl);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>WWW-Authenticate</c> header.
    /// </summary>
    public static bool IsWwwAuthenticate(string name) => Equals(name, WwwAuthenticate);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Allow</c> header.
    /// </summary>
    public static bool IsAllow(string name) => Equals(name, Allow);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Location</c> header.
    /// </summary>
    public static bool IsLocation(string name) => Equals(name, Location);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Date</c> header.
    /// </summary>
    public static bool IsDate(string name) => Equals(name, Date);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Age</c> header.
    /// </summary>
    public static bool IsAge(string name) => Equals(name, Age);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Expires</c> header.
    /// </summary>
    public static bool IsExpires(string name) => Equals(name, Expires);

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="name"/> is the
    /// <c>Set-Cookie</c> header.
    /// </summary>
    public static bool IsSetCookie(string name) => Equals(name, SetCookie);

    /// <summary>
    /// Tests whether <paramref name="name"/> names <see cref="TraceParent"/> through <see cref="Equals"/>.
    /// The <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#header-name">W3C Trace Context Recommendation §3.2.1</see>
    /// says "Vendors MUST expect the header name in any case (upper, lower, mixed), and SHOULD send the header name in lowercase."
    /// </summary>
    public static bool IsTraceParent(string name) => Equals(name, TraceParent);

    /// <summary>
    /// Tests whether <paramref name="name"/> names <see cref="TraceState"/> through <see cref="Equals"/>.
    /// The <see href="https://www.w3.org/TR/2021/REC-trace-context-1-20211123/#header-name-0">W3C Trace Context Recommendation §3.3.1</see>
    /// says "Vendors MUST expect the header name in any case (upper, lower, mixed), and SHOULD send the header name in lowercase."
    /// </summary>
    public static bool IsTraceState(string name) => Equals(name, TraceState);

    /// <summary>
    /// Tests whether <paramref name="name"/> names <see cref="Baggage"/> through <see cref="Equals"/>.
    /// <see href="https://www.w3.org/TR/2024/CR-baggage-20240530/#header-name">W3C Baggage §3.1</see>,
    /// a Candidate Recommendation Snapshot dated 30 May 2024, names "Header name: baggage".
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110 §5.1</see> says
    /// "Field names are case-insensitive".
    /// </summary>
    public static bool IsBaggage(string name) => Equals(name, Baggage);

    /// <summary>
    /// Tests whether <paramref name="name"/> names <see cref="RetryAfter"/> through <see cref="Equals"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-10.2.3">RFC 9110 §10.2.3</see>
    /// defines "Retry-After = HTTP-date / delay-seconds"; <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">§5.1</see>
    /// says "Field names are case-insensitive".
    /// </summary>
    public static bool IsRetryAfter(string name) => Equals(name, RetryAfter);

    /// <summary>
    /// Tests whether <paramref name="name"/> names <see cref="RateLimitPolicy"/> through <see cref="Equals"/>.
    /// The Internet-Draft
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-3">draft-ietf-httpapi-ratelimit-headers-11 §3</see>
    /// names "The &quot;RateLimit-Policy&quot; response header field"; <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110 §5.1</see>
    /// says "Field names are case-insensitive".
    /// </summary>
    public static bool IsRateLimitPolicy(string name) => Equals(name, RateLimitPolicy);

    /// <summary>
    /// Tests whether <paramref name="name"/> names <see cref="RateLimit"/> through <see cref="Equals"/>.
    /// The Internet-Draft
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-4">draft-ietf-httpapi-ratelimit-headers-11 §4</see>
    /// names "the &quot;RateLimit&quot; response header field"; <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110 §5.1</see>
    /// says "Field names are case-insensitive".
    /// </summary>
    public static bool IsRateLimit(string name) => Equals(name, RateLimit);


    /// <summary>
    /// Returns the canonical instance for <paramref name="name"/> when it
    /// matches one of the well-known headers, otherwise the input unchanged.
    /// The library's canonical-instance rule follows
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110 §5.1</see>:
    /// "Field names are case-insensitive".
    /// </summary>
    public static string GetCanonicalizedValue(string name) => name switch
    {
        var n when IsAuthorization(n) => Authorization,
        var n when IsProxyAuthorization(n) => ProxyAuthorization,
        var n when IsCookie(n) => Cookie,
        var n when IsAccept(n) => Accept,
        var n when IsAcceptLanguage(n) => AcceptLanguage,
        var n when IsContentLanguage(n) => ContentLanguage,
        var n when IsContentType(n) => ContentType,
        var n when IsContentLength(n) => ContentLength,
        var n when IsDPoP(n) => DPoP,
        var n when IsDPoPNonce(n) => DPoPNonce,
        var n when IsCacheControl(n) => CacheControl,
        var n when IsWwwAuthenticate(n) => WwwAuthenticate,
        var n when Equals(n, AccessControlExposeHeaders) => AccessControlExposeHeaders,
        var n when IsAllow(n) => Allow,
        var n when IsLocation(n) => Location,
        var n when IsDate(n) => Date,
        var n when IsAge(n) => Age,
        var n when IsExpires(n) => Expires,
        var n when IsSetCookie(n) => SetCookie,
        var n when IsTraceParent(n) => TraceParent,
        var n when IsTraceState(n) => TraceState,
        var n when IsBaggage(n) => Baggage,
        var n when IsRetryAfter(n) => RetryAfter,
        var n when IsRateLimitPolicy(n) => RateLimitPolicy,
        var n when IsRateLimit(n) => RateLimit,
        _ => name
    };


    /// <summary>
    /// Compares two HTTP header names per the library's comparison rule
    /// (ordinal, case-insensitive — header names are case-insensitive per
    /// RFC 9110 §5.1).
    /// </summary>
    public static bool Equals(string nameA, string nameB) =>
        string.Equals(nameA, nameB, StringComparison.OrdinalIgnoreCase);
}
